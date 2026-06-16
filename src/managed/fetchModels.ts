import Providers from '../providers';
import providersMeta from '../data/providers.json';
import { DEFAULT_MODEL_PREFIXES } from './modelRouting';

export type FetchedModel = {
  id: string;
  object: string;
  owned_by: string;
  created?: number;
};

type ModelsListStrategy = 'openai' | 'anthropic' | 'google' | 'openrouter' | 'cohere' | 'none';

const OPENAI_COMPAT_IDS = new Set([
  'openai',
  'groq',
  'mistral-ai',
  'together-ai',
  'deepinfra',
  'deepseek',
  'fireworks-ai',
  'perplexity-ai',
  'novita-ai',
  'cerebras',
  'sambanova',
  'hyperbolic',
  'deepbricks',
  'siliconflow',
  'x-ai',
  'moonshot',
  'zhipu',
  'dashscope',
  'nebius',
  'inference-net',
  'cometapi',
  'ovhcloud',
  'ncompass',
  'iointelligence',
  'kluster-ai',
  'krutrim',
]);

function strategyFor(providerId: string): ModelsListStrategy {
  if (providerId === 'anthropic') return 'anthropic';
  if (providerId === 'google' || providerId === 'palm') return 'google';
  if (providerId === 'openrouter') return 'openrouter';
  if (providerId === 'cohere') return 'cohere';
  if (OPENAI_COMPAT_IDS.has(providerId)) return 'openai';
  return 'none';
}

function openAiStyleModelsUrl(base: string): string {
  const b = base.replace(/\/$/, '');
  if (b.endsWith('/v1')) return `${b}/models`;
  return `${b}/v1/models`;
}

async function fetchOpenAiStyle(
  base: string,
  headers: Record<string, string>
): Promise<FetchedModel[]> {
  const url = openAiStyleModelsUrl(base);
  const res = await fetch(url, { headers });
  if (!res.ok) return [];
  const json = (await res.json()) as {
    data?: { id: string; created?: number; owned_by?: string }[];
  };
  return (json.data ?? []).map((m) => ({
    id: m.id,
    object: 'model',
    owned_by: m.owned_by ?? 'provider',
    created: m.created,
  }));
}

async function fetchAnthropic(apiKey: string): Promise<FetchedModel[]> {
  const res = await fetch('https://api.anthropic.com/v1/models', {
    headers: {
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
  });
  if (!res.ok) return [];
  const json = (await res.json()) as {
    data?: { id: string; created_at?: string }[];
  };
  return (json.data ?? []).map((m) => ({
    id: m.id,
    object: 'model',
    owned_by: 'anthropic',
  }));
}

async function fetchGoogle(apiKey: string): Promise<FetchedModel[]> {
  const res = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models?key=${encodeURIComponent(apiKey)}`
  );
  if (!res.ok) return [];
  const json = (await res.json()) as {
    models?: { name: string; displayName?: string }[];
  };
  return (json.models ?? []).map((m) => {
    const id = m.name.replace(/^models\//, '');
    return { id, object: 'model', owned_by: 'google' };
  });
}

async function fetchOpenRouter(apiKey: string): Promise<FetchedModel[]> {
  const res = await fetch('https://openrouter.ai/api/v1/models', {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (!res.ok) return [];
  const json = (await res.json()) as { data?: { id: string }[] };
  return (json.data ?? []).map((m) => ({
    id: m.id,
    object: 'model',
    owned_by: 'openrouter',
  }));
}

async function fetchCohere(apiKey: string): Promise<FetchedModel[]> {
  const res = await fetch('https://api.cohere.ai/v1/models', {
    headers: { Authorization: `Bearer ${apiKey}` },
  });
  if (!res.ok) return [];
  const json = (await res.json()) as {
    models?: { name: string }[];
  };
  const list = json.models ?? (json as { data?: { name: string }[] }).data ?? [];
  return list.map((m: { name: string }) => ({
    id: m.name,
    object: 'model',
    owned_by: 'cohere',
  }));
}

/** Fetch latest models from provider APIs (OpenAI GET /v1/models pattern + provider-specific). */
export async function fetchLatestModelsForProvider(
  providerId: string,
  apiKey: string
): Promise<{ models: FetchedModel[]; error?: string }> {
  const strategy = strategyFor(providerId);
  if (strategy === 'none') {
    return {
      models: [],
      error:
        'Live model listing not supported for this provider yet. Add model prefixes manually or use an OpenAI-compatible provider.',
    };
  }

  try {
    if (strategy === 'anthropic') {
      return { models: await fetchAnthropic(apiKey) };
    }
    if (strategy === 'google') {
      return { models: await fetchGoogle(apiKey) };
    }
    if (strategy === 'openrouter') {
      return { models: await fetchOpenRouter(apiKey) };
    }
    if (strategy === 'cohere') {
      return { models: await fetchCohere(apiKey) };
    }

    const cfg = Providers[providerId];
    if (!cfg?.api) {
      return { models: [], error: 'Provider not found in gateway' };
    }
    const apiConfig = cfg.api;
    const base =
      apiConfig.getBaseURL?.({
        apiKey,
        providerOptions: { apiKey },
      } as never) ?? '';
    if (!base) {
      return { models: [], error: 'No API base URL for this provider' };
    }
    const hdrs =
      (await Promise.resolve(
        apiConfig.headers?.({
          apiKey,
          providerOptions: { apiKey },
        } as never)
      )) ?? { Authorization: `Bearer ${apiKey}` };
    const models = await fetchOpenAiStyle(String(base), hdrs as Record<string, string>);
    return {
      models: models.map((m) => ({ ...m, owned_by: providerId })),
      error: models.length ? undefined : 'Provider returned no models (check API key)',
    };
  } catch (e) {
    return {
      models: [],
      error: e instanceof Error ? e.message : 'Failed to fetch models',
    };
  }
}

/** Derive routing prefixes from model ids (longest unique prefixes). */
export function prefixesFromModelIds(ids: string[]): string[] {
  const prefixes = new Set<string>();
  for (const id of ids) {
    const dash = id.indexOf('-');
    const slash = id.indexOf('/');
    let cut = id.length;
    if (dash > 0) cut = Math.min(cut, dash + 1);
    if (slash > 0) cut = Math.min(cut, slash + 1);
    const p = id.slice(0, cut);
    if (p.length >= 2) prefixes.add(p);
  }
  return [...prefixes].sort();
}

export type GatewayProviderInfo = {
  id: string;
  name: string;
  description?: string;
  supportsLiveModels: boolean;
  defaultPrefixes: string[];
};

export function listGatewayProviders(): GatewayProviderInfo[] {
  const meta = (providersMeta as { data?: { id: string; name: string; description?: string }[] })
    .data ?? [];
  const metaById = new Map(meta.map((p) => [p.id, p]));
  const ids = Object.keys(Providers).sort();
  return ids.map((id) => {
    const m = metaById.get(id);
    return {
      id,
      name: m?.name ?? id,
      description: m?.description,
      supportsLiveModels: strategyFor(id) !== 'none',
      defaultPrefixes: DEFAULT_MODEL_PREFIXES[id] ?? [],
    };
  });
}