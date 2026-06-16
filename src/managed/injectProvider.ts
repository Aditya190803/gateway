import { POWERED_BY } from '../globals';
import { decryptProviderKey } from './encryption';
import { fetchLatestModelsForProvider } from './fetchModels';
import type { ManagedEnv } from './types';

export async function decryptActiveProviderKey(
  env: ManagedEnv,
  providerId: string
): Promise<string | null> {
  const encSecret = env.PROVIDER_KEY_ENCRYPTION_KEY?.trim();
  if (!encSecret || encSecret.length < 16 || !env.DB) return null;
  const prov = await env.DB.prepare(
    `SELECT api_key FROM providers WHERE id = ? AND is_active = 1`
  )
    .bind(providerId)
    .first<{ api_key: string }>();
  if (!prov) return null;
  try {
    return await decryptProviderKey(prov.api_key, encSecret);
  } catch {
    return null;
  }
}

export function applyProviderHeaders(
  req: Request,
  providerId: string,
  providerApiKey: string,
  body?: ReadableStream | null
): Request {
  const configHeader = `x-${POWERED_BY}-config`;
  const providerHeader = `x-${POWERED_BY}-provider`;
  const headers = new Headers(req.headers);
  headers.set(
    configHeader,
    JSON.stringify({ provider: providerId, api_key: providerApiKey })
  );
  headers.set(providerHeader, providerId);
  headers.set('authorization', `Bearer ${providerApiKey}`);
  const init: RequestInit = { method: req.method, headers };
  if (body && req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = body;
    (init as RequestInit & { duplex?: string }).duplex = 'half';
  }
  return new Request(req.url, init);
}

export async function fetchProviderModelsList(
  providerId: string,
  apiKey: string
): Promise<{ id: string; object: string; owned_by: string }[]> {
  const { models } = await fetchLatestModelsForProvider(providerId, apiKey);
  return models.map((m) => ({
    id: m.id,
    object: m.object,
    owned_by: m.owned_by || providerId,
  }));
}

export async function aggregateModelsFromProviders(
  env: ManagedEnv,
  providerIds: string[]
): Promise<{ object: string; data: { id: string; object: string; owned_by: string }[] }> {
  const seen = new Set<string>();
  const data: { id: string; object: string; owned_by: string }[] = [];
  for (const id of providerIds) {
    const key = await decryptActiveProviderKey(env, id);
    if (!key) continue;
    const models = await fetchProviderModelsList(id, key);
    for (const m of models) {
      if (seen.has(m.id)) continue;
      seen.add(m.id);
      data.push(m);
    }
  }
  return { object: 'list', data };
}