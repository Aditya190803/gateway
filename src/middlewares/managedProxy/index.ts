import { Context, Next } from 'hono';
import { hashApiKey } from '../../managed/apiKeys';
import {
  aggregateModelsFromProviders,
  applyProviderHeaders,
  decryptActiveProviderKey,
} from '../../managed/injectProvider';
import {
  matchProviderWithDefaults,
  parseModelsJson,
} from '../../managed/modelRouting';
import {
  hasLegacyPortkeyAuth,
  isManagedUserApiKey,
} from '../../managed/legacyAuth';
import { checkRateLimits, recordRequestForRpm } from '../../managed/rateLimit';
import type { ApiKeyRecord, ManagedEnv } from '../../managed/types';
import { extractUsageFromJson, logRequest } from '../../managed/usageLog';

const MANAGED_API_KEY = 'managedApiKey';
const MANAGED_PROVIDER = 'managedProvider';

function isManagedV1Route(path: string): boolean {
  return path.startsWith('/v1/');
}

function getBearer(c: Context): string | undefined {
  const auth = c.req.header('authorization');
  if (!auth) return undefined;
  const [scheme, token] = auth.trim().split(/\s+/, 2);
  if (scheme?.toLowerCase() !== 'bearer' || !token) return undefined;
  return token;
}

async function extractModelFromRequest(c: Context): Promise<string | null> {
  if (c.req.method === 'GET') {
    return null;
  }
  const ct = c.req.header('content-type')?.split(';')[0]?.trim() ?? '';
  if (ct === 'application/json') {
    try {
      const clone = c.req.raw.clone();
      const body = (await clone.json()) as { model?: string };
      return body.model ?? null;
    } catch {
      return null;
    }
  }
  if (ct === 'multipart/form-data') {
    try {
      const clone = c.req.raw.clone();
      const form = await clone.formData();
      const m = form.get('model');
      if (typeof m === 'string' && m.trim()) return m.trim();
    } catch {
      return null;
    }
  }
  return null;
}

function defaultModelForPath(path: string): string | null {
  if (path.includes('/audio/transcriptions')) return 'whisper-1';
  if (path.includes('/audio/translations')) return 'whisper-1';
  if (path.includes('/audio/speech')) return 'tts-1';
  if (path.includes('/images/generations')) return 'dall-e-3';
  if (path.includes('/images/edits')) return 'dall-e-2';
  return null;
}

/** Anthropic /v1/messages uses model in JSON body (same as extractModelFromRequest). */
function routeModelForMessages(path: string, model: string | null): string | null {
  if (path === '/v1/messages' || path.startsWith('/v1/messages/')) {
    return model;
  }
  return model;
}

export const managedProxyMiddleware = async (c: Context, next: Next) => {
  const path = new URL(c.req.url).pathname;
  if (!isManagedV1Route(path)) {
    return next();
  }

  const env = c.env as ManagedEnv;
  const reqHeaders = c.req.raw.headers;

  if (hasLegacyPortkeyAuth(reqHeaders)) {
    return next();
  }

  if (!env.DB) {
    return next();
  }

  const rawKey = getBearer(c);
  if (!rawKey) {
    return c.json(
      {
        error: {
          message:
            'Missing Authorization: Bearer <api_key>. Use a managed key (sk-…) or legacy x-portkey-config / x-portkey-provider headers.',
          type: 'invalid_request_error',
        },
      },
      401
    );
  }

  if (!isManagedUserApiKey(rawKey)) {
    return next();
  }

  const keyHash = await hashApiKey(rawKey);
  const keyRow = await env.DB.prepare(
    `SELECT id, user_id, key_hash, key_prefix, label, is_active, rpm_limit, monthly_token_limit
     FROM api_keys WHERE key_hash = ? LIMIT 1`
  )
    .bind(keyHash)
    .first<ApiKeyRecord>();

  if (!keyRow || !keyRow.is_active) {
    return c.json(
      {
        error: { message: 'Invalid API key', type: 'invalid_request_error' },
      },
      401
    );
  }

  const limits = await checkRateLimits(env.DB, keyRow);
  if (!limits.ok) {
    return c.json(
      {
        error: { message: limits.message, type: 'rate_limit_error' },
      },
      limits.status as 429
    );
  }

  const isModelsList = path === '/v1/models' && c.req.method === 'GET';
  let model = await extractModelFromRequest(c);
  if (!model) {
    model = defaultModelForPath(path);
  }
  model = routeModelForMessages(path, model);

  if (!model && !isModelsList) {
    return c.json(
      {
        error: {
          message:
            'Request must include a model field (JSON or multipart) for routing',
          type: 'invalid_request_error',
        },
      },
      400
    );
  }

  const providerRows = await env.DB.prepare(
    `SELECT id, models FROM providers WHERE is_active = 1`
  ).all<{ id: string; models: string }>();

  const providerModels = (providerRows.results ?? []).map((r) => ({
    id: r.id,
    models: parseModelsJson(r.models),
  }));

  c.set(MANAGED_API_KEY, keyRow);

  if (isModelsList) {
    const ids = providerModels.map((p) => p.id);
    if (!ids.length) {
      return c.json(
        {
          error: {
            message: 'No providers configured',
            type: 'server_error',
          },
        },
        503
      );
    }
    const list = await aggregateModelsFromProviders(env, ids);
    c.executionCtx.waitUntil(recordRequestForRpm(env.DB, keyRow.id));
    return c.json(list);
  }

  const providerId = matchProviderWithDefaults(model!, providerModels);
  if (!providerId) {
    return c.json(
      {
        error: {
          message: `No active provider configured for model: ${model}`,
          type: 'invalid_request_error',
        },
      },
      400
    );
  }

  const providerApiKey = await decryptActiveProviderKey(env, providerId);
  if (!providerApiKey) {
    return c.json(
      {
        error: {
          message: 'Provider not available or decryption failed',
          type: 'server_error',
        },
      },
      503
    );
  }

  c.set(MANAGED_PROVIDER, providerId);

  c.req.raw = applyProviderHeaders(
    c.req.raw,
    providerId,
    providerApiKey,
    c.req.raw.body
  );

  await next();

  const apiKeyRec = c.get(MANAGED_API_KEY) as ApiKeyRecord | undefined;
  const providerUsed = c.get(MANAGED_PROVIDER) as string | undefined;
  const modelForLog = model;
  if (!apiKeyRec || !providerUsed || !modelForLog) return;

  const logAfterResponse = async () => {
    try {
      const res = c.res;
      if (!res || res.status < 200 || res.status >= 300) return;
      await recordRequestForRpm(env.DB, apiKeyRec.id);
      let usage: { prompt: number; completion: number } | undefined;
      const ct = res.headers.get('content-type') ?? '';
      if (ct.includes('application/json')) {
        const cloned = res.clone();
        const json = (await cloned.json()) as Record<string, unknown>;
        const u = extractUsageFromJson(json);
        usage = { prompt: u.prompt, completion: u.completion };
      }
      await logRequest(env.DB, apiKeyRec.id, modelForLog, providerUsed, usage);
    } catch {
      /* non-fatal */
    }
  };

  c.executionCtx.waitUntil(logAfterResponse());
};