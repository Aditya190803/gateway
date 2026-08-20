import { Context, Next } from 'hono';
import { hashApiKey } from '../../managed/apiKeys';
import {
  aggregateModelsFromProviders,
  applyProviderHeaders,
  resolveProviderCredential,
} from '../../managed/injectProvider';
import {
  matchProvidersWithDefaults,
  parseExplicitTarget,
  parseModelsJson,
  parseVendorAlias,
} from '../../managed/modelRouting';
import { vendorRoutable, vendorServesPath } from '../../managed/oauth';
import {
  hasLegacyPortkeyAuth,
  isManagedUserApiKey,
} from '../../managed/legacyAuth';
import { getFailoverState } from '../../managed/failover';
import {
  classifyStatus,
  isRetryable,
  recordProviderFailure,
  recordProviderSuccess,
  selectCandidate,
  type Candidate,
} from '../../managed/providerHealth';
import { checkRateLimits, recordRequestForRpm } from '../../managed/rateLimit';
import type { ApiKeyRecord, ManagedEnv } from '../../managed/types';
import {
  collectStreamUsage,
  extractErrorMessage,
  extractUsageFromJson,
  logRequest,
} from '../../managed/usageLog';

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

/**
 * Strip the `provider/` prefix before the request leaves the gateway — the
 * vendor has never heard of the provider id and would reject or mis-route a
 * model name it doesn't recognise.
 */
async function rewriteModelInBody(req: Request, model: string): Promise<Request> {
  const json = (await req.clone().json()) as Record<string, unknown>;
  json.model = model;
  const headers = new Headers(req.headers);
  headers.delete('content-length');
  return new Request(req.url, {
    method: req.method,
    headers,
    body: JSON.stringify(json),
  });
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
function routeModelForMessages(
  path: string,
  model: string | null
): string | null {
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

  // Owner-only providers (subscription seats) are visible only to keys owned by
  // the account that connected them, so routing never picks one for someone else.
  const providerRows = await env.DB.prepare(
    `SELECT id, models, auth_type, oauth_vendor, weight, cooldown_until
       FROM providers
      WHERE is_active = 1
        AND (owner_only = 0 OR owner_user_id = ?)`
  )
    .bind(keyRow.user_id)
    .all<{
      id: string;
      models: string;
      auth_type: string | null;
      oauth_vendor: string | null;
      weight: number | null;
      cooldown_until: number | null;
    }>();

  const providerModels = (providerRows.results ?? []).map((r) => ({
    id: r.id,
    models: parseModelsJson(r.models),
    authType: r.auth_type,
    vendor: r.oauth_vendor,
    weight: r.weight ?? 1,
    cooldownUntil: r.cooldown_until,
  }));

  // A vendor the gateway can hold credentials for but cannot yet serve traffic
  // to is excluded everywhere routing is decided, including the models listing:
  // advertising a model that no request can reach is worse than omitting it.
  const servable = providerModels.filter(
    (p) => p.authType !== 'oauth' || vendorRoutable(p.vendor)
  );

  c.set(MANAGED_API_KEY, keyRow);

  if (isModelsList) {
    const ids = servable.map((p) => p.id);
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

  // A subscription backend may expose only part of the vendor's API surface.
  // Filtering before the match means an unsupported path falls through to a
  // metered provider for the same model instead of routing into a 404 upstream.
  // The models listing above intentionally skips this filter: those models are
  // still real, they just are not reachable on every path.
  const routableProviders = servable.filter(
    (p) => p.authType !== 'oauth' || vendorServesPath(p.vendor, path)
  );

  // `provider_id/model` names a specific row rather than leaving it to prefix
  // matching. Checked against `servable` (not `routableProviders`) so a target
  // that exists but can't serve this path gets a clear error instead of
  // silently falling through to a prefix guess.
  const explicitTarget = model
    ? parseExplicitTarget(
        model,
        servable.map((p) => p.id)
      )
    : null;

  if (
    explicitTarget &&
    !routableProviders.some((p) => p.id === explicitTarget.providerId)
  ) {
    return c.json(
      {
        error: {
          message: `Provider "${explicitTarget.providerId}" cannot serve ${path}`,
          type: 'invalid_request_error',
        },
      },
      400
    );
  }

  // `alias/model` (e.g. `anti/gemini-3-pro`) names a vendor rather than one
  // row, so every provider for that vendor competes for the request exactly
  // like plain prefix matching would — weight, cooldown and failover all
  // still apply across however many seats are connected. Only tried when
  // there was no exact provider-id match above, so a provider actually named
  // "codex" still wins over the alias.
  const vendorAlias = !explicitTarget && model ? parseVendorAlias(model) : null;

  if (
    vendorAlias &&
    !routableProviders.some((p) => p.vendor === vendorAlias.vendor)
  ) {
    return c.json(
      {
        error: {
          message: `No connected "${vendorAlias.alias}" seat can serve ${path}`,
          type: 'invalid_request_error',
        },
      },
      400
    );
  }

  const matched = explicitTarget
    ? [explicitTarget.providerId]
    : vendorAlias
      ? routableProviders
          .filter((p) => p.vendor === vendorAlias.vendor)
          .map((p) => p.id)
      : matchProvidersWithDefaults(model!, routableProviders);
  const byId = new Map(routableProviders.map((p) => [p.id, p]));

  // A retry must not land on the credential that just failed, so providers
  // already attempted for this request are removed before anything is chosen.
  const failover = getFailoverState(env);
  const attempted = new Set(failover?.attempted ?? []);
  const available = matched.filter((id) => !attempted.has(id));

  const candidates: Candidate[] = available.map((id) => ({
    id,
    weight: byId.get(id)?.weight ?? 1,
    cooldownUntil: byId.get(id)?.cooldownUntil ?? null,
  }));
  const providerId = selectCandidate(candidates);

  if (!providerId) {
    // Distinguish "you have nothing for this model" from "everything we had
    // for it has already been tried", because they need different actions.
    const message = matched.length
      ? `All providers for model ${model} failed this request`
      : `No active provider configured for model: ${model}`;
    return c.json(
      { error: { message, type: 'invalid_request_error' } },
      matched.length ? 502 : 400
    );
  }
  failover?.attempted.push(providerId);
  /** Whether a different credential could still take this request. */
  const hasAlternative = available.length > 1;

  const credential = await resolveProviderCredential(env, providerId);
  if (!credential.ok) {
    const err = credential.error;
    // Name the provider that needs reconnecting rather than returning a bare
    // 503, but keep the vendor's own error text out of the response: it is
    // relayed verbatim from the token endpoint and can carry account or token
    // detail. The operator gets the full text from the log line below and from
    // the admin-only POST /admin/oauth/:id/refresh.
    if (err.kind === 'oauth') {
      console.error(
        `[managed] oauth credential failure for provider ${providerId}: ${err.message}`
      );
    }
    const message =
      err.kind === 'oauth'
        ? `Provider ${providerId} is not usable right now; its subscription login needs to be reconnected.`
        : 'Provider not available or decryption failed';

    // A credential the vendor will not renew is the case auto-disable exists
    // for. A local decryption failure is not: it means this deployment's
    // encryption key is wrong, which would otherwise deactivate every provider
    // at once over a problem that is fixed with an environment variable.
    c.executionCtx.waitUntil(
      recordProviderFailure(
        env.DB,
        providerId,
        err.kind === 'oauth' ? 'auth' : 'server',
        err.kind === 'oauth' ? err.message : 'Credential could not be decrypted'
      )
    );
    if (hasAlternative && failover) failover.retry = true;

    return c.json(
      {
        error: {
          message,
          type: 'server_error',
        },
      },
      503
    );
  }

  c.set(MANAGED_PROVIDER, providerId);

  const strippedModel = explicitTarget?.model ?? vendorAlias?.model ?? null;
  let forwardRequest = c.req.raw;
  if (strippedModel) {
    const ct = c.req.header('content-type')?.split(';')[0]?.trim() ?? '';
    if (ct === 'application/json') {
      forwardRequest = await rewriteModelInBody(forwardRequest, strippedModel);
    }
  }

  c.req.raw = applyProviderHeaders(
    forwardRequest,
    providerId,
    credential.value,
    forwardRequest.body
  );

  const startedAt = Date.now();
  await next();
  const durationMs = Date.now() - startedAt;

  const apiKeyRec = c.get(MANAGED_API_KEY) as ApiKeyRecord | undefined;
  const providerUsed = c.get(MANAGED_PROVIDER) as string | undefined;
  const modelForLog = model;
  if (!apiKeyRec || !providerUsed || !modelForLog) return;

  const res = c.res;
  const failureKind = res ? classifyStatus(res.status) : null;

  // Ask for a retry before returning, while the wrapper is still waiting on
  // this response. Everything else about the failure is recorded afterwards.
  if (failureKind && isRetryable(failureKind) && hasAlternative && failover) {
    failover.retry = true;
  }

  const ok = res ? res.status >= 200 && res.status < 300 : false;
  const contentType = res?.headers.get('content-type') ?? '';

  /**
   * Streamed responses carry their token counts in the frames themselves, and
   * a stream can only be read once. Tee it here — before the response leaves —
   * so the client gets one copy and the meter gets the other; `res.clone()`
   * cannot serve, because the clone would compete for the same source.
   */
  let meteredStream: ReadableStream<Uint8Array> | null = null;
  if (ok && res?.body && contentType.includes('text/event-stream')) {
    const [toClient, toMeter] = res.body.tee();
    c.res = new Response(toClient, res);
    meteredStream = toMeter;
  }

  const recordAfterResponse = async () => {
    try {
      if (!res) return;

      // Every attempt that reached a provider counts against the key's rate
      // limit. Charging only for successes would let a failing client retry
      // without limit, which is the case the limit exists for.
      await recordRequestForRpm(env.DB, apiKeyRec.id);

      let usage: { prompt: number; completion: number } | undefined;
      let errorMessage: string | null = null;
      const ct = contentType;

      if (meteredStream) {
        // Resolves when the upstream stream ends, which is after the client has
        // its answer. waitUntil keeps the isolate alive for exactly this.
        usage = await collectStreamUsage(meteredStream);
      } else if (ok && ct.includes('application/json')) {
        const json = (await res.clone().json()) as Record<string, unknown>;
        const u = extractUsageFromJson(json);
        usage = { prompt: u.prompt, completion: u.completion };
      } else if (!ok) {
        // Error bodies are small and are the whole point of logging a failure.
        errorMessage = extractErrorMessage(await res.clone().text(), ct);
      }

      await logRequest(env.DB, apiKeyRec.id, modelForLog, providerUsed, usage, {
        statusCode: res.status,
        errorMessage,
        durationMs,
      });

      if (failureKind) {
        await recordProviderFailure(
          env.DB,
          providerUsed,
          failureKind,
          errorMessage || `Upstream returned ${res.status}`,
          res.headers.get('retry-after')
        );
      } else if (ok) {
        await recordProviderSuccess(env.DB, providerUsed);
      }
    } catch {
      /* logging and health tracking are never worth failing a request over */
    }
  };

  c.executionCtx.waitUntil(recordAfterResponse());
};
