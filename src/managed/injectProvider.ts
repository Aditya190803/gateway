import { POWERED_BY } from '../globals';
import { decryptProviderKey } from './encryption';
import { fetchLatestModelsForProvider } from './fetchModels';
// Import via the barrel: loading it is what registers the OAuth adapters.
import { resolveOAuthCredential } from './oauth';
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

/**
 * A provider's credentials, normalised across API-key and OAuth auth types.
 *
 * `gatewayProvider` is the built-in provider whose request/response transforms
 * apply. It can differ from the provider row's id, because an OAuth account is
 * a credential for an existing vendor rather than a new wire format.
 */
export type ResolvedCredential = {
  token: string;
  gatewayProvider: string;
  /** Overrides the vendor's default base URL when the subscription endpoint differs. */
  customHost?: string;
  /** Vendor-required headers to forward verbatim. */
  extraHeaders?: Record<string, string>;
  /** Where the credential goes, when it is not the vendor's usual API-key slot. */
  authHeader?: { header: string; scheme?: string };
  /** Extra provider-config keys the transform needs; see UpstreamCall. */
  configOverrides?: Record<string, string>;
};

export type CredentialError =
  | { kind: 'not_found' }
  | { kind: 'decrypt_failed' }
  | { kind: 'oauth'; message: string };

/**
 * Resolve whatever credential a provider is configured with. For OAuth
 * providers this refreshes the access token first when it is near expiry.
 */
export async function resolveProviderCredential(
  env: ManagedEnv,
  providerId: string
): Promise<
  { ok: true; value: ResolvedCredential } | { ok: false; error: CredentialError }
> {
  if (!env.DB) return { ok: false, error: { kind: 'not_found' } };

  const row = await env.DB.prepare(
    `SELECT auth_type FROM providers WHERE id = ? AND is_active = 1 LIMIT 1`
  )
    .bind(providerId)
    .first<{ auth_type: string | null }>();
  if (!row) return { ok: false, error: { kind: 'not_found' } };

  if (row.auth_type !== 'oauth') {
    const key = await decryptActiveProviderKey(env, providerId);
    if (!key) return { ok: false, error: { kind: 'decrypt_failed' } };
    return { ok: true, value: { token: key, gatewayProvider: providerId } };
  }

  const resolved = await resolveOAuthCredential(env, providerId);
  if (!resolved.ok) {
    const err = resolved.error;
    const message =
      err.kind === 'refresh_failed'
        ? err.message
        : err.kind === 'unknown_vendor'
          ? `Unsupported OAuth vendor: ${err.vendor ?? 'unknown'}`
          : err.kind === 'no_credentials'
            ? 'No OAuth credentials stored. Reconnect the account.'
            : 'Provider is not OAuth-backed';
    return { ok: false, error: { kind: 'oauth', message } };
  }

  const { adapter, tokens } = resolved.value;
  const call = adapter.decorate(tokens);
  return {
    ok: true,
    value: {
      token: tokens.access_token,
      gatewayProvider: adapter.gatewayProvider,
      customHost: call.baseUrl,
      extraHeaders: call.headers,
      authHeader: call.auth,
      configOverrides: call.configOverrides,
    },
  };
}

export function applyProviderHeaders(
  req: Request,
  providerId: string,
  credential: ResolvedCredential,
  body?: ReadableStream | null
): Request {
  const configHeader = `x-${POWERED_BY}-config`;
  const providerHeader = `x-${POWERED_BY}-provider`;
  const headers = new Headers(req.headers);

  const gatewayProvider = credential.gatewayProvider || providerId;
  const config: Record<string, unknown> = {
    provider: gatewayProvider,
    // When the adapter names its own auth header, the credential travels only
    // in that header. Handing it to the provider as well would additionally
    // populate the provider's default auth slot (Anthropic's X-API-Key, say),
    // and a vendor that validates that slot first rejects the request before it
    // ever looks at the bearer token.
    api_key: credential.authHeader ? '' : credential.token,
  };
  if (credential.customHost) {
    config.custom_host = credential.customHost;
  }
  // Account facts the provider's parameter transform needs. They ride in the
  // config rather than a header because that is the only channel that reaches
  // providerOptions, which is what a transform can read.
  for (const [key, value] of Object.entries(credential.configOverrides ?? {})) {
    config[key] = value;
  }

  // Vendor-required headers ride along as forwarded headers. constructRequestHeaders
  // spreads forwarded headers last, so these deliberately override whatever the
  // built-in provider config would have set (see handlers/handlerUtils.ts).
  const forwarded: string[] = [];
  for (const [name, value] of Object.entries(credential.extraHeaders ?? {})) {
    const key = name.toLowerCase();
    headers.set(key, value);
    forwarded.push(key);
  }

  if (credential.authHeader) {
    const key = credential.authHeader.header.toLowerCase();
    const scheme = credential.authHeader.scheme;
    headers.set(
      key,
      scheme ? `${scheme} ${credential.token}` : credential.token
    );
    if (!forwarded.includes(key)) forwarded.push(key);
  } else {
    headers.set('authorization', `Bearer ${credential.token}`);
  }

  if (forwarded.length) {
    config.forward_headers = forwarded;
  }

  headers.set(configHeader, JSON.stringify(config));
  headers.set(providerHeader, gatewayProvider);

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
    const models = await modelsForProvider(env, id);
    for (const m of models) {
      if (seen.has(m.id)) continue;
      seen.add(m.id);
      data.push(m);
    }
  }
  return { object: 'list', data };
}

/**
 * Same walk as {@link aggregateModelsFromProviders}, but keeps attribution:
 * every model carries the ids of all servable providers claiming it, which is
 * what a model catalog needs to show `provider_id/model` routing targets.
 * The first claimant's `owned_by` wins, matching the flat listing.
 */
export async function aggregateModelsVerbose(
  env: ManagedEnv,
  providerIds: string[]
): Promise<{
  object: string;
  data: {
    id: string;
    object: string;
    owned_by: string;
    provider_ids: string[];
  }[];
}> {
  const byId = new Map<
    string,
    { id: string; object: string; owned_by: string; provider_ids: string[] }
  >();
  for (const id of providerIds) {
    const models = await modelsForProvider(env, id);
    for (const m of models) {
      const existing = byId.get(m.id);
      if (existing) {
        existing.provider_ids.push(id);
      } else {
        byId.set(m.id, {
          id: m.id,
          object: m.object,
          owned_by: m.owned_by,
          provider_ids: [id],
        });
      }
    }
  }
  return { object: 'list', data: [...byId.values()] };
}

/**
 * Subscription endpoints generally do not expose a /models listing, and probing
 * one with a subscription token is a wasted round trip. For OAuth providers the
 * model list configured on the provider row is authoritative; API-key providers
 * still get a live fetch.
 */
async function modelsForProvider(
  env: ManagedEnv,
  providerId: string
): Promise<{ id: string; object: string; owned_by: string }[]> {
  if (!env.DB) return [];
  const row = await env.DB.prepare(
    `SELECT auth_type, models FROM providers WHERE id = ? AND is_active = 1 LIMIT 1`
  )
    .bind(providerId)
    .first<{ auth_type: string | null; models: string }>();
  if (!row) return [];

  if (row.auth_type === 'oauth') {
    let configured: string[] = [];
    try {
      const parsed = JSON.parse(row.models ?? '[]');
      if (Array.isArray(parsed))
        configured = parsed.filter((m) => typeof m === 'string');
    } catch {
      configured = [];
    }
    return configured.map((id) => ({
      id,
      object: 'model',
      owned_by: providerId,
    }));
  }

  const key = await decryptActiveProviderKey(env, providerId);
  if (!key) return [];
  try {
    return await fetchProviderModelsList(providerId, key);
  } catch {
    return [];
  }
}