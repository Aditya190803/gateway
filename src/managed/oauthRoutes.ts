import { Context, Hono } from 'hono';
import { encryptProviderKey } from './encryption';
import { parseModelsJson } from './modelRouting';
import { getAdapter, listAdapters } from './oauth';
import { createPkcePair, generateState } from './oauth/pkce';
import {
  decryptTokens,
  getOAuthProviderRow,
  persistTokens,
} from './oauth/store';
import type { OAuthTokens } from './oauth/types';
import type { ManagedEnv } from './types';

type AuthUser = { userId: number; email: string; role: 'admin' | 'user' };
type Guard = (
  c: Context,
) => Promise<{ ok: true; user: AuthUser } | { ok: false; response: Response }>;

const STATE_TTL_MS = 10 * 60 * 1000;

function encryptionKey(env: ManagedEnv): string | null {
  const s = env.PROVIDER_KEY_ENCRYPTION_KEY?.trim();
  return s && s.length >= 16 ? s : null;
}

/** Never return tokens themselves; only whether they exist and when they lapse. */
function describeStatus(row: {
  oauth_expires_at: number | null;
  oauth_account_label: string | null;
  oauth_vendor: string | null;
}) {
  const expiresAt = row.oauth_expires_at ?? 0;
  return {
    vendor: row.oauth_vendor,
    account: row.oauth_account_label,
    expires_at: expiresAt ? new Date(expiresAt).toISOString() : null,
    expired: !expiresAt || expiresAt <= Date.now(),
  };
}

/**
 * Guard against connecting a subscription over an unrelated provider.
 *
 * Writing an OAuth row blanks api_key on conflict, so a mistyped provider_id
 * would destroy a working API-key provider's only copy of its encrypted secret.
 * Converting a key-based provider to a subscription is a legitimate thing to
 * want, so this asks rather than forbids — but it has to be deliberate.
 */
async function checkProviderCollision(
  env: ManagedEnv,
  providerId: string,
  overwrite: boolean,
): Promise<{ ok: true } | { ok: false; message: string }> {
  if (overwrite || !env.DB) return { ok: true };
  const existing = await env.DB.prepare(
    `SELECT auth_type FROM providers WHERE id = ? LIMIT 1`,
  )
    .bind(providerId)
    .first<{ auth_type: string | null }>();
  if (existing && existing.auth_type !== 'oauth') {
    return {
      ok: false,
      message:
        `Provider "${providerId}" already exists with an API key. Connecting a ` +
        `subscription here permanently discards that key. Pass overwrite: true ` +
        `to convert it, or choose a different provider id.`,
    };
  }
  return { ok: true };
}

async function storeConnectedAccount(
  env: ManagedEnv,
  args: {
    providerId: string;
    providerName: string;
    vendor: string;
    tokens: OAuthTokens;
    models: string[];
    ownerUserId: number;
    overwrite: boolean;
  },
): Promise<{ ok: true } | { ok: false; message: string; status: 409 | 503 }> {
  const enc = encryptionKey(env);
  if (!enc)
    return {
      ok: false,
      message: 'PROVIDER_KEY_ENCRYPTION_KEY not set',
      status: 503,
    };

  const collision = await checkProviderCollision(
    env,
    args.providerId,
    args.overwrite,
  );
  if (!collision.ok) {
    return { ok: false, message: collision.message, status: 409 };
  }

  const encrypted = await encryptProviderKey(JSON.stringify(args.tokens), enc);
  const label =
    (args.tokens.extra?.email as string | undefined) ??
    args.tokens.account_id ??
    null;

  // api_key is NOT NULL on the base schema; OAuth rows keep '' there and carry
  // their credentials in oauth_credentials instead. The conflict update also
  // blanks api_key so converting a key-based row drops the now-unused secret.
  await env.DB.prepare(
    `INSERT INTO providers
       (id, name, api_key, models, is_active, auth_type, oauth_vendor,
        oauth_credentials, oauth_expires_at, oauth_account_label,
        owner_only, owner_user_id)
     VALUES (?, ?, '', ?, 1, 'oauth', ?, ?, ?, ?, 1, ?)
     ON CONFLICT(id) DO UPDATE SET
       name = excluded.name,
       api_key = '',
       models = excluded.models,
       is_active = 1,
       auth_type = 'oauth',
       oauth_vendor = excluded.oauth_vendor,
       oauth_credentials = excluded.oauth_credentials,
       oauth_expires_at = excluded.oauth_expires_at,
       oauth_account_label = excluded.oauth_account_label,
       oauth_version = providers.oauth_version + 1,
       owner_only = 1,
       owner_user_id = excluded.owner_user_id`,
  )
    .bind(
      args.providerId,
      args.providerName,
      JSON.stringify(args.models),
      args.vendor,
      encrypted,
      args.tokens.expires_at,
      label,
      args.ownerUserId,
    )
    .run();

  return { ok: true };
}

export function createOAuthRoutes(
  requirePlatformAdmin: Guard,
): Hono<{ Bindings: ManagedEnv }> {
  const app = new Hono<{ Bindings: ManagedEnv }>();

  app.get('/vendors', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    return c.json({
      vendors: listAdapters().map((a) => ({
        id: a.id,
        label: a.label,
        gateway_provider: a.gatewayProvider,
        supports_manual_code: a.supportsManualCode,
        credential_file: a.credentialFileHint ?? null,
        default_models: a.defaultModels,
        supported_paths: a.supportedPaths ?? null,
      })),
    });
  });

  /** Begin a PKCE flow. Returns the URL the operator should open. */
  app.post('/start', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;

    let body: {
      vendor?: string;
      provider_id?: string;
      provider_name?: string;
      redirect_uri?: string;
      overwrite?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }

    const adapter = getAdapter(body.vendor);
    if (!adapter) {
      return c.json(
        { status: 'failure', message: 'Unknown OAuth vendor' },
        400,
      );
    }
    const providerId = body.provider_id?.trim().toLowerCase();
    if (!providerId) {
      return c.json(
        { status: 'failure', message: 'provider_id is required' },
        400,
      );
    }

    // Fail before sending the operator to the vendor, so a mistyped id costs a
    // corrected form field rather than a completed authorization they cannot use.
    const collision = await checkProviderCollision(
      c.env,
      providerId,
      body.overwrite === true,
    );
    if (!collision.ok) {
      return c.json({ status: 'failure', message: collision.message }, 409);
    }

    const { verifier, challenge } = await createPkcePair();
    const state = generateState();
    const redirectUri = body.redirect_uri?.trim() ?? '';

    // Abandoned authorizations are never completed and so are never deleted by
    // the single-use path below. Sweep them here: this is the only route that
    // creates them, so it is the only place they can accumulate.
    await c.env.DB.prepare(`DELETE FROM oauth_states WHERE expires_at < ?`)
      .bind(Date.now())
      .run();

    await c.env.DB.prepare(
      `INSERT INTO oauth_states
         (state, vendor, provider_id, provider_name, code_verifier, redirect_uri, created_by, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        state,
        adapter.id,
        providerId,
        body.provider_name?.trim() || adapter.label,
        verifier,
        redirectUri,
        auth.user.userId,
        Date.now() + STATE_TTL_MS,
      )
      .run();

    return c.json({
      status: 'success',
      state,
      authorize_url: adapter.buildAuthorizeUrl({
        redirectUri,
        state,
        codeChallenge: challenge,
      }),
      supports_manual_code: adapter.supportsManualCode,
    });
  });

  /** Finish a PKCE flow with the code the vendor issued. */
  app.post('/complete', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;

    let body: {
      state?: string;
      code?: string;
      models?: string[];
      overwrite?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    if (!body.state || !body.code) {
      return c.json(
        { status: 'failure', message: 'state and code are required' },
        400,
      );
    }

    const pending = await c.env.DB.prepare(
      `SELECT state, vendor, provider_id, provider_name, code_verifier, redirect_uri, created_by, expires_at
         FROM oauth_states WHERE state = ? LIMIT 1`,
    )
      .bind(body.state)
      .first<{
        state: string;
        vendor: string;
        provider_id: string;
        provider_name: string;
        code_verifier: string;
        redirect_uri: string;
        created_by: number | null;
        expires_at: number;
      }>();

    // Single-use regardless of outcome, so a leaked state cannot be replayed.
    await c.env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`)
      .bind(body.state)
      .run();

    if (!pending) {
      return c.json(
        { status: 'failure', message: 'Unknown or already-used state' },
        400,
      );
    }
    if (pending.expires_at <= Date.now()) {
      return c.json(
        { status: 'failure', message: 'Authorization attempt expired' },
        400,
      );
    }
    // owner_user_id decides who can route to this subscription, so the account
    // that gets it must be the one that authorized, not whoever posts the code.
    if (
      pending.created_by !== null &&
      pending.created_by !== auth.user.userId
    ) {
      return c.json(
        {
          status: 'failure',
          message: 'This authorization was started by a different admin',
        },
        403,
      );
    }

    const adapter = getAdapter(pending.vendor);
    if (!adapter) {
      return c.json(
        { status: 'failure', message: 'Unknown OAuth vendor' },
        400,
      );
    }

    let tokens: OAuthTokens;
    try {
      tokens = await adapter.exchangeCode({
        code: body.code,
        codeVerifier: pending.code_verifier,
        redirectUri: pending.redirect_uri,
        state: pending.state,
      });
    } catch (e) {
      return c.json(
        {
          status: 'failure',
          message: e instanceof Error ? e.message : 'Token exchange failed',
        },
        502,
      );
    }

    const stored = await storeConnectedAccount(c.env, {
      providerId: pending.provider_id,
      providerName: pending.provider_name,
      vendor: adapter.id,
      tokens,
      models: body.models ?? adapter.defaultModels,
      ownerUserId: auth.user.userId,
      overwrite: body.overwrite === true,
    });
    if (!stored.ok) {
      return c.json(
        { status: 'failure', message: stored.message },
        stored.status,
      );
    }

    return c.json({ status: 'success', provider_id: pending.provider_id });
  });

  /**
   * Import credentials the vendor's own CLI already wrote to disk. This is the
   * only workable route for vendors whose redirect_uri is a fixed localhost
   * port that a deployed gateway cannot receive.
   */
  app.post('/import', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;

    let body: {
      vendor?: string;
      provider_id?: string;
      provider_name?: string;
      credentials?: unknown;
      models?: string[];
      overwrite?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }

    const adapter = getAdapter(body.vendor);
    if (!adapter) {
      return c.json(
        { status: 'failure', message: 'Unknown OAuth vendor' },
        400,
      );
    }
    if (!adapter.importFromFile) {
      return c.json(
        {
          status: 'failure',
          message: `${adapter.label} does not support import`,
        },
        400,
      );
    }
    const providerId = body.provider_id?.trim().toLowerCase();
    if (!providerId) {
      return c.json(
        { status: 'failure', message: 'provider_id is required' },
        400,
      );
    }

    // Accept the file either parsed or as the raw string the operator pasted.
    let blob = body.credentials;
    if (typeof blob === 'string') {
      try {
        blob = JSON.parse(blob);
      } catch {
        return c.json(
          { status: 'failure', message: 'credentials is not valid JSON' },
          400,
        );
      }
    }

    const tokens = adapter.importFromFile(blob);
    if (!tokens) {
      return c.json(
        {
          status: 'failure',
          message: `Credentials are not in ${adapter.label} format. Expected ${adapter.credentialFileHint ?? 'the vendor CLI credential file'}.`,
        },
        400,
      );
    }

    const stored = await storeConnectedAccount(c.env, {
      providerId,
      providerName: body.provider_name?.trim() || adapter.label,
      vendor: adapter.id,
      tokens,
      models: body.models ?? adapter.defaultModels,
      ownerUserId: auth.user.userId,
      overwrite: body.overwrite === true,
    });
    if (!stored.ok) {
      return c.json(
        { status: 'failure', message: stored.message },
        stored.status,
      );
    }

    return c.json({ status: 'success', provider_id: providerId });
  });

  app.get('/providers', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const rows = await c.env.DB.prepare(
      `SELECT id, name, models, oauth_vendor, oauth_expires_at, oauth_account_label,
              owner_only, owner_user_id, is_active
         FROM providers WHERE auth_type = 'oauth' ORDER BY id`,
    ).all<{
      id: string;
      name: string;
      models: string;
      oauth_vendor: string | null;
      oauth_expires_at: number | null;
      oauth_account_label: string | null;
      owner_only: number;
      owner_user_id: number | null;
      is_active: number;
    }>();

    return c.json({
      providers: (rows.results ?? []).map((r) => ({
        id: r.id,
        name: r.name,
        models: parseModelsJson(r.models),
        is_active: r.is_active,
        owner_only: r.owner_only,
        owner_user_id: r.owner_user_id,
        ...describeStatus(r),
      })),
    });
  });

  /**
   * Replace the routing model list. Subscription endpoints expose no /models
   * API, so this list is the only routing source and needs a manual editor.
   */
  app.post('/:id/models', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;

    const id = c.req.param('id');
    let body: { models?: unknown };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    if (
      !Array.isArray(body.models) ||
      !body.models.every((m) => typeof m === 'string' && m.trim())
    ) {
      return c.json(
        {
          status: 'failure',
          message: 'models must be an array of non-empty strings',
        },
        400,
      );
    }

    const row = await getOAuthProviderRow(c.env, id);
    if (!row || row.auth_type !== 'oauth') {
      return c.json(
        { status: 'failure', message: 'Not an OAuth provider' },
        404,
      );
    }

    const models = (body.models as string[]).map((m) => m.trim());
    await c.env.DB.prepare(`UPDATE providers SET models = ? WHERE id = ?`)
      .bind(JSON.stringify(models), id)
      .run();
    return c.json({ status: 'success', models });
  });

  /** Force a refresh, so the operator can verify a connection without traffic. */
  app.post('/:id/refresh', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;

    const id = c.req.param('id');
    const row = await getOAuthProviderRow(c.env, id);
    if (!row || row.auth_type !== 'oauth') {
      return c.json(
        { status: 'failure', message: 'Not an OAuth provider' },
        404,
      );
    }
    const adapter = getAdapter(row.oauth_vendor);
    if (!adapter) {
      return c.json(
        { status: 'failure', message: 'Unknown OAuth vendor' },
        400,
      );
    }
    const tokens = await decryptTokens(c.env, row);
    if (!tokens?.refresh_token) {
      return c.json(
        { status: 'failure', message: 'No refresh token stored' },
        400,
      );
    }

    try {
      const refreshed = await adapter.refresh(tokens);
      // Credential-only write: leaves the configured model list and ownership
      // untouched, and the version guard keeps it safe against a concurrent
      // refresh on the request path.
      const written = await persistTokens(
        c.env,
        row.id,
        refreshed,
        row.oauth_version,
      );
      if (!written) {
        return c.json(
          {
            status: 'failure',
            message: 'Credentials changed concurrently; retry',
          },
          409,
        );
      }
      return c.json({
        status: 'success',
        expires_at: new Date(refreshed.expires_at).toISOString(),
      });
    } catch (e) {
      return c.json(
        {
          status: 'failure',
          message: e instanceof Error ? e.message : 'Refresh failed',
        },
        502,
      );
    }
  });

  return app;
}
