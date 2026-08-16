import { Context, Hono } from 'hono';
import { encryptProviderKey } from './encryption';
import { parseModelsJson } from './modelRouting';
import { getAdapter, listAdapters } from './oauth';
import { createPkcePair, generateState, parsePastedCode } from './oauth/pkce';
import {
  forceRefresh,
  getOAuthProviderRow,
  resolveOAuthCredential,
} from './oauth/store';
import type { OAuthAdapter, OAuthTokens } from './oauth/types';
import type { ManagedEnv } from './types';

type AuthUser = { userId: number; email: string; role: 'admin' | 'user' };
type Guard = (
  c: Context,
) => Promise<{ ok: true; user: AuthUser } | { ok: false; response: Response }>;

const STATE_TTL_MS = 10 * 60 * 1000;
/**
 * Base polling interval handed to a device poll. RFC 8628's `slow_down` is
 * relative to it, so it has to be a real interval rather than zero.
 */
const DEVICE_POLL_INTERVAL_MS = 5000;

/**
 * Every route here writes to or reads from D1. The admin app is mounted
 * unconditionally and the session guard is JWT-only, so a deployment missing
 * the binding reaches these handlers with a valid cookie and would otherwise
 * fail on `env.DB.prepare` with an opaque 500. Match the 503 that the rest of
 * the admin API returns.
 */
function requireDb(
  c: Context,
): { ok: true } | { ok: false; response: Response } {
  if ((c.env as ManagedEnv).DB) return { ok: true };
  return {
    ok: false,
    response: c.json(
      { status: 'failure', message: 'Database not configured' },
      503,
    ),
  };
}

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

/**
 * Work out which models a freshly connected account should route.
 *
 * An explicit list from the operator always wins. Otherwise ask the vendor what
 * this account can actually use, so nobody has to type model ids by hand, and
 * fall back to the adapter's seeded list when the vendor has no listing to give.
 */
async function resolveModels(
  adapter: OAuthAdapter,
  tokens: OAuthTokens,
  requested?: string[],
): Promise<{ models: string[]; discovered: boolean }> {
  if (requested?.length) return { models: requested, discovered: false };
  if (adapter.listModels) {
    try {
      const models = await adapter.listModels(tokens);
      if (models.length) return { models, discovered: true };
    } catch {
      // Best-effort: a missing or changed listing must not block connecting.
    }
  }
  return { models: adapter.defaultModels, discovered: false };
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
        supports_device_code: Boolean(a.device),
      })),
    });
  });

  /**
   * Begin a device authorization (RFC 8628), for a vendor with no redirect
   * worth using. The device code is the polling secret, so it stays here: only
   * the short user code and the verification URL go to the browser. It is
   * parked in oauth_states.code_verifier, the same role that column plays for
   * PKCE — the flow's secret, single-use and short-lived.
   */
  app.post('/device/start', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const db = requireDb(c);
    if (!db.ok) return db.response;

    let body: {
      vendor?: string;
      provider_id?: string;
      provider_name?: string;
      overwrite?: boolean;
    };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }

    const adapter = getAdapter(body.vendor);
    if (!adapter?.device) {
      return c.json(
        {
          status: 'failure',
          message: 'This vendor does not support device authorization',
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

    const collision = await checkProviderCollision(
      c.env,
      providerId,
      body.overwrite === true,
    );
    if (!collision.ok) {
      return c.json({ status: 'failure', message: collision.message }, 409);
    }

    let device;
    try {
      device = await adapter.device.start();
    } catch (e) {
      return c.json(
        {
          status: 'failure',
          message:
            e instanceof Error ? e.message : 'Device authorization failed',
        },
        502,
      );
    }

    const state = generateState();
    await c.env.DB.prepare(`DELETE FROM oauth_states WHERE expires_at < ?`)
      .bind(Date.now())
      .run();
    await c.env.DB.prepare(
      `INSERT INTO oauth_states
         (state, vendor, provider_id, provider_name, code_verifier, redirect_uri, created_by, expires_at)
       VALUES (?, ?, ?, ?, ?, '', ?, ?)`,
    )
      .bind(
        state,
        adapter.id,
        providerId,
        body.provider_name?.trim() || adapter.label,
        device.deviceCode,
        auth.user.userId,
        device.expiresAt,
      )
      .run();

    return c.json({
      status: 'success',
      state,
      user_code: device.userCode,
      verification_uri: device.verificationUri,
      verification_uri_complete: device.verificationUriComplete ?? null,
      interval_ms: device.intervalMs,
      expires_at: new Date(device.expiresAt).toISOString(),
    });
  });

  /**
   * Poll a device authorization once.
   *
   * The browser drives the loop rather than the Worker blocking on it: an
   * operator can take minutes to approve, far past what a request should hold
   * open. The pending row survives between polls, so the tab can be closed and
   * the connection resumed.
   */
  app.post('/device/poll', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const db = requireDb(c);
    if (!db.ok) return db.response;

    let body: { state?: string; models?: string[]; overwrite?: boolean };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    if (!body.state) {
      return c.json({ status: 'failure', message: 'state is required' }, 400);
    }

    const pending = await c.env.DB.prepare(
      `SELECT state, vendor, provider_id, provider_name, code_verifier, created_by, expires_at
         FROM oauth_states WHERE state = ? LIMIT 1`,
    )
      .bind(body.state)
      .first<{
        state: string;
        vendor: string;
        provider_id: string;
        provider_name: string;
        code_verifier: string;
        created_by: number | null;
        expires_at: number;
      }>();

    if (!pending) {
      return c.json(
        { status: 'failure', message: 'Unknown or already-used state' },
        400,
      );
    }
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
    if (pending.expires_at <= Date.now()) {
      await c.env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`)
        .bind(body.state)
        .run();
      return c.json(
        { status: 'failure', message: 'Device code expired; start again' },
        400,
      );
    }

    const adapter = getAdapter(pending.vendor);
    if (!adapter?.device) {
      return c.json(
        { status: 'failure', message: 'Unknown OAuth vendor' },
        400,
      );
    }

    let result;
    try {
      result = await adapter.device.poll(
        pending.code_verifier,
        DEVICE_POLL_INTERVAL_MS,
      );
    } catch (e) {
      // Terminal: expired, denied, or a protocol error. The attempt is spent.
      await c.env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`)
        .bind(body.state)
        .run();
      return c.json(
        {
          status: 'failure',
          message: e instanceof Error ? e.message : 'Authorization failed',
        },
        400,
      );
    }

    if (result.status === 'pending') {
      // Honours a slow_down from the vendor.
      return c.json({ status: 'pending', retry_in_ms: result.intervalMs });
    }

    // Authorized. Burn the state before storing, so it cannot be replayed.
    await c.env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`)
      .bind(body.state)
      .run();

    const stored = await storeConnectedAccount(c.env, {
      providerId: pending.provider_id,
      providerName: pending.provider_name,
      vendor: adapter.id,
      tokens: result.tokens,
      models: (await resolveModels(adapter, result.tokens, body.models)).models,
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

  /** Begin a PKCE flow. Returns the URL the operator should open. */
  app.post('/start', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const db = requireDb(c);
    if (!db.ok) return db.response;

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
    const db = requireDb(c);
    if (!db.ok) return db.response;

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

    // The operator may paste the bare code, "code#state", or the whole
    // redirect URL from the address bar of the page that failed to load.
    const pasted = parsePastedCode(body.code);
    if (!pasted.code) {
      return c.json(
        {
          status: 'failure',
          message:
            'No authorization code found. Paste the code, or the whole URL you were redirected to.',
        },
        400,
      );
    }
    // A state that came back with the code must be the one we issued; a
    // mismatch means this code belongs to a different authorization attempt.
    if (pasted.state && pasted.state !== pending.state) {
      return c.json(
        {
          status: 'failure',
          message:
            'That code came from a different authorization attempt. Start again.',
        },
        400,
      );
    }

    let tokens: OAuthTokens;
    try {
      tokens = await adapter.exchangeCode({
        code: pasted.code,
        codeVerifier: pending.code_verifier,
        redirectUri: pending.redirect_uri,
        state: pasted.state ?? pending.state,
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
      models: (await resolveModels(adapter, tokens, body.models)).models,
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
    const db = requireDb(c);
    if (!db.ok) return db.response;

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

    let tokens: OAuthTokens | null;
    try {
      tokens = adapter.importFromFile(blob);
    } catch (e) {
      // Right format, but unusable — the adapter's own message says why.
      return c.json(
        {
          status: 'failure',
          message: e instanceof Error ? e.message : 'Credentials are unusable',
        },
        400,
      );
    }
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
      models: (await resolveModels(adapter, tokens, body.models)).models,
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
    const db = requireDb(c);
    if (!db.ok) return db.response;
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
  /**
   * Re-ask the vendor which models this account can use and store the answer.
   *
   * Subscriptions gain and lose models over time, so this is the same
   * "Sync models" affordance API-key providers have, pointed at the
   * subscription's own listing rather than a metered one.
   */
  app.post('/:id/models/sync', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const db = requireDb(c);
    if (!db.ok) return db.response;

    const id = c.req.param('id');
    const resolved = await resolveOAuthCredential(c.env, id);
    if (!resolved.ok) {
      const err = resolved.error;
      return c.json(
        {
          status: 'failure',
          message:
            err.kind === 'refresh_failed'
              ? err.message
              : 'Not a connected OAuth provider',
        },
        err.kind === 'not_oauth' ? 404 : 502,
      );
    }

    const { adapter, tokens } = resolved.value;
    if (!adapter.listModels) {
      return c.json(
        {
          status: 'failure',
          message: `${adapter.label} does not publish a model list; edit the models manually.`,
        },
        400,
      );
    }

    let models: string[];
    try {
      models = await adapter.listModels(tokens);
    } catch (e) {
      return c.json(
        {
          status: 'failure',
          message: e instanceof Error ? e.message : 'Model listing failed',
        },
        502,
      );
    }

    // The vendor answering with nothing is not an error — it just has no list
    // to publish for this account. Keep what is configured and say so.
    if (!models.length) {
      const row = await c.env.DB.prepare(
        `SELECT models FROM providers WHERE id = ? LIMIT 1`,
      )
        .bind(id)
        .first<{ models: string }>();
      return c.json({
        status: 'unchanged',
        message: `${adapter.label} does not publish a model list for this account. The configured models were kept.`,
        models: parseModelsJson(row?.models ?? '[]'),
      });
    }

    await c.env.DB.prepare(`UPDATE providers SET models = ? WHERE id = ?`)
      .bind(JSON.stringify(models), id)
      .run();
    return c.json({ status: 'success', models });
  });

  app.post('/:id/models', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const db = requireDb(c);
    if (!db.ok) return db.response;

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
    const db = requireDb(c);
    if (!db.ok) return db.response;

    // Takes the same claim the request path takes, so pressing this while a
    // request-path refresh is in flight cannot spend the token twice. It is a
    // credential-only write: model list and ownership are left alone.
    const result = await forceRefresh(c.env, c.req.param('id'));
    if (!result.ok) {
      const status = result.message === 'Not an OAuth provider' ? 404 : 502;
      return c.json({ status: 'failure', message: result.message }, status);
    }
    return c.json({
      status: 'success',
      expires_at: new Date(result.tokens.expires_at).toISOString(),
    });
  });

  return app;
}
