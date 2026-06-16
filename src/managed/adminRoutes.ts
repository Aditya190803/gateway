import { Context, Hono } from 'hono';
import { encryptProviderKey } from './encryption';
import {
  generateUserApiKey,
  hashApiKey,
  keyPrefix,
} from './apiKeys';
import {
  createAdminToken,
  getAdminJwtSecret,
  getSessionTokenFromRequest,
  setAdminSessionCookie,
  verifyAdminToken,
} from './adminSession';
import {
  hashPassword,
  shouldUpgradePasswordHash,
  verifyPassword,
} from './password';
import { getProviderCatalogForAdmin } from './providerCatalog';
import {
  fetchLatestModelsForProvider,
  prefixesFromModelIds,
} from './fetchModels';
import { parseModelsJson } from './modelRouting';
import { generateInviteCode, hashInviteCode, invitePrefix } from './invites';
import type { ManagedEnv } from './types';

type AuthUser = { userId: number; email: string; role: 'admin' | 'user' };

async function requireSession(c: Context): Promise<
  | { ok: true; user: AuthUser }
  | { ok: false; response: Response }
> {
  const env = c.env as ManagedEnv;
  let secret: Uint8Array;
  try {
    secret = getAdminJwtSecret(env);
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'Admin auth misconfigured';
    return { ok: false, response: c.json({ status: 'failure', message: msg }, 500) };
  }
  const token = getSessionTokenFromRequest(c.req.raw);
  if (!token) {
    return {
      ok: false,
      response: c.json({ status: 'failure', message: 'Authentication required' }, 401),
    };
  }
  const session = await verifyAdminToken(token, secret);
  if (!session) {
    return {
      ok: false,
      response: c.json({ status: 'failure', message: 'Invalid or expired session' }, 401),
    };
  }
  return { ok: true, user: session };
}

async function requirePlatformAdmin(c: Context): Promise<
  | { ok: true; user: AuthUser }
  | { ok: false; response: Response }
> {
  const auth = await requireSession(c);
  if (!auth.ok) return auth;
  if (auth.user.role !== 'admin') {
    return {
      ok: false,
      response: c.json({ status: 'failure', message: 'Admin role required' }, 403),
    };
  }
  return auth;
}

function encryptionKey(env: ManagedEnv): string | null {
  const s = env.PROVIDER_KEY_ENCRYPTION_KEY?.trim();
  return s && s.length >= 16 ? s : null;
}

function userFilter(auth: AuthUser): { sql: string; binds: unknown[] } {
  return auth.role === 'admin'
    ? { sql: '', binds: [] }
    : { sql: ' AND k.user_id = ?', binds: [auth.userId] };
}

export function createAdminApp(): Hono<{ Bindings: ManagedEnv }> {
  const admin = new Hono<{ Bindings: ManagedEnv }>();

  admin.post('/login', async (c) => {
    const env = c.env;
    if (!env.DB) {
      return c.json({ status: 'failure', message: 'D1 not configured' }, 503);
    }
    let body: { email?: string; password?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON body' }, 400);
    }
    const email = body.email?.trim().toLowerCase();
    const password = body.password;
    if (!email || !password) {
      return c.json({ status: 'failure', message: 'email and password required' }, 400);
    }

    const user = await env.DB.prepare(
      `SELECT id, email, password_hash, role, is_active FROM users WHERE email = ?`
    )
      .bind(email)
      .first<{ id: number; email: string; password_hash: string; role: 'admin' | 'user'; is_active: number }>();

    if (!user || !user.is_active || !(await verifyPassword(password, user.password_hash))) {
      return c.json({ status: 'failure', message: 'Invalid credentials' }, 401);
    }

    if (shouldUpgradePasswordHash(user.password_hash)) {
      const upgraded = await hashPassword(password);
      await env.DB.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`)
        .bind(upgraded, user.id)
        .run();
    }

    let secret: Uint8Array;
    try {
      secret = getAdminJwtSecret(env);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'ADMIN_JWT_SECRET required';
      return c.json({ status: 'failure', message: msg }, 500);
    }

    const role = user.role === 'admin' ? 'admin' : 'user';
    const jwt = await createAdminToken(user.id, user.email, role, secret);
    c.header('Set-Cookie', setAdminSessionCookie(jwt));
    return c.json({ authenticated: true, email: user.email, role });
  });

  admin.post('/signup', async (c) => {
    const env = c.env;
    if (!env.DB) {
      return c.json({ status: 'failure', message: 'D1 not configured' }, 503);
    }
    let body: { email?: string; password?: string; invite_code?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    const email = body.email?.trim().toLowerCase();
    const password = body.password;
    const inviteCode = body.invite_code?.trim();
    if (!email || !password || password.length < 8 || !inviteCode) {
      return c.json(
        { status: 'failure', message: 'Valid email, invite code, and password (min 8 chars) required' },
        400
      );
    }

    const codeHash = await hashInviteCode(inviteCode);
    const invite = await env.DB.prepare(
      `SELECT id, max_uses, used_count, is_active, expires_at
       FROM invite_codes WHERE code_hash = ? LIMIT 1`
    )
      .bind(codeHash)
      .first<{ id: number; max_uses: number; used_count: number; is_active: number; expires_at: string | null }>();
    if (
      !invite ||
      !invite.is_active ||
      invite.used_count >= invite.max_uses ||
      (invite.expires_at && Date.parse(invite.expires_at) <= Date.now())
    ) {
      return c.json({ status: 'failure', message: 'Invalid or expired invite code' }, 403);
    }

    const ph = await hashPassword(password);
    try {
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, 'user', 1)`
        ).bind(email, ph),
        env.DB.prepare(
          `UPDATE invite_codes SET used_count = used_count + 1 WHERE id = ?`
        ).bind(invite.id),
      ]);
    } catch (e) {
      const msg = e instanceof Error && e.message.includes('UNIQUE')
        ? 'An account with this email already exists'
        : 'Could not create account';
      return c.json({ status: 'failure', message: msg }, 400);
    }

    return c.json({ status: 'success', message: 'Account created' });
  });

  admin.get('/session', async (c) => {
    const auth = await requireSession(c);
    if (!auth.ok) return auth.response;
    return c.json({ authenticated: true, email: auth.user.email, role: auth.user.role });
  });

  admin.post('/logout', async (c) => {
    c.header(
      'Set-Cookie',
      'ai_gateway_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'
    );
    return c.json({ authenticated: false });
  });

  admin.get('/provider-presets', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    return c.json({ presets: getProviderCatalogForAdmin() });
  });

  admin.get('/gateway-catalog', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    return c.json({ providers: getProviderCatalogForAdmin() });
  });

  admin.post('/providers/fetch-models', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    let body: { provider_id?: string; api_key?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    const id = body.provider_id?.trim().toLowerCase();
    const apiKey = body.api_key?.trim();
    if (!id || !apiKey) {
      return c.json(
        { status: 'failure', message: 'provider_id and api_key required' },
        400
      );
    }
    const result = await fetchLatestModelsForProvider(id, apiKey);
    const prefixes = prefixesFromModelIds(result.models.map((m) => m.id));
    return c.json({
      status: 'success',
      models: result.models,
      suggested_prefixes: prefixes,
      error: result.error,
    });
  });

  admin.post('/providers/:id/sync-models', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const enc = encryptionKey(c.env);
    if (!enc) {
      return c.json(
        { status: 'failure', message: 'PROVIDER_KEY_ENCRYPTION_KEY not set' },
        503
      );
    }
    const id = c.req.param('id');
    const row = await c.env.DB.prepare(
      `SELECT api_key FROM providers WHERE id = ? AND is_active = 1`
    )
      .bind(id)
      .first<{ api_key: string }>();
    if (!row) return c.json({ status: 'failure', message: 'Provider not found' }, 404);
    const { decryptProviderKey } = await import('./encryption');
    let apiKey: string;
    try {
      apiKey = await decryptProviderKey(row.api_key, enc);
    } catch {
      return c.json({ status: 'failure', message: 'Decrypt failed' }, 500);
    }
    const result = await fetchLatestModelsForProvider(id, apiKey);
    if (!result.models.length) {
      return c.json(
        {
          status: 'failure',
          message: result.error || 'Provider returned no models; existing prefixes were not changed.',
          model_count: 0,
        },
        502
      );
    }
    const prefixes = prefixesFromModelIds(result.models.map((m) => m.id));
    await c.env.DB.prepare(`UPDATE providers SET models = ? WHERE id = ?`)
      .bind(JSON.stringify(prefixes), id)
      .run();
    return c.json({
      status: 'success',
      model_count: result.models.length,
      prefixes,
      models: result.models.slice(0, 100),
      error: result.error,
    });
  });

  admin.get('/providers', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const rows = await c.env.DB.prepare(
      `SELECT id, name, models, is_active, created_at FROM providers ORDER BY id`
    ).all();
    const results = (rows.results ?? []).map((r) => ({
      ...r,
      models: parseModelsJson(String((r as { models: string }).models)),
      has_api_key: true,
    }));
    return c.json({ providers: results });
  });

  admin.post('/providers', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const enc = encryptionKey(c.env);
    if (!enc) {
      return c.json(
        { status: 'failure', message: 'PROVIDER_KEY_ENCRYPTION_KEY not set' },
        503
      );
    }
    let body: { id?: string; name?: string; api_key?: string; models?: string[]; is_active?: boolean };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    const id = body.id?.trim().toLowerCase();
    const name = body.name?.trim();
    const apiKey = body.api_key?.trim();
    if (!id || !name || !apiKey) {
      return c.json({ status: 'failure', message: 'id, name, and api_key are required' }, 400);
    }
    const modelsJson = JSON.stringify(body.models ?? []);
    const encrypted = await encryptProviderKey(apiKey, enc);
    const isActive = body.is_active === false ? 0 : 1;
    await c.env.DB.prepare(
      `INSERT INTO providers (id, name, api_key, models, is_active)
       VALUES (?, ?, ?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         name = excluded.name,
         api_key = excluded.api_key,
         models = excluded.models,
         is_active = excluded.is_active`
    )
      .bind(id, name, encrypted, modelsJson, isActive)
      .run();
    return c.json({ status: 'success', id });
  });

  admin.delete('/providers/:id', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const id = c.req.param('id');
    await c.env.DB.prepare(`DELETE FROM providers WHERE id = ?`).bind(id).run();
    return c.json({ status: 'success' });
  });

  admin.get('/users', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const rows = await c.env.DB.prepare(
      `SELECT id, email, role, is_active, created_at FROM users ORDER BY id DESC`
    ).all();
    return c.json({ users: rows.results ?? [] });
  });

  admin.get('/invites', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const rows = await c.env.DB.prepare(
      `SELECT id, label, max_uses, used_count, is_active, created_at, expires_at
       FROM invite_codes ORDER BY id DESC`
    ).all();
    return c.json({ invites: rows.results ?? [] });
  });

  admin.post('/invites', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    let body: { label?: string; max_uses?: number | null; expires_at?: string | null };
    try {
      body = await c.req.json();
    } catch {
      body = {};
    }
    const code = generateInviteCode();
    const codeHash = await hashInviteCode(code);
    const maxUses = Math.max(1, Math.min(Number(body.max_uses ?? 1) || 1, 1000));
    const result = await c.env.DB.prepare(
      `INSERT INTO invite_codes (code_hash, label, max_uses, created_by, expires_at)
       VALUES (?, ?, ?, ?, ?)`
    )
      .bind(codeHash, body.label ?? '', maxUses, auth.user.userId, body.expires_at ?? null)
      .run();
    return c.json({
      status: 'success',
      id: result.meta.last_row_id,
      invite_code: code,
      invite_prefix: invitePrefix(code),
      message: 'Copy this invite code now; it will not be shown again.',
    });
  });

  admin.delete('/invites/:id', async (c) => {
    const auth = await requirePlatformAdmin(c);
    if (!auth.ok) return auth.response;
    const id = parseInt(c.req.param('id'), 10);
    await c.env.DB.prepare(`UPDATE invite_codes SET is_active = 0 WHERE id = ?`)
      .bind(id)
      .run();
    return c.json({ status: 'success' });
  });

  admin.get('/api-keys', async (c) => {
    const auth = await requireSession(c);
    if (!auth.ok) return auth.response;
    const where = auth.user.role === 'admin' ? '' : 'WHERE k.user_id = ?';
    const binds = auth.user.role === 'admin' ? [] : [auth.user.userId];
    const rows = await c.env.DB.prepare(
      `SELECT k.id, k.key_prefix, k.label, k.is_active, k.rpm_limit, k.monthly_token_limit, k.created_at,
              u.email as user_email, k.user_id
       FROM api_keys k
       JOIN users u ON u.id = k.user_id
       ${where}
       ORDER BY k.id DESC`
    )
      .bind(...binds)
      .all();
    return c.json({ api_keys: rows.results ?? [] });
  });

  admin.post('/api-keys', async (c) => {
    const auth = await requireSession(c);
    if (!auth.ok) return auth.response;
    let body: { label?: string; rpm_limit?: number | null; monthly_token_limit?: number | null };
    try {
      body = await c.req.json();
    } catch {
      body = {};
    }
    const raw = generateUserApiKey();
    const kh = await hashApiKey(raw);
    const prefix = keyPrefix(raw);
    const rpmLimit = auth.user.role === 'admin' ? (body.rpm_limit ?? null) : null;
    const monthlyLimit = auth.user.role === 'admin' ? (body.monthly_token_limit ?? null) : null;
    const result = await c.env.DB.prepare(
      `INSERT INTO api_keys (user_id, key_hash, key_prefix, label, rpm_limit, monthly_token_limit)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(auth.user.userId, kh, prefix, body.label ?? '', rpmLimit, monthlyLimit)
      .run();
    return c.json({
      status: 'success',
      id: result.meta.last_row_id,
      api_key: raw,
      key_prefix: prefix,
      message: 'Store this key securely; it will not be shown again.',
    });
  });

  admin.delete('/api-keys/:id', async (c) => {
    const auth = await requireSession(c);
    if (!auth.ok) return auth.response;
    const id = parseInt(c.req.param('id'), 10);
    if (auth.user.role === 'admin') {
      await c.env.DB.prepare(`UPDATE api_keys SET is_active = 0 WHERE id = ?`)
        .bind(id)
        .run();
    } else {
      await c.env.DB.prepare(`UPDATE api_keys SET is_active = 0 WHERE id = ? AND user_id = ?`)
        .bind(id, auth.user.userId)
        .run();
    }
    return c.json({ status: 'success' });
  });

  admin.get('/usage', async (c) => {
    const auth = await requireSession(c);
    if (!auth.ok) return auth.response;
    const days = Math.min(parseInt(c.req.query('days') ?? '30', 10), 365);
    const window = `-${days} days`;
    const f = userFilter(auth.user);

    const summary = await c.env.DB.prepare(
      `SELECT COUNT(*) as requests,
              COALESCE(SUM(u.prompt_tokens), 0) as prompt_tokens,
              COALESCE(SUM(u.completion_tokens), 0) as completion_tokens
       FROM usage_logs u
       JOIN api_keys k ON k.id = u.api_key_id
       WHERE u.created_at >= datetime('now', ?)${f.sql}`
    )
      .bind(window, ...f.binds)
      .first();

    const byModel = await c.env.DB.prepare(
      `SELECT u.model, u.provider, COUNT(*) as requests,
              SUM(u.prompt_tokens) as prompt_tokens,
              SUM(u.completion_tokens) as completion_tokens
       FROM usage_logs u
       JOIN api_keys k ON k.id = u.api_key_id
       WHERE u.created_at >= datetime('now', ?)${f.sql}
       GROUP BY u.model, u.provider
       ORDER BY requests DESC
       LIMIT 50`
    )
      .bind(window, ...f.binds)
      .all();

    const byProvider = await c.env.DB.prepare(
      `SELECT u.provider, COUNT(*) as requests,
              SUM(u.prompt_tokens) as prompt_tokens,
              SUM(u.completion_tokens) as completion_tokens
       FROM usage_logs u
       JOIN api_keys k ON k.id = u.api_key_id
       WHERE u.created_at >= datetime('now', ?)${f.sql}
       GROUP BY u.provider
       ORDER BY requests DESC`
    )
      .bind(window, ...f.binds)
      .all();

    const byDay = await c.env.DB.prepare(
      `SELECT date(u.created_at) as day, COUNT(*) as requests,
              SUM(u.prompt_tokens) as prompt_tokens,
              SUM(u.completion_tokens) as completion_tokens
       FROM usage_logs u
       JOIN api_keys k ON k.id = u.api_key_id
       WHERE u.created_at >= datetime('now', ?)${f.sql}
       GROUP BY date(u.created_at)
       ORDER BY day ASC`
    )
      .bind(window, ...f.binds)
      .all();

    const byKey = await c.env.DB.prepare(
      `SELECT k.key_prefix, k.label, ${auth.user.role === 'admin' ? 'usr.email as user_email,' : ''}
              COUNT(*) as requests,
              SUM(u.prompt_tokens) as prompt_tokens,
              SUM(u.completion_tokens) as completion_tokens
       FROM usage_logs u
       JOIN api_keys k ON k.id = u.api_key_id
       JOIN users usr ON usr.id = k.user_id
       WHERE u.created_at >= datetime('now', ?)${f.sql}
       GROUP BY u.api_key_id
       ORDER BY requests DESC
       LIMIT 25`
    )
      .bind(window, ...f.binds)
      .all();

    return c.json({
      days,
      role: auth.user.role,
      summary,
      by_model: byModel.results ?? [],
      by_provider: byProvider.results ?? [],
      by_day: byDay.results ?? [],
      by_api_key: byKey.results ?? [],
    });
  });

  admin.get('/setup/status', async (c) => {
    const env = c.env;
    if (!env.DB) return c.json({ needs_setup: false, error: 'D1 not configured' }, 503);
    const count = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first<{ c: number }>();
    return c.json({ needs_setup: (count?.c ?? 0) === 0 });
  });

  admin.post('/setup', async (c) => {
    const env = c.env;
    if (!env.DB) return c.json({ status: 'failure', message: 'D1 not configured' }, 503);
    const count = await env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first<{ c: number }>();
    if ((count?.c ?? 0) > 0) return c.json({ status: 'failure', message: 'Setup already completed' }, 403);
    let body: { email?: string; password?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ status: 'failure', message: 'Invalid JSON' }, 400);
    }
    const email = body.email?.trim().toLowerCase();
    const password = body.password;
    if (!email || !password || password.length < 8) {
      return c.json({ status: 'failure', message: 'Valid email and password (min 8 chars) required' }, 400);
    }
    const ph = await hashPassword(password);
    await env.DB.prepare(
      `INSERT INTO users (email, password_hash, role, is_active) VALUES (?, ?, 'admin', 1)`
    )
      .bind(email, ph)
      .run();
    return c.json({ status: 'success', message: 'Admin user created' });
  });

  return admin;
}
