import { decryptProviderKey, encryptProviderKey } from '../encryption';
import type { ManagedEnv } from '../types';
import { getAdapter } from './registry';
import { isExpired, type OAuthAdapter, type OAuthTokens } from './types';

export type OAuthProviderRow = {
  id: string;
  name: string;
  auth_type: string;
  oauth_vendor: string | null;
  oauth_credentials: string | null;
  oauth_expires_at: number | null;
  oauth_account_label: string | null;
  oauth_version: number;
  owner_only: number;
  owner_user_id: number | null;
  is_active: number;
};

const OAUTH_COLUMNS = `id, name, auth_type, oauth_vendor, oauth_credentials,
  oauth_expires_at, oauth_account_label, oauth_version, owner_only,
  owner_user_id, is_active`;

export async function getOAuthProviderRow(
  env: ManagedEnv,
  providerId: string,
): Promise<OAuthProviderRow | null> {
  if (!env.DB) return null;
  const row = await env.DB.prepare(
    `SELECT ${OAUTH_COLUMNS} FROM providers WHERE id = ? AND is_active = 1 LIMIT 1`,
  )
    .bind(providerId)
    .first<OAuthProviderRow>();
  return row ?? null;
}

/**
 * Same row regardless of active state.
 *
 * Refreshing a credential must not require the seat to already be in service:
 * an auto-disabled seat's grant can be perfectly valid at the vendor, and
 * requiring a Reinstate click before Refresh would make recovery two manual
 * steps where one would do.
 */
export async function getOAuthProviderRowAnyState(
  env: ManagedEnv,
  providerId: string,
): Promise<OAuthProviderRow | null> {
  if (!env.DB) return null;
  const row = await env.DB.prepare(
    `SELECT ${OAUTH_COLUMNS} FROM providers WHERE id = ? AND auth_type = 'oauth' LIMIT 1`,
  )
    .bind(providerId)
    .first<OAuthProviderRow>();
  return row ?? null;
}

export function isOAuthProvider(row: { auth_type?: string | null }): boolean {
  return row.auth_type === 'oauth';
}

function encryptionSecret(env: ManagedEnv): string | null {
  const secret = env.PROVIDER_KEY_ENCRYPTION_KEY?.trim();
  if (!secret || secret.length < 16) return null;
  return secret;
}

export async function decryptTokens(
  env: ManagedEnv,
  row: OAuthProviderRow,
): Promise<OAuthTokens | null> {
  const secret = encryptionSecret(env);
  if (!secret || !row.oauth_credentials) return null;
  try {
    const plain = await decryptProviderKey(row.oauth_credentials, secret);
    return JSON.parse(plain) as OAuthTokens;
  } catch {
    return null;
  }
}

/**
 * Persist refreshed credentials, but only if the row is still on the version
 * the caller claimed. Callers reach this holding a claim from claimRefresh, so
 * a failure here means the row moved underneath them (an admin converted it, or
 * a claim expired) rather than an ordinary race.
 *
 * Returns false when the compare-and-swap did not match.
 */
export async function persistTokens(
  env: ManagedEnv,
  providerId: string,
  tokens: OAuthTokens,
  expectedVersion: number,
  accountLabel?: string | null,
): Promise<boolean> {
  const secret = encryptionSecret(env);
  if (!secret || !env.DB) return false;
  const encrypted = await encryptProviderKey(JSON.stringify(tokens), secret);
  const result = await env.DB.prepare(
    `UPDATE providers
       SET oauth_credentials = ?,
           oauth_expires_at = ?,
           oauth_account_label = COALESCE(?, oauth_account_label),
           oauth_version = oauth_version + 1
     WHERE id = ? AND oauth_version = ?`,
  )
    .bind(
      encrypted,
      tokens.expires_at,
      accountLabel ?? null,
      providerId,
      expectedVersion,
    )
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

export type ResolvedOAuth = {
  adapter: OAuthAdapter;
  tokens: OAuthTokens;
  row: OAuthProviderRow;
};

export type OAuthResolveError =
  | { kind: 'not_oauth' }
  | { kind: 'unknown_vendor'; vendor: string | null }
  | { kind: 'no_credentials' }
  | { kind: 'refresh_failed'; message: string };

/**
 * How long a waiter sits out someone else's in-flight refresh. A refresh is one
 * round trip to the vendor, so waiters normally return well inside this; the
 * budget only binds when the claimer is failing, and it caps how long a request
 * can be delayed by a credential that is dead anyway.
 */
const REFRESH_WAIT_MS = 3000;
const REFRESH_POLL_MS = 250;
/**
 * Claim, wait, retry once. The retry is what lets a request heal a claim whose
 * holder died; beyond that, failing fast beats stacking multi-second waits onto
 * a request that a broken credential cannot serve either way.
 */
const REFRESH_ATTEMPTS = 2;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Take exclusive ownership of the next refresh by bumping the version.
 *
 * This is the part a compare-and-swap on the *write* cannot do. These vendors
 * rotate refresh tokens, so two requests that both read version N and both call
 * the vendor with the same refresh token spend it twice: one rotation wins and
 * the other is invalidated — and under reuse detection the whole token family
 * can be revoked, which kills the seat until an operator reconnects it. Losing
 * the write race afterwards is too late; the damage happened at the vendor.
 *
 * So the claim happens before the network call. Exactly one caller can move the
 * row off version N, and only that caller talks to the vendor.
 *
 * A claimer that dies mid-refresh leaves the version bumped and the credentials
 * untouched, which is self-healing: the row is still expired, so the next
 * request claims the new version and retries.
 */
async function claimRefresh(
  env: ManagedEnv,
  providerId: string,
  version: number,
): Promise<boolean> {
  if (!env.DB) return false;
  const result = await env.DB.prepare(
    `UPDATE providers SET oauth_version = oauth_version + 1
      WHERE id = ? AND oauth_version = ?`,
  )
    .bind(providerId, version)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

/**
 * Wait for whoever holds the claim to publish fresh credentials.
 *
 * Returns null on timeout so the caller can claim and retry itself rather than
 * failing a request that a working credential could have served.
 */
async function waitForRefreshedTokens(
  env: ManagedEnv,
  providerId: string,
): Promise<{ row: OAuthProviderRow; tokens: OAuthTokens } | null> {
  const deadline = Date.now() + REFRESH_WAIT_MS;
  while (Date.now() < deadline) {
    await sleep(REFRESH_POLL_MS);
    const row = await getOAuthProviderRow(env, providerId);
    if (!row) return null;
    const tokens = await decryptTokens(env, row);
    if (tokens?.access_token && !isExpired(tokens.expires_at)) {
      return { row, tokens };
    }
  }
  return null;
}

/**
 * Load a provider's OAuth credentials, refreshing them first if they are at or
 * near expiry. Safe to call on every request: it only touches the network when
 * the access token is actually stale.
 */
export async function resolveOAuthCredential(
  env: ManagedEnv,
  providerId: string,
): Promise<
  { ok: true; value: ResolvedOAuth } | { ok: false; error: OAuthResolveError }
> {
  let lastRefreshError: string | null = null;

  for (let attempt = 0; attempt < REFRESH_ATTEMPTS; attempt++) {
    const row = await getOAuthProviderRow(env, providerId);
    if (!row || !isOAuthProvider(row)) {
      return { ok: false, error: { kind: 'not_oauth' } };
    }

    const adapter = getAdapter(row.oauth_vendor);
    if (!adapter) {
      return {
        ok: false,
        error: { kind: 'unknown_vendor', vendor: row.oauth_vendor },
      };
    }

    const tokens = await decryptTokens(env, row);
    if (!tokens?.access_token) {
      return { ok: false, error: { kind: 'no_credentials' } };
    }

    if (!isExpired(tokens.expires_at)) {
      return { ok: true, value: { adapter, tokens, row } };
    }

    if (!tokens.refresh_token) {
      return {
        ok: false,
        error: {
          kind: 'refresh_failed',
          message:
            'Access token expired and no refresh token is stored. Reconnect the account.',
        },
      };
    }

    if (!(await claimRefresh(env, providerId, row.oauth_version))) {
      // Another request is already refreshing. Spending the same refresh token
      // alongside it would invalidate one of the two rotations, so wait for its
      // result instead of racing it.
      const fresh = await waitForRefreshedTokens(env, providerId);
      if (fresh) {
        return {
          ok: true,
          value: { adapter, tokens: fresh.tokens, row: fresh.row },
        };
      }
      // It failed or is stuck. Loop round and try to claim it ourselves.
      continue;
    }

    let refreshed: OAuthTokens;
    try {
      refreshed = await adapter.refresh(tokens, env);
    } catch (e) {
      // The claim stays bumped, so the next request re-claims and retries
      // rather than reusing the refresh token we just spent.
      const raw = e instanceof Error ? e.message : 'Token refresh failed';
      // `invalid_grant` means the vendor revoked or expired the refresh
      // token itself, not a transient failure — retrying gets the same
      // answer forever. Naming that distinguishes it from every other error
      // here, which the operator can wait out.
      lastRefreshError = /invalid_grant/i.test(raw)
        ? `${raw} — the refresh token was revoked or expired at the vendor. Retrying will not fix this; reconnect the seat from Subscriptions.`
        : raw;
      return {
        ok: false,
        error: { kind: 'refresh_failed', message: lastRefreshError },
      };
    }

    // We hold the claim, so this writes against the version we bumped to.
    const claimedVersion = row.oauth_version + 1;
    const stored = await persistTokens(
      env,
      providerId,
      refreshed,
      claimedVersion,
    );
    // A failed write means the row moved (an admin converted it mid-refresh).
    // The tokens are still valid for this request, so serve it either way.
    return {
      ok: true,
      value: {
        adapter,
        tokens: refreshed,
        row: {
          ...row,
          oauth_version: stored ? claimedVersion + 1 : claimedVersion,
        },
      },
    };
  }

  return {
    ok: false,
    error: {
      kind: 'refresh_failed',
      message:
        lastRefreshError ??
        'Timed out waiting for a concurrent token refresh. Retry the request.',
    },
  };
}

/**
 * Re-activate a seat the gateway itself deactivated.
 *
 * Only automatic deactivations are lifted: `disabled_reason` is written by the
 * auth-failure auto-disable and by nothing else, so an operator's own manual
 * disable is never overridden. The failure run is cleared with it, so if the
 * credential really is still broken the next upstream 401 starts counting from
 * one — a broken seat re-disables itself after its own evidence, rather than
 * staying dead until someone clicks Reinstate.
 */
export async function reinstateIfAutoDisabled(
  db: D1Database,
  providerId: string,
): Promise<boolean> {
  if (!db) return false;
  const result = await db.prepare(
    `UPDATE providers
        SET is_active = 1,
            failure_count = 0,
            cooldown_until = NULL,
            cooldown_reason = NULL,
            disabled_reason = NULL
      WHERE id = ? AND is_active = 0 AND disabled_reason IS NOT NULL`,
  )
    .bind(providerId)
    .run();
  return (result.meta?.changes ?? 0) > 0;
}

/**
 * Refresh on demand, taking the same claim the request path takes so an
 * operator pressing "Refresh" cannot double-spend the token against a refresh
 * already in flight.
 */
export async function forceRefresh(
  env: ManagedEnv,
  providerId: string,
): Promise<{ ok: true; tokens: OAuthTokens } | { ok: false; message: string }> {
  // Any-state on purpose: see getOAuthProviderRowAnyState. A deactivated seat
  // is exactly the one whose credential most needs proving.
  const row = await getOAuthProviderRowAnyState(env, providerId);
  if (!row || !isOAuthProvider(row)) {
    return { ok: false, message: 'Not an OAuth provider' };
  }
  const adapter = getAdapter(row.oauth_vendor);
  if (!adapter) {
    return { ok: false, message: 'Unknown OAuth vendor' };
  }
  const tokens = await decryptTokens(env, row);
  if (!tokens?.refresh_token) {
    return { ok: false, message: 'No refresh token stored' };
  }
  if (!(await claimRefresh(env, providerId, row.oauth_version))) {
    return {
      ok: false,
      message: 'A refresh is already in flight for this provider; retry',
    };
  }

  let refreshed: OAuthTokens;
  try {
    refreshed = await adapter.refresh(tokens, env);
  } catch (e) {
    return {
      ok: false,
      message: e instanceof Error ? e.message : 'Refresh failed',
    };
  }

  const stored = await persistTokens(
    env,
    providerId,
    refreshed,
    row.oauth_version + 1,
  );
  if (!stored) {
    return { ok: false, message: 'Credentials changed concurrently; retry' };
  }
  return { ok: true, tokens: refreshed };
}
