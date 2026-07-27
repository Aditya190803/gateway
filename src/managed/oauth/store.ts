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
 * Persist refreshed credentials, but only if nobody else refreshed first.
 *
 * Refresh tokens rotate on most of these vendors: if two in-flight requests
 * both refresh and both write, the older write resurrects a refresh token the
 * vendor has already invalidated and the next refresh fails. The version guard
 * makes the write a compare-and-swap so exactly one writer wins.
 *
 * Returns false when another writer won the race; the caller should re-read.
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

  let refreshed: OAuthTokens;
  try {
    refreshed = await adapter.refresh(tokens);
  } catch (e) {
    return {
      ok: false,
      error: {
        kind: 'refresh_failed',
        message: e instanceof Error ? e.message : 'Token refresh failed',
      },
    };
  }

  const won = await persistTokens(
    env,
    providerId,
    refreshed,
    row.oauth_version,
  );
  if (won) {
    return {
      ok: true,
      value: {
        adapter,
        tokens: refreshed,
        row: { ...row, oauth_version: row.oauth_version + 1 },
      },
    };
  }

  // Someone else refreshed while we were in flight. Their tokens are the live
  // ones; ours may already be invalidated by rotation, so re-read and use theirs.
  const fresh = await getOAuthProviderRow(env, providerId);
  const freshTokens = fresh ? await decryptTokens(env, fresh) : null;
  if (
    fresh &&
    freshTokens?.access_token &&
    !isExpired(freshTokens.expires_at)
  ) {
    return { ok: true, value: { adapter, tokens: freshTokens, row: fresh } };
  }

  return {
    ok: false,
    error: {
      kind: 'refresh_failed',
      message: 'Concurrent token refresh failed',
    },
  };
}
