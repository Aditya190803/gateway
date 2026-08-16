-- OAuth-backed providers.
--
-- Existing providers authenticate with a metered API key stored (encrypted) in
-- providers.api_key. An OAuth provider instead authenticates with a
-- subscription account's access/refresh token pair, which must be refreshed
-- before expiry. Both live in the same table, discriminated by auth_type.
--
-- providers.api_key is NOT NULL on the original schema and SQLite cannot relax
-- that in place, so OAuth rows store '' there and keep credentials in
-- oauth_credentials instead.

ALTER TABLE providers ADD COLUMN auth_type TEXT NOT NULL DEFAULT 'api_key';

-- Adapter that owns this credential, e.g. 'anthropic-claude-code',
-- 'openai-codex'. Distinct from providers.id so a user can connect several
-- accounts of the same vendor.
ALTER TABLE providers ADD COLUMN oauth_vendor TEXT;

-- Encrypted JSON blob: access_token, refresh_token, scope, account_id, extra.
-- Same AES-256-GCM envelope as api_key (src/managed/encryption.ts).
ALTER TABLE providers ADD COLUMN oauth_credentials TEXT;

-- Access-token expiry, epoch ms, stored in plaintext so the hot path can decide
-- whether a refresh is needed without decrypting first.
ALTER TABLE providers ADD COLUMN oauth_expires_at INTEGER;

-- Display-only: which account is connected (email, plan tier).
ALTER TABLE providers ADD COLUMN oauth_account_label TEXT;

-- Bumped on every successful credential write. Used as a compare-and-swap guard
-- so two concurrent requests cannot both spend a rotating refresh token.
ALTER TABLE providers ADD COLUMN oauth_version INTEGER NOT NULL DEFAULT 0;

-- A subscription seat is licensed to one person, so OAuth providers are created
-- with owner_only = 1 and are reachable only by keys belonging to owner_user_id.
-- The column defaults to 0 so existing API-key providers keep working unchanged;
-- the restriction is opt-in and applied at creation time, not retroactively.
ALTER TABLE providers ADD COLUMN owner_only INTEGER NOT NULL DEFAULT 0;
ALTER TABLE providers ADD COLUMN owner_user_id INTEGER;

-- In-flight PKCE authorization attempts. Rows are single-use and short-lived.
CREATE TABLE IF NOT EXISTS oauth_states (
  state         TEXT PRIMARY KEY,
  vendor        TEXT NOT NULL,
  provider_id   TEXT NOT NULL,
  provider_name TEXT NOT NULL DEFAULT '',
  code_verifier TEXT NOT NULL,
  redirect_uri  TEXT NOT NULL,
  created_by    INTEGER,
  created_at    TEXT DEFAULT (datetime('now')),
  expires_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_states_expiry ON oauth_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_providers_auth_type ON providers(auth_type);
