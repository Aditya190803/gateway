export type ManagedEnv = {
  DB: D1Database;
  PROVIDER_KEY_ENCRYPTION_KEY?: string;
  ADMIN_JWT_SECRET?: string;
  ENVIRONMENT?: string;
  /**
   * Where quota alerts are posted. Slack and Discord webhook URLs both work as
   * they are; anything else receives the same JSON. Unset means no alerts,
   * which is the default — sampling and history still run.
   */
  ALERT_WEBHOOK_URL?: string;
  /** Days of request log kept by the scheduled prune. Defaults to 30. */
  LOG_RETENTION_DAYS?: string;
  /**
   * Antigravity's Google client credentials, read out of its desktop client.
   * Not committed: they belong to Google, not to this project. Without them the
   * Antigravity adapter refuses to authorize or refresh, and says so.
   */
  ANTIGRAVITY_CLIENT_ID?: string;
  ANTIGRAVITY_CLIENT_SECRET?: string;
};

export type ApiKeyRecord = {
  id: number;
  user_id: number;
  key_hash: string;
  key_prefix: string;
  label: string;
  is_active: number;
  rpm_limit: number | null;
  monthly_token_limit: number | null;
};

export type ProviderRecord = {
  id: string;
  name: string;
  api_key: string;
  models: string;
  is_active: number;
  /** 'api_key' (default) or 'oauth'. See migrations/0004_provider_oauth.sql. */
  auth_type?: string;
  oauth_vendor?: string | null;
  oauth_credentials?: string | null;
  oauth_expires_at?: number | null;
  oauth_account_label?: string | null;
  oauth_version?: number;
  owner_only?: number;
  owner_user_id?: number | null;
};