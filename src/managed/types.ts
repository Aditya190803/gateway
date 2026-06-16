export type ManagedEnv = {
  DB: D1Database;
  PROVIDER_KEY_ENCRYPTION_KEY?: string;
  ADMIN_JWT_SECRET?: string;
  ENVIRONMENT?: string;
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
};