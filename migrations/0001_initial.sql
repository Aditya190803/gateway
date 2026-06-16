-- Provider API keys (encrypted at rest)
CREATE TABLE IF NOT EXISTS providers (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  api_key    TEXT NOT NULL,
  models     TEXT NOT NULL DEFAULT '[]',
  is_active  INTEGER DEFAULT 1,
  created_at TEXT DEFAULT (datetime('now'))
);

-- Admin users (dashboard login)
CREATE TABLE IF NOT EXISTS users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TEXT DEFAULT (datetime('now'))
);

-- User-facing API keys
CREATE TABLE IF NOT EXISTS api_keys (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id          INTEGER NOT NULL DEFAULT 1,
  key_hash         TEXT UNIQUE NOT NULL,
  key_prefix       TEXT NOT NULL,
  label            TEXT DEFAULT '',
  is_active        INTEGER DEFAULT 1,
  rpm_limit        INTEGER,
  monthly_token_limit INTEGER,
  created_at       TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS usage_logs (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  api_key_id  INTEGER NOT NULL,
  model       TEXT NOT NULL,
  provider    TEXT NOT NULL,
  prompt_tokens  INTEGER DEFAULT 0,
  completion_tokens INTEGER DEFAULT 0,
  created_at  TEXT DEFAULT (datetime('now')),
  FOREIGN KEY (api_key_id) REFERENCES api_keys(id)
);

CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_usage_logs_key_time ON usage_logs(api_key_id, created_at);