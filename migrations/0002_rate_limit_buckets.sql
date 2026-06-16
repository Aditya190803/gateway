CREATE TABLE IF NOT EXISTS rate_limit_buckets (
  key        TEXT PRIMARY KEY,
  count      INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_updated ON rate_limit_buckets(updated_at);