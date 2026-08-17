-- Quota history and threshold alerts.
--
-- Reading a seat's limits live answers "how much is left right now", but only
-- for whoever is looking. The interesting moment — a weekly window crossing 90%
-- on a Friday evening — is exactly the one nobody is watching. A scheduled job
-- samples every connected seat, keeps the samples, and notifies on a crossing.
--
-- The history is also what turns a single instantaneous reading in the
-- dashboard into a trend.

CREATE TABLE IF NOT EXISTS quota_snapshots (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  provider_id  TEXT NOT NULL,
  -- Window id as the adapter reported it, e.g. 'five-hour', 'weekly'.
  window_id    TEXT NOT NULL,
  label        TEXT NOT NULL,
  used_percent REAL,
  -- Epoch ms the window refills, when the vendor says.
  resets_at    INTEGER,
  taken_at     INTEGER NOT NULL
);

-- Read as "the recent history of this window", which is the only access shape.
CREATE INDEX IF NOT EXISTS idx_quota_snapshots_window
  ON quota_snapshots(provider_id, window_id, taken_at DESC);
CREATE INDEX IF NOT EXISTS idx_quota_snapshots_taken ON quota_snapshots(taken_at);

-- The highest threshold each window has been notified about.
--
-- Without this a window sitting at 91% would notify on every single sample.
-- The level is cleared when usage falls back below the lowest threshold, which
-- is how a window that has reset becomes eligible to notify again.
CREATE TABLE IF NOT EXISTS quota_alerts (
  provider_id TEXT NOT NULL,
  window_id   TEXT NOT NULL,
  level       INTEGER NOT NULL,
  notified_at INTEGER NOT NULL,
  PRIMARY KEY (provider_id, window_id)
);
