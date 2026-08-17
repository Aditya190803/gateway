-- Provider health, rotation, and a request log that records failures.
--
-- Three problems this addresses, all of which appear as soon as more than one
-- credential can serve a model:
--
-- 1. A seat that has exhausted its vendor quota keeps being selected, so every
--    request fails until a human notices. Cooldown marks it unusable for a
--    while; routing skips it and picks another credential instead.
-- 2. Only the first matching provider was ever chosen, so a second seat for the
--    same model was dead weight. Weight makes the choice explicit.
-- 3. usage_logs only ever recorded successes, so "why did that fail" was
--    unanswerable after the fact.

-- Epoch ms until which routing should skip this provider. NULL = usable now.
ALTER TABLE providers ADD COLUMN cooldown_until INTEGER;

-- Why it is cooling down ('quota', 'auth', 'server'), for the admin UI.
ALTER TABLE providers ADD COLUMN cooldown_reason TEXT;

-- Consecutive failures. Reset to 0 by any success, so this counts a *run* of
-- failures rather than a lifetime total: the backoff and the auto-disable
-- threshold both key off it.
ALTER TABLE providers ADD COLUMN failure_count INTEGER NOT NULL DEFAULT 0;

ALTER TABLE providers ADD COLUMN last_failure_at INTEGER;
ALTER TABLE providers ADD COLUMN last_failure_message TEXT;

-- Set when the gateway deactivates a provider itself, so the UI can distinguish
-- "an admin turned this off" from "this credential kept being rejected".
ALTER TABLE providers ADD COLUMN disabled_reason TEXT;

-- Relative share of traffic among providers that can serve the same model.
-- 1 for everything existing, which is a plain even split.
ALTER TABLE providers ADD COLUMN weight INTEGER NOT NULL DEFAULT 1;

-- Request outcome. NULL on rows written before this migration, which is why
-- every query treats NULL as "succeeded" rather than as an error.
ALTER TABLE usage_logs ADD COLUMN status_code INTEGER;
ALTER TABLE usage_logs ADD COLUMN error_message TEXT;
ALTER TABLE usage_logs ADD COLUMN duration_ms INTEGER;

-- The log is read newest-first and filtered by outcome.
CREATE INDEX IF NOT EXISTS idx_usage_logs_created ON usage_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_providers_cooldown ON providers(cooldown_until);
