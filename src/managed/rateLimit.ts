import type { ApiKeyRecord } from './types';

const WINDOW_MS = 60_000;
const BUCKET_MS = 10_000;
const BUCKET_COUNT = WINDOW_MS / BUCKET_MS;

function bucketKey(apiKeyId: number, bucketIndex: number): string {
  return `rpm:${apiKeyId}:${bucketIndex}`;
}

/** Sliding-window RPM using D1 (10s buckets, 6 buckets = 60s). */
async function countSlidingWindowRpm(
  db: D1Database,
  apiKeyId: number,
  nowMs: number = Date.now()
): Promise<number> {
  const currentBucket = Math.floor(nowMs / BUCKET_MS);
  let total = 0;
  const stmts: D1PreparedStatement[] = [];
  for (let i = 0; i < BUCKET_COUNT; i++) {
    const idx = currentBucket - i;
    stmts.push(
      db
        .prepare(`SELECT count FROM rate_limit_buckets WHERE key = ?`)
        .bind(bucketKey(apiKeyId, idx))
    );
  }
  const results = await db.batch(stmts);
  for (const r of results) {
    const row = r.results?.[0] as { count?: number } | undefined;
    total += row?.count ?? 0;
  }
  return total;
}

export async function recordRequestForRpm(
  db: D1Database,
  apiKeyId: number,
  nowMs: number = Date.now()
): Promise<void> {
  const bucketIndex = Math.floor(nowMs / BUCKET_MS);
  const key = bucketKey(apiKeyId, bucketIndex);
  await db
    .prepare(
      `INSERT INTO rate_limit_buckets (key, count, updated_at)
       VALUES (?, 1, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET
         count = count + 1,
         updated_at = datetime('now')`
    )
    .bind(key)
    .run();
  await db
    .prepare(
      `DELETE FROM rate_limit_buckets WHERE key LIKE ? AND updated_at < datetime('now', '-3 minutes')`
    )
    .bind(`rpm:${apiKeyId}:%`)
    .run()
    .catch(() => {});
}

export async function checkRateLimits(
  db: D1Database,
  key: ApiKeyRecord
): Promise<{ ok: true } | { ok: false; message: string; status: number }> {
  if (key.rpm_limit != null && key.rpm_limit > 0) {
    const count = await countSlidingWindowRpm(db, key.id);
    if (count >= key.rpm_limit) {
      return {
        ok: false,
        message: 'Rate limit exceeded (requests per minute)',
        status: 429,
      };
    }
  }

  if (key.monthly_token_limit != null && key.monthly_token_limit > 0) {
    const row = await db
      .prepare(
        `SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0) as t
         FROM usage_logs
         WHERE api_key_id = ?
           AND created_at >= datetime('now', 'start of month')`
      )
      .bind(key.id)
      .first<{ t: number }>();
    const tokens = row?.t ?? 0;
    if (tokens >= key.monthly_token_limit) {
      return {
        ok: false,
        message: 'Monthly token limit exceeded',
        status: 429,
      };
    }
  }

  return { ok: true };
}