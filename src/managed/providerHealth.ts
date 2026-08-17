/**
 * Provider health: cooldown after failure, and auto-disable on a dead credential.
 *
 * A subscription seat has the quota of one interactive user, so it runs out.
 * Without this, an exhausted seat stays selected and every request to it fails
 * until someone notices. Health state turns that into a routing decision: a
 * provider that just failed is skipped for a while, and traffic goes to another
 * credential that can serve the same model.
 *
 * The state lives on the provider row rather than in memory because a Worker
 * isolate does not survive between requests — there is nowhere else to put it
 * that the next request would see.
 */

/** How an upstream response should be treated for health purposes. */
export type FailureKind = 'quota' | 'auth' | 'server';

/** Default cooldown for a vendor quota rejection that names no retry time. */
const QUOTA_COOLDOWN_MS = 5 * 60 * 1000;
const QUOTA_COOLDOWN_MAX_MS = 60 * 60 * 1000;
/** A rejected credential is not going to start working within seconds. */
const AUTH_COOLDOWN_MS = 5 * 60 * 1000;
/** Server errors are usually transient, so back off briefly and escalate. */
const SERVER_COOLDOWN_BASE_MS = 30 * 1000;
const SERVER_COOLDOWN_MAX_MS = 10 * 60 * 1000;

/**
 * Consecutive auth failures before the provider is deactivated.
 *
 * Only auth failures count toward this. A credential the vendor keeps rejecting
 * is broken and needs a human; an exhausted quota is not broken and must never
 * be disabled, or a seat would take itself out of service every time it hit its
 * weekly ceiling.
 */
const AUTH_FAILURES_BEFORE_DISABLE = 3;

/**
 * Classify an upstream status.
 *
 * Returns null for anything that is the caller's problem rather than the
 * provider's — a 400 for a malformed body says nothing about the credential,
 * and counting it would cool down a perfectly good seat.
 */
export function classifyStatus(status: number): FailureKind | null {
  if (status === 429) return 'quota';
  if (status === 401 || status === 403) return 'auth';
  // 402 is "payment required": the seat is out of credit, which behaves like a
  // quota ceiling rather than a broken credential.
  if (status === 402) return 'quota';
  if (status >= 500) return 'server';
  return null;
}

/** Whether another credential is worth trying for this failure. */
export function isRetryable(kind: FailureKind): boolean {
  // All three are: quota and auth are specific to the credential, and a 5xx
  // from one vendor host says nothing about a different one.
  return kind === 'quota' || kind === 'auth' || kind === 'server';
}

/**
 * How long to skip this provider.
 *
 * `Retry-After` is the vendor telling us exactly this, so it wins when present;
 * everything else is a backoff that grows with the run of failures.
 */
export function cooldownMs(
  kind: FailureKind,
  failureCount: number,
  retryAfter?: string | null
): number {
  if (kind === 'quota') {
    const seconds = parseRetryAfter(retryAfter);
    if (seconds !== null) {
      return Math.min(seconds * 1000, QUOTA_COOLDOWN_MAX_MS);
    }
    return QUOTA_COOLDOWN_MS;
  }
  if (kind === 'auth') return AUTH_COOLDOWN_MS;
  const escalated =
    SERVER_COOLDOWN_BASE_MS * 2 ** Math.max(0, failureCount - 1);
  return Math.min(escalated, SERVER_COOLDOWN_MAX_MS);
}

/** `Retry-After` is either delay-seconds or an HTTP date. Both are legal. */
function parseRetryAfter(value?: string | null): number | null {
  if (!value) return null;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return seconds;
  const date = Date.parse(value);
  if (Number.isNaN(date)) return null;
  return Math.max(0, Math.round((date - Date.now()) / 1000));
}

/**
 * Record a failed request against a provider and put it in cooldown.
 *
 * Best-effort by design: this runs after the response has been handed back, so
 * a write failure here must not surface to the caller, whose request already
 * succeeded or failed on its own terms.
 */
export async function recordProviderFailure(
  db: D1Database,
  providerId: string,
  kind: FailureKind,
  message: string,
  retryAfter?: string | null
): Promise<void> {
  try {
    const row = await db
      .prepare(`SELECT failure_count FROM providers WHERE id = ? LIMIT 1`)
      .bind(providerId)
      .first<{ failure_count: number | null }>();
    const failures = (row?.failure_count ?? 0) + 1;
    const until = Date.now() + cooldownMs(kind, failures, retryAfter);

    // Auto-disable only on a run of auth failures; see the constant's comment.
    const disable = kind === 'auth' && failures >= AUTH_FAILURES_BEFORE_DISABLE;
    if (disable) {
      await db
        .prepare(
          `UPDATE providers
              SET failure_count = ?, cooldown_until = ?, cooldown_reason = ?,
                  last_failure_at = ?, last_failure_message = ?,
                  is_active = 0,
                  disabled_reason = ?
            WHERE id = ?`
        )
        .bind(
          failures,
          until,
          kind,
          Date.now(),
          message.slice(0, 500),
          `Deactivated automatically after ${failures} consecutive authentication failures. Reconnect the account, then re-enable it.`,
          providerId
        )
        .run();
      return;
    }

    await db
      .prepare(
        `UPDATE providers
            SET failure_count = ?, cooldown_until = ?, cooldown_reason = ?,
                last_failure_at = ?, last_failure_message = ?
          WHERE id = ?`
      )
      .bind(
        failures,
        until,
        kind,
        Date.now(),
        message.slice(0, 500),
        providerId
      )
      .run();
  } catch {
    /* health tracking must never break the request path */
  }
}

/**
 * Clear the failure run after a request succeeds.
 *
 * Guarded on there being something to clear, so the overwhelmingly common case
 * (a healthy provider serving a request) costs a cheap no-op update rather than
 * a write on every single request.
 */
export async function recordProviderSuccess(
  db: D1Database,
  providerId: string
): Promise<void> {
  try {
    await db
      .prepare(
        `UPDATE providers
            SET failure_count = 0, cooldown_until = NULL, cooldown_reason = NULL
          WHERE id = ? AND (failure_count > 0 OR cooldown_until IS NOT NULL)`
      )
      .bind(providerId)
      .run();
  } catch {
    /* see recordProviderFailure */
  }
}

/** Admin override: put a provider back in service immediately. */
export async function clearProviderCooldown(
  db: D1Database,
  providerId: string
): Promise<void> {
  await db
    .prepare(
      `UPDATE providers
          SET failure_count = 0, cooldown_until = NULL, cooldown_reason = NULL,
              disabled_reason = NULL
        WHERE id = ?`
    )
    .bind(providerId)
    .run();
}

/** A routing candidate, as the proxy sees it. */
export type Candidate = {
  id: string;
  weight: number;
  cooldownUntil: number | null;
};

/**
 * Pick one provider from those that can serve the request.
 *
 * Healthy candidates are preferred and chosen by weight, so two seats with the
 * same weight split traffic evenly rather than the first one absorbing all of
 * it. When everything is cooling down the request is still served — by whichever
 * recovers soonest — because a stale cooldown is a guess and failing a request
 * on a guess is worse than trying.
 */
export function selectCandidate(
  candidates: Candidate[],
  now = Date.now(),
  random = Math.random
): string | null {
  if (!candidates.length) return null;

  const healthy = candidates.filter(
    (c) => c.cooldownUntil === null || c.cooldownUntil <= now
  );
  if (!healthy.length) {
    return candidates.reduce((best, c) =>
      (c.cooldownUntil ?? 0) < (best.cooldownUntil ?? 0) ? c : best
    ).id;
  }

  const total = healthy.reduce((sum, c) => sum + Math.max(1, c.weight), 0);
  let ticket = random() * total;
  for (const c of healthy) {
    ticket -= Math.max(1, c.weight);
    if (ticket <= 0) return c.id;
  }
  return healthy[healthy.length - 1].id;
}
