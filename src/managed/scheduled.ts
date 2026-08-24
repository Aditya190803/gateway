/**
 * Scheduled maintenance: quota sampling, threshold alerts, and log retention.
 *
 * Everything here runs on a Cron Trigger rather than on the request path,
 * because none of it belongs to any particular request and all of it is slow
 * relative to one — a quota sample is a round trip per connected seat.
 *
 * Failures are contained per seat and per task. A vendor that is down must not
 * stop the other seats from being sampled, and neither must stop the logs from
 * being pruned; a scheduled run that half-works is far better than one that
 * aborts on the first error and leaves the table growing.
 */

import { forceRefresh, reinstateIfAutoDisabled, resolveOAuthCredential } from './oauth';
import { REFRESH_SKEW_MS } from './oauth/types';
import type { QuotaSnapshot } from './oauth/quota';
import type { ManagedEnv } from './types';

/**
 * Usage levels worth telling someone about, highest first.
 *
 * A seat at 75% of a weekly window on a Monday is worth knowing; at 100% it has
 * already started refusing requests, which is worth knowing loudly.
 */
const ALERT_LEVELS = [100, 90, 75];

/** How long request rows are kept before pruning, unless configured otherwise. */
const DEFAULT_LOG_RETENTION_DAYS = 30;
/** Quota history outlives request logs: it is small and the trend is the point. */
const SNAPSHOT_RETENTION_DAYS = 90;

/**
 * Refresh any access token expiring inside this window.
 *
 * The cron runs hourly, so a two-hour horizon means every token is refreshed
 * at least an hour before its expiry-minus-skew moment — an idle weekend no
 * longer turns the first Monday request into a synchronous refresh, or into
 * the auth failures that get a seat deactivated.
 */
const PROACTIVE_REFRESH_MS = 2 * 60 * 60 * 1000;

/** Rows deleted per pass, so one run cannot exceed D1's statement limits. */
const PRUNE_BATCH = 5000;

export type ScheduledReport = {
  seatsSampled: number;
  windowsRecorded: number;
  alertsRaised: number;
  tokensRefreshed: number;
  seatsReinstated: number;
  logsPruned: number;
  snapshotsPruned: number;
  errors: string[];
};

function retentionDays(env: ManagedEnv): number {
  const raw = Number(env.LOG_RETENTION_DAYS);
  if (!Number.isFinite(raw) || raw < 1) return DEFAULT_LOG_RETENTION_DAYS;
  // A year of per-request rows is already more than D1 wants to hold.
  return Math.min(Math.floor(raw), 365);
}

/** The highest threshold this reading has reached, or 0 for none. */
export function alertLevelFor(usedPercent: number | null): number {
  if (usedPercent === null) return 0;
  return ALERT_LEVELS.find((level) => usedPercent >= level) ?? 0;
}

/**
 * Post an alert to whatever the operator configured.
 *
 * One JSON body carries both `text` and `content`, which covers Slack and
 * Discord webhooks respectively without asking anyone to say which they use.
 * A plain HTTP endpoint gets both and can read either.
 */
async function notify(env: ManagedEnv, message: string): Promise<void> {
  const url = env.ALERT_WEBHOOK_URL?.trim();
  if (!url) return;
  await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ text: message, content: message }),
    signal: AbortSignal.timeout(10000),
  });
}

/** Seats that can report their own limits. */
async function connectedSeats(
  env: ManagedEnv
): Promise<{ id: string; name: string }[]> {
  const rows = await env.DB.prepare(
    `SELECT id, name FROM providers
      WHERE auth_type = 'oauth' AND is_active = 1
      ORDER BY id`
  ).all<{ id: string; name: string }>();
  return rows.results ?? [];
}

/**
 * Active seats whose stored access token expires within the proactive
 * horizon (or has already passed it).
 */
async function seatsWithExpiringTokens(
  env: ManagedEnv
): Promise<{ id: string; name: string }[]> {
  const deadline = Date.now() + REFRESH_SKEW_MS + PROACTIVE_REFRESH_MS;
  const rows = await env.DB.prepare(
    `SELECT id, name FROM providers
      WHERE auth_type = 'oauth' AND is_active = 1
        AND oauth_expires_at IS NOT NULL AND oauth_expires_at <= ?
      ORDER BY id`
  )
    .bind(deadline)
    .all<{ id: string; name: string }>();
  return rows.results ?? [];
}

/**
 * Seats the gateway itself deactivated after consecutive auth failures.
 *
 * A successful refresh proves the account's grant is still valid at the
 * vendor, which is exactly the evidence an automatic deactivation was missing,
 * so the seat goes straight back into rotation. One that was revoked by the
 * vendor keeps failing the refresh and stays out.
 */
async function autoDisabledSeats(
  env: ManagedEnv
): Promise<{ id: string; name: string }[]> {
  const rows = await env.DB.prepare(
    `SELECT id, name FROM providers
      WHERE auth_type = 'oauth' AND is_active = 0
        AND disabled_reason IS NOT NULL
      ORDER BY id`
  ).all<{ id: string; name: string }>();
  return rows.results ?? [];
}

/**
 * Refresh one seat's credentials out-of-band.
 *
 * Returns true when the token changed; a failed refresh is reported into the
 * run's errors and returns false, so callers can gate follow-up actions
 * (reinstatement) on actual success.
 */
async function refreshTokenForSeat(
  env: ManagedEnv,
  seat: { id: string; name: string },
  report: ScheduledReport
): Promise<boolean> {
  const result = await forceRefresh(env, seat.id);
  if (!result.ok) {
    report.errors.push(`${seat.id}: refresh failed — ${result.message}`);
    return false;
  }
  report.tokensRefreshed++;
  return true;
}

/**
 * Record one seat's windows and raise any threshold crossings.
 *
 * Alerting is per window rather than per seat: a Claude account can be fine on
 * its 5-hour window and out of weekly Opus, and collapsing those into one
 * "seat is at 96%" would hide which limit actually bit.
 */
async function sampleSeat(
  env: ManagedEnv,
  seat: { id: string; name: string },
  report: ScheduledReport
): Promise<void> {
  const resolved = await resolveOAuthCredential(env, seat.id);
  if (!resolved.ok) {
    report.errors.push(`${seat.id}: credential unavailable`);
    return;
  }
  const { adapter, tokens } = resolved.value;
  if (!adapter.fetchQuota) return;

  let quota: QuotaSnapshot;
  try {
    quota = await adapter.fetchQuota(tokens);
  } catch (e) {
    report.errors.push(
      `${seat.id}: ${e instanceof Error ? e.message : 'usage lookup failed'}`
    );
    return;
  }

  report.seatsSampled++;
  const takenAt = Date.now();

  const previous = await env.DB.prepare(
    `SELECT window_id, level FROM quota_alerts WHERE provider_id = ?`
  )
    .bind(seat.id)
    .all<{ window_id: string; level: number }>();
  const lastLevel = new Map(
    (previous.results ?? []).map((r) => [r.window_id, r.level])
  );

  for (const window of quota.windows) {
    await env.DB.prepare(
      `INSERT INTO quota_snapshots
         (provider_id, window_id, label, used_percent, resets_at, taken_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    )
      .bind(
        seat.id,
        window.id,
        window.label,
        window.usedPercent,
        window.resetsAt,
        takenAt
      )
      .run();
    report.windowsRecorded++;

    const level = alertLevelFor(window.usedPercent);
    const before = lastLevel.get(window.id) ?? 0;
    if (level === before) continue;

    // Only a rise is news. A fall means the window reset, which is recorded so
    // the next rise notifies again, but nobody needs telling about it.
    if (level > before) {
      const percent = Math.round(window.usedPercent ?? 0);
      await notify(
        env,
        `${seat.name} (${seat.id}) — ${window.label} is at ${percent}% of its limit.` +
          (window.resetsAt
            ? ` Resets ${new Date(window.resetsAt).toISOString()}.`
            : '')
      ).catch(() => {
        report.errors.push(`${seat.id}: alert delivery failed`);
      });
      report.alertsRaised++;
    }

    await env.DB.prepare(
      `INSERT INTO quota_alerts (provider_id, window_id, level, notified_at)
       VALUES (?, ?, ?, ?)
       ON CONFLICT(provider_id, window_id) DO UPDATE SET
         level = excluded.level,
         notified_at = excluded.notified_at`
    )
      .bind(seat.id, window.id, level, takenAt)
      .run();
  }
}

/**
 * Delete rows past their retention window.
 *
 * Bounded per call rather than "delete everything older than X": a first run
 * against a long-neglected table would otherwise be a single enormous statement.
 * Whatever is left is picked up by the next run.
 */
async function prune(
  env: ManagedEnv,
  table: 'usage_logs' | 'quota_snapshots',
  cutoffSql: string,
  binds: unknown[]
): Promise<number> {
  const result = await env.DB.prepare(
    `DELETE FROM ${table} WHERE id IN (
       SELECT id FROM ${table} WHERE ${cutoffSql} LIMIT ${PRUNE_BATCH}
     )`
  )
    .bind(...binds)
    .run();
  return result.meta?.changes ?? 0;
}

/**
 * One scheduled pass.
 *
 * Returns a report rather than logging it, so the caller decides what to do
 * with it — the Worker's scheduled handler prints it, and a test can assert on
 * it.
 */
export async function runScheduled(env: ManagedEnv): Promise<ScheduledReport> {
  const report: ScheduledReport = {
    seatsSampled: 0,
    windowsRecorded: 0,
    alertsRaised: 0,
    tokensRefreshed: 0,
    seatsReinstated: 0,
    logsPruned: 0,
    snapshotsPruned: 0,
    errors: [],
  };
  if (!env.DB) {
    report.errors.push('D1 not configured');
    return report;
  }

  // Heal deactivated seats before anything reads the active set, so a seat
  // this run revives can also be sampled below instead of waiting an hour.
  let disabled: { id: string; name: string }[] = [];
  try {
    disabled = await autoDisabledSeats(env);
  } catch (e) {
    report.errors.push(
      `disabled-seat listing failed: ${e instanceof Error ? e.message : 'unknown'}`
    );
  }
  // Sequential like sampling below: one refresh round trip per seat, spaced
  // out, is not the burst pattern vendors rate-limit desktop clients for.
  for (const seat of disabled) {
    try {
      if (
        (await refreshTokenForSeat(env, seat, report)) &&
        (await reinstateIfAutoDisabled(env.DB, seat.id))
      ) {
        report.seatsReinstated++;
      }
    } catch (e) {
      report.errors.push(
        `${seat.id}: ${e instanceof Error ? e.message : 'recovery failed'}`
      );
    }
  }

  // Refresh tokens nearing expiry so requests never meet a stale one.
  let expiring: { id: string; name: string }[] = [];
  try {
    expiring = await seatsWithExpiringTokens(env);
  } catch (e) {
    report.errors.push(
      `expiry scan failed: ${e instanceof Error ? e.message : 'unknown'}`
    );
  }
  for (const seat of expiring) {
    try {
      await refreshTokenForSeat(env, seat, report);
    } catch (e) {
      report.errors.push(
        `${seat.id}: ${e instanceof Error ? e.message : 'refresh crashed'}`
      );
    }
  }

  let seats: { id: string; name: string }[] = [];
  try {
    seats = await connectedSeats(env);
  } catch (e) {
    report.errors.push(
      `seat listing failed: ${e instanceof Error ? e.message : 'unknown'}`
    );
  }

  // Sequential on purpose: these are vendor endpoints operated for a desktop
  // client, and a burst of parallel requests from one account is exactly the
  // pattern that gets a seat rate-limited.
  for (const seat of seats) {
    try {
      await sampleSeat(env, seat, report);
    } catch (e) {
      report.errors.push(
        `${seat.id}: ${e instanceof Error ? e.message : 'sampling failed'}`
      );
    }
  }

  try {
    report.logsPruned = await prune(
      env,
      'usage_logs',
      `created_at < datetime('now', ?)`,
      [`-${retentionDays(env)} days`]
    );
  } catch (e) {
    report.errors.push(
      `log pruning failed: ${e instanceof Error ? e.message : 'unknown'}`
    );
  }

  try {
    report.snapshotsPruned = await prune(
      env,
      'quota_snapshots',
      `taken_at < ?`,
      [Date.now() - SNAPSHOT_RETENTION_DAYS * 86400_000]
    );
  } catch (e) {
    report.errors.push(
      `snapshot pruning failed: ${e instanceof Error ? e.message : 'unknown'}`
    );
  }

  return report;
}
