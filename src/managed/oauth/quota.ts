/**
 * Vendor-side usage limits for a connected subscription.
 *
 * This is the seat's own quota — the rolling windows the vendor's client shows
 * you — not the gateway's request log. The two answer different questions:
 * `/admin/usage` says what this gateway spent, this says how much of the
 * subscription is left before the vendor starts refusing requests.
 *
 * None of these endpoints are public API. They are the ones the vendor's own CLI
 * calls, so they can change shape or disappear without notice; every parser here
 * treats a missing field as "not reported" rather than an error, and a whole
 * failed fetch surfaces as an error on one seat instead of breaking the page.
 */

/** One rolling limit window, normalized across vendors. */
export type QuotaWindow = {
  id: string;
  label: string;
  /** Percent of the window consumed, 0–100. Null when not reported. */
  usedPercent: number | null;
  /** Epoch ms at which the window refills. Null when not reported. */
  resetsAt: number | null;
  /** Window length in hours, so the UI can say "of 5h" without guessing. */
  periodHours: number | null;
};

/**
 * What one seat's limits look like right now.
 *
 * `notes` carries the vendor facts that are not a window — pay-as-you-go
 * credits, spend caps, reset credits — as already-formatted lines, because they
 * differ too much per vendor to model and only ever get displayed.
 */
export type QuotaSnapshot = {
  plan: string | null;
  windows: QuotaWindow[];
  notes: string[];
  /** Epoch ms the snapshot was taken, so a cached view can date itself. */
  fetchedAt: number;
  /**
   * A vendor-side lever the operator can pull from the dashboard, when the
   * vendor offers one — Codex sells credits that clear a rate-limit window
   * early. `available` false still renders, so the affordance is discoverable
   * before it can be used rather than appearing from nowhere.
   */
  action?: { id: string; label: string; available: boolean };
};

const QUOTA_TIMEOUT_MS = 10000;

export const HOUR = 1;
export const DAY = 24;
export const WEEK = 24 * 7;

/**
 * GET a vendor usage endpoint and parse the JSON.
 *
 * Bounded like every other outbound call on the admin path: a vendor that
 * accepts the connection and stalls would otherwise hold the request open until
 * the platform kills it.
 */
export async function getJson<T>(
  url: string,
  headers: Record<string, string>,
): Promise<T> {
  const res = await fetch(url, {
    headers: { accept: 'application/json', ...headers },
    signal: AbortSignal.timeout(QUOTA_TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `Usage lookup failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error('Usage endpoint did not return JSON');
  }
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

/** Vendors send percentages as numbers or numeric strings, interchangeably. */
export function num(value: unknown): number | null {
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

export function str(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

/** Absolute reset instant, from an RFC 3339 string or an epoch (s or ms). */
export function resetMs(value: unknown): number | null {
  const n = num(value);
  if (n !== null) {
    // Anything below ~year 2001 in ms is really a seconds-since-epoch value.
    return n > 1e11 ? n : n * 1000;
  }
  const s = str(value);
  if (!s) return null;
  const parsed = Date.parse(s);
  return Number.isNaN(parsed) ? null : parsed;
}

/** Reset instant from a "seconds from now" offset, which Codex prefers. */
export function resetFromOffset(
  seconds: unknown,
  now = Date.now(),
): number | null {
  const n = num(seconds);
  return n === null ? null : now + n * 1000;
}

/** Human label for a window length, used when the vendor names no window. */
export function periodLabel(hours: number | null): string {
  if (hours === null) return 'window';
  if (hours < 24) return `${Math.round(hours)}h`;
  const days = hours / 24;
  return days === 7 ? 'weekly' : `${Math.round(days)}d`;
}
