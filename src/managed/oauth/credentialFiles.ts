/**
 * Helpers for reading pasted credential files.
 *
 * Operators arrive with whichever JSON their tooling wrote: the vendor CLI's own
 * file, or the auth file a proxy like CLIProxyAPI saved after running the login
 * for them. Those share a flat `access_token` / `refresh_token` / `id_token` /
 * `expired` shape, while the native CLI files each nest things differently.
 * These helpers let an adapter accept both without repeating the same defensive
 * parsing five times.
 */

export function asRecord(blob: unknown): Record<string, unknown> | null {
  if (!blob || typeof blob !== 'object' || Array.isArray(blob)) return null;
  return blob as Record<string, unknown>;
}

/** First key that holds a non-empty string. */
export function pickString(
  obj: Record<string, unknown>,
  ...keys: string[]
): string | undefined {
  for (const key of keys) {
    const value = obj[key];
    if (typeof value === 'string' && value.trim()) return value;
  }
  return undefined;
}

/**
 * Normalise the many ways these files record expiry into epoch ms.
 *
 * Seen in the wild: an RFC 3339 string (`expired`), epoch milliseconds
 * (Claude Code's `expiresAt`), and epoch seconds. Seconds and milliseconds are
 * told apart by magnitude — anything below this threshold cannot be a plausible
 * millisecond timestamp for a live token.
 */
const EPOCH_SECONDS_CEILING = 1e11;

export function parseExpiry(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value < EPOCH_SECONDS_CEILING ? Math.round(value * 1000) : value;
  }
  if (typeof value === 'string' && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric > 0) {
      return numeric < EPOCH_SECONDS_CEILING
        ? Math.round(numeric * 1000)
        : numeric;
    }
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}
