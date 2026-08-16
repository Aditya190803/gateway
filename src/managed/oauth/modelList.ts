/**
 * Model discovery for subscription accounts.
 *
 * Every one of these vendors answers a `/models` listing in the same OpenAI
 * shape (`{ data: [{ id }] }`), so one fetcher covers all of them; the adapters
 * only supply the URL and the headers their credential needs.
 *
 * Discovery is always best-effort. A subscription backend can answer 404, or
 * change shape, and none of that should stop an account from connecting — the
 * caller falls back to the adapter's seeded list.
 */

const MODELS_TIMEOUT_MS = 10000;

/**
 * `data` is the OpenAI/Anthropic shape; the Codex backend answers with
 * `models` instead. Entries name themselves with `id` or `slug`.
 */
type ModelListResponse = {
  data?: { id?: unknown; slug?: unknown }[];
  models?: { id?: unknown; slug?: unknown }[];
};

export async function fetchModelIds(
  url: string,
  headers: Record<string, string>,
): Promise<string[]> {
  const res = await fetch(url, {
    headers: { accept: 'application/json', ...headers },
    signal: AbortSignal.timeout(MODELS_TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `Model listing failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }

  let parsed: ModelListResponse;
  try {
    parsed = JSON.parse(text) as ModelListResponse;
  } catch {
    throw new Error('Model listing did not return JSON');
  }

  const entries = parsed.data ?? parsed.models ?? [];
  const ids = entries
    .map((m) => m?.id ?? m?.slug)
    .filter(
      (id): id is string => typeof id === 'string' && id.trim().length > 0,
    );

  // An empty list is a real answer, not a failure: the Codex backend returns
  // one routinely. Callers keep whatever models are already configured.
  // Vendors repeat aliases and dated snapshots; keep first-seen order.
  return Array.from(new Set(ids));
}
