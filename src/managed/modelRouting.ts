/** Default model prefix → gateway provider id */
export const DEFAULT_MODEL_PREFIXES: Record<string, string[]> = {
  openai: [
    'gpt-',
    'o1-',
    'o3-',
    'o4-',
    'dall-e-',
    'tts-',
    'whisper-',
    'text-embedding-',
    'chatgpt-',
  ],
  anthropic: ['claude-'],
  google: ['gemini-', 'imagen-', 'text-embedding-004'],
  groq: ['llama-', 'mixtral-', 'deepseek-', 'gemma-', 'qwen/', 'moonshotai/'],
  'mistral-ai': [
    'mistral-',
    'codestral-',
    'pixtral-',
    'open-mistral',
    'open-codestral',
  ],
  cohere: ['command-', 'c4ai-', 'embed-'],
};

/**
 * Every provider whose configured prefixes claim this model, in row order.
 *
 * Plural because a user can connect several credentials that serve the same
 * model — two subscription seats, or a seat plus a metered key. The caller
 * decides which to use; returning only the first would make the others
 * unreachable and leave nothing to fail over to.
 */
export function matchProvidersFromPrefixes(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string[] {
  const normalized = model.toLowerCase();
  const matched: string[] = [];
  for (const { id, models } of providerModels) {
    for (const prefix of models) {
      const p = prefix.toLowerCase();
      if (normalized === p || normalized.startsWith(p)) {
        matched.push(id);
        break;
      }
    }
  }
  return matched;
}

export function matchProviderFromPrefixes(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string | null {
  return matchProvidersFromPrefixes(model, providerModels)[0] ?? null;
}

/**
 * Candidates for a model, falling back to the built-in prefix table.
 *
 * The defaults only apply when no configured prefix claimed the model: an
 * explicit list on a provider row is a deliberate statement about routing, and
 * a built-in guess must not add candidates alongside it.
 */
export function matchProvidersWithDefaults(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string[] {
  const fromDb = matchProvidersFromPrefixes(model, providerModels);
  if (fromDb.length) return fromDb;

  const matched: string[] = [];
  for (const [providerId, prefixes] of Object.entries(DEFAULT_MODEL_PREFIXES)) {
    const active = providerModels.some((p) => p.id === providerId);
    if (!active) continue;
    for (const prefix of prefixes) {
      if (normalizedStartsWith(model, prefix)) {
        matched.push(providerId);
        break;
      }
    }
  }
  return matched;
}

export function matchProviderWithDefaults(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string | null {
  return matchProvidersWithDefaults(model, providerModels)[0] ?? null;
}

function normalizedStartsWith(model: string, prefix: string): boolean {
  const m = model.toLowerCase();
  const p = prefix.toLowerCase();
  return m === p || m.startsWith(p);
}

export type ExplicitTarget = { providerId: string; model: string };

/**
 * `provider_id/model` addressing: a caller naming exactly which provider row
 * to use instead of leaving it to prefix matching and weighted selection.
 *
 * Recognised only when the segment before the slash is a real, visible
 * provider id, never as a general "has a slash" rule — an org-qualified model
 * name like `qwen/qwen3-32b` (a real Groq model) must not be mistaken for one.
 */
export function parseExplicitTarget(
  model: string,
  providerIds: string[]
): ExplicitTarget | null {
  const idx = model.indexOf('/');
  if (idx <= 0) return null;
  const providerId = model.slice(0, idx);
  if (!providerIds.includes(providerId)) return null;
  const rest = model.slice(idx + 1);
  if (!rest) return null;
  return { providerId, model: rest };
}

/**
 * Short, vendor-level names for `alias/model` addressing.
 *
 * `provider_id/model` (above) pins to one exact row and gives up failover —
 * right when you deliberately want a specific seat, wrong when you just
 * connected a second seat on the same vendor and want the short name to keep
 * meaning "either of them, whichever is healthy". An alias resolves to every
 * provider row for that vendor instead of one id, so it stays valid as seats
 * are added or removed and never leaks a provider's internal id (its own
 * `-sub` suffix, or whatever an operator named it) into a model string.
 */
export const VENDOR_ALIASES: Record<string, string> = {
  codex: 'openai-codex',
  claude: 'anthropic-claude-code',
  grok: 'xai-grok-cli',
  anti: 'google-antigravity',
  antigravity: 'google-antigravity',
  kimi: 'kimi-code',
};

export type AliasTarget = { alias: string; vendor: string; model: string };

export function parseVendorAlias(model: string): AliasTarget | null {
  const idx = model.indexOf('/');
  if (idx <= 0) return null;
  const alias = model.slice(0, idx).toLowerCase();
  const vendor = VENDOR_ALIASES[alias];
  if (!vendor) return null;
  const rest = model.slice(idx + 1);
  if (!rest) return null;
  return { alias, vendor, model: rest };
}

export function parseModelsJson(models: string): string[] {
  try {
    const parsed = JSON.parse(models);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}
