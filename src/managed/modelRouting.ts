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

export function parseModelsJson(models: string): string[] {
  try {
    const parsed = JSON.parse(models);
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}
