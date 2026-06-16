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
  'mistral-ai': ['mistral-', 'codestral-', 'pixtral-', 'open-mistral', 'open-codestral'],
  cohere: ['command-', 'c4ai-', 'embed-'],
};

export function matchProviderFromPrefixes(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string | null {
  const normalized = model.toLowerCase();
  for (const { id, models } of providerModels) {
    for (const prefix of models) {
      const p = prefix.toLowerCase();
      if (normalized === p || normalized.startsWith(p)) {
        return id;
      }
    }
  }
  return null;
}

export function matchProviderWithDefaults(
  model: string,
  providerModels: { id: string; models: string[] }[]
): string | null {
  const fromDb = matchProviderFromPrefixes(model, providerModels);
  if (fromDb) return fromDb;

  for (const [providerId, prefixes] of Object.entries(DEFAULT_MODEL_PREFIXES)) {
    const active = providerModels.some((p) => p.id === providerId);
    if (!active) continue;
    for (const prefix of prefixes) {
      if (normalizedStartsWith(model, prefix)) {
        return providerId;
      }
    }
  }
  return null;
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