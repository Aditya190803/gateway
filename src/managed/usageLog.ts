export async function logUsage(
  db: D1Database,
  apiKeyId: number,
  model: string,
  provider: string,
  promptTokens: number,
  completionTokens: number
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO usage_logs (api_key_id, model, provider, prompt_tokens, completion_tokens)
       VALUES (?, ?, ?, ?, ?)`
    )
    .bind(apiKeyId, model, provider, promptTokens, completionTokens)
    .run();
}

/** Counts toward RPM even when token usage is unknown (e.g. audio, images). */
export async function logRequest(
  db: D1Database,
  apiKeyId: number,
  model: string,
  provider: string,
  usage?: { prompt: number; completion: number }
): Promise<void> {
  await logUsage(
    db,
    apiKeyId,
    model,
    provider,
    usage?.prompt ?? 0,
    usage?.completion ?? 0
  );
}

export function extractUsageFromJson(
  body: Record<string, unknown> | null
): { prompt: number; completion: number } {
  if (!body) return { prompt: 0, completion: 0 };
  const usage = body.usage as Record<string, number> | undefined;
  if (usage) {
    return {
      prompt: usage.prompt_tokens ?? usage.input_tokens ?? 0,
      completion: usage.completion_tokens ?? usage.output_tokens ?? 0,
    };
  }
  return { prompt: 0, completion: 0 };
}