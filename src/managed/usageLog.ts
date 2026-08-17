/**
 * The request log.
 *
 * Every proxied request lands here, including the ones that failed — a log that
 * only records successes cannot answer "why did that 502", which is the
 * question people actually bring to it. Rows written before the outcome columns
 * existed have a NULL status_code, so readers treat NULL as "succeeded".
 */

export type RequestOutcome = {
  /** Status the client was given. */
  statusCode: number;
  /** Upstream error text, already truncated for storage. */
  errorMessage?: string | null;
  durationMs?: number | null;
};

export async function logUsage(
  db: D1Database,
  apiKeyId: number,
  model: string,
  provider: string,
  promptTokens: number,
  completionTokens: number,
  outcome?: RequestOutcome
): Promise<void> {
  await db
    .prepare(
      `INSERT INTO usage_logs
         (api_key_id, model, provider, prompt_tokens, completion_tokens,
          status_code, error_message, duration_ms)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .bind(
      apiKeyId,
      model,
      provider,
      promptTokens,
      completionTokens,
      outcome?.statusCode ?? null,
      outcome?.errorMessage ?? null,
      outcome?.durationMs ?? null
    )
    .run();
}

/** Counts toward RPM even when token usage is unknown (e.g. audio, images). */
export async function logRequest(
  db: D1Database,
  apiKeyId: number,
  model: string,
  provider: string,
  usage?: { prompt: number; completion: number },
  outcome?: RequestOutcome
): Promise<void> {
  await logUsage(
    db,
    apiKeyId,
    model,
    provider,
    usage?.prompt ?? 0,
    usage?.completion ?? 0,
    outcome
  );
}

export function extractUsageFromJson(body: Record<string, unknown> | null): {
  prompt: number;
  completion: number;
} {
  if (!body) return { prompt: 0, completion: 0 };
  // Anthropic's `message_start` frame reports the prompt cost one level down,
  // inside the message it is starting; everything else puts usage at the root.
  const nested = body.message as Record<string, unknown> | undefined;
  const usage = (body.usage ?? nested?.usage) as
    | Record<string, number>
    | undefined;
  if (usage) {
    return {
      prompt: usage.prompt_tokens ?? usage.input_tokens ?? 0,
      completion: usage.completion_tokens ?? usage.output_tokens ?? 0,
    };
  }
  return { prompt: 0, completion: 0 };
}

/**
 * Read token usage out of a streamed response.
 *
 * A streamed body never parses as JSON, so before this every streamed request
 * was logged as zero tokens — which silently under-counted exactly the traffic
 * most clients send, including against monthly token limits.
 *
 * The stream is scanned, not buffered: each `data:` frame is parsed and
 * discarded. Vendors disagree about where the numbers appear — OpenAI sends
 * both totals in a final chunk, Anthropic sends input on `message_start` and
 * output on `message_delta` — so each field keeps the largest value seen, which
 * is right for both and for a stream that ends early.
 */
export async function collectStreamUsage(
  stream: ReadableStream<Uint8Array>
): Promise<{ prompt: number; completion: number }> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  const usage = { prompt: 0, completion: 0 };
  let buffered = '';

  const scan = (frame: string) => {
    const payload = frame.replace(/^data:\s*/, '').trim();
    if (!payload || payload === '[DONE]') return;
    try {
      const parsed = JSON.parse(payload) as Record<string, unknown>;
      const found = extractUsageFromJson(parsed);
      usage.prompt = Math.max(usage.prompt, found.prompt);
      usage.completion = Math.max(usage.completion, found.completion);
    } catch {
      /* keep-alives and event: lines are not JSON */
    }
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffered += decoder.decode(value, { stream: true });
      // Frames are newline-delimited; hold the trailing partial for the next read.
      const lines = buffered.split('\n');
      buffered = lines.pop() ?? '';
      for (const line of lines) scan(line);
    }
    scan(buffered);
  } catch {
    // A client that disconnects mid-stream aborts this read. Whatever was
    // counted so far is still the best answer available.
  } finally {
    reader.releaseLock();
  }

  return usage;
}

/** Longest error text kept per row. Enough to identify the failure, not a dump. */
const MAX_ERROR_CHARS = 400;

/**
 * The human-readable part of an upstream error body.
 *
 * Vendors disagree on the envelope — `{error:{message}}`, `{error:"..."}`,
 * `{message}` — and some answer with plain text or HTML. Whatever comes back,
 * the log needs one line that identifies the failure.
 */
export function extractErrorMessage(
  body: string,
  contentType: string | null
): string {
  const trimmed = body.trim();
  if (!trimmed) return '';
  if (contentType?.includes('application/json')) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      const error = parsed.error;
      if (typeof error === 'string') return error.slice(0, MAX_ERROR_CHARS);
      if (error && typeof error === 'object') {
        const message = (error as Record<string, unknown>).message;
        if (typeof message === 'string')
          return message.slice(0, MAX_ERROR_CHARS);
      }
      if (typeof parsed.message === 'string') {
        return parsed.message.slice(0, MAX_ERROR_CHARS);
      }
    } catch {
      /* fall through to the raw text */
    }
  }
  return trimmed.slice(0, MAX_ERROR_CHARS);
}
