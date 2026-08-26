import { Options, Params } from '../../types/requestBody';
import {
  GoogleChatCompleteConfig,
  GoogleChatCompleteResponseTransform,
  GoogleChatCompleteStreamChunkTransform,
} from '../google/chatComplete';
import { ParameterConfig, ProviderConfig } from '../types';

/**
 * Antigravity speaks Gemini inside an envelope.
 *
 * The body it wants is
 *
 *   { model, project, requestId, requestType, userAgent,
 *     request: { …the ordinary Gemini generateContent body… } }
 *
 * and the response comes back as `{ response: …the ordinary Gemini response… }`.
 * So none of the Gemini translation is re-implemented here: the whole Google
 * parameter map is reused with every target path moved under `request.`, and
 * the response transforms unwrap the envelope before handing off to Google's.
 *
 * The consequence worth knowing: anything Gemini gains, this gains, because
 * there is one translation and it lives in ../google.
 */

/** Envelope fields that live at the root rather than inside `request`. */
const ROOT_PARAMS = new Set(['model']);

/**
 * Move a parameter's destination under `request.`.
 *
 * `param` is a dotted path the transformer walks (setNestedProperty), so
 * prefixing is all it takes — `generationConfig.temperature` becomes
 * `request.generationConfig.temperature` with no other change.
 */
function scopeToRequest(config: ProviderConfig): ProviderConfig {
  const scoped: ProviderConfig = {};
  for (const [key, value] of Object.entries(config)) {
    if (ROOT_PARAMS.has(key)) {
      scoped[key] = value;
      continue;
    }
    const rewrite = (entry: ParameterConfig): ParameterConfig => ({
      ...entry,
      param: `request.${entry.param}`,
    });
    scoped[key] = Array.isArray(value) ? value.map(rewrite) : rewrite(value);
  }
  return scoped;
}

/**
 * Image models take a different request type and id format, which is the only
 * place the envelope varies by model.
 */
const isImageModel = (model: unknown) =>
  typeof model === 'string' && model.includes('image');

/**
 * A stable id for the conversation.
 *
 * The backend requires one. Deriving it from the request content rather than
 * generating a fresh uuid means a client that resends the same conversation
 * keeps the same session, which is what the vendor's own client does; the
 * gateway holds no per-conversation state of its own to key it on.
 */
function sessionIdFor(params: Params): string {
  const material = JSON.stringify(params.messages ?? []);
  let hash = 0;
  for (let i = 0; i < material.length; i++) {
    hash = (Math.imul(31, hash) + material.charCodeAt(i)) | 0;
  }
  return `-${Math.abs(hash)}`;
}

export const GoogleAntigravityChatCompleteConfig: ProviderConfig = {
  ...scopeToRequest(GoogleChatCompleteConfig),

  // The four envelope fields below are not request parameters, so they are
  // declared as always-defaulted entries under keys no caller sends. The
  // transformer applies `default` whenever the key is absent and `required`
  // is set, which is exactly "always" for these.
  antigravity_project: {
    param: 'project',
    required: true,
    default: (_params: Params, providerOptions: Options) =>
      providerOptions.antigravityProjectId ?? '',
  },
  // The wire value is a proto enum (google.internal.cloud.code.v1internal
  // exa.api_server_pb.ChatMessageRequestType — CASCADE/GENERAL/PLAN/etc, not
  // a free string), confirmed from the real Antigravity CLI binary's
  // embedded descriptors. `agent` matched no member, which is a plausible
  // reason every generateContent call landed in whatever bucket an
  // unrecognized/UNSPECIFIED request type gets routed to.
  antigravity_request_type: {
    param: 'requestType',
    required: true,
    default: (params: Params) =>
      isImageModel(params.model)
        ? 'image_gen'
        : 'CHAT_MESSAGE_REQUEST_TYPE_CASCADE',
  },
  antigravity_request_id: {
    param: 'requestId',
    required: true,
    default: (params: Params) =>
      isImageModel(params.model)
        ? `image_gen/${Date.now()}/${crypto.randomUUID()}/12`
        : `agent-${crypto.randomUUID()}`,
  },
  antigravity_user_agent: {
    param: 'userAgent',
    required: true,
    default: () => 'antigravity',
  },
  antigravity_session_id: {
    param: 'request.sessionId',
    required: true,
    default: (params: Params) => sessionIdFor(params),
  },
};

/** Both the whole response and every stream chunk arrive in this envelope. */
type AntigravityEnvelope = { response?: unknown; traceId?: string };

/**
 * Peel the envelope off, when there is one.
 *
 * Errors are *not* enveloped — a 4xx carries a bare `{error}` — so an absent
 * `response` key means the body is already in the shape Google's transform
 * expects, and passing it through unchanged is what makes error handling work
 * without a second code path.
 */
function unwrap(body: unknown): any {
  if (body && typeof body === 'object' && 'response' in body) {
    const inner = (body as AntigravityEnvelope).response;
    if (inner && typeof inner === 'object') return inner;
  }
  return body;
}

export const GoogleAntigravityChatCompleteResponseTransform = (
  response: any,
  responseStatus: number,
  responseHeaders: Headers,
  strictOpenAiCompliance: boolean,
) =>
  GoogleChatCompleteResponseTransform(
    unwrap(response),
    responseStatus,
    responseHeaders,
    strictOpenAiCompliance,
  );

export const GoogleAntigravityChatCompleteStreamChunkTransform = (
  responseChunk: string,
  fallbackId: string,
  streamState: any,
  strictOpenAiCompliance: boolean,
): string => {
  const chunk = responseChunk.trim().replace(/^data:\s*/, '');
  // Not delegated: Google's stream is a JSON *array* rather than SSE, so its
  // transform strips array brackets before it looks for the data: prefix and
  // turns a `data: [DONE]` sentinel into `DON`. Antigravity is real SSE, so the
  // sentinel is handled here and never reaches that path.
  if (!chunk) return '';
  if (chunk === '[DONE]') return 'data: [DONE]\n\n';

  let unwrapped: string;
  try {
    unwrapped = JSON.stringify(unwrap(JSON.parse(chunk)));
  } catch {
    // An SSE stream carries more than data frames — comment keep-alives and
    // `event:` lines are legal and are not JSON. Dropping them keeps the stream
    // alive; passing them on would throw inside the Gemini transform and take
    // the whole response down over a heartbeat.
    return '';
  }

  return GoogleChatCompleteStreamChunkTransform(
    unwrapped,
    fallbackId,
    streamState,
    strictOpenAiCompliance,
  );
};
