import { decodeJwtPayload } from './pkce';
import type {
  AuthorizeRequest,
  ExchangeRequest,
  OAuthAdapter,
  OAuthTokens,
  UpstreamCall,
} from './types';

/**
 * ChatGPT Plus/Pro subscription login, as performed by the Codex CLI.
 *
 * Scope and caveats:
 *
 * 1. The client_id below belongs to the Codex CLI. OpenAI does not register
 *    third-party clients against it, and its only permitted redirect_uri is
 *    http://localhost:1455/auth/callback. A deployed Worker therefore cannot
 *    receive the callback: run `codex login` locally and import the resulting
 *    ~/.codex/auth.json (importFromFile). Refresh works from anywhere once
 *    imported, so this is a one-time step per account.
 *
 * 2. Subscription auth is licensed for interactive use, not backend services.
 *    Fronting it with a proxy is outside what that licence covers.
 *
 * 3. This backend speaks the Responses API only. Route /v1/responses traffic
 *    here; /v1/chat/completions is not served by this host.
 */

const CLIENT_ID = 'app_EMoamEEZ73f0CkXaXp7hrann';
const AUTHORIZE_URL = 'https://auth.openai.com/oauth/authorize';
const TOKEN_URL = 'https://auth.openai.com/oauth/token';
const REDIRECT_URI = 'http://localhost:1455/auth/callback';
const SCOPES = 'openid profile email offline_access';
const BACKEND_BASE_URL = 'https://chatgpt.com/backend-api/codex';
const TOKEN_TIMEOUT_MS = 15000;

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  scope?: string;
};

/**
 * Pull the ChatGPT account id out of the id_token.
 *
 * OpenAI namespaces these claims under an auth URL rather than putting them at
 * the top level, and the namespace has moved before, so try the known shapes
 * and fall back to whatever the caller already had.
 */
function accountIdFromIdToken(idToken?: string): {
  accountId?: string;
  planType?: string;
  email?: string;
} {
  if (!idToken) return {};
  const claims = decodeJwtPayload(idToken);
  if (!claims) return {};

  const namespaces = [
    'https://api.openai.com/auth',
    'https://api.openai.com/profile',
  ];
  for (const ns of namespaces) {
    const scoped = claims[ns];
    if (scoped && typeof scoped === 'object') {
      const s = scoped as Record<string, unknown>;
      const accountId = s.chatgpt_account_id ?? s.account_id;
      const planType = s.chatgpt_plan_type ?? s.plan_type;
      if (typeof accountId === 'string') {
        return {
          accountId,
          planType: typeof planType === 'string' ? planType : undefined,
          email: typeof claims.email === 'string' ? claims.email : undefined,
        };
      }
    }
  }

  const flat = claims.chatgpt_account_id ?? claims.account_id;
  return {
    accountId: typeof flat === 'string' ? flat : undefined,
    email: typeof claims.email === 'string' ? claims.email : undefined,
  };
}

function toTokens(raw: TokenResponse, previous?: OAuthTokens): OAuthTokens {
  if (!raw.access_token) {
    throw new Error('OpenAI token response contained no access_token');
  }
  const idToken =
    raw.id_token ?? (previous?.extra?.id_token as string | undefined);
  const { accountId, planType, email } = accountIdFromIdToken(idToken);
  return {
    access_token: raw.access_token,
    refresh_token: raw.refresh_token ?? previous?.refresh_token,
    expires_at: Date.now() + (raw.expires_in ?? 3600) * 1000,
    scope: raw.scope ?? previous?.scope,
    account_id: accountId ?? previous?.account_id,
    extra: {
      ...(previous?.extra ?? {}),
      ...(idToken ? { id_token: idToken } : {}),
      ...(planType ? { plan_type: planType } : {}),
      ...(email ? { email } : {}),
    },
  };
}

async function postToken(
  body: Record<string, unknown>,
): Promise<TokenResponse> {
  // Bounded: this runs on the request path during refresh, so a vendor endpoint
  // that accepts the connection and then stalls would otherwise hold the caller
  // until the platform kills the whole request.
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `OpenAI OAuth token request failed (${res.status}): ${text.slice(0, 300)}`,
    );
  }
  try {
    return JSON.parse(text) as TokenResponse;
  } catch {
    throw new Error('OpenAI OAuth token response was not JSON');
  }
}

export const openaiCodexAdapter: OAuthAdapter = {
  id: 'openai-codex',
  label: 'ChatGPT Plus/Pro (Codex login)',
  gatewayProvider: 'openai',
  callbackPath: '/auth/callback',
  // The redirect target is a fixed localhost port, so there is no code to paste
  // from a hosted flow; importing auth.json is the supported route.
  supportsManualCode: false,

  buildAuthorizeUrl({
    redirectUri,
    state,
    codeChallenge,
  }: AuthorizeRequest): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      // Honour the caller's URI so a locally-run gateway can use its own port,
      // but note OpenAI only accepts URIs registered for this client.
      redirect_uri: redirectUri || REDIRECT_URI,
      scope: SCOPES,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      id_token_add_organizations: 'true',
      codex_cli_simplified_flow: 'true',
      state,
    });
    return `${AUTHORIZE_URL}?${params.toString()}`;
  },

  async exchangeCode({ code, codeVerifier, redirectUri }: ExchangeRequest) {
    const raw = await postToken({
      grant_type: 'authorization_code',
      code: code.trim(),
      code_verifier: codeVerifier,
      client_id: CLIENT_ID,
      redirect_uri: redirectUri || REDIRECT_URI,
    });
    return toTokens(raw);
  },

  async refresh(tokens: OAuthTokens) {
    if (!tokens.refresh_token) {
      throw new Error('No refresh token stored for this ChatGPT account');
    }
    const raw = await postToken({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
      scope: SCOPES,
    });
    return toTokens(raw, tokens);
  },

  decorate(tokens: OAuthTokens): UpstreamCall {
    const headers: Record<string, string> = {
      'openai-beta': 'responses=experimental',
      originator: 'codex_cli_rs',
      'user-agent': 'codex_cli_rs/0.0.0 (external)',
      // Codex sends a per-conversation id; the backend only requires presence.
      session_id: crypto.randomUUID(),
    };
    // The backend resolves which subscription to bill from this header. Without
    // it the request is rejected even with a valid bearer token.
    if (tokens.account_id) {
      headers['chatgpt-account-id'] = tokens.account_id;
    }
    return {
      baseUrl: BACKEND_BASE_URL,
      headers,
      auth: { header: 'authorization', scheme: 'Bearer' },
    };
  },

  /** Shape written by the Codex CLI at ~/.codex/auth.json. */
  importFromFile(blob: unknown): OAuthTokens | null {
    if (!blob || typeof blob !== 'object') return null;
    const root = blob as Record<string, unknown>;
    const tokensNode = (root.tokens ?? root) as Record<string, unknown>;
    const access = tokensNode.access_token;
    if (typeof access !== 'string' || !access) return null;

    const idToken =
      typeof tokensNode.id_token === 'string' ? tokensNode.id_token : undefined;
    const { accountId, planType, email } = accountIdFromIdToken(idToken);
    const fileAccountId =
      typeof tokensNode.account_id === 'string'
        ? tokensNode.account_id
        : undefined;

    // decorate() sends this as chatgpt-account-id, and the backend rejects the
    // request without it. Import is the only onboarding route for this vendor,
    // so refuse here rather than let the first inference fail opaquely.
    if (!accountId && !fileAccountId) {
      throw new Error(
        'No ChatGPT account id found in the credential file. Re-run `codex login` ' +
          'and import the regenerated ~/.codex/auth.json.',
      );
    }

    return {
      access_token: access,
      refresh_token:
        typeof tokensNode.refresh_token === 'string'
          ? tokensNode.refresh_token
          : undefined,
      // auth.json records last_refresh rather than an expiry. Treat an imported
      // token as already stale so the first request refreshes it and we learn
      // the real lifetime from the response.
      expires_at: 0,
      account_id: accountId ?? fileAccountId,
      extra: {
        ...(idToken ? { id_token: idToken } : {}),
        ...(planType ? { plan_type: planType } : {}),
        ...(email ? { email } : {}),
      },
    };
  },

  credentialFileHint: '~/.codex/auth.json (created by `codex login`)',

  // Deliberately narrow. A bare 'gpt-5' entry here is a prefix, so it would
  // capture every gpt-5* request the owner makes — including ones meant for a
  // metered OpenAI key — and send them to a host that only speaks Responses.
  // Widen this only with model ids this backend genuinely serves.
  defaultModels: ['gpt-5-codex'],

  supportedPaths: ['/v1/responses'],
};
