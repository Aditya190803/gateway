import type {
  AuthorizeRequest,
  ExchangeRequest,
  OAuthAdapter,
  OAuthTokens,
  UpstreamCall,
} from './types';

/**
 * Claude Pro/Max subscription login, as performed by the Claude Code CLI.
 *
 * IMPORTANT — read before enabling this adapter:
 *
 * 1. Anthropic does not operate an OAuth program for third-party clients. The
 *    client_id below belongs to Claude Code itself; there is no way to register
 *    your own. Using it from another application is a Consumer Terms violation.
 *
 * 2. Anthropic now enforces this server-side. Consumer-plan OAuth credentials
 *    used outside Claude Code / claude.ai are rejected with:
 *      "This credential is only authorized for use with Claude Code and cannot
 *       be used for other API requests."
 *    That check is why this adapter reproduces Claude Code's client headers
 *    exactly. Even so, expect requests to fail, and expect the behaviour to
 *    change without notice — none of these endpoints are a public API.
 *
 * A metered API key from console.anthropic.com is the supported path and is
 * what the api_key auth_type is for.
 */

const CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const AUTHORIZE_URL = 'https://claude.ai/oauth/authorize';
const TOKEN_URL = 'https://console.anthropic.com/v1/oauth/token';
const REDIRECT_URI = 'https://console.anthropic.com/oauth/code/callback';
const SCOPES = 'org:create_api_key user:profile user:inference';

/** Claude Code's client identity. The server-side check keys off these. */
const CLIENT_HEADERS: Record<string, string> = {
  'anthropic-version': '2023-06-01',
  'anthropic-beta': 'oauth-2025-04-20,claude-code-20250219',
  'anthropic-dangerous-direct-browser-access': 'true',
  'x-app': 'cli',
  'user-agent': 'claude-cli/1.0.0 (external, cli)',
};

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  account?: { uuid?: string; email_address?: string };
  organization?: { uuid?: string; name?: string };
};

function toTokens(raw: TokenResponse, previous?: OAuthTokens): OAuthTokens {
  if (!raw.access_token) {
    throw new Error('Anthropic token response contained no access_token');
  }
  // expires_in is seconds; store an absolute deadline so it survives storage.
  const ttlMs = (raw.expires_in ?? 3600) * 1000;
  return {
    access_token: raw.access_token,
    // Anthropic rotates refresh tokens; fall back to the previous one only when
    // the response genuinely omits it.
    refresh_token: raw.refresh_token ?? previous?.refresh_token,
    expires_at: Date.now() + ttlMs,
    scope: raw.scope ?? previous?.scope,
    account_id: raw.account?.uuid ?? previous?.account_id,
    extra: {
      ...(previous?.extra ?? {}),
      ...(raw.account?.email_address
        ? { email: raw.account.email_address }
        : {}),
      ...(raw.organization?.uuid
        ? { organization_id: raw.organization.uuid }
        : {}),
    },
  };
}

async function postToken(
  body: Record<string, unknown>,
): Promise<TokenResponse> {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'user-agent': 'anthropic',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(
      `Anthropic OAuth token request failed (${res.status}): ${text.slice(0, 300)}`,
    );
  }
  try {
    return JSON.parse(text) as TokenResponse;
  } catch {
    throw new Error('Anthropic OAuth token response was not JSON');
  }
}

export const anthropicClaudeCodeAdapter: OAuthAdapter = {
  id: 'anthropic-claude-code',
  label: 'Claude Pro/Max (Claude Code login)',
  gatewayProvider: 'anthropic',
  // Anthropic redirects to its own console page which displays the code, so the
  // gateway never receives a callback; the operator pastes the code instead.
  callbackPath: '',
  supportsManualCode: true,

  buildAuthorizeUrl({ state, codeChallenge }: AuthorizeRequest): string {
    const params = new URLSearchParams({
      code: 'true',
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });
    return `${AUTHORIZE_URL}?${params.toString()}`;
  },

  async exchangeCode({ code, codeVerifier, state }: ExchangeRequest) {
    // The console callback presents the value as "code#state"; accept either form.
    const [rawCode, embeddedState] = code.trim().split('#', 2);
    const raw = await postToken({
      grant_type: 'authorization_code',
      code: rawCode,
      code_verifier: codeVerifier,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      state: embeddedState ?? state,
    });
    return toTokens(raw);
  },

  async refresh(tokens: OAuthTokens) {
    if (!tokens.refresh_token) {
      throw new Error('No refresh token stored for this Anthropic account');
    }
    const raw = await postToken({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: CLIENT_ID,
    });
    return toTokens(raw, tokens);
  },

  decorate(): UpstreamCall {
    return {
      // Same host as the public API; only the credential and client headers differ.
      headers: { ...CLIENT_HEADERS },
      // Sources disagree on whether the OAuth token goes in x-api-key or
      // Authorization. Bearer is what the current Claude Code build sends, and
      // it also displaces the provider's default x-api-key header rather than
      // sending both, which Anthropic rejects.
      auth: { header: 'authorization', scheme: 'Bearer' },
    };
  },

  /** Shape written by Claude Code at ~/.claude/.credentials.json. */
  importFromFile(blob: unknown): OAuthTokens | null {
    if (!blob || typeof blob !== 'object') return null;
    const root = blob as Record<string, unknown>;
    const oauth = (root.claudeAiOauth ?? root) as Record<string, unknown>;
    const access = oauth.accessToken ?? oauth.access_token;
    if (typeof access !== 'string' || !access) return null;
    const refresh = oauth.refreshToken ?? oauth.refresh_token;
    const expires = oauth.expiresAt ?? oauth.expires_at;
    return {
      access_token: access,
      refresh_token: typeof refresh === 'string' ? refresh : undefined,
      // Claude Code stores an absolute epoch-ms deadline already.
      expires_at: typeof expires === 'number' ? expires : Date.now(),
      scope: typeof oauth.scopes === 'string' ? oauth.scopes : undefined,
    };
  },

  credentialFileHint:
    '~/.claude/.credentials.json (macOS: Keychain item "Claude Code-credentials")',

  defaultModels: ['claude-opus-4-1', 'claude-sonnet-4-5', 'claude-haiku-4-5'],
};
