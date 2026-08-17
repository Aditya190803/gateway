import { asRecord, parseExpiry, pickString } from './credentialFiles';
import { fetchModelIds } from './modelList';
import { decodeJwtPayload } from './pkce';
import {
  getJson,
  num,
  resetFromOffset,
  resetMs,
  str,
  type QuotaSnapshot,
  type QuotaWindow,
} from './quota';
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
/**
 * Codex CLI version we present.
 *
 * The backend gates its model catalog on this: every model carries a
 * `minimal_client_version`, and anything newer than the version we claim is
 * filtered out. Too low a value returns an empty list rather than an error, so
 * this has to track a current CLI release to see the current models.
 */
const CLIENT_VERSION = '0.144.0';

/**
 * Usage lives on the ChatGPT web backend rather than the Codex one, so it has
 * its own base and is not reachable through BACKEND_BASE_URL.
 */
const USAGE_URL = 'https://chatgpt.com/backend-api/wham/usage';

/**
 * Spending one of the account's rate-limit reset credits, which clears the
 * current window early. The vendor sells these; the gateway only redeems one
 * when an operator explicitly asks.
 */
const RESET_CREDIT_URL =
  'https://chatgpt.com/backend-api/wham/rate-limit-reset-credits/consume';
export const CODEX_RESET_CREDIT_ACTION = 'reset-credit';

/** A rolling window as the wham/usage payload reports it. */
type CodexWindow = {
  used_percent?: unknown;
  usedPercent?: unknown;
  limit_window_seconds?: unknown;
  limitWindowSeconds?: unknown;
  reset_after_seconds?: unknown;
  resetAfterSeconds?: unknown;
  reset_at?: unknown;
  resetAt?: unknown;
};

type CodexRateLimit = {
  allowed?: unknown;
  limit_reached?: unknown;
  limitReached?: unknown;
  primary_window?: CodexWindow | null;
  primaryWindow?: CodexWindow | null;
  secondary_window?: CodexWindow | null;
  secondaryWindow?: CodexWindow | null;
};

type CodexUsagePayload = {
  plan_type?: unknown;
  planType?: unknown;
  rate_limit?: CodexRateLimit | null;
  rateLimit?: CodexRateLimit | null;
  code_review_rate_limit?: CodexRateLimit | null;
  codeReviewRateLimit?: CodexRateLimit | null;
  rate_limit_reset_credits?: {
    available_count?: unknown;
    availableCount?: unknown;
  } | null;
  rateLimitResetCredits?: {
    available_count?: unknown;
    availableCount?: unknown;
  } | null;
};

/**
 * Name a window by the period the payload states, not by its position.
 *
 * `primary`/`secondary` are not stable labels — a Team seat's secondary window
 * is monthly where an individual's is weekly — so the duration is the only
 * honest source for what to call it.
 */
function windowLabel(seconds: number | null): {
  label: string;
  hours: number | null;
} {
  if (seconds === null) return { label: 'Rolling window', hours: null };
  const hours = seconds / 3600;
  if (hours <= 24) return { label: `Rolling ${Math.round(hours)}h`, hours };
  const days = Math.round(hours / 24);
  if (days >= 28 && days <= 31) return { label: 'Monthly', hours };
  if (days === 7) return { label: 'Weekly', hours };
  return { label: `Rolling ${days}d`, hours };
}

/**
 * Both windows of one rate-limit block.
 *
 * A window with no percentage still matters when the limit is already reached:
 * the vendor stops reporting utilization at that point, and showing nothing
 * would read as "plenty left" on a seat that is actually blocked.
 */
function windowsFrom(
  limit: CodexRateLimit | null | undefined,
  prefix: string,
  namePrefix: string,
): QuotaWindow[] {
  if (!limit) return [];
  const blocked =
    limit.limit_reached === true ||
    limit.limitReached === true ||
    limit.allowed === false;
  const raw = [
    limit.primary_window ?? limit.primaryWindow,
    limit.secondary_window ?? limit.secondaryWindow,
  ];

  return raw
    .map((w, i): QuotaWindow | null => {
      if (!w) return null;
      const seconds = num(w.limit_window_seconds ?? w.limitWindowSeconds);
      const { label, hours } = windowLabel(seconds);
      const usedPercent =
        num(w.used_percent ?? w.usedPercent) ?? (blocked ? 100 : null);
      return {
        id: `${prefix}-${i}`,
        label: namePrefix ? `${namePrefix} · ${label}` : label,
        usedPercent,
        resetsAt:
          resetMs(w.reset_at ?? w.resetAt) ??
          resetFromOffset(w.reset_after_seconds ?? w.resetAfterSeconds),
        periodHours: hours,
      };
    })
    .filter((w): w is QuotaWindow => w !== null);
}

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

async function postToken(body: Record<string, string>): Promise<TokenResponse> {
  // Form-encoded, per OAuth 2.0 and what the Codex CLI itself sends.
  // Bounded: this runs on the request path during refresh, so a vendor endpoint
  // that accepts the connection and then stalls would otherwise hold the caller
  // until the platform kills the whole request.
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams(body).toString(),
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
  /**
   * The redirect target is a fixed localhost port that this gateway cannot
   * receive. That is still workable in a browser: approving sends you to
   * http://localhost:1455/auth/callback?code=…, which fails to load, and the
   * code sits in the address bar for you to paste back. Importing auth.json
   * remains the alternative.
   */
  supportsManualCode: true,

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
      prompt: 'login',
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

  async listModels(tokens: OAuthTokens): Promise<string[]> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${tokens.access_token}`,
      'user-agent': `codex_cli_rs/${CLIENT_VERSION} (external)`,
      originator: 'codex_cli_rs',
    };
    if (tokens.account_id) headers['chatgpt-account-id'] = tokens.account_id;
    // The backend rejects the listing without client_version, and gates which
    // models it returns on the value. It commonly answers with an empty list,
    // in which case the caller keeps the configured models.
    return fetchModelIds(
      `${BACKEND_BASE_URL}/models?client_version=${CLIENT_VERSION}`,
      headers,
    );
  },

  /**
   * The rate-limit windows the Codex CLI prints as `/status`.
   *
   * Two blocks are reported separately — ordinary usage and code review — and a
   * seat can be blocked on one while the other still has capacity, so both are
   * shown rather than merged.
   */
  async fetchQuota(tokens: OAuthTokens): Promise<QuotaSnapshot> {
    const headers: Record<string, string> = {
      authorization: `Bearer ${tokens.access_token}`,
      'user-agent': `codex_cli_rs/${CLIENT_VERSION} (external)`,
      originator: 'codex_cli_rs',
    };
    // Same reason as decorate(): the backend resolves the subscription from it.
    if (tokens.account_id) headers['chatgpt-account-id'] = tokens.account_id;

    const payload = await getJson<CodexUsagePayload>(USAGE_URL, headers);
    const windows = [
      ...windowsFrom(payload.rate_limit ?? payload.rateLimit, 'code', ''),
      ...windowsFrom(
        payload.code_review_rate_limit ?? payload.codeReviewRateLimit,
        'review',
        'Code review',
      ),
    ];

    const notes: string[] = [];
    const credits =
      payload.rate_limit_reset_credits ?? payload.rateLimitResetCredits;
    const available = num(credits?.available_count ?? credits?.availableCount);
    if (available !== null && available > 0) {
      notes.push(
        `${available} rate-limit reset credit${available === 1 ? '' : 's'} available`,
      );
    }

    return {
      plan:
        str(payload.plan_type ?? payload.planType) ??
        str(tokens.extra?.plan_type) ??
        null,
      windows,
      notes,
      fetchedAt: Date.now(),
      action: {
        id: CODEX_RESET_CREDIT_ACTION,
        label: 'Use a reset credit',
        available: (available ?? 0) > 0,
      },
    };
  },

  /**
   * Redeem one reset credit, clearing the current rate-limit window.
   *
   * The credit is spent whether or not the window needed clearing, so this is
   * only ever called from an explicit operator action, never automatically on a
   * 429. The redeem id makes the call idempotent at the vendor.
   */
  async runQuotaAction(tokens: OAuthTokens, actionId: string): Promise<void> {
    if (actionId !== CODEX_RESET_CREDIT_ACTION) {
      throw new Error(`Unknown action for ChatGPT: ${actionId}`);
    }
    const headers: Record<string, string> = {
      authorization: `Bearer ${tokens.access_token}`,
      'content-type': 'application/json',
      'user-agent': `codex_cli_rs/${CLIENT_VERSION} (external)`,
      originator: 'codex_cli_rs',
    };
    if (tokens.account_id) headers['chatgpt-account-id'] = tokens.account_id;

    const res = await fetch(RESET_CREDIT_URL, {
      method: 'POST',
      headers,
      body: JSON.stringify({ redeem_request_id: crypto.randomUUID() }),
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(
        `Reset credit could not be redeemed (${res.status}): ${text.slice(0, 200)}`,
      );
    }
  },

  decorate(tokens: OAuthTokens): UpstreamCall {
    const headers: Record<string, string> = {
      'openai-beta': 'responses=experimental',
      originator: 'codex_cli_rs',
      'user-agent': `codex_cli_rs/${CLIENT_VERSION} (external)`,
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

  /**
   * Shape written by the Codex CLI at ~/.codex/auth.json, and the flat auth
   * file a proxy writes after running that login for you.
   */
  importFromFile(blob: unknown): OAuthTokens | null {
    const root = asRecord(blob);
    if (!root) return null;
    const tokensNode = asRecord(root.tokens) ?? root;
    const access = pickString(tokensNode, 'access_token', 'accessToken');
    if (!access) return null;

    const idToken = pickString(tokensNode, 'id_token', 'idToken');
    const { accountId, planType, email } = accountIdFromIdToken(idToken);
    const fileAccountId = pickString(tokensNode, 'account_id', 'accountId');

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
      refresh_token: pickString(tokensNode, 'refresh_token', 'refreshToken'),
      // auth.json records last_refresh rather than an expiry, so unless the file
      // states one, treat the token as already stale: the first request then
      // refreshes it and learns the real lifetime from the response.
      expires_at: parseExpiry(tokensNode.expired ?? tokensNode.expires_at) ?? 0,
      account_id: accountId ?? fileAccountId,
      extra: {
        ...(idToken ? { id_token: idToken } : {}),
        ...(planType ? { plan_type: planType } : {}),
        ...(email ? { email } : {}),
      },
    };
  },

  credentialFileHint: '~/.codex/auth.json (created by `codex login`)',

  /**
   * Fallback only — listModels asks the backend what this account really has.
   * These are the models the Codex backend serves, which are not the public
   * OpenAI model names: there is no gpt-5-codex here. Keep entries specific,
   * because matching is by prefix and a bare 'gpt-5' would capture every
   * gpt-5* request the owner makes.
   */
  defaultModels: ['gpt-5.6-sol', 'gpt-5.6-terra', 'gpt-5.6-luna', 'gpt-5.5'],

  supportedPaths: ['/v1/responses'],
};
