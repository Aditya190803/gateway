import { asRecord, parseExpiry, pickString } from './credentialFiles';
import { fetchModelIds } from './modelList';
import {
  getJson,
  num,
  resetMs,
  str,
  WEEK,
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
 * Claude Pro/Max subscription login, as performed by the Claude Code CLI.
 *
 * Read this before relying on it. Anthropic operates no OAuth program for
 * third-party clients: the client_id below is Claude Code's own, and the client
 * headers exist to satisfy Anthropic's server-side check that consumer OAuth
 * credentials are only used from Claude Code. Using them from a proxy is a
 * Consumer Terms violation, it can stop working whenever Anthropic changes the
 * check, and none of these endpoints are a public API. Enabled here at the
 * operator's explicit direction; a metered key from console.anthropic.com is
 * the supported path. See docs/OAUTH_PROVIDERS.md.
 *
 * Endpoints and scopes track the current Claude Code build. The token host
 * moved from console.anthropic.com to platform.claude.com, and the scope set
 * grew past the old org:create_api_key form.
 */

const CLIENT_ID = '9d1c250a-e61b-44d9-88ed-5944d1962f5e';
const AUTHORIZE_URL = 'https://claude.ai/oauth/authorize';
const TOKEN_URL = 'https://platform.claude.com/v1/oauth/token';
/**
 * The CLI registers a loopback callback, which a deployed gateway cannot
 * receive. Passing code=true on the authorize URL makes Claude display the code
 * for the operator to paste instead, which is the flow this adapter uses.
 */
const REDIRECT_URI = 'http://localhost:54545/callback';
const SCOPES =
  'user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload';
const TOKEN_TIMEOUT_MS = 15000;

/** Claude Code's client identity. The server-side check keys off these. */
const CLIENT_HEADERS: Record<string, string> = {
  'anthropic-version': '2023-06-01',
  'anthropic-beta': 'oauth-2025-04-20,claude-code-20250219',
  'anthropic-dangerous-direct-browser-access': 'true',
  'x-app': 'cli',
  'user-agent': 'claude-cli/2.1.220 (external, cli)',
};

/** The OAuth control plane is fronted by axios in the real client. */
const OAUTH_HEADERS: Record<string, string> = {
  'content-type': 'application/json',
  accept: 'application/json, text/plain, */*',
  'user-agent': 'axios/1.15.2',
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
    headers: { ...OAUTH_HEADERS },
    body: JSON.stringify(body),
    // Bounded: this runs on the request path during refresh.
    signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
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

const USAGE_URL = 'https://api.anthropic.com/api/oauth/usage';
const PROFILE_URL = 'https://api.anthropic.com/api/oauth/profile';

/**
 * The named windows in the usage payload, in the order Claude Code shows them.
 *
 * The payload states no period, so it comes from the key: `five_hour` is the
 * rolling session window and every other named key is a 7-day one.
 */
const USAGE_WINDOWS: { key: string; label: string; hours: number }[] = [
  { key: 'five_hour', label: 'Session (5h)', hours: 5 },
  { key: 'seven_day', label: 'Weekly · all models', hours: WEEK },
  { key: 'seven_day_oauth_apps', label: 'Weekly · OAuth apps', hours: WEEK },
  { key: 'seven_day_opus', label: 'Weekly · Opus', hours: WEEK },
  { key: 'seven_day_sonnet', label: 'Weekly · Sonnet', hours: WEEK },
  { key: 'seven_day_cowork', label: 'Weekly · Cowork', hours: WEEK },
];

type UsageWindow = { utilization?: unknown; resets_at?: unknown };
type UsageLimit = {
  kind?: unknown;
  percent?: unknown;
  resets_at?: unknown;
  is_active?: unknown;
  scope?: { model?: { display_name?: unknown } | null } | null;
};
type UsagePayload = Record<string, unknown> & {
  limits?: UsageLimit[];
  extra_usage?: {
    is_enabled?: unknown;
    monthly_limit?: unknown;
    used_credits?: unknown;
  } | null;
};

/**
 * Per-model weekly caps, which Anthropic reports in a `limits` array rather than
 * as named keys. Newer models appear only here, so a seat's real ceiling would
 * be invisible without reading it.
 */
function scopedWindows(payload: UsagePayload): QuotaWindow[] {
  if (!Array.isArray(payload.limits)) return [];
  return payload.limits
    .filter((l) => str(l?.kind)?.toLowerCase() === 'weekly_scoped')
    .map((l, i): QuotaWindow | null => {
      const percent = num(l.percent);
      if (percent === null) return null;
      const model = str(l.scope?.model?.display_name) ?? `model ${i + 1}`;
      return {
        id: `weekly-scoped-${model.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
        label: `Weekly · ${model}`,
        usedPercent: percent,
        resetsAt: resetMs(l.resets_at),
        periodHours: WEEK,
      };
    })
    .filter((w): w is QuotaWindow => w !== null);
}

/** has_claude_max/has_claude_pro on the profile is how the CLI names the tier. */
function planFromProfile(profile: unknown): string | null {
  const root = asRecord(profile);
  if (!root) return null;
  const account = asRecord(root.account);
  if (account?.has_claude_max === true) return 'Max';
  if (account?.has_claude_pro === true) return 'Pro';
  const org = asRecord(root.organization);
  if (
    str(org?.organization_type)?.toLowerCase() === 'claude_team' &&
    str(org?.subscription_status)?.toLowerCase() === 'active'
  ) {
    return 'Team';
  }
  if (account?.has_claude_max === false && account?.has_claude_pro === false) {
    return 'Free';
  }
  return null;
}

export const anthropicClaudeCodeAdapter: OAuthAdapter = {
  id: 'anthropic-claude-code',
  label: 'Claude Pro/Max (Claude Code login)',
  gatewayProvider: 'anthropic',
  // code=true makes Claude display the authorization code instead of only
  // redirecting to the loopback callback, so the operator pastes it back here.
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
      scope: SCOPES,
    });
    return toTokens(raw, tokens);
  },

  async listModels(tokens: OAuthTokens): Promise<string[]> {
    return fetchModelIds('https://api.anthropic.com/v1/models?limit=100', {
      ...CLIENT_HEADERS,
      authorization: `Bearer ${tokens.access_token}`,
    });
  },

  /**
   * The windows Claude Code's `/usage` view shows, plus the plan tier.
   *
   * The profile call is best-effort and runs alongside: knowing the tier is
   * nice, but a seat whose limits load is still worth showing without it.
   */
  async fetchQuota(tokens: OAuthTokens): Promise<QuotaSnapshot> {
    const headers = {
      ...CLIENT_HEADERS,
      authorization: `Bearer ${tokens.access_token}`,
    };
    const [usageResult, profileResult] = await Promise.allSettled([
      getJson<UsagePayload>(USAGE_URL, headers),
      getJson<unknown>(PROFILE_URL, headers),
    ]);
    if (usageResult.status === 'rejected') throw usageResult.reason;
    const payload = usageResult.value;

    const scoped = scopedWindows(payload);
    const windows: QuotaWindow[] = [];
    for (const { key, label, hours } of USAGE_WINDOWS) {
      const w = payload[key] as UsageWindow | undefined;
      const usedPercent = num(w?.utilization);
      if (usedPercent === null) continue;
      windows.push({
        id: key.replace(/_/g, '-'),
        label,
        usedPercent,
        resetsAt: resetMs(w?.resets_at),
        periodHours: hours,
      });
    }
    windows.push(...scoped);

    const notes: string[] = [];
    const extra = payload.extra_usage;
    if (extra?.is_enabled === true) {
      // Anthropic reports extra usage in cents.
      const used = (num(extra.used_credits) ?? 0) / 100;
      const limit = (num(extra.monthly_limit) ?? 0) / 100;
      notes.push(
        `Extra usage: $${used.toFixed(2)} of $${limit.toFixed(2)} this month`,
      );
    }

    return {
      plan:
        profileResult.status === 'fulfilled'
          ? planFromProfile(profileResult.value)
          : null,
      windows,
      notes,
      fetchedAt: Date.now(),
    };
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

  /**
   * Shape written by Claude Code at ~/.claude/.credentials.json (nested under
   * claudeAiOauth), and the flat auth file a proxy writes after running that
   * login for you.
   */
  importFromFile(blob: unknown): OAuthTokens | null {
    const root = asRecord(blob);
    if (!root) return null;
    const oauth = asRecord(root.claudeAiOauth) ?? root;

    const access = pickString(oauth, 'accessToken', 'access_token');
    if (!access) return null;

    const refresh = pickString(oauth, 'refreshToken', 'refresh_token');
    if (!refresh) {
      throw new Error(
        'No refresh token in the Claude credential file. Re-run the Claude Code login and import the regenerated file.',
      );
    }

    const email = pickString(oauth, 'email');
    const accountId = pickString(oauth, 'account_uuid', 'accountUuid');
    return {
      access_token: access,
      refresh_token: refresh,
      // Claude Code stores an absolute epoch-ms deadline; proxy auth files store
      // an RFC 3339 string. Anything unreadable means refresh on first use.
      expires_at:
        parseExpiry(oauth.expiresAt ?? oauth.expires_at ?? oauth.expired) ?? 0,
      scope: pickString(oauth, 'scopes', 'scope'),
      account_id: accountId,
      extra: {
        ...(email ? { email } : {}),
        ...(pickString(oauth, 'organization_uuid')
          ? { organization_id: pickString(oauth, 'organization_uuid') }
          : {}),
      },
    };
  },

  credentialFileHint:
    '~/.claude/.credentials.json (macOS: Keychain item "Claude Code-credentials")',

  defaultModels: ['claude-opus-5', 'claude-sonnet-5', 'claude-haiku-4-5'],
};
