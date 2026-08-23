import { asRecord, parseExpiry, pickString } from './credentialFiles';
import {
  getJson,
  num,
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
  VendorSecrets,
} from './types';

/**
 * Antigravity (Google's agentic IDE) subscription login.
 *
 * Same caveat as the other three: the client credentials below belong to
 * Antigravity's own desktop client, Google registers no third-party client
 * against this API, and `cloudcode-pa.googleapis.com/v1internal` is not a public
 * API. Connecting a seat here is a terms violation against that Google account
 * and can stop working whenever the client checks change. See
 * docs/OAUTH_PROVIDERS.md.
 *
 * Unlike the other three this is not purely a credential swap: the Code Assist
 * backend wraps the Gemini body in `{model, project, request}` and answers with
 * `{response}`, so it has its own gateway provider
 * (src/providers/google-antigravity) that reuses Google's parameter map and
 * response transforms inside that envelope.
 *
 * One account fact has to travel with every request: the Cloud project the seat
 * is onboarded to. It is resolved once at connect time from `loadCodeAssist`,
 * stored beside the tokens, and handed to the provider through the config
 * channel, because a parameter transform can read provider options but not
 * headers.
 */

/**
 * Antigravity's own Google client credentials, supplied by the deployment.
 *
 * Unlike the other adapters here, Google issues installed applications a client
 * *secret* alongside the id. It is not confidential — it ships inside the
 * desktop app, and Google's own flow depends on that — but it is still a
 * credential belonging to someone else, so it is configured rather than
 * committed. Read them out of the Antigravity client and set them as Wrangler
 * secrets; see docs/OAUTH_PROVIDERS.md.
 */
function clientCredentials(vendorEnv?: VendorSecrets): {
  id: string;
  secret: string;
} {
  const id = vendorEnv?.ANTIGRAVITY_CLIENT_ID?.trim();
  const secret = vendorEnv?.ANTIGRAVITY_CLIENT_SECRET?.trim();
  if (!id || !secret) {
    throw new Error(
      'Antigravity is not configured on this gateway. Set the ANTIGRAVITY_CLIENT_ID and ANTIGRAVITY_CLIENT_SECRET secrets, then try again.',
    );
  }
  return { id, secret };
}

const AUTHORIZE_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const TOKEN_URL = 'https://oauth2.googleapis.com/token';
const USERINFO_URL = 'https://www.googleapis.com/oauth2/v2/userinfo?alt=json';
/** The port the desktop client listens on. Registered, so it cannot be changed. */
const REDIRECT_URI = 'http://localhost:51121/oauth-callback';
const SCOPES = [
  'https://www.googleapis.com/auth/cloud-platform',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
  'https://www.googleapis.com/auth/cclog',
  'https://www.googleapis.com/auth/experimentsandconfigs',
].join(' ');

const API_BASE = 'https://cloudcode-pa.googleapis.com';
/**
 * Quota is served by the daily and sandbox fleets as well as production, and
 * which one answers for a given account varies. Tried in order.
 */
const QUOTA_BASES = [
  API_BASE,
  'https://daily-cloudcode-pa.googleapis.com',
  'https://daily-cloudcode-pa.sandbox.googleapis.com',
];

const TOKEN_TIMEOUT_MS = 15000;
const CALL_TIMEOUT_MS = 15000;

/** Client identity the v1internal fleet expects. */
const CLIENT_HEADERS: Record<string, string> = {
  'user-agent': 'antigravity/hub/2.2.1 darwin/arm64',
  accept: '*/*',
};

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
};

async function postForm(form: Record<string, string>): Promise<TokenResponse> {
  const res = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
    },
    body: new URLSearchParams(form).toString(),
    signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
  });
  const text = await res.text();
  let parsed: TokenResponse;
  try {
    parsed = JSON.parse(text) as TokenResponse;
  } catch {
    throw new Error(
      `Google token endpoint returned non-JSON (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  if (parsed.error) {
    // Keep the vendor's error code in the message even when a description
    // exists — `invalid_grant` is matched downstream to tell the operator
    // reconnecting is required rather than retrying.
    throw new Error(
      `Antigravity token request failed: ${parsed.error}${
        parsed.error_description ? ` (${parsed.error_description})` : ''
      }`
    );
  }
  if (!res.ok) {
    throw new Error(
      `Antigravity token request failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  return parsed;
}

/** POST a v1internal method and return its JSON body. */
async function callInternal<T>(
  base: string,
  method: string,
  accessToken: string,
  body: unknown,
): Promise<T> {
  const res = await fetch(`${base}/v1internal:${method}`, {
    method: 'POST',
    headers: {
      ...CLIENT_HEADERS,
      authorization: `Bearer ${accessToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(CALL_TIMEOUT_MS),
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`${method} failed (${res.status}): ${text.slice(0, 200)}`);
  }
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new Error(`${method} did not return JSON`);
  }
}

function toTokens(raw: TokenResponse, previous?: OAuthTokens): OAuthTokens {
  if (!raw.access_token) {
    throw new Error('Google token response contained no access_token');
  }
  return {
    access_token: raw.access_token,
    // Google only issues a refresh token on the initial consent, so a refresh
    // response legitimately omits it and the stored one must be kept.
    refresh_token: raw.refresh_token ?? previous?.refresh_token,
    expires_at: Date.now() + (raw.expires_in ?? 3600) * 1000,
    scope: raw.scope ?? previous?.scope,
    account_id: previous?.account_id,
    extra: { ...(previous?.extra ?? {}) },
  };
}

/** The Cloud project the seat's quota and models hang off. */
function projectId(tokens: OAuthTokens): string | null {
  return str(tokens.extra?.project_id);
}

/**
 * Ask which project this account is onboarded to.
 *
 * Every other call needs it, and it is stable per account, so it is resolved
 * once at connect time and stored beside the tokens rather than fetched on each
 * lookup.
 */
async function resolveProject(accessToken: string): Promise<string | null> {
  const loaded = await callInternal<Record<string, unknown>>(
    API_BASE,
    'loadCodeAssist',
    accessToken,
    { metadata: { ideType: 'ANTIGRAVITY' } },
  );
  for (const key of ['cloudaicompanionProject', 'projectId', 'project']) {
    const value = loaded[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
    const nested = asRecord(value);
    const id = nested ? pickString(nested, 'id') : null;
    if (id) return id;
  }
  return null;
}

type QuotaSummary = {
  groups?: {
    displayName?: unknown;
    display_name?: unknown;
    buckets?: {
      bucketId?: unknown;
      bucket_id?: unknown;
      displayName?: unknown;
      display_name?: unknown;
      window?: unknown;
      remainingFraction?: unknown;
      remaining_fraction?: unknown;
      resetTime?: unknown;
      reset_time?: unknown;
    }[];
  }[];
};

/** Antigravity states the window explicitly, so this is a lookup, not a guess. */
function windowHours(window: string | null): number | null {
  switch (window?.trim().toLowerCase()) {
    case '5h':
    case 'five-hour':
    case 'five_hour':
      return 5;
    case 'weekly':
    case 'week':
      return 24 * 7;
    default:
      return null;
  }
}

const slug = (value: string) =>
  value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');

/**
 * Antigravity names its buckets after what is *left* — "Weekly Limit
 * Remaining". Every window in the shared shape reports what has been *used*, so
 * keeping the vendor's wording verbatim would put "0% used" next to a label
 * that says "Remaining" and leave the reader to work out which way round it is.
 */
const trimRemaining = (label: string) =>
  label.replace(/\s*remaining\s*$/i, '').trim() || label;

export const googleAntigravityAdapter: OAuthAdapter = {
  id: 'google-antigravity',
  label: 'Antigravity (Google IDE login)',
  // Its own provider rather than `google`: the Code Assist backend wraps the
  // Gemini body in an envelope and answers with one, which is a wire-format
  // difference, not a credential difference. See src/providers/google-antigravity.
  gatewayProvider: 'google-antigravity',
  callbackPath: '',
  supportsManualCode: true,
  requiredSecrets: ['ANTIGRAVITY_CLIENT_ID', 'ANTIGRAVITY_CLIENT_SECRET'],

  buildAuthorizeUrl({
    state,
    codeChallenge,
    vendorEnv,
  }: AuthorizeRequest): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: clientCredentials(vendorEnv).id,
      redirect_uri: REDIRECT_URI,
      scope: SCOPES,
      // Without both of these Google issues no refresh token on a repeat
      // authorization, and the seat would die at the first expiry.
      access_type: 'offline',
      prompt: 'consent',
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      state,
    });
    return `${AUTHORIZE_URL}?${params.toString()}`;
  },

  async exchangeCode({ code, codeVerifier, vendorEnv }: ExchangeRequest) {
    const client = clientCredentials(vendorEnv);
    const raw = await postForm({
      grant_type: 'authorization_code',
      code: code.trim(),
      code_verifier: codeVerifier,
      client_id: client.id,
      client_secret: client.secret,
      redirect_uri: REDIRECT_URI,
    });
    const tokens = toTokens(raw);

    // Identity and project are resolved once, here, because every later call
    // needs the project and the UI needs a label. Neither is fatal: a seat with
    // no project still holds working credentials, and the failure is reported
    // when something actually needs it.
    const [email, project] = await Promise.all([
      getJson<{ email?: unknown }>(USERINFO_URL, {
        authorization: `Bearer ${tokens.access_token}`,
      })
        .then((profile) => str(profile.email))
        .catch(() => null),
      resolveProject(tokens.access_token).catch(() => null),
    ]);

    return {
      ...tokens,
      account_id: email ?? tokens.account_id,
      extra: {
        ...tokens.extra,
        ...(email ? { email } : {}),
        ...(project ? { project_id: project } : {}),
      },
    };
  },

  async refresh(tokens: OAuthTokens, vendorEnv?: VendorSecrets) {
    if (!tokens.refresh_token) {
      throw new Error('No refresh token stored for this Antigravity account');
    }
    const client = clientCredentials(vendorEnv);
    const raw = await postForm({
      grant_type: 'refresh_token',
      refresh_token: tokens.refresh_token,
      client_id: client.id,
      client_secret: client.secret,
    });
    return toTokens(raw, tokens);
  },

  /**
   * Models come back keyed by id rather than as a list, which is why this does
   * not use the shared OpenAI-shaped fetcher.
   */
  async listModels(tokens: OAuthTokens): Promise<string[]> {
    const project = projectId(tokens);
    const payload = await callInternal<{ models?: Record<string, unknown> }>(
      API_BASE,
      'fetchAvailableModels',
      tokens.access_token,
      project ? { project } : {},
    );
    const models = payload.models;
    if (!models || typeof models !== 'object') return [];
    return Object.keys(models).filter((id) => id.trim().length > 0);
  },

  /**
   * Per-model quota buckets, each with a window and how much of it is left.
   *
   * Antigravity reports what *remains* rather than what was used; the shared
   * window shape is "used", so the fraction is inverted here rather than every
   * consumer having to remember which vendor means which.
   */
  async fetchQuota(tokens: OAuthTokens): Promise<QuotaSnapshot> {
    const project = projectId(tokens);
    if (!project) {
      throw new Error(
        'No Antigravity project is associated with this account. Open the Antigravity IDE once to finish onboarding, then reconnect.',
      );
    }

    let summary: QuotaSummary | null = null;
    let lastError: unknown = null;
    for (const base of QUOTA_BASES) {
      try {
        summary = await callInternal<QuotaSummary>(
          base,
          'retrieveUserQuotaSummary',
          tokens.access_token,
          { project },
        );
        break;
      } catch (e) {
        // 403/404 here means "not this fleet", not "no quota" — keep looking.
        lastError = e;
      }
    }
    if (!summary) throw lastError ?? new Error('No quota endpoint answered');

    const windows: QuotaWindow[] = [];
    for (const [i, group] of (summary.groups ?? []).entries()) {
      const groupName =
        str(group.displayName ?? group.display_name) ?? `Group ${i + 1}`;
      for (const [j, bucket] of (group.buckets ?? []).entries()) {
        const remaining = num(
          bucket.remainingFraction ?? bucket.remaining_fraction,
        );
        if (remaining === null) continue;
        const bucketName =
          str(bucket.displayName ?? bucket.display_name) ??
          str(bucket.bucketId ?? bucket.bucket_id) ??
          `Bucket ${j + 1}`;
        const window = str(bucket.window);
        windows.push({
          id: `${slug(groupName)}-${slug(bucketName)}-${j}`,
          label: `${groupName} · ${trimRemaining(bucketName)}`,
          // remainingFraction is 0–1 remaining; the shared shape is percent used.
          usedPercent: Math.max(0, Math.min(100, (1 - remaining) * 100)),
          resetsAt: resetMs(bucket.resetTime ?? bucket.reset_time),
          periodHours: windowHours(window),
        });
      }
    }

    return { plan: null, windows, notes: [], fetchedAt: Date.now() };
  },

  decorate(tokens: OAuthTokens): UpstreamCall {
    const project = projectId(tokens);
    return {
      baseUrl: API_BASE,
      headers: { ...CLIENT_HEADERS },
      auth: { header: 'authorization', scheme: 'Bearer' },
      // The backend rejects a generation without a project, and the value has
      // to reach the body rather than a header — hence the config channel.
      ...(project
        ? { configOverrides: { antigravity_project_id: project } }
        : {}),
    };
  },

  /** The credential file a proxy writes after running the Antigravity login. */
  importFromFile(blob: unknown): OAuthTokens | null {
    const root = asRecord(blob);
    if (!root) return null;
    const node = asRecord(root.antigravity) ?? root;

    const access = pickString(node, 'access_token', 'accessToken');
    if (!access) return null;

    const refresh = pickString(node, 'refresh_token', 'refreshToken');
    if (!refresh) {
      throw new Error(
        'No refresh token in the Antigravity credential file. Re-run the login and import the regenerated file.',
      );
    }

    const email = pickString(node, 'email');
    const project = pickString(node, 'project_id', 'projectId', 'project');
    return {
      access_token: access,
      refresh_token: refresh,
      expires_at:
        parseExpiry(node.expired ?? node.expires_at ?? node.expiresAt) ?? 0,
      scope: pickString(node, 'scope', 'scopes'),
      account_id: email,
      extra: {
        ...(email ? { email } : {}),
        ...(project ? { project_id: project } : {}),
      },
    };
  },

  credentialFileHint: '~/.cli-proxy-api/antigravity-*.json',

  /**
   * The Code Assist backend serves generation and nothing else — no embeddings,
   * no audio. Declaring the limit means a request for one of those falls
   * through to a provider that can answer it, instead of failing here.
   */
  supportedPaths: ['/v1/chat/completions'],

  /**
   * Antigravity publishes a real listing, so this is only the seed shown before
   * the first sync. Kept short deliberately: these ids are what the IDE offered
   * at the time of writing and the vendor rotates them.
   */
  defaultModels: ['gemini-3-pro', 'gemini-3-flash'],
};
