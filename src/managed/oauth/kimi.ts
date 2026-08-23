import { asRecord, parseExpiry, pickString } from './credentialFiles';
import { fetchModelIds } from './modelList';
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
  DeviceAuthorization,
  DevicePollResult,
  ExchangeRequest,
  OAuthAdapter,
  OAuthTokens,
  UpstreamCall,
} from './types';

/**
 * Kimi Code subscription login.
 *
 * The easiest of the vendors here: a textbook RFC 8628 device flow, and an
 * OpenAI-compatible API on the other side, so the gateway's existing Moonshot
 * provider serves it with nothing but a base-URL override.
 *
 * The usual caveat still applies — the client_id belongs to Kimi Code, and a
 * subscription is licensed for use from that client. See docs/OAUTH_PROVIDERS.md.
 */

const CLIENT_ID = '17e5f671-d194-4dfb-9706-5516cb48c098';
const OAUTH_HOST = 'https://auth.kimi.com';
const DEVICE_CODE_URL = `${OAUTH_HOST}/api/oauth/device_authorization`;
const TOKEN_URL = `${OAUTH_HOST}/api/oauth/token`;
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
/** The coding subscription's API root; OpenAI-shaped under /v1. */
const API_BASE = 'https://api.kimi.com/coding/v1';
const USAGE_URL = `${API_BASE}/usages`;
const TOKEN_TIMEOUT_MS = 15000;

/**
 * Client identity Kimi's OAuth server expects.
 *
 * The device id is stable per connected account rather than per request: the
 * vendor ties the authorization to it, so a value that changed between the
 * authorization and the poll would strand the flow.
 */
function clientHeaders(deviceId: string): Record<string, string> {
  return {
    'X-Msh-Platform': 'ai-gateway',
    'X-Msh-Version': '1.0.0',
    'X-Msh-Device-Name': 'ai-gateway',
    'X-Msh-Device-Model': 'cloudflare-worker',
    'X-Msh-Device-Id': deviceId,
  };
}

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
};

/**
 * The device id for the authorization currently in flight.
 *
 * Kimi's device flow spans two calls that must present the same id, and the
 * gateway's device contract passes only the device code between them. The
 * isolate holding the flow is the same one polling it, so a module-level value
 * carries it; a lost isolate costs a restarted authorization, not a broken seat.
 *
 * Generated lazily, never at module load: a Worker forbids randomness (and any
 * I/O) in global scope, and doing it there fails the *whole worker* at startup
 * rather than just this vendor.
 */
let pendingDeviceId: string | null = null;

/** A fresh id for a new authorization attempt. */
function newDeviceId(): string {
  pendingDeviceId = crypto.randomUUID();
  return pendingDeviceId;
}

/** The id of the attempt in flight, minting one if this isolate has none. */
function currentDeviceId(): string {
  return (pendingDeviceId ??= crypto.randomUUID());
}

async function postForm(
  url: string,
  form: Record<string, string>,
  deviceId: string,
): Promise<TokenResponse> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      accept: 'application/json',
      ...clientHeaders(deviceId),
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
      `Kimi returned non-JSON (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  // Kimi answers 200 for a pending authorization with an `error` code in the
  // body, so a non-ok status without one is the only true transport failure.
  if (!res.ok && !parsed.error) {
    throw new Error(
      `Kimi request failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  return parsed;
}

function toTokens(raw: TokenResponse, previous?: OAuthTokens): OAuthTokens {
  if (!raw.access_token) {
    throw new Error('Kimi token response contained no access_token');
  }
  return {
    access_token: raw.access_token,
    refresh_token: raw.refresh_token ?? previous?.refresh_token,
    expires_at: Date.now() + (raw.expires_in ?? 3600) * 1000,
    scope: raw.scope ?? previous?.scope,
    account_id: previous?.account_id,
    extra: {
      ...(previous?.extra ?? {}),
      device_id: (previous?.extra?.device_id as string) ?? currentDeviceId(),
    },
  };
}

const deviceIdOf = (tokens: OAuthTokens) =>
  str(tokens.extra?.device_id) ?? currentDeviceId();

type UsageDetail = {
  used?: unknown;
  limit?: unknown;
  remaining?: unknown;
  name?: unknown;
  title?: unknown;
  resetAt?: unknown;
  reset_at?: unknown;
  resetIn?: unknown;
  reset_in?: unknown;
  ttl?: unknown;
};

type LimitItem = UsageDetail & {
  scope?: unknown;
  detail?: UsageDetail;
  window?: { duration?: unknown; timeUnit?: unknown };
  duration?: unknown;
  timeUnit?: unknown;
};

/** Kimi states windows as a duration plus a protobuf-style unit. */
function windowHours(duration: unknown, timeUnit: unknown): number | null {
  const value = num(duration);
  if (value === null) return null;
  const unit = (str(timeUnit) ?? 'MINUTE')
    .toUpperCase()
    .replace(/^TIME_UNIT_/, '')
    .replace(/S$/, '');
  const perHour: Record<string, number> = {
    SECOND: 1 / 3600,
    MINUTE: 1 / 60,
    HOUR: 1,
    DAY: 24,
    WEEK: 24 * 7,
  };
  const factor = perHour[unit];
  return factor === undefined ? null : value * factor;
}

/**
 * One limit row as a shared quota window.
 *
 * Kimi reports absolute counts rather than a percentage, so the percentage is
 * derived; a row with no limit is not a window at all (nothing to be a fraction
 * of) and is skipped rather than shown as 0%.
 */
function toWindow(item: LimitItem, index: number): QuotaWindow | null {
  const detail = item.detail ?? item;
  const limit = num(detail.limit ?? item.limit);
  const used = num(detail.used ?? item.used);
  const remaining = num(detail.remaining ?? item.remaining);
  if (limit === null || limit <= 0) return null;

  const consumed = used ?? (remaining === null ? null : limit - remaining);
  if (consumed === null) return null;

  const label =
    str(item.title ?? item.name ?? detail.title ?? detail.name) ??
    str(item.scope) ??
    `Limit ${index + 1}`;
  const hours = windowHours(
    item.window?.duration ?? item.duration,
    item.window?.timeUnit ?? item.timeUnit,
  );

  return {
    id: `kimi-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${index}`,
    label,
    usedPercent: Math.max(0, Math.min(100, (consumed / limit) * 100)),
    resetsAt:
      resetMs(
        detail.resetAt ?? detail.reset_at ?? item.resetAt ?? item.reset_at,
      ) ?? resetFromOffset(detail.resetIn ?? detail.reset_in ?? detail.ttl),
    periodHours: hours,
  };
}

export const kimiCodeAdapter: OAuthAdapter = {
  id: 'kimi-code',
  label: 'Kimi Code (device login)',
  // Kimi is Moonshot's product and serves the same OpenAI-compatible shape, so
  // the existing provider covers it with only the base URL changed.
  gatewayProvider: 'moonshot',
  callbackPath: '',
  supportsManualCode: false,

  device: {
    async start(): Promise<DeviceAuthorization> {
      // New authorization, new device id: reusing one across attempts would let
      // an abandoned flow's id follow the account that eventually connects.
      const deviceId = newDeviceId();
      const raw = (await postForm(
        DEVICE_CODE_URL,
        { client_id: CLIENT_ID },
        deviceId,
      )) as TokenResponse & {
        device_code?: string;
        user_code?: string;
        verification_uri?: string;
        verification_uri_complete?: string;
        interval?: number;
        expires_in?: number;
      };
      if (raw.error) {
        throw new Error(
          `Kimi device authorization failed: ${raw.error_description ?? raw.error}`,
        );
      }
      if (!raw.device_code || !raw.user_code || !raw.verification_uri) {
        throw new Error('Kimi device authorization response was incomplete');
      }
      return {
        deviceCode: raw.device_code,
        userCode: raw.user_code,
        verificationUri: raw.verification_uri,
        verificationUriComplete: raw.verification_uri_complete,
        intervalMs: (raw.interval ?? 5) * 1000,
        expiresAt: Date.now() + (raw.expires_in ?? 900) * 1000,
      };
    },

    async poll(
      deviceCode: string,
      intervalMs: number,
    ): Promise<DevicePollResult> {
      const raw = await postForm(
        TOKEN_URL,
        {
          client_id: CLIENT_ID,
          device_code: deviceCode,
          grant_type: DEVICE_GRANT,
        },
        currentDeviceId(),
      );
      if (raw.error === 'authorization_pending') {
        return { status: 'pending', intervalMs };
      }
      if (raw.error === 'slow_down') {
        // The spec's own back-off: add five seconds and keep waiting.
        return { status: 'pending', intervalMs: intervalMs + 5000 };
      }
      if (raw.error === 'expired_token') {
        throw new Error('The Kimi authorization expired. Start again.');
      }
      if (raw.error === 'access_denied') {
        throw new Error('The Kimi authorization was denied.');
      }
      if (raw.error) {
        throw new Error(
          `Kimi authorization failed: ${raw.error_description ?? raw.error}`,
        );
      }
      return { status: 'complete', tokens: toTokens(raw) };
    },
  },

  buildAuthorizeUrl(_req: AuthorizeRequest): string {
    throw new Error(
      'Kimi authorizes by device code; start the connection instead.',
    );
  },

  async exchangeCode(_req: ExchangeRequest): Promise<OAuthTokens> {
    throw new Error(
      'Kimi authorizes by device code; there is no code to paste.',
    );
  },

  async refresh(tokens: OAuthTokens): Promise<OAuthTokens> {
    if (!tokens.refresh_token) {
      throw new Error('No refresh token stored for this Kimi account');
    }
    const raw = await postForm(
      TOKEN_URL,
      {
        client_id: CLIENT_ID,
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token,
      },
      deviceIdOf(tokens),
    );
    if (raw.error) {
      // Keep the vendor's error code even when a description exists —
      // `invalid_grant` is matched downstream to signal a dead refresh token.
      throw new Error(
        `Kimi token refresh failed: ${raw.error}${
          raw.error_description ? ` (${raw.error_description})` : ''
        }`
      );
    }
    return toTokens(raw, tokens);
  },

  async listModels(tokens: OAuthTokens): Promise<string[]> {
    return fetchModelIds(`${API_BASE}/models`, {
      ...clientHeaders(deviceIdOf(tokens)),
      authorization: `Bearer ${tokens.access_token}`,
    });
  },

  async fetchQuota(tokens: OAuthTokens): Promise<QuotaSnapshot> {
    const payload = await getJson<{
      usage?: UsageDetail;
      limits?: LimitItem[];
    }>(USAGE_URL, {
      ...clientHeaders(deviceIdOf(tokens)),
      authorization: `Bearer ${tokens.access_token}`,
    });

    const windows = (payload.limits ?? [])
      .map((item, i) => toWindow(item, i))
      .filter((w): w is QuotaWindow => w !== null);

    // The top-level `usage` block is a total rather than a window, so it reads
    // as a note: it has no period and nothing to reset.
    const notes: string[] = [];
    const total = num(payload.usage?.used);
    const cap = num(payload.usage?.limit);
    if (total !== null) {
      notes.push(
        cap !== null && cap > 0
          ? `Total usage: ${total} of ${cap}`
          : `Total usage: ${total}`,
      );
    }

    return { plan: null, windows, notes, fetchedAt: Date.now() };
  },

  decorate(tokens: OAuthTokens): UpstreamCall {
    return {
      // Subscription traffic goes to the coding host, not api.moonshot.cn,
      // which is for metered keys and rejects these tokens.
      baseUrl: API_BASE,
      headers: { ...clientHeaders(deviceIdOf(tokens)) },
      auth: { header: 'authorization', scheme: 'Bearer' },
    };
  },

  /** The credential JSON the Kimi CLI login writes (`"type": "kimi"`). */
  importFromFile(blob: unknown): OAuthTokens | null {
    const root = asRecord(blob);
    if (!root) return null;
    const node = asRecord(root.kimi) ?? root;

    const access = pickString(node, 'access_token', 'accessToken');
    if (!access) return null;

    const refresh = pickString(node, 'refresh_token', 'refreshToken');
    if (!refresh) {
      throw new Error(
        'No refresh token in the Kimi credential file. Re-run the login and import the regenerated file.',
      );
    }
    const deviceId = pickString(node, 'device_id', 'deviceId');
    return {
      access_token: access,
      refresh_token: refresh,
      expires_at:
        parseExpiry(node.expired ?? node.expires_at ?? node.expiresAt) ?? 0,
      scope: pickString(node, 'scope', 'scopes'),
      extra: { device_id: deviceId ?? crypto.randomUUID() },
    };
  },

  credentialFileHint: 'the auth JSON the Kimi Code login writes',

  /** The Moonshot provider implements chat completions and nothing else. */
  supportedPaths: ['/v1/chat/completions'],

  defaultModels: ['kimi-k2', 'kimi-k2-turbo'],
};
