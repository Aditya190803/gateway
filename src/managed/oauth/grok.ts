import { asRecord, parseExpiry, pickString } from './credentialFiles';
import { fetchModelIds } from './modelList';
import { decodeJwtPayload } from './pkce';
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
 * Grok subscription login, as performed by the Grok CLI.
 *
 * Connected by importing the credential JSON the CLI login produced, the same
 * as the other two vendors: xAI's client registers no redirect a hosted gateway
 * could receive, so running the flow here is not possible. Refresh works from
 * anywhere once imported.
 *
 * The usual caveat applies: the client_id belongs to the Grok CLI, and a
 * subscription is licensed for interactive use rather than for fronting with a
 * proxy. See docs/OAUTH_PROVIDERS.md.
 */

const ISSUER = 'https://auth.x.ai';
const DISCOVERY_URL = `${ISSUER}/.well-known/openid-configuration`;
const CLIENT_ID = 'b1a00492-073a-47ea-816f-4c329264a828';
const SCOPES = 'openid profile email offline_access grok-cli:access api:access';
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';
/** Chat endpoint the CLI's subscription traffic goes to (not api.x.ai). */
const CLI_CHAT_BASE_URL = 'https://cli-chat-proxy.grok.com/v1';
const TOKEN_TIMEOUT_MS = 15000;
const DEFAULT_POLL_INTERVAL_MS = 5000;

/** Client identity the chat proxy expects alongside the bearer token. */
const CLIENT_VERSION = '0.2.120';
const CLIENT_HEADERS: Record<string, string> = {
  'x-xai-token-auth': 'xai-grok-cli',
  'x-grok-client-version': CLIENT_VERSION,
  'x-grok-client-identifier': 'grok-shell',
  'x-authenticateresponse': 'authenticate-response',
  'user-agent': `xai-grok-workspace/${CLIENT_VERSION}`,
};

type Discovery = {
  device_authorization_endpoint?: string;
  token_endpoint?: string;
};

type TokenResponse = {
  access_token?: string;
  refresh_token?: string;
  id_token?: string;
  expires_in?: number;
  scope?: string;
  error?: string;
  error_description?: string;
};

/**
 * Endpoints come from OIDC discovery rather than being hard-coded, because that
 * is the documented contract and it survives xAI moving them. Cached for the
 * isolate's lifetime: a Worker may serve many requests, and this never changes
 * within one.
 */
let discoveryCache: Promise<Required<Discovery>> | null = null;

async function discover(): Promise<Required<Discovery>> {
  if (!discoveryCache) {
    discoveryCache = (async () => {
      const res = await fetch(DISCOVERY_URL, {
        headers: { accept: 'application/json' },
        signal: AbortSignal.timeout(TOKEN_TIMEOUT_MS),
      });
      if (!res.ok) {
        throw new Error(`xAI OIDC discovery failed (${res.status})`);
      }
      const doc = (await res.json()) as Discovery;
      if (!doc.token_endpoint || !doc.device_authorization_endpoint) {
        throw new Error('xAI OIDC discovery is missing required endpoints');
      }
      return {
        device_authorization_endpoint: doc.device_authorization_endpoint,
        token_endpoint: doc.token_endpoint,
      };
    })().catch((e) => {
      // Never cache a failure, or one blip poisons the isolate.
      discoveryCache = null;
      throw e;
    });
  }
  return discoveryCache;
}

/** xAI's token endpoints are form-encoded, per the OAuth specs. */
async function postForm(
  endpoint: string,
  form: Record<string, string>,
): Promise<TokenResponse> {
  const res = await fetch(endpoint, {
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
      `xAI token endpoint returned non-JSON (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  // An OAuth error arrives as a 4xx carrying an `error` code, which the caller
  // turns into a specific message, so only surface the raw status otherwise.
  if (!res.ok && !parsed.error) {
    throw new Error(
      `xAI token request failed (${res.status}): ${text.slice(0, 200)}`,
    );
  }
  return parsed;
}

function identityFromIdToken(idToken?: string): {
  email?: string;
  subject?: string;
} {
  if (!idToken) return {};
  const claims = decodeJwtPayload(idToken);
  if (!claims) return {};
  return {
    email: typeof claims.email === 'string' ? claims.email : undefined,
    subject: typeof claims.sub === 'string' ? claims.sub : undefined,
  };
}

function toTokens(raw: TokenResponse, previous?: OAuthTokens): OAuthTokens {
  if (!raw.access_token) {
    throw new Error('xAI token response contained no access_token');
  }
  const idToken =
    raw.id_token ?? (previous?.extra?.id_token as string | undefined);
  const { email, subject } = identityFromIdToken(idToken);
  return {
    access_token: raw.access_token,
    refresh_token: raw.refresh_token ?? previous?.refresh_token,
    expires_at: Date.now() + (raw.expires_in ?? 3600) * 1000,
    scope: raw.scope ?? previous?.scope,
    account_id: subject ?? previous?.account_id,
    extra: {
      ...(previous?.extra ?? {}),
      ...(idToken ? { id_token: idToken } : {}),
      ...(email ? { email } : {}),
    },
  };
}

export const xaiGrokAdapter: OAuthAdapter = {
  id: 'xai-grok-cli',
  label: 'Grok (Grok CLI login)',
  gatewayProvider: 'x-ai',
  // Nothing is redirected back, so there is no callback path and no code to
  // paste — the operator types our code into xAI's page instead.
  callbackPath: '',
  supportsManualCode: false,

  device: {
    async start(): Promise<DeviceAuthorization> {
      const { device_authorization_endpoint } = await discover();
      const raw = (await postForm(device_authorization_endpoint, {
        client_id: CLIENT_ID,
        scope: SCOPES,
      })) as TokenResponse & {
        device_code?: string;
        user_code?: string;
        verification_uri?: string;
        verification_uri_complete?: string;
        interval?: number;
        expires_in?: number;
      };
      if (raw.error) {
        throw new Error(
          `Grok device authorization failed: ${raw.error_description ?? raw.error}`,
        );
      }
      if (!raw.device_code || !raw.user_code || !raw.verification_uri) {
        throw new Error('Grok device authorization response was incomplete');
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
      const { token_endpoint } = await discover();
      const raw = await postForm(token_endpoint, {
        grant_type: DEVICE_GRANT,
        device_code: deviceCode,
        client_id: CLIENT_ID,
      });

      if (raw.error) {
        switch (raw.error) {
          case 'authorization_pending':
            return { status: 'pending', intervalMs };
          case 'slow_down':
            // RFC 8628: back off by the base interval and keep waiting.
            return {
              status: 'pending',
              intervalMs: intervalMs + DEFAULT_POLL_INTERVAL_MS,
            };
          case 'expired_token':
            throw new Error(
              'The Grok device code expired. Start the connection again.',
            );
          case 'access_denied':
            throw new Error('Grok authorization was denied.');
          default:
            throw new Error(
              `Grok authorization failed: ${raw.error_description ?? raw.error}`,
            );
        }
      }
      return { status: 'complete', tokens: toTokens(raw) };
    },
  },

  // xAI's client authorizes by device code, so there is no authorize URL the
  // gateway can build and no code coming back to paste.
  buildAuthorizeUrl(_req: AuthorizeRequest): string {
    throw new Error(
      'Grok authorizes by device code; start the connection instead.',
    );
  },

  async exchangeCode(_req: ExchangeRequest): Promise<OAuthTokens> {
    throw new Error(
      'Grok authorizes by device code; there is no code to paste.',
    );
  },

  async refresh(tokens: OAuthTokens): Promise<OAuthTokens> {
    if (!tokens.refresh_token) {
      throw new Error('No refresh token stored for this Grok account');
    }
    const { token_endpoint } = await discover();
    const raw = await postForm(token_endpoint, {
      grant_type: 'refresh_token',
      client_id: CLIENT_ID,
      refresh_token: tokens.refresh_token,
    });
    if (raw.error) {
      throw new Error(
        `Grok token refresh failed: ${raw.error_description ?? raw.error}`,
      );
    }
    return toTokens(raw, tokens);
  },

  async listModels(tokens: OAuthTokens): Promise<string[]> {
    return fetchModelIds(`${CLI_CHAT_BASE_URL}/models`, {
      ...CLIENT_HEADERS,
      authorization: `Bearer ${tokens.access_token}`,
    });
  },

  decorate(): UpstreamCall {
    return {
      // Subscription chat goes to the CLI proxy, not api.x.ai — that host is
      // for metered API keys and rejects these tokens.
      baseUrl: CLI_CHAT_BASE_URL,
      headers: { ...CLIENT_HEADERS },
      auth: { header: 'authorization', scheme: 'Bearer' },
    };
  },

  /**
   * Accepts the flat credential JSON the Grok CLI login produces, either from
   * the CLI itself or from a proxy that ran the login and saved an auth file
   * (`{"type":"xai","access_token":…,"refresh_token":…,"expired":…}`).
   */
  importFromFile(blob: unknown): OAuthTokens | null {
    const root = asRecord(blob);
    if (!root) return null;
    // Tolerate the credentials being nested under a wrapper key.
    const node = asRecord(root.tokens) ?? asRecord(root.token_data) ?? root;

    const access = pickString(node, 'access_token', 'accessToken');
    if (!access) return null;

    const refresh = pickString(node, 'refresh_token', 'refreshToken');
    if (!refresh) {
      throw new Error(
        'No refresh token in the Grok credential file. Re-run the Grok CLI login and import the regenerated file.',
      );
    }

    const idToken = pickString(node, 'id_token', 'idToken');
    const { email, subject } = identityFromIdToken(idToken);
    const expiresAt = parseExpiry(
      node.expired ?? node.expires_at ?? node.expiresAt,
    );

    return {
      access_token: access,
      refresh_token: refresh,
      // An unparseable or absent expiry is treated as already stale, so the
      // first request refreshes and learns the real lifetime from the vendor.
      expires_at: expiresAt ?? 0,
      account_id: subject ?? pickString(node, 'sub', 'account_id'),
      extra: {
        ...(idToken ? { id_token: idToken } : {}),
        ...(email ?? pickString(node, 'email')
          ? { email: email ?? pickString(node, 'email') }
          : {}),
      },
    };
  },

  credentialFileHint:
    'the auth JSON written by the Grok CLI login (type "xai")',

  defaultModels: ['grok-4.5', 'grok-4.3'],
};
