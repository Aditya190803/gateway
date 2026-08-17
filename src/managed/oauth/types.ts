/**
 * Vendor-agnostic OAuth support for subscription-backed providers.
 *
 * An adapter encapsulates everything vendor-specific about signing in with a
 * subscription account and then spending it on an inference request:
 * the authorize URL, the token exchange, the refresh, and how the resulting
 * token is presented upstream (which host, which headers).
 */

import type { QuotaSnapshot } from './quota';

/** Credential set for one connected account. Persisted encrypted. */
export type OAuthTokens = {
  access_token: string;
  refresh_token?: string;
  /** Epoch ms. Absolute, not a TTL, so it survives storage. */
  expires_at: number;
  scope?: string;
  /** Vendor account identifier, when the vendor requires echoing it back. */
  account_id?: string;
  /** Anything else an adapter needs to round-trip (id_token, plan tier, …). */
  extra?: Record<string, unknown>;
};

/** How a request carrying these tokens must be addressed upstream. */
export type UpstreamCall = {
  /**
   * Base URL override handed to the gateway as config.custom_host. Subscription
   * endpoints frequently differ from the vendor's public API host.
   */
  baseUrl?: string;
  /** Headers the vendor requires in addition to the credential itself. */
  headers: Record<string, string>;
  /**
   * Credential placement. Some vendors reject the same token in the header slot
   * their API-key auth uses, so this is explicit rather than assumed.
   */
  auth: { header: string; scheme?: string };
  /**
   * Extra provider-config keys, merged into the gateway config the request
   * carries (snake_case, as the config schema names them).
   *
   * For account facts the provider transform needs in the *body* rather than in
   * a header — Antigravity's Code Assist project id is the case this exists
   * for. A header cannot serve: the value has to reach the parameter transform,
   * which only sees params and provider options.
   */
  configOverrides?: Record<string, string>;
};

/**
 * Vendor client credentials supplied by the deployment rather than compiled in.
 *
 * Most adapters here need none: their vendors issue public clients that
 * authorize with PKCE and no secret. Google is the exception — it issues
 * installed applications a client secret, which by definition is not
 * confidential but is still a credential belonging to somebody else, so it is
 * configured per deployment instead of living in this repository.
 */
export type VendorSecrets = {
  ANTIGRAVITY_CLIENT_ID?: string;
  ANTIGRAVITY_CLIENT_SECRET?: string;
};

export type AuthorizeRequest = {
  redirectUri: string;
  state: string;
  codeChallenge: string;
  /** Deployment-supplied client credentials, for adapters that need them. */
  vendorEnv?: VendorSecrets;
};

export type ExchangeRequest = {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  state?: string;
  vendorEnv?: VendorSecrets;
};

/**
 * A device authorization (RFC 8628) in progress.
 *
 * Used by vendors whose client has no redirect a gateway can make use of. The
 * operator opens a URL, types a short code, and the gateway polls for the
 * result — a browser authorization with nothing to paste back.
 */
export type DeviceAuthorization = {
  /** Secret the gateway polls with. Never shown to the operator. */
  deviceCode: string;
  /** Short code the operator types into the vendor's page. */
  userCode: string;
  verificationUri: string;
  /** Same page with the code pre-filled, when the vendor provides one. */
  verificationUriComplete?: string;
  intervalMs: number;
  /** Epoch ms after which the device code is dead. */
  expiresAt: number;
};

/**
 * One poll attempt. `pending` carries the interval back because a vendor can
 * answer `slow_down`, which requires backing off before the next poll.
 */
export type DevicePollResult =
  | { status: 'complete'; tokens: OAuthTokens }
  | { status: 'pending'; intervalMs: number };

export interface DeviceFlow {
  start(): Promise<DeviceAuthorization>;
  /**
   * Poll once. Throws when the authorization ends unsuccessfully — expired,
   * denied, or a protocol error the operator has to act on.
   */
  poll(deviceCode: string, intervalMs: number): Promise<DevicePollResult>;
}

export interface OAuthAdapter {
  /** Stable adapter id, stored in providers.oauth_vendor. */
  id: string;
  /** Human label for the admin UI. */
  label: string;
  /**
   * Which built-in gateway provider handles request/response transformation for
   * this vendor (e.g. 'anthropic', 'openai'). The OAuth layer only swaps out
   * credentials and routing; the body transforms are reused as-is.
   */
  gatewayProvider: string;

  /**
   * Deployment-supplied secrets this adapter cannot work without, so the admin
   * UI can say which are missing before anyone tries to connect a seat.
   */
  requiredSecrets?: (keyof VendorSecrets)[];

  /** Callback path this adapter expects, relative to the gateway origin. */
  callbackPath: string;

  /**
   * Some vendors hand the user a code to paste rather than redirecting to a
   * gateway-hosted callback. When true the admin UI offers a paste box.
   */
  supportsManualCode: boolean;

  /**
   * Device authorization, for a vendor whose client registers no redirect worth
   * using. Mutually exclusive with supportsManualCode in practice: both are
   * "browser authorization", they differ only in which side carries the code.
   */
  device?: DeviceFlow;

  buildAuthorizeUrl(req: AuthorizeRequest): string;
  exchangeCode(req: ExchangeRequest): Promise<OAuthTokens>;
  refresh(
    tokens: OAuthTokens,
    vendorEnv?: VendorSecrets,
  ): Promise<OAuthTokens>;

  /** Describes how to address an upstream call carrying these tokens. */
  decorate(tokens: OAuthTokens): UpstreamCall;

  /**
   * Parse credentials the vendor's own CLI already wrote to disk, so an
   * existing login can be imported instead of re-running the flow.
   *
   * Returns null when the blob is not in this vendor's format. Throws when it
   * IS this vendor's format but is missing something the adapter needs to make
   * a call — the two cases want different messages, and an unusable import must
   * fail at import rather than as an opaque upstream rejection later.
   */
  importFromFile?(blob: unknown): OAuthTokens | null;

  /** Where that CLI stores them, shown in the UI as an import hint. */
  credentialFileHint?: string;

  /** Models to seed the provider row with, so routing works immediately. */
  defaultModels: string[];

  /**
   * Ask the vendor which models this account can actually use, so the operator
   * does not have to type the list. Best-effort: callers fall back to
   * defaultModels when it throws, because a subscription backend may not serve
   * a listing at all.
   */
  listModels?(tokens: OAuthTokens): Promise<string[]>;

  /**
   * Read the seat's own usage limits from the vendor — the rolling windows its
   * client displays, not this gateway's request log.
   *
   * Optional because it depends on an endpoint the vendor operates for its own
   * client and may withdraw. Callers report a throw as an error against that one
   * seat; an adapter without it simply has no limits to show.
   */
  fetchQuota?(tokens: OAuthTokens): Promise<QuotaSnapshot>;

  /**
   * Consume a vendor-side allowance that lifts a limit, when the vendor sells
   * one. Codex grants "reset credits" that clear a rate-limit window early.
   *
   * Named by the `action.id` the snapshot advertised, so the route stays one
   * endpoint rather than one per vendor trick.
   */
  runQuotaAction?(tokens: OAuthTokens, actionId: string): Promise<void>;

  /**
   * Whether inference can be routed to this vendor. Defaults to true.
   *
   * A seat is worth connecting before the gateway can serve it: credentials,
   * refresh and usage limits are vendor-agnostic, but the request and response
   * transforms are not. False means "connected and observable, not routable",
   * and routing leaves it out entirely rather than sending traffic to an
   * endpoint that would reject the body shape.
   */
  routable?: boolean;

  /**
   * Request paths this credential can actually serve, as prefixes. A
   * subscription backend often exposes only part of the vendor's API surface,
   * and routing to it for anything else produces a confusing upstream 404.
   *
   * Omit to serve every path the gateway handles.
   */
  supportedPaths?: string[];
}

/**
 * Whether an adapter can serve a request path. Adapters without an explicit
 * list serve everything, so a vendor that mirrors the full API needs no config.
 */
export function adapterServesPath(
  adapter: OAuthAdapter,
  path: string,
): boolean {
  if (!adapter.supportedPaths?.length) return true;
  return adapter.supportedPaths.some((p) => path === p || path.startsWith(p));
}

/** Refresh slightly early: a token that expires mid-flight reads as a 401. */
export const REFRESH_SKEW_MS = 5 * 60 * 1000;

export function isExpired(expiresAt: number, now = Date.now()): boolean {
  return !Number.isFinite(expiresAt) || expiresAt - REFRESH_SKEW_MS <= now;
}
