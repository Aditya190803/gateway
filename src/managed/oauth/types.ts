/**
 * Vendor-agnostic OAuth support for subscription-backed providers.
 *
 * An adapter encapsulates everything vendor-specific about signing in with a
 * subscription account and then spending it on an inference request:
 * the authorize URL, the token exchange, the refresh, and how the resulting
 * token is presented upstream (which host, which headers).
 */

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
};

export type AuthorizeRequest = {
  redirectUri: string;
  state: string;
  codeChallenge: string;
};

export type ExchangeRequest = {
  code: string;
  codeVerifier: string;
  redirectUri: string;
  state?: string;
};

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

  /** Callback path this adapter expects, relative to the gateway origin. */
  callbackPath: string;

  /**
   * Some vendors hand the user a code to paste rather than redirecting to a
   * gateway-hosted callback. When true the admin UI offers a paste box.
   */
  supportsManualCode: boolean;

  buildAuthorizeUrl(req: AuthorizeRequest): string;
  exchangeCode(req: ExchangeRequest): Promise<OAuthTokens>;
  refresh(tokens: OAuthTokens): Promise<OAuthTokens>;

  /** Describes how to address an upstream call carrying these tokens. */
  decorate(tokens: OAuthTokens): UpstreamCall;

  /**
   * Parse credentials the vendor's own CLI already wrote to disk, so an
   * existing login can be imported instead of re-running the flow.
   * Returns null when the blob is not in this vendor's format.
   */
  importFromFile?(blob: unknown): OAuthTokens | null;

  /** Where that CLI stores them, shown in the UI as an import hint. */
  credentialFileHint?: string;

  /** Models to seed the provider row with, so routing works immediately. */
  defaultModels: string[];
}

/** Refresh slightly early: a token that expires mid-flight reads as a 401. */
export const REFRESH_SKEW_MS = 5 * 60 * 1000;

export function isExpired(expiresAt: number, now = Date.now()): boolean {
  return !Number.isFinite(expiresAt) || expiresAt - REFRESH_SKEW_MS <= now;
}
