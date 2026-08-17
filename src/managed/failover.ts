/**
 * Retrying a managed request against a second credential.
 *
 * Marking an exhausted seat as cooling down only helps the *next* request; the
 * one that discovered the exhaustion still fails. This wrapper gives that
 * request another try on a different provider, which is the difference between
 * "one request in every quota window fails" and "nothing fails until every
 * credential is out".
 *
 * It sits outside the Hono app rather than inside the proxy middleware because
 * Hono's `next()` may be called exactly once per request — retrying downstream
 * from within a middleware is not expressible. Re-entering `app.fetch` with a
 * fresh Request is, so the retry happens here and the proxy middleware only
 * reports whether one is worth attempting.
 */

import { hasLegacyPortkeyAuth, isManagedUserApiKey } from './legacyAuth';

/** Shared between this wrapper and the proxy middleware, carried on `env`. */
export type FailoverState = {
  /** Providers already tried for this request, so a retry picks another. */
  attempted: string[];
  /**
   * Set by the proxy when the attempt failed in a way another credential could
   * plausibly serve. Cleared before each attempt, so it always describes the
   * most recent one.
   */
  retry: boolean;
};

/**
 * Where the state hangs off `env`.
 *
 * `env` is the only channel that reaches the middleware and comes back out:
 * the Request is rebuilt per attempt and the Response is the thing being
 * retried. Prefixed to keep it clearly distinct from real bindings.
 */
export const FAILOVER_STATE_KEY = '__managedFailover';

/** Initial attempt plus two retries. Three dead seats is a real outage. */
const MAX_ATTEMPTS = 3;

/**
 * Largest body the wrapper will hold in memory to make a retry possible.
 *
 * A retry needs the body a second time, and the only way to have it is to have
 * kept it. Above this, the request streams straight through and simply cannot
 * be retried — better than buffering an audio upload into a Worker's heap.
 */
const MAX_REPLAY_BYTES = 1024 * 1024;

export function getFailoverState(env: unknown): FailoverState | null {
  if (!env || typeof env !== 'object') return null;
  const state = (env as Record<string, unknown>)[FAILOVER_STATE_KEY];
  return state && typeof state === 'object' ? (state as FailoverState) : null;
}

/** Requests the managed proxy will route, and therefore might retry. */
function isManagedRequest(request: Request): boolean {
  if (!new URL(request.url).pathname.startsWith('/v1/')) return false;
  if (hasLegacyPortkeyAuth(request.headers)) return false;
  const auth = request.headers.get('authorization');
  if (!auth) return false;
  const [scheme, token] = auth.trim().split(/\s+/, 2);
  return (
    scheme?.toLowerCase() === 'bearer' && !!token && isManagedUserApiKey(token)
  );
}

type FetchLike = (
  request: Request,
  env: unknown,
  ctx: ExecutionContext
) => Response | Promise<Response>;

/**
 * Wrap an app so managed requests can be retried on a second provider.
 *
 * Anything that is not a managed request — the admin UI, legacy Portkey
 * routing, health checks — is handed straight through untouched, so the wrapper
 * costs nothing outside the path it exists for.
 */
export function withProviderFailover(app: { fetch: FetchLike }): FetchLike {
  return async (request: Request, env: unknown, ctx: ExecutionContext) => {
    if (!isManagedRequest(request)) {
      return app.fetch(request, env, ctx);
    }

    let body: ArrayBuffer | null = null;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const declared = Number(request.headers.get('content-length'));
      if (!Number.isFinite(declared) || declared > MAX_REPLAY_BYTES) {
        return app.fetch(request, env, ctx);
      }
      body = await request.arrayBuffer();
    }

    const state: FailoverState = { attempted: [], retry: false };
    const scopedEnv = {
      ...(env as Record<string, unknown>),
      [FAILOVER_STATE_KEY]: state,
    };

    for (let attempt = 0; ; attempt++) {
      state.retry = false;
      const attemptRequest = new Request(request.url, {
        method: request.method,
        headers: request.headers,
        ...(body ? { body } : {}),
      });
      const response = await app.fetch(attemptRequest, scopedEnv, ctx);

      // Out of attempts means this response is the answer, even though another
      // credential might have served it — the alternative is an unbounded
      // retry loop across a user's whole provider list.
      if (!state.retry || attempt >= MAX_ATTEMPTS - 1) return response;

      // Another credential is going to answer instead, so this body is never
      // read. Cancelling releases it rather than leaving the stream dangling;
      // the failure itself has already been logged by the middleware.
      await response.body?.cancel().catch(() => {});
    }
  };
}
