import { adapterServesPath, type OAuthAdapter } from './types';

/**
 * Registered OAuth adapters, keyed by adapter id (providers.oauth_vendor).
 *
 * Adapters are registered rather than hard-referenced so a vendor whose flow
 * breaks can be dropped without touching the request path.
 */
const adapters = new Map<string, OAuthAdapter>();

export function registerAdapter(adapter: OAuthAdapter): void {
  adapters.set(adapter.id, adapter);
}

export function getAdapter(id: string | null | undefined): OAuthAdapter | null {
  if (!id) return null;
  return adapters.get(id) ?? null;
}

export function listAdapters(): OAuthAdapter[] {
  return Array.from(adapters.values());
}

/**
 * Whether a stored vendor id can serve a request path.
 *
 * An unregistered vendor returns true so routing still selects the row and the
 * request fails with the credential layer's explicit "unsupported vendor"
 * message, rather than the caller seeing a misleading "no provider for model".
 */
export function vendorServesPath(
  vendor: string | null | undefined,
  path: string,
): boolean {
  const adapter = getAdapter(vendor);
  return adapter ? adapterServesPath(adapter, path) : true;
}
