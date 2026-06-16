import { listGatewayProviders } from './fetchModels';

/** All gateway providers for admin UI (replaces short hardcoded list). */
export function getProviderCatalogForAdmin() {
  return listGatewayProviders();
}

/** @deprecated use getProviderCatalogForAdmin */
export const MANAGED_PROVIDER_PRESETS = getProviderCatalogForAdmin().filter(
  (p) => p.defaultPrefixes.length > 0 || p.supportsLiveModels
);