import { POWERED_BY } from '../globals';

/**
 * Legacy Portkey-style routing: client sends provider + api_key via headers/config.
 * When present, managed proxy must not intercept.
 */
export function hasLegacyPortkeyAuth(headers: Headers): boolean {
  const config = headers.get(`x-${POWERED_BY}-config`);
  const provider = headers.get(`x-${POWERED_BY}-provider`);
  if (config?.trim()) return true;
  if (provider?.trim()) return true;
  return false;
}

/** Managed user keys issued by this gateway. */
export function isManagedUserApiKey(token: string): boolean {
  return token.startsWith('sk-') && token.length > 10;
}