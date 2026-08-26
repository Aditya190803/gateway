import { ProviderAPIConfig } from '../types';

/**
 * Antigravity's Code Assist backend.
 *
 * The credential layer normally overrides this with the base URL the adapter
 * reports (src/managed/oauth/antigravity.ts). This value is just the fallback
 * for a request that arrives without one — kept in sync with that adapter's
 * default (the daily fleet; the real Antigravity CLI never calls the plain
 * `cloudcode-pa.googleapis.com` host at all).
 */
const API_BASE = 'https://daily-cloudcode-pa.googleapis.com';

export const GoogleAntigravityApiConfig: ProviderAPIConfig = {
  getBaseURL: () => API_BASE,
  headers: () => ({ 'Content-Type': 'application/json' }),
  getEndpoint: ({ gatewayRequestBodyJSON }) => {
    // Every generation goes through one of two v1internal methods; the model is
    // in the body rather than the path, unlike the public Gemini API.
    const { stream } = gatewayRequestBodyJSON;
    return stream
      ? '/v1internal:streamGenerateContent?alt=sse'
      : '/v1internal:generateContent';
  },
};

export default GoogleAntigravityApiConfig;
