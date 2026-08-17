import { ProviderAPIConfig } from '../types';

/**
 * Antigravity's Code Assist backend.
 *
 * The credential layer normally overrides this with the base URL the adapter
 * reports (src/managed/oauth/antigravity.ts), which is how a seat pinned to the
 * daily or sandbox fleet keeps working. This value is the production default
 * for a request that arrives without one.
 */
const API_BASE = 'https://cloudcode-pa.googleapis.com';

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
