/** PKCE (RFC 7636) helpers, WebCrypto-only so they run on Workers. */

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function randomBase64Url(byteLength: number): string {
  return base64UrlEncode(crypto.getRandomValues(new Uint8Array(byteLength)));
}

/** 32 random bytes → 43-char verifier, the RFC's recommended length. */
export function generateCodeVerifier(): string {
  return randomBase64Url(32);
}

export async function deriveCodeChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(verifier),
  );
  return base64UrlEncode(new Uint8Array(digest));
}

export function generateState(): string {
  return randomBase64Url(24);
}

export async function createPkcePair(): Promise<{
  verifier: string;
  challenge: string;
}> {
  const verifier = generateCodeVerifier();
  return { verifier, challenge: await deriveCodeChallenge(verifier) };
}

/**
 * Decode a JWT payload without verifying it.
 *
 * Only for reading non-security claims out of an id_token the vendor just
 * handed us over TLS (account id, plan tier). Never use this to make an
 * authorization decision.
 */
export function decodeJwtPayload(
  token: string,
): Record<string, unknown> | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const json = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4));
    const decoded = decodeURIComponent(
      Array.from(json)
        .map((ch) => '%' + ch.charCodeAt(0).toString(16).padStart(2, '0'))
        .join(''),
    );
    return JSON.parse(decoded) as Record<string, unknown>;
  } catch {
    return null;
  }
}
