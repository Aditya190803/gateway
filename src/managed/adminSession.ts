import { SignJWT, jwtVerify } from 'jose';

const COOKIE_NAME = 'ai_gateway_admin_session';
const MAX_AGE_SEC = 60 * 60 * 12;

export function getAdminJwtSecret(env: { ADMIN_JWT_SECRET?: string }): Uint8Array {
  const s = env.ADMIN_JWT_SECRET?.trim();
  if (!s || s.length < 16) {
    throw new Error(
      'ADMIN_JWT_SECRET must be set (min 16 chars) as a Workers secret'
    );
  }
  return new TextEncoder().encode(s);
}

export async function createAdminToken(
  userId: number,
  email: string,
  role: 'admin' | 'user',
  secret: Uint8Array
): Promise<string> {
  return new SignJWT({ sub: String(userId), email, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${MAX_AGE_SEC}s`)
    .sign(secret);
}

export async function verifyAdminToken(
  token: string,
  secret: Uint8Array
): Promise<{ userId: number; email: string; role: 'admin' | 'user' } | null> {
  try {
    const { payload } = await jwtVerify(token, secret);
    const sub = payload.sub;
    const email = payload.email;
    const role = payload.role === 'admin' ? 'admin' : 'user';
    if (!sub || typeof email !== 'string') return null;
    return { userId: parseInt(String(sub), 10), email, role };
  } catch {
    return null;
  }
}

export function parseCookies(cookieHeader?: string): Record<string, string> {
  if (!cookieHeader) return {};
  return cookieHeader.split(';').reduce(
    (acc, part) => {
      const [rawKey, ...rest] = part.trim().split('=');
      if (!rawKey) return acc;
      acc[rawKey] = decodeURIComponent(rest.join('='));
      return acc;
    },
    {} as Record<string, string>
  );
}

export function getSessionTokenFromRequest(req: Request): string | undefined {
  const cookies = parseCookies(req.headers.get('cookie') ?? undefined);
  if (cookies[COOKIE_NAME]) return cookies[COOKIE_NAME];
  const auth = req.headers.get('authorization');
  if (auth?.toLowerCase().startsWith('bearer ')) {
    return auth.slice(7).trim();
  }
  return undefined;
}

export function setAdminSessionCookie(token: string): string {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${MAX_AGE_SEC}`;
}

export { COOKIE_NAME };