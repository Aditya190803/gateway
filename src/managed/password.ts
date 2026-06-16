import bcrypt from 'bcryptjs';

const BCRYPT_ROUNDS = 12;
const PBKDF2_PREFIX = 'pbkdf2:';

/** New hashes use bcrypt (plan: bcrypt at rest). */
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt(BCRYPT_ROUNDS);
  return bcrypt.hash(password, salt);
}

export async function verifyPassword(
  password: string,
  stored: string
): Promise<boolean> {
  if (stored.startsWith('$2')) {
    return bcrypt.compare(password, stored);
  }
  if (stored.startsWith(PBKDF2_PREFIX)) {
    return verifyPbkdf2Legacy(password, stored);
  }
  return false;
}

/** Upgrade legacy PBKDF2 hashes after successful login. */
export function shouldUpgradePasswordHash(stored: string): boolean {
  return stored.startsWith(PBKDF2_PREFIX);
}

async function verifyPbkdf2Legacy(
  password: string,
  stored: string
): Promise<boolean> {
  const parts = stored.split(':');
  if (parts[0] !== 'pbkdf2' || parts.length !== 4) return false;
  const iterations = parseInt(parts[1], 10);
  const salt = Uint8Array.from(atob(parts[2]), (c) => c.charCodeAt(0));
  const expected = Uint8Array.from(atob(parts[3]), (c) => c.charCodeAt(0));
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    key,
    256
  );
  const actual = new Uint8Array(bits);
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i++) diff |= actual[i] ^ expected[i];
  return diff === 0;
}