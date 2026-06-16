const IV_LENGTH = 12;
const TAG_LENGTH = 128;

async function getKeyMaterial(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', enc.encode(secret));
  return crypto.subtle.importKey(
    'raw',
    hash,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function encryptProviderKey(
  plain: string,
  secret: string
): Promise<string> {
  const key = await getKeyMaterial(secret);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const enc = new TextEncoder();
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
    key,
    enc.encode(plain)
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipher), iv.length);
  return btoa(String.fromCharCode(...combined));
}

export async function decryptProviderKey(
  stored: string,
  secret: string
): Promise<string> {
  const key = await getKeyMaterial(secret);
  const raw = Uint8Array.from(atob(stored), (c) => c.charCodeAt(0));
  const iv = raw.slice(0, IV_LENGTH);
  const data = raw.slice(IV_LENGTH);
  const dec = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv, tagLength: TAG_LENGTH },
    key,
    data
  );
  return new TextDecoder().decode(dec);
}