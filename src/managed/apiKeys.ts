export async function hashApiKey(raw: string): Promise<string> {
  const data = new TextEncoder().encode(raw);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateUserApiKey(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
  return `sk-${hex}`;
}

/** Plan: first 8 chars for display (includes `sk-` prefix). */
export function keyPrefix(raw: string): string {
  return raw.slice(0, 8);
}