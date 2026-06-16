import { randomBytes, createHash } from 'crypto';

export function generateInviteCode(): string {
  return `inv-${randomBytes(24).toString('hex')}`;
}

export async function hashInviteCode(code: string): Promise<string> {
  return createHash('sha256').update(code.trim()).digest('hex');
}

export function invitePrefix(code: string): string {
  return code.slice(0, 12);
}
