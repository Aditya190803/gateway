import { googleAntigravityAdapter } from './antigravity';
import { anthropicClaudeCodeAdapter } from './anthropic';
import { xaiGrokAdapter } from './grok';
import { kimiCodeAdapter } from './kimi';
import { openaiCodexAdapter } from './openaiCodex';
import { registerAdapter } from './registry';

// Registration happens once at module load. Importing this module is what makes
// an adapter reachable; drop a line here to disable a vendor entirely.
//
// Every one uses a client_id belonging to the vendor's own client, because none
// of them register third-party clients. That makes each a terms violation
// against the account you connect, and each can stop working whenever the
// vendor changes its client checks. Enabled deliberately; see
// docs/OAUTH_PROVIDERS.md.
registerAdapter(openaiCodexAdapter);
registerAdapter(anthropicClaudeCodeAdapter);
registerAdapter(xaiGrokAdapter);
registerAdapter(googleAntigravityAdapter);
registerAdapter(kimiCodeAdapter);

export {
  getAdapter,
  listAdapters,
  registerAdapter,
  vendorRoutable,
  vendorServesPath,
} from './registry';
export {
  resolveOAuthCredential,
  persistTokens,
  decryptTokens,
  forceRefresh,
  reinstateIfAutoDisabled,
  getOAuthProviderRowAnyState,
} from './store';
export type { QuotaSnapshot, QuotaWindow } from './quota';
export * from './types';
