import { anthropicClaudeCodeAdapter } from './anthropic';
import { xaiGrokAdapter } from './grok';
import { openaiCodexAdapter } from './openaiCodex';
import { registerAdapter } from './registry';

// Registration happens once at module load. Importing this module is what makes
// an adapter reachable; drop a line here to disable a vendor entirely.
//
// All three use a client_id belonging to the vendor's own CLI, because none of
// them register third-party clients. That makes each a terms violation against
// the account you connect, and each can stop working whenever the vendor
// changes its client checks. Enabled deliberately; see docs/OAUTH_PROVIDERS.md.
registerAdapter(openaiCodexAdapter);
registerAdapter(anthropicClaudeCodeAdapter);
registerAdapter(xaiGrokAdapter);

export {
  getAdapter,
  listAdapters,
  registerAdapter,
  vendorServesPath,
} from './registry';
export {
  resolveOAuthCredential,
  persistTokens,
  decryptTokens,
  forceRefresh,
} from './store';
export * from './types';
