import { anthropicClaudeCodeAdapter } from './anthropic';
import { openaiCodexAdapter } from './openaiCodex';
import { registerAdapter } from './registry';

// Registration happens once at module load. Importing this module is what makes
// an adapter reachable; drop a line here to disable a vendor entirely.
registerAdapter(anthropicClaudeCodeAdapter);
registerAdapter(openaiCodexAdapter);

export { getAdapter, listAdapters, registerAdapter } from './registry';
export { resolveOAuthCredential, persistTokens, decryptTokens } from './store';
export * from './types';
