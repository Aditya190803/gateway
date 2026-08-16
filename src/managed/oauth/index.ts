import { openaiCodexAdapter } from './openaiCodex';
import { registerAdapter } from './registry';

// Registration happens once at module load. Importing this module is what makes
// an adapter reachable; drop a line here to disable a vendor entirely.
registerAdapter(openaiCodexAdapter);

// The Claude Pro/Max adapter (./anthropic.ts) is deliberately NOT registered.
//
// It authenticates by presenting Claude Code's own client_id and client headers,
// which is what Anthropic's server-side check keys off — those headers exist
// only to make the gateway look like Claude Code to that check. Anthropic runs
// no OAuth program for third-party clients, and using consumer-plan credentials
// outside Claude Code / claude.ai is a Consumer Terms violation that Anthropic
// now rejects at the API anyway.
//
// The file is kept because the adapter interface it implements documents the
// shape a vendor integration takes. Use a metered key from console.anthropic.com
// (the normal `api_key` provider type) for Anthropic models.
// See docs/OAUTH_PROVIDERS.md.

export {
  getAdapter,
  listAdapters,
  registerAdapter,
  vendorServesPath,
} from './registry';
export { resolveOAuthCredential, persistTokens, decryptTokens } from './store';
export * from './types';
