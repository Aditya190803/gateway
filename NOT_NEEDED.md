# Files Not Needed for Simplified Managed Proxy

This lists every file/folder that can be removed for the simplified self-hosted use case (Cloudflare Workers, admin UI, user API keys, auto-routing).

## Deleted

### Node.js Server (not used on Workers)
```
src/start-server.ts
src/handlers/realtimeHandlerNode.ts
```

### Plugin System (guardrails, PII, content moderation, etc.)
The plugins are an entire external guardrail system. Not needed for basic proxying.

```
plugins/                          ← entire directory
src/middlewares/hooks/             ← tightly coupled to plugins; replace with stubs
src/handlers/services/hooksService.ts
src/middlewares/hooks/globals.ts
src/middlewares/hooks/types.ts
```

### Rollup Build System (Wrangler bundles for Workers)
```
rollup.config.js
start-test.js
```

### Docker / Deployment Files (not Workers)
```
Dockerfile
.dockerignore
docker-compose.yaml
deployment.yaml
```

### Documentation
```
docs/                             ← entire directory
README.md
CLAUDE.md
```

### Examples & Cookbooks
```
cookbook/                         ← entire directory
```

### GitHub Config & Git Hooks
```
.github/                          ← entire directory
.husky/                           ← entire directory
.gitattributes
.git-blame-ignore-revs
```

### Patches (package fixes, not needed with modern deps)
```
patches/                          ← entire directory
```

### Test Files
```
src/tests/                        ← entire directory
tests/                            ← entire directory
plugins/*/**.test.ts              ← covered by plugins/ delete above
jest.config.js
```

### Linting / Formatting
```
eslint.config.js
.prettierrc
.prettierignore
```

### VS Code Config
```
.vscode/                          ← entire directory
```

### Example / Sample Configs
```
conf.example.json
initializeSettings.ts
```

### Replit Docs
```
docs/deploy-on-replit.md          ← covered by docs/ delete above
```

## Keep (Core Functionality)

### Source Code — Keep All
```
src/index.ts                      ← Main entry point
src/providers/                    ← ALL 80+ provider integrations (core value)
src/handlers/                     ← Keep all handlers except realtimeHandlerNode.ts
  └── chatCompletionsHandler.ts    ← Essential
  └── completionsHandler.ts        ← Essential
  └── embeddingsHandler.ts         ← Essential
  └── handlerUtils.ts              ← Core routing logic
  └── modelsHandler.ts             ← Model listing
  └── responseHandlers.ts          ← Response transformation
  └── retryHandler.ts              ← Retry logic
  └── streamHandler.ts             ← Streaming support
  └── streamHandlerUtils.ts
  └── createSpeechHandler.ts       ← Audio
  └── createTranscriptionHandler.ts
  └── createTranslationHandler.ts
  └── imageGenerationsHandler.ts   ← Image
  └── imageEditsHandler.ts
  └── messagesHandler.ts           ← Anthropic format
  └── messagesCountTokensHandler.ts
  └── modelResponsesHandler.ts
  └── batchesHandler.ts            ← Optional but harmless
  └── filesHandler.ts              ← Optional but harmless
  └── finetuneHandler.ts           ← Optional but harmless
  └── proxyHandler.ts              ← Deprecated but referenced
  └── realtimeHandler.ts           ← WebSocket (Workers)
  └── websocketUtils.ts
  └── services/
      ├── cacheService.ts
      ├── logsService.ts
      ├── preRequestValidatorService.ts
      ├── providerContext.ts
      ├── requestContext.ts
      └── responseService.ts
src/middlewares/
  ├── requestValidator/            ← Essential (validates incoming requests)
  ├── cache/                       ← Optional but lightweight
  ├── log/                         ← Keep (logging)
  └── adminAuth/                   ← Modify to user our admin auth
src/types/                         ← All type definitions (essential)
src/utils/                         ← All utilities (essential)
src/errors/                        ← Error handling (essential)
src/services/                      ← Core services (essential)
src/shared/                        ← Shared utilities, cache backends
src/apm/                           ← Logging/monitoring
src/data/                          ← Provider + model data
src/globals.ts                     ← Constants
src/utils.ts                       ← Utility functions
src/public/index.html              ← Keep / modify into admin UI
```

### Config & Infrastructure
```
wrangler.toml                      ← Needed for Workers deployment
package.json                       ← Dependencies
tsconfig.json                      ← TypeScript config
conf.json                          ← Modify to strip plugins, use minimal config
LICENSE                            ← Keep for licensing
```

## Summary

**Total kept:** ~500+ source files (all providers + handlers + types + utilities)
**Total deleted:** ~200+ files (plugins, docs, tests, cookbook, build config)
**Modified:** ~5-10 files (conf.json, wrangler.toml, index.ts, adminAuth, handlerUtils for auto-routing)
**New files:** ~10-15 files (D1 schema, admin UI pages, new middleware, model routing map, rate limiter)
