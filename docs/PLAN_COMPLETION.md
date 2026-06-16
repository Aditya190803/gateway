# plan.md — completion checklist

All items from [plan.md](../plan.md) implementation plan.

## Phase 1 — Foundation

| # | Task | Status | Location |
|---|------|--------|----------|
| 1 | D1 schema migration | ✅ | `migrations/0001_initial.sql` |
| 2 | Workers secrets (encryption + JWT) | ✅ | `PROVIDER_KEY_ENCRYPTION_KEY`, `ADMIN_JWT_SECRET`, `.dev.vars.example` |
| 3 | API key validation middleware | ✅ | `src/middlewares/managedProxy/` |
| 4 | Model → provider mapping | ✅ | `src/managed/modelRouting.ts` |
| 5 | wrangler.toml D1 binding | ✅ | `wrangler.toml` |

## Phase 2 — Admin UI

| # | Task | Status | Location |
|---|------|--------|----------|
| 1 | Admin login | ✅ | `POST /admin/login`, dashboard login view |
| 2 | Provider management | ✅ | `POST/DELETE /admin/providers`, presets |
| 3 | User API keys + limits | ✅ | `POST/DELETE /admin/api-keys` |
| 4 | Usage dashboard | ✅ | `GET /admin/usage`, charts + tables |
| 5 | Styled frontend | ✅ | `src/public/admin-dashboard.html` |

## Phase 3 — Rate limiting & polish

| # | Task | Status | Location |
|---|------|--------|----------|
| 1 | RPM sliding window (D1) | ✅ | `migrations/0002_*.sql`, `src/managed/rateLimit.ts` |
| 2 | Monthly token cap | ✅ | `checkRateLimits()` |
| 3 | Usage logging every request | ✅ | `logRequest` + `recordRequestForRpm` |
| 4 | Errors & edge cases | ✅ | multipart model, path defaults, legacy passthrough, OpenAI-style errors |

## API endpoints (plan table)

| Endpoint | Status |
|----------|--------|
| All listed `/v1/*` user routes | ✅ via existing handlers + managed middleware |
| `GET /v1/models` aggregated | ✅ managed middleware |
| All listed `/admin/*` routes | ✅ + logout, presets, setup, health |

## Security (plan)

| Requirement | Status |
|-------------|--------|
| AES-256-GCM provider keys | ✅ `src/managed/encryption.ts` |
| SHA-256 user key hash | ✅ `src/managed/apiKeys.ts` |
| `sk-` key format | ✅ |
| bcrypt admin passwords | ✅ `src/managed/password.ts` |
| Key prefix 8 chars | ✅ |

## Minimal deploy (NOT_NEEDED.md)

| Action | Status |
|--------|--------|
| Stub plugins bundle | ✅ `plugins/index.ts` empty export |
| Remove Node server entry | ✅ `start-server.ts` removed |
| Remove tests/cookbook/docker rollup | ✅ removed |
| package.json Workers-first scripts | ✅ |