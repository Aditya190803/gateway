# AI Gateway — Managed Proxy Plan

## Goal

Turn the Portkey AI Gateway into a self-hosted, managed LLM proxy on Cloudflare Workers where:

- **Admin** adds provider API keys (OpenAI, Anthropic, Groq, etc.) via a web UI
- **Admin** creates user API keys with rate limits
- **Users** get a single API key that works with any model across all configured providers
- **Provider is auto-detected** from the model name (e.g. `gpt-4o` → OpenAI, `claude-3` → Anthropic)

## Architecture

```
                         ┌──────────────────────────────────┐
                         │        Cloudflare Worker          │
                         │                                  │
  User request ──────────┤  POST /v1/chat/completions        │
  Authorization:         │  Authorization: sk-user-xxx       │
  sk-user-xxx            │                                  │
                         │  Middleware pipeline:             │
                         │  1. Validate user API key (D1)   │
                         │  2. Check rate limits (D1)       │
                         │  3. Map model → provider (D1)    │
                         │  4. Look up provider API key (D1)│
                         │  5. Route + decrypt + proxy      │
                         │  6. Log usage (D1)               │
                         │                                  │
                         │  Also serves:                    │
                         │  /admin/* — Admin dashboard UI   │
                         └──────┬───────────────────────────┘
                                │
                     ┌──────────┴──────────┐
                     │   D1 Database        │
                     │   (Cloudflare SQL)   │
                     │                      │
                     │  Tables:             │
                     │  • providers         │
                     │  • users (admin)     │
                     │  • api_keys (user)   │
                     │  • usage_logs        │
                     │  • rate_limit_buckets│
                     └──────────────────────┘
```

## Storage: Cloudflare D1

**Why D1:** Relational queries needed (lookup by key hash, join users to keys, aggregate usage).

**Free tier:** 5GB storage, 5M reads/month, 100K writes/month — comfortable for this use case.

### Database Schema

See `migrations/0001_initial.sql` and `migrations/0002_rate_limit_buckets.sql`.

## Provider Key Security

- Encrypt provider API keys with **AES-256-GCM** before storing in D1
- Encryption key stored in **Workers Secrets** (`PROVIDER_KEY_ENCRYPTION_KEY`)
- Decrypted only in-memory at request time, never logged

## User API Key Security

- User keys generated as `sk-<random-64-chars-hex>`
- Only the **SHA-256 hash** is stored in D1
- The plain key is shown to the admin once at creation time
- On each request, the incoming key is hashed and looked up

## Auto-Routing by Model Name

Map model name patterns → providers. Examples:

| Model pattern | Provider |
|--------------|----------|
| `gpt-*`, `o1-*`, `o3-*`, `dall-e-*`, `tts-*`, `whisper-*`, `text-embedding-*` | openai |
| `claude-*` | anthropic |
| `gemini-*` | google |
| `llama-*`, `mixtral-*`, `deepseek-*` | groq |
| `mistral-*` | mistral-ai |
| `command-*`, `c4ai-*` | cohere |

Configurable per provider in the admin UI or via default prefix map.

## API Endpoints

### Public (user-facing)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/v1/chat/completions` | User key | Chat completions |
| POST | `/v1/completions` | User key | Text completions |
| POST | `/v1/embeddings` | User key | Embeddings |
| POST | `/v1/images/generations` | User key | Image generation |
| POST | `/v1/audio/speech` | User key | Text-to-speech |
| POST | `/v1/audio/transcriptions` | User key | Speech-to-text |
| POST | `/v1/messages` | User key | Anthropic-format chat |
| GET | `/v1/models` | User key | Aggregated models (all providers) |

### Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/admin/login` | — | Admin login |
| GET | `/admin/dashboard` | Session | Admin dashboard HTML |
| POST | `/admin/providers` | Session | Add/update provider key |
| DELETE | `/admin/providers/:id` | Session | Remove provider |
| POST | `/admin/api-keys` | Session | Create user API key |
| GET | `/admin/api-keys` | Session | List user API keys |
| DELETE | `/admin/api-keys/:id` | Session | Revoke user API key |
| GET | `/admin/usage` | Session | View usage stats |

## Implementation Plan

### Phase 1 — Foundation ✅

1. ✅ Create D1 database schema (migration)
2. ✅ Add Workers Secrets for encryption key + admin JWT secret
3. ✅ Build API key validation middleware (hash + lookup + rate limit check)
4. ✅ Build model-to-provider mapping logic
5. ✅ Update `wrangler.toml` with D1 binding

### Phase 2 — Admin UI ✅

1. ✅ Build admin login page
2. ✅ Build provider management page (add/remove API keys)
3. ✅ Build user API key management page (create with limits, revoke)
4. ✅ Build usage dashboard
5. ✅ Style with a clean, simple frontend (inline HTML/JS)

### Phase 3 — Rate Limiting & Polish ✅

1. ✅ Implement RPM limiter (sliding window, stored in D1)
2. ✅ Implement monthly token cap
3. ✅ Add usage logging on every request
4. ✅ Error handling + edge cases (multipart, audio/images defaults, legacy auth passthrough)

## Files to Keep / Remove

See `NOT_NEEDED.md` for optional cleanup of Node/Docker/plugins/tests for minimal Workers deployment.