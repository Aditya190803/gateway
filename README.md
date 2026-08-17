# AI Gateway — Managed Proxy

Self-hosted LLM proxy on **Cloudflare Workers** with admin UI, encrypted provider keys, user API keys, and automatic model → provider routing.

## Features

- **Admin dashboard** (`/admin/dashboard`) — providers, subscription accounts, user keys, usage analytics
- **User API** — OpenAI-compatible `/v1/*` with `Authorization: Bearer sk-…`
- **Subscription providers** — serve requests from a ChatGPT, Claude, Grok, Antigravity or Kimi seat via OAuth, owner-only ([docs](docs/OAUTH_PROVIDERS.md))
- **Vendor usage limits** — each seat's own rolling quota windows, read live, shown as meters with a trend, and alerted on at 75/90/100%
- **Auto-routing** — `gpt-*` → OpenAI, `claude-*` → Anthropic, etc.
- **Cooldown and failover** — a seat that hits its vendor ceiling is skipped, and the request is retried on another credential
- **Weighted rotation** — several seats can serve the same model and split the traffic
- **Rate limits** — RPM (sliding window) and monthly token caps per key, with consumption visible to the key's owner
- **Request log** — every call including failures and streamed token counts, with the upstream error text
- **Security** — AES-256-GCM provider keys, SHA-256 user key hashes, bcrypt admin passwords

What is missing and what it would take: [docs/ROADMAP.md](docs/ROADMAP.md)

## Quick start

```bash
npm install
cp .dev.vars.example .dev.vars   # set secrets
npx wrangler d1 create ai-gateway-db   # paste database_id into wrangler.toml
npm run db:migrate:local
npm run dev
```

Open `http://localhost:8787/admin/dashboard` → initial setup → add providers → create keys.

Full guide: [docs/MANAGED_PROXY_SETUP.md](docs/MANAGED_PROXY_SETUP.md)

## Secrets (production)

```bash
npx wrangler secret put PROVIDER_KEY_ENCRYPTION_KEY
npx wrangler secret put ADMIN_JWT_SECRET
```

## Deploy

```bash
npm run db:migrate
npm run deploy
```

## Plan status

Implementation tracks [plan.md](plan.md) — Phases 1–3 complete.