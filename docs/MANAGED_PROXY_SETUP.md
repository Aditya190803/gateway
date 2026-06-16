# Managed proxy setup (Cloudflare Workers + D1)

## 1. Create D1 database

```bash
npx wrangler d1 create ai-gateway-db
```

Copy the `database_id` from the output into `wrangler.toml` under `[[d1_databases]]`.

## 2. Apply migrations

```bash
npx wrangler d1 migrations apply ai-gateway-db --local   # dev (0001 schema + 0002 RPM buckets)
npx wrangler d1 migrations apply ai-gateway-db           # production
```

Migrations:

- `0001_initial.sql` — providers, users, api_keys, usage_logs
- `0002_rate_limit_buckets.sql` — sliding-window RPM counters

## 3. Secrets

```bash
npx wrangler secret put PROVIDER_KEY_ENCRYPTION_KEY   # 32+ char random string
npx wrangler secret put ADMIN_JWT_SECRET                # 32+ char random string
```

For local dev, copy `.dev.vars.example` to `.dev.vars` and set strong random values.

## 4. Run

```bash
npm run dev
```

Open **http://localhost:8787/admin/dashboard**

1. Create the first admin user (setup flow when no users exist).
2. Add providers (id must match gateway provider slugs, e.g. `openai`, `anthropic`, `groq`).
3. Create user API keys; clients call `/v1/*` with `Authorization: Bearer sk-...`.

## Auth modes on `/v1/*`

| Mode | When |
|------|------|
| **Managed** | D1 bound, `Bearer sk-…` user key, no legacy Portkey headers |
| **Legacy Portkey** | `x-portkey-config` and/or `x-portkey-provider` set — middleware skips managed auth |
| **Direct provider key** | D1 missing, or `Bearer` token is not an `sk-…` managed key — passes through (you supply provider via Portkey headers) |

Admin passwords are stored with **bcrypt**; older PBKDF2 hashes are upgraded automatically on login.

## API surface

| Area | Paths |
|------|--------|
| User LLM API | Existing `/v1/chat/completions`, `/v1/embeddings`, etc. |
| Admin UI | `GET /admin/dashboard` |
| Health | `GET /health` — `{ status, managed_proxy, db }` |
| Admin API | `POST /admin/login`, `POST /admin/logout`, `GET /admin/provider-presets`, `GET /admin/providers`, `POST /admin/providers`, `DELETE /admin/providers/:id`, `GET/POST/DELETE /admin/api-keys`, `GET /admin/usage`, `POST /admin/setup`, `GET /admin/setup/status` |