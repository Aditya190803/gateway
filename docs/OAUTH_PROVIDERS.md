# Subscription-backed (OAuth) providers

The gateway normally talks to model vendors with a metered API key. This adds a
second credential type: a **subscription account's OAuth tokens**, so the
gateway can serve requests from a Claude Pro/Max or ChatGPT Plus/Pro seat
instead of a pay-per-token key.

Read the [Feasibility](#feasibility) section before you invest time in this.
One of the two vendors actively blocks it.

---

## Feasibility

| Vendor | Adapter id | Status | Notes |
|---|---|---|---|
| ChatGPT Plus/Pro (Codex) | `openai-codex` | Registered, with caveats | Callback is a fixed `localhost:1455`, so credentials must be imported rather than authorized in-gateway. Responses API only. |
| Claude Pro/Max (Claude Code) | `anthropic-claude-code` | **Not registered — disabled** | Impersonates Claude Code's client identity; see below. |

### Anthropic: disabled on purpose

The adapter file (`src/managed/oauth/anthropic.ts`) exists but is **not
registered** in `src/managed/oauth/index.ts`, so it is unreachable from the API
and the dashboard.

Anthropic runs no OAuth program for third-party clients. The `client_id` the
adapter uses belongs to Claude Code itself, and there is no way to register your
own. Anthropic enforces this at the API: consumer-plan OAuth credentials used
outside Claude Code and claude.ai are rejected with

> This credential is only authorized for use with Claude Code and cannot be
> used for other API requests.

The adapter reproduces Claude Code's client headers exactly (`anthropic-beta:
oauth-2025-04-20,claude-code-20250219`, `x-app: cli`, the `claude-cli`
user-agent) — those headers exist for no reason other than to satisfy that
check. That makes it both a Consumer Terms violation and an evasion of a vendor
control, which is why it ships disabled rather than merely documented as risky.

For Anthropic models, use an API key from console.anthropic.com with the normal
`api_key` provider type. That path is supported, metered, and does not depend on
undocumented endpoints.

### OpenAI: what "works" means

Subscription auth is licensed for interactive use, not for backend services.
Putting a proxy in front of it is outside what that licence covers, and the
tokens in `~/.codex/auth.json` are password-equivalent — treat them like a
password, because anyone holding them can spend or impersonate your account.

---

## How it works

`providers` rows gained an `auth_type` column. `api_key` rows behave exactly as
before. `oauth` rows store an encrypted credential blob plus a plaintext expiry:

```
auth_type            'oauth'
oauth_vendor         adapter id, e.g. 'openai-codex'
oauth_credentials    AES-256-GCM blob: access/refresh token, scope, account id
oauth_expires_at     epoch ms, plaintext so the hot path can check it cheaply
oauth_version        bumped on every write; a compare-and-swap guard
owner_only           1 for OAuth rows
owner_user_id        the account that connected it
```

On each request the proxy refreshes the access token if it is within 5 minutes
of expiry, then hands the result to the existing provider transforms via
`custom_host` and `forward_headers`. Forwarded headers are applied last in
`constructRequestHeaders`, so they deliberately override what the built-in
provider config would have sent — that is how the OAuth credential displaces
the vendor's usual API-key header.

### Ownership

A subscription seat is licensed to one person. OAuth providers are created with
`owner_only = 1` and are only visible to `sk-` keys belonging to
`owner_user_id`. Model routing filters them out for everyone else, so another
user's key cannot route onto your seat — it will report "no active provider
configured for model" instead.

Existing API-key providers are unaffected: the column defaults to `0`.

The admin who completes a flow becomes the owner, and `/complete` rejects a
`state` started by a different admin — otherwise the seat could be attached to
an account that never authorized it.

### Concurrent refresh

Both vendors rotate refresh tokens. If two in-flight requests both refresh and
both write, the slower write restores a refresh token the vendor has already
invalidated, and the *next* refresh fails. Writes are therefore guarded on
`oauth_version`; the loser re-reads and uses the winner's tokens.

---

## Setup

> **Apply the migration before deploying this code.** The proxy's provider
> lookup filters on `owner_only` / `owner_user_id` on every request, so code
> running against a pre-0004 database fails **all** `/v1/*` traffic, not just
> subscription routing. Migrate first, then deploy.

```bash
npm run db:migrate:local   # or db:migrate for remote
```

`PROVIDER_KEY_ENCRYPTION_KEY` must be set — it encrypts the credential blob
exactly as it encrypts API keys.

All admin endpoints below require an admin session cookie and the `admin` role.
The same operations are available in the dashboard at
`/admin/dashboard` → **Subscriptions** tab, which is the easier path; the curl
examples are for scripting.

### Connect ChatGPT (Codex)

The Codex client only accepts `http://localhost:1455/auth/callback` as a
redirect target, which a deployed Worker cannot receive. So log in with the
real CLI first, then import the result:

```bash
codex login              # writes ~/.codex/auth.json
```

```bash
curl -X POST https://<gateway>/admin/oauth/import \
  -H 'content-type: application/json' \
  -b cookie.txt \
  -d "$(jq -n --argjson creds "$(cat ~/.codex/auth.json)" '{
        vendor: "openai-codex",
        provider_id: "chatgpt-sub",
        provider_name: "ChatGPT Pro seat",
        credentials: $creds
      }')"
```

The imported access token is marked stale on purpose, so the first request
refreshes it and the gateway learns the real lifetime from the response.

### Overwriting an existing provider

Connecting a subscription under a `provider_id` that already holds an API key
discards that key — the encrypted secret is not recoverable afterwards. Both
`/start` and `/import` refuse with **409** in that case:

```
Provider "openai" already exists with an API key. Connecting a subscription
here permanently discards that key. Pass overwrite: true to convert it, or
choose a different provider id.
```

Add `"overwrite": true` to convert deliberately. `/start` checks before sending
you to the vendor, so a mistyped id costs a corrected form field rather than a
wasted authorization; when you start with `overwrite`, pass it to `/complete`
as well. The dashboard asks for confirmation and handles both calls for you.

### Inspect and refresh

```bash
curl https://<gateway>/admin/oauth/vendors    -b cookie.txt
curl https://<gateway>/admin/oauth/providers  -b cookie.txt
curl -X POST https://<gateway>/admin/oauth/chatgpt-sub/refresh -b cookie.txt
```

`/providers` reports the connected account, the routing model list, expiry, and
whether it has lapsed. It never returns the tokens themselves. `/refresh`
forces a round trip so you can verify a connection without sending real
traffic.

### Change which models route to a subscription

Subscription endpoints expose no `/models` API, so the model list on the
provider row is authoritative and is edited directly:

```bash
curl -X POST https://<gateway>/admin/oauth/chatgpt-sub/models \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"models":["gpt-5-codex"]}'
```

An empty list routes nothing to the account. In the dashboard this is
**Subscriptions → Edit models**. Entries are matched as prefixes, so keep them
specific enough not to swallow traffic meant for a metered provider.

### Disconnect

Deleting the provider row deletes the stored credentials:

```bash
curl -X DELETE https://<gateway>/admin/providers/chatgpt-sub -b cookie.txt
```

---

## Using it

Once connected, an OAuth provider is routed to by model name like any other, using
your normal managed `sk-` key — the client sends nothing special:

```bash
curl https://<gateway>/v1/responses \
  -H "authorization: Bearer sk-<your managed key>" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-5-codex","input":"write a haiku about proxies"}'
```

**Codex is Responses-API only.** `https://chatgpt.com/backend-api/codex` serves
`/responses`; it does not serve `/chat/completions`. The adapter declares
`supportedPaths: ['/v1/responses']`, and routing drops OAuth providers that do
not serve the request path *before* matching a model — so a
`/v1/chat/completions` call falls through to an API-key OpenAI provider if you
have one, and otherwise reports "no active provider configured for model"
rather than failing against an upstream that was never going to answer.

Keep the seeded model list narrow for the same reason. Model matching is by
prefix, so a bare `gpt-5` entry captures every `gpt-5*` request the owner makes.
The adapter seeds only `gpt-5-codex`.

---

## Adding another vendor

Implement `OAuthAdapter` (`src/managed/oauth/types.ts`) and register it in
`src/managed/oauth/index.ts`. The interface covers the authorize URL, the code
exchange, the refresh, and `decorate()` — which returns the base URL, extra
headers, and where the credential goes. Set `supportedPaths` when the backend
serves less than the vendor's full API, and keep `defaultModels` specific
(they are prefixes). Nothing else in the request path is vendor-aware.
Registration and removal are both one line.

Do not add a vendor by borrowing another client's `client_id` and reproducing
its headers to get past a server-side client check. That is what got the
Anthropic adapter disabled.

Vendors deliberately **not** implemented, and why:

- **Cursor** — the backend speaks Connect/gRPC over protobuf with an
  anti-abuse checksum header, not JSON. A reimplementation would be brittle and
  would break on any client update.
- **Kiro** — AWS IAM Identity Center OIDC into CodeWhisperer endpoints, whose
  responses are AWS event-stream framed rather than JSON. Doable, but it needs
  its own wire-format decoder rather than an adapter.
- **Cline** — no separate protocol to implement. Cline is bring-your-own-key:
  point it at this gateway as an OpenAI-compatible base URL with your `sk-`
  key. Nothing to add here.
- **GitHub Copilot** — a device-code flow plus a short-lived token exchange.
  This one is a reasonable next adapter if you want it; it was out of scope
  for this pass.
