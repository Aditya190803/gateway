# Subscription-backed (OAuth) providers

The gateway normally talks to model vendors with a metered API key. This adds a
second credential type: a **subscription account's OAuth tokens**, so the
gateway can serve requests from a Claude Pro/Max or ChatGPT Plus/Pro seat
instead of a pay-per-token key.

Read the [Feasibility](#feasibility) section before you invest time in this.
One of the two vendors actively blocks it.

---

## Feasibility

| Vendor | Adapter id | Status | Blocker |
|---|---|---|---|
| ChatGPT Plus/Pro (Codex) | `openai-codex` | Works, with caveats | Callback is a fixed `localhost:1455`, so credentials must be imported rather than authorized in-gateway. Responses API only. |
| Claude Pro/Max (Claude Code) | `anthropic-claude-code` | **Likely rejected upstream** | Anthropic enforces client identity server-side. |

### Anthropic: read this first

Anthropic does not run an OAuth program for third-party clients. The
`client_id` the adapter uses belongs to Claude Code itself, and there is no way
to register your own. Beyond the terms question, Anthropic now enforces this at
the API: consumer-plan OAuth credentials used outside Claude Code and claude.ai
are rejected with

> This credential is only authorized for use with Claude Code and cannot be
> used for other API requests.

The adapter reproduces Claude Code's client headers exactly (`anthropic-beta:
oauth-2025-04-20,claude-code-20250219`, `x-app: cli`, the `claude-cli`
user-agent) because that is what the check keys off, but **assume this will
fail**, and assume the behaviour can change without notice. None of these
endpoints are a public API.

If you want Anthropic models through this gateway reliably, use an API key from
console.anthropic.com with the normal `api_key` provider type.

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

### Concurrent refresh

Both vendors rotate refresh tokens. If two in-flight requests both refresh and
both write, the slower write restores a refresh token the vendor has already
invalidated, and the *next* refresh fails. Writes are therefore guarded on
`oauth_version`; the loser re-reads and uses the winner's tokens.

---

## Setup

Apply the migration:

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

### Connect Claude (expected to fail upstream — see above)

Anthropic redirects to a console page that displays a code, so this one can be
completed against a hosted gateway.

```bash
# 1. Start the flow; open authorize_url in a browser.
curl -X POST https://<gateway>/admin/oauth/start \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"vendor":"anthropic-claude-code","provider_id":"claude-sub"}'

# 2. Paste back the code the console shows (the "code#state" form is accepted).
curl -X POST https://<gateway>/admin/oauth/complete \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"state":"<state from step 1>","code":"<code#state>"}'
```

An existing Claude Code login can be imported instead:

```bash
curl -X POST https://<gateway>/admin/oauth/import \
  -H 'content-type: application/json' -b cookie.txt \
  -d "$(jq -n --argjson creds "$(cat ~/.claude/.credentials.json)" '{
        vendor: "anthropic-claude-code",
        provider_id: "claude-sub",
        credentials: $creds
      }')"
```

On macOS the credentials live in the Keychain item `Claude Code-credentials`
rather than in a file.

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
  -d '{"models":["gpt-5-codex","gpt-5"]}'
```

An empty list routes nothing to the account. In the dashboard this is
**Subscriptions → Edit models**.

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
`/responses`; it does not serve `/chat/completions`. Point clients at
`/v1/responses`, or keep an API-key OpenAI provider configured alongside for
chat-completions traffic.

---

## Adding another vendor

Implement `OAuthAdapter` (`src/managed/oauth/types.ts`) and register it in
`src/managed/oauth/index.ts`. The interface covers the authorize URL, the code
exchange, the refresh, and `decorate()` — which returns the base URL, extra
headers, and where the credential goes. Nothing else in the request path is
vendor-aware. Removing a vendor is a one-line deletion from the registry.

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
