# Subscription-backed (OAuth) providers

The gateway normally talks to model vendors with a metered API key. This adds a
second credential type: a **subscription account's OAuth tokens**, so the
gateway can serve requests from a ChatGPT, Claude, or Grok seat instead of a
pay-per-token key.

Read [What you are agreeing to](#what-you-are-agreeing-to) before you invest
time in this.

---

## Vendors

| Vendor | Adapter id | Gateway provider | Browser authorization | Serves |
|---|---|---|---|---|
| ChatGPT Plus/Pro (Codex) | `openai-codex` | `openai` | Approve, paste the URL back | `/v1/responses` only |
| Claude Pro/Max (Claude Code) | `anthropic-claude-code` | `anthropic` | Approve, paste the URL back | Full Anthropic surface |
| Grok (Grok CLI) | `xai-grok-cli` | `x-ai` | Type a code into xAI's page | Chat, via the CLI chat proxy |

All three can be connected in the browser from Subscriptions → Connect an
account, and all three can alternatively be connected by importing a credential
file. Both routes end in the same place.

### Browser authorization

**Codex and Claude — approve, then paste back the URL.** These clients register
a loopback redirect (`localhost:1455` and `localhost:54545`) that a deployed
gateway cannot receive. That is fine: approving sends the browser to that
address, the page fails with *"this site can't be reached"* because nothing is
listening there, **and the authorization code is sitting in the address bar**.
Copy the whole URL and paste it in. The bare code and Anthropic's `code#state`
form are accepted too. A `state` that does not match the attempt is rejected.

**Grok — type a code into xAI's page.** xAI's client authorizes by device code
(RFC 8628), so there is nothing to paste back: the gateway shows a short code
and a link to `accounts.x.ai/oauth2/device`, and polls until you approve.

### Importing a credential file instead

Run the vendor's CLI login and paste what it wrote. The parser accepts the
native CLI file and the flatter auth file a proxy such as CLIProxyAPI writes,
as JSON or as raw file contents:

| Vendor | File |
|---|---|
| Codex | `~/.codex/auth.json` (`codex login`) |
| Claude | `~/.claude/.credentials.json` — on macOS, Keychain item `Claude Code-credentials` |
| Grok | the auth JSON the Grok CLI login writes (`"type": "xai"`) |

## What you are agreeing to

Every adapter authenticates with a `client_id` belonging to the vendor's own
CLI, because none of these vendors register third-party clients. That has
consequences worth stating plainly:

- **It is a terms violation on the account you connect.** Subscription auth is
  licensed for interactive use in the vendor's own client, not for fronting with
  a proxy. The account you connect is the one at risk.
- **It can break without notice.** None of these endpoints are a public API.
  Client ids, hosts, scopes, and required headers change with CLI releases.
- **Anthropic enforces it server-side.** Consumer-plan OAuth credentials used
  outside Claude Code and claude.ai are rejected with *"This credential is only
  authorized for use with Claude Code and cannot be used for other API
  requests."* The adapter sends Claude Code's client headers because that is
  what the check keys off. Expect it to fail, and expect any workaround to stop
  working.

A metered API key remains the supported path for all three vendors, and the
`api_key` provider type is unchanged. Use it where reliability matters.

Treat these tokens as password-equivalent: anyone holding them can spend or
impersonate the account.

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

These vendors rotate refresh tokens, so the refresh **call** has to be
exclusive, not just the write. Two requests that both read version `N` and both
call the vendor with the same refresh token spend it twice: one rotation wins
and the other is invalidated, and under reuse detection the whole token family
can be revoked — which kills the seat until an operator reconnects it. Guarding
only the write is too late; the damage happens at the vendor.

So a refresh is claimed before the network call, with a conditional
`UPDATE … SET oauth_version = oauth_version + 1 WHERE id = ? AND oauth_version = ?`.
Exactly one caller moves the row off version `N` and only that caller talks to
the vendor. Others wait briefly for it to publish, then use its tokens.

A claimer that dies mid-refresh leaves the version bumped and the credentials
untouched. That is self-healing: the row is still expired, so the next request
claims the new version and retries. The admin refresh endpoint takes the same
claim, so pressing **Refresh** during an in-flight refresh cannot double-spend.

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

The request body is built on stdin and piped in. Do not pass it with `-d "$(…)"`
— that puts your access and refresh tokens in the argument list of both `jq` and
`curl`, where any local process listing can read them.

```bash
jq -n --slurpfile creds ~/.codex/auth.json '{
      vendor: "openai-codex",
      provider_id: "chatgpt-sub",
      provider_name: "ChatGPT Pro seat",
      credentials: $creds[0]
    }' | curl -X POST https://<gateway>/admin/oauth/import \
      -H 'content-type: application/json' \
      -b cookie.txt \
      --data-binary @-
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

Prefer `importFromFile` over an in-gateway flow. Every vendor here registers a
loopback redirect that a deployed gateway cannot receive, so importing the
credential the vendor's CLI already wrote is what actually works. The helpers in
`credentialFiles.ts` cover the shapes these files come in — nested or flat, with
expiry as epoch milliseconds, epoch seconds, or an RFC 3339 string.

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
