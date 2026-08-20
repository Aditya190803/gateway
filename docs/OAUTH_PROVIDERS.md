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
| Antigravity (Google IDE) | `google-antigravity` | `google-antigravity` | Approve, paste the URL back | Chat, via Code Assist |
| Kimi Code | `kimi-code` | `moonshot` | Type a code into Kimi's page | Chat, via the coding API |

Each can be connected in the browser from Subscriptions → Connect an account,
and each can alternatively be connected by importing a credential file. Both
routes end in the same place.

### Antigravity needs its client credentials configured

Every other adapter here authorizes as a public client with PKCE and no secret.
Google issues installed applications a client *secret* as well, and although it
ships inside the desktop app and is not confidential in any real sense, it is
still a credential belonging to Google rather than to this project — so it is
not committed. Read both values out of the Antigravity client and set them:

```bash
npx wrangler secret put ANTIGRAVITY_CLIENT_ID
npx wrangler secret put ANTIGRAVITY_CLIENT_SECRET
```

Until they are set, Antigravity refuses to authorize or refresh and says so, and
the connect form names the missing secrets rather than letting you get as far as
a failed token exchange. Seats already connected keep serving traffic on their
current access token but cannot refresh, so set these before the token lapses.

### Antigravity is not a credential swap

The other vendors speak a wire format the gateway already implements, so
connecting a seat changes only which token and host a request uses. Antigravity
speaks `v1internal` on `cloudcode-pa.googleapis.com`, where the body is a Gemini
payload wrapped as

```json
{ "model": "…", "project": "…", "requestId": "…", "requestType": "agent",
  "request": { "contents": [...], "generationConfig": {...} } }
```

and every response — including each SSE frame — comes back as `{"response": …}`.

So it has its own gateway provider, `src/providers/google-antigravity`. That
provider does not re-implement any Gemini translation: it reuses Google's entire
parameter map with each target path moved under `request.`, and unwraps the
envelope before handing responses to Google's transforms. Anything Gemini gains
here, Antigravity gains, because there is one translation and it lives in
`src/providers/google`.

**The project id matters.** Quota, model discovery and every generation need the
Cloud project the account is onboarded to. The gateway reads it once at connect
time from `loadCodeAssist` and stores it beside the tokens; from there it
travels in the provider config, because a parameter transform can read provider
options but not headers. An account that has never opened the Antigravity IDE
has no project yet, and the connection says so rather than failing opaquely
later.

### Browser authorization

**Codex, Claude, and Antigravity — approve, then paste back the URL.** These
clients register a loopback redirect (`localhost:1455`, `localhost:54545`,
`localhost:51121`) that a deployed gateway cannot receive. That is fine:
approving sends the browser to that address, the page fails with *"this site
can't be reached"* because nothing is listening there, **and the authorization
code is sitting in the address bar**. Copy the whole URL and paste it in. The
bare code and Anthropic's `code#state` form are accepted too. A `state` that
does not match the attempt is rejected.

Or skip the copy-paste: run `node scripts/oauth-catch.mjs <codex|claude|antigravity> <gateway-url>`
before clicking Authorize — for example
`node scripts/oauth-catch.mjs codex https://your-gateway.example.workers.dev`, or
`node scripts/oauth-catch.mjs claude http://localhost:8787` against a local dev
server. The gateway URL is required, not defaulted: this catcher redirects a
live browser tab, and a wrong guess (say, a local test landing on prod) sends
the code to the wrong deployment with no visible error. It listens on that
exact loopback port, catches the redirect the vendor sends the browser to, and
forwards the code to `/admin/dashboard` as a query param — the dashboard
finishes the connection itself as soon as it sees one, the same way it would
from a pasted URL. One redirect and the script exits.

**Grok and Kimi — type a code into the vendor's page.** Both clients authorize
by device code
(RFC 8628), so there is nothing to paste back: the gateway shows a
short code and a link to the vendor's device page, and polls until you approve.

### Importing a credential file instead

Run the vendor's CLI login and paste what it wrote. The parser accepts the
native CLI file and the flatter auth file a proxy such as CLIProxyAPI writes,
as JSON or as raw file contents:

| Vendor | File |
|---|---|
| Codex | `~/.codex/auth.json` (`codex login`) |
| Claude | `~/.claude/.credentials.json` — on macOS, Keychain item `Claude Code-credentials` |
| Grok | the auth JSON the Grok CLI login writes (`"type": "xai"`) |
| Antigravity | the auth JSON a proxy writes after the Antigravity login (`"type": "antigravity"`) |
| Kimi | the auth JSON the Kimi Code login writes (`"type": "kimi"`) |

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

`provider_id` is worth picking deliberately — it shows up in `owned_by` on
`/v1/models` and in any `provider_id/model` address (see
[SUBSCRIPTIONS_AS_API.md](SUBSCRIPTIONS_AS_API.md)), and the vendor alias
(`codex/`, `claude/`, `grok/`, `anti/`, `kimi/`) already routes without ever
naming a row, so there's no reason the id itself has to say which vendor it is
or that it's a subscription seat. `q1-a` below is a stand-in for whatever short,
opaque id you pick; the dashboard suggests one in the same style
(`q1-a`, `q1-b`, …) when you connect from the browser.

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
      provider_id: "q1-a",
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
curl -X POST https://<gateway>/admin/oauth/q1-a/refresh -b cookie.txt
```

`/providers` reports the connected account, the routing model list, expiry, and
whether it has lapsed. It never returns the tokens themselves. `/refresh`
forces a round trip so you can verify a connection without sending real
traffic.

### See how much of the subscription is left

```bash
curl https://<gateway>/admin/oauth/q1-a/usage -b cookie.txt
```

```json
{
  "status": "success",
  "plan": "pro",
  "windows": [
    { "id": "code-0", "label": "Rolling 5h", "usedPercent": 41.2,
      "resetsAt": 1755412800000, "periodHours": 5 },
    { "id": "code-1", "label": "Weekly", "usedPercent": 63.0,
      "resetsAt": 1755840000000, "periodHours": 168 }
  ],
  "notes": ["2 rate-limit reset credits available"],
  "fetchedAt": 1755400000000
}
```

This is the **seat's** quota — the rolling windows the vendor's own client
shows — and is a different question from `/admin/usage`, which reports what this
gateway spent. A subscription has the capacity of one interactive user, so this
is what tells you a seat is about to start refusing requests.

| Vendor | Reported |
|---|---|
| Claude Pro/Max | 5-hour session window, the weekly windows (all models, Opus, Sonnet, Cowork, OAuth apps), any per-model weekly cap, plan tier, extra-usage credits |
| ChatGPT (Codex) | Rolling and weekly/monthly rate-limit windows, the same again for code review, plan type, reset credits |
| Grok | Credit consumption for the current billing period, per-product usage, monthly spend against the cap |
| Antigravity | Every quota bucket the Code Assist backend reports, per group, with its window and reset time |
| Kimi | Each limit with a window, derived from the counts the coding API reports |

The dashboard shows the same thing as meters under each row in
**Subscriptions**, loaded once per visit with a per-seat **Refresh**.

### History and alerts

A live read answers "how much is left right now", for whoever is looking. An
hourly Cron Trigger samples every connected seat and keeps the samples, which
covers the case nobody is looking:

```bash
curl 'https://<gateway>/admin/oauth/q1-a/history?days=7' -b cookie.txt
```

```json
{ "days": 7, "series": { "code-0": [ { "t": 1755400000000, "p": 41.2 }, … ] } }
```

The dashboard draws each series as a sparkline beside its meter, on a fixed
0–100 scale so a window at 2% cannot look like one at 90%.

Set `ALERT_WEBHOOK_URL` and the same job posts when a window crosses **75%,
90% or 100%**. Slack and Discord webhook URLs work unchanged; anything else
receives the same JSON, which carries the message under both `text` and
`content`. Each window is tracked separately — a Claude seat can be fine on its
5-hour window and out of weekly Opus, and one number for the seat would hide
which limit actually bit. A crossing notifies once: the level is remembered, and
only a *rise* is news, so a window that resets is recorded silently and becomes
eligible to notify again.

The same job prunes the request log (`LOG_RETENTION_DAYS`, default 30) and quota
history (90 days).

These are the vendors' own client endpoints, not public APIs, and carry the same
caveat as everything else here: they can change shape or disappear. A seat whose
lookup fails reports `502` with the vendor's message and is shown as "Limits
unavailable" on that row alone; a vendor with no usage endpoint at all answers
`200` with `"status": "unsupported"`.

### Spend a reset credit

Some vendors sell a way out of a rate-limit window. Where one exists, the usage
snapshot advertises it as `action` and it is redeemed explicitly:

```bash
curl -X POST https://<gateway>/admin/oauth/q1-a/quota-action \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"action":"reset-credit"}'
```

Today only Codex offers one. It is never redeemed automatically on a 429: the
credit is spent whether or not it was needed, so that decision stays with the
operator. In the dashboard it is the button beside the limits, greyed out when
the account has none left.

### When a seat runs out: cooldown and failover

A subscription has the quota of one interactive user, so it runs out. The
gateway treats that as a routing fact rather than an error to hand back:

**Failures put a provider in cooldown.** A `429` or `402` is quota, `401`/`403`
is auth, `5xx` is the vendor having a bad day; a `400` is your request and
counts against nobody. Quota honours the vendor's `Retry-After` when it sends
one and otherwise waits five minutes, auth waits five, and server errors back
off from thirty seconds, doubling, capped at ten.

**Routing skips a cooling-down provider** and picks another credential that
serves the same model. Where several are healthy, the choice is weighted, so two
seats at equal weight split traffic evenly instead of the first absorbing all of
it. If *every* candidate is cooling down the request is still sent — to whichever
recovers soonest — because a cooldown is a prediction and failing a request on a
prediction is worse than trying.

**The request that discovers the exhaustion is retried**, not just the ones
after it, up to three providers. Retrying needs the request body a second time,
so bodies over 1 MB stream straight through and are not retried; everything
normal-sized is. A retry never lands on a provider already tried for that
request.

**Three consecutive auth failures deactivate the provider.** Only auth: a
credential the vendor keeps rejecting is broken and needs a human, whereas an
exhausted quota is a seat working exactly as sold, and disabling it every time
it hit its weekly ceiling would be absurd. The row records why.

Any success clears the whole run — failure count, cooldown, everything.

To override, once you have fixed the underlying problem:

```bash
curl -X POST https://<gateway>/admin/oauth/q1-a/reinstate -b cookie.txt
# API-key providers: /admin/providers/<id>/reinstate
```

Weight is `1` unless you say otherwise:

```bash
curl -X POST https://<gateway>/admin/oauth/q1-a/weight \
  -H 'content-type: application/json' -b cookie.txt -d '{"weight":3}'
```

`GET /admin/oauth/providers` reports `cooling_down`, `cooldown_until`,
`cooldown_reason`, `failure_count`, `last_failure_message` and `disabled_reason`
alongside the rest; the dashboard renders them as badges on the row.

### Change which models route to a subscription

Subscription endpoints expose no `/models` API, so the model list on the
provider row is authoritative and is edited directly:

```bash
curl -X POST https://<gateway>/admin/oauth/q1-a/models \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"models":["gpt-5-codex"]}'
```

An empty list routes nothing to the account. In the dashboard this is
**Subscriptions → Edit models**. Entries are matched as prefixes, so keep them
specific enough not to swallow traffic meant for a metered provider.

### Disconnect

Deleting the provider row deletes the stored credentials:

```bash
curl -X DELETE https://<gateway>/admin/providers/q1-a -b cookie.txt
```

---

## Using it

Once connected, an OAuth provider is routed to by model name like any other, using
your normal managed `sk-` key — the client sends nothing special. The
client-side guide, including SDK and tool configuration, is
[SUBSCRIPTIONS_AS_API.md](SUBSCRIPTIONS_AS_API.md):

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
