# Using a subscription as an API

Your ChatGPT, Claude, or Grok subscription is licensed for the vendor's own
client, not for API access. Once that seat is connected to this gateway, the
gateway exposes it at an OpenAI-compatible endpoint, so anything that speaks the
OpenAI or Anthropic API can talk to it with a normal `Bearer` key.

This page is the **client-side** guide: you have a connected seat and want to
send requests to it. For connecting the seat in the first place — the OAuth
flows, credential import, token refresh, ownership model — see
[OAUTH_PROVIDERS.md](OAUTH_PROVIDERS.md). Read that document's
[What you are agreeing to](OAUTH_PROVIDERS.md#what-you-are-agreeing-to) section
before relying on any of this: subscription auth outside the vendor's client is
a terms violation on the account you connect, and it can stop working without
notice.

---

## 1. Get a key

Log in to `/admin/dashboard` → **API keys** → **Create key**. The `sk-…` value is
shown once and stored only as a hash — if you lose it, make another.

Or over HTTP, with an admin session cookie:

```bash
curl -X POST https://<gateway>/admin/api-keys \
  -H 'content-type: application/json' -b cookie.txt \
  -d '{"label":"laptop"}'
```

```json
{
  "status": "success",
  "api_key": "sk-…",
  "key_prefix": "sk-abcd1234",
  "message": "Store this key securely; it will not be shown again."
}
```

Admins can also set `rpm_limit` and `monthly_token_limit` on a key; those fields
are ignored when a non-admin creates one.

> **Your key only reaches your own seats.** A subscription belongs to the person
> who connected it, so it is visible only to `sk-` keys owned by that account.
> Someone else's key routing to the same model gets *"no active provider
> configured for model"* rather than a ride on your seat.

## 2. Point a client at the gateway

The base URL is your gateway's `/v1`, and the key goes in the standard
`Authorization` header. No extra headers, no vendor keys on the client.

```bash
curl https://<gateway>/v1/chat/completions \
  -H "authorization: Bearer sk-<your key>" \
  -H 'content-type: application/json' \
  -d '{"model":"claude-sonnet-5","messages":[{"role":"user","content":"hi"}]}'
```

**OpenAI SDK (Python)**

```python
from openai import OpenAI

client = OpenAI(api_key="sk-<your key>", base_url="https://<gateway>/v1")
client.chat.completions.create(
    model="claude-sonnet-5",
    messages=[{"role": "user", "content": "hi"}],
)
```

**Anthropic SDK (Python)** — `/v1/messages` is served too:

```python
from anthropic import Anthropic

client = Anthropic(api_key="sk-<your key>", base_url="https://<gateway>")
client.messages.create(
    model="claude-sonnet-5",
    max_tokens=1024,
    messages=[{"role": "user", "content": "hi"}],
)
```

**Anything else** — Cline, Continue, Aider, LangChain, a `.env` in your own app:
set the OpenAI base URL to `https://<gateway>/v1` and the API key to your `sk-`
key. Clients that hardcode `api.openai.com` need a base-URL override to work,
and clients that send their own vendor key will have it ignored — the gateway
authenticates with the stored credential, not with what the client sends.

## 3. Pick a model

Routing is by **model name**, matched as a prefix against the model list on each
provider row. Requests carrying a name that no active provider claims fail with
*"no active provider configured for model"*.

| Seat | Adapter | Seeded models |
|---|---|---|
| ChatGPT Plus/Pro | `openai-codex` | `gpt-5.6-sol`, `gpt-5.6-terra`, `gpt-5.6-luna`, `gpt-5.5` |
| Claude Pro/Max | `anthropic-claude-code` | `claude-opus-5`, `claude-sonnet-5`, `claude-haiku-4-5` |
| Grok | `xai-grok-cli` | `grok-4.5`, `grok-4.3` |
| Antigravity | `google-antigravity` | `gemini-3-pro`, `gemini-3-flash` |
| Kimi Code | `kimi-code` | `kimi-k2`, `kimi-k2-turbo` |

Several seats may claim the same model. That is supported and useful: traffic is
split between them by weight, a seat that has hit its vendor ceiling is skipped
until it recovers, and a request that runs into the ceiling is retried on
another seat rather than handed back to you. See
[OAUTH_PROVIDERS.md](OAUTH_PROVIDERS.md#when-a-seat-runs-out-cooldown-and-failover).

These lists are editable per provider (dashboard → **Subscriptions → Edit
models**), because subscription backends expose no `/models` endpoint to sync
from. Keep entries specific: a bare `gpt-5` entry captures every `gpt-5*`
request you make, including ones you meant to send to a metered key.

`GET /v1/models` lists what your key can currently reach.

**Or skip matching and name the provider directly**: `provider_id/model` routes
straight to that row — no prefix guessing, no weighted split across seats that
happen to share a model, no failover to a different credential. Only the
provider id itself is stripped; the gateway sends `model` upstream unprefixed.
It has to be a real provider id you can see, or the request 400s. Useful when
you have two seats claiming the same model and want to pin a request (or a
whole client) to one of them:

```bash
curl https://<gateway>/v1/chat/completions \
  -H "authorization: Bearer sk-<your key>" \
  -H 'content-type: application/json' \
  -d '{"model":"4a7f/gemini-3-pro","messages":[{"role":"user","content":"hi"}]}'
```

Provider ids are worth picking deliberately when you connect a seat — short and
opaque (`4a7f`, not `antigravity-sub`) is a reasonable default, since it is
what shows up in `owned_by` on `/v1/models` and in any `provider_id/model`
address, and a name that announces "this is a subscription seat wired in as an
API" is exactly the kind of thing worth not broadcasting.

**Or name the vendor instead of a row**: a short alias —
`codex/`, `claude/`, `grok/`, `anti/` (or `antigravity/`), `kimi/` — spreads the
request across *every* provider row for that vendor, the same weighted,
failing-over selection plain prefix matching would use. Unlike
`provider_id/model`, this stays correct as seats are added or removed: connect
a second Antigravity seat and `anti/gemini-3-flash` load-balances across both
without you touching the model string, and it never has to say the provider's
own id (its `-sub` suffix or whatever an operator named it) at all:

```bash
curl https://<gateway>/v1/chat/completions \
  -H "authorization: Bearer sk-<your key>" \
  -H 'content-type: application/json' \
  -d '{"model":"anti/gemini-3-flash","messages":[{"role":"user","content":"hi"}]}'
```

A real provider id always wins over an alias if the two happen to collide — a
provider actually named `codex` is addressed by `codex/model` before the alias
table is even consulted.

## 4. Know the limits

**Codex serves `/v1/responses` only.** `chatgpt.com/backend-api/codex` has no
chat-completions endpoint, so the adapter declares `supportedPaths:
['/v1/responses']` and routing skips it for other paths:

```bash
curl https://<gateway>/v1/responses \
  -H "authorization: Bearer sk-<your key>" \
  -H 'content-type: application/json' \
  -d '{"model":"gpt-5.6-sol","input":"write a haiku about proxies"}'
```

A `/v1/chat/completions` call for the same model falls through to a metered
OpenAI provider if you have one, and otherwise reports no provider — it will not
be sent to an endpoint that was never going to answer it. Claude and Grok seats
serve their vendor's full surface and have no such restriction.

**Anthropic rejects consumer-plan credentials server-side.** Claude Pro/Max
OAuth tokens used outside Claude Code come back with *"This credential is only
authorized for use with Claude Code and cannot be used for other API
requests."* Expect this, and expect any workaround to be temporary.

**Vendor rate limits are the seat's, not an API tier's.** A subscription has the
quota of one interactive user; several clients hammering it in parallel will hit
that ceiling much sooner than a metered key would. How much is left is visible
in the dashboard under **Subscriptions**, or at
`GET /admin/oauth/<id>/usage` — see
[OAUTH_PROVIDERS.md](OAUTH_PROVIDERS.md#see-how-much-of-the-subscription-is-left).

**Sessions are not shared.** Each request is independent — the gateway forwards
what your client sends, so conversation history is your client's job, as with
any API.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `401` with *"Missing Authorization: Bearer"* | No key sent, or the client put it somewhere other than the `Authorization` header. |
| *"no active provider configured for model"* | The model name matches nothing on a provider you own; or it's a Codex model on a non-`/responses` path; or the seat belongs to another user. |
| Anthropic *"only authorized for use with Claude Code"* | The server-side consumer-plan check above. Not fixable from here. |
| Sudden failures on a seat that worked | The credential lapsed or was revoked. Check `GET /admin/oauth/providers`, then force a round trip with `POST /admin/oauth/<id>/refresh`. |

Usage per key, model, and provider is in the dashboard's **Usage** tab, or at
`GET /admin/usage`. Individual requests — including the failed ones, with the
upstream error text — are under **Recent requests** on the same tab, or at
`GET /admin/logs?status=error`. Your key's own consumption against its RPM and
monthly-token limits is on the **Keys** tab.
