# What to add next

A working list of what this gateway is missing, why each gap matters, and what
closing it involves — plus, for the parts already built, why they are built the
way they are. "Why is it like that" outlives "that it exists".

Most of this comes from comparing against [CLIProxyAPI][cli] and its
[management centre][mc], which solve the same problem — subscription seats
fronted as an API — with more mileage on the routing and observability side.

[cli]: https://github.com/router-for-me/CLIProxyAPI
[mc]: https://github.com/router-for-me/Cli-Proxy-API-Management-Center

---

## Built

### Vendor usage limits

Each OAuth adapter reads its own vendor's limits (`fetchQuota`), normalized to
one `QuotaSnapshot` shape so the dashboard has a single renderer.
`GET /admin/oauth/:id/usage`.

CLIProxyAPI does this differently: a generic `POST /admin/api-call` passthrough
lets the frontend send an authenticated request to any vendor URL and parse it
client-side. That is more flexible and needs no backend change per vendor — but
an admin endpoint that will fetch an arbitrary URL with stored credentials is a
liability, so the parsing lives in the adapters here instead.

### Cooldown, weighted rotation, and failover

`src/managed/providerHealth.ts`, `src/managed/failover.ts`. Behaviour is
documented in
[OAUTH_PROVIDERS.md](OAUTH_PROVIDERS.md#when-a-seat-runs-out-cooldown-and-failover).

The retry lives *outside* the Hono app, which is not a stylistic choice: Hono's
`compose` throws on a second `next()`, so retrying downstream from inside a
middleware is not expressible. The wrapper re-enters `app.fetch` with a rebuilt
request instead, and the middleware only reports whether a retry is worth
attempting. That is also why request bodies over 1 MB are never retried — a
retry needs the body twice, and the only way to have it is to have kept it.

Auto-disable counts *auth* failures only. An exhausted quota is a seat working
exactly as sold; disabling it every time it hit a weekly ceiling would be
absurd. A local decryption failure is deliberately classified as a server error
rather than auth, because a wrong `PROVIDER_KEY_ENCRYPTION_KEY` would otherwise
deactivate every provider at once over an environment variable.

### Request log with failures, including streamed token counts

`usage_logs` gained `status_code`, `error_message` and `duration_ms`, and every
request writes a row. `GET /admin/logs`.

Streamed responses are teed rather than cloned — a clone would compete for the
same source — and the copy is scanned frame by frame for usage. Before this,
every streamed request logged zero tokens, which silently under-counted exactly
the traffic most clients send, monthly limits included. Vendors disagree about
where the numbers live (OpenAI sends both totals in a final chunk; Anthropic
sends input on `message_start` and output on `message_delta`), so each field
keeps the largest value seen.

### Per-key limit visibility

`GET /admin/api-keys` returns each key's requests in the last minute and tokens
this month beside its limits. A limit nobody can see is a limit people discover
by being cut off.

### Quota history and threshold alerts

An hourly Cron Trigger (`src/managed/scheduled.ts`) samples every connected
seat, stores the samples, alerts on 75/90/100% crossings via `ALERT_WEBHOOK_URL`,
and prunes both the request log and the history.

Sampling is sequential on purpose: these are vendor endpoints operated for a
desktop client, and a burst of parallel requests from one account is the exact
pattern that gets a seat rate-limited. Every task is failure-contained — a
vendor being down must not stop the other seats being sampled, and neither must
stop the logs being pruned.

### Antigravity, including inference

Its own gateway provider (`src/providers/google-antigravity`) rather than a
credential swap, because the Code Assist backend wraps the Gemini body in
`{model, project, request}` and answers with `{response}`.

The provider re-implements none of the Gemini translation. It reuses Google's
whole parameter map with each target path moved under `request.`, which works
because the transformer walks dotted paths, and unwraps the envelope before
handing responses to Google's transforms. Anything Gemini gains, this gains.

Two things had to be special-cased. The `[DONE]` sentinel is handled locally
because Google's stream is a JSON *array*, so its transform strips array
brackets before it looks for the `data:` prefix and turns `data: [DONE]` into
`DON`. And unparseable frames are dropped rather than passed on, because a real
SSE stream carries comment keep-alives that would otherwise throw inside the
Gemini transform and take the whole response down over a heartbeat.

### Per-user ownership of metered providers

`POST /admin/providers/:id/owner`. Subscription seats were already owner-only;
this covers the API-key providers, which are shared by default and stay that way
unless someone says otherwise — existing rows are untouched. Re-saving a
provider's key no longer resets its owner, which it used to.

### Multi-seat connect flow

**Add another account** on a connected seat sets the form up for a sibling: the
next free numeric id suffix, and the same model list copied across. Routing
splits traffic across every seat claiming a model, so a second seat is only
useful if it claims the same ones.

### Kimi

A textbook RFC 8628 device flow and an OpenAI-compatible API, so the existing
Moonshot provider serves it with a base-URL override and nothing else.

---

## Next

### Vertex service-account import

**Why:** the one credential type in CLIProxyAPI with no equivalent here. It is
also the only *supported*, non-terms-violating way to reach Gemini at scale,
which makes it the odd one out in a document otherwise full of caveats.

**What it involves:** not OAuth. A service-account JSON holds a private key that
must sign a JWT assertion, which is exchanged for an access token — so it does
not fit `OAuthAdapter`, whose whole shape assumes an authorization flow and a
refresh token. Either a third `auth_type` alongside `api_key` and `oauth`, or a
widening of the adapter contract so "how a credential is obtained" and "how it
is presented upstream" are separate concerns. The gateway already has a
`vertex-ai` provider, so only the credential half is missing.

**Watch out for:** RS256 signing in a Worker (`crypto.subtle.importKey` with
PKCS#8, which the JSON gives in PEM form), and that the resulting token expires
in an hour with no refresh token — the existing refresh machinery assumes one.

### Embeddings and non-chat endpoints for Antigravity

**Why:** the provider declares `chatComplete` only. A request for embeddings on
an Antigravity model reports that the endpoint is unsupported.

**What it involves:** finding out whether the Code Assist backend exposes an
embedding method at all. If it does not, the honest answer is the current one
and this item should be deleted rather than built.

### Alert delivery beyond a webhook

**Why:** `ALERT_WEBHOOK_URL` covers Slack, Discord and anything that accepts a
POST. It does not cover email, and it is a single global destination — on a
shared gateway, the person whose seat is at 95% is not necessarily the person
receiving the alert.

**What it involves:** a per-user destination on the seat's owner, and a delivery
abstraction with more than one implementation. Worth doing when a second person
is actually using the gateway; over-engineering before that.

### Cost, not just tokens

**Why:** token counts are recorded but never priced, so "what did this month
cost" is unanswerable for metered providers, and the comparison that justifies a
subscription seat — seat versus what the same traffic would have cost metered —
cannot be made.

**What it involves:** a per-model price table and a cost column on the log.
The table is the hard part: it goes stale silently, and a wrong number is worse
than no number.

### Vendors not implemented

Qwen, iFlow and AIStudio appear in the management centre's UI but have no
adapter in the CLIProxyAPI revision this was built against, so there is no
reference for their flows here. Anything OpenAI-shaped behind a bearer token is
close to Kimi in effort; anything on a Google `v1internal` host is close to
Antigravity, and would likely reuse its provider outright.

---

## Deliberately not doing

**A generic `POST /admin/api-call` passthrough.** CLIProxyAPI has one and it is
what makes their management centre so flexible: any vendor endpoint becomes
readable without a backend change. It is also an authenticated
fetch-any-URL-with-my-credentials endpoint sitting behind an admin session. The
per-adapter `fetchQuota` costs more code and cannot be extended from the
frontend, which is the trade being made on purpose.

**Automatic reset-credit redemption on 429.** The credit is spent whether or not
it was needed, and a retry loop that spends money without being asked is the
kind of automation people discover from a bill.

**In-memory provider health.** It would avoid a D1 write per failure, but a
Worker isolate does not survive between requests, so there is nowhere to keep it
that the next request would see.

**Buffering every request body to make it retryable.** Retries stop at 1 MB.
Holding a multi-megabyte audio upload in a Worker's heap to enable a retry that
usually is not needed is the wrong trade.

---

## Operational notes

- **Migrations must be applied before deploying this code.** `0005` adds columns
  the proxy selects on every request; `0006` adds the tables the scheduled job
  writes. CI applies migrations before deploy, but a manual `wrangler deploy`
  without `wrangler d1 migrations apply` will break every managed request.
- The worker's default export is `{ fetch, scheduled }` rather than the Hono
  app, so anything importing `src/index.ts` expecting an app instance needs
  updating.
- The Cron Trigger is declared in `wrangler.toml`. Without `ALERT_WEBHOOK_URL`
  it still samples, stores history and prunes — it just tells no one.
