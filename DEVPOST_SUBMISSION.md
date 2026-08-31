# Devpost submission — copy/paste reference

Not itself submitted anywhere; this is the working draft for the Devpost form fields.
Update MORTEMTRACE_SUBMISSION.md-style docs (SUBMISSION.md, this file) stay in the repo
as a record of what was submitted.

---

## Elevator pitch

> Four departments, one committed timeline, zero shared access — MortemTrace turns a 3am
> alert into a source-traced incident record and fans it out to Engineering, Support,
> Legal, and Finance, each structurally unable to see what their role doesn't scope.

Alternates, if you want to A/B:

> The postmortem writes itself, and Legal only sees what Legal is allowed to see.

> An incident-response fleet where "Support can't read raw logs" is enforced by the
> database, not a system prompt.

---

## About the project

```markdown
## Inspiration

Every real incident produces the same second disaster: the postmortem gets written three
days later from memory, Support improvises a status update that contradicts what actually
happened, nobody checks whether customer data was touched until Legal asks two weeks in,
and Finance learns about SLA credit exposure from an invoice instead of from the incident
itself. The information existed the whole time — it just never got structured, traced to
its source, or routed to the people with obligations *because* of the incident, not just
the people debugging it.

The harder problem underneath: those four teams shouldn't see the same things. Support
drafting a customer update has no business reading raw application logs. Legal assessing
a GDPR clock doesn't need Engineering's stack traces. Every "role-based access control" we
looked at solves this in the UI layer — a dashboard hides a button — which means the data
is one API call away from anyone with slightly broader access than intended. We wanted to
know if scope enforcement could live in the data layer itself, so that "Support cannot
read raw evidence" isn't a prompt instruction an attacker or a bug can talk an agent out of
— it's a query the database itself refuses to serve.

## What it does

MortemTrace ingests an alert, a pasted log, a Slack thread, or a dashboard screenshot, and
turns it into one committed, source-traced incident timeline — every entry carries the
`source_event_ids[]` it was extracted from, and a commit without one is rejected at the
store layer, not just discouraged in a prompt. That single timeline then fans out to four
independently-scoped agents:

- **Engineering** drafts a postmortem with a proposed runbook fix.
- **Support** drafts a customer-facing status update — timeline access only, no raw logs.
- **Legal** assesses whether customer data was touched and starts a GDPR 72-hour clock the
  moment it's true, not when someone remembers to check.
- **Finance** calculates SLA credit exposure per affected customer.

A Watcher agent independently polls provider-status and CVE-shaped feeds on a schedule and
correlates them against *active* incidents by service dependency graph — so "was this us
or our cloud provider" is answered automatically, for exactly the incidents it actually
affects, before anyone has to ask.

Every model call is screened both directions by Model Armor — prompt injection on the way
in, secrets/PII on the way out — and every read, write, and denial is an OpenTelemetry
span and a Firestore audit entry, queryable by run, incident, and org. A new department
joins the fleet by publishing a registry entry with its scopes; nothing routes to it until
that happens, and nothing about the Coordinator's code has to change.

Real organizations connect their existing tools — PagerDuty, GitHub Actions, Jenkins,
Terraform, or anything else that can fire a webhook — through one universal receiver with
per-connector signature verification (HMAC, bearer, or IP allowlist), not a bespoke
integration per vendor.

## How we built it

Google ADK for every agent, Gemini 3.5 Flash via Vertex AI, Model Armor for injection and
secrets screening, Firestore as the sole data store (one module — `data/scope_store.py` —
is the only code in the repository allowed to import the Firestore client at all; a test
greps the tree and fails the build if a second entry point appears), Pub/Sub for genuinely
asynchronous multi-hop dispatch, Cloud Run for both the ingest API and the operator
console, Cloud Scheduler for the periodic Watcher sweep, and OpenTelemetry/Cloud Trace for
tracing. FastAPI and Pydantic underneath; every Firestore document and Pub/Sub payload is
validated against a Pydantic schema before it's written or acted on.

The Coordinator is the only thing that decides who receives an event — a static routing
table plus a Firestore-backed agent registry — and it never reasons about incident content
itself; every actual decision is made by whichever worker it dispatches to. Guardian sits
in front of every dispatch as a deterministic policy checkpoint, screening the real
evidence body before a worker is even invoked, not just the envelope metadata around it.

Authentication went through a real design pass partway through the build, once it became
clear a hackathon demo and a plausible production system have different needs here:
Google/org SSO via OIDC (PKCE, state, and nonce all independently verified) mints a signed
session cookie; which organizations a session may act as, and with what role, is resolved
fresh from live membership rows on every request — never cached in the cookie itself, so a
revoked membership takes effect on the very next request. Machine callers (the ingest API,
scheduled sweeps, webhooks) authenticate through an entirely separate credential path —
API tokens or per-connector signatures — so a webhook can never authenticate *as* a human,
and a stolen session cookie can never touch the machine-to-machine surface.

## Challenges we ran into

The architecture was right on paper well before it was right in production, and almost
every real bug lived in the seam between our code and someone else's SDK or API — the kind
of thing 149 unit tests that correctly mock Gemini and Model Armor will never catch,
because the mock is exactly where the bug wasn't.

- **ADK invokes `before_model_callback`/`after_model_callback` by keyword, not position**,
  despite the type hints being declared positionally — confirmed by reading ADK's own
  source, whose comment admits it. Every live model call threw `TypeError` until this was
  found; every test using a positional call passed the whole time.
- **The actual P0 requirement — Model Armor blocking a live prompt injection — was
  silently a no-op.** The code compared a protobuf enum via `"MATCH_FOUND" in
  str(enum_value)`. `str()` on a bare proto enum returns its ordinal ("2"), not its name.
  Model Armor was correctly returning `MATCH_FOUND` for a real injection string on a fully
  enabled filter, and the interpretation code still returned "allow" — every time.
- **A real, reproducible Model Armor false positive** turned up during our own final
  verification pass: an entirely benign incident report ("nginx pods restarted, 503s on
  checkout") was flagged by the live `pi_and_jailbreak` filter. Confirmed twice, not
  flaky. A useful reminder that a content-safety classifier sitting in a live pipeline is
  itself something to monitor, not a black box to trust blindly — Guardian's audit trail
  is exactly what let us catch it in seconds instead of guessing.
- **Vertex AI 429 RESOURCE_EXHAUSTED, live, mid-hackathon**, on a free-trial project.
  Backoff-and-retry alone doesn't help if the exhausted window is long; we added a genuine
  second layer — falling back to a different model on sustained exhaustion — and proved
  both layers firing together on a real quota event, not just in a test.
- **A stale browser session cookie could wedge a login into a permanent, silent loop** —
  found through live testing, not a unit test, because the failure only appears once real
  browser cookie state is involved. Fixed by expiring an unusable cookie on the way out
  instead of leaving the browser stuck holding it.
- **Firestore's own concurrency model bit us**: two evidence items landing for the same
  incident could each read the same timeline document, each append their own entry, and
  the second write would silently discard the first — no error, just a missing entry in
  the one artifact the whole product is built around. Fixed with a real Firestore
  transaction, and proved the fix with a concurrency test using actual threads, not mocked
  timing.
- **A cross-tenant authorization gap**, caught in our own review pass before it ever
  reached a judge: an early version resolved which tenant a request could act as from a
  client-supplied `org_id` rather than from the authenticated credential. Rebuilt so tenant
  identity comes only from a verified principal, and `org_id` can only *select among*
  organizations that principal already belongs to — never introduce one.

## Accomplishments that we're proud of

Every claim in the architecture doc is backed by something we actually watched happen
against live Google Cloud infrastructure — not "should work," but a real incident that ran
through all eleven agents, wrote a real timeline with a real cited source, and landed a
real severity on a real dashboard. We found the P0 governance bug — the one requirement a
judge would most want to see actually work — by hitting our own deployed service with the
exact injection string from our own spec, watching it correctly return "allow," and not
accepting that as good enough. And when we found a genuine security gap in our own
implementation during a self-review pass, we fixed it, wrote a regression test that proves
it, and are disclosing it here rather than hoping nobody notices — because a "fortified
enterprise fleet" that hides its own past mistakes has already missed the point of the
category.

## What we learned

The gap between "the architecture is correct" and "the deployed system behaves correctly"
is not a small one, and almost nothing closes it except actually running the thing against
the real infrastructure it's meant to run on, with a payload designed to break it. A
positional-vs-keyword callback, a `str()` on the wrong enum, a client-supplied tenant id
trusted one layer too early — every one of these reads as obviously wrong in hindsight and
was invisible in code review, invisible in 149 passing tests, and only became visible by
deploying and attacking our own system the way a real caller eventually would.

## What's next for MortemTrace

Message-level Pub/Sub dedup (currently a documented, accepted gap at demo scale — a
duplicate delivery re-runs a worker rather than being caught before a redundant Gemini
call), a real dead-letter replay UI in the console instead of a CLI script, SAML support
alongside OIDC for the enterprise identity providers that still require it, and a genuine
global rate limit (today's is a real, tested per-instance token bucket — a meaningful
floor, not the final answer at Cloud Run scale with many concurrent instances).
```

---

## Built With (tags)

```
python, google-adk, gemini, vertex-ai, model-armor, firestore, google-cloud-pubsub,
google-cloud-run, cloud-scheduler, opentelemetry, cloud-trace, fastapi, pydantic,
oauth2, oidc, jinja2, uvicorn, docker, google-cloud-secret-manager, pytest, ruff,
ai-agents, multi-agent-systems, incident-response, github-actions
```
(24 tags — trim or swap freely; keep `google-adk`, `gemini`, `vertex-ai`, `firestore`,
`google-cloud-run`, `model-armor` since those map directly to the required-tech checklist.)

---

## Factual form answers (confirmed against the actual codebase, not assumed)

- **Google SDK used:** Agent Development Kit (ADK) — `google-adk>=2.7` in `pyproject.toml`,
  used by every agent via `gateway/agent_gateway.py`.
- **Google Cloud services used:** Cloud Run (both services), Firestore, Pub/Sub. Also in
  use but not in Devpost's checkbox list: Cloud Scheduler, Cloud Trace/Logging, Model
  Armor, Secret Manager. **Not used:** Cloud SQL, GKE — don't check those.
- **Google AI model:** Gemini 3.5 Flash via Vertex AI (`DEFAULT_MODEL` in
  `gateway/agent_gateway.py`), with `gemini-2.5-flash` as a live-tested fallback on
  sustained quota exhaustion. Satisfies the "Gemini 3.5 or newer" requirement.
- **Hosted project URL:** `https://mortemtrace-console-gi2fbto67q-uc.a.run.app`
- **Public code repo:** `https://github.com/alamz-tech/mortemtrace`
- **Reproducible testing instructions in README:** Yes — see README.md's "Try it live"
  and "Spin up locally" sections.

---

## Fields only you can answer — nothing here is a guess

Submitter type, country of residence, organization name (if any), project start date,
Startup Prize opt-in/corporate email, video link, screenshots, and architecture diagram
upload all require information or files I don't have. See the chat response for the full
list and what's needed for each.
