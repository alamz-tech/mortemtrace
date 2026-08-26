# MortemTrace — submission text

Copy/paste into the Devpost text-description field. See [README.md](README.md) for
spin-up instructions and [ARCHITECTURE.md](ARCHITECTURE.md) for the full design.

## Features

- **One committed incident timeline, four departmental scopes.** Engineering, Support,
  Legal, and Finance each read the same timeline through a different, independently
  enforced read scope. Support's agent isn't instructed to skip raw logs — it is
  structurally unable to read them, because `data/scope_store.py` denies the request at
  the data layer regardless of what any prompt says.
- **Multimodal, zero-transcription intake.** Alert payloads, pasted logs, and dashboard
  screenshots all normalize into one validated, source-traced `IncidentEvent` schema.
  Low-confidence extraction never gets coerced into a committed fact — it raises exactly
  one clarification question instead.
- **A Watcher that reacts to the world changing, not just to inbound alerts.** Polls
  provider-status/changelog/CVE-shaped signals on a schedule, correlates each one against
  active incidents by service dependency graph (a bounded, cycle-protected BFS), and
  emits a match only for genuinely affected incidents — the negative case (unaffected
  incidents staying untouched) is deliberately part of the design, not an afterthought.
- **Governance enforced in code, not policy.** Every model call is screened both
  directions by Model Armor (prompt injection/jailbreak on input, secrets/PII on output),
  with a local heuristic layered in as a live-tested supplementary check, not just an
  outage fallback. Every timeline entry and hypothesis carries `source_event_ids[]`; a
  commit without one is rejected at the store layer.
- **A registry-driven fleet.** Publishing a new department's agent to the registry makes
  it start consuming the existing timeline with no Coordinator code change and no
  redeploy — proven by a test that publishes an agent mid-run and dispatches it in the
  same process.
- **Full OpenTelemetry tracing.** Every ingest, agent invocation, model call, and
  read/write (including denials) is a span, queryable by `run_id`, `incident_id`, and
  `org_id`.

## Technologies

Gemini 3.5 Flash via Vertex AI (Google Agent Development Kit, Python), Model Armor,
Firestore, Pub/Sub, Cloud Run, Cloud Scheduler, Cloud Trace/Logging via OpenTelemetry,
FastAPI, Pydantic.

## Data sources

- PagerDuty and Datadog's public alert-payload shapes, used as structural reference for
  what an inbound alert looks like. No live PagerDuty/Datadog integration exists or is
  claimed.
- Public postmortem archives (Cloudflare's, GitLab's) as structural reference only — no
  content reproduced.
- All incident, service, customer, and signal data in the repository (`seed/generate.py`)
  is synthetic, generated for this demo. No real customer data, logs, or credentials
  appear anywhere in the repository.

## Findings and learnings

The architecture was right on paper well before it was right in production, and the gap
between those two turned out to be the most useful part of building this. Every one of
the following was found by actually deploying to Cloud Run and hitting the live service
with real requests — none of them showed up in 130+ unit/integration tests that mocked
Gemini and Model Armor to stay fast and free:

- **ADK invokes `before_model_callback`/`after_model_callback` by keyword, not
  position**, despite the type aliases being declared positionally — confirmed by
  reading ADK's own source, whose comment admits the trap. A positional callback
  parameter meant every single live model call raised `TypeError`, silently, until this
  was caught.
- **`google-genai` defaults to the Gemini Developer API (needs an API key) instead of
  Vertex AI** unless `GOOGLE_GENAI_USE_VERTEXAI=true` is set explicitly — an easy way to
  end up on the wrong backend entirely without an obvious error pointing at why.
- **Gemini 3.5 Flash 404s on every specific Vertex AI region** we tried, but works on the
  `global` endpoint — the normal rollout pattern for a newly-released model ahead of
  regional availability. Model Armor stayed regional; only the Gemini model call needed
  to move, which is a good reminder that "location" isn't one setting in a system with
  several independently-configured Google Cloud services.
- **The actual P0 requirement — Model Armor blocking a live prompt injection — was
  silently a no-op**, and this is the one worth explaining in full: the code compared a
  protobuf enum via `"MATCH_FOUND" in str(enum_value)`. `str()` on a bare proto enum
  returns its ordinal ("2"), not its name. The substring check was always false. Verified
  against a raw, unfiltered API response that Model Armor was correctly returning
  `MATCH_FOUND` for the exact injection string in this project's own spec's acceptance
  criterion, with the filter fully enabled on the template — and the interpretation code
  still returned "allow," every time. A second, related finding while fixing the first:
  different Model Armor filter types nest their verdict differently (one has
  `match_state` directly on itself, another nests it one level deeper), which is real API
  behavior, not a modeling inconsistency to code around generically. Fixed both,
  confirmed live, and added tests that construct real API response shapes (no live call
  needed) specifically so this class of bug — correct-looking code silently checking the
  wrong thing — is caught automatically going forward.
- **The deployed ingest endpoint was violating its own <500ms requirement.** The
  synchronous, in-process dispatch mode that's genuinely useful for fast local testing
  had been left on in the deployed service, which meant `/ingest` blocked its HTTP
  response until the entire multi-agent cascade finished — 60+ seconds in one live
  timing. Replaced with a real Pub/Sub push-subscriber path (`POST
  /pubsub/push/{event_type}`, one HTTP request per agent hop, OIDC-authenticated at the
  application layer since Cloud Run's own IAM check is service-wide and this service
  needs to stay publicly reachable for its other routes) so the deployed system is
  genuinely asynchronous, not just described that way.

The throughline: an architecture document is a claim, and a deployed system either backs
that claim up or it doesn't. Every one of these was invisible from the code, invisible in
review, and only became visible by actually running the thing against real Google Cloud
infrastructure and reading what it did.
