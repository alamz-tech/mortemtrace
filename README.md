# MortemTrace

An on-call incident agent fleet. One committed incident timeline, eleven agents, four
departmental read scopes enforced at the data layer — not in a prompt.

Built for the Google **All Things Agentic Hackathon**, category **Fortified Enterprise
Fleet**, by Alamz Tech. Full problem statement and requirements: [SPEC-postmortem.md](SPEC-postmortem.md).
Architecture and trade-offs: [ARCHITECTURE.md](ARCHITECTURE.md) ([diagram](docs/architecture.mermaid)).

## The problem

Something breaks at 3am. An alert fires, an engineer pastes logs into a thread, drops a
screenshot, restarts a pod. The incident resolves. The actual damage starts after: the
postmortem gets written three days later from memory, Support improvises a status update
that contradicts the timeline, nobody checks whether customer data was touched (which
starts a GDPR 72-hour clock), Finance learns about SLA credit exposure from an invoice.

MortemTrace converts scattered multimodal evidence into one validated, source-traced
timeline the moment an alert fires, then fans that single timeline out to Engineering,
Support, Legal, and Finance — each reading it at a different, independently enforced
scope. Support's agent isn't instructed to avoid raw logs; it is structurally unable to
read them, because the data layer denies the request regardless of what the prompt says.

## Architecture at a glance

- **Coordinator** (supervisor) routes events, resolves agent versions from a Firestore
  registry, enforces turn/token budgets, detects loops, quarantines misbehaving versions.
- **Ledger** is the sole writer of the committed timeline; every entry carries
  `source_event_ids[]`, and a commit without one is rejected at the store layer, not the
  agent layer.
- **`data/scope_store.py`** is the sole Firestore access path in the codebase. Every read
  and write checks the caller's registry-declared scope and signed org claim before
  touching Firestore. This is the file the whole architecture turns on.
- **`gateway/`** is the sole Vertex AI / ADK path. Every model call is screened both
  directions by Model Armor (injection/jailbreak on input, secrets/PII on output), with a
  local fallback screener if the API is unavailable.
- **Watcher** correlates external signals against active incidents by service dependency
  graph and emits a match only for genuinely affected incidents — unaffected incidents
  stay untouched, not just unmentioned.
- Full OpenTelemetry tracing across ingest, every agent invocation, every model call,
  every read/write (including denials), queryable by `run_id`, `incident_id`, `org_id`.

Nothing here auto-executes. Every departmental output is `status: draft`, pending human
approval — no service restarts, no status page updates, no regulator notifications.

## Repository layout

```
agents/           coordinator, watcher, intake, ledger, diagnosis, classifier, guardian,
                   departments/{postmortem,comms,compliance,exposure}
gateway/          agent_gateway.py (ADK), model_armor.py
data/             models.py (schemas), scope_store.py (the data layer)
registry/         publish / resolve / deprecate agent versions
memory/           Memory Bank
telemetry/        OpenTelemetry setup
api/               ingest endpoint
console/          operator UI
infra/            GCP setup scripts (Firestore, Pub/Sub, Model Armor, deploy)
seed/             synthetic demo data
tests/            41+ tests — scope enforcement, tenant isolation, hallucination guard,
                   injection blocking, registry resolution, orchestration
```

## Spin up locally

Requires Python 3.11+ and a GCP project with billing on a free trial.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Run the test suite (no GCP credentials required — scope enforcement, tenant isolation,
Model Armor fallback screening, and orchestration are all tested against an in-memory
fake Firestore client):

```bash
pytest tests/ -v
```

To run against real GCP services locally:

```bash
gcloud auth login
gcloud auth application-default login
export GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon
export MORTEMTRACE_DEMO_ORG=org_demo
export MORTEMTRACE_CLAIM_SECRET=<a real secret, not the test default>

python -m infra.setup_model_armor      # one-time, idempotent
python -m infra.init_firestore         # seeds the agent registry
python -m seed.generate                # seeds demo services/customers/incidents

export MORTEMTRACE_SYNC_DISPATCH=1     # dispatch in-process instead of via Pub/Sub, for local runs
uvicorn api.ingest:app --reload --port 8080
uvicorn console.ui:app --reload --port 8081
```

## Deploy

```bash
GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/deploy.sh
```

Deploys the ingest API and operator console to Cloud Run with `min-instances=0` (this is
deliberate — every service is stateless and scales to zero between demo runs, which is
what keeps a full rehearsal cycle inside free-trial cost).

## GCP resources this project provisions

Project `mortemtrace-hackathon`, region `us-central1`: Firestore (Native mode), six
Pub/Sub topics (`evidence.received`, `evidence.staged`, `timeline.committed`,
`incident.classified`, `upstream.matched`, `dead-letter`), a Model Armor template
(`mortemtrace-guardian`), and Cloud Run services for the ingest API and console.

## Data sources

- **PagerDuty and Datadog alert payload shapes** are used as public, documented schema
  references for what an inbound alert looks like. No live PagerDuty/Datadog integration
  exists or is claimed — inbound channels are simulated over Pub/Sub using these public
  shapes (see SPEC-postmortem.md's non-goals).
- **Public postmortem archives** (e.g. Cloudflare's and GitLab's published postmortems)
  were used only as structural reference for what a real incident timeline and postmortem
  document look like — no content was reproduced.
- **All incident, service, customer, and signal data in this repository is synthetic**,
  generated by `seed/generate.py` for demonstration purposes. No real customer data,
  logs, or credentials appear anywhere in this repository or its seed data.

## Disclosure

All code in this repository was written during the hackathon submission period
(2026-08-25 through 2026-08-31) using [Claude Code](https://claude.com/claude-code) under
direct human direction, building against the specification and architecture documents in
this repository. No pre-existing proprietary template, library, or codebase was used as a
starting point beyond standard open-source dependencies declared in `pyproject.toml`
(Google ADK, the Vertex AI and Firestore client libraries, FastAPI, Pydantic, and
OpenTelemetry).

## License

MIT — see [LICENSE](LICENSE).
