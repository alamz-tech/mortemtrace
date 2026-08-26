# infra/

One-time and periodic environment setup for MortemTrace. Nothing here runs in the request
path; everything is either a script you run once per environment or a deploy/schedule
definition you run deliberately.

| File | Run as | Does |
|---|---|---|
| `setup_model_armor.py` | `python -m infra.setup_model_armor` | Creates the Model Armor template (already provisioned for `mortemtrace-hackathon`; kept for a fresh environment). |
| `init_firestore.py` | `python -m infra.init_firestore` | Bootstraps the agent registry: platform-admin via the unauthenticated bootstrap path, then every other agent via the real authenticated `registry.publish()` path. Idempotent. |
| `seed_data.py` | `python -m infra.seed_data` | Thin wrapper around `seed/generate.py` - writes synthetic services, customers, incidents, evidence, and a committed timeline under the demo org. Idempotent (deterministic doc IDs). |
| `firestore.indexes.json` | `gcloud firestore indexes composite create --help` / deployed via `gcloud firestore deploy` conventions | The one composite index this codebase's landed queries actually require today (see below). |
| `deploy.sh` | not run by this task - review then run manually | `gcloud run deploy` for the ingest API and console, `min-instances=0`. Ingest runs real async dispatch (no `MORTEMTRACE_SYNC_DISPATCH`); sets `MORTEMTRACE_PUSH_AUDIENCE` from the service's own URL after the first deploy. |
| `setup_pubsub_push.sh` | run once, after `deploy.sh`'s first-ever ingest-api deploy | Creates the Pub/Sub push-authenticator service account and one push subscription per topic (excluding `dead-letter`), each pointing at `POST /pubsub/push/{event_type}` - this is what makes production dispatch actually asynchronous rather than blocking the request. |
| `schedule.sh` | not run by this task - review then run manually | Cloud Scheduler job for the periodic Watcher sweep. |

## Firestore composite indexes

At demo scale, Firestore's automatic single-field indexes cover almost every query this
system issues: a query with only equality (`==`) filters across multiple fields - even
several at once - does **not** need a composite index, because Firestore serves those from
automatic single-field indexes via a merge join. A composite index is only required when a
query combines an `array-contains` (or a range/`orderBy`) filter with at least one other
filter on a different field in the *same* query call.

Walking the four candidates named in the build brief against the code that actually exists
right now:

- **`Collection.INCIDENTS` filtered by `status`** (Watcher's active-incident query,
  `ARCHITECTURE.md` section 4) - not yet landed (Watcher's own module is still a stub as of
  this writing). A single equality filter on `status` needs no composite index regardless.
  Tenant scoping is a path prefix (`/tenants/{org_id}/incidents`), not a filter, so it
  doesn't add a second field to the query either. Revisit only if the real query later adds
  a second filter or an `orderBy` on a different field (e.g. `status == "open" order by
  opened_at`).
- **`Collection.DRAFTS` filtered by `incident_ref`** (console's per-incident view) - not yet
  landed (`console/` is still a stub). Single equality filter; no composite index needed
  unless the real query adds `department == X` or `status == "draft"` alongside it.
- **`Collection.QUARANTINE` filtered by `agent_name` + `version`** (Coordinator's
  `_is_quarantined`, `agents/coordinator/coordinator.py`) - **this one is landed and real**:
  `scope_store.try_query(..., filters=[("agent_name", "==", agent_name), ("version", "==",
  version)], limit=1)`. Two fields, but both are equality filters, so per the rule above it
  is served by automatic indexes with no composite index required. No action needed unless a
  third filter or a range/`orderBy` is added later.
- **`Collection.MEMORY` filtered by `kind`, and separately by `related_incident_ids`
  array-contains** (`memory/memory_bank.py`'s `retrieve()`) - **this one is landed, real, and
  does need a composite index.** `retrieve()` accepts `kind` and `related_incident_id`
  independently, but when a caller passes *both* (e.g. Diagnosis asking "prior
  `failure_pattern` records touching this incident"), it builds one query with
  `kind == X` **and** `related_incident_ids array_contains Y` together - an equality filter
  combined with an array-contains filter on a different field, in the same call. That
  combination is exactly the case Firestore cannot serve from automatic indexes alone.

  `firestore.indexes.json` in this directory declares that one index: collection group
  `memory`, fields `kind` (ascending) + `related_incident_ids` (array-contains). It's
  declared at the collection-group level (not a specific document path) specifically because
  every org's memory lives at `/tenants/{org_id}/memory` - a `COLLECTION`-scoped composite
  index on the `memory` collection ID applies under every org's subcollection without one
  index per tenant.

No other query in the landed codebase combines a range/array-contains filter with another
filter, so no other composite index is included. If Watcher's or console's real
implementation lands a genuinely compound query (equality + range/orderBy, or
array-contains + anything), add it to `firestore.indexes.json` then rather than guessing its
shape now.
