# infra/

One-time and periodic environment setup for MortemTrace. Nothing here runs in the request
path; everything is either a script you run once per environment or a deploy/schedule
definition you run deliberately.

## Prerequisites — run every Python script from the project venv

These scripts import the application's dependencies, so they must run under the
project's virtualenv, **not** your system Python. Activate it once per shell:

```bash
cd /path/to/mortemtrace && source .venv/bin/activate
```

After activating, `python -m infra.<script>` works as written below. Without it you get
`ModuleNotFoundError: No module named 'google.api_core'` (or a similar missing Google
package) — that error means the system interpreter is being used, not that anything is
broken. If you would rather not activate, prefix each command with the venv interpreter
explicitly: `.venv/bin/python -m infra.setup_model_armor`.

Every script also needs `GOOGLE_CLOUD_PROJECT` set and `gcloud auth application-default
login` already done.

| File | Run as | Does |
|---|---|---|
| `setup_model_armor.py` | `python -m infra.setup_model_armor` | Creates the Model Armor template (already provisioned for `mortemtrace-hackathon`; kept for a fresh environment). |
| `init_firestore.py` | `python -m infra.init_firestore` | Bootstraps the agent registry: platform-admin via the unauthenticated bootstrap path, then every other agent via the real authenticated `registry.publish()` path. Idempotent. |
| `seed_data.py` | `python -m infra.seed_data` (add `MORTEMTRACE_SEED_PUBLIC_DEMO=1` to also flag the org for judge/demo auto-join) | Thin wrapper around `seed/generate.py` - writes synthetic services, customers, incidents, evidence, and a committed timeline for all three seeded incidents. Idempotent (deterministic doc IDs). Free and fast: writes documents directly, no model calls. |
| `seed_drafts.py` | `python -m infra.seed_drafts` (after `seed_data.py`) | Drives the three seeded incidents' committed timelines through the REAL agent fan-out - diagnosis, postmortem, comms, compliance, exposure - so the demo tenant has real departmental drafts, not just a timeline. Deliberately separate from `seed_data.py`: this makes real, billed Gemini calls, so it's an explicit second step rather than the unconditional default every reseed pays for. Re-running it after a fresh `seed_data.py` reseed adds a fresh set of drafts rather than replacing the old ones - drafts aren't idempotent by design (each is a new `new_id("draft")`), so don't run it twice against the same seed generation unless you want duplicates. |
| `mint_token.py` | `python -m infra.mint_token --org org_demo --subject alice` | Generates an API token and prints the `{digest: {...}}` entry for `MORTEMTRACE_API_TOKENS`. The token itself is shown once. `--org-id` is accepted as an alias; repeat `--org` for a multi-tenant token. Needs no GCP access. |
| `replay_dead_letter.py` | `python -m infra.replay_dead_letter --dry-run` | Drains the `dead-letter` topic back into the pipeline. Start with `--dry-run` to see what would be replayed. |
| `set_sso_domain_hint.py` | `python -m infra.set_sso_domain_hint --org org_acme --domain acme.com` (or `--clear`) | Sets which email domain routes to an org's SSO. Deliberately NOT on the console's self-service `/orgs/{org_id}/sso` form - see the script's own docstring for the security reasoning (org creation is open to anyone; a self-service domain claim with no ownership proof is a phishing primitive). Confirm you actually control the domain before running this. |
| `reset_demo_org.py` | `python -m infra.reset_demo_org --org org_demo` (add `--confirm` to apply) | Wipes a demo tenant's incident data back to a clean state, then reseed. Refuses any org not flagged `public_demo_auto_join`, and preserves `audit`/`runs` (the governance trail) unless `--include-history`. Dry-run by default. |
| `firestore.indexes.json` | see [Firestore composite indexes](#firestore-composite-indexes) for the exact `gcloud` command | The one composite index this codebase's landed queries actually require today. |
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
  `ARCHITECTURE.md` section 4) - landed, and a single equality filter on `status` needs no
  composite index. Tenant scoping is a path prefix (`/tenants/{org_id}/incidents`), not a
  filter, so it doesn't add a second field to the query either. Revisit only if the query
  later adds a second filter or an `orderBy` on a different field (e.g. `status == "open"
  order by opened_at` - see the note on `_active_incidents()` below, which is exactly this
  case and deliberately sorts in Python instead).
- **`Collection.DRAFTS` filtered by `incident_ref`** (console's per-incident view) - landed.
  Single equality filter; no composite index needed unless the query later adds
  `department == X` or `status == "draft"` alongside it.
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
filter, so no other composite index is included. If a later change lands a genuinely
compound query (equality + range/orderBy, or array-contains + anything), add it to
`firestore.indexes.json` then rather than guessing its shape now.

### Creating it

There is no `gcloud firestore deploy` subcommand — `firestore.indexes.json` is the
declarative record, and `gcloud` creates indexes one at a time from explicit flags. This
single command is the whole of it:

```bash
gcloud firestore indexes composite create \
  --collection-group=memory \
  --query-scope=COLLECTION \
  --field-config=field-path=kind,order=ascending \
  --field-config=field-path=related_incident_ids,array-config=contains \
  --project="${GOOGLE_CLOUD_PROJECT}"
```

Index builds are asynchronous; the command returns before the index is ready. Check with:

```bash
gcloud firestore indexes composite list --project="${GOOGLE_CLOUD_PROJECT}"
```

Re-running the create command for an index that already exists fails with `ALREADY_EXISTS`,
which is safe to ignore.

**This is optional at demo scale.** Nothing in the demo path calls `retrieve()` with both
`kind` and `related_incident_id` at once. Without the index, that specific combined query
raises `FAILED_PRECONDITION` (with a link to create it) rather than returning wrong data,
and every other query keeps working.

If you use the Firebase CLI elsewhere, `firebase deploy --only firestore:indexes` consumes
`firestore.indexes.json` directly, including the `fieldOverrides` TTL block below.

## Ordered console queries (no composite index needed)

The console orders runs by `created_at` and audit entries by `ts`, each with a `limit`
and **no accompanying filter**. Firestore serves a single-field `order_by` from its
automatic indexes, so these need no composite index — a composite would only be required
if an equality filter and an `order_by` on a *different* field were combined.

`_active_incidents()` deliberately keeps its Python-side sort for this reason: it filters
on `status == "open"`, so ordering it server-side by `opened_at` *would* require a
composite index. The incident list is small and bounded per tenant, so the sort is done
in application code instead of adding an index for it.

## Audit retention (TTL) — one-time enablement

`data/scope_store.py` writes an `expires_at` Timestamp on every audit entry. Firestore
does not act on it until a TTL policy is enabled for that field:

```bash
gcloud firestore fields ttls update expires_at \
  --collection-group=audit \
  --enable-ttl \
  --project="${GOOGLE_CLOUD_PROJECT}"
```

Without this the field is inert and the audit collection grows without bound — it gains
roughly three documents per agent operation and is read by the console.

Retention defaults to 400 days and is set by `MORTEMTRACE_AUDIT_RETENTION_DAYS`. It is
deliberately long: this is a compliance audit trail, so shortening it is a policy
decision rather than a performance tuning knob. Verify the policy is active with:

```bash
gcloud firestore fields ttls list --collection-group=audit --project="${GOOGLE_CLOUD_PROJECT}"
```

Before enablement that prints `Listed 0 items.`; afterwards it lists the `expires_at`
field with state `ACTIVE`. (There is no `gcloud firestore fields describe` subcommand —
`ttls list` is the check.)

Note that TTL deletion is asynchronous — Firestore removes expired documents within about
24 hours of expiry, not at the instant they expire.

## Configuration reference

Every environment variable the code reads. Anything marked **security-relevant** changes
the system's exposure, not just its behaviour.

### Required in production

| Variable | Purpose |
|---|---|
| `GOOGLE_CLOUD_PROJECT` | GCP project. Also addresses the Model Armor template — when unset, screening silently degrades to local regex heuristics and logs an ERROR. |
| `GOOGLE_CLOUD_LOCATION` | Must be `global` for `gemini-3.5-flash`. Regional endpoints 404 on it. |
| `GOOGLE_GENAI_USE_VERTEXAI` | Must be `true`, or google-genai targets the Gemini Developer API (needs an API key) instead of Vertex AI. |
| `MORTEMTRACE_CLAIM_SECRET` | **Security-relevant.** HMAC key for org claims (agent-to-tenant trust). From Secret Manager. A dev fallback exists and warns loudly; never deploy on it. |
| `MORTEMTRACE_SESSION_SECRET` | **Security-relevant.** HMAC key for human session cookies, CSRF tokens, and the OAuth handshake cookie (`auth/session.py`, `auth/oidc.py`). A SEPARATE key from the claim secret above — rotating one must never affect the other. Same dev-fallback-and-warn pattern. |
| `MORTEMTRACE_API_TOKENS` | **Security-relevant.** MACHINE-caller-auth table, `{sha256(token): {org_ids, subject}}`. From Secret Manager. No longer how a human reaches the console. Empty ⇒ every machine-credential route 401s. |
| `MORTEMTRACE_PUSH_AUDIENCE` | **Security-relevant.** Expected `aud` on Pub/Sub push tokens (the service's own URL). Unset ⇒ push route 500s. |
| `MORTEMTRACE_PUSH_SERVICE_ACCOUNT` | **Security-relevant.** The pusher SA whose email must appear in the token. Audience alone is not authentication — any Google principal can mint a token for an arbitrary audience. |
| `MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID` / `MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET` | **Security-relevant** (the secret half). Google Sign-In's OAuth client — see "Google Sign-In setup" below. Client ID is a plain env var (not sensitive); client secret is Secret Manager-backed. Both unset ⇒ Google Sign-In is unavailable and `/login` offers only an org's own SSO, if configured. |
| `MORTEMTRACE_OIDC_CLIENT_SECRETS` | **Security-relevant.** `{secret_ref: secret}` for organizations that configure their own SSO via `/orgs/{org_id}/sso`. From Secret Manager, same indirection as connector secrets — the actual secret is never stored in the `Organization` document. |

### Security posture

| Variable | Default | Effect |
|---|---|---|
| `MORTEMTRACE_ALLOW_ANONYMOUS_DEMO` | `0` (closed) | `1` serves unauthenticated callers as `MORTEMTRACE_DEMO_ORG`. Demo only. Warns at startup. |
| `MORTEMTRACE_PLATFORM_ORG` | unset (permissive) | Restricts registry writes to one org. Unset ⇒ any tenant with registry write scope can alter agent definitions for every tenant; warns. |
| `MORTEMTRACE_INSECURE_COOKIES` | unset | `1` drops the `Secure` flag on the session cookie. Local HTTP development only. |
| `MORTEMTRACE_TRUSTED_PROXY_HOPS` | `1` | How many proxies in front of this service append to `X-Forwarded-For`. Used by every IP-based decision in the codebase — connectors' `ip_allowlist` strategy and the pre-auth rate limiters above. `1` is correct for Cloud Run (one Google front end); add one for a custom load balancer in front of it. A wrong value fails closed rather than trusting a caller-supplied address — see `auth/identity.py:resolve_client_address`. |
| `MORTEMTRACE_SESSION_MAX_AGE` | `43200` (12h) | Console session cookie lifetime, seconds. |
| `MORTEMTRACE_AUDIT_RETENTION_DAYS` | `400` | Audit TTL. Requires the TTL policy above to be enabled to take effect. |

### Rate limits

Per-instance, not global (Cloud Run runs many instances — see `auth/identity.py`).

| Variable | Default |
|---|---|
| `MORTEMTRACE_INGEST_BURST` / `MORTEMTRACE_INGEST_PER_MINUTE` | `20` / `60` |
| `MORTEMTRACE_CONSOLE_BURST` / `MORTEMTRACE_CONSOLE_PER_MINUTE` | `120` / `600` |
| `MORTEMTRACE_PRE_AUTH_BURST` / `MORTEMTRACE_PRE_AUTH_PER_MINUTE` | `20` / `60` | IP-keyed, not org-keyed — covers routes reachable before any credential check (Home Realm Discovery, invite-link redemption, the webhook connector lookup before it knows which connector's own limit applies). No tenant identity exists yet at this point, so this is the only pre-auth backstop these routes have. |

### Tuning and models

| Variable | Default | Notes |
|---|---|---|
| `MORTEMTRACE_MODEL` | `gemini-3.5-flash` | Primary model. |
| `MORTEMTRACE_FALLBACK_MODEL` | `gemini-2.5-flash` | Used on resource-exhaustion; a different quota pool. |
| `MORTEMTRACE_FIRESTORE_TIMEOUT` | `10` | Seconds. Every Firestore call carries it. |
| `MORTEMTRACE_SCOPE_CACHE_TTL` | `30` | Seconds a registry scope lookup is cached. Also the delay before a publish takes effect. |
| `MODEL_ARMOR_TEMPLATE_ID` / `MODEL_ARMOR_LOCATION` | `mortemtrace-guardian` / `us-central1` | Independent of the Gemini location. |

### Development only

| Variable | Notes |
|---|---|
| `MORTEMTRACE_SYNC_DISPATCH` | `1` runs the whole pipeline in-process. **Never in production** — it puts the full agent cascade in the HTTP request path, violating the <500ms budget. |
| `MORTEMTRACE_PLAIN_LOGS` | `1` for human-readable logs instead of structured JSON. |
| `MORTEMTRACE_DEMO_SCOPE_PROOFS` | `1` re-enables the deliberate denied-reads that generate on-camera audit proof. Costs a registry lookup + audit write per agent run. |
| `MORTEMTRACE_LOG_LEVEL` | Default `INFO`. |
| `MORTEMTRACE_SEED_PUBLIC_DEMO` | `1` makes `seed/generate.py` also write an `Organization` record flagged `public_demo_auto_join=True` for the seeded org — the org `/login/demo` joins anyone into. **Never set this against an org holding real tenant data**; it is meant for exactly one seeded, synthetic-data-only organization. |

## Google Sign-In setup

One-time, interactive, and cannot be scripted safely — it goes through Google's OAuth
consent screen, which requires a human clicking through it. Console's OIDC client
(`auth/oidc.py`) works with the result the same way it works with any other IdP.

1. In [Google Cloud Console](https://console.cloud.google.com/apis/credentials), select
   this project, then **APIs & Services → OAuth consent screen**. Choose **External**
   (or **Internal** if every user is inside your own Google Workspace), fill in the
   required app name/support email, and publish it (Testing mode is fine while iterating,
   but only pre-approved test users can sign in until it's published).
2. **APIs & Services → Credentials → Create Credentials → OAuth client ID.** Application
   type: **Web application**.
3. Under **Authorized redirect URIs**, add `https://<your-console-url>/auth/callback` —
   the exact console URL `infra/deploy.sh` printed, with `/auth/callback` appended. Both
   Google Sign-In and every org's own SSO share this one callback path (see
   `console/ui.py`'s `auth_callback` route), so this is the only redirect URI to register.
4. Copy the generated **Client ID** and **Client secret**. Client ID is not sensitive —
   it's routinely embedded in frontend code — so it becomes a plain deploy-time variable;
   the secret goes into Secret Manager:
   ```bash
   export MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID="<client id>"
   echo -n "<client secret>" | gcloud secrets versions add \
     mortemtrace-google-oauth-client-secret --project "${GOOGLE_CLOUD_PROJECT}" --data-file=-
   ```
5. Redeploy with the same `MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID` set in your shell:
   ```bash
   GOOGLE_CLOUD_PROJECT="${GOOGLE_CLOUD_PROJECT}" bash infra/deploy.sh
   ```
   `deploy.sh` checks the secret actually holds a real value (not the placeholder
   `infra/create_secrets.sh` seeds it with) before wiring Google Sign-In in — its own
   output tells you whether it detected one.

Until this is done, `/login` still works but offers only an organization's own configured
SSO (if any) — no error, just a missing button.

## Connector secrets

Webhook signing secrets live in `MORTEMTRACE_CONNECTOR_SECRETS`, a Secret Manager-backed
JSON object of `{secret_ref: secret}` — the same indirection the API token table uses, and
for the same reason: the connector *document* is readable by anything holding `connectors`
read scope, so a signing key stored in it would make read access equivalent to the ability
to forge events for that tenant.

Add a connector's secret after registering it:

```bash
gcloud secrets versions access latest --secret=mortemtrace-connector-secrets \
  --project="${GOOGLE_CLOUD_PROJECT}" > /tmp/cs.json
# merge in the {connector_id: secret} printed by register_connector.py, then:
gcloud secrets versions add mortemtrace-connector-secrets \
  --project="${GOOGLE_CLOUD_PROJECT}" --data-file=/tmp/cs.json
rm /tmp/cs.json
```

The service reads it at request time, so a new version takes effect on the next cold start
(or immediately with `gcloud run services update --update-secrets`).

## Change events and indexes

`change_events` is queried as `occurred_at >= window_start` ordered by `occurred_at`
descending. The range filter and the sort are on the **same field**, which Firestore serves
from its automatic single-field index — no composite index is required. A composite would
only become necessary if the query also filtered on `service` or `source`, which it
deliberately does not: correlation is by time window, with service matching left to the
model, so that a service named differently in the CI tool than in the incident still
correlates.

### Connector variables

| Variable | Default | Notes |
|---|---|---|
| `MORTEMTRACE_CONNECTOR_SECRETS` | — | **Security-relevant.** Secret Manager-backed `{secret_ref: secret}` for webhook signing. Never stored in the connector document. |
| `MORTEMTRACE_WEBHOOK_BURST` / `MORTEMTRACE_WEBHOOK_PER_MINUTE` | `100` / `300` | Per-tenant webhook rate limit. Higher than the human-facing limits because sources are machines, still bounded because a webhook fans out into paid model calls. |
