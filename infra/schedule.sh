#!/usr/bin/env bash
# Cloud Scheduler job for the periodic Watcher sweep (R2, R3).
#
# Not run automatically - review, then run manually after infra/deploy.sh
# has deployed mortemtrace-ingest-api and you have its *.run.app URL:
#
#   INGEST_URL=https://mortemtrace-ingest-api-xxxxx.a.run.app \
#     MORTEMTRACE_SWEEP_TOKEN=<api token> \
#     GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/schedule.sh
#
# Hits POST /watcher/sweep on the ingest API (api/ingest.py) - the same
# endpoint tests/test_ingest.py's
# test_watcher_sweep_endpoint_correlates_real_seed_data exercises
# end-to-end against real seed data, not a placeholder route.
#
# AUTHENTICATION: /watcher/sweep triggers a real agent dispatch and, on a
# correlation, a real (paid) Gemini call, so it is authenticated like
# /ingest. The scheduler carries an API token; mint a dedicated one for
# it rather than reusing an operator's:
#
#   python infra/mint_token.py --org org_demo --subject cloud-scheduler
#
# The token is passed via --headers, which Cloud Scheduler stores
# encrypted at rest. It is visible to anyone with
# cloudscheduler.jobs.get on the project, so treat it as a
# service-to-service credential with a single narrow scope, and rotate it
# by minting a new one and re-running this script.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
INGEST_URL="${INGEST_URL:?set INGEST_URL to the deployed ingest API run.app URL}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"
SWEEP_TOKEN="${MORTEMTRACE_SWEEP_TOKEN:?set MORTEMTRACE_SWEEP_TOKEN - mint one with infra/mint_token.py}"
SCHEDULE="${MORTEMTRACE_SWEEP_SCHEDULE:-*/30 * * * *}"

# org_id is omitted from the body deliberately: a single-tenant token
# resolves its own tenant, so there is nothing to assert and nothing that
# could disagree with the credential.
BODY='{}'

common_args=(
  --project "${PROJECT}"
  --location "${REGION}"
  --schedule "${SCHEDULE}"
  --uri "${INGEST_URL}/watcher/sweep"
  --http-method POST
  --headers "Content-Type=application/json,Authorization=Bearer ${SWEEP_TOKEN}"
  --message-body "${BODY}"
  --attempt-deadline 60s
)

if gcloud scheduler jobs describe mortemtrace-watcher-sweep \
     --project "${PROJECT}" --location "${REGION}" >/dev/null 2>&1; then
  echo "Updating existing scheduler job..."
  gcloud scheduler jobs update http mortemtrace-watcher-sweep "${common_args[@]}"
else
  echo "Creating scheduler job..."
  gcloud scheduler jobs create http mortemtrace-watcher-sweep "${common_args[@]}"
fi

echo
echo "Watcher sweep scheduled: ${SCHEDULE} (tenant resolved from the token)."
echo
echo "Verify it works before trusting the schedule:"
echo "  gcloud scheduler jobs run mortemtrace-watcher-sweep --project ${PROJECT} --location ${REGION}"
echo
echo "For a live demo trigger with a specific injected signal:"
echo "  curl -X POST ${INGEST_URL}/watcher/sweep \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -H \"Authorization: Bearer \${MORTEMTRACE_SWEEP_TOKEN}\" \\"
echo "    -d '{\"injected_signal\": {...}}'"
