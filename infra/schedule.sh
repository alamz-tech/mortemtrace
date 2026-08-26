#!/usr/bin/env bash
# Cloud Scheduler job for the periodic Watcher sweep (R2, R3).
#
# Not run automatically - review, then run manually after infra/deploy.sh
# has deployed mortemtrace-ingest-api and you have its *.run.app URL:
#
#   INGEST_URL=https://mortemtrace-ingest-api-xxxxx.a.run.app \
#     GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/schedule.sh
#
# Hits POST /watcher/sweep on the ingest API (api/ingest.py) - the same
# endpoint tests/test_ingest.py's
# test_watcher_sweep_endpoint_correlates_real_seed_data exercises
# end-to-end against real seed data, not a placeholder route.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
INGEST_URL="${INGEST_URL:?set INGEST_URL to the deployed ingest API's *.run.app URL}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"

gcloud scheduler jobs create http mortemtrace-watcher-sweep \
  --project "${PROJECT}" \
  --location "${REGION}" \
  --schedule "*/30 * * * *" \
  --uri "${INGEST_URL}/watcher/sweep" \
  --http-method POST \
  --headers "Content-Type=application/json" \
  --message-body "{\"org_id\": \"${DEMO_ORG}\"}" \
  --attempt-deadline 60s \
  || gcloud scheduler jobs update http mortemtrace-watcher-sweep \
       --project "${PROJECT}" \
       --location "${REGION}" \
       --schedule "*/30 * * * *" \
       --uri "${INGEST_URL}/watcher/sweep" \
       --http-method POST \
       --headers "Content-Type=application/json" \
       --message-body "{\"org_id\": \"${DEMO_ORG}\"}" \
       --attempt-deadline 60s

echo
echo "Watcher sweep scheduled every 30 minutes. For a live demo trigger with"
echo "a specific injected signal instead of waiting on the schedule:"
echo "  curl -X POST ${INGEST_URL}/watcher/sweep -H 'Content-Type: application/json' \\"
echo "    -d '{\"org_id\": \"${DEMO_ORG}\", \"injected_signal\": {...}}'"
