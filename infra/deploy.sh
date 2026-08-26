#!/usr/bin/env bash
# Deploys the ingest API and operator console to Cloud Run.
#
# Not run automatically by anything in this repo - review, then run
# manually: `GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/deploy.sh`
#
# min-instances=0 on both services is deliberate, not an oversight: the
# NFR ("No in-memory state survives a Cloud Run instance") means nothing
# is lost by scaling to zero between demo runs, and it is what keeps a
# full rehearsal cycle inside free-trial cost.
#
# Both services build from the same source tree via Cloud Buildpacks
# (no Dockerfile needed) with GOOGLE_ENTRYPOINT set per service, since
# one repo here serves two distinct FastAPI apps - this is the
# documented buildpacks mechanism for exactly that, not a workaround.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"

COMMON_ENV="GOOGLE_CLOUD_PROJECT=${PROJECT},MORTEMTRACE_DEMO_ORG=${DEMO_ORG}"

echo "Deploying mortemtrace-ingest-api..."
gcloud run deploy mortemtrace-ingest-api \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --set-build-env-vars "GOOGLE_ENTRYPOINT=uvicorn api.ingest:app --host 0.0.0.0 --port \$PORT" \
  --set-env-vars "${COMMON_ENV}"

echo "Deploying mortemtrace-console..."
gcloud run deploy mortemtrace-console \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --set-build-env-vars "GOOGLE_ENTRYPOINT=uvicorn console.ui:app --host 0.0.0.0 --port \$PORT" \
  --set-env-vars "${COMMON_ENV}"

echo
echo "Done. Note the two *.run.app URLs above - the demo video needs at least"
echo "one visible on screen as live Google Cloud proof (SPEC section 9)."
