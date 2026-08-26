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
# Both services build from the same Dockerfile at repo root (see its
# comment - buildpacks' auto-detection hit an unrelated failure on an
# older gcloud SDK, so this deploys explicitly instead); APP_MODULE
# selects which FastAPI app that image's CMD actually serves.
#
# The ingest API runs with MORTEMTRACE_SYNC_DISPATCH=1: no separate
# Pub/Sub-subscriber service exists (or is required by the spec) to
# consume evidence.staged/timeline.committed/etc downstream - the
# verified, working end-to-end path is Coordinator's routing table
# cascading in-process within one request (see api/ingest.py's
# _route_sync, and tests/test_full_pipeline.py). Without this flag the
# deployed service would publish evidence.received to a topic with no
# subscriber and nothing downstream would ever run.
#
# MORTEMTRACE_CLAIM_SECRET comes from Secret Manager
# (mortemtrace-claim-secret), not a plain --set-env-vars value - this is
# the HMAC key data/scope_store.py signs every org claim with, and it
# needs the same real-secret handling this repo's own code calls for
# (see scope_store.py's docstring on the dev fallback secret). The
# deploying identity's runtime service account needs
# roles/secretmanager.secretAccessor on it. Note: if this secret doesn't
# already exist, `gcloud run deploy --set-secrets` silently auto-creates
# it - verify its value is actually strong (`openssl rand -hex 32 |
# gcloud secrets versions add mortemtrace-claim-secret --data-file=-`)
# rather than trusting whatever gcloud generated for you.
#
# GOOGLE_GENAI_USE_VERTEXAI=true and GOOGLE_CLOUD_LOCATION are both
# required by gateway/agent_gateway.py - see that file's docstring for
# why (without the first, google-genai silently tries the wrong backend
# entirely). GOOGLE_CLOUD_LOCATION is deliberately "global", not REGION
# below - confirmed live that gemini-3.5-flash 404s on every specific
# region tried but works on the global endpoint (the common rollout
# pattern for a newly-released model). This is independent of
# MODEL_ARMOR_LOCATION (gateway/model_armor.py's own default,
# us-central1) and of REGION (where the Cloud Run *service* itself
# runs) - three separate location settings, only the Gemini one needed
# to move to global.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
GEMINI_LOCATION="${MORTEMTRACE_GEMINI_LOCATION:-global}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"
CLAIM_SECRET_NAME="${MORTEMTRACE_CLAIM_SECRET_NAME:-mortemtrace-claim-secret}"

COMMON_SECRETS="MORTEMTRACE_CLAIM_SECRET=${CLAIM_SECRET_NAME}:latest"
COMMON_ENV="GOOGLE_CLOUD_PROJECT=${PROJECT},GOOGLE_CLOUD_LOCATION=${GEMINI_LOCATION},GOOGLE_GENAI_USE_VERTEXAI=true,MORTEMTRACE_DEMO_ORG=${DEMO_ORG}"

echo "Deploying mortemtrace-ingest-api..."
gcloud run deploy mortemtrace-ingest-api \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --port 8080 \
  --set-env-vars "${COMMON_ENV},APP_MODULE=api.ingest:app,MORTEMTRACE_SYNC_DISPATCH=1" \
  --set-secrets "${COMMON_SECRETS}"

echo "Deploying mortemtrace-console..."
gcloud run deploy mortemtrace-console \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --port 8080 \
  --set-env-vars "${COMMON_ENV},APP_MODULE=console.ui:app" \
  --set-secrets "${COMMON_SECRETS}"

echo
echo "Done. Note the two *.run.app URLs above - the demo video needs at least"
echo "one visible on screen as live Google Cloud proof (SPEC section 9)."
