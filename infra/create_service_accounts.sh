#!/usr/bin/env bash
# Creates two dedicated, least-privilege service accounts for the two Cloud
# Run services, and grants each exactly the roles its own code actually
# uses - not roles/editor, which is what the default Compute Engine
# service account both services ran as before this script existed.
#
#   GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/create_service_accounts.sh
#
# Run once, before the next infra/deploy.sh - that script passes
# --service-account and will fail its own precondition check if these
# don't exist yet.
#
# Idempotent: service account creation and IAM bindings are both safe to
# re-run.
#
# Role choices, cross-checked against actual code (not assumed):
#   ingest-api reads/writes Firestore (data/scope_store.py), publishes to
#   Pub/Sub (api/ingest.py's _publish_pubsub), calls Vertex AI/Gemini
#   (gateway/agent_gateway.py) and Model Armor (gateway/model_armor.py),
#   and exports OpenTelemetry traces (telemetry/otel_setup.py) - every
#   Cloud Run service needs logging/monitoring write regardless.
#   console reads Firestore, exports traces, and - unlike ingest-api -
#   never publishes to Pub/Sub, never calls Vertex AI, never calls Model
#   Armor (console/ui.py is a read-only dashboard; no agent invocation
#   happens there).
#
# Secret Manager access is granted per-secret, not via a project-wide
# role - but both services get the SAME secret set, deliberately, not
# split by which app's code actually reads which one. infra/deploy.sh's
# COMMON_SECRETS is one shared --set-secrets string passed to BOTH
# `gcloud run deploy` calls (including MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET,
# which only console's code uses); asymmetric per-service secret access
# would mean restructuring that shared wiring to match, which is real,
# separate work with its own risk of breaking a live deployment, not a
# blocking part of this fix. The actual finding this script closes is
# broader: both services ran as the default Compute Engine service
# account with roles/editor - project-wide, effectively admin over
# Firestore/Pub/Sub/IAM/GCS/Cloud Build - not narrow per-secret
# over-access. That's what the PROJECT ROLES below are split for; the
# secrets are not, on purpose, for now.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"

INGEST_SA="${MORTEMTRACE_INGEST_SA_NAME:-mortemtrace-ingest-runtime}"
CONSOLE_SA="${MORTEMTRACE_CONSOLE_SA_NAME:-mortemtrace-console-runtime}"
INGEST_EMAIL="${INGEST_SA}@${PROJECT}.iam.gserviceaccount.com"
CONSOLE_EMAIL="${CONSOLE_SA}@${PROJECT}.iam.gserviceaccount.com"

ensure_sa() {
  local name="$1" display="$2"
  if gcloud iam service-accounts describe "${name}@${PROJECT}.iam.gserviceaccount.com" \
      --project "${PROJECT}" >/dev/null 2>&1; then
    echo "  service account '${name}' already exists"
  else
    gcloud iam service-accounts create "${name}" \
      --project "${PROJECT}" --display-name="${display}"
    echo "  created service account '${name}'"
  fi
}

grant_project_role() {
  local email="$1" role="$2"
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:${email}" --role="${role}" \
    --condition=None >/dev/null
}

grant_secret_access() {
  local email="$1" secret="$2"
  if ! gcloud secrets describe "${secret}" --project "${PROJECT}" >/dev/null 2>&1; then
    echo "  (skipping ${secret}: doesn't exist yet - run infra/create_secrets.sh first)"
    return
  fi
  gcloud secrets add-iam-policy-binding "${secret}" \
    --project "${PROJECT}" \
    --member="serviceAccount:${email}" \
    --role="roles/secretmanager.secretAccessor" >/dev/null
}

echo "Ensuring service accounts exist..."
ensure_sa "${INGEST_SA}" "MortemTrace ingest-api runtime"
ensure_sa "${CONSOLE_SA}" "MortemTrace console runtime"

echo
echo "Granting mortemtrace-ingest-runtime its roles..."
for role in roles/datastore.user roles/pubsub.publisher roles/aiplatform.user \
            roles/modelarmor.user roles/cloudtrace.agent roles/logging.logWriter \
            roles/monitoring.metricWriter; do
  grant_project_role "${INGEST_EMAIL}" "${role}"
done
for secret in mortemtrace-claim-secret mortemtrace-session-secret \
              mortemtrace-api-tokens mortemtrace-connector-secrets \
              mortemtrace-oidc-client-secrets mortemtrace-google-oauth-client-secret; do
  grant_secret_access "${INGEST_EMAIL}" "${secret}"
done
echo "  done"

echo
echo "Granting mortemtrace-console-runtime its roles..."
for role in roles/datastore.user roles/cloudtrace.agent roles/logging.logWriter \
            roles/monitoring.metricWriter; do
  grant_project_role "${CONSOLE_EMAIL}" "${role}"
done
for secret in mortemtrace-claim-secret mortemtrace-session-secret \
              mortemtrace-api-tokens mortemtrace-connector-secrets \
              mortemtrace-oidc-client-secrets mortemtrace-google-oauth-client-secret; do
  grant_secret_access "${CONSOLE_EMAIL}" "${secret}"
done
echo "  done"

echo
echo "Done. Next: GOOGLE_CLOUD_PROJECT=${PROJECT} bash infra/deploy.sh"
echo "deploy.sh now passes --service-account for both services automatically."
