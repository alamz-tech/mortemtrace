#!/usr/bin/env bash
# Deploys the ingest API and operator console to Cloud Run.
#
# Not run automatically by anything in this repo - review, then run
# manually:
#   GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/deploy.sh
#
# After the first-ever deploy, also run infra/setup_pubsub_push.sh once
# to create the real push subscriptions (needs the ingest URL this
# script produces).
#
# min-instances=0 on both services is deliberate, not an oversight: the
# NFR ("No in-memory state survives a Cloud Run instance") means nothing
# is lost by scaling to zero between demo runs, and it is what keeps a
# full rehearsal cycle inside free-trial cost.
#
# Both services build from the same Dockerfile at repo root; APP_MODULE
# selects which FastAPI app that image's CMD actually serves.
#
# ---------------------------------------------------------------------
# ENV VAR HANDLING - read this before editing
# ---------------------------------------------------------------------
# `--set-env-vars` REPLACES the service's entire environment. An earlier
# version of this script deployed with a partial set and then patched
# MORTEMTRACE_PUSH_AUDIENCE in with a second `gcloud run services update`
# call. That works exactly once: the next deploy's --set-env-vars silently
# wipes the patched-in variable, after which _verify_push_token returns
# HTTP 500 on every Pub/Sub delivery with no traceback and the whole
# pipeline dies quietly. That happened in practice and took log
# archaeology to find.
#
# The fix is structural: resolve the service URL FIRST (it is stable
# across revisions), then pass one complete, self-contained env set.
# Never add a follow-up `update-env-vars` call to this script.
#
# GOOGLE_GENAI_USE_VERTEXAI=true and GOOGLE_CLOUD_LOCATION are both
# required by gateway/agent_gateway.py - see that file's docstring for
# why (without the first, google-genai silently tries the wrong backend
# entirely). GOOGLE_CLOUD_LOCATION is deliberately "global", not REGION -
# confirmed live that gemini-3.5-flash 404s on every specific region
# tried but works on the global endpoint. This is independent of
# MODEL_ARMOR_LOCATION and of REGION (where the Cloud Run *service*
# runs) - three separate location settings, only the Gemini one moved.
#
# SECRETS: MORTEMTRACE_CLAIM_SECRET, MORTEMTRACE_SESSION_SECRET,
# MORTEMTRACE_API_TOKENS, MORTEMTRACE_CONNECTOR_SECRETS, and
# MORTEMTRACE_OIDC_CLIENT_SECRETS all come from Secret Manager, never
# from --set-env-vars. Create them with infra/create_secrets.sh.
#
# GOOGLE SIGN-IN: MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID is a plain env var
# (not secret - Google OAuth client IDs are routinely public), read from
# this script's own environment if set. MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET
# comes from Secret Manager, but is wired in only if it holds a real
# value - infra/create_secrets.sh seeds it with a placeholder, and
# deploying with the placeholder still in place would otherwise silently
# tell every service "Google Sign-In is configured" with a secret that
# cannot authenticate anyone. See infra/README.md's "Google Sign-In
# setup" section for the one-time manual Google Cloud Console steps.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
GEMINI_LOCATION="${MORTEMTRACE_GEMINI_LOCATION:-global}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"
PLATFORM_ORG="${MORTEMTRACE_PLATFORM_ORG:-${DEMO_ORG}}"
CLAIM_SECRET_NAME="${MORTEMTRACE_CLAIM_SECRET_NAME:-mortemtrace-claim-secret}"
SESSION_SECRET_NAME="${MORTEMTRACE_SESSION_SECRET_NAME:-mortemtrace-session-secret}"
TOKENS_SECRET_NAME="${MORTEMTRACE_TOKENS_SECRET_NAME:-mortemtrace-api-tokens}"
CONNECTOR_SECRETS_NAME="${MORTEMTRACE_CONNECTOR_SECRETS_NAME:-mortemtrace-connector-secrets}"
OIDC_CLIENT_SECRETS_NAME="${MORTEMTRACE_OIDC_CLIENT_SECRETS_NAME:-mortemtrace-oidc-client-secrets}"
GOOGLE_OAUTH_SECRET_NAME="${MORTEMTRACE_GOOGLE_OAUTH_SECRET_NAME:-mortemtrace-google-oauth-client-secret}"
GOOGLE_OAUTH_PLACEHOLDER="unset-see-infra-README-google-sign-in-setup"
PUSHER_EMAIL="mortemtrace-pubsub-pusher@${PROJECT}.iam.gserviceaccount.com"

# Anonymous demo mode is OFF unless explicitly requested. Default-closed
# is the whole point: with it off and no tokens configured, the services
# return 401 rather than serving any tenant's data to anyone.
ALLOW_ANON="${MORTEMTRACE_ALLOW_ANONYMOUS_DEMO:-0}"
if [ "${ALLOW_ANON}" = "1" ]; then
  echo "WARNING: deploying with MORTEMTRACE_ALLOW_ANONYMOUS_DEMO=1."
  echo "         Unauthenticated callers will be served as tenant '${DEMO_ORG}'."
  echo "         Use this only for the recorded demo, never with real tenant data."
  echo
fi

require_secret() {
  local name="$1"
  if ! gcloud secrets describe "${name}" --project "${PROJECT}" >/dev/null 2>&1; then
    echo "Missing Secret Manager secret '${name}'." >&2
    echo "Create it first:  GOOGLE_CLOUD_PROJECT=${PROJECT} bash infra/create_secrets.sh" >&2
    exit 1
  fi
}
require_secret "${CLAIM_SECRET_NAME}"
require_secret "${SESSION_SECRET_NAME}"
require_secret "${TOKENS_SECRET_NAME}"
require_secret "${CONNECTOR_SECRETS_NAME}"
require_secret "${OIDC_CLIENT_SECRETS_NAME}"

COMMON_SECRETS="MORTEMTRACE_CLAIM_SECRET=${CLAIM_SECRET_NAME}:latest,MORTEMTRACE_SESSION_SECRET=${SESSION_SECRET_NAME}:latest,MORTEMTRACE_API_TOKENS=${TOKENS_SECRET_NAME}:latest,MORTEMTRACE_CONNECTOR_SECRETS=${CONNECTOR_SECRETS_NAME}:latest,MORTEMTRACE_OIDC_CLIENT_SECRETS=${OIDC_CLIENT_SECRETS_NAME}:latest"

# Google Sign-In is wired in only if a real (non-placeholder) client
# secret has been set - see the header comment above.
GOOGLE_OAUTH_ENV=""
if gcloud secrets describe "${GOOGLE_OAUTH_SECRET_NAME}" --project "${PROJECT}" >/dev/null 2>&1; then
  CURRENT_OAUTH_SECRET=$(gcloud secrets versions access latest \
    --secret="${GOOGLE_OAUTH_SECRET_NAME}" --project "${PROJECT}" 2>/dev/null || true)
  if [ -n "${CURRENT_OAUTH_SECRET}" ] && [ "${CURRENT_OAUTH_SECRET}" != "${GOOGLE_OAUTH_PLACEHOLDER}" ]; then
    if [ -z "${MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID:-}" ]; then
      echo "MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET is set but MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID is not." >&2
      echo "Set both (see infra/README.md's Google Sign-In setup section) or neither." >&2
      exit 1
    fi
    GOOGLE_OAUTH_ENV=",MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID=${MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID}"
    COMMON_SECRETS="${COMMON_SECRETS},MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET=${GOOGLE_OAUTH_SECRET_NAME}:latest"
    echo "Google Sign-In: configured (client_id=${MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID})."
  else
    echo "Google Sign-In: NOT configured yet (placeholder secret) - human login will only work via"
    echo "  an org's own SSO, if any is configured. See infra/README.md's Google Sign-In setup section."
  fi
fi

# Resolve the ingest URL before deploying so the env set can be complete
# in one shot. Empty on the very first deploy; handled below.
INGEST_URL=$(gcloud run services describe mortemtrace-ingest-api \
  --project "${PROJECT}" --region "${REGION}" --format="value(status.url)" 2>/dev/null || true)

build_common_env() {
  printf '%s' \
    "GOOGLE_CLOUD_PROJECT=${PROJECT},GOOGLE_CLOUD_LOCATION=${GEMINI_LOCATION},GOOGLE_GENAI_USE_VERTEXAI=true,MORTEMTRACE_DEMO_ORG=${DEMO_ORG},MORTEMTRACE_PLATFORM_ORG=${PLATFORM_ORG},MORTEMTRACE_ALLOW_ANONYMOUS_DEMO=${ALLOW_ANON},MORTEMTRACE_PUSH_SERVICE_ACCOUNT=${PUSHER_EMAIL}${GOOGLE_OAUTH_ENV}"
}

deploy_ingest() {
  local url="$1"
  local env_vars
  env_vars="$(build_common_env),APP_MODULE=api.ingest:app"
  if [ -n "${url}" ]; then
    env_vars="${env_vars},MORTEMTRACE_PUSH_AUDIENCE=${url}"
  fi

  gcloud run deploy mortemtrace-ingest-api \
    --source . \
    --project "${PROJECT}" \
    --region "${REGION}" \
    --allow-unauthenticated \
    --min-instances 0 \
    --max-instances "${MORTEMTRACE_MAX_INSTANCES:-10}" \
    --port 8080 \
    --set-env-vars "${env_vars}" \
    --set-secrets "${COMMON_SECRETS}"
}

echo "Deploying mortemtrace-ingest-api..."
deploy_ingest "${INGEST_URL}"

if [ -z "${INGEST_URL}" ]; then
  # First-ever deploy only: the URL did not exist until the deploy above
  # created it. Redeploy once with the now-complete env set rather than
  # patching a single variable in - see the ENV VAR HANDLING note.
  INGEST_URL=$(gcloud run services describe mortemtrace-ingest-api \
    --project "${PROJECT}" --region "${REGION}" --format="value(status.url)")
  echo "First deploy detected; redeploying with MORTEMTRACE_PUSH_AUDIENCE=${INGEST_URL}..."
  deploy_ingest "${INGEST_URL}"
fi

echo "Deploying mortemtrace-console..."
gcloud run deploy mortemtrace-console \
  --source . \
  --project "${PROJECT}" \
  --region "${REGION}" \
  --allow-unauthenticated \
  --min-instances 0 \
  --max-instances "${MORTEMTRACE_MAX_INSTANCES:-10}" \
  --port 8080 \
  --set-env-vars "$(build_common_env),APP_MODULE=console.ui:app" \
  --set-secrets "${COMMON_SECRETS}"

CONSOLE_URL=$(gcloud run services describe mortemtrace-console \
  --project "${PROJECT}" --region "${REGION}" --format="value(status.url)")

echo
echo "Done."
echo "  ingest : ${INGEST_URL}"
echo "  console: ${CONSOLE_URL}"
echo
echo "Verify the deployment is closed by default (expect 401):"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' '${CONSOLE_URL}/api/runs'"
echo
if [ -n "${GOOGLE_OAUTH_ENV}" ]; then
  echo "Human login: ${CONSOLE_URL}/login (Google Sign-In is configured)."
  echo "Judge/demo access, if a public_demo_auto_join org has been seeded:"
  echo "  ${CONSOLE_URL}/login/demo"
else
  echo "Google Sign-In is not yet configured - human login will 401 with no working path"
  echo "until you complete infra/README.md's 'Google Sign-In setup' section and redeploy."
fi
echo
echo "If this was mortemtrace-ingest-api's first-ever deploy, now run:"
echo "  GOOGLE_CLOUD_PROJECT=${PROJECT} bash infra/setup_pubsub_push.sh"
