#!/usr/bin/env bash
# Creates the two Secret Manager secrets the services require, and mints
# an initial API token.
#
#   GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/create_secrets.sh
#
# Idempotent for the secret *containers*; it adds a new version only when
# a secret has none, so re-running never silently rotates a live
# credential out from under a running service.
#
# Secrets created here:
#   mortemtrace-claim-secret    - HMAC key data/scope_store.py signs org
#       claims with (agent-to-tenant trust, unrelated to human login).
#   mortemtrace-session-secret  - HMAC key auth/session.py signs human
#       session cookies and CSRF tokens with, and auth/oidc.py's OAuth
#       handshake cookie. A SEPARATE key from the claim secret above -
#       rotating one must never silently affect the other.
#   mortemtrace-api-tokens      - the MACHINE-caller authentication table
#       consumed by auth/identity.py (/ingest, /watcher/sweep; no longer
#       how a human reaches the console - see auth/identity.py's module
#       docstring). Maps sha256(token) -> {org_ids, subject}. Only
#       digests are stored, so the secret's contents are not themselves a
#       usable credential if they leak into a log or a process listing.
#   mortemtrace-connector-secrets - webhook signing secrets, per connector.
#   mortemtrace-oidc-client-secrets - client secrets for organizations
#       that configure their own SSO (Entra ID/Okta/etc.) via the
#       console's /orgs/{org_id}/sso page. Empty until an admin does so.
#   mortemtrace-google-oauth-client-secret - the OAuth client secret for
#       Google Sign-In. Created here as an EMPTY placeholder - creating
#       the actual OAuth 2.0 Client is an interactive, consent-screen-
#       bound step in the Google Cloud Console that cannot be safely
#       scripted. See infra/README.md's "Google Sign-In setup" section
#       for the manual steps, then add the real value with:
#         echo -n "<client secret>" | gcloud secrets versions add \
#           mortemtrace-google-oauth-client-secret --project ${GOOGLE_CLOUD_PROJECT} --data-file=-
#       The client ID is not secret and is passed as a plain env var
#       (MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID) by infra/deploy.sh instead.
#
# The plaintext API token is printed ONCE, here, and never stored anywhere.
# If it is lost, mint another with infra/mint_token.py and add a new
# secret version - there is no way to recover it from the digest.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
DEMO_ORG="${MORTEMTRACE_DEMO_ORG:-org_demo}"
CLAIM_SECRET_NAME="${MORTEMTRACE_CLAIM_SECRET_NAME:-mortemtrace-claim-secret}"
SESSION_SECRET_NAME="${MORTEMTRACE_SESSION_SECRET_NAME:-mortemtrace-session-secret}"
TOKENS_SECRET_NAME="${MORTEMTRACE_TOKENS_SECRET_NAME:-mortemtrace-api-tokens}"
CONNECTOR_SECRETS_NAME="${MORTEMTRACE_CONNECTOR_SECRETS_NAME:-mortemtrace-connector-secrets}"
OIDC_CLIENT_SECRETS_NAME="${MORTEMTRACE_OIDC_CLIENT_SECRETS_NAME:-mortemtrace-oidc-client-secrets}"
GOOGLE_OAUTH_SECRET_NAME="${MORTEMTRACE_GOOGLE_OAUTH_SECRET_NAME:-mortemtrace-google-oauth-client-secret}"

ensure_secret() {
  local name="$1"
  if gcloud secrets describe "${name}" --project "${PROJECT}" >/dev/null 2>&1; then
    echo "  secret '${name}' already exists"
  else
    gcloud secrets create "${name}" --project "${PROJECT}" --replication-policy=automatic
    echo "  created secret '${name}'"
  fi
}

has_version() {
  gcloud secrets versions list "$1" --project "${PROJECT}" --limit=1 --format="value(name)" 2>/dev/null | grep -q .
}

echo "Ensuring secrets exist..."
ensure_secret "${CLAIM_SECRET_NAME}"
ensure_secret "${SESSION_SECRET_NAME}"
ensure_secret "${TOKENS_SECRET_NAME}"
ensure_secret "${CONNECTOR_SECRETS_NAME}"
ensure_secret "${OIDC_CLIENT_SECRETS_NAME}"
ensure_secret "${GOOGLE_OAUTH_SECRET_NAME}"

echo
if has_version "${CLAIM_SECRET_NAME}"; then
  echo "Claim secret already has a version; leaving it alone."
  echo "  (to rotate deliberately: openssl rand -hex 32 | gcloud secrets versions add ${CLAIM_SECRET_NAME} --project ${PROJECT} --data-file=-)"
else
  openssl rand -hex 32 | gcloud secrets versions add "${CLAIM_SECRET_NAME}" \
    --project "${PROJECT}" --data-file=- >/dev/null
  echo "Generated a 256-bit claim secret."
fi

echo
if has_version "${SESSION_SECRET_NAME}"; then
  echo "Session secret already has a version; leaving it alone."
  echo "  (to rotate deliberately: openssl rand -hex 32 | gcloud secrets versions add ${SESSION_SECRET_NAME} --project ${PROJECT} --data-file=-)"
  echo "  (rotating this signs every existing human session out immediately - it does not affect API tokens)"
else
  openssl rand -hex 32 | gcloud secrets versions add "${SESSION_SECRET_NAME}" \
    --project "${PROJECT}" --data-file=- >/dev/null
  echo "Generated a 256-bit session secret."
fi

echo
if has_version "${TOKENS_SECRET_NAME}"; then
  echo "API token table already has a version; leaving it alone."
  echo "  (to add a token: python infra/mint_token.py --org ${DEMO_ORG} --subject <name>)"
else
  TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
  DIGEST="$(printf '%s' "${TOKEN}" | python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
  printf '{"%s": {"org_ids": ["%s"], "subject": "initial-operator"}}' "${DIGEST}" "${DEMO_ORG}" \
    | gcloud secrets versions add "${TOKENS_SECRET_NAME}" --project "${PROJECT}" --data-file=- >/dev/null

  echo "============================================================"
  echo "API token for tenant '${DEMO_ORG}' (shown once, not recoverable):"
  echo
  echo "  ${TOKEN}"
  echo
  echo "Use it as:  Authorization: Bearer ${TOKEN}"
  echo "This is for MACHINE callers (/ingest, /watcher/sweep) or scripts -"
  echo "it is no longer how a human reaches the console. For a human, see"
  echo "infra/README.md's Google Sign-In setup section."
  echo "============================================================"
fi

echo
echo "Granting the Cloud Run runtime service account access to all secrets..."
PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format="value(projectNumber)")
RUNTIME_SA="${PROJECT_NUMBER}-compute@developer.gserviceaccount.com"
for secret in "${CLAIM_SECRET_NAME}" "${SESSION_SECRET_NAME}" "${TOKENS_SECRET_NAME}" \
              "${CONNECTOR_SECRETS_NAME}" "${OIDC_CLIENT_SECRETS_NAME}" "${GOOGLE_OAUTH_SECRET_NAME}"; do
  gcloud secrets add-iam-policy-binding "${secret}" \
    --project "${PROJECT}" \
    --member="serviceAccount:${RUNTIME_SA}" \
    --role="roles/secretmanager.secretAccessor" >/dev/null
done
echo "  granted to ${RUNTIME_SA}"

# Webhook signing secrets, empty until a connector is registered.
if ! has_version "${CONNECTOR_SECRETS_NAME}"; then
  printf '{}' | gcloud secrets versions add "${CONNECTOR_SECRETS_NAME}" \
    --project "${PROJECT}" --data-file=- >/dev/null
  echo "Initialised an empty connector-secrets table."
fi

# Per-org SSO client secrets, empty until an admin configures one via
# the console's /orgs/{org_id}/sso page.
if ! has_version "${OIDC_CLIENT_SECRETS_NAME}"; then
  printf '{}' | gcloud secrets versions add "${OIDC_CLIENT_SECRETS_NAME}" \
    --project "${PROJECT}" --data-file=- >/dev/null
  echo "Initialised an empty OIDC client-secrets table."
fi

# Placeholder only - deploy.sh checks for a REAL (non-placeholder) value
# before wiring Google Sign-In into the running service, so this alone
# does not turn it on.
GOOGLE_OAUTH_PLACEHOLDER="unset-see-infra-README-google-sign-in-setup"
if ! has_version "${GOOGLE_OAUTH_SECRET_NAME}"; then
  printf '%s' "${GOOGLE_OAUTH_PLACEHOLDER}" | gcloud secrets versions add "${GOOGLE_OAUTH_SECRET_NAME}" \
    --project "${PROJECT}" --data-file=- >/dev/null
  echo "Initialised a placeholder Google OAuth client secret (Google Sign-In stays off until you replace it)."
fi

echo
echo "Done. Google Sign-In still needs a one-time manual step - see"
echo "infra/README.md's 'Google Sign-In setup' section - before human login works."
echo "Next: GOOGLE_CLOUD_PROJECT=${PROJECT} bash infra/deploy.sh"
