#!/usr/bin/env bash
# One-time setup for real asynchronous dispatch: a dedicated service
# account Pub/Sub signs push requests with, and one push subscription
# per topic (excluding dead-letter, which is a destination, not a
# subscriber) pointing at api/ingest.py's POST /pubsub/push/{event_type}.
#
# Run after infra/deploy.sh has deployed mortemtrace-ingest-api once
# (needs its URL):
#
#   GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon bash infra/setup_pubsub_push.sh
#
# Idempotent - subscription/IAM-binding commands are safe to re-run.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${MORTEMTRACE_REGION:-us-central1}"
PUSHER_SA="mortemtrace-pubsub-pusher"
PUSHER_EMAIL="${PUSHER_SA}@${PROJECT}.iam.gserviceaccount.com"

INGEST_URL=$(gcloud run services describe mortemtrace-ingest-api \
  --project "${PROJECT}" --region "${REGION}" --format="value(status.url)")
if [ -z "${INGEST_URL}" ]; then
  echo "Could not resolve mortemtrace-ingest-api's URL - deploy it first (infra/deploy.sh)." >&2
  exit 1
fi
echo "ingest URL: ${INGEST_URL}"

PROJECT_NUMBER=$(gcloud projects describe "${PROJECT}" --format="value(projectNumber)")
PUBSUB_SERVICE_AGENT="service-${PROJECT_NUMBER}@gcp-sa-pubsub.iam.gserviceaccount.com"

echo "Ensuring pusher service account exists..."
gcloud iam service-accounts create "${PUSHER_SA}" \
  --project "${PROJECT}" \
  --display-name="MortemTrace Pub/Sub push authenticator" \
  2>&1 | grep -v "already exists" || true

echo "Granting the pusher SA run.invoker on mortemtrace-ingest-api..."
gcloud run services add-iam-policy-binding mortemtrace-ingest-api \
  --project "${PROJECT}" --region "${REGION}" \
  --member="serviceAccount:${PUSHER_EMAIL}" \
  --role="roles/run.invoker" > /dev/null

echo "Granting Pub/Sub's own service agent permission to publish to dead-letter..."
gcloud pubsub topics add-iam-policy-binding dead-letter \
  --project "${PROJECT}" \
  --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
  --role="roles/pubsub.publisher" > /dev/null

create_push_subscription() {
  local topic="$1"
  local sub_name
  sub_name="$(echo "${topic}" | tr '.' '-')-push"

  echo "Granting Pub/Sub's service agent subscriber rights for dead-lettering on ${topic}..."
  gcloud pubsub subscriptions create "${sub_name}" \
    --project "${PROJECT}" \
    --topic="${topic}" \
    --push-endpoint="${INGEST_URL}/pubsub/push/${topic}" \
    --push-auth-service-account="${PUSHER_EMAIL}" \
    --push-auth-token-audience="${INGEST_URL}" \
    --ack-deadline=60 \
    --dead-letter-topic="dead-letter" \
    --max-delivery-attempts=5 \
    2>&1 | grep -v "already exists" || true

  gcloud pubsub subscriptions add-iam-policy-binding "${sub_name}" \
    --project "${PROJECT}" \
    --member="serviceAccount:${PUBSUB_SERVICE_AGENT}" \
    --role="roles/pubsub.subscriber" > /dev/null
}

for topic in evidence.received evidence.staged timeline.committed incident.classified upstream.matched; do
  echo "Creating push subscription for ${topic}..."
  create_push_subscription "${topic}"
done

# A pull subscription on the dead-letter topic, so failed messages have a
# path back into the pipeline. The dead-letter *destination* existed
# already, but nothing consumed it: messages accumulated with no recovery
# route and replaying meant hand-writing a script. See
# infra/replay_dead_letter.py.
echo "Creating the dead-letter replay subscription..."
gcloud pubsub subscriptions create dead-letter-replay \
  --project "${PROJECT}" \
  --topic="dead-letter" \
  --ack-deadline=60 \
  2>&1 | grep -v "already exists" || true

echo
echo "Done. mortemtrace-ingest-api must be deployed WITHOUT MORTEMTRACE_SYNC_DISPATCH=1,"
echo "WITH MORTEMTRACE_PUSH_AUDIENCE=${INGEST_URL}, and WITH"
echo "MORTEMTRACE_PUSH_SERVICE_ACCOUNT=${PUSHER_EMAIL} for these to be used and verified"
echo "(infra/deploy.sh sets all three correctly)."
echo
echo "The push route verifies the issuing service account, not just the token audience -"
echo "without MORTEMTRACE_PUSH_SERVICE_ACCOUNT set, any Google principal could mint an"
echo "ID token for this URL and inject events."
echo
echo "Inspect dead-lettered messages at any time:"
echo "  python infra/replay_dead_letter.py --dry-run"
