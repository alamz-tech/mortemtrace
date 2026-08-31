#!/usr/bin/env bash
# Creates a Cloud Billing budget alert for this project.
#
#   BILLING_ACCOUNT_ID=0X0X0X-0X0X0X-0X0X0X \
#     GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon \
#     bash infra/create_budget_alert.sh
#
# Why this is a separate, manually-run script and not part of deploy.sh:
# creating a budget needs billing-account-level permissions that the
# deploying identity usually does not have, and the billing account id
# cannot be derived from the project - it has to be supplied. Find yours
# with:
#
#   gcloud billing accounts list
#
# WHY IT MATTERS: /ingest fans out into a chain of ~8 agents making real
# Gemini calls (observed 16k-33k tokens per incident). Application-level
# rate limits (auth/identity.py) are per-Cloud-Run-instance, so N
# instances allow N x the per-instance budget. A billing alert is the
# only backstop that sees total spend across every instance, and on a
# free-trial project quota exhaustion takes the demo down.
#
# This creates an ALERT, not a cap. GCP budgets notify; they do not stop
# spend. To actually halt spend you need a Pub/Sub-triggered function
# that disables billing, which is deliberately out of scope here - it is
# an irreversible action on a live project and should be a considered
# decision, not a side effect of running a setup script.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
BILLING_ACCOUNT_ID="${BILLING_ACCOUNT_ID:?set BILLING_ACCOUNT_ID - find it with: gcloud billing accounts list}"
BUDGET_AMOUNT="${MORTEMTRACE_BUDGET_USD:-50}"
BUDGET_NAME="${MORTEMTRACE_BUDGET_NAME:-mortemtrace-spend-guard}"

echo "Creating budget '${BUDGET_NAME}': \$${BUDGET_AMOUNT} USD on project ${PROJECT}"
echo "Alert thresholds: 50%, 90%, 100% of budget."
echo

gcloud billing budgets create \
  --billing-account="${BILLING_ACCOUNT_ID}" \
  --display-name="${BUDGET_NAME}" \
  --budget-amount="${BUDGET_AMOUNT}USD" \
  --filter-projects="projects/${PROJECT}" \
  --threshold-rule=percent=0.5 \
  --threshold-rule=percent=0.9 \
  --threshold-rule=percent=1.0

echo
echo "Done. Verify with:"
echo "  gcloud billing budgets list --billing-account=${BILLING_ACCOUNT_ID}"
echo
echo "Reminder: this notifies, it does not cap. Watch the alerts."
