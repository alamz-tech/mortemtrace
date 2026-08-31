"""Drives the seeded demo incidents' already-committed timelines through
the REAL agent fan-out, so the demo tenant has real departmental drafts -
not just a timeline and a classification.

    GOOGLE_CLOUD_PROJECT=mortemtrace-hackathon python -m infra.seed_drafts

Why this is separate from seed/generate.py, not part of it: generate()
writes Timeline/Classification directly, deliberately bypassing the live
agent pipeline, so a normal reseed stays fast, free, and deterministic.
Producing real drafts means real Gemini calls - genuinely useful for a
judge-facing demo, genuinely wrong as the unconditional default every
time someone reseeds. This script is the explicit, separately-run,
costed step.

Each incident here already has a committed Timeline and a hand-set
Classification (seed/generate.py's own design, for demo consistency -
e.g. inc_seed_checkout_outage is deliberately data_touched=True to
showcase the GDPR clock). Dispatching Classifier again would overwrite
that hand-set classification with the model's own read of the evidence,
which may not agree - so this dispatches the SIX timeline.committed fan-
out targets EXCEPT classifier: diagnosis, postmortem, comms, compliance,
exposure. Compliance still runs (it only needs Classification, which
already exists) and correctly writes a GDPR clock for the data-touched
incident. classifier is skipped, not routed through _ROUTES, so its own
severity/services backfill (agents/classifier/classifier.py) never fires
here - the hand-seeded Incident.severity/services_affected already carry
the right values for these three incidents.
"""
from __future__ import annotations

import logging
import os
import sys

sys.path.insert(0, ".")

os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "true")
os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")
os.environ.setdefault("MORTEMTRACE_SYNC_DISPATCH", "1")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
for _noisy in ("google", "grpc", "urllib3"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)

DEMO_ORG_ID_DEFAULT = os.environ.get("MORTEMTRACE_DEMO_ORG", "org_demo")

_FAN_OUT_MINUS_CLASSIFIER = ["diagnosis", "postmortem", "comms", "compliance", "exposure"]

_SEED_INCIDENT_IDS = ["inc_seed_checkout_outage", "inc_seed_search_degraded", "inc_seed_billing_delay"]


def main() -> None:
    import api.ingest as ingest_module
    from agents.coordinator import coordinator
    from data.models import Envelope, new_id

    org_id = os.environ.get("MORTEMTRACE_DEMO_ORG", DEMO_ORG_ID_DEFAULT)

    for incident_id in _SEED_INCIDENT_IDS:
        run_id = new_id("run")
        claim = ingest_module._ingest_claim(org_id, run_id)
        envelope = Envelope(
            run_id=run_id, org_id=org_id, incident_id=incident_id, claim=claim,
            event_type="timeline.committed",
            payload={"incident_id": incident_id, "run_id": run_id, "org_id": org_id},
        )
        print(f"--- {incident_id}: dispatching {_FAN_OUT_MINUS_CLASSIFIER} ---", flush=True)
        for agent_name in _FAN_OUT_MINUS_CLASSIFIER:
            result = coordinator.dispatch(agent_name, envelope)
            print(f"  {agent_name:12s} -> {result.status:10s} {result.detail}", flush=True)

    print("\nDone. Reload the console to see real departmental drafts on the seed incidents.")


if __name__ == "__main__":
    main()
