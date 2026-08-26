"""Registers every worker agent's run() function with the Coordinator.

No agent module self-registers as an import side effect - every worker
built for this system was deliberately kept to a plain `run(claim,
envelope) -> RunResult` function with no import-time behavior, so "is
this worker wired up" doesn't depend on which modules happened to get
imported first in what order. register_all() is the one explicit place
that wiring happens; call it once at process startup (api/ingest.py does,
since it's the thing that calls coordinator.route()/dispatch()).

This is Python-level wiring only - it says "this code exists and can be
called." Whether a worker is actually active for a given org is the
Firestore registry's `published`/`deprecated` status (registry/
registry.py, seeded by infra/init_firestore.py), which is the layer R4's
"publish a new department with no code change and no redeploy"
acceptance criterion is actually about.
"""
from __future__ import annotations

from agents.coordinator import coordinator

_REGISTERED = False


def register_all() -> None:
    global _REGISTERED
    if _REGISTERED:
        return

    from agents.classifier.classifier import run as classifier_run
    from agents.departments.comms.comms import run as comms_run
    from agents.departments.compliance.compliance import run as compliance_run
    from agents.departments.exposure.exposure import run as exposure_run
    from agents.departments.postmortem.postmortem import run as postmortem_run
    from agents.diagnosis.diagnosis import run as diagnosis_run
    from agents.intake.intake import run as intake_run
    from agents.ledger.ledger import run as ledger_run
    from agents.watcher.watcher import run as watcher_run

    coordinator.register_worker("intake", intake_run)
    coordinator.register_worker("ledger", ledger_run)
    coordinator.register_worker("diagnosis", diagnosis_run)
    coordinator.register_worker("classifier", classifier_run)
    coordinator.register_worker("watcher", watcher_run)
    coordinator.register_worker("postmortem", postmortem_run)
    coordinator.register_worker("comms", comms_run)
    coordinator.register_worker("compliance", compliance_run)
    coordinator.register_worker("exposure", exposure_run)

    _REGISTERED = True
