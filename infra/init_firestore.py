"""One-time registry bootstrap for MortemTrace. Run once per environment:

    python -m infra.init_firestore

Writes the platform-admin registry entry via the unauthenticated
`scope_store.bootstrap_registry_write` path - the one entry that MUST use
it, because nothing can authenticate to publish it otherwise (it is the
identity that will publish everyone else). Every other agent in the fleet
is then published through the real, authenticated path: mint a
platform-admin claim with `scope_store.sign_claim`, call
`registry.publish(claim, AgentVersionRecord(...))`. That exercises the
same code path a real platform admin uses from the console, not just the
bootstrap escape hatch (R4's "publish once, no redeploy" acceptance is
only proven if the publish path is the real one).

Idempotent: every write here is a Firestore `.set()` on a deterministic
document id (`registry/{agent_name}/versions/{version}`), so re-running
overwrites the same documents rather than creating duplicates or raising.

Firestore composite indexes: see infra/README.md. Short version - at
demo scale only one landed query needs one (Collection.MEMORY filtered by
`kind` + `related_incident_ids` array-contains in memory/memory_bank.py);
it's declared in infra/firestore.indexes.json. Coordinator's quarantine
query (agent_name + version) is two equality filters, which Firestore
serves from automatic indexes with no composite index required.
"""
from __future__ import annotations

import os

from data import scope_store
from data.models import AgentVersionRecord, Collection, new_id
from registry import registry

DEMO_ORG_ID = os.environ.get("MORTEMTRACE_DEMO_ORG", "org_demo")

_PLATFORM_ADMIN = dict(
    agent_name="platform-admin", version="1.0.0",
    input_schema="AgentVersionRecord", output_schema="AgentVersionRecord",
    read_scopes=[Collection.REGISTRY], write_scopes=[Collection.REGISTRY],
    department=None,
)

# Registry entries for the rest of the fleet. Scopes here are the security
# boundary (data/scope_store.py enforces exactly these, nothing looser) -
# they mirror the table in the build brief, cross-checked against actual
# agent code where that code has landed:
#   - coordinator's read/write scopes match agents/coordinator/coordinator.py
#     exactly: registry.resolve() needs REGISTRY read, _is_quarantined()
#     needs QUARANTINE read, _touch_run() needs RUNS read+write,
#     _quarantine() needs QUARANTINE write.
#   - guardian's scopes match agents/guardian/guardian.py exactly:
#     RAW_EVIDENCE read (preflight screens the evidence body) plus a
#     write to Collection.ALERTS via _escalate().
# Every agent below now has a landed implementation, and the scopes here
# have been reconciled against what that code actually reads and writes.
# If they ever disagree, the code is the source of truth: an agent
# denied a scope it needs degrades (or dead-letters) rather than
# escalating, so an over-narrow entry is a visible bug and an over-broad
# one is a silent security hole. Re-run this script after changing any
# agent's data access.
#
# NOTE: re-running is REQUIRED after upgrading a deployment that predates
# guardian gaining RAW_EVIDENCE read scope - without it, guardian.preflight
# cannot read the evidence it is supposed to screen and degrades to
# screening nothing (which is exactly the no-op bug that scope fixed).
_FLEET: list[dict] = [
    dict(
        agent_name="coordinator", version="1.0.0",
        input_schema="Envelope", output_schema="Run",
        read_scopes=[Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
        write_scopes=[Collection.RUNS, Collection.QUARANTINE],
        department=None,
    ),
    dict(
        agent_name="guardian", version="1.0.0",
        input_schema="Envelope", output_schema="AlertRecord",
        # RAW_EVIDENCE is required for preflight to screen the evidence
        # body rather than only envelope metadata (see guardian.preflight).
        # Guardian is a governance agent, not a departmental one: it reads
        # evidence solely to screen it and never writes anything derived
        # from the content - only an alert saying it was blocked.
        read_scopes=[Collection.RAW_EVIDENCE],
        write_scopes=[Collection.ALERTS],
        department=None,
    ),
    dict(
        agent_name="intake", version="1.0.0",
        input_schema="RawEvidence", output_schema="IncidentEvent",
        read_scopes=[Collection.RAW_EVIDENCE],
        write_scopes=[Collection.EVENTS],
        department=None,
    ),
    dict(
        agent_name="ledger", version="1.0.0",
        input_schema="IncidentEvent", output_schema="Timeline",
        read_scopes=[Collection.EVENTS, Collection.TIMELINE],
        write_scopes=[Collection.TIMELINE, Collection.EVENTS],
        department=None,
    ),
    dict(
        agent_name="diagnosis", version="1.0.0",
        input_schema="Timeline", output_schema="Hypothesis",
        # CHANGE_EVENTS: "what shipped just before this broke?" - the
        # correlation signal inbound CI/CD connectors feed (see
        # connectors/ and diagnosis._recent_changes).
        read_scopes=[
            Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.MEMORY,
            Collection.CHANGE_EVENTS,
        ],
        # MEMORY write is for Diagnosis's own incident_signature record
        # (agents/diagnosis/diagnosis.py) - previously read-only, so R6's
        # "learns across incidents" had nowhere to write the thing a
        # later incident's Diagnosis run would need to read.
        write_scopes=[Collection.HYPOTHESES, Collection.MEMORY],
        department=None,
    ),
    dict(
        agent_name="classifier", version="1.0.0",
        input_schema="Timeline", output_schema="Classification",
        # INCIDENTS read+write is for the severity/services_affected
        # backfill in agents/classifier/classifier.py: Classification is
        # where those values first become known, and the Incident record
        # the dashboard lists is where they have to land to be visible.
        # Read is required alongside write because the backfill is a
        # transactional read-modify-write (it must not clobber `status`,
        # owned by the incident lifecycle) - see scope_store.
        # update_in_transaction, which authorizes both for exactly this reason.
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.INCIDENTS],
        write_scopes=[Collection.CLASSIFICATION, Collection.INCIDENTS],
        department=None,
    ),
    dict(
        agent_name="watcher", version="1.0.0",
        input_schema="Signal", output_schema="UpstreamSignalMatched",
        read_scopes=[Collection.SIGNALS, Collection.INCIDENTS, Collection.SERVICES],
        write_scopes=[Collection.SIGNALS],
        department=None,
    ),
    dict(
        agent_name="postmortem", version="1.0.0",
        input_schema="Timeline", output_schema="PostmortemDraft",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.HYPOTHESES],
        write_scopes=[Collection.DRAFTS],
        department="engineering",
    ),
    dict(
        agent_name="comms", version="1.0.0",
        input_schema="Timeline", output_schema="StatusUpdateDraft",
        read_scopes=[Collection.TIMELINE],
        write_scopes=[Collection.DRAFTS],
        department="support",
    ),
    dict(
        agent_name="compliance", version="1.0.0",
        input_schema="Classification", output_schema="GdprAssessmentDraft",
        read_scopes=[Collection.TIMELINE, Collection.CLASSIFICATION],
        write_scopes=[Collection.DRAFTS, Collection.CLOCKS],
        department="legal",
    ),
    dict(
        agent_name="exposure", version="1.0.0",
        input_schema="Classification", output_schema="SlaExposureDraft",
        read_scopes=[Collection.CLASSIFICATION, Collection.CUSTOMERS],
        write_scopes=[Collection.DRAFTS],
        department="finance",
    ),
    dict(
        agent_name="ingest-api", version="1.0.0",
        input_schema="HTTP multipart (alert JSON | text | image) or arbitrary webhook JSON",
        output_schema="RawEvidence | ChangeEvent",
        # CONNECTORS read is for listing a tenant's connectors; the
        # webhook receiver itself resolves one by id through the
        # unauthenticated find_connector path (see scope_store's connector
        # section for why that indirection is unavoidable).
        read_scopes=[Collection.CONNECTORS],
        write_scopes=[
            Collection.INCIDENTS, Collection.RAW_EVIDENCE,
            Collection.CHANGE_EVENTS, Collection.CONNECTORS,
        ],
        department=None,
    ),
    dict(
        agent_name="console", version="1.0.0",
        input_schema="(none - read-only UI)", output_schema="(none - read-only UI)",
        read_scopes=[
            Collection.INCIDENTS, Collection.TIMELINE, Collection.HYPOTHESES,
            Collection.CLASSIFICATION, Collection.DRAFTS, Collection.CLOCKS,
            Collection.AUDIT, Collection.SIGNALS, Collection.RUNS,
        ],
        write_scopes=[],
        department=None,
    ),
]


def _registry_entry_exists(agent_name: str, version: str) -> bool:
    """Pre-write existence check, for the summary print only. Reaches
    directly into scope_store's client/constant instead of going through
    registry.resolve(): before platform-admin's own entry exists, no claim
    can pass _authorize() to read the registry at all - that chicken-and-
    egg is exactly why bootstrap_registry_write exists, so this one check
    can't use the authenticated path the way every other entry's check
    below does."""
    doc = (
        scope_store._client()
        .collection(scope_store._REGISTRY_ROOT)
        .document(agent_name)
        .collection("versions")
        .document(version)
        .get()
    )
    return doc.exists


def main() -> None:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        print(
            "GOOGLE_CLOUD_PROJECT is not set; relying on `gcloud config` or "
            "Application Default Credentials to resolve a project (see "
            "google-cloud-firestore's default client resolution). Set "
            "GOOGLE_CLOUD_PROJECT explicitly if that's not what you want."
        )

    print(f"demo org: {DEMO_ORG_ID}\n")

    # 1. Platform-admin: the one bootstrap-path write.
    admin_existed = _registry_entry_exists(_PLATFORM_ADMIN["agent_name"], _PLATFORM_ADMIN["version"])
    admin_record = AgentVersionRecord(**_PLATFORM_ADMIN)
    scope_store.bootstrap_registry_write(
        admin_record.agent_name, admin_record.version, admin_record.model_dump(mode="json"),
    )
    _print_entry(admin_record, existed=admin_existed, via="bootstrap")

    # 2. Everyone else: minted admin claim, real authenticated publish path.
    admin_claim = scope_store.sign_claim(
        org_id=DEMO_ORG_ID,
        agent_name=_PLATFORM_ADMIN["agent_name"],
        agent_version=_PLATFORM_ADMIN["version"],
        run_id=new_id("run"),
    )

    for spec in _FLEET:
        record = AgentVersionRecord(**spec)
        existed = registry.resolve(admin_claim, record.agent_name, version=record.version) is not None
        registry.publish(admin_claim, record)
        _print_entry(record, existed=existed, via="registry.publish")

    print(f"\ndone: {1 + len(_FLEET)} registry entries ensured ({admin_record.agent_name} + {len(_FLEET)} fleet agents).")


def _print_entry(record: AgentVersionRecord, *, existed: bool, via: str) -> None:
    verb = "already existed, overwritten" if existed else "created"
    reads = [c.value for c in record.read_scopes] or "(none)"
    writes = [c.value for c in record.write_scopes] or "(none)"
    dept = record.department or "-"
    print(
        f"  [{verb:>24}] {record.agent_name}@{record.version} via {via} "
        f"| dept={dept} | read={reads} | write={writes}"
    )


if __name__ == "__main__":
    main()
