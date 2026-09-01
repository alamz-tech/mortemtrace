"""Comms (Support) is the sharpest version of the scope-boundary proof
(SPEC-postmortem.md section 6; ARCHITECTURE.md section 2). The point of
this test file is not "the draft body happens to lack log content" - a
prompt instruction could produce that by accident. The point is that the
denial is structural: Comms' registry entry does not grant raw_evidence
read scope, so data/scope_store.py refuses the read regardless of what
comms.py or its prompt asks for.
"""
from __future__ import annotations

import json

import pytest

from agents.departments.comms import comms
from data import scope_store
from data.models import Collection, Envelope, OrgClaim
from tests.conftest import TEST_ORG, seed_agent, stub_gateway


@pytest.fixture(autouse=True)
def _enable_demo_scope_proofs(monkeypatch):
    """These cases assert the deliberate denied-read that produces the
    on-camera audit proof. It is off by default in production (it costs a
    registry lookup plus an audit write per run), so the tests that assert
    it must turn it on explicitly."""
    monkeypatch.setenv("MORTEMTRACE_DEMO_SCOPE_PROOFS", "1")


INCIDENT_ID = "inc_1"


def _claim(run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="comms", agent_version="1.0.0", run_id=run_id)


def _envelope(run_id: str = "run_1") -> Envelope:
    origin = scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id)
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=INCIDENT_ID, claim=origin,
        event_type="timeline.committed",
        payload={"run_id": run_id, "org_id": TEST_ORG, "incident_id": INCIDENT_ID, "entry_count": 1},
    )


def _seed_comms_agent(fake_db):
    seed_agent(
        fake_db, "comms", "1.0.0",
        read_scopes=[Collection.TIMELINE],
        write_scopes=[Collection.DRAFTS],
        department="support",
    )


def _seed_timeline(fake_db):
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{INCIDENT_ID}", {
        "incident_id": INCIDENT_ID, "org_id": TEST_ORG,
        "entries": [
            {"ts": "2026-08-25T03:14:00+00:00", "actor": "ledger", "action": "checkout latency spiked",
             "evidence": "p99 latency alert fired", "source_event_ids": ["evt_1"]},
            {"ts": "2026-08-25T03:40:00+00:00", "actor": "ledger", "action": "latency recovered",
             "evidence": "p99 back to baseline", "source_event_ids": ["evt_2"]},
        ],
        "downtime_windows": [],
        "last_updated": "2026-08-25T03:40:00+00:00",
    })


def _drafts(fake_db):
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "drafts")]


# --------------------------------------------------------------------------
# The boundary itself - the most important assertions in this file
# --------------------------------------------------------------------------

def test_comms_registry_scope_does_not_include_raw_evidence(fake_db):
    """Static half of the proof: read back exactly what comms.run() will
    be evaluated against - the registry entry itself - rather than
    registry.resolve(), which would need its own privileged (REGISTRY
    read-scoped) claim unrelated to what this file is testing."""
    _seed_comms_agent(fake_db)

    registry_doc = fake_db._docs[("registry", "comms", "versions", "1.0.0")]

    assert registry_doc["read_scopes"] == [Collection.TIMELINE.value]
    assert Collection.RAW_EVIDENCE.value not in registry_doc["read_scopes"]


def test_comms_claim_denied_reading_raw_evidence_directly(fake_db):
    """Not try_read - the real read(), which raises. This proves the
    denial is enforced by data/scope_store.py itself, independent of
    comms.py's own use of try_read to survive it gracefully."""
    _seed_comms_agent(fake_db)

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(_claim(), Collection.RAW_EVIDENCE, INCIDENT_ID)

    entries = [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "audit")]
    assert any(e["verdict"] == "deny" and "raw_evidence" in e["path"] for e in entries)


def test_run_attempts_raw_evidence_read_and_it_is_audited_as_denied(fake_db, monkeypatch):
    """End to end through comms.run(): the attempted read happens as a
    side effect of a normal dispatch (not just when a test calls
    scope_store.read directly), and it leaves a deny entry in /audit -
    the entry the demo shows on camera (SPEC section 10, beat 2)."""
    _seed_comms_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "We experienced elevated checkout latency; service has recovered."}))

    result = comms.run(_claim(), _envelope())

    assert result.status == "ok"
    audit_entries = [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "audit")]
    deny_entries = [e for e in audit_entries if e["verdict"] == "deny" and "raw_evidence" in e["path"]]
    assert len(deny_entries) == 1
    assert deny_entries[0]["actor_agent"] == "comms"


# --------------------------------------------------------------------------
# Draft quality (secondary to the boundary, but still exercised)
# --------------------------------------------------------------------------

def test_happy_path_writes_status_update_draft_from_timeline_only(fake_db, monkeypatch):
    _seed_comms_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "We experienced elevated checkout latency; service has recovered.",
    }))

    result = comms.run(_claim(), _envelope())

    assert result.status == "ok"
    drafts = _drafts(fake_db)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft["department"] == "support"
    assert draft["kind"] == "status_update"
    assert draft["source_refs"] == ["evt_1", "evt_2"]  # timeline's own source_event_ids, nothing else


def test_redelivery_of_the_same_run_does_not_write_a_second_draft(fake_db, monkeypatch):
    """Regression: timeline.committed's six-way departmental fan-out can
    outrun Pub/Sub's ack deadline and get redelivered
    (agents/coordinator/coordinator.py's _dispatch_concurrently docstring).
    A second dispatch with the SAME run_id/incident_id must not write a
    second, independent draft."""
    _seed_comms_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "We experienced elevated checkout latency; service has recovered.",
    }))
    envelope = _envelope()

    first = comms.run(_claim(), envelope)
    second = comms.run(_claim(), envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    assert len(_drafts(fake_db)) == 1


def test_model_armor_block_returns_blocked_and_writes_nothing(fake_db, monkeypatch):
    _seed_comms_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text="", blocked=True, block_reason="prompt injection detected")

    result = comms.run(_claim(), _envelope())

    assert result.status == "blocked"
    assert _drafts(fake_db) == []


def test_no_committed_timeline_dead_letters(fake_db, monkeypatch):
    _seed_comms_agent(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "x"}))

    result = comms.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _drafts(fake_db) == []
