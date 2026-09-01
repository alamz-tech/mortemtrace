"""Compliance (Legal/DPO) fans out from two events (SPEC-postmortem.md
section 6): timeline.committed only proves the raw_evidence denial (see
comms.py's docstring for why that proof matters), and incident.classified
does the real GDPR Article 33 work once Classifier has flagged whether
customer data was touched. These tests cover both branches, with the
72-hour clock math and the "no artifacts when data wasn't touched" rule
as the most important assertions.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from agents.departments.compliance import compliance
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
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="compliance", agent_version="1.0.0", run_id=run_id)


def _envelope_timeline_committed(run_id: str = "run_1") -> Envelope:
    origin = scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id)
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=INCIDENT_ID, claim=origin,
        event_type="timeline.committed",
        payload={"run_id": run_id, "org_id": TEST_ORG, "incident_id": INCIDENT_ID, "entry_count": 1},
    )


def _envelope_incident_classified(run_id: str = "run_2", data_touched: bool = True) -> Envelope:
    origin = scope_store.sign_claim(org_id=TEST_ORG, agent_name="classifier", agent_version="1.0.0", run_id=run_id)
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=INCIDENT_ID, claim=origin,
        event_type="incident.classified",
        payload={"run_id": run_id, "org_id": TEST_ORG, "incident_id": INCIDENT_ID,
                  "severity": "sev2", "data_touched": data_touched},
    )


def _seed_compliance_agent(fake_db):
    seed_agent(
        fake_db, "compliance", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.CLASSIFICATION],
        write_scopes=[Collection.DRAFTS, Collection.CLOCKS],
        department="legal",
    )


def _seed_classification(fake_db, data_touched: bool):
    fake_db.seed(f"tenants/{TEST_ORG}/classification/{INCIDENT_ID}", {
        "incident_id": INCIDENT_ID, "org_id": TEST_ORG, "severity": "sev2",
        "services": ["checkout"], "downtime_windows": [],
        "data_touched": data_touched,
        "data_categories": ["email", "billing_address"] if data_touched else [],
        "classified_at": "2026-08-25T04:00:00+00:00",
    })


def _drafts(fake_db):
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "drafts")]


def _clocks(fake_db):
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "clocks")]


# --------------------------------------------------------------------------
# timeline.committed: the denial proof only, nothing drafted yet
# --------------------------------------------------------------------------

def test_compliance_claim_denied_reading_raw_evidence_directly(fake_db):
    """Not try_read - the real read(), which raises. Proves the denial is
    enforced by data/scope_store.py, independent of compliance.py's own
    use of try_read to survive it gracefully."""
    _seed_compliance_agent(fake_db)

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(_claim(), Collection.RAW_EVIDENCE, INCIDENT_ID)


def test_timeline_committed_attempts_denied_raw_evidence_read_and_drafts_nothing(fake_db):
    _seed_compliance_agent(fake_db)

    result = compliance.run(_claim(), _envelope_timeline_committed())

    assert result.status == "ok"
    assert _drafts(fake_db) == []
    assert _clocks(fake_db) == []
    audit_entries = [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "audit")]
    deny_entries = [e for e in audit_entries if e["verdict"] == "deny" and "raw_evidence" in e["path"]]
    assert len(deny_entries) == 1
    assert deny_entries[0]["actor_agent"] == "compliance"


# --------------------------------------------------------------------------
# incident.classified: the real work
# --------------------------------------------------------------------------

def test_data_touched_true_produces_gdpr_draft_and_72h_clock(fake_db, monkeypatch):
    _seed_compliance_agent(fake_db)
    _seed_classification(fake_db, data_touched=True)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "Email addresses and billing addresses for affected customers appeared in application logs.",
    }))

    result = compliance.run(_claim(), _envelope_incident_classified(data_touched=True))

    assert result.status == "ok"

    drafts = _drafts(fake_db)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft["department"] == "legal"
    assert draft["kind"] == "gdpr_assessment"
    assert draft["data_categories"] == ["email", "billing_address"]
    assert draft["source_refs"] == [f"classification:{INCIDENT_ID}"]
    # The Legal agent produces an assessment; it does not decide whether
    # to notify anyone (SPEC section 3, non-goals) - nothing in the draft
    # schema even has a field for that decision.
    assert "notify" not in draft

    clocks = _clocks(fake_db)
    assert len(clocks) == 1
    clock = clocks[0]
    assert clock["incident_id"] == INCIDENT_ID
    assert clock["status"] == "running"

    started = datetime.fromisoformat(clock["gdpr_started_at"])
    deadline = datetime.fromisoformat(clock["deadline_at"])
    assert deadline - started == timedelta(hours=72)

    draft_deadline = datetime.fromisoformat(draft["clock_deadline_at"])
    assert draft_deadline == deadline


def test_redelivery_of_the_same_run_does_not_duplicate_the_draft_or_reset_the_clock(fake_db, monkeypatch):
    """Regression, more consequential than a duplicate draft alone: the
    GDPR clock document is keyed by incident_id and was previously
    overwritten unconditionally on every incident.classified dispatch. A
    redelivery (timeline.committed's six-way fan-out can outrun Pub/Sub's
    ack deadline; Classifier republishing incident.classified on its own
    redelivery is the other path in) would silently push the 72-hour
    deadline forward to a later now(), not just add a second draft."""
    _seed_compliance_agent(fake_db)
    _seed_classification(fake_db, data_touched=True)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "Email addresses and billing addresses for affected customers appeared in application logs.",
    }))
    envelope = _envelope_incident_classified(data_touched=True)

    first = compliance.run(_claim(), envelope)
    first_deadline = _clocks(fake_db)[0]["deadline_at"]
    second = compliance.run(_claim(), envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    assert len(_drafts(fake_db)) == 1
    clocks = _clocks(fake_db)
    assert len(clocks) == 1
    assert clocks[0]["deadline_at"] == first_deadline


def test_data_touched_false_writes_no_artifacts(fake_db, monkeypatch):
    _seed_compliance_agent(fake_db)
    _seed_classification(fake_db, data_touched=False)
    stub_gateway(monkeypatch, text=json.dumps({"body": "should never be reached"}))

    result = compliance.run(_claim(), _envelope_incident_classified(data_touched=False))

    assert result.status == "ok"
    assert _drafts(fake_db) == []
    assert _clocks(fake_db) == []


def test_model_armor_block_on_classified_writes_no_draft_or_clock(fake_db, monkeypatch):
    _seed_compliance_agent(fake_db)
    _seed_classification(fake_db, data_touched=True)
    stub_gateway(monkeypatch, text="", blocked=True, block_reason="prompt injection detected")

    result = compliance.run(_claim(), _envelope_incident_classified(data_touched=True))

    assert result.status == "blocked"
    assert _drafts(fake_db) == []
    assert _clocks(fake_db) == []


def test_missing_classification_dead_letters(fake_db, monkeypatch):
    _seed_compliance_agent(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "x"}))

    result = compliance.run(_claim(), _envelope_incident_classified(data_touched=True))

    assert result.status == "dead_letter"
    assert _drafts(fake_db) == []
