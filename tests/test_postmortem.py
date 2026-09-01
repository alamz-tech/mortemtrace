"""Postmortem (Engineering) is the broad-access department - SPEC section
6's "no scope tricks" row. These tests exercise its happy path (a real
hypothesis and timeline present, source_refs non-empty) and the Model
Armor blocked path every departmental agent must honor.
"""
from __future__ import annotations

import json

from agents.departments.postmortem import postmortem
from data import scope_store
from data.models import Collection, Envelope, OrgClaim
from tests.conftest import TEST_ORG, seed_agent, stub_gateway

INCIDENT_ID = "inc_1"


def _claim(run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="postmortem", agent_version="1.0.0", run_id=run_id)


def _envelope(run_id: str = "run_1") -> Envelope:
    origin = scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id)
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=INCIDENT_ID, claim=origin,
        event_type="timeline.committed",
        payload={"run_id": run_id, "org_id": TEST_ORG, "incident_id": INCIDENT_ID, "entry_count": 1},
    )


def _seed_postmortem_agent(fake_db):
    seed_agent(
        fake_db, "postmortem", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.HYPOTHESES],
        write_scopes=[Collection.DRAFTS],
        department="engineering",
    )


def _seed_timeline(fake_db):
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{INCIDENT_ID}", {
        "incident_id": INCIDENT_ID, "org_id": TEST_ORG,
        "entries": [
            {"ts": "2026-08-25T03:14:00+00:00", "actor": "ledger", "action": "pods restarted",
             "evidence": "restart command observed in alert payload", "source_event_ids": ["evt_1"]},
            {"ts": "2026-08-25T03:20:00+00:00", "actor": "on-call", "action": "confirmed recovery",
             "evidence": "dashboard back to baseline", "source_event_ids": ["evt_2"]},
        ],
        "downtime_windows": [],
        "last_updated": "2026-08-25T03:20:00+00:00",
    })


def _seed_hypothesis(fake_db):
    fake_db.seed(f"tenants/{TEST_ORG}/hypotheses/hyp_1", {
        "hypothesis_id": "hyp_1", "incident_ref": INCIDENT_ID, "org_id": TEST_ORG,
        "statement": "A bad deploy exhausted memory on the pod, triggering the OOM restart loop.",
        "confidence": 0.82, "source_event_ids": ["evt_1"], "prior_incident_refs": [],
    })


def _drafts(fake_db):
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "drafts")]


def test_happy_path_writes_postmortem_draft_with_nonempty_source_refs(fake_db, monkeypatch):
    _seed_postmortem_agent(fake_db)
    _seed_timeline(fake_db)
    _seed_hypothesis(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "At 03:14 UTC pods began restarting; root cause was a memory-exhausting deploy.",
        "runbook_proposal": "Add a memory ceiling alert before OOM triggers a restart loop.",
    }))

    result = postmortem.run(_claim(), _envelope())

    assert result.status == "ok"
    drafts = _drafts(fake_db)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft["department"] == "engineering"
    assert draft["kind"] == "postmortem"
    assert draft["runbook_proposal"] == "Add a memory ceiling alert before OOM triggers a restart loop."
    assert draft["source_refs"]  # non-empty, per DraftBase.source_refs min_length=1
    assert set(draft["source_refs"]) >= {"evt_1", "evt_2"}  # timeline entries
    assert "hyp_1" not in draft["source_refs"]  # hypothesis id itself isn't a source_event_id...
    # ...but the hypothesis's own cited event id is folded in:
    assert "evt_1" in draft["source_refs"]


def test_redelivery_of_the_same_run_does_not_write_a_second_draft(fake_db, monkeypatch):
    """Regression: timeline.committed's six-way departmental fan-out can
    outrun Pub/Sub's ack deadline and get redelivered
    (agents/coordinator/coordinator.py's _dispatch_concurrently docstring).
    A second dispatch with the SAME run_id/incident_id must not write a
    second, independent draft."""
    _seed_postmortem_agent(fake_db)
    _seed_timeline(fake_db)
    _seed_hypothesis(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({
        "body": "At 03:14 UTC pods began restarting; root cause was a memory-exhausting deploy.",
        "runbook_proposal": "Add a memory ceiling alert before OOM triggers a restart loop.",
    }))
    envelope = _envelope()

    first = postmortem.run(_claim(), envelope)
    second = postmortem.run(_claim(), envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    assert len(_drafts(fake_db)) == 1


def test_model_armor_block_returns_blocked_and_writes_nothing(fake_db, monkeypatch):
    _seed_postmortem_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text="", blocked=True, block_reason="prompt injection detected")

    result = postmortem.run(_claim(), _envelope())

    assert result.status == "blocked"
    assert result.detail == "prompt injection detected"
    assert _drafts(fake_db) == []


def test_no_committed_timeline_dead_letters(fake_db, monkeypatch):
    _seed_postmortem_agent(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "x", "runbook_proposal": "y"}))

    result = postmortem.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _drafts(fake_db) == []


def test_malformed_model_output_dead_letters_without_writing(fake_db, monkeypatch):
    _seed_postmortem_agent(fake_db)
    _seed_timeline(fake_db)
    stub_gateway(monkeypatch, text="not valid json")

    result = postmortem.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _drafts(fake_db) == []
