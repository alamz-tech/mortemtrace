"""Ledger is deterministic (no model call), so these tests exercise the
sort/merge/idempotency logic directly against the fake Firestore client -
no monkeypatching of gateway.agent_gateway needed here. Covers: starting
a fresh timeline vs reconciling into an existing one, chronological
ordering when evidence stages out of order, the missing-event dead-
letter path, and idempotency on a duplicate source_event_ids delivery
(Pub/Sub redelivery of the same evidence.staged event).
"""
from __future__ import annotations

from agents.ledger import ledger
from data import scope_store
from data.models import Collection, Envelope, OrgClaim
from tests.conftest import TEST_ORG, seed_agent


def _claim(run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id)


def _envelope(event_id: str = "evt_1", incident_ref: str = "inc_1", run_id: str = "run_1",
              confidence: float = 0.9) -> Envelope:
    claim = _claim(run_id)
    payload = {
        "run_id": run_id,
        "org_id": TEST_ORG,
        "incident_ref": incident_ref,
        "event_id": event_id,
        "confidence": confidence,
    }
    return Envelope(run_id=run_id, org_id=TEST_ORG, incident_id=incident_ref, claim=claim,
                     event_type="evidence.staged", payload=payload)


def _seed_event(fake_db, event_id: str = "evt_1", incident_ref: str = "inc_1",
                 action: str = "pod restarted", ts: str = "2026-08-25T03:14:00+00:00",
                 confidence: float = 0.9, status: str = "staged") -> None:
    fake_db.seed(f"tenants/{TEST_ORG}/events/{event_id}", {
        "event_id": event_id,
        "org_id": TEST_ORG,
        "incident_ref": incident_ref,
        "status": status,
        "confidence": confidence,
        "extracted": {"action": action},
        "ts": ts,
        "source_ref": "raw_1",
    })


def _seed_timeline(fake_db, incident_ref: str, entries: list[dict]) -> None:
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{incident_ref}", {
        "incident_id": incident_ref,
        "org_id": TEST_ORG,
        "entries": entries,
        "downtime_windows": [],
        "last_updated": "2026-08-25T03:00:00+00:00",
    })


def _seed_ledger_scopes(fake_db) -> None:
    seed_agent(fake_db, "ledger", "1.0.0",
               read_scopes=[Collection.EVENTS, Collection.TIMELINE],
               write_scopes=[Collection.TIMELINE, Collection.EVENTS])


# --------------------------------------------------------------------------
# Starting fresh vs reconciling into an existing timeline
# --------------------------------------------------------------------------

def test_ledger_starts_fresh_timeline_when_none_exists(fake_db):
    _seed_ledger_scopes(fake_db)
    _seed_event(fake_db)
    claim = _claim()
    envelope = _envelope()

    result = ledger.run(claim, envelope)

    assert result.status == "ok"
    timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_1")]
    assert timeline["incident_id"] == "inc_1"
    assert timeline["org_id"] == TEST_ORG
    assert len(timeline["entries"]) == 1
    entry = timeline["entries"][0]
    assert entry["source_event_ids"] == ["evt_1"]
    assert entry["action"] == "pod restarted"
    assert entry["actor"] == "system"

    committed_event = fake_db._docs[("tenants", TEST_ORG, "events", "evt_1")]
    assert committed_event["status"] == "committed"

    assert len(result.next_events) == 1
    next_event = result.next_events[0]
    assert next_event.topic == "timeline.committed"
    assert next_event.payload["entry_count"] == 1
    assert next_event.payload["incident_id"] == "inc_1"


def test_ledger_reconciles_into_existing_timeline(fake_db):
    _seed_ledger_scopes(fake_db)
    _seed_timeline(fake_db, "inc_1", [{
        "ts": "2026-08-25T03:00:00+00:00", "actor": "system", "action": "alert fired",
        "evidence": "alert fired (confidence 0.80, source event evt_0)",
        "source_event_ids": ["evt_0"],
    }])
    _seed_event(fake_db, event_id="evt_1", ts="2026-08-25T03:14:00+00:00", action="pod restarted")
    claim = _claim()
    envelope = _envelope(event_id="evt_1")

    result = ledger.run(claim, envelope)

    assert result.status == "ok"
    timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_1")]
    assert len(timeline["entries"]) == 2
    assert [e["source_event_ids"][0] for e in timeline["entries"]] == ["evt_0", "evt_1"]
    assert result.next_events[0].payload["entry_count"] == 2


def test_ledger_reconciles_out_of_order_evidence_by_ts(fake_db):
    """Evidence can stage out of chronological order (a pasted log
    arriving after a screenshot timestamped earlier); the committed
    timeline must still read chronologically - 'reconciles by recency'."""
    _seed_ledger_scopes(fake_db)
    _seed_timeline(fake_db, "inc_1", [{
        "ts": "2026-08-25T03:20:00+00:00", "actor": "system", "action": "recovery observed",
        "evidence": "recovery observed (confidence 0.80, source event evt_later)",
        "source_event_ids": ["evt_later"],
    }])
    _seed_event(fake_db, event_id="evt_1", ts="2026-08-25T03:14:00+00:00", action="pod restarted")
    claim = _claim()
    envelope = _envelope(event_id="evt_1")

    ledger.run(claim, envelope)

    timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_1")]
    assert [e["source_event_ids"][0] for e in timeline["entries"]] == ["evt_1", "evt_later"]


# --------------------------------------------------------------------------
# Missing staged event
# --------------------------------------------------------------------------

def test_ledger_event_not_found_dead_letters(fake_db):
    _seed_ledger_scopes(fake_db)
    claim = _claim()
    envelope = _envelope(event_id="does_not_exist")

    result = ledger.run(claim, envelope)

    assert result.status == "dead_letter"
    assert "staged event not found" in result.detail
    assert ("tenants", TEST_ORG, "timeline", "inc_1") not in fake_db._docs


# --------------------------------------------------------------------------
# Idempotency on duplicate source_event_ids
# --------------------------------------------------------------------------

def test_ledger_idempotent_on_duplicate_source_event_ids(fake_db):
    """Pub/Sub redelivery of the same evidence.staged event must not
    double-count the entry in the committed timeline (R9/failure
    tolerance: 'duplicate evidence submission... second write is a
    no-op', applied here at the entry-merge level, not just doc idempotency_key)."""
    _seed_ledger_scopes(fake_db)
    _seed_event(fake_db)
    claim = _claim()
    envelope = _envelope()

    first = ledger.run(claim, envelope)
    second = ledger.run(claim, envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_1")]
    assert len(timeline["entries"]) == 1
    assert second.next_events[0].payload["entry_count"] == 1


def test_ledger_second_incident_stays_untouched(fake_db):
    """Sanity check on tenancy/incident scoping within a single org:
    reconciling one incident's event must not touch another incident's
    timeline document."""
    _seed_ledger_scopes(fake_db)
    _seed_timeline(fake_db, "inc_other", [{
        "ts": "2026-08-25T02:00:00+00:00", "actor": "system", "action": "unrelated",
        "evidence": "unrelated (confidence 0.80, source event evt_other)",
        "source_event_ids": ["evt_other"],
    }])
    _seed_event(fake_db, event_id="evt_1", incident_ref="inc_1")
    claim = _claim()
    envelope = _envelope(event_id="evt_1", incident_ref="inc_1")

    ledger.run(claim, envelope)

    other_timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_other")]
    assert len(other_timeline["entries"]) == 1
    assert other_timeline["entries"][0]["source_event_ids"] == ["evt_other"]
