"""Classifier: data_touched is the field that triggers Compliance's GDPR
clock, so it gets the most scrutiny here - true when the timeline says
so, false by considered default, and never silently coerced when the
model's output is malformed or inconsistent.
gateway.agent_gateway.invoke is always monkeypatched - never call real
Gemini from this file.
"""
from __future__ import annotations

from data import scope_store
from data.models import Collection, Envelope, OrgClaim
from agents.classifier import classifier
from gateway import agent_gateway
from tests.conftest import TEST_ORG, seed_agent


def _claim(agent_name: str = "classifier", version: str = "1.0.0", run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name=agent_name, agent_version=version, run_id=run_id)


def _envelope(incident_id: str = "inc_1", run_id: str = "run_1") -> Envelope:
    publisher_claim = scope_store.sign_claim(
        org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id,
    )
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=incident_id, claim=publisher_claim,
        event_type="timeline.committed", payload={"incident_id": incident_id},
    )


def _seed_timeline(fake_db, incident_id: str = "inc_1", entries: list[dict] | None = None) -> None:
    if entries is None:
        entries = [
            {"ts": "2026-08-25T03:00:00Z", "actor": "alert", "action": "pods crash-looping",
             "evidence": "CrashLoopBackOff x12 on checkout-worker", "source_event_ids": ["evt_1"]},
        ]
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG, "entries": entries,
        "downtime_windows": [], "last_updated": "2026-08-25T03:10:00Z",
    })


def _seed_classifier_agent(fake_db) -> None:
    seed_agent(
        fake_db, "classifier", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE],
        write_scopes=[Collection.CLASSIFICATION],
    )


def _classification(fake_db, incident_id: str = "inc_1") -> dict | None:
    return fake_db._docs.get(("tenants", TEST_ORG, "classification", incident_id))


# --------------------------------------------------------------------------
# data_touched = false path
# --------------------------------------------------------------------------

def test_classifier_sets_severity_and_data_touched_false(fake_db, monkeypatch):
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"severity": "sev2", "services": ["checkout-worker"], "downtime_windows": [], '
                 '"data_touched": false, "data_categories": []}',
            tokens_used=70, turns=1,
        ),
    )

    result = classifier.run(_claim(), _envelope())

    assert result.status == "ok"
    written = _classification(fake_db)
    assert written["severity"] == "sev2"
    assert written["services"] == ["checkout-worker"]
    assert written["data_touched"] is False
    assert written["data_categories"] == []
    # incident.classified must carry the same verdict downstream to Compliance.
    assert len(result.next_events) == 1
    next_event = result.next_events[0]
    assert next_event.topic == "incident.classified"
    assert next_event.payload["incident_id"] == "inc_1"
    assert next_event.payload["severity"] == "sev2"
    assert next_event.payload["data_touched"] is False


# --------------------------------------------------------------------------
# data_touched = true path
# --------------------------------------------------------------------------

def test_classifier_sets_data_touched_true_with_categories(fake_db, monkeypatch):
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db, entries=[
        {"ts": "2026-08-25T03:00:00Z", "actor": "oncall", "action": "found exposed export bucket",
         "evidence": "customer PII export bucket was publicly readable for 40 minutes",
         "source_event_ids": ["evt_1"]},
    ])
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"severity": "sev1", "services": ["exports"], "downtime_windows": [], '
                 '"data_touched": true, "data_categories": ["customer_pii", "email"]}',
            tokens_used=95, turns=1,
        ),
    )

    result = classifier.run(_claim(), _envelope())

    assert result.status == "ok"
    written = _classification(fake_db)
    assert written["data_touched"] is True
    assert written["data_categories"] == ["customer_pii", "email"]
    assert result.next_events[0].payload["data_touched"] is True


def test_classifier_clears_categories_when_data_touched_false(fake_db, monkeypatch):
    """Belt-and-braces: an inconsistent model response (categories
    alongside data_touched=false) must never leave data_categories
    populated on a record marked as not data-touching."""
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"severity": "sev3", "services": [], "downtime_windows": [], '
                 '"data_touched": false, "data_categories": ["email"]}',
            tokens_used=70, turns=1,
        ),
    )

    result = classifier.run(_claim(), _envelope())

    assert result.status == "ok"
    written = _classification(fake_db)
    assert written["data_touched"] is False
    assert written["data_categories"] == []


# --------------------------------------------------------------------------
# data_touched must never be silently defaulted
# --------------------------------------------------------------------------

def test_classifier_missing_data_touched_dead_letters_not_silently_false(fake_db, monkeypatch):
    """ClassificationDraft.data_touched has no schema default (see
    classifier.py's module docstring): if the model omits the field
    entirely, that is schema drift and must dead-letter rather than
    quietly resolving to False."""
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"severity": "sev3", "services": [], "downtime_windows": []}',
            tokens_used=40, turns=1,
        ),
    )

    result = classifier.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _classification(fake_db) is None


# --------------------------------------------------------------------------
# No timeline yet
# --------------------------------------------------------------------------

def test_classifier_no_committed_timeline_dead_letters(fake_db):
    _seed_classifier_agent(fake_db)

    result = classifier.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _classification(fake_db) is None


# --------------------------------------------------------------------------
# Model Armor
# --------------------------------------------------------------------------

def test_classifier_model_armor_block_writes_nothing(fake_db, monkeypatch):
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.build_agent",
        lambda **kw: ("fake-agent", agent_gateway.InvocationOutcome(
            blocked=True, block_reason="Model Armor: injection pattern matched",
        )),
    )
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(text="", tokens_used=5, turns=1),
    )

    result = classifier.run(_claim(), _envelope())

    assert result.status == "blocked"
    assert "injection" in result.detail.lower()
    assert _classification(fake_db) is None
    assert result.next_events == []
