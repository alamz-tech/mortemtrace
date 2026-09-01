"""Classifier: data_touched is the field that triggers Compliance's GDPR
clock, so it gets the most scrutiny here - true when the timeline says
so, false by considered default, and never silently coerced when the
model's output is malformed or inconsistent.
gateway.agent_gateway.invoke is always monkeypatched - never call real
Gemini from this file.
"""
from __future__ import annotations

from agents.classifier import classifier
from data import scope_store
from data.models import Collection, Envelope, OrgClaim
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
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.INCIDENTS],
        write_scopes=[Collection.CLASSIFICATION, Collection.INCIDENTS],
    )


def _seed_incident(fake_db, incident_id: str = "inc_1") -> None:
    """An incident as api/ingest.py actually creates it: no severity and
    no services_affected, because at ingest time nothing has read the
    evidence yet."""
    fake_db.seed(f"tenants/{TEST_ORG}/incidents/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG,
        "opened_at": "2026-08-25T02:55:00Z", "resolved_at": None,
        "status": "open", "severity": None, "services_affected": [], "alert_source": None,
    })


def _incident(fake_db, incident_id: str = "inc_1") -> dict | None:
    return fake_db._docs.get(("tenants", TEST_ORG, "incidents", incident_id))


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


def test_redelivery_of_the_same_run_does_not_overwrite_or_republish(fake_db, monkeypatch):
    """Regression: timeline.committed's six-way departmental fan-out can
    outrun Pub/Sub's ack deadline and get redelivered
    (agents/coordinator/coordinator.py's _dispatch_concurrently docstring).
    Classification is keyed by incident_id, so a redelivery previously
    overwrote it unconditionally - and since the model call isn't pinned
    to temperature 0, a redelivery could silently flip data_touched
    (and, downstream, whether Compliance's GDPR clock starts). It also
    always re-published incident.classified, re-triggering Compliance's
    real work a second time."""
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    calls = []

    def _fake_invoke(agent, prompt, **kw):
        calls.append(1)
        # A different verdict on the second (duplicate) call proves the
        # guard fires BEFORE any write, not that the model happened to
        # repeat itself.
        data_touched = len(calls) > 1
        return agent_gateway.InvokeResult(
            text=f'{{"severity": "sev2", "services": ["checkout-worker"], "downtime_windows": [], '
                 f'"data_touched": {str(data_touched).lower()}, "data_categories": []}}',
            tokens_used=70, turns=1,
        )

    monkeypatch.setattr("gateway.agent_gateway.invoke", _fake_invoke)
    envelope = _envelope()

    first = classifier.run(_claim(), envelope)
    second = classifier.run(_claim(), envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    assert len(first.next_events) == 1
    assert second.next_events == []
    written = _classification(fake_db)
    assert written["data_touched"] is False  # the FIRST call's verdict, untouched by the second


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


# --------------------------------------------------------------------------
# Incident enrichment
#
# Regression: Classification is where severity and affected services
# first become known, but nothing carried them back to the Incident
# record the dashboard's incident table actually renders - so every real
# incident showed "—" in both columns permanently, while seeded demo
# incidents showed values and made it look like a data problem rather
# than a missing write.
# --------------------------------------------------------------------------

def _stub_classification(monkeypatch, severity: str = "sev1", services: list[str] | None = None) -> None:
    import json as _json
    payload = {
        "severity": severity, "services": services if services is not None else ["checkout-api"],
        "downtime_windows": [], "data_touched": False, "data_categories": [],
    }
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text=_json.dumps(payload), tokens_used=70, turns=1,
        ),
    )


def test_classifier_backfills_severity_and_services_onto_the_incident(fake_db, monkeypatch):
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    _seed_incident(fake_db)
    _stub_classification(monkeypatch, severity="sev1", services=["checkout-api", "orders-db"])

    result = classifier.run(_claim(), _envelope())

    assert result.status == "ok"
    incident = _incident(fake_db)
    assert incident["severity"] == "sev1"
    assert incident["services_affected"] == ["checkout-api", "orders-db"]


def test_backfill_preserves_fields_it_does_not_own(fake_db, monkeypatch):
    """status and opened_at belong to the incident lifecycle and to
    ingest respectively. A full-document overwrite here would race
    Watcher's own status transitions and could silently revert one."""
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    _seed_incident(fake_db)
    fake_db._docs[("tenants", TEST_ORG, "incidents", "inc_1")]["status"] = "monitoring"
    _stub_classification(monkeypatch)

    classifier.run(_claim(), _envelope())

    incident = _incident(fake_db)
    assert incident["status"] == "monitoring"          # not clobbered
    assert incident["opened_at"] == "2026-08-25T02:55:00Z"
    assert incident["severity"] == "sev1"              # still enriched


def test_classification_still_succeeds_when_the_incident_is_missing(fake_db, monkeypatch):
    """The Classification record is the source of truth; the incident
    copy is a convenience denormalisation. A missing incident document
    must not dead-letter a run whose real work already succeeded."""
    _seed_classifier_agent(fake_db)
    _seed_timeline(fake_db)
    # deliberately no _seed_incident
    _stub_classification(monkeypatch)

    result = classifier.run(_claim(), _envelope())

    assert result.status == "ok"
    assert _classification(fake_db)["severity"] == "sev1"
