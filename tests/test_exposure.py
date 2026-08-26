"""Exposure (Finance) explicitly does NOT get timeline or raw_evidence
scope (SPEC-postmortem.md section 6; ARCHITECTURE.md section 2's
diagram: "windows + terms only, timeline detail DENIED"). These tests
prove that boundary is real, and that the customer-matching intersection
(services_subscribed vs. classification.services) actually excludes an
unrelated customer rather than merely happening to omit them.
"""
from __future__ import annotations

import json

import pytest

from data import scope_store
from data.models import Collection, Envelope, OrgClaim
from agents.departments.exposure import exposure
from tests.conftest import TEST_ORG, seed_agent, stub_gateway

INCIDENT_ID = "inc_1"


def _claim(run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="exposure", agent_version="1.0.0", run_id=run_id)


def _envelope(run_id: str = "run_1") -> Envelope:
    origin = scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id)
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=INCIDENT_ID, claim=origin,
        event_type="timeline.committed",
        payload={"run_id": run_id, "org_id": TEST_ORG, "incident_id": INCIDENT_ID, "entry_count": 1},
    )


def _seed_exposure_agent(fake_db):
    seed_agent(
        fake_db, "exposure", "1.0.0",
        read_scopes=[Collection.CLASSIFICATION, Collection.CUSTOMERS],
        write_scopes=[Collection.DRAFTS],
        department="finance",
    )


def _seed_classification(fake_db, services=("checkout",)):
    fake_db.seed(f"tenants/{TEST_ORG}/classification/{INCIDENT_ID}", {
        "incident_id": INCIDENT_ID, "org_id": TEST_ORG, "severity": "sev2",
        "services": list(services),
        "downtime_windows": [
            {"start": "2026-08-25T03:00:00+00:00", "end": "2026-08-25T05:00:00+00:00",
             "services": list(services)},
        ],
        "data_touched": False, "data_categories": [],
        "classified_at": "2026-08-25T05:00:00+00:00",
    })


def _seed_customers(fake_db):
    fake_db.seed(f"tenants/{TEST_ORG}/customers/cust_affected", {
        "customer_id": "cust_affected", "org_id": TEST_ORG, "name": "Affected Co",
        "sla_terms": {"uptime_target": 0.999, "credit_rate": 100.0},
        "data_region": "eu", "services_subscribed": ["checkout"],
    })
    fake_db.seed(f"tenants/{TEST_ORG}/customers/cust_unrelated", {
        "customer_id": "cust_unrelated", "org_id": TEST_ORG, "name": "Unrelated Co",
        "sla_terms": {"uptime_target": 0.999, "credit_rate": 100.0},
        "data_region": "eu", "services_subscribed": ["billing"],
    })


def _drafts(fake_db):
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "drafts")]


# --------------------------------------------------------------------------
# The boundary itself
# --------------------------------------------------------------------------

def test_exposure_registry_scope_does_not_include_timeline(fake_db):
    """Static half of the proof: read back exactly what exposure.run()
    will be evaluated against - the registry entry itself."""
    _seed_exposure_agent(fake_db)

    registry_doc = fake_db._docs[("registry", "exposure", "versions", "1.0.0")]

    assert registry_doc["read_scopes"] == [Collection.CLASSIFICATION.value, Collection.CUSTOMERS.value]
    assert Collection.TIMELINE.value not in registry_doc["read_scopes"]


def test_exposure_claim_denied_reading_timeline_directly(fake_db):
    """Not try_read - the real read(), which raises. Proves the denial is
    enforced by data/scope_store.py, independent of exposure.py's own use
    of try_read to survive it gracefully."""
    _seed_exposure_agent(fake_db)

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(_claim(), Collection.TIMELINE, INCIDENT_ID)


def test_run_attempts_denied_timeline_read_and_it_is_audited(fake_db, monkeypatch):
    _seed_exposure_agent(fake_db)
    _seed_classification(fake_db)
    _seed_customers(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "Exposure computed from downtime windows and SLA terms."}))

    result = exposure.run(_claim(), _envelope())

    assert result.status == "ok"
    audit_entries = [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "audit")]
    deny_entries = [e for e in audit_entries if e["verdict"] == "deny" and "timeline" in e["path"]]
    assert len(deny_entries) == 1
    assert deny_entries[0]["actor_agent"] == "exposure"


# --------------------------------------------------------------------------
# Customer matching and the exposure figure
# --------------------------------------------------------------------------

def test_unrelated_customer_excluded_from_exposure(fake_db, monkeypatch):
    _seed_exposure_agent(fake_db)
    _seed_classification(fake_db)
    _seed_customers(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "Exposure computed from downtime windows and SLA terms."}))

    result = exposure.run(_claim(), _envelope())

    assert result.status == "ok"
    drafts = _drafts(fake_db)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft["department"] == "finance"
    assert draft["kind"] == "sla_exposure"
    assert "cust_affected" in draft["exposure_by_customer"]
    assert "cust_unrelated" not in draft["exposure_by_customer"]
    assert draft["exposure_by_customer"]["cust_affected"] > 0.0
    assert draft["source_refs"] == [f"classification:{INCIDENT_ID}"]


def test_exposure_figure_traceable_to_downtime_and_sla_terms(fake_db, monkeypatch):
    """2 hours of downtime against a 0.999 uptime target over an
    approximate 720-hour month allows 0.72 hours - the remaining 1.28
    breach hours at a $100/hour credit_rate is $128.00. Pinning the
    number (not just its sign) proves it is traceable to its inputs
    rather than incidentally positive."""
    _seed_exposure_agent(fake_db)
    _seed_classification(fake_db)
    _seed_customers(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "x"}))

    result = exposure.run(_claim(), _envelope())

    assert result.status == "ok"
    draft = _drafts(fake_db)[0]
    assert draft["exposure_by_customer"]["cust_affected"] == 128.0


def test_model_armor_block_returns_blocked_and_writes_nothing(fake_db, monkeypatch):
    _seed_exposure_agent(fake_db)
    _seed_classification(fake_db)
    _seed_customers(fake_db)
    stub_gateway(monkeypatch, text="", blocked=True, block_reason="prompt injection detected")

    result = exposure.run(_claim(), _envelope())

    assert result.status == "blocked"
    assert _drafts(fake_db) == []


def test_missing_classification_dead_letters(fake_db, monkeypatch):
    _seed_exposure_agent(fake_db)
    stub_gateway(monkeypatch, text=json.dumps({"body": "x"}))

    result = exposure.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _drafts(fake_db) == []
