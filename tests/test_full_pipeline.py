"""The capstone integration test: one POST /ingest call, real registry
scopes, real Coordinator routing, all nine real worker modules (not
fakes) wired via agents.wiring, sync-dispatch cascading through every
hop - only the Gemini calls themselves are stubbed (canned per-agent
JSON, keyed by agent name), since a live call costs real money and
isn't necessary to prove the *pipeline* is wired correctly end to end.

This is R2's acceptance criterion made literal: "a postmortem draft, a
status update draft, and (if data-touching) a compliance assessment all
exist" after one trigger, with zero human input in between.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agents import wiring
from data.models import Collection
from gateway import agent_gateway
from tests.conftest import TEST_ORG, auth_header, seed_agent


@pytest.fixture(autouse=True)
def _enable_demo_scope_proofs(monkeypatch):
    """These cases assert the deliberate denied-read that produces the
    on-camera audit proof. It is off by default in production (it costs a
    registry lookup plus an audit write per run), so the tests that assert
    it must turn it on explicitly."""
    monkeypatch.setenv("MORTEMTRACE_DEMO_SCOPE_PROOFS", "1")


_CANNED = {
    "intake": '{"action": "checkout-api pods restarting under memory pressure", "confidence": 0.91}',
    "diagnosis": (
        '{"statement": "Memory pressure from a leaked connection pool caused repeated pod '
        'restarts", "confidence": 0.8, "source_entry_indices": [0], "prior_incident_refs": []}'
    ),
    "classifier": (
        '{"severity": "sev2", "services": ["checkout-api"], "downtime_windows": [], '
        '"data_touched": true, "data_categories": ["customer_pii"]}'
    ),
    "postmortem": '{"body": "Postmortem: checkout-api pods restarted under memory pressure.", '
                  '"runbook_proposal": "Add a memory-based autoscaling policy to checkout-api."}',
    "comms": '{"body": "We identified and resolved an issue affecting checkout. No action needed."}',
    "compliance": '{"body": "Customer PII exposure assessed as limited; DPO review recommended."}',
    "exposure": '{"body": "SLA exposure computed from classification and customer records."}',
}


class _FakeAgent:
    def __init__(self, name: str):
        self.name = name
        self.model = "fake-model"


def _fake_build_agent(*, name, run_id, org_id, instruction, tools=None, output_schema=None, model=None, **kw):
    return _FakeAgent(name), agent_gateway.InvocationOutcome()


def _fake_invoke(agent, prompt, *, run_id, org_id):
    return agent_gateway.InvokeResult(text=_CANNED.get(agent.name, "{}"), tokens_used=25, turns=1)


_FLEET_SCOPES = {
    "coordinator": ([Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
                     [Collection.RUNS, Collection.QUARANTINE]),
    "guardian": ([], [Collection.ALERTS]),
    "intake": ([Collection.RAW_EVIDENCE], [Collection.EVENTS]),
    "ledger": ([Collection.EVENTS, Collection.TIMELINE], [Collection.TIMELINE, Collection.EVENTS]),
    "diagnosis": ([Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.MEMORY], [Collection.HYPOTHESES]),
    "classifier": ([Collection.TIMELINE, Collection.RAW_EVIDENCE], [Collection.CLASSIFICATION]),
    "postmortem": ([Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.HYPOTHESES], [Collection.DRAFTS]),
    "comms": ([Collection.TIMELINE], [Collection.DRAFTS]),
    "compliance": ([Collection.TIMELINE, Collection.CLASSIFICATION], [Collection.DRAFTS, Collection.CLOCKS]),
    "exposure": ([Collection.CLASSIFICATION, Collection.CUSTOMERS], [Collection.DRAFTS]),
    "ingest-api": ([], [Collection.INCIDENTS, Collection.RAW_EVIDENCE]),
}


def test_one_ingest_call_produces_timeline_classification_and_all_four_drafts(
    fake_db, clean_coordinator, monkeypatch,
):
    for agent_name, (reads, writes) in _FLEET_SCOPES.items():
        seed_agent(fake_db, agent_name, "1.0.0", read_scopes=reads, write_scopes=writes)

    monkeypatch.setattr(agent_gateway, "build_agent", _fake_build_agent)
    monkeypatch.setattr(agent_gateway, "invoke", _fake_invoke)
    monkeypatch.setenv("MORTEMTRACE_SYNC_DISPATCH", "1")

    wiring._REGISTERED = False  # force re-registration against this test's clean_coordinator
    wiring.register_all()

    import api.ingest as ingest_module
    client = TestClient(ingest_module.app, headers=auth_header())

    resp = client.post("/ingest", data={
        "org_id": TEST_ORG, "kind": "log",
        "payload": "checkout-api: OOMKilled, pod restarted 4 times in 5 minutes",
    })

    assert resp.status_code == 200
    incident_id = resp.json()["incident_id"]

    timeline = fake_db._docs[("tenants", TEST_ORG, "timeline", incident_id)]
    assert len(timeline["entries"]) == 1
    assert timeline["entries"][0]["source_event_ids"], "timeline entry must carry a real source"

    classification = fake_db._docs[("tenants", TEST_ORG, "classification", incident_id)]
    assert classification["data_touched"] is True
    assert classification["severity"] == "sev2"

    clock = fake_db._docs[("tenants", TEST_ORG, "clocks", incident_id)]
    assert clock["status"] == "running"

    drafts = [
        d for path, d in fake_db._docs.items()
        if path[:3] == ("tenants", TEST_ORG, "drafts") and d.get("incident_ref") == incident_id
    ]
    drafts_by_department = {d["department"]: d for d in drafts}
    assert set(drafts_by_department) == {"engineering", "support", "legal", "finance"}
    for department, draft in drafts_by_department.items():
        assert draft["source_refs"], f"{department} draft has no source_refs"

    hypotheses = [
        d for path, d in fake_db._docs.items()
        if path[:3] == ("tenants", TEST_ORG, "hypotheses") and d.get("incident_ref") == incident_id
    ]
    assert len(hypotheses) == 1
    assert hypotheses[0]["source_event_ids"]

    # The actual P0 claim, not just an implementation detail: Comms really
    # was denied raw_evidence during this real run, and it's in the audit
    # trail - this is what the demo shows on camera (SPEC section 10, beat 2).
    audit_entries = [
        d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "audit")
    ]
    comms_denials = [
        e for e in audit_entries
        if e["actor_agent"] == "comms" and e["verdict"] == "deny" and e["path"].startswith("raw_evidence")
    ]
    assert comms_denials, "expected a real scope denial for comms reading raw_evidence"
