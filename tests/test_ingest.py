"""Tests for api/ingest.py: R1/R2's entry point.

These prove ingest writes the right Firestore docs and calls publish
with the right topic/payload - not that Coordinator's dispatch chain
does the right thing downstream (that's tests/test_coordinator.py's
job). MORTEMTRACE_SYNC_DISPATCH is left unset for most of these so
_dispatch_evidence_received() takes the plain _publish() branch, which
is monkeypatched to a list-appending stub; one test flips the env var
and monkeypatches coordinator.route() itself to prove the flag wires
the pipeline in-process without needing a full registry-seeded chain.
"""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

import api.ingest as ingest_module
from agents.contracts import NextEvent, RunResult
from data.models import Collection
from tests.conftest import TEST_ORG, seed_agent


@pytest.fixture
def client(fake_db):
    seed_agent(
        fake_db, ingest_module.INGEST_AGENT_NAME, ingest_module.INGEST_AGENT_VERSION,
        read_scopes=[], write_scopes=[Collection.INCIDENTS, Collection.RAW_EVIDENCE],
    )
    return TestClient(ingest_module.app)


@pytest.fixture
def published(monkeypatch):
    calls: list[tuple[str, dict]] = []
    monkeypatch.setattr(ingest_module, "_publish", lambda topic, payload: calls.append((topic, payload)))
    return calls


def _raw_evidence_docs(fake_db) -> list[dict]:
    return [
        data for path, data in fake_db._docs.items()
        if path[:3] == ("tenants", TEST_ORG, Collection.RAW_EVIDENCE.value)
    ]


def test_healthz():
    resp = TestClient(ingest_module.app).get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_ingest_returns_run_id_and_incident_id_promptly(client, published):
    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "log", "payload": "some log line"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["run_id"].startswith("run_")
    assert body["incident_id"].startswith("inc_")


def test_ingest_creates_new_incident_when_absent(client, published, fake_db):
    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "alert", "payload": "{}"})

    incident_id = resp.json()["incident_id"]
    doc = fake_db._docs[("tenants", TEST_ORG, "incidents", incident_id)]
    assert doc["status"] == "open"
    assert doc["org_id"] == TEST_ORG
    assert doc["incident_id"] == incident_id


def test_ingest_reuses_existing_incident_id_without_creating_one(client, published, fake_db):
    resp = client.post("/ingest", data={
        "org_id": TEST_ORG, "kind": "slack", "payload": "restarting the pods",
        "incident_id": "inc_existing",
    })

    assert resp.status_code == 200
    assert resp.json()["incident_id"] == "inc_existing"
    assert ("tenants", TEST_ORG, "incidents", "inc_existing") not in fake_db._docs


def test_ingest_writes_raw_evidence_with_kind_and_payload(client, published, fake_db):
    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "log", "payload": "log body here"})
    incident_id = resp.json()["incident_id"]

    docs = _raw_evidence_docs(fake_db)
    assert len(docs) == 1
    assert docs[0]["kind"] == "log"
    assert docs[0]["payload"] == "log body here"
    assert docs[0]["incident_ref"] == incident_id
    assert docs[0]["org_id"] == TEST_ORG


def test_ingest_screenshot_upload_is_base64_encoded_into_payload(client, published, fake_db):
    resp = client.post(
        "/ingest",
        data={"org_id": TEST_ORG, "kind": "screenshot"},
        files={"file": ("dash.png", io.BytesIO(b"\x89PNG\r\nnot really a png but fine for a test"), "image/png")},
    )

    assert resp.status_code == 200
    docs = _raw_evidence_docs(fake_db)
    assert len(docs) == 1
    assert docs[0]["kind"] == "screenshot"
    assert docs[0]["payload"].startswith("data:image/png;base64,")


def test_ingest_publishes_evidence_received_with_correct_shape(client, published):
    resp = client.post("/ingest", data={
        "org_id": TEST_ORG, "kind": "alert", "payload": '{"x": 1}', "incident_id": "inc_1",
    })
    run_id = resp.json()["run_id"]

    assert len(published) == 1
    topic, payload = published[0]
    assert topic == "evidence.received"
    assert payload["run_id"] == run_id
    assert payload["org_id"] == TEST_ORG
    assert payload["incident_ref"] == "inc_1"
    assert payload["kind"] == "alert"
    assert "raw_evidence_id" in payload
    assert "received_at" in payload


def test_ingest_rejects_invalid_kind_with_422(client, published):
    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "carrier-pigeon", "payload": "x"})

    assert resp.status_code == 422


def test_ingest_rejects_missing_org_id_with_422(client, published):
    resp = client.post("/ingest", data={"kind": "log", "payload": "x"})

    assert resp.status_code == 422


def test_sync_dispatch_flag_calls_coordinator_route_in_process(client, monkeypatch):
    """Proves the one-line env var flip: with MORTEMTRACE_SYNC_DISPATCH=1,
    ingest calls coordinator.route() directly instead of _publish(). We
    stub route() itself rather than exercising a real dispatch chain -
    Coordinator's own behavior is covered by tests/test_coordinator.py."""
    monkeypatch.setenv("MORTEMTRACE_SYNC_DISPATCH", "1")
    calls = []
    monkeypatch.setattr(
        ingest_module.coordinator, "route",
        lambda event_type, envelope, *, publish: calls.append((event_type, envelope)),
    )

    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "log", "payload": "x"})

    assert resp.status_code == 200
    assert len(calls) == 1
    event_type, envelope = calls[0]
    assert event_type == "evidence.received"
    assert envelope.run_id == resp.json()["run_id"]
    assert envelope.org_id == TEST_ORG
    assert envelope.incident_id == resp.json()["incident_id"]


def test_sync_dispatch_cascades_through_multiple_hops(client, monkeypatch, clean_coordinator, fake_db):
    """The gap this closes: _publish() is the exact `publish=` callback
    Coordinator.route() invokes for *every* worker's next_events, at
    every hop - not just the one ingest calls directly. Before this fix,
    only evidence.received -> Intake ran in-process under
    MORTEMTRACE_SYNC_DISPATCH=1; evidence.staged and everything after it
    silently fell through to a real Pub/Sub publish (dropped, since no
    subscriber is deployed), so "the whole pipeline runs in-process"
    (README, this module's docstring) was true for exactly one hop. This
    test seeds a fake intake -> ledger chain and proves both actually
    run within a single request, with no real Pub/Sub involved."""
    monkeypatch.setenv("MORTEMTRACE_SYNC_DISPATCH", "1")
    # Coordinator/Guardian need their own registry entries too - dispatch()
    # mints claims for both on every call (RUNS bookkeeping, ALERTS
    # escalation), same requirement test_coordinator.py's tests have.
    seed_agent(fake_db, "coordinator", "1.0.0",
               read_scopes=[Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
               write_scopes=[Collection.RUNS, Collection.QUARANTINE])
    seed_agent(fake_db, "guardian", "1.0.0", read_scopes=[], write_scopes=[Collection.ALERTS])
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[])
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[], write_scopes=[])
    invoked = []

    def fake_intake(claim, envelope):
        invoked.append(("intake", envelope.event_type))
        return RunResult(status="ok", next_events=[
            NextEvent(topic="evidence.staged", payload={
                "run_id": envelope.run_id, "org_id": envelope.org_id,
                "incident_ref": envelope.incident_id, "event_id": "evt_fake", "confidence": 0.9,
            })
        ])

    def fake_ledger(claim, envelope):
        invoked.append(("ledger", envelope.event_type))
        return RunResult(status="ok")

    clean_coordinator.register_worker("intake", fake_intake)
    clean_coordinator.register_worker("ledger", fake_ledger)

    resp = client.post("/ingest", data={"org_id": TEST_ORG, "kind": "log", "payload": "x"})

    assert resp.status_code == 200
    assert invoked == [
        ("intake", "evidence.received"),
        ("ledger", "evidence.staged"),
    ]


def test_watcher_sweep_endpoint_correlates_real_seed_data(fake_db, clean_coordinator, monkeypatch):
    """End-to-end proof for the endpoint Cloud Scheduler actually hits
    (infra/schedule.sh) and the demo operator presses live (SPEC section
    10, beat 5): real seed data, the real Watcher worker registered, no
    mocking of the correlation logic itself - only Diagnosis (the next
    hop after a match) is stubbed, since this test is about proving the
    sweep endpoint reaches Watcher and Watcher's real match fires, not
    about Diagnosis's own behavior."""
    from agents.watcher.watcher import run as watcher_run
    from agents.contracts import RunResult
    from seed.generate import generate

    generate(TEST_ORG)
    seed_agent(fake_db, "coordinator", "1.0.0",
               read_scopes=[Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
               write_scopes=[Collection.RUNS, Collection.QUARANTINE])
    seed_agent(fake_db, "guardian", "1.0.0", read_scopes=[], write_scopes=[Collection.ALERTS])
    seed_agent(fake_db, "watcher", "1.0.0",
               read_scopes=[Collection.SIGNALS, Collection.INCIDENTS, Collection.SERVICES],
               write_scopes=[Collection.SIGNALS])
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[])
    clean_coordinator.register_worker("watcher", watcher_run)
    clean_coordinator.register_worker("diagnosis", lambda claim, envelope: RunResult(status="ok"))
    monkeypatch.setenv("MORTEMTRACE_DEMO_ORG", TEST_ORG)

    resp = TestClient(ingest_module.app).post("/watcher/sweep", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert "3 signal(s) polled" in body["detail"]
    assert "1 incident(s) correlated" in body["detail"]
