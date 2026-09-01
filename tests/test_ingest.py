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

import base64
import io
import json

import pytest
from fastapi.testclient import TestClient

import api.ingest as ingest_module
from agents.contracts import NextEvent, RunResult
from auth import identity
from data.models import Collection
from tests.conftest import OTHER_ORG, TEST_ORG, auth_header, seed_agent


@pytest.fixture
def client(fake_db):
    seed_agent(
        fake_db, ingest_module.INGEST_AGENT_NAME, ingest_module.INGEST_AGENT_VERSION,
        read_scopes=[], write_scopes=[Collection.INCIDENTS, Collection.RAW_EVIDENCE],
    )
    return TestClient(ingest_module.app, headers=auth_header())


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


def test_status():
    resp = TestClient(ingest_module.app).get("/status")
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


def test_ingest_without_org_id_uses_the_tenant_the_token_grants(client, published, fake_db):
    """org_id is now optional: a single-tenant credential determines it.
    It is no longer a required *input* because it was never safe as one."""
    resp = client.post("/ingest", data={"kind": "log", "payload": "x"})

    assert resp.status_code == 200
    assert _raw_evidence_docs(fake_db)[0]["org_id"] == TEST_ORG


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


def _push_body(payload: dict) -> dict:
    data = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return {"message": {"data": data, "messageId": "1"}, "subscription": "projects/p/subscriptions/s"}


@pytest.fixture
def push_config(monkeypatch):
    monkeypatch.setenv(identity._PUSH_AUDIENCE_ENV, "https://example.run.app")
    monkeypatch.setenv(identity._PUSH_SA_ENV, "pusher@example.iam.gserviceaccount.com")


def test_pubsub_push_rejects_missing_auth_header(client, push_config):
    resp = client.post(
        "/pubsub/push/evidence.staged",
        json=_push_body({"run_id": "r", "org_id": TEST_ORG}),
        headers={"Authorization": ""},
    )

    assert resp.status_code == 401


def test_pubsub_push_rejects_invalid_token(client, push_config):
    resp = client.post(
        "/pubsub/push/evidence.staged",
        json=_push_body({"run_id": "r", "org_id": TEST_ORG}),
        headers={"Authorization": "Bearer not-a-real-token"},
    )

    assert resp.status_code == 401


def test_pubsub_push_dispatches_decoded_message(client, fake_db, monkeypatch, clean_coordinator):
    """Proves the actual decode-and-dispatch logic, independent of token
    verification (which test_pubsub_push_rejects_* above already covers) -
    monkeypatches _verify_push_token to a no-op, same as production code
    would see a request Pub/Sub itself already authenticated."""
    monkeypatch.setattr(ingest_module, "_verify_push_token", lambda header: None)
    seed_agent(fake_db, "coordinator", "1.0.0",
               read_scopes=[Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
               write_scopes=[Collection.RUNS, Collection.QUARANTINE])
    seed_agent(fake_db, "guardian", "1.0.0", read_scopes=[], write_scopes=[Collection.ALERTS])
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[], write_scopes=[])
    invoked = []
    clean_coordinator.register_worker(
        "ledger", lambda claim, envelope: invoked.append(envelope.payload) or RunResult(status="ok")
    )

    resp = client.post(
        "/pubsub/push/evidence.staged",
        json=_push_body({"run_id": "run_push_1", "org_id": TEST_ORG, "incident_ref": "inc_1", "event_id": "evt_1"}),
        headers={"Authorization": "Bearer whatever"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "processed"
    assert len(invoked) == 1
    assert invoked[0]["event_id"] == "evt_1"


def test_pubsub_push_drops_undecodable_message_without_erroring(client, monkeypatch):
    monkeypatch.setattr(ingest_module, "_verify_push_token", lambda header: None)

    resp = client.post(
        "/pubsub/push/evidence.staged",
        json={"message": {"data": "not-valid-base64!!!", "messageId": "1"}, "subscription": "s"},
        headers={"Authorization": "Bearer whatever"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "dropped"


def test_pubsub_push_drops_message_missing_run_id(client, monkeypatch):
    monkeypatch.setattr(ingest_module, "_verify_push_token", lambda header: None)

    resp = client.post(
        "/pubsub/push/evidence.staged",
        json=_push_body({"org_id": TEST_ORG}),
        headers={"Authorization": "Bearer whatever"},
    )

    assert resp.status_code == 200
    assert resp.json()["status"] == "dropped"


def test_watcher_sweep_endpoint_correlates_real_seed_data(fake_db, clean_coordinator, monkeypatch):
    """End-to-end proof for the endpoint Cloud Scheduler actually hits
    (infra/schedule.sh) and the demo operator presses live (SPEC section
    10, beat 5): real seed data, the real Watcher worker registered, no
    mocking of the correlation logic itself - only Diagnosis (the next
    hop after a match) is stubbed, since this test is about proving the
    sweep endpoint reaches Watcher and Watcher's real match fires, not
    about Diagnosis's own behavior."""
    from agents.contracts import RunResult
    from agents.watcher.watcher import run as watcher_run
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

    resp = TestClient(ingest_module.app, headers=auth_header()).post("/watcher/sweep", json={})

    assert resp.status_code == 200
    body = resp.json()
    assert "3 signal(s) polled" in body["detail"]
    assert "1 incident(s) correlated" in body["detail"]


# --------------------------------------------------------------------------
# Security regressions (see tests/test_auth.py for the unit-level cases)
# --------------------------------------------------------------------------

def test_ingest_without_credential_is_rejected(fake_db):
    """The deployed service accepted this with no credential at all and
    signed a claim for whatever org_id the body named."""
    resp = TestClient(ingest_module.app).post(
        "/ingest", data={"org_id": TEST_ORG, "kind": "log", "payload": "x"},
    )
    assert resp.status_code == 401


def test_ingest_cannot_write_into_another_tenant(client, published, fake_db):
    """Cross-tenant write: a credential for TEST_ORG naming OTHER_ORG."""
    resp = client.post(
        "/ingest", data={"org_id": OTHER_ORG, "kind": "log", "payload": "x"},
    )

    assert resp.status_code == 403
    assert not [p for p in fake_db._docs if p[:2] == ("tenants", OTHER_ORG)]


def test_ingest_rejects_org_id_with_firestore_path_separator(client, published):
    resp = client.post(
        "/ingest", data={"org_id": "org_test/evil", "kind": "log", "payload": "x"},
    )
    assert resp.status_code in (400, 403)


def test_ingest_rejects_incident_id_with_path_separator(client, published):
    resp = client.post("/ingest", data={
        "kind": "log", "payload": "x", "incident_id": "inc_a/../../other",
    })
    assert resp.status_code == 400


def test_ingest_rate_limits_repeated_calls(client, published, monkeypatch):
    """Ingest fans out into paid model calls, so an unbounded caller is a
    cost-exhaustion vector. Verified against the real limiter."""
    monkeypatch.setattr(ingest_module, "_INGEST_LIMITER",
                        identity.TokenBucketLimiter(capacity=2, refill_per_second=0.0))

    codes = [
        client.post("/ingest", data={"kind": "log", "payload": "x"}).status_code
        for _ in range(4)
    ]

    assert codes[:2] == [200, 200]
    assert codes[2:] == [429, 429]


def test_webhook_pre_lookup_rate_limit_fires_before_the_firestore_read(client, monkeypatch):
    """Regression, found in a security self-review: connector_registry.
    load() is a real Firestore read that ran with NO rate limit at all -
    _WEBHOOK_LIMITER is keyed by config.org_id, which doesn't exist until
    AFTER that read succeeds. Proven here with a connector_id that is
    format-valid but never registered: if the limiter only ran after the
    lookup (the old, broken order), every one of these would 404, never
    429 - so seeing 429 here is the actual proof the check now runs
    first, not just that a 429 exists somewhere in the response space."""
    monkeypatch.setattr(ingest_module, "_PRE_LOOKUP_WEBHOOK_LIMITER",
                        identity.TokenBucketLimiter(capacity=2, refill_per_second=0.0))

    codes = [
        client.post("/webhook/conn_deadbeef0000", content=b'{"a":1}').status_code
        for _ in range(4)
    ]

    assert codes[:2] == [404, 404]  # connector genuinely doesn't exist - correct, once past the limiter
    assert codes[2:] == [429, 429]  # limiter now fires BEFORE the lookup gets a chance to 404 again


def test_watcher_sweep_without_credential_is_rejected():
    resp = TestClient(ingest_module.app).post("/watcher/sweep", json={})
    assert resp.status_code == 401


def test_watcher_sweep_cannot_target_another_tenant(client):
    resp = client.post("/watcher/sweep", json={"org_id": OTHER_ORG})
    assert resp.status_code == 403


# --------------------------------------------------------------------------
# Payload size limits (Firestore's 1 MiB document ceiling)
# --------------------------------------------------------------------------

def test_oversized_screenshot_is_rejected_not_truncated(client, published):
    """Previously truncated at 5 MB, which base64-expands to ~7 MB and is
    ~6.7x over Firestore's 1 MiB document limit - so every upload above
    ~768 KB produced an opaque 500 from the write instead of a clear 4xx."""
    oversized = b"\x89PNG" + b"\x00" * (ingest_module._MAX_INLINE_FILE_BYTES + 1)

    resp = client.post(
        "/ingest",
        data={"kind": "screenshot"},
        files={"file": ("big.png", io.BytesIO(oversized), "image/png")},
    )

    assert resp.status_code == 413
    assert "Firestore" in resp.json()["detail"]


def test_largest_allowed_screenshot_still_fits_a_firestore_document(client, published, fake_db):
    at_limit = b"\x89PNG" + b"\x00" * (ingest_module._MAX_INLINE_FILE_BYTES - 4)

    resp = client.post(
        "/ingest",
        data={"kind": "screenshot"},
        files={"file": ("big.png", io.BytesIO(at_limit), "image/png")},
    )

    assert resp.status_code == 200
    stored = _raw_evidence_docs(fake_db)[0]["payload"]
    assert len(stored.encode("utf-8")) < ingest_module._FIRESTORE_MAX_DOC_BYTES


def test_oversized_text_payload_is_rejected(client, published):
    resp = client.post("/ingest", data={
        "kind": "log", "payload": "x" * (ingest_module._MAX_TEXT_PAYLOAD_BYTES + 1),
    })
    assert resp.status_code == 413
