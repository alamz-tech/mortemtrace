"""Universal inbound connector tests.

The design claim being tested is "any tool, any JSON, no adapter" - so
these deliberately push payload shapes from several real vendors plus
deliberately malformed ones through the *same* code path, and assert none
of them require vendor-specific handling.

The security claim is that the connector_id alone is not sufficient: a
signed connector must reject a body it did not sign.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

import api.ingest as ingest_module
from auth import identity
from connectors import registry as connector_registry
from connectors import verification
from data import scope_store
from data.models import Collection, ConnectorConfig, VerificationConfig
from tests.conftest import OTHER_ORG, TEST_ORG, seed_agent

SECRET = "connector-signing-secret-for-tests"


@pytest.fixture
def client(fake_db, monkeypatch):
    seed_agent(
        fake_db, ingest_module.INGEST_AGENT_NAME, ingest_module.INGEST_AGENT_VERSION,
        read_scopes=[Collection.CONNECTORS],
        write_scopes=[
            Collection.INCIDENTS, Collection.RAW_EVIDENCE,
            Collection.CHANGE_EVENTS, Collection.CONNECTORS,
        ],
    )
    monkeypatch.setenv(verification._SECRETS_ENV, json.dumps({"conn_secret_ref": SECRET}))
    monkeypatch.setattr(ingest_module, "_publish", lambda topic, payload: None)
    return TestClient(ingest_module.app)


def _register(fake_db, *, connector_id="conn_aaaabbbbcccc", strategy="hmac",
              header="X-Hub-Signature-256", prefix="sha256=", is_change_source=False,
              org_id=TEST_ORG, enabled=True, encoding="hex"):
    config = ConnectorConfig(
        connector_id=connector_id, org_id=org_id, name="test", source="testtool",
        is_change_source=is_change_source, enabled=enabled,
        verification=VerificationConfig(
            strategy=strategy, header=header, prefix=prefix, encoding=encoding,
            secret_ref="conn_secret_ref" if strategy in ("hmac", "bearer") else None,
            allowed_ips=["10.0.0.0/8"] if strategy == "ip_allowlist" else [],
        ),
    )
    fake_db.seed(f"connectors/{connector_id}", config.model_dump(mode="json"))
    return config


def _sign(body: bytes, encoding="hex") -> str:
    mac = hmac.new(SECRET.encode(), body, hashlib.sha256)
    return base64.b64encode(mac.digest()).decode() if encoding == "base64" else mac.hexdigest()


# --------------------------------------------------------------------------
# "Any tool, any JSON, no adapter"
# --------------------------------------------------------------------------

VENDOR_PAYLOADS = {
    "datadog": {"alert_type": "error", "title": "High error rate", "body": "checkout-api 5xx",
                "priority": "P1", "tags": ["service:checkout-api"]},
    "pagerduty": {"event": {"data": {"type": "incident", "title": "API down",
                                      "service": {"summary": "payments"}}}},
    "grafana": {"state": "alerting", "ruleName": "Latency", "evalMatches": [{"value": 900}]},
    "sentry": {"action": "triggered", "data": {"issue": {"title": "NPE in checkout"}}},
    "alertmanager": {"status": "firing", "alerts": [{"labels": {"alertname": "PodCrash"}}]},
    "deeply_nested": {"a": {"b": {"c": {"d": {"e": "buried value"}}}}},
    "arrays": {"items": [{"name": "x"}, {"name": "y"}]},
    "empty": {},
}


@pytest.mark.parametrize("vendor", sorted(VENDOR_PAYLOADS))
def test_any_vendor_payload_is_accepted_without_an_adapter(client, fake_db, vendor):
    """One code path, many vendor shapes. If this needed per-vendor
    branching, the whole design claim would be false."""
    _register(fake_db)
    body = json.dumps(VENDOR_PAYLOADS[vendor]).encode()

    resp = client.post(
        "/webhook/conn_aaaabbbbcccc", content=body,
        headers={"X-Hub-Signature-256": "sha256=" + _sign(body),
                 "Content-Type": "application/json"},
    )

    assert resp.status_code == 200, resp.text
    assert resp.json()["incident_id"].startswith("inc_")


def test_non_json_body_degrades_instead_of_failing(client, fake_db):
    """A tool posting form data or plain text is still ingestable - the
    extraction layer reads text, so rejecting it would be a self-inflicted
    limitation."""
    _register(fake_db)
    body = b"plain text alert: disk full on db-primary"

    resp = client.post(
        "/webhook/conn_aaaabbbbcccc", content=body,
        headers={"X-Hub-Signature-256": "sha256=" + _sign(body)},
    )

    assert resp.status_code == 200


def test_evidence_reaches_raw_evidence_with_source_attribution(client, fake_db):
    _register(fake_db)
    body = json.dumps({"title": "checkout latency spike", "service": "checkout-api"}).encode()

    client.post("/webhook/conn_aaaabbbbcccc", content=body,
                headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})

    stored = [d for p, d in fake_db._docs.items() if p[:3] == ("tenants", TEST_ORG, "raw_evidence")]
    assert len(stored) == 1
    assert "[testtool]" in stored[0]["payload"]
    assert "checkout-api" in stored[0]["payload"]


# --------------------------------------------------------------------------
# Signature verification
# --------------------------------------------------------------------------

def test_forged_body_is_rejected(client, fake_db):
    """The core security property: knowing the URL is not enough."""
    _register(fake_db)
    signed = json.dumps({"real": "payload"}).encode()
    forged = json.dumps({"injected": "payload"}).encode()

    resp = client.post(
        "/webhook/conn_aaaabbbbcccc", content=forged,
        headers={"X-Hub-Signature-256": "sha256=" + _sign(signed)},
    )

    assert resp.status_code == 401
    assert not [p for p in fake_db._docs if p[:3] == ("tenants", TEST_ORG, "raw_evidence")]


def test_missing_signature_header_is_rejected(client, fake_db):
    _register(fake_db)
    resp = client.post("/webhook/conn_aaaabbbbcccc", content=b'{"a":1}')
    assert resp.status_code == 401


def test_wrong_prefix_is_rejected(client, fake_db):
    _register(fake_db)
    body = b'{"a":1}'
    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": _sign(body)})  # no "sha256=" prefix
    assert resp.status_code == 401


def test_base64_encoding_strategy_works(client, fake_db):
    _register(fake_db, encoding="base64", prefix=None)
    body = b'{"a":1}'
    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": _sign(body, "base64")})
    assert resp.status_code == 200


def test_bearer_strategy(client, fake_db):
    _register(fake_db, strategy="bearer", header="DD-Webhook-Token", prefix=None)
    ok = client.post("/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
                     headers={"DD-Webhook-Token": SECRET})
    bad = client.post("/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
                      headers={"DD-Webhook-Token": "wrong"})
    assert ok.status_code == 200
    assert bad.status_code == 401


def test_ip_allowlist_accepts_the_real_client_behind_one_proxy_hop(client, fake_db):
    """With the default single Google front-end hop, `<client>, <gfe>`
    resolves to the client."""
    _register(fake_db, strategy="ip_allowlist", header=None, prefix=None)

    resp = client.post("/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
                       headers={"X-Forwarded-For": "10.1.2.3, 172.16.0.1"})

    assert resp.status_code == 200


def test_ip_allowlist_ignores_a_caller_prepended_forwarded_address(client, fake_db):
    """Regression: the allowlist was bypassable by sending your own
    X-Forwarded-For.

    Google's front end *appends* to whatever the caller sent, so an
    attacker sending `X-Forwarded-For: 10.1.2.3` (an allowlisted address)
    arrives as `10.1.2.3, <their-real-ip>, <gfe>`. The previous
    implementation read position 0 and let them straight through. Only
    entries the infrastructure appended - counted from the right - are
    trustworthy.
    """
    _register(fake_db, strategy="ip_allowlist", header=None, prefix=None)

    resp = client.post(
        "/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
        headers={"X-Forwarded-For": "10.1.2.3, 203.0.113.9, 172.16.0.1"},
    )

    assert resp.status_code == 401


def test_ip_allowlist_fails_closed_when_forwarded_chain_is_too_short(client, fake_db):
    """Fewer entries than configured trusted hops means the real client
    cannot be identified. That must deny, not fall back to whatever entry
    happens to be present."""
    _register(fake_db, strategy="ip_allowlist", header=None, prefix=None)

    resp = client.post("/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
                       headers={"X-Forwarded-For": "10.1.2.3"})

    assert resp.status_code == 401


def test_ip_allowlist_honours_configured_proxy_hop_count(client, fake_db, monkeypatch):
    """Two hops (a custom load balancer in front of Cloud Run) shifts
    which entry is authoritative."""
    monkeypatch.setenv(identity._TRUSTED_PROXY_HOPS_ENV, "2")
    _register(fake_db, strategy="ip_allowlist", header=None, prefix=None)

    resp = client.post(
        "/webhook/conn_aaaabbbbcccc", content=b'{"a":1}',
        headers={"X-Forwarded-For": "203.0.113.9, 10.1.2.3, 172.16.0.1, 192.0.2.1"},
    )

    assert resp.status_code == 200


def test_missing_secret_is_a_server_error_not_an_auth_failure(client, fake_db, monkeypatch):
    """A misconfigured connector must not report itself as 'caller
    unauthorized' - that sends whoever is debugging it in the wrong
    direction entirely."""
    _register(fake_db)
    monkeypatch.setenv(verification._SECRETS_ENV, "{}")
    body = b'{"a":1}'
    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})
    assert resp.status_code == 500


# --------------------------------------------------------------------------
# Connector resolution
# --------------------------------------------------------------------------

def test_unknown_and_disabled_connectors_are_indistinguishable(client, fake_db):
    """Same response for both, so the endpoint is not an oracle for which
    connector ids exist."""
    _register(fake_db, connector_id="conn_ddddeeeeffff", enabled=False)
    unknown = client.post("/webhook/conn_000011112222", content=b"{}")
    disabled = client.post("/webhook/conn_ddddeeeeffff", content=b"{}")
    assert unknown.status_code == disabled.status_code == 404
    assert unknown.json() == disabled.json()


def test_malformed_connector_id_is_rejected_before_any_lookup(client, fake_db):
    for bad in ["../../etc", "conn_short", "notaconnector", "conn_" + "z" * 40]:
        assert client.post(f"/webhook/{bad}", content=b"{}").status_code == 404


def test_connector_writes_land_in_its_own_tenant_only(client, fake_db):
    """The tenant comes from the connector document, never the payload -
    so a payload claiming another org cannot redirect the write."""
    _register(fake_db, org_id=OTHER_ORG)
    body = json.dumps({"org_id": TEST_ORG, "title": "attempted redirect"}).encode()

    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})

    assert resp.status_code == 200
    assert [p for p in fake_db._docs if p[:3] == ("tenants", OTHER_ORG, "raw_evidence")]
    assert not [p for p in fake_db._docs if p[:3] == ("tenants", TEST_ORG, "raw_evidence")]


def test_oversized_body_is_rejected(client, fake_db):
    _register(fake_db)
    body = b"x" * (ingest_module._MAX_TEXT_PAYLOAD_BYTES + 1)
    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})
    assert resp.status_code == 413


# --------------------------------------------------------------------------
# Change events
# --------------------------------------------------------------------------

def test_change_source_records_a_change_not_an_incident(client, fake_db):
    """A deploy is not an outage. It must become correlatable history
    without opening an incident."""
    _register(fake_db, is_change_source=True)
    body = json.dumps({
        "action": "completed", "repository": "checkout-api",
        "head_sha": "abc123def456", "sender": "alice", "workflow": "deploy",
    }).encode()

    resp = client.post("/webhook/conn_aaaabbbbcccc", content=body,
                       headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})

    assert resp.status_code == 200
    assert resp.json()["status"] == "recorded"
    changes = [d for p, d in fake_db._docs.items() if p[:3] == ("tenants", TEST_ORG, "change_events")]
    assert len(changes) == 1
    assert changes[0]["service"] == "checkout-api"
    assert changes[0]["ref"] == "abc123def456"
    assert changes[0]["actor"] == "alice"
    assert changes[0]["kind"] == "deploy"
    # No incident opened.
    assert not [p for p in fake_db._docs if p[:3] == ("tenants", TEST_ORG, "incidents")]


def test_unrecognised_change_payload_still_produces_a_usable_record(client, fake_db):
    """A tool whose field names we have never seen must still yield a
    correlatable record - the raw body is retained either way."""
    _register(fake_db, is_change_source=True)
    body = json.dumps({"weird_field": "value", "another": 42}).encode()

    client.post("/webhook/conn_aaaabbbbcccc", content=body,
                headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})

    changes = [d for p, d in fake_db._docs.items() if p[:3] == ("tenants", TEST_ORG, "change_events")]
    assert len(changes) == 1
    assert changes[0]["raw"] == {"weird_field": "value", "another": 42}
    assert "weird_field" in changes[0]["summary"]


def test_credential_shaped_fields_are_not_echoed_into_evidence(client, fake_db):
    """A webhook body can contain a token; that must not be copied into
    evidence text that later reaches a model and a draft."""
    _register(fake_db)
    body = json.dumps({"title": "deploy done", "token": "super-secret-value",
                       "password": "hunter2"}).encode()

    client.post("/webhook/conn_aaaabbbbcccc", content=body,
                headers={"X-Hub-Signature-256": "sha256=" + _sign(body)})

    stored = [d for p, d in fake_db._docs.items() if p[:3] == ("tenants", TEST_ORG, "raw_evidence")]
    assert "super-secret-value" not in stored[0]["payload"]
    assert "hunter2" not in stored[0]["payload"]


# --------------------------------------------------------------------------
# Presets are data, not code
# --------------------------------------------------------------------------

def test_every_preset_is_a_valid_connector_config():
    import pathlib
    presets = sorted((pathlib.Path("connectors/presets")).glob("*.json"))
    assert presets, "expected shipped presets"
    for path in presets:
        raw = json.loads(path.read_text())
        raw.pop("_setup", None)
        config = ConnectorConfig(
            connector_id="conn_aaaabbbbcccc", org_id=TEST_ORG, **raw,
        )
        assert config.verification.strategy in ("hmac", "bearer", "ip_allowlist", "none")


def test_scope_store_rejects_a_connector_written_into_another_tenant(fake_db):
    """The connectors collection is global, so _authorize's automatic
    tenant check does not apply and the org match is made explicitly."""
    seed_agent(fake_db, "ingest-api", "1.0.0",
               read_scopes=[Collection.CONNECTORS], write_scopes=[Collection.CONNECTORS])
    claim = scope_store.sign_claim(
        org_id=TEST_ORG, agent_name="ingest-api", agent_version="1.0.0", run_id="run_1",
    )
    config = ConnectorConfig(
        connector_id="conn_aaaabbbbcccc", org_id=OTHER_ORG, name="x", source="y",
    )

    with pytest.raises(scope_store.TenantViolation):
        scope_store.connector_put(claim, "conn_aaaabbbbcccc", config.model_dump(mode="json"))


def test_find_connector_respects_an_org_hint(fake_db):
    _register(fake_db, org_id=TEST_ORG)
    assert scope_store.find_connector("conn_aaaabbbbcccc", org_hint=TEST_ORG) is not None
    assert scope_store.find_connector("conn_aaaabbbbcccc", org_hint=OTHER_ORG) is None


def test_connector_registry_load_raises_for_unknown(fake_db):
    with pytest.raises(connector_registry.UnknownConnector):
        connector_registry.load(None, "conn_aaaabbbbcccc")


# --------------------------------------------------------------------------
# Field extraction across vendors, with no vendor-specific code
# --------------------------------------------------------------------------

def _cfg(source="ci", change=True):
    return ConnectorConfig(connector_id="conn_aaaabbbbcccc", org_id=TEST_ORG,
                           name="x", source=source, is_change_source=change)


EXTRACTION_CASES = {
    "github": (
        {"action": "completed",
         "workflow_run": {"name": "Deploy to production", "head_sha": "9f2c1a4e"},
         "repository": {"name": "payments-api", "full_name": "org/payments-api"},
         "sender": {"login": "hussein"}},
        {"service": "payments-api", "ref": "9f2c1a4e", "actor": "hussein", "kind": "deploy"},
    ),
    "jenkins": (
        {"job_name": "deploy-checkout", "build_number": 4821, "actor": "ci-bot"},
        {"service": "deploy-checkout", "ref": "4821", "actor": "ci-bot", "kind": "deploy"},
    ),
    "gitlab": (
        {"object_kind": "deployment", "project": {"name": "billing"},
         "user": {"username": "dev1"}, "commit": {"id": "77aa"}},
        {"service": "billing", "ref": "77aa", "actor": "dev1", "kind": "deploy"},
    ),
    "argocd": (
        {"app": {"name": "checkout"}, "status": {"sync": "Synced"}},
        {"service": "checkout"},
    ),
    "terraform": (
        {"run": {"status": "applied"}, "workspace": {"name": "prod-network"}, "actor": "tfc"},
        {"service": "prod-network", "actor": "tfc"},
    ),
}


@pytest.mark.parametrize("vendor", sorted(EXTRACTION_CASES))
def test_semantic_fields_extract_from_nested_vendor_payloads(vendor):
    """Every one of these nests the meaningful value differently -
    repository.name, job_name, project.name, app.name, workspace.name.
    Resolving them without per-vendor branching is the whole claim."""
    payload, expected = EXTRACTION_CASES[vendor]
    change = connector_registry.to_change_event(_cfg(), payload)
    for field, value in expected.items():
        assert getattr(change, field) == value, f"{vendor}.{field}"


def test_completely_unknown_payload_yields_a_record_with_no_invented_fields():
    """Honest absence beats a confident wrong guess: unmatched fields stay
    None, and the raw body is retained so nothing is actually lost."""
    change = connector_registry.to_change_event(_cfg(), {"foo": "bar", "baz": 123})
    assert change.service is None and change.ref is None and change.actor is None
    assert change.raw == {"foo": "bar", "baz": 123}
    assert "foo" in change.summary


@pytest.mark.parametrize("secret_field", [
    {"token": "leak-me"}, {"password": "leak-me"}, {"api_key": "leak-me"},
    {"auth": {"token": "leak-me"}}, {"config": {"db_password": "leak-me"}},
    {"headers": {"authorization": "leak-me"}},
])
def test_credential_shaped_fields_never_reach_evidence_text(secret_field):
    """Evidence text reaches a model and then a draft a human may
    circulate, so a token in a webhook body must not survive the trip -
    including when nested."""
    payload = {"ok": "visible", **secret_field}
    summary = connector_registry.summarize("tool", payload)
    assert "leak-me" not in summary
    assert "visible" in summary


def test_walk_is_bounded_against_a_hostile_payload():
    """A webhook body is attacker-influenced; an unbounded walk over a
    deeply nested or very wide payload would be a DoS on our own path."""
    deep = current = {}
    for _ in range(50):
        current["nested"] = {}
        current = current["nested"]
    current["leaf"] = "too-deep-to-reach"
    wide = {f"k{i}": f"v{i}" for i in range(5000)}

    assert "too-deep-to-reach" not in connector_registry.summarize("t", deep)
    assert len(connector_registry.summarize("t", wide)) <= 400
