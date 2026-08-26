"""Tests for console/ui.py: R11's operator console.

Seeds Firestore documents directly via FakeFirestore.seed() (bypassing
any agent/model-validation path - the console only ever reads plain
dicts back through data/scope_store.py, same as production) and asserts
on the rendered HTML/JSON. No real Firestore, no real agents involved.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import console.ui as console_module
from data.models import Collection
from tests.conftest import TEST_ORG, seed_agent

OTHER = "org_console_other"


@pytest.fixture
def client(fake_db):
    seed_agent(
        fake_db, console_module.CONSOLE_AGENT_NAME, console_module.CONSOLE_AGENT_VERSION,
        read_scopes=[
            Collection.INCIDENTS, Collection.TIMELINE, Collection.HYPOTHESES,
            Collection.CLASSIFICATION, Collection.DRAFTS, Collection.CLOCKS,
            Collection.AUDIT, Collection.SIGNALS, Collection.RUNS,
        ],
        write_scopes=[],
    )
    return TestClient(console_module.app)


def _seed_runs_and_incidents(fake_db):
    fake_db.seed(f"tenants/{TEST_ORG}/runs/run_a", {
        "run_id": "run_a", "org_id": TEST_ORG, "status": "running",
        "turns_used": 3, "tokens_used": 500, "span_id": None,
        "agents_invoked": ["intake", "ledger"],
        "created_at": "2026-08-25T10:00:00+00:00", "updated_at": "2026-08-25T10:05:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/runs/run_b", {
        "run_id": "run_b", "org_id": TEST_ORG, "status": "dead_letter",
        "turns_used": 1, "tokens_used": 50, "span_id": None,
        "agents_invoked": ["diagnosis"],
        "created_at": "2026-08-25T11:00:00+00:00", "updated_at": "2026-08-25T11:01:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/incidents/inc_open", {
        "incident_id": "inc_open", "org_id": TEST_ORG, "opened_at": "2026-08-25T09:00:00+00:00",
        "resolved_at": None, "status": "open", "severity": "sev2",
        "services_affected": ["checkout-api"], "alert_source": "pagerduty",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/incidents/inc_resolved", {
        "incident_id": "inc_resolved", "org_id": TEST_ORG, "opened_at": "2026-08-24T09:00:00+00:00",
        "resolved_at": "2026-08-24T10:00:00+00:00", "status": "resolved", "severity": "sev3",
        "services_affected": [], "alert_source": None,
    })


def _seed_incident_full(fake_db, *, data_touched: bool, with_clock: bool) -> str:
    """A fully-populated incident: timeline, hypotheses, classification,
    one draft (engineering only, so support/legal/finance exercise the
    empty-slot states), a correlated + an uncorrelated signal, and audit
    entries covering both the path-correlated and org-wide-deny cases."""
    incident_id = "inc_full_touched" if data_touched else "inc_full_untouched"

    fake_db.seed(f"tenants/{TEST_ORG}/incidents/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG, "opened_at": "2026-08-25T09:00:00+00:00",
        "resolved_at": None, "status": "open", "severity": "sev1",
        "services_affected": ["checkout-api"], "alert_source": "datadog",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG,
        "entries": [{
            "ts": "2026-08-25T09:05:00+00:00", "actor": "ledger", "action": "pods restarted",
            "evidence": "slack thread confirms restart", "source_event_ids": ["eventraw_abc123"],
        }],
        "downtime_windows": [], "last_updated": "2026-08-25T09:06:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/hypotheses/hyp_1", {
        "hypothesis_id": "hyp_1", "incident_ref": incident_id, "org_id": TEST_ORG,
        "statement": "checkout-api OOM after traffic spike", "confidence": 0.82,
        "source_event_ids": ["eventraw_abc123"], "prior_incident_refs": [],
    })
    fake_db.seed(f"tenants/{TEST_ORG}/classification/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG, "severity": "sev1",
        "services": ["checkout-api"], "downtime_windows": [], "data_touched": data_touched,
        "data_categories": ["customer_pii"] if data_touched else [],
        "classified_at": "2026-08-25T09:10:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/drafts/draft_eng_{incident_id}", {
        "draft_id": f"draft_eng_{incident_id}", "incident_ref": incident_id, "org_id": TEST_ORG,
        "department": "engineering", "kind": "postmortem", "status": "draft",
        "body": "Postmortem draft body.", "source_refs": ["eventraw_abc123"],
        "redaction_note": None, "created_at": "2026-08-25T09:15:00+00:00",
        "runbook_proposal": None,
    })
    if with_clock:
        fake_db.seed(f"tenants/{TEST_ORG}/clocks/{incident_id}", {
            "incident_id": incident_id, "org_id": TEST_ORG,
            "gdpr_started_at": "2026-08-25T09:10:00+00:00",
            "deadline_at": "2099-01-01T00:00:00+00:00",  # far future -> deterministic non-expired countdown
            "status": "running",
        })

    fake_db.seed(f"tenants/{TEST_ORG}/signals/sig_correlated_{incident_id}", {
        "signal_id": f"sig_correlated_{incident_id}", "source": "status-page", "provider": "aws",
        "region": "us-east-1", "service": "checkout-api", "severity": "degraded",
        "window": {"start": "2026-08-25T08:55:00+00:00", "end": None, "services": ["checkout-api"]},
        "seen_at": "2026-08-25T08:56:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/signals/sig_unrelated_{incident_id}", {
        "signal_id": f"sig_unrelated_{incident_id}", "source": "status-page", "provider": "gcp",
        "region": "eu-west-1", "service": "totally-unrelated-svc", "severity": "degraded",
        "window": {"start": "2026-08-25T08:55:00+00:00", "end": None, "services": []},
        "seen_at": "2026-08-25T08:56:00+00:00",
    })

    fake_db.seed(f"tenants/{TEST_ORG}/audit/audit_correlated_{incident_id}", {
        "entry_id": f"audit_correlated_{incident_id}", "org_id": TEST_ORG, "actor_agent": "ledger",
        "version": "1.0.0", "verdict": "allow", "reason": "write granted",
        "path": f"timeline/{incident_id}", "run_id": "run_a", "ts": "2026-08-25T10:05:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/audit/audit_deny_{incident_id}", {
        "entry_id": f"audit_deny_{incident_id}", "org_id": TEST_ORG, "actor_agent": "comms",
        "version": "1.0.0", "verdict": "deny", "reason": "comms has no read scope for raw_evidence",
        "path": "raw_evidence", "run_id": "run_c", "ts": "2026-08-25T10:06:00+00:00",
    })
    fake_db.seed(f"tenants/{TEST_ORG}/audit/audit_unrelated_allow_{incident_id}", {
        "entry_id": f"audit_unrelated_allow_{incident_id}", "org_id": TEST_ORG, "actor_agent": "exposure",
        "version": "1.0.0", "verdict": "allow", "reason": "write granted",
        "path": "drafts/draft_totally_unrelated", "run_id": "run_d", "ts": "2026-08-25T10:07:00+00:00",
    })

    return incident_id


def test_dashboard_renders_seeded_runs_and_active_incidents(client, fake_db):
    _seed_runs_and_incidents(fake_db)

    resp = client.get("/", params={"org_id": TEST_ORG})

    assert resp.status_code == 200
    assert "run_a" in resp.text
    assert "run_b" in resp.text
    assert "inc_open" in resp.text
    assert "inc_resolved" not in resp.text  # not status=open, must not appear


def test_dashboard_uses_demo_org_env_var_when_query_param_omitted(client, fake_db, monkeypatch):
    monkeypatch.setenv(console_module._DEMO_ORG_ENV, TEST_ORG)
    _seed_runs_and_incidents(fake_db)

    resp = client.get("/")

    assert resp.status_code == 200
    assert "inc_open" in resp.text


def test_api_runs_returns_json_shape(client, fake_db):
    _seed_runs_and_incidents(fake_db)

    resp = client.get("/api/runs", params={"org_id": TEST_ORG})

    assert resp.status_code == 200
    body = resp.json()
    run_ids = {r["run_id"] for r in body}
    assert {"run_a", "run_b"} <= run_ids
    assert all("_tone" in r for r in body)


def test_incident_detail_renders_timeline_hypotheses_drafts_and_audit(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=True)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})
    text = resp.text

    assert resp.status_code == 200
    # timeline entry with its source_event_ids visible (traceability)
    assert "pods restarted" in text
    assert "eventraw_abc123" in text
    # hypothesis with confidence
    assert "checkout-api OOM after traffic spike" in text
    assert "82%" in text
    # engineering draft present
    assert "Postmortem draft body." in text


def test_incident_detail_shows_no_draft_state_for_missing_departments(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    # only engineering has a draft; support, legal, and finance don't, and
    # the incident IS data-touching, so all three fall back to the generic
    # empty state (legal's special "not data-touching" message must NOT fire)
    assert resp.text.count("No draft yet.") == 3
    assert "Not data-touching" not in resp.text


def test_incident_detail_legal_shows_scope_explanation_when_not_data_touching(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=False, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    assert "Not data-touching" in resp.text
    # support and finance still show the generic empty state (2), legal shows the scope explanation instead
    assert resp.text.count("No draft yet.") == 2


def test_incident_detail_gdpr_clock_renders_when_present(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=True)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    assert "GDPR Article 33 clock" in resp.text
    assert "gdpr-remaining" in resp.text
    assert "running" in resp.text


def test_incident_detail_no_error_when_clock_absent(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    assert resp.status_code == 200
    assert "GDPR Article 33 clock" not in resp.text


def test_incident_detail_correlates_signals_by_affected_service(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    assert f"sig_correlated_{incident_id}" not in resp.text  # id itself isn't rendered, but provider/region are
    assert "us-east-1" in resp.text  # the correlated signal's region
    assert "eu-west-1" not in resp.text  # the unrelated signal must not appear


def test_incident_detail_audit_includes_correlated_and_deny_but_not_unrelated_allow(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})
    text = resp.text

    assert "write granted" in text  # correlated allow (path == timeline/{incident_id})
    assert "comms has no read scope for raw_evidence" in text  # org-wide deny, always surfaced
    assert "draft_totally_unrelated" not in text  # unrelated allow must not leak in


def test_incident_detail_404_for_unknown_incident(client, fake_db):
    resp = client.get("/incidents/inc_does_not_exist", params={"org_id": TEST_ORG})

    assert resp.status_code == 404


def test_audit_log_shows_all_recent_entries_globally(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get("/audit", params={"org_id": TEST_ORG})
    text = resp.text

    assert resp.status_code == 200
    assert "write granted" in text
    assert "comms has no read scope for raw_evidence" in text
    assert "draft_totally_unrelated" in text  # unlike the incident page, /audit is unfiltered
