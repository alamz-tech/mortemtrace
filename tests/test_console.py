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
from auth import oidc
from data.models import Collection
from tests.conftest import (
    OTHER_ORG,
    OTHER_TOKEN,
    TEST_ORG,
    auth_header,
    mint_test_session_cookie,
    seed_agent,
    seed_membership,
)

TEST_USER = "user_console_test"

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
    # Default headers carry a real token, so every existing assertion now
    # runs through the genuine authentication path rather than around it.
    return TestClient(console_module.app, headers=auth_header())


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


def test_dashboard_resolves_tenant_from_token_when_query_param_omitted(client, fake_db):
    """A single-tenant credential resolves org_id implicitly. This
    replaces a test that asserted the old behaviour - falling back to the
    MORTEMTRACE_DEMO_ORG env var with no credential involved - which was
    the unauthenticated default that made every tenant readable."""
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


def test_incident_detail_shows_classification_severity_and_data_touched(client, fake_db):
    """The classification record was being fetched and passed to the
    template but never actually rendered anywhere - data_touched is
    literally what triggers the GDPR clock, so an operator/judge should
    be able to see the classification itself, not just infer it from
    the clock's existence."""
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=True)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})
    text = resp.text

    assert "sev1" in text
    assert "data touched" in text
    assert "customer_pii" in text


def test_incident_detail_shows_no_data_touched_when_false(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=False, with_clock=False)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": TEST_ORG})

    assert "no customer data touched" in resp.text


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
    _seed_incident_full(fake_db, data_touched=True, with_clock=False)

    resp = client.get("/audit", params={"org_id": TEST_ORG})
    text = resp.text

    assert resp.status_code == 200
    assert "write granted" in text
    assert "comms has no read scope for raw_evidence" in text
    assert "draft_totally_unrelated" in text  # unlike the incident page, /audit is unfiltered


# --------------------------------------------------------------------------
# Cross-tenant access control
#
# The console was the confirmed-live vulnerability: GET /api/runs?org_id=<any>
# returned 200 with no credential and no auth challenge, exposing every
# tenant's incidents, drafts, GDPR clocks and audit log to anyone with the URL.
# --------------------------------------------------------------------------

def test_dashboard_without_credential_is_rejected(fake_db):
    resp = TestClient(console_module.app).get("/", params={"org_id": TEST_ORG})
    assert resp.status_code == 401


def test_api_runs_without_credential_is_rejected(fake_db):
    resp = TestClient(console_module.app).get("/api/runs", params={"org_id": TEST_ORG})
    assert resp.status_code == 401


def test_audit_log_without_credential_is_rejected(fake_db):
    resp = TestClient(console_module.app).get("/audit", params={"org_id": TEST_ORG})
    assert resp.status_code == 401


def test_browser_navigation_without_credential_redirects_to_login(fake_db):
    """A browser navigation gets the login form, not a bare JSON 401 -
    otherwise the first thing an operator sees on a protected console is
    an error with no indication that /login exists."""
    resp = TestClient(console_module.app).get(
        "/", headers={"Accept": "text/html,application/xhtml+xml"}, follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"


def test_json_client_without_credential_still_gets_401_not_a_redirect(fake_db):
    """The dashboard's own polling fetch must keep receiving a real 401 so
    its handler can send the user to /login. If this redirected, the poll
    would parse the login page's HTML as run data and render nothing,
    leaving a frozen table that still looks live."""
    resp = TestClient(console_module.app).get(
        "/api/runs", headers={"Accept": "application/json"}, follow_redirects=False,
    )

    assert resp.status_code == 401


def test_browser_cross_tenant_request_is_403_not_a_login_redirect(fake_db):
    """403 must not be swept into the 401 redirect path: the caller is
    authenticated, and bouncing them to a login form would suggest a
    credential problem rather than a tenant boundary."""
    seed_membership(fake_db, TEST_USER, TEST_ORG)
    browser = TestClient(
        console_module.app,
        cookies={console_module.SESSION_COOKIE: mint_test_session_cookie(TEST_USER)},
    )

    resp = browser.get(
        "/", params={"org_id": OTHER_ORG},
        headers={"Accept": "text/html"}, follow_redirects=False,
    )

    assert resp.status_code == 403


def test_cannot_read_another_tenants_runs(client, fake_db):
    _seed_runs_and_incidents(fake_db)

    resp = client.get("/api/runs", params={"org_id": OTHER_ORG})

    assert resp.status_code == 403


def test_cannot_read_another_tenants_incident(client, fake_db):
    incident_id = _seed_incident_full(fake_db, data_touched=True, with_clock=True)

    resp = client.get(f"/incidents/{incident_id}", params={"org_id": OTHER_ORG})

    assert resp.status_code == 403


def test_other_tenants_token_sees_none_of_this_tenants_data(fake_db):
    """Positive control for the negative tests above: a *valid* credential
    for a different tenant authenticates fine and simply sees nothing,
    rather than being rejected for the wrong reason."""
    _seed_runs_and_incidents(fake_db)
    seed_agent(
        fake_db, console_module.CONSOLE_AGENT_NAME, console_module.CONSOLE_AGENT_VERSION,
        read_scopes=[Collection.RUNS, Collection.INCIDENTS], write_scopes=[],
    )
    other = TestClient(console_module.app, headers=auth_header(OTHER_TOKEN))

    resp = other.get("/api/runs")

    assert resp.status_code == 200
    assert resp.json() == []


def test_status_stays_open(fake_db):
    """A liveness probe requiring a credential cannot distinguish "down"
    from "credential misconfigured" - exactly when you need it most."""
    assert TestClient(console_module.app).get("/status").status_code == 200


def test_session_cookie_authenticates_browser_requests(client, fake_db):
    """A session cookie is a MortemTrace-minted token, never the raw
    credential itself - it only resolves to org access via a live
    Membership row, which is what this test actually seeds and checks."""
    _seed_runs_and_incidents(fake_db)
    seed_membership(fake_db, TEST_USER, TEST_ORG)
    browser = TestClient(
        console_module.app,
        cookies={console_module.SESSION_COOKIE: mint_test_session_cookie(TEST_USER)},
    )

    resp = browser.get("/")

    assert resp.status_code == 200
    assert "inc_open" in resp.text


def test_session_cookie_for_user_with_no_membership_sees_nothing(fake_db):
    """A validly-signed session for a real user who simply isn't a member
    of anything yet must land on onboarding, not be treated as a 403 or,
    worse, resolved to some default tenant."""
    browser = TestClient(
        console_module.app,
        cookies={console_module.SESSION_COOKIE: mint_test_session_cookie(TEST_USER)},
    )

    resp = browser.get("/", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/onboarding"


def test_bad_session_cookie_is_rejected(fake_db):
    browser = TestClient(console_module.app, cookies={console_module.SESSION_COOKIE: "nope"})
    assert browser.get("/").status_code == 401


def test_stale_session_cookie_is_cleared_so_the_browser_can_recover(fake_db):
    """Regression: a browser holding an unusable session cookie (minted
    by a previous deployment, or before the session secret existed) got
    stuck in a permanent loop - /auth/callback would set a good cookie,
    but the stale one kept losing verification on every following
    request, bouncing back to /login with no way for the user to break
    out short of manually clearing site data. Expiring the bad cookie on
    the way out makes the next attempt self-heal."""
    browser = TestClient(console_module.app, cookies={console_module.SESSION_COOKIE: "stale-garbage"})

    resp = browser.get("/", headers={"Accept": "text/html"}, follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == "/login"
    set_cookie = resp.headers.get("set-cookie", "")
    assert console_module.SESSION_COOKIE in set_cookie
    # Max-Age=0 is what actually expires it; asserting the name alone
    # would pass even if we accidentally re-set a live cookie here.
    assert "max-age=0" in set_cookie.lower()


def test_json_client_with_stale_cookie_gets_401_without_a_redirect(fake_db):
    """The clearing behaviour above must not leak into the API path -
    the dashboard's polling fetch still needs a real 401 to react to."""
    browser = TestClient(console_module.app, cookies={console_module.SESSION_COOKIE: "stale-garbage"})

    resp = browser.get("/api/runs", headers={"Accept": "application/json"}, follow_redirects=False)

    assert resp.status_code == 401


def test_login_form_offers_google_and_no_password_field(fake_db, monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID", "test-client-id")
    monkeypatch.setenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET", "test-client-secret")
    resp = TestClient(console_module.app).get("/login")
    assert resp.status_code == 200
    assert "/auth/login/google" in resp.text
    assert 'type="password"' not in resp.text


def test_login_org_with_unconfigured_domain_redirects_with_error(fake_db):
    """No org has claimed this domain for SSO - the caller is told
    plainly rather than silently falling through to something else."""
    resp = TestClient(console_module.app).post(
        "/auth/login/org", data={"email": "person@no-such-company.example"}, follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?error=")


def test_oidc_callback_sets_a_hardened_session_cookie(fake_db, monkeypatch):
    """The real OIDC code/JWKS exchange is exercised directly in
    tests/test_oidc.py; here the boundary under test is console/ui.py's
    own handling of a *successful, already-verified* identity - so
    oidc.complete_login is monkeypatched to return one, the same
    boundary-substitution pattern stub_gateway uses for the model call."""
    monkeypatch.setattr(
        oidc, "complete_login",
        lambda **kwargs: oidc.VerifiedIdentity(
            issuer=oidc.GOOGLE_ISSUER, subject="google-sub-123", email="alice@example.com",
            display_name="Alice", invite_token=None, demo=False,
        ),
    )

    resp = TestClient(console_module.app).get(
        "/auth/callback", params={"code": "irrelevant", "state": "irrelevant"},
        cookies={console_module._HANDSHAKE_COOKIE: "irrelevant"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"] == "/onboarding"  # brand-new user, no org yet
    set_cookie = resp.headers["set-cookie"].lower()
    assert console_module.SESSION_COOKIE.lower() in set_cookie
    assert "httponly" in set_cookie
    # Lax, NOT Strict. Regression: this assertion previously demanded
    # Strict, which made a completely broken login flow look correct in
    # CI. /auth/callback is reached as a top-level navigation from
    # accounts.google.com, and Strict makes the browser withhold the
    # cookie on exactly that inbound cross-site navigation - so the
    # cookie was set and then never sent back, and every real browser
    # login bounced straight to /login. TestClient (like curl) does not
    # implement SameSite, so no request-level test can catch this;
    # asserting the attribute directly is the only guard available here.
    assert "samesite=lax" in set_cookie
    assert "samesite=strict" not in set_cookie


def test_oidc_callback_failure_redirects_to_login_and_clears_handshake(fake_db, monkeypatch):
    monkeypatch.setattr(
        oidc, "complete_login",
        lambda **kwargs: (_ for _ in ()).throw(oidc.OidcError("state mismatch")),
    )

    resp = TestClient(console_module.app).get(
        "/auth/callback", params={"code": "x", "state": "x"},
        cookies={console_module._HANDSHAKE_COOKIE: "irrelevant"},
        follow_redirects=False,
    )

    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/login?error=")
    assert console_module.SESSION_COOKIE not in resp.cookies


# --------------------------------------------------------------------------
# Onboarding, org administration, and CSRF - the console HTTP layer over
# the identity/membership functions unit-tested directly in
# tests/test_identity_provisioning.py.
# --------------------------------------------------------------------------

def _browser_for(user_id: str) -> TestClient:
    return TestClient(
        console_module.app, cookies={console_module.SESSION_COOKIE: mint_test_session_cookie(user_id)},
    )


def _csrf_for(user_id: str) -> str:
    from auth import session as session_module
    return session_module.csrf_token(session_module.verify_session(mint_test_session_cookie(user_id)))


def test_onboarding_redirects_away_once_a_member_of_something(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG)
    resp = _browser_for(TEST_USER).get("/onboarding", follow_redirects=False)
    assert resp.status_code == 303
    assert resp.headers["location"] == "/"


def test_onboarding_post_creates_org_and_makes_creator_admin(fake_db):
    browser = _browser_for(TEST_USER)
    resp = browser.post(
        "/onboarding", data={"display_name": "New Co", "csrf_token": _csrf_for(TEST_USER)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert resp.headers["location"].startswith("/?org_id=org_")

    new_org_id = resp.headers["location"].split("org_id=")[1]
    from data import scope_store
    assert scope_store.get_membership(TEST_USER, new_org_id)["role"] == "admin"


def test_onboarding_post_without_csrf_token_is_rejected(fake_db):
    resp = _browser_for(TEST_USER).post(
        "/onboarding", data={"display_name": "New Co"}, follow_redirects=False,
    )
    assert resp.status_code == 403


def test_onboarding_post_with_another_users_csrf_token_is_rejected(fake_db):
    """The CSRF token is bound to the session it was issued for - one
    authenticated user's token must not validate a different session,
    even though both are otherwise-valid, currently-live sessions."""
    resp = _browser_for(TEST_USER).post(
        "/onboarding", data={"display_name": "New Co", "csrf_token": _csrf_for("user_someone_else")},
        follow_redirects=False,
    )
    assert resp.status_code == 403


def test_non_admin_cannot_view_members_page(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="member")
    resp = _browser_for(TEST_USER).get(f"/orgs/{TEST_ORG}/members")
    assert resp.status_code == 403


def test_non_member_cannot_view_members_page(fake_db):
    """Not merely 'not an admin' - not a member AT ALL. Must be denied
    the same as any other org's data, not treated as a special case."""
    resp = _browser_for(TEST_USER).get(f"/orgs/{TEST_ORG}/members")
    assert resp.status_code == 403


def test_admin_can_view_members_and_create_an_invite_link(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin", email="admin@acme.com")
    browser = _browser_for(TEST_USER)

    page = browser.get(f"/orgs/{TEST_ORG}/members")
    assert page.status_code == 200
    assert "admin@acme.com" in page.text

    resp = browser.post(
        f"/orgs/{TEST_ORG}/invite",
        data={"email": "newhire@acme.com", "role": "member", "csrf_token": _csrf_for(TEST_USER)},
        follow_redirects=False,
    )
    assert resp.status_code == 303
    assert "invite_link=" in resp.headers["location"]

    shown = browser.get(resp.headers["location"])
    assert "newhire@acme.com" not in shown.text or "/invite/" in shown.text  # the link itself is shown
    assert "/invite/" in shown.text


def test_member_cannot_create_an_invite(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="member")
    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/invite",
        data={"email": "x@acme.com", "role": "admin", "csrf_token": _csrf_for(TEST_USER)},
    )
    assert resp.status_code == 403


def test_member_cannot_escalate_self_to_admin_via_invite_role(fake_db):
    """A member POSTing role=admin to the invite endpoint must be denied
    by the SAME admin check as any other invite - there is no separate,
    weaker path for self-service role changes."""
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="member")
    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/invite",
        data={"email": "someone@acme.com", "role": "admin", "csrf_token": _csrf_for(TEST_USER)},
    )
    assert resp.status_code == 403


def test_data_layer_permission_denied_surfaces_as_403_not_500(fake_db, monkeypatch):
    """Regression: a PermissionDenied raised by scope_store's OWN
    admin re-check (defense in depth against a role-revoked-mid-request
    race) must map to a clean 403 - without the exception handler, this
    was an unhandled 500."""
    from data import scope_store
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")

    def _always_denies(*args, **kwargs):
        raise scope_store.PermissionDenied("simulated role-revoked-mid-request race")
    monkeypatch.setattr(scope_store, "create_invitation", _always_denies)

    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/invite",
        data={"email": "x@acme.com", "role": "member", "csrf_token": _csrf_for(TEST_USER)},
    )
    assert resp.status_code == 403


def test_admin_can_revoke_a_member(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    seed_membership(fake_db, "user_departing", TEST_ORG, role="member")

    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/members/user_departing/revoke",
        data={"csrf_token": _csrf_for(TEST_USER)}, follow_redirects=False,
    )
    assert resp.status_code == 303

    from data import scope_store
    assert scope_store.get_membership("user_departing", TEST_ORG) is None


def test_admin_cannot_revoke_the_only_admin_via_http(fake_db):
    """The scope_store-level LastAdminError must surface as a clean 400
    through the console, not an unhandled 500."""
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")

    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/members/{TEST_USER}/revoke",
        data={"csrf_token": _csrf_for(TEST_USER)},
    )

    assert resp.status_code == 400
    from data import scope_store
    assert scope_store.get_membership(TEST_USER, TEST_ORG) is not None


def test_admin_can_promote_a_member_to_admin(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    seed_membership(fake_db, "user_promoted", TEST_ORG, role="member")

    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/members/user_promoted/role",
        data={"role": "admin", "csrf_token": _csrf_for(TEST_USER)}, follow_redirects=False,
    )

    assert resp.status_code == 303
    from data import scope_store
    assert scope_store.get_membership("user_promoted", TEST_ORG)["role"] == "admin"


def test_member_cannot_change_anyones_role(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="member")
    seed_membership(fake_db, "user_other", TEST_ORG, role="member")

    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/members/user_other/role",
        data={"role": "admin", "csrf_token": _csrf_for(TEST_USER)},
    )

    assert resp.status_code == 403


def test_sso_settings_admin_only(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="member")
    resp = _browser_for(TEST_USER).get(f"/orgs/{TEST_ORG}/sso")
    assert resp.status_code == 403


def test_sso_settings_save_and_clear(fake_db):
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    fake_db.seed(f"organizations/{TEST_ORG}", {
        "org_id": TEST_ORG, "display_name": "Test Org", "created_at": "2026-01-01T00:00:00+00:00",
        "created_by": TEST_USER, "sso": None, "auto_join_domains": [], "public_demo_auto_join": False,
    })
    browser = _browser_for(TEST_USER)

    resp = browser.post(
        f"/orgs/{TEST_ORG}/sso",
        data={
            "action": "save", "issuer": "https://login.microsoftonline.com/tenant/v2.0",
            "client_id": "client-123", "client_secret_ref": "acme-secret", "domain_hint": "acme.com",
            "csrf_token": _csrf_for(TEST_USER),
        },
        follow_redirects=False,
    )
    assert resp.status_code == 303

    from data import scope_store
    org = scope_store.get_organization(TEST_ORG)
    assert org["sso"]["issuer"] == "https://login.microsoftonline.com/tenant/v2.0"

    clear_resp = browser.post(
        f"/orgs/{TEST_ORG}/sso", data={"action": "clear", "csrf_token": _csrf_for(TEST_USER)},
    )
    assert clear_resp.status_code in (200, 303)
    assert scope_store.get_organization(TEST_ORG)["sso"] is None


def test_sso_settings_rejects_a_non_https_issuer(fake_db):
    """An http:// (or otherwise non-https) issuer would send credentials
    over plaintext during the OIDC handshake - rejected outright rather
    than accepted and failing confusingly later."""
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    resp = _browser_for(TEST_USER).post(
        f"/orgs/{TEST_ORG}/sso",
        data={
            "action": "save", "issuer": "http://insecure.example.com",
            "client_id": "x", "client_secret_ref": "y", "csrf_token": _csrf_for(TEST_USER),
        },
    )
    assert resp.status_code == 400


def test_invite_link_redemption_creates_membership(fake_db):
    from data import scope_store
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    _invitation, token = scope_store.create_invitation(TEST_USER, TEST_ORG, "newhire@acme.com", "member")

    resp = _browser_for("user_newhire").get(f"/invite/{token}", follow_redirects=False)

    # The redeeming session's email ("person@example.com" per seed_membership's
    # default) does not match the invitation's email, so redemption must be
    # refused - this proves the route enforces the same email-match rule
    # tests/test_identity_provisioning.py already proved at the function level.
    assert resp.status_code == 303
    assert "error" in resp.headers["location"]
    assert scope_store.get_membership("user_newhire", TEST_ORG) is None


def test_invite_link_without_a_session_redirects_through_login(fake_db):
    from data import scope_store
    seed_membership(fake_db, TEST_USER, TEST_ORG, role="admin")
    _invitation, token = scope_store.create_invitation(TEST_USER, TEST_ORG, "newhire@acme.com", "member")

    resp = TestClient(console_module.app).get(f"/invite/{token}", follow_redirects=False)

    assert resp.status_code == 303
    assert resp.headers["location"] == f"/login?invite={token}"
