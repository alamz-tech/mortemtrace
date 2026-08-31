"""Regression tests for the authentication layer.

Every test here corresponds to a defect that was live in a deployed
service: unauthenticated cross-tenant read and write, tenant identity
taken from request input, unbounded request rates on endpoints that
trigger paid model calls, and a Pub/Sub push route that verified a
token's audience but not who issued it.

The point of the file is that reopening any of those holes fails the
suite rather than shipping.
"""
from __future__ import annotations

import json

import pytest

from auth import identity, session
from tests.conftest import (
    MULTI_ORG_TOKEN,
    OTHER_ORG,
    TEST_ORG,
    TEST_TOKEN,
    _digest,
)

# --------------------------------------------------------------------------
# Default posture
# --------------------------------------------------------------------------

def test_no_credential_is_rejected(monkeypatch):
    monkeypatch.delenv(identity._ANON_DEMO_ENV, raising=False)
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate(None)


def test_unknown_token_is_rejected():
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate("Bearer not-a-configured-token")


def test_non_bearer_scheme_is_rejected():
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate("Basic dXNlcjpwYXNz")


def test_empty_token_table_denies_everything(monkeypatch):
    """The default posture with nothing configured must be closed, not
    open - a service that ships with no tokens should reject, never fall
    back to a default tenant."""
    monkeypatch.setenv(identity._TOKENS_ENV, "{}")
    monkeypatch.delenv(identity._ANON_DEMO_ENV, raising=False)
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate(f"Bearer {TEST_TOKEN}")


def test_malformed_token_table_denies_rather_than_crashing(monkeypatch):
    monkeypatch.setenv(identity._TOKENS_ENV, "not json at all")
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate(f"Bearer {TEST_TOKEN}")


def test_invalid_token_is_not_downgraded_to_anonymous_in_demo_mode(monkeypatch):
    """An explicitly-presented bad token must fail even when anonymous
    demo mode is on: silently downgrading it would make a misconfigured
    client look like a working one, and would mask the credential failure
    the operator needs to see."""
    monkeypatch.setenv(identity._ANON_DEMO_ENV, "1")
    monkeypatch.setenv(identity._DEMO_ORG_ENV, TEST_ORG)
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate("Bearer wrong-token")


def test_anonymous_demo_mode_grants_only_the_demo_org(monkeypatch):
    monkeypatch.setenv(identity._ANON_DEMO_ENV, "1")
    monkeypatch.setenv(identity._DEMO_ORG_ENV, TEST_ORG)

    principal = identity.authenticate(None)

    assert principal.method == identity.METHOD_ANONYMOUS_DEMO
    assert principal.authorize_org(None) == TEST_ORG
    with pytest.raises(identity.AuthorizationError):
        principal.authorize_org(OTHER_ORG)


# --------------------------------------------------------------------------
# Tenant resolution - the core of the cross-tenant fix
# --------------------------------------------------------------------------

def test_token_resolves_its_single_tenant_implicitly():
    principal = identity.authenticate(f"Bearer {TEST_TOKEN}")
    assert principal.authorize_org(None) == TEST_ORG


def test_token_cannot_select_a_tenant_it_was_not_granted():
    """This is the confirmed-live vulnerability: `?org_id=<any tenant>`
    was honoured with no credential at all."""
    principal = identity.authenticate(f"Bearer {TEST_TOKEN}")
    with pytest.raises(identity.AuthorizationError):
        principal.authorize_org(OTHER_ORG)


def test_multi_tenant_token_may_select_among_its_own_tenants():
    principal = identity.authenticate(f"Bearer {MULTI_ORG_TOKEN}")
    assert principal.authorize_org(TEST_ORG) == TEST_ORG
    assert principal.authorize_org(OTHER_ORG) == OTHER_ORG


def test_multi_tenant_token_must_disambiguate():
    principal = identity.authenticate(f"Bearer {MULTI_ORG_TOKEN}")
    with pytest.raises(identity.AuthorizationError):
        principal.authorize_org(None)


def test_authorization_error_does_not_reveal_whether_tenant_exists():
    """The message must read the same for "tenant not yours" and "tenant
    does not exist" - otherwise the error is a tenant-enumeration oracle."""
    principal = identity.authenticate(f"Bearer {TEST_TOKEN}")

    with pytest.raises(identity.AuthorizationError) as existing:
        principal.authorize_org(OTHER_ORG)
    with pytest.raises(identity.AuthorizationError) as absent:
        principal.authorize_org("org_does_not_exist")

    assert str(existing.value) == str(absent.value)


# --------------------------------------------------------------------------
# org_id validation - Firestore path safety
# --------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [
    "org/../other",          # traversal-ish
    "a/b",                   # slash = extra Firestore path segment
    "",                      # empty document id
    "org demo",              # space
    "x" * 200,               # oversized
    "../registry",
])
def test_invalid_org_ids_are_rejected(bad):
    with pytest.raises(identity.InvalidOrgId):
        identity.validate_org_id(bad)


@pytest.mark.parametrize("good", ["org_demo", "org-1", "A1", "org_test_123"])
def test_valid_org_ids_are_accepted(good):
    assert identity.validate_org_id(good) == good


def test_token_granting_an_invalid_org_id_is_rejected(monkeypatch):
    """A bad value in configuration is as dangerous as one from a request,
    so the token table is validated too rather than trusted."""
    monkeypatch.setenv(identity._TOKENS_ENV, json.dumps({
        _digest("cfg-token"): {"org_ids": ["bad/org"], "subject": "misconfigured"},
    }))
    with pytest.raises(identity.AuthenticationError):
        identity.authenticate("Bearer cfg-token")


# --------------------------------------------------------------------------
# Google OIDC (Pub/Sub push)
# --------------------------------------------------------------------------

def _oidc_env(monkeypatch):
    monkeypatch.setenv(identity._PUSH_AUDIENCE_ENV, "https://ingest.example.run.app")
    monkeypatch.setenv(identity._PUSH_SA_ENV, "pusher@proj.iam.gserviceaccount.com")


def test_oidc_rejects_token_from_a_different_service_account(monkeypatch):
    """The original code verified signature + audience only. Any Google
    principal can mint an ID token with an arbitrary `aud`, so audience
    alone authenticated nothing - this asserts the issuer is checked."""
    _oidc_env(monkeypatch)
    monkeypatch.setattr(
        "google.oauth2.id_token.verify_oauth2_token",
        lambda token, request, audience=None: {
            "email": "attacker@evil.iam.gserviceaccount.com", "email_verified": True,
        },
    )
    with pytest.raises(identity.AuthenticationError):
        identity.verify_google_oidc("Bearer forged")


def test_oidc_accepts_the_configured_pusher(monkeypatch):
    _oidc_env(monkeypatch)
    monkeypatch.setattr(
        "google.oauth2.id_token.verify_oauth2_token",
        lambda token, request, audience=None: {
            "email": "pusher@proj.iam.gserviceaccount.com", "email_verified": True,
        },
    )
    principal = identity.verify_google_oidc("Bearer legit")
    assert principal.method == identity.METHOD_GOOGLE_OIDC


def test_oidc_rejects_unverified_email(monkeypatch):
    _oidc_env(monkeypatch)
    monkeypatch.setattr(
        "google.oauth2.id_token.verify_oauth2_token",
        lambda token, request, audience=None: {
            "email": "pusher@proj.iam.gserviceaccount.com", "email_verified": False,
        },
    )
    with pytest.raises(identity.AuthenticationError):
        identity.verify_google_oidc("Bearer legit-but-unverified")


def test_oidc_missing_service_account_config_is_a_server_error(monkeypatch):
    """Distinguished from an auth failure on purpose: a misconfigured
    server must not report itself as "caller unauthorized"."""
    monkeypatch.setenv(identity._PUSH_AUDIENCE_ENV, "https://ingest.example.run.app")
    monkeypatch.delenv(identity._PUSH_SA_ENV, raising=False)
    with pytest.raises(RuntimeError):
        identity.verify_google_oidc("Bearer anything")


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

def test_rate_limiter_allows_burst_then_blocks():
    limiter = identity.TokenBucketLimiter(capacity=3, refill_per_second=0.0)
    for _ in range(3):
        limiter.check("org_a")
    with pytest.raises(identity.RateLimitExceeded):
        limiter.check("org_a")


def test_rate_limiter_is_per_key():
    limiter = identity.TokenBucketLimiter(capacity=1, refill_per_second=0.0)
    limiter.check("org_a")
    limiter.check("org_b")  # separate budget, must not be affected
    with pytest.raises(identity.RateLimitExceeded):
        limiter.check("org_a")


def test_rate_limiter_refills_over_time(monkeypatch):
    clock = {"t": 1000.0}
    monkeypatch.setattr(identity.time, "monotonic", lambda: clock["t"])
    limiter = identity.TokenBucketLimiter(capacity=1, refill_per_second=1.0)

    limiter.check("org_a")
    with pytest.raises(identity.RateLimitExceeded):
        limiter.check("org_a")

    clock["t"] += 1.5
    limiter.check("org_a")  # refilled


def test_rate_limiter_bounds_its_own_memory():
    """Without eviction, a caller cycling tenant ids turns the rate
    limiter into the memory-exhaustion vector it exists to prevent."""
    limiter = identity.TokenBucketLimiter(capacity=5, refill_per_second=1.0, max_keys=50)
    for i in range(500):
        limiter.check(f"org_{i}")
    assert len(limiter._buckets) <= 50


# --------------------------------------------------------------------------
# Session cookies (auth/session.py) - the human credential
# --------------------------------------------------------------------------

def test_session_roundtrip():
    cookie = session.mint_session("user_123")
    verified = session.verify_session(cookie)
    assert verified.user_id == "user_123"


def test_session_rejects_tampered_signature():
    cookie = session.mint_session("user_123")
    tampered = cookie[:-4] + "aaaa"
    with pytest.raises(session.InvalidSession):
        session.verify_session(tampered)


def test_session_rejects_a_forged_user_id_with_a_stale_signature():
    """Splicing a different user_id onto an otherwise-valid session's
    signature must not verify - proves the signature actually covers the
    user_id field, not just the envelope shape."""
    cookie = session.mint_session("user_123")
    _uid, issued_at, expires_at, sig = cookie.split("|")
    forged = f"user_attacker|{issued_at}|{expires_at}|{sig}"
    with pytest.raises(session.InvalidSession):
        session.verify_session(forged)


def test_session_rejects_expired(monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_SESSION_MAX_AGE", "10")
    cookie = session.mint_session("user_123")
    real_now = session.time.time()  # captured BEFORE patching - session.time IS the time module
    monkeypatch.setattr(session.time, "time", lambda: real_now + 20)
    with pytest.raises(session.InvalidSession, match="expired"):
        session.verify_session(cookie)


def test_session_rejects_missing_or_malformed():
    with pytest.raises(session.InvalidSession):
        session.verify_session(None)
    with pytest.raises(session.InvalidSession):
        session.verify_session("not-even-the-right-shape")


def test_csrf_token_is_per_session_and_rejects_a_foreign_token():
    session_a = session.verify_session(session.mint_session("user_a"))
    session_b = session.verify_session(session.mint_session("user_b"))

    token_a = session.csrf_token(session_a)
    assert session.verify_csrf(session_a, token_a) is True
    assert session.verify_csrf(session_b, token_a) is False
    assert session.verify_csrf(session_a, "garbage") is False
    assert session.verify_csrf(session_a, None) is False


# --------------------------------------------------------------------------
# Principal.require_role - admin-gated actions
# --------------------------------------------------------------------------

def test_require_role_allows_matching_admin():
    principal = identity.Principal(
        org_ids=frozenset({"org_a"}), subject="alice@example.com", method="session",
        user_id="user_a", role_by_org={"org_a": "admin"},
    )
    principal.require_role("org_a", "admin")  # must not raise


def test_require_role_denies_member():
    principal = identity.Principal(
        org_ids=frozenset({"org_a"}), subject="alice@example.com", method="session",
        user_id="user_a", role_by_org={"org_a": "member"},
    )
    with pytest.raises(identity.AuthorizationError):
        principal.require_role("org_a", "admin")


def test_require_role_denies_an_api_token_principal_regardless_of_org_ids():
    """A machine credential has no role at all - require_role must deny
    it even though it may legitimately hold the org_id itself, so an
    admin-gated action can never be reached with an API token."""
    principal = identity.Principal(org_ids=frozenset({"org_a"}), subject="svc", method="api_token")
    with pytest.raises(identity.AuthorizationError):
        principal.require_role("org_a", "admin")


def test_authorize_org_zero_memberships_gives_a_distinct_message():
    principal = identity.Principal(org_ids=frozenset(), subject="alice@example.com", method="session")
    with pytest.raises(identity.AuthorizationError, match="not a member of any organization"):
        principal.authorize_org(None)
