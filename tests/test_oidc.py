"""Tests for auth/oidc.py - the new authentication boundary.

These exercise REAL cryptographic verification (a genuine RSA-signed JWT,
checked with joserfc against a genuine JWKS) rather than mocking the
crypto itself: only network I/O (discovery document, JWKS fetch, token
exchange) is faked. A test suite that mocks the verification step would
prove nothing about whether the verification step actually rejects a
forged token - see gateway/model_armor.py's own history for exactly this
class of bug (a check that looked right and let everything through).
"""
from __future__ import annotations

import time

import pytest
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt as joserfc_jwt
from joserfc.jwk import RSAKey

from auth import oidc

_ISSUER = "https://idp.example.com"
_CLIENT_ID = "test-client-id"
_KID = "test-key-1"
_BASE_URL = "https://console.example.com"


@pytest.fixture(scope="module")
def rsa_key():
    return RSAKey.generate_key(2048, parameters={"kid": _KID})


def _discovery_document(issuer: str) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
    }


def _sign_id_token(key, *, issuer, audience, subject, nonce, email="alice@example.com",
                    email_verified=True, exp_delta=3600) -> str:
    now = int(time.time())
    claims = {
        "iss": issuer, "aud": audience, "sub": subject, "nonce": nonce,
        "email": email, "email_verified": email_verified,
        "iat": now, "exp": now + exp_delta, "name": "Alice",
    }
    return joserfc_jwt.encode({"alg": "RS256", "kid": _KID}, claims, key)


def _mock_network(monkeypatch, *, discovery: dict, jwks: dict) -> None:
    class _Resp:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._payload

    def fake_get(url, timeout=None):
        if url.endswith("/.well-known/openid-configuration"):
            return _Resp(discovery)
        if url.endswith("/jwks"):
            return _Resp(jwks)
        raise AssertionError(f"unexpected GET {url}")

    monkeypatch.setattr(oidc.requests, "get", fake_get)


def _configure_google(monkeypatch) -> None:
    monkeypatch.setattr(oidc, "GOOGLE_ISSUER", _ISSUER)
    monkeypatch.setenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID", _CLIENT_ID)
    monkeypatch.setenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET", "test-secret")


def _start_login(monkeypatch, rsa_key, *, jwks_key=None) -> oidc.Handshake:
    _configure_google(monkeypatch)
    _mock_network(
        monkeypatch, discovery=_discovery_document(_ISSUER),
        jwks={"keys": [(jwks_key or rsa_key).as_dict(private=False)]},
    )
    _url, handshake_cookie = oidc.start_google_login(_BASE_URL)
    return oidc._unpack_handshake(handshake_cookie), handshake_cookie


def test_authorization_url_carries_a_matching_pkce_code_challenge(monkeypatch, rsa_key):
    """Regression: Authlib's create_authorization_url() only attaches a
    code_challenge to the URL when the OAuth2Session was CONSTRUCTED with
    code_challenge_method="S256" - passing code_verifier to the call
    alone silently does nothing without it. This was a real, live bug:
    the authorization URL went out with no code_challenge at all, so
    Google had nothing on file to check the code_verifier this same
    flow later sent at token-exchange time against, and rejected the
    whole login (invalid_grant: "code_verifier or verifier is not
    needed"). Every other test in this file stubs fetch_token() directly
    and never inspects the authorization URL's own query string, which
    is exactly how this got missed the first time - this test is the
    fix for that blind spot, not just for the bug.
    """
    from urllib.parse import parse_qs, urlparse

    from authlib.oauth2.rfc7636 import create_s256_code_challenge

    _configure_google(monkeypatch)
    _mock_network(
        monkeypatch, discovery=_discovery_document(_ISSUER),
        jwks={"keys": [rsa_key.as_dict(private=False)]},
    )

    url, handshake_cookie = oidc.start_google_login(_BASE_URL)
    handshake = oidc._unpack_handshake(handshake_cookie)

    query = parse_qs(urlparse(url).query)
    assert query.get("code_challenge_method") == ["S256"]
    # Not just present - the correct one, derived from the SAME
    # code_verifier stored in the handshake for later use at token
    # exchange. A present-but-wrong challenge would fail exactly the
    # same way the missing one did.
    assert query.get("code_challenge") == [create_s256_code_challenge(handshake.code_verifier)]


def _complete_with_token(monkeypatch, handshake, handshake_cookie, id_token: str,
                          *, state: str = None):
    def fake_fetch_token(self, url, code=None, code_verifier=None, redirect_uri=None, **kwargs):
        return {"id_token": id_token, "access_token": "unused"}

    monkeypatch.setattr(OAuth2Session, "fetch_token", fake_fetch_token)
    return oidc.complete_login(
        query_params={"code": "auth-code-123", "state": state or handshake.state},
        handshake_cookie=handshake_cookie,
        base_url=_BASE_URL,
    )


# --------------------------------------------------------------------------
# The happy path, and every way the ID token itself can be wrong
# --------------------------------------------------------------------------

def test_valid_login_verifies_and_returns_identity(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce)

    identity = _complete_with_token(monkeypatch, handshake, cookie, id_token)

    assert identity.email == "alice@example.com"
    assert identity.issuer == _ISSUER
    assert identity.subject == "sub-123"
    assert identity.display_name == "Alice"


def test_wrong_audience_is_rejected(monkeypatch, rsa_key):
    """A token issued for a DIFFERENT client_id must never be accepted -
    the whole point of the audience check."""
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience="someone-elses-client-id",
                               subject="sub-123", nonce=handshake.nonce)

    with pytest.raises(oidc.OidcError):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


def test_wrong_issuer_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer="https://evil.example.com", audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce)

    with pytest.raises(oidc.OidcError):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


def test_nonce_mismatch_is_rejected(monkeypatch, rsa_key):
    """A perfectly validly-signed token minted for a DIFFERENT login
    attempt (a different nonce) must be rejected - this is the replay
    guard, and it is a separate check from the signature/iss/aud ones."""
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce="a-different-logins-nonce")

    with pytest.raises(oidc.OidcError, match="nonce"):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


def test_unverified_email_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce, email_verified=False)

    with pytest.raises(oidc.OidcError, match="unverified"):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


def test_expired_id_token_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce, exp_delta=-3600)

    with pytest.raises(oidc.OidcError):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


def test_signature_from_an_unpublished_key_is_rejected(monkeypatch, rsa_key):
    """A token signed by a key that is NOT in the IdP's published JWKS -
    forged, or signed with a since-rotated key - must fail verification.
    This is what actually proves the JWKS check does something: every
    other test above uses a token correctly signed by the published key,
    so only this one would catch a verification step that silently
    no-ops (exactly the class of bug gateway/model_armor.py's
    str(enum)-vs-.name defect was)."""
    forged_key = RSAKey.generate_key(2048, parameters={"kid": _KID})
    handshake, cookie = _start_login(monkeypatch, rsa_key)  # JWKS publishes rsa_key, not forged_key
    id_token = _sign_id_token(forged_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce)

    with pytest.raises(oidc.OidcError, match="verification"):
        _complete_with_token(monkeypatch, handshake, cookie, id_token)


# --------------------------------------------------------------------------
# The handshake/state layer, independent of the ID token's own validity
# --------------------------------------------------------------------------

def test_state_mismatch_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    id_token = _sign_id_token(rsa_key, issuer=_ISSUER, audience=_CLIENT_ID,
                               subject="sub-123", nonce=handshake.nonce)

    with pytest.raises(oidc.OidcError, match="state"):
        _complete_with_token(monkeypatch, handshake, cookie, id_token, state="wrong-state")


def test_idp_error_param_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    with pytest.raises(oidc.OidcError, match="access_denied"):
        oidc.complete_login(
            query_params={"error": "access_denied", "state": handshake.state},
            handshake_cookie=cookie, base_url=_BASE_URL,
        )


def test_missing_code_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    with pytest.raises(oidc.OidcError, match="code"):
        oidc.complete_login(
            query_params={"state": handshake.state},
            handshake_cookie=cookie, base_url=_BASE_URL,
        )


def test_tampered_handshake_cookie_is_rejected(monkeypatch, rsa_key):
    _handshake, cookie = _start_login(monkeypatch, rsa_key)
    tampered = cookie[:-4] + "aaaa"
    with pytest.raises(oidc.OidcError):
        oidc.complete_login(
            query_params={"code": "x", "state": "x"},
            handshake_cookie=tampered, base_url=_BASE_URL,
        )


def test_missing_handshake_cookie_is_rejected(monkeypatch, rsa_key):
    with pytest.raises(oidc.OidcError):
        oidc.complete_login(
            query_params={"code": "x", "state": "x"},
            handshake_cookie=None, base_url=_BASE_URL,
        )


def test_expired_handshake_is_rejected(monkeypatch, rsa_key):
    handshake, cookie = _start_login(monkeypatch, rsa_key)
    old_handshake = oidc.Handshake(
        flow=handshake.flow, org_id=handshake.org_id, state=handshake.state,
        nonce=handshake.nonce, code_verifier=handshake.code_verifier,
        invite_token=handshake.invite_token, demo=handshake.demo,
        issued_at=int(time.time()) - oidc.HANDSHAKE_TTL_SECONDS - 1,
    )
    expired_cookie = oidc._pack_handshake(old_handshake)

    with pytest.raises(oidc.OidcError, match="expired"):
        oidc.complete_login(
            query_params={"code": "x", "state": handshake.state},
            handshake_cookie=expired_cookie, base_url=_BASE_URL,
        )


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def test_google_login_unavailable_without_client_credentials(monkeypatch):
    monkeypatch.delenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID", raising=False)
    monkeypatch.delenv("MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET", raising=False)
    assert oidc.google_login_available() is False
    with pytest.raises(oidc.OidcError):
        oidc.start_google_login(_BASE_URL)


def test_stable_user_id_is_deterministic_and_issuer_scoped():
    """Same (issuer, sub) always resolves to the same user_id (a returning
    user re-authenticating must map to the same account), and different
    issuers with a coincidentally-equal subject must NOT collide - two
    different IdPs are two different trust domains."""
    a = oidc.stable_user_id("https://idp-one.example.com", "12345")
    b = oidc.stable_user_id("https://idp-one.example.com", "12345")
    c = oidc.stable_user_id("https://idp-two.example.com", "12345")

    assert a == b
    assert a != c
