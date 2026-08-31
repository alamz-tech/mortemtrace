"""OIDC client: Google Sign-In (fixed, always available) and any
organization's own IdP (Entra ID, Okta, Auth0, or another OIDC-compliant
provider - resolved dynamically per-org from Organization.sso).

Built on Authlib's OAuth2Session plus joserfc directly, rather than
Authlib's Starlette-integration wrapper: that wrapper expects a
server-side or itsdangerous-signed `request.session` to stash the PKCE
verifier and state between the redirect and the callback, which would
mean running a second, differently-shaped session mechanism alongside
auth/session.py's existing one. Instead, handshake state (state, nonce,
PKCE verifier, which flow, an optional pending invitation token) is
packed into one short-lived, HMAC-signed cookie, using the same
sign-and-compare primitive auth/session.py and data/scope_store.py
already use - one mechanism, not two.

joserfc, not the older authlib.jose: Authlib 1.7 deprecates jose in
favor of joserfc (its own declared dependency), and this is exactly the
new-project code that should not start on a module already flagged for
removal.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import logging
import os
import secrets
import socket
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import requests
from authlib.integrations.requests_client import OAuth2Session
from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

logger = logging.getLogger("mortemtrace.auth.oidc")

GOOGLE_ISSUER = "https://accounts.google.com"

_GOOGLE_CLIENT_ID_ENV = "MORTEMTRACE_GOOGLE_OAUTH_CLIENT_ID"
_GOOGLE_CLIENT_SECRET_ENV = "MORTEMTRACE_GOOGLE_OAUTH_CLIENT_SECRET"
_OIDC_CLIENT_SECRETS_ENV = "MORTEMTRACE_OIDC_CLIENT_SECRETS"  # JSON {secret_ref: secret}

# Shares auth/session.py's secret rather than introducing a third one:
# both are "sign a short-lived value, verify it later, no server-side
# store" - the same trust root MortemTrace's own cookies already use.
_HANDSHAKE_SECRET_ENV = "MORTEMTRACE_SESSION_SECRET"
_DEV_FALLBACK_SECRET = "dev-only-insecure-session-secret-do-not-deploy"
HANDSHAKE_TTL_SECONDS = 600  # long enough for a slow IdP login page, short-lived by design

_DISCOVERY_CACHE_TTL_SECONDS = 3600
_discovery_cache: dict[str, tuple[float, dict]] = {}
_HTTP_TIMEOUT_SECONDS = 10


class OidcError(Exception):
    """The IdP redirect could not be verified, or OIDC/SSO is not
    configured for what was requested. Callers map this to a clear login
    error, not a 500 - most causes here are configuration or an expired
    handshake, not a server fault."""


def _secret() -> bytes:
    secret = os.environ.get(_HANDSHAKE_SECRET_ENV)
    if not secret:
        secret = _DEV_FALLBACK_SECRET
    return secret.encode("utf-8")


_DISCOVERY_CACHE_MAX_ENTRIES = 256


def _reject_non_public_host(hostname: str) -> None:
    """Refuses to resolve/fetch a hostname whose DNS answer is a private,
    loopback, link-local, or otherwise internal address.

    Found in a security self-review, not exploited in production:
    `issuer` for org SSO is admin-supplied (anyone can self-register an
    org and configure "their own" SSO issuer - see console/ui.py's
    /orgs/{org_id}/sso route), and this function's only caller made a
    plain requests.get() against it with no host restriction at all -
    the textbook shape of SSRF, reachable by any self-registered user,
    against Cloud Run's own metadata server among other targets.

    Resolves via DNS rather than trusting the hostname string alone,
    since a hostname that looks public can still resolve to an internal
    address (attacker-controlled DNS, or DNS rebinding between this
    check and the actual request) - checking the string would miss
    exactly the attack this exists to stop. Rejects if ANY resolved
    address is non-public, not just the first, since a multi-A-record
    response only needs one internal answer to matter.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise OidcError(f"could not resolve issuer host {hostname!r}: {exc}") from exc

    for _family, _, _, _, sockaddr in infos:
        raw_ip = sockaddr[0]
        try:
            ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if (
            ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
        ):
            raise OidcError(
                f"issuer host {hostname!r} resolves to a non-public address "
                f"({raw_ip}) - refusing to fetch it"
            )


def _validated_https_url(url: str, *, what: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise OidcError(f"{what} must be an https:// URL, got {url!r}")
    if not parsed.hostname:
        raise OidcError(f"{what} has no host: {url!r}")
    _reject_non_public_host(parsed.hostname)
    return url


def _safe_get(url: str, *, what: str) -> requests.Response:
    """The one place this module makes an outbound HTTP request to an
    admin-supplied host. Validates the URL, then explicitly refuses to
    follow redirects: `_reject_non_public_host` only checked the address
    behind the URL we were given, and requests() follows redirects by
    default - so a validated public host redirecting to an internal one
    would otherwise sail straight past this check on the second hop.
    A real OIDC discovery/JWKS endpoint has no legitimate reason to
    redirect; if one does, that's a configuration problem for whoever
    owns that IdP to fix by pointing at the canonical URL, not something
    to follow blindly.
    """
    _validated_https_url(url, what=what)
    response = requests.get(url, timeout=_HTTP_TIMEOUT_SECONDS, allow_redirects=False)
    if response.is_redirect:
        raise OidcError(f"{what} at {url!r} returned a redirect, which is not followed")
    response.raise_for_status()
    return response


def _discovery_document(issuer: str) -> dict:
    nowt = time.time()
    cached = _discovery_cache.get(issuer)
    if cached and cached[0] > nowt:
        return cached[1]
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    document = _safe_get(url, what="OIDC discovery document").json()
    if len(_discovery_cache) >= _DISCOVERY_CACHE_MAX_ENTRIES:
        # Bounded because `issuer` is admin-supplied per-org input, not a
        # fixed set of values - an unbounded cache keyed on it would let
        # a stream of distinct issuer strings grow this dict without
        # limit, the same class of problem the rate limiter's own
        # max_keys guards against.
        oldest_key = min(_discovery_cache, key=lambda k: _discovery_cache[k][0])
        del _discovery_cache[oldest_key]
    _discovery_cache[issuer] = (nowt + _DISCOVERY_CACHE_TTL_SECONDS, document)
    return document


def _jwks(jwks_uri: str) -> KeySet:
    response = _safe_get(jwks_uri, what="JWKS")
    return KeySet.import_key_set(response.json())


# --------------------------------------------------------------------------
# Handshake cookie: state carried between the redirect-to-IdP and the
# callback. Short-lived, its own cookie, never merged into the long-lived
# session cookie.
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Handshake:
    flow: str                          # "google" or "org"
    org_id: Optional[str]
    state: str
    nonce: str
    code_verifier: str
    invite_token: Optional[str]
    demo: bool
    issued_at: int


def _pack_handshake(h: Handshake) -> str:
    payload = json.dumps({
        "flow": h.flow, "org_id": h.org_id, "state": h.state, "nonce": h.nonce,
        "code_verifier": h.code_verifier, "invite_token": h.invite_token,
        "demo": h.demo, "issued_at": h.issued_at,
    }, separators=(",", ":"))
    signature = hmac.new(_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{signature}"


def _unpack_handshake(cookie_value: Optional[str]) -> Handshake:
    if not cookie_value or "." not in cookie_value:
        raise OidcError("missing or malformed OAuth handshake cookie - try signing in again")
    payload, _, signature = cookie_value.rpartition(".")
    expected = hmac.new(_secret(), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise OidcError("OAuth handshake cookie signature does not verify")
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise OidcError("OAuth handshake cookie is not valid JSON") from exc
    if time.time() - data.get("issued_at", 0) > HANDSHAKE_TTL_SECONDS:
        raise OidcError("sign-in took too long and the handshake expired - try again")
    return Handshake(**data)


# --------------------------------------------------------------------------
# Google Sign-In
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class GoogleClientConfig:
    client_id: str
    client_secret: str


def google_client_config() -> Optional[GoogleClientConfig]:
    client_id = os.environ.get(_GOOGLE_CLIENT_ID_ENV)
    client_secret = os.environ.get(_GOOGLE_CLIENT_SECRET_ENV)
    if not client_id or not client_secret:
        return None
    return GoogleClientConfig(client_id=client_id, client_secret=client_secret)


def google_login_available() -> bool:
    return google_client_config() is not None


# --------------------------------------------------------------------------
# Per-organization SSO
# --------------------------------------------------------------------------

def _oidc_client_secret(org_id: str, secret_ref: str) -> Optional[str]:
    """Looks up a per-org SSO client secret.

    Regression, found in a security self-review: MORTEMTRACE_OIDC_CLIENT_SECRETS
    is one flat table shared by every tenant, and this used to be looked
    up by `secret_ref` alone - a value an org's own admin chooses on the
    SSO settings form (console/ui.py's /orgs/{org_id}/sso route), with no
    check that the ref they typed actually belongs to their org. Any
    self-registered admin (org creation is open to anyone with a Google
    account) could type in another organization's ref and have MortemTrace
    present that organization's real IdP client secret to whatever
    `issuer`/token endpoint they configured - a live, working credential
    handed to an attacker's own server.

    The fix is structural, not a permission check: the lookup key is now
    ALWAYS built here, from `org_id` supplied by the caller (which comes
    from the signed OAuth handshake - see complete_login - never from
    anything Firestore's `sso` document says about itself), concatenated
    with whatever suffix the admin chose. An org can therefore only ever
    reference secrets stored under ITS OWN org_id prefix, structurally -
    there is no `secret_ref` value an admin could type that resolves to a
    different tenant's entry, because the org_id half is never something
    their input controls.

    Operators populating MORTEMTRACE_OIDC_CLIENT_SECRETS out of band
    (there is no in-app write path - see the secret's own docs) must key
    each entry as f"{org_id}:{ref}", matching this lookup.
    """
    raw = os.environ.get(_OIDC_CLIENT_SECRETS_ENV, "{}")
    try:
        table = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("%s is not valid JSON", _OIDC_CLIENT_SECRETS_ENV)
        return None
    if not isinstance(table, dict):
        return None
    return table.get(f"{org_id}:{secret_ref}")


# --------------------------------------------------------------------------
# Starting a login
# --------------------------------------------------------------------------

def _redirect_uri(base_url: str) -> str:
    return base_url.rstrip("/") + "/auth/callback"


def start_google_login(base_url: str, *, invite_token: Optional[str] = None,
                        demo: bool = False) -> tuple[str, str]:
    """Returns (authorization_url, handshake_cookie_value)."""
    config = google_client_config()
    if config is None:
        raise OidcError(
            f"Google sign-in is not configured ({_GOOGLE_CLIENT_ID_ENV}/"
            f"{_GOOGLE_CLIENT_SECRET_ENV} are not set)"
        )
    return _start_login(
        issuer=GOOGLE_ISSUER, client_id=config.client_id, base_url=base_url,
        flow="google", org_id=None, invite_token=invite_token, demo=demo,
    )


def start_org_login(org_id: str, sso: dict, base_url: str, *,
                     invite_token: Optional[str] = None) -> tuple[str, str]:
    """Returns (authorization_url, handshake_cookie_value) for one org's
    configured IdP."""
    return _start_login(
        issuer=sso["issuer"], client_id=sso["client_id"], base_url=base_url,
        flow="org", org_id=org_id, invite_token=invite_token, demo=False,
    )


def _start_login(*, issuer: str, client_id: str, base_url: str, flow: str,
                  org_id: Optional[str], invite_token: Optional[str], demo: bool) -> tuple[str, str]:
    document = _discovery_document(issuer)
    # code_challenge_method must be set HERE, on the client itself - Authlib's
    # create_authorization_url() only attaches a code_challenge to the
    # authorization URL when self.code_challenge_method == "S256"; passing
    # code_verifier to that call alone does nothing without it. Missing this
    # produced a real, live failure: the authorization URL went out with no
    # code_challenge at all, so Google had nothing on file to check the
    # code_verifier this same flow later sent at token-exchange time against,
    # and correctly rejected it (invalid_grant: "code_verifier or verifier is
    # not needed" - Google's way of saying no PKCE challenge was registered
    # for this authorization). Confirmed by constructing both a client with
    # and without this argument and inspecting the resulting URL directly.
    session = OAuth2Session(client_id, scope="openid email profile", code_challenge_method="S256")
    code_verifier = secrets.token_urlsafe(48)
    nonce = secrets.token_urlsafe(24)
    uri, state = session.create_authorization_url(
        document["authorization_endpoint"],
        redirect_uri=_redirect_uri(base_url),
        code_verifier=code_verifier,
        nonce=nonce,
    )
    handshake = Handshake(
        flow=flow, org_id=org_id, state=state, nonce=nonce, code_verifier=code_verifier,
        invite_token=invite_token, demo=demo, issued_at=int(time.time()),
    )
    return uri, _pack_handshake(handshake)


# --------------------------------------------------------------------------
# Completing a login
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    email: str
    display_name: str
    invite_token: Optional[str]
    demo: bool


def complete_login(*, query_params: dict, handshake_cookie: Optional[str], base_url: str) -> VerifiedIdentity:
    """Verifies the IdP's redirect and returns the caller's verified
    identity, or raises OidcError. Every check here fails closed:
    state mismatch, IdP-reported error, missing code, a client secret
    that isn't configured, a signature that doesn't verify against the
    IdP's own published keys, a wrong issuer/audience, or a nonce that
    doesn't match what this handshake started with.
    """
    handshake = _unpack_handshake(handshake_cookie)

    presented_state = query_params.get("state")
    if not presented_state or not hmac.compare_digest(str(presented_state), handshake.state):
        raise OidcError("OAuth state does not match - possible CSRF, or the handshake expired")

    error = query_params.get("error")
    if error:
        raise OidcError(f"identity provider returned an error: {error}")

    code = query_params.get("code")
    if not code:
        raise OidcError("no authorization code in callback")

    if handshake.flow == "google":
        config = google_client_config()
        if config is None:
            raise OidcError("Google sign-in is not configured")
        issuer, client_id, client_secret = GOOGLE_ISSUER, config.client_id, config.client_secret
    elif handshake.flow == "org":
        from data import scope_store  # deferred: scope_store imports auth-adjacent modules too

        org = scope_store.get_organization(handshake.org_id) if handshake.org_id else None
        if org is None or not org.get("sso"):
            raise OidcError("this organization's SSO configuration is missing or was removed mid-login")
        sso = org["sso"]
        # handshake.org_id, not anything read from `sso` or `org` -
        # see _oidc_client_secret's docstring for why the org half of
        # this lookup must come from code, not from stored data.
        secret = _oidc_client_secret(handshake.org_id, sso["client_secret_ref"])
        if secret is None:
            raise OidcError(f"no secret configured for {sso['client_secret_ref']!r}")
        issuer, client_id, client_secret = sso["issuer"], sso["client_id"], secret
    else:
        raise OidcError(f"unknown OAuth flow {handshake.flow!r}")

    document = _discovery_document(issuer)
    session = OAuth2Session(client_id, client_secret)
    token = session.fetch_token(
        document["token_endpoint"],
        code=code,
        code_verifier=handshake.code_verifier,
        redirect_uri=_redirect_uri(base_url),
    )

    id_token = token.get("id_token")
    if not id_token:
        raise OidcError("token response carried no id_token")

    keys = _jwks(document["jwks_uri"])
    try:
        decoded = jwt.decode(id_token, keys)
        registry = JWTClaimsRegistry(
            iss={"essential": True, "values": [issuer, issuer.rstrip("/")]},
            aud={"essential": True, "value": client_id},
            exp={"essential": True},
        )
        registry.validate(decoded.claims)
    except JoseError as exc:
        raise OidcError(f"ID token failed verification: {exc}") from exc

    claims = decoded.claims
    if claims.get("nonce") != handshake.nonce:
        raise OidcError("ID token nonce does not match - possible token replay")

    email = claims.get("email")
    if not email:
        raise OidcError("ID token carried no email claim")
    if claims.get("email_verified") is False:
        raise OidcError("identity provider reports this email address as unverified")

    return VerifiedIdentity(
        issuer=str(claims["iss"]), subject=str(claims["sub"]), email=str(email).lower(),
        display_name=str(claims.get("name") or email),
        invite_token=handshake.invite_token, demo=handshake.demo,
    )


def stable_user_id(issuer: str, subject: str) -> str:
    """sha256(issuer|sub), truncated - stable across logins, keyed off
    values only the IdP controls. Never email: an IdP can reassign an
    email address to a different person, which would otherwise let a new
    hire silently inherit a departed employee's MortemTrace identity."""
    return hashlib.sha256(f"{issuer}|{subject}".encode()).hexdigest()[:24]
