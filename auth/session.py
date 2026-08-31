"""MortemTrace's own signed session cookie, and the CSRF token derived
from it.

Deliberately not the IdP's ID token: an ID token is a one-time proof of
authentication, scoped to the moment of login, not a bearer credential
meant to be replayed on every request for hours. This reuses the same
HMAC-SHA256 sign-and-compare pattern data/scope_store.py's
sign_claim/verify_claim already implements correctly, rather than a
second, different primitive for a structurally identical problem -
"prove this value was minted by us and hasn't expired, with no
server-side session store" - both here and there.

The cookie carries user_id ONLY - never org_id or role. Which
organizations a session may act as, and with what role, is resolved
fresh from live Membership rows on every request (see console/ui.py's
principal dependency). That is what makes revoking a membership take
effect on the user's very next request rather than only once this
cookie happens to expire.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("mortemtrace.auth.session")

_SESSION_SECRET_ENV = "MORTEMTRACE_SESSION_SECRET"
_DEV_FALLBACK_SECRET = "dev-only-insecure-session-secret-do-not-deploy"
_DEFAULT_SESSION_TTL_SECONDS = 12 * 3600


class InvalidSession(Exception):
    """Session cookie missing, malformed, expired, or its signature does
    not verify. Callers map this to a redirect to /login, not a 500."""


def _secret() -> bytes:
    secret = os.environ.get(_SESSION_SECRET_ENV)
    if not secret:
        logger.warning(
            "%s not set; using an insecure development default. "
            "Never deploy this state - set a real secret via Secret Manager.",
            _SESSION_SECRET_ENV,
        )
        secret = _DEV_FALLBACK_SECRET
    return secret.encode("utf-8")


def _session_ttl_seconds() -> int:
    raw = os.environ.get("MORTEMTRACE_SESSION_MAX_AGE")
    if not raw:
        return _DEFAULT_SESSION_TTL_SECONDS
    try:
        return int(raw)
    except ValueError:
        logger.warning("MORTEMTRACE_SESSION_MAX_AGE=%r is not an integer; using default", raw)
        return _DEFAULT_SESSION_TTL_SECONDS


@dataclass(frozen=True)
class Session:
    user_id: str
    issued_at: int
    expires_at: int


def _sign(user_id: str, issued_at: int, expires_at: int) -> str:
    message = f"{user_id}|{issued_at}|{expires_at}".encode()
    return hmac.new(_secret(), message, hashlib.sha256).hexdigest()


def mint_session(user_id: str) -> str:
    """Returns the opaque cookie value: user_id|issued_at|expires_at|sig."""
    issued_at = int(time.time())
    expires_at = issued_at + _session_ttl_seconds()
    signature = _sign(user_id, issued_at, expires_at)
    return f"{user_id}|{issued_at}|{expires_at}|{signature}"


def verify_session(cookie_value: Optional[str]) -> Session:
    if not cookie_value:
        raise InvalidSession("no session cookie")
    parts = cookie_value.split("|")
    if len(parts) != 4:
        raise InvalidSession("malformed session cookie")
    user_id, issued_at_raw, expires_at_raw, signature = parts
    try:
        issued_at, expires_at = int(issued_at_raw), int(expires_at_raw)
    except ValueError:
        raise InvalidSession("malformed session cookie") from None

    expected = _sign(user_id, issued_at, expires_at)
    if not hmac.compare_digest(expected, signature):
        raise InvalidSession("session signature does not verify")
    if time.time() > expires_at:
        raise InvalidSession("session expired")
    if not user_id:
        raise InvalidSession("session carries no user_id")
    return Session(user_id=user_id, issued_at=issued_at, expires_at=expires_at)


# --------------------------------------------------------------------------
# CSRF
#
# The session cookie is SameSite=Strict, which already blocks a
# cross-site POST from carrying it in most browsers - but the OAuth
# handshake cookie (auth/oidc.py) must be SameSite=Lax to survive the
# IdP's redirect back to us, so relying on cookie policy alone across
# every POST route would be uneven. A request-shape-independent token
# gives every state-changing console route the same guarantee.
# --------------------------------------------------------------------------

def csrf_token(session: Session) -> str:
    """Deterministic per-session token - no server-side storage needed,
    consistent with this deployment's "no in-memory state survives a
    Cloud Run instance" rule."""
    message = f"csrf|{session.user_id}|{session.issued_at}".encode()
    return hmac.new(_secret(), message, hashlib.sha256).hexdigest()


def verify_csrf(session: Session, presented: Optional[str]) -> bool:
    if not presented:
        return False
    return hmac.compare_digest(csrf_token(session), presented)
