"""Resolves the calling principal, and with it the tenant a request is
allowed to act as.

Three credential types, deliberately kept conceptually separate rather
than layered on top of one another - a webhook must never authenticate
as a human, and a human's browser session must never double as a
machine credential:

  1. Bearer API token - MACHINE callers only (`/ingest`, `/watcher/sweep`:
     operator scripts, non-interactive integrations). MORTEMTRACE_API_TOKENS
     holds a JSON object of {"<sha256-hex of token>": {"org_ids": [...],
     "subject": "..."}}. Only digests are configured, never the tokens
     themselves. This is no longer how a human reaches the console - see
     auth/session.py and auth/oidc.py for that.

  2. Google-issued OIDC ID token (Pub/Sub push authentication - a service
     account proving *itself*, not a person). Verified for signature,
     expiry, audience AND issuing service-account email - see
     verify_google_oidc(). Audience alone is not sufficient: any Google
     principal can mint a token with an arbitrary `aud`. This is a
     different use of "Google OIDC" from human sign-in in auth/oidc.py -
     that one verifies a *person's* Google identity against
     accounts.google.com; this one verifies a *service account's*
     identity for a Pub/Sub push subscription, and the two are not
     interchangeable.

  3. Session cookie - HUMAN callers (the console). Minted by
     auth/session.py after a real OIDC login (auth/oidc.py) proves who
     the person is; which org(s) they may act as, and with what role, is
     then resolved server-side from live Membership rows (data/
     scope_store.py), never from anything the cookie itself carries.

Default posture is closed. With no tokens configured, no session, and
demo mode off, every authenticated route returns 401 rather than falling
back to a default tenant. MORTEMTRACE_ALLOW_ANONYMOUS_DEMO=1 is a legacy
escape hatch, superseded by the public_demo_auto_join organization flag
(console/ui.py's "View live demo" path) which grants a real,
individually-identified session instead of no identity at all - kept
only so an existing deployment that set the old flag does not silently
change behavior, and still logs the same loud startup warning.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger("mortemtrace.auth")

_TOKENS_ENV = "MORTEMTRACE_API_TOKENS"
_ANON_DEMO_ENV = "MORTEMTRACE_ALLOW_ANONYMOUS_DEMO"
_DEMO_ORG_ENV = "MORTEMTRACE_DEMO_ORG"
_PUSH_SA_ENV = "MORTEMTRACE_PUSH_SERVICE_ACCOUNT"
_PUSH_AUDIENCE_ENV = "MORTEMTRACE_PUSH_AUDIENCE"

# org_id lands in a Firestore document path (tenants/{org_id}/...). A
# slash there silently re-points the write at a different path depth -
# Firestore treats document ids as slash-separated path segments - so the
# character class is deliberately narrow rather than "anything without a
# slash".
_ORG_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

METHOD_API_TOKEN = "api_token"  # noqa: S105 - an auth-method label, not a secret
METHOD_GOOGLE_OIDC = "google_oidc"
METHOD_ANONYMOUS_DEMO = "anonymous_demo"


class AuthenticationError(Exception):
    """No usable credential. Maps to HTTP 401."""


class AuthorizationError(Exception):
    """Valid credential, but not for the tenant being requested. HTTP 403."""


class InvalidOrgId(Exception):
    """org_id is not a legal tenant identifier. HTTP 400."""


def validate_org_id(org_id: str) -> str:
    """Raises InvalidOrgId unless `org_id` is safe to use as a Firestore
    path segment. Called on every path that can introduce an org_id,
    including trusted ones - a malformed value from configuration is as
    damaging as one from a request."""
    if not isinstance(org_id, str) or not _ORG_ID_RE.match(org_id):
        raise InvalidOrgId(f"invalid org_id: {org_id!r}")
    return org_id


@dataclass(frozen=True)
class Principal:
    """Who is calling, and which tenants they may act as.

    `role_by_org` is populated only for session-backed (human) principals,
    resolved fresh from live Membership rows on every request - never
    cached in a cookie. It is empty for API-token/service principals,
    which have no concept of a role; `require_role` on one of those
    always denies, which is correct: an admin-only action should never be
    reachable by a machine credential regardless of which org_ids it grants.
    """

    org_ids: frozenset[str]
    subject: str
    method: str
    user_id: Optional[str] = None
    role_by_org: dict[str, str] = field(default_factory=dict)

    def authorize_org(self, requested: Optional[str]) -> str:
        """Returns the tenant this request may act as.

        `requested` is caller-supplied and never trusted: it can only
        *select among* tenants the credential already grants, never
        introduce a new one. When omitted, a single-tenant principal
        resolves unambiguously; a multi-tenant principal must say which.
        """
        if requested is None:
            if len(self.org_ids) == 1:
                return next(iter(self.org_ids))
            if not self.org_ids:
                raise AuthorizationError("this credential is not a member of any organization")
            raise AuthorizationError(
                "this credential is valid for multiple tenants; specify org_id explicitly"
            )

        validate_org_id(requested)
        if requested not in self.org_ids:
            # Deliberately does not distinguish "no such tenant" from
            # "not yours" - that difference is a tenant-enumeration oracle.
            raise AuthorizationError("credential is not valid for the requested tenant")
        return requested

    def require_role(self, org_id: str, role: str) -> None:
        """Raises AuthorizationError unless this principal holds exactly
        `role` in `org_id`. Used for admin-gated actions (invite a user,
        configure SSO, change a role) - re-checked here against whatever
        was resolved server-side moments ago, never against a claim the
        caller made about themselves."""
        if self.role_by_org.get(org_id) != role:
            raise AuthorizationError(f"this action requires the {role!r} role in {org_id}")


# --------------------------------------------------------------------------
# API tokens
# --------------------------------------------------------------------------

def _load_token_table() -> dict[str, dict]:
    raw = os.environ.get(_TOKENS_ENV)
    if not raw:
        return {}
    try:
        table = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("%s is not valid JSON; treating as empty (all token auth will fail)", _TOKENS_ENV)
        return {}
    if not isinstance(table, dict):
        logger.error("%s must be a JSON object of digest -> {org_ids, subject}", _TOKENS_ENV)
        return {}
    return table


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _principal_from_token(token: str) -> Optional[Principal]:
    """Constant-time lookup over the configured digests.

    A plain `table.get(digest)` would be a dict lookup on a secret-derived
    key, which is fine in practice, but comparing every entry with
    compare_digest keeps the match itself timing-independent and costs
    nothing at this table size.
    """
    presented = _hash_token(token)
    for configured_digest, entry in _load_token_table().items():
        if not hmac.compare_digest(presented, str(configured_digest)):
            continue
        if not isinstance(entry, dict):
            logger.error("malformed token table entry for a configured digest; rejecting")
            return None
        org_ids = entry.get("org_ids") or ([entry["org_id"]] if entry.get("org_id") else [])
        if not org_ids:
            logger.error("token table entry grants no org_ids; rejecting")
            return None
        try:
            validated = frozenset(validate_org_id(o) for o in org_ids)
        except InvalidOrgId:
            logger.error("token table entry contains an invalid org_id; rejecting")
            return None
        return Principal(
            org_ids=validated,
            subject=str(entry.get("subject") or "api-token"),
            method=METHOD_API_TOKEN,
        )
    return None


# --------------------------------------------------------------------------
# Anonymous demo mode
# --------------------------------------------------------------------------

def anonymous_demo_enabled() -> bool:
    return os.environ.get(_ANON_DEMO_ENV) == "1"


def demo_org_id() -> Optional[str]:
    org = os.environ.get(_DEMO_ORG_ENV)
    if not org:
        return None
    try:
        return validate_org_id(org)
    except InvalidOrgId:
        logger.error("%s is not a valid org_id; anonymous demo mode disabled", _DEMO_ORG_ENV)
        return None


def _anonymous_principal() -> Optional[Principal]:
    if not anonymous_demo_enabled():
        return None
    org = demo_org_id()
    if org is None:
        return None
    return Principal(org_ids=frozenset({org}), subject="anonymous-demo", method=METHOD_ANONYMOUS_DEMO)


def warn_if_open() -> None:
    """Called once at service startup so an accidentally-open deployment
    is visible in the first page of logs rather than discovered later."""
    if anonymous_demo_enabled():
        logger.warning(
            "%s=1: unauthenticated requests are accepted and act as tenant %r. "
            "This is intended only for the recorded demo - never enable it on a "
            "deployment holding real tenant data.",
            _ANON_DEMO_ENV, demo_org_id(),
        )
    elif not _load_token_table():
        logger.warning(
            "No API tokens configured (%s is empty) and anonymous demo mode is off - "
            "every authenticated route will return 401. Set %s to enable access.",
            _TOKENS_ENV, _TOKENS_ENV,
        )


_RUNNING_ON_CLOUD_RUN_ENV = "K_SERVICE"  # set automatically by Cloud Run, never by a developer


def is_production_runtime() -> bool:
    return bool(os.environ.get(_RUNNING_ON_CLOUD_RUN_ENV))


def enforce_production_secrets() -> None:
    """Refuses to start if a real signing secret is missing on Cloud Run.

    data/scope_store.py, auth/session.py, and auth/oidc.py's HMAC
    secrets each fall back to a hardcoded, publicly-known constant when
    their env var is unset, logging a warning and continuing - the right
    behavior for a laptop running `uvicorn --reload` with no Secret
    Manager access, and a genuine hole on a real deployment: if
    MORTEMTRACE_SESSION_SECRET (say) were ever missing - a Secret
    Manager IAM regression, a partially-applied deploy, a new region -
    the service would start up FINE and silently accept any session
    cookie forged with a secret published in this repository's own
    source. Found in a security self-review, not exploited in
    production - the per-request fallback path never actually fired on
    the live deployment.

    Checked once, here, at process startup rather than per-request in
    each `_secret()`: a hard crash on a missing secret is loud and
    obvious in Cloud Run's own deploy/revision logs, exactly where an
    operator would look after a bad deploy - a 401 or a subtly-forgeable
    session on whichever request happened to call _secret() first would
    not be.

    Deliberately does not check MORTEMTRACE_OIDC_CLIENT_SECRETS: that
    one is legitimately empty until an org configures its own SSO (see
    infra/create_secrets.sh), not a secret every deployment needs from
    the start.
    """
    if not is_production_runtime():
        return  # local/dev: the per-module dev fallback is the correct behavior here

    from auth import session as session_module
    from data import scope_store

    missing = [
        env_name for env_name in (
            scope_store._CLAIM_SECRET_ENV,
            session_module._SESSION_SECRET_ENV,
        )
        if not os.environ.get(env_name)
    ]
    if missing:
        raise RuntimeError(
            f"Refusing to start on Cloud Run with {missing} unset - each would silently "
            "fall back to a hardcoded, publicly-known secret, making every session/claim "
            "forgeable. Set them via Secret Manager (see infra/create_secrets.sh) and "
            "verify the runtime service account can actually read them."
        )


# --------------------------------------------------------------------------
# Entry point used by the HTTP layers
# --------------------------------------------------------------------------

def authenticate_session(cookie_value: Optional[str]) -> Principal:
    """Resolves a Principal from a MortemTrace session cookie (human,
    browser callers only).

    Membership is looked up fresh from Firestore on every call, not
    cached: unlike the registry's agent-scope cache (hit many times per
    request, for records that change only when someone publishes a new
    agent version), this runs once per HTTP request, and a revoked
    membership must stop working on the very next request a person
    makes, not after some cache TTL elapses.

    Raises AuthenticationError if the cookie is missing/invalid/expired.
    A valid session belonging to a user with zero active memberships is
    NOT an error here - `Principal.org_ids` is simply empty, and the
    caller (console/ui.py) sends them to org creation/onboarding rather
    than a 401, since they are a real, authenticated person who simply
    has nowhere to go yet.
    """
    from auth import session as session_module
    from data import scope_store

    try:
        verified = session_module.verify_session(cookie_value)
    except session_module.InvalidSession as exc:
        raise AuthenticationError(str(exc)) from exc

    memberships = scope_store.list_memberships_for_user(verified.user_id)
    role_by_org = {m["org_id"]: m["role"] for m in memberships}
    user = scope_store.get_user(verified.user_id)
    subject = user["email"] if user else verified.user_id

    return Principal(
        org_ids=frozenset(role_by_org.keys()), subject=subject, method="session",
        user_id=verified.user_id, role_by_org=role_by_org,
    )


def authenticate(authorization_header: Optional[str]) -> Principal:
    """Resolves a Principal from an Authorization header.

    Raises AuthenticationError when no credential is usable. Callers map
    that to 401; they must never fall back to a default tenant.
    """
    if authorization_header:
        scheme, _, token = authorization_header.partition(" ")
        if scheme.lower() == "bearer" and token:
            principal = _principal_from_token(token.strip())
            if principal is not None:
                return principal
            # An explicitly-presented-but-invalid token is never silently
            # downgraded to the anonymous path, even in demo mode: that
            # would mask a misconfigured client as a working one.
            raise AuthenticationError("invalid bearer token")
        raise AuthenticationError("unsupported Authorization scheme; expected Bearer")

    anonymous = _anonymous_principal()
    if anonymous is not None:
        return anonymous
    raise AuthenticationError("authentication required")


# --------------------------------------------------------------------------
# Google OIDC (Pub/Sub push)
# --------------------------------------------------------------------------

def verify_google_oidc(authorization_header: Optional[str]) -> Principal:
    """Verifies a Google-issued ID token for the Pub/Sub push route.

    Checks the issuing service account's email, not only the audience.
    Audience alone is not an authorization decision: any Google Cloud
    principal can mint an ID token with an arbitrary `aud` claim
    (`gcloud auth print-identity-token --audiences=...`), so a service
    that accepts "any Google-signed token naming my URL" accepts tokens
    from every Google account in existence.
    """
    import google.auth.transport.requests
    import google.oauth2.id_token

    if not authorization_header or not authorization_header.lower().startswith("bearer "):
        raise AuthenticationError("missing bearer token")

    audience = os.environ.get(_PUSH_AUDIENCE_ENV)
    if not audience:
        # Configuration error, not a caller error - surfaced distinctly so
        # it cannot be mistaken for "the pusher is unauthorized".
        raise RuntimeError(f"{_PUSH_AUDIENCE_ENV} is not configured")

    expected_sa = os.environ.get(_PUSH_SA_ENV)
    if not expected_sa:
        raise RuntimeError(f"{_PUSH_SA_ENV} is not configured")

    token = authorization_header.split(" ", 1)[1].strip()
    try:
        claims = google.oauth2.id_token.verify_oauth2_token(
            token, google.auth.transport.requests.Request(), audience=audience,
        )
    except Exception as exc:
        logger.warning("rejected push delivery with an unverifiable token: %s", exc)
        raise AuthenticationError("invalid push token") from exc

    email = claims.get("email")
    if not email or not hmac.compare_digest(str(email), expected_sa):
        logger.warning(
            "rejected push delivery: token verified but was issued to %r, not the "
            "configured pusher service account", email,
        )
        raise AuthenticationError("push token was not issued to the expected service account")

    if claims.get("email_verified") is False:
        raise AuthenticationError("push token carries an unverified email claim")

    return Principal(org_ids=frozenset(), subject=str(email), method=METHOD_GOOGLE_OIDC)


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------

class RateLimitExceeded(Exception):
    """Caller exceeded their request budget. HTTP 429."""


@dataclass
class _Bucket:
    tokens: float
    last_refill: float


class TokenBucketLimiter:
    """Per-key token bucket.

    Scope note, stated plainly because it changes what this control is
    worth: Cloud Run runs many instances and this state is per-process,
    so N instances allow up to N x `capacity`. That makes this a blast-
    radius bound on a single instance, not a global quota. A global limit
    needs shared state (Cloud Armor, or Redis) and is the right answer at
    real scale; this is the useful, dependency-free 80% - it stops a
    single client trivially exhausting an instance's Gemini budget.

    `max_keys` bounds memory: without it, a caller cycling tenant ids
    would grow the dict without limit, turning the rate limiter itself
    into the memory-exhaustion vector it exists to prevent.
    """

    def __init__(self, capacity: int, refill_per_second: float, *, max_keys: int = 10_000):
        self._capacity = float(capacity)
        self._refill = float(refill_per_second)
        self._max_keys = max_keys
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> None:
        """Consumes one token, or raises RateLimitExceeded."""
        nowt = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    self._evict_stalest(nowt)
                bucket = _Bucket(tokens=self._capacity, last_refill=nowt)
                self._buckets[key] = bucket

            elapsed = max(nowt - bucket.last_refill, 0.0)
            bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._refill)
            bucket.last_refill = nowt

            if bucket.tokens < 1.0:
                # A zero refill rate is a legal configuration (a hard cap
                # that never replenishes), so the retry hint has to handle
                # it rather than dividing by it - otherwise the limiter
                # raises ZeroDivisionError instead of rate-limiting, which
                # turns a throttle into a 500 on the hot path.
                if self._refill > 0:
                    detail = f"; retry in ~{(1.0 - bucket.tokens) / self._refill:.1f}s"
                else:
                    detail = ""
                raise RateLimitExceeded(f"rate limit exceeded{detail}")
            bucket.tokens -= 1.0

    def _evict_stalest(self, nowt: float) -> None:
        """Drops fully-refilled (idle) buckets first, since those carry no
        rate-limiting state worth keeping; falls back to the oldest."""
        idle = [k for k, b in self._buckets.items() if b.tokens >= self._capacity]
        for key in idle[: max(1, len(self._buckets) // 10)]:
            del self._buckets[key]
        if len(self._buckets) >= self._max_keys:
            oldest = min(self._buckets, key=lambda k: self._buckets[k].last_refill)
            del self._buckets[oldest]

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        logger.warning("%s=%r is not an integer; using default %d", name, raw, default)
        return default


def build_ingest_limiter() -> TokenBucketLimiter:
    """Ingest triggers a chain of paid model calls, so its budget is
    deliberately much tighter than a read-only console page view."""
    return TokenBucketLimiter(
        capacity=_int_env("MORTEMTRACE_INGEST_BURST", 20),
        refill_per_second=float(_int_env("MORTEMTRACE_INGEST_PER_MINUTE", 60)) / 60.0,
    )


def build_console_limiter() -> TokenBucketLimiter:
    return TokenBucketLimiter(
        capacity=_int_env("MORTEMTRACE_CONSOLE_BURST", 120),
        refill_per_second=float(_int_env("MORTEMTRACE_CONSOLE_PER_MINUTE", 600)) / 60.0,
    )


def build_webhook_limiter() -> TokenBucketLimiter:
    """Inbound webhooks are machine-generated, so a legitimate alerting
    source bursts higher than a human operator ever would. Still bounded:
    a webhook fans out into the same paid model calls /ingest does, so an
    unbounded (or compromised) source is the same cost-exhaustion vector.
    """
    return TokenBucketLimiter(
        capacity=_int_env("MORTEMTRACE_WEBHOOK_BURST", 100),
        refill_per_second=float(_int_env("MORTEMTRACE_WEBHOOK_PER_MINUTE", 300)) / 60.0,
    )


def build_pre_auth_limiter() -> TokenBucketLimiter:
    """For routes reachable before any credential is checked: Home Realm
    Discovery (console/ui.py's /auth/login/org), invitation-link
    redemption, and the webhook connector lookup (api/ingest.py) before
    it can resolve which connector's own rate limit applies.

    Found in a security self-review: each of these did a full Firestore
    collection scan (or, for the webhook route, at least one document
    read) with no rate limit at all - _CONSOLE_LIMITER/_INGEST_LIMITER
    are keyed by org_id and only reachable AFTER authentication succeeds,
    so a pre-auth route was unlimited by construction, not by oversight.
    Keyed by client IP rather than org_id, since there is no tenant
    identity yet at this point - see resolve_client_address.
    """
    return TokenBucketLimiter(
        capacity=_int_env("MORTEMTRACE_PRE_AUTH_BURST", 20),
        refill_per_second=float(_int_env("MORTEMTRACE_PRE_AUTH_PER_MINUTE", 60)) / 60.0,
    )


# --------------------------------------------------------------------------
# Client address resolution (X-Forwarded-For)
#
# Shared by build_pre_auth_limiter's callers and connectors/verification.py's
# ip_allowlist strategy - one implementation, not two, of a check that is
# easy to get subtly wrong (see the docstring below) and was actually
# wrong here once already.
# --------------------------------------------------------------------------

_TRUSTED_PROXY_HOPS_ENV = "MORTEMTRACE_TRUSTED_PROXY_HOPS"
_DEFAULT_TRUSTED_PROXY_HOPS = 1  # Cloud Run: one Google front-end hop


def _trusted_proxy_hops() -> int:
    raw = os.environ.get(_TRUSTED_PROXY_HOPS_ENV)
    if raw is None:
        return _DEFAULT_TRUSTED_PROXY_HOPS
    try:
        return max(0, int(raw))
    except ValueError:
        logger.warning(
            "%s=%r is not an integer; falling back to %d",
            _TRUSTED_PROXY_HOPS_ENV, raw, _DEFAULT_TRUSTED_PROXY_HOPS,
        )
        return _DEFAULT_TRUSTED_PROXY_HOPS


def resolve_client_address(headers) -> Optional[str]:
    """Resolves the caller's address from X-Forwarded-For, counting from
    the RIGHT, not the left.

    Reading the leftmost entry is the intuitive choice and the wrong one:
    Google's front end *appends* to any X-Forwarded-For the client
    already sent, so a caller who sends their own
    `X-Forwarded-For: <anything>` arrives as `<anything>, <their-real-ip>,
    <gfe>` - trusting position 0 hands them whatever they typed. Only the
    entries the infrastructure itself appended can be trusted, and those
    are at the right-hand end. `hops` is configurable because the correct
    value is a property of deployment topology (one Google front end by
    default; add one for a custom load balancer in front of it), and a
    wrong value fails closed (returns None) rather than silently trusting
    the wrong entry.

    Returns None - never raises - on a missing or too-short header, so
    every caller decides for itself what "no address" means for its own
    purpose (a rate limiter degrading open vs. an allowlist check failing
    closed are different, both legitimate, answers to the same gap).

    `headers` is duck-typed to whatever `.get(name, default)` a caller's
    header mapping supports - FastAPI's Request.headers and a plain dict
    (connectors/verification.py's raw dict of lower-cased header names)
    both satisfy this with no adapter needed.
    """
    forwarded = headers.get("x-forwarded-for", "")
    parts = [p.strip() for p in forwarded.split(",") if p.strip()]
    if not parts:
        return None

    hops = _trusted_proxy_hops()
    index = len(parts) - 1 - hops
    if index < 0:
        return None
    return parts[index]
