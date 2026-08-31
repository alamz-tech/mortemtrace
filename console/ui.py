"""R11's operator console: a server-rendered dashboard over the same
Firestore state every agent reads and writes through data/scope_store.py.
No frontend build step, no JS framework - plain Jinja2 templates
(console/templates/) plus a few lines of inline vanilla JS for the
live-feel polling on the dashboard and the GDPR clock countdown.

Identity: every request mints a fresh "console" claim via
scope_store.sign_claim() - nothing survives a Cloud Run instance, so
there is no reason to cache one across requests. This is a
registry-scope requirement for whoever seeds the agent registry
(infra/init_firestore.py) - flagged here and in the implementation
report:

    console @ 1.0.0 needs:
        read_scopes: [Collection.INCIDENTS, Collection.TIMELINE,
                      Collection.HYPOTHESES, Collection.CLASSIFICATION,
                      Collection.DRAFTS, Collection.CLOCKS,
                      Collection.AUDIT, Collection.SIGNALS, Collection.RUNS]
        write_scopes: [] (the console never writes)

Authentication: every route requires a credential (auth/identity.py) and
takes its tenant from the resulting Principal. The `org_id` query
parameter still exists, but it can now only *select* among tenants the
credential already grants - it can no longer introduce one.

This is the fix for what was the most serious defect in the system: the
console previously accepted `?org_id=` from anyone, on a service
deployed --allow-unauthenticated, and minted a valid claim for whatever
tenant was named. Every incident, timeline, draft, GDPR clock and audit
entry belonging to any tenant was readable by anyone holding the URL.
The data layer was never at fault - it correctly enforced the scopes of
the identity it was handed. Nothing established that the caller was
entitled to that identity.

Schema note (also called out in the implementation report): AuditEntry
and Run carry run_id/org_id but not incident_id in the current data
model, so "every audit entry for this incident" can't be expressed as a
single scope_store filter. _correlated_audit_entries() below is a
documented best-effort approximation, not a precise join - see its
docstring.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Optional
from urllib.parse import quote

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from auth import identity, oidc, provisioning
from auth import session as session_module
from data import scope_store
from data.models import Collection, OrgSsoConfig, new_id
from telemetry import otel_setup

logger = logging.getLogger("mortemtrace.console")

CONSOLE_AGENT_NAME = "console"
CONSOLE_AGENT_VERSION = "1.0.0"

RECENT_RUNS_LIMIT = 20
RECENT_AUDIT_LIMIT = 100
INCIDENT_AUDIT_LIMIT = 50
# How much of the audit log the incident page scans to find entries
# related to this incident. AuditEntry carries no incident_id (see
# _correlated_audit_entries), so correlation is a bounded scan.
AUDIT_SCAN_LIMIT = 1000

# (department value on DraftBase, display label) - fixed order and set so
# the console always renders exactly four columns, never a variable-length
# list. Showing "no draft yet" (or, for Legal on a non-data-touching
# incident, an explicit scope explanation) in an empty slot is the point:
# it proves the fan-out ran even where a department produced nothing.
DEPARTMENTS: list[tuple[str, str]] = [
    ("engineering", "Postmortem — Engineering"),
    ("support", "Comms — Support"),
    ("legal", "Compliance — Legal"),
    ("finance", "Exposure — Finance"),
]

# Shared verdict/status -> visual tone mapping, used for Run.status,
# AuditEntry.verdict, Incident.status, GdprClock.status, and draft status
# badges alike, so "ok/allow/resolved" always reads green, "deny/block/
# dead_letter/rejected" always reads red, etc. across every table in the
# console instead of ad-hoc per-template color logic.
_TONE_BY_VALUE = {
    "ok": "ok", "allow": "ok", "running": "ok", "completed": "ok",
    "approved": "ok", "resolved": "ok", "met": "ok",
    "degraded": "warn", "clarification_needed": "warn", "redact": "warn",
    "open": "warn", "monitoring": "warn", "draft": "neutral",
    "denied": "bad", "deny": "bad", "blocked": "bad", "block": "bad",
    "dead_letter": "bad", "failed": "bad", "quarantined": "bad",
    "rejected": "bad", "missed": "bad",
    "sev1": "bad", "sev2": "bad", "sev3": "warn", "sev4": "neutral",
}

otel_setup.init_telemetry("mortemtrace-console")
otel_setup.configure_logging("mortemtrace-console")
identity.warn_if_open()

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

app = FastAPI(title="MortemTrace Operator Console")


@app.exception_handler(HTTPException)
async def _auth_aware_http_exception_handler(request: Request, exc: HTTPException):
    """Sends an unauthenticated *browser navigation* to the login form,
    while leaving programmatic callers with a real 401.

    Without this, the first thing an operator saw on a protected console
    was a bare JSON 401 with no indication that /login exists. The split
    is on what the client asked for, not on the path: a fetch() from the
    dashboard's own polling code sends `Accept: application/json` and
    must keep receiving 401 so its handler can react (a redirect there
    would quietly render the login page's HTML into a data table).
    """
    if exc.status_code == 401:
        accepts_html = "text/html" in request.headers.get("accept", "")
        if accepts_html:
            response = RedirectResponse(url="/login", status_code=303)
            # Clear a session cookie that is present but unusable, so a
            # stale one cannot wedge a browser into a permanent loop:
            # /login -> IdP -> /auth/callback sets a NEW good cookie ->
            # but if the browser still also holds an OLD cookie of the
            # same name (from a previous deployment, or minted before the
            # session secret existed in Secret Manager), the parser can
            # hand us the stale one on every subsequent request, which
            # fails verification and bounces straight back to /login
            # forever. The user has no way to fix that themselves short of
            # manually clearing site data, and nothing in the flow ever
            # invalidates the bad cookie. Expiring it here makes the next
            # login attempt succeed on its own.
            if request.cookies.get(SESSION_COOKIE):
                response.delete_cookie(SESSION_COOKIE, path="/")
            return response
    return await http_exception_handler(request, exc)


@app.exception_handler(scope_store.PermissionDenied)
async def _permission_denied_handler(request: Request, exc: scope_store.PermissionDenied):
    """data/scope_store.py's admin-role checks (create_invitation,
    revoke_membership, update_membership_role, set_organization_sso) are
    a deliberate SECOND check, independent of console/ui.py's own
    _require_admin - the same "the data layer decides, never the
    caller" discipline the agent-scope system already has. Without this
    handler, the narrow race that check exists to catch (role revoked
    between the HTTP-layer check and the data-layer one) would surface
    as an unhandled 500 instead of the 403 it actually is.
    """
    return await http_exception_handler(request, HTTPException(status_code=403, detail=str(exc)))


@app.exception_handler(scope_store.LastAdminError)
async def _last_admin_handler(request: Request, exc: scope_store.LastAdminError):
    """Not a security boundary - a lockout guard. 400, not 403: the
    caller IS authorized to do this, the operation just can't be
    satisfied without leaving the org unadministerable."""
    return await http_exception_handler(request, HTTPException(status_code=400, detail=str(exc)))


_CONSOLE_LIMITER = identity.build_console_limiter()


# --------------------------------------------------------------------------
# Org resolution / identity
# --------------------------------------------------------------------------

SESSION_COOKIE = "mortemtrace_session"
_HANDSHAKE_COOKIE = "mortemtrace_oauth_handshake"
_INVITE_QUERY_PARAM = "invite"


def _authenticate_request(authorization: Optional[str], request: Optional[Request]) -> identity.Principal:
    """Two genuinely separate credential paths, checked in order, never
    one treated as the other:

      - Authorization: Bearer <api-token> - a MACHINE/operator credential
        (auth/identity.py's MORTEMTRACE_API_TOKENS table), same as
        /ingest accepts. Resolves to a Principal with no user_id/role -
        it can read, but require_role() always denies it, so it can
        never reach an admin-gated action.
      - mortemtrace_session cookie - a HUMAN credential, minted only
        after a real OIDC login (see /auth/callback below). Resolves
        org membership and role fresh from Firestore on every call.

    A session cookie is never accepted as if it were itself an API
    token (the previous design's actual defect - see git history), and
    an API token is never treated as a human identity.
    """
    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            try:
                return identity.authenticate(authorization)
            except identity.AuthenticationError as exc:
                raise HTTPException(status_code=401, detail=str(exc)) from exc

    if request is not None:
        cookie = request.cookies.get(SESSION_COOKIE)
        if cookie:
            try:
                return identity.authenticate_session(cookie)
            except identity.AuthenticationError as exc:
                _log_session_rejection(request, cookie, str(exc))
                raise HTTPException(status_code=401, detail=str(exc)) from exc
        _log_session_rejection(request, None, "no session cookie on the request")

    raise HTTPException(status_code=401, detail="authentication required")


def _log_session_rejection(request: Request, cookie: Optional[str], reason: str) -> None:
    """Why a browser was bounced to /login, in enough detail to tell the
    two very different causes apart without a debugger.

    "The browser never sent the cookie" (a Set-Cookie the browser
    declined to store, a domain/path/Secure mismatch, a redirect that
    dropped it) and "the cookie arrived but did not verify" (wrong
    signing secret, truncation, expiry) look identical from the outside -
    both are a silent 303 back to the login page - and cost real time to
    separate when a login flow breaks in an environment you cannot
    attach a debugger to.

    Logs cookie NAMES and structural shape only, never values: a session
    cookie is a bearer credential, and anything logged here lands in
    Cloud Logging where it would outlive the session it belongs to.
    """
    logger.warning(
        "session rejected: %s",
        reason,
        extra={
            "cookie_names": sorted(request.cookies.keys()),
            "session_cookie_present": cookie is not None,
            # Shape, not content: a correct value is 4 pipe-separated
            # fields, so "3 segments" points at truncation and "1
            # segment" at a value that was never ours to begin with.
            "session_cookie_segments": len(cookie.split("|")) if cookie else 0,
            "session_cookie_length": len(cookie) if cookie else 0,
            "path": request.url.path,
        },
    )


def _authorize_and_rate_limit(principal: identity.Principal, org_id: Optional[str]) -> str:
    """`org_id` may only *select* among orgs the principal already
    belongs to. When omitted and the principal belongs to more than one,
    this defaults to the alphabetically-first rather than erroring - a
    view default a switcher can override, not a security decision (the
    authorization check below still runs against whichever org_id is
    actually used)."""
    if org_id is None and len(principal.org_ids) > 1:
        org_id = sorted(principal.org_ids)[0]

    try:
        resolved = principal.authorize_org(org_id)
    except identity.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except identity.InvalidOrgId as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        _CONSOLE_LIMITER.check(resolved)
    except identity.RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return resolved


def _resolve_org_id(authorization: Optional[str], org_id: Optional[str],
                    request: Optional[Request] = None) -> str:
    """Authenticates the caller and returns the tenant they may read."""
    principal = _authenticate_request(authorization, request)
    return _authorize_and_rate_limit(principal, org_id)


def _require_session_principal(request: Request) -> identity.Principal:
    """For routes that only make sense for a logged-in human (onboarding,
    org administration) - an API token has no user_id to act as, so it is
    refused here even though it might otherwise carry a valid org_id."""
    cookie = request.cookies.get(SESSION_COOKIE)
    try:
        principal = identity.authenticate_session(cookie)
    except identity.AuthenticationError as exc:
        _log_session_rejection(request, cookie, str(exc))
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    if principal.user_id is None:
        raise HTTPException(status_code=401, detail="a human session is required for this action")
    return principal


def _require_admin(request: Request, org_id: str) -> identity.Principal:
    principal = _require_session_principal(request)
    try:
        principal.authorize_org(org_id)
        principal.require_role(org_id, "admin")
    except identity.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return principal


def _base_url(request: Request) -> str:
    """The externally-visible origin, honoring Cloud Run's own
    front-end-terminated-TLS setup: request.url.scheme is "http" behind
    Cloud Run's proxy even when the actual request arrived over https, so
    the OAuth redirect_uri built from it would not match what was
    registered with the IdP. X-Forwarded-Proto is trustworthy here
    specifically because Cloud Run's own front end sets it - unlike
    connectors/verification.py's X-Forwarded-For handling, there is no
    caller-supplied-and-then-appended-to ambiguity for a single-valued
    scheme header on a platform that always sets it itself.
    """
    scheme = request.headers.get("x-forwarded-proto", request.url.scheme)
    return f"{scheme}://{request.url.netloc}"


def _current_session(request: Request) -> session_module.Session:
    try:
        return session_module.verify_session(request.cookies.get(SESSION_COOKIE))
    except session_module.InvalidSession as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def _verify_csrf(request: Request, form: dict) -> session_module.Session:
    session = _current_session(request)
    presented = form.get("csrf_token")
    if not session_module.verify_csrf(session, presented if isinstance(presented, str) else None):
        raise HTTPException(status_code=403, detail="invalid or missing CSRF token")
    return session


def _console_claim(org_id: str):
    return scope_store.sign_claim(
        org_id=org_id, agent_name=CONSOLE_AGENT_NAME, agent_version=CONSOLE_AGENT_VERSION,
        run_id=new_id("run"),
    )


def _tone(value: Optional[str]) -> str:
    return _TONE_BY_VALUE.get(value or "", "neutral")


def _with_tone(items: list[dict], field: str) -> list[dict]:
    for item in items:
        item["_tone"] = _tone(item.get(field))
    return items


# --------------------------------------------------------------------------
# Data gathering (all reads go through data/scope_store.py, degrade-not-
# fail via try_read/try_query so a scope this identity turns out not to
# have shows an empty section instead of a 500)
# --------------------------------------------------------------------------

def _recent_runs(claim, limit: int = RECENT_RUNS_LIMIT) -> list[dict]:
    # Server-side order + limit. This used to fetch every run in the
    # tenant and sort in Python, which grew without bound as runs
    # accumulated. Needs the composite index declared in
    # infra/firestore.indexes.json.
    runs = scope_store.try_query(
        claim, Collection.RUNS, limit=limit, order_by="created_at", descending=True,
    )
    return _with_tone(runs, "status")


def _active_incidents(claim) -> list[dict]:
    incidents = scope_store.try_query(claim, Collection.INCIDENTS, filters=[("status", "==", "open")])
    incidents.sort(key=lambda i: i.get("opened_at", ""), reverse=True)
    return _with_tone(incidents, "status")


def _department_drafts(drafts: list[dict], classification: Optional[dict]) -> list[dict]:
    by_department = {d.get("department"): d for d in drafts}
    rows = []
    for department, label in DEPARTMENTS:
        draft = by_department.get(department)
        if draft is not None:
            draft["_tone"] = _tone(draft.get("status"))
            rows.append({"department": department, "label": label, "draft": draft, "empty_reason": None})
        elif department == "legal" and classification is not None and not classification.get("data_touched", False):
            rows.append({
                "department": department, "label": label, "draft": None,
                "empty_reason": "Not data-touching — no GDPR assessment required.",
            })
        else:
            rows.append({"department": department, "label": label, "draft": None, "empty_reason": "No draft yet."})
    return rows


def _correlated_signals(signals: list[dict], services_affected: list[str]) -> list[dict]:
    """Signal (ARCHITECTURE.md section 6) doesn't carry an incident_ref
    either - it's keyed by provider/region/service, matching what Watcher
    polls. This approximates Watcher's own correlation rule (R3: "by
    affected service and dependency graph") against the incident's own
    services_affected list rather than showing an unfiltered signal firehose."""
    if not services_affected:
        return []
    affected = set(services_affected)
    return [s for s in signals if s.get("service") in affected]


def _related_doc_ids(incident_id: str, hypotheses: list[dict], drafts: list[dict]) -> set[str]:
    ids = {incident_id}
    ids.update(h.get("hypothesis_id") for h in hypotheses if h.get("hypothesis_id"))
    ids.update(d.get("draft_id") for d in drafts if d.get("draft_id"))
    return ids


def _correlated_audit_entries(all_entries: list[dict], related_ids: set[str], limit: int) -> list[dict]:
    """Best-effort correlation: AuditEntry (and Run) carry run_id/org_id
    but no incident_id in the current schema, so "every audit entry for
    this incident" isn't a single scope_store filter. Timeline,
    Classification, and Clocks are keyed by incident_id directly, so
    audit entries for those (including a scope denial on one of them)
    match exactly via a path substring; Hypotheses/Drafts audit entries
    match via the doc IDs already fetched for this page. A collection-
    level denial with no doc id in its path (e.g. Comms denied
    raw_evidence - the R5 scope-denial the demo leads with) can't be tied
    to one incident this way, so every non-"allow" verdict is included
    regardless of correlation: at demo scale these are rare enough that
    showing them here is right far more often than it's noisy, and every
    one is still visible, unfiltered, on /audit either way. Flagged in
    the implementation report as a schema gap worth an incident_id field
    on AuditEntry/Run if this were going further than a hackathon demo.
    """
    matched = [
        e for e in all_entries
        if e.get("verdict") != "allow" or any(rid and rid in e.get("path", "") for rid in related_ids)
    ]
    matched.sort(key=lambda e: e.get("ts", ""), reverse=True)
    return _with_tone(matched[:limit], "verdict")


def _format_remaining(deadline_at_iso: Optional[str]) -> str:
    if not deadline_at_iso:
        return ""
    try:
        deadline = datetime.fromisoformat(deadline_at_iso)
    except ValueError:
        return ""
    remaining = deadline - datetime.now(UTC)
    total_seconds = int(remaining.total_seconds())
    if total_seconds <= 0:
        return "deadline passed"
    hours, rem = divmod(total_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours}h {minutes}m {seconds}s"


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

def _header_context(principal: identity.Principal, resolved_org: str) -> dict:
    """Shared template context every HTML page needs for base.html's
    header - the org switcher, the Members/SSO admin links, and whether
    to show a Sign out control. Computed once here so the three
    HTML-rendering routes below stay consistent with each other rather
    than each reimplementing it slightly differently."""
    return {
        "other_org_ids": sorted(principal.org_ids - {resolved_org}),
        "current_role": principal.role_by_org.get(resolved_org),
        "is_human": principal.user_id is not None,
    }


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, org_id: Optional[str] = None,
              authorization: Optional[str] = Header(None)):
    principal = _authenticate_request(authorization, request)
    if not principal.org_ids:
        # Only a session (human) principal can have zero org_ids - an API
        # token with none is rejected at authentication, never resolved
        # to a Principal at all. A real, authenticated person with
        # nowhere to go yet belongs at org creation, not a 403 page.
        return RedirectResponse(url="/onboarding", status_code=303)
    resolved_org = _authorize_and_rate_limit(principal, org_id)

    with otel_setup.span("mortemtrace.console", "dashboard", org_id=resolved_org):
        claim = _console_claim(resolved_org)
        runs = _recent_runs(claim)
        incidents = _active_incidents(claim)
    return templates.TemplateResponse(request, "dashboard.html", {
        "org_id": resolved_org, "org_id_json": json.dumps(resolved_org),
        "runs": runs, "incidents": incidents,
        **_header_context(principal, resolved_org),
    })


@app.get("/api/runs")
def api_runs(request: Request, org_id: Optional[str] = None,
             authorization: Optional[str] = Header(None)) -> list[dict]:
    resolved_org = _resolve_org_id(authorization, org_id, request)
    claim = _console_claim(resolved_org)
    return _recent_runs(claim)


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: str, org_id: Optional[str] = None,
                    authorization: Optional[str] = Header(None)):
    principal = _authenticate_request(authorization, request)
    resolved_org = _authorize_and_rate_limit(principal, org_id)
    with otel_setup.span(
        "mortemtrace.console", "incident_detail", org_id=resolved_org, incident_id=incident_id,
    ):
        claim = _console_claim(resolved_org)
        incident = scope_store.try_read(claim, Collection.INCIDENTS, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail=f"no such incident: {incident_id}")

        timeline = scope_store.try_read(claim, Collection.TIMELINE, incident_id)
        entries = sorted((timeline or {}).get("entries", []), key=lambda e: e.get("ts", ""))

        hypotheses = scope_store.try_query(
            claim, Collection.HYPOTHESES, filters=[("incident_ref", "==", incident_id)],
        )
        hypotheses.sort(key=lambda h: h.get("confidence", 0), reverse=True)

        classification = scope_store.try_read(claim, Collection.CLASSIFICATION, incident_id)
        if classification:
            classification["_tone_severity"] = _tone(classification.get("severity"))
            classification["_tone_data_touched"] = "bad" if classification.get("data_touched") else "ok"

        drafts = scope_store.try_query(claim, Collection.DRAFTS, filters=[("incident_ref", "==", incident_id)])
        draft_rows = _department_drafts(drafts, classification)

        clock = scope_store.try_read(claim, Collection.CLOCKS, incident_id)
        clock_remaining = _format_remaining(clock.get("deadline_at")) if clock else None
        if clock:
            clock["_tone"] = _tone(clock.get("status"))

        signals = scope_store.try_query(claim, Collection.SIGNALS)
        correlated_signals = _correlated_signals(signals, incident.get("services_affected", []))

        # Bounded scan: the audit collection grows by roughly three
        # entries per agent operation and is never truncated, so reading
        # all of it made this page slower on every incident forever.
        # AUDIT_SCAN_LIMIT is the correlation window, not the whole log -
        # /audit shows the unfiltered view.
        all_audit = scope_store.try_query(
            claim, Collection.AUDIT, limit=AUDIT_SCAN_LIMIT,
            order_by="ts", descending=True,
        )
        related_ids = _related_doc_ids(incident_id, hypotheses, drafts)
        audit_entries = _correlated_audit_entries(all_audit, related_ids, INCIDENT_AUDIT_LIMIT)

    return templates.TemplateResponse(request, "incident_detail.html", {
        "org_id": resolved_org,
        "incident": incident,
        "entries": entries,
        "hypotheses": hypotheses,
        "classification": classification,
        "draft_rows": draft_rows,
        "clock": clock,
        "clock_remaining": clock_remaining,
        "signals": correlated_signals,
        "audit_entries": audit_entries,
        **_header_context(principal, resolved_org),
    })


def _secure_cookies() -> bool:
    return os.environ.get("MORTEMTRACE_INSECURE_COOKIES") != "1"


def _set_session_cookie(response, user_id: str) -> None:
    """SameSite=Lax, not Strict.

    This cookie is set on /auth/callback, which the browser reaches as a
    top-level navigation FROM accounts.google.com - a cross-site
    navigation. Strict tells the browser to withhold the cookie on
    exactly that kind of inbound cross-site request, so the browser
    accepted the Set-Cookie and then refused to send it back on the
    immediately-following redirect to "/", which read as "not signed in"
    and bounced to /login. Every login looked like it silently failed.

    Lax still blocks the case that matters for CSRF - a cross-site
    POST/form submission never carries it - while permitting the
    top-level GET navigation that completing an OAuth login inherently
    is. This is the same reasoning already applied to the OAuth
    handshake cookie below; the session cookie needed it for the same
    structural reason and did not have it. Every state-changing route is
    additionally CSRF-token protected (see _verify_csrf), so Lax here is
    not the only thing standing between a forged request and a write.

    Not caught by curl-based testing: curl does not implement SameSite
    at all, so a manually-crafted request succeeds where a real browser
    is correctly refused.
    """
    response.set_cookie(
        SESSION_COOKIE, session_module.mint_session(user_id),
        httponly=True, samesite="lax", secure=_secure_cookies(), path="/",
        max_age=int(os.environ.get("MORTEMTRACE_SESSION_MAX_AGE", "43200")),
    )


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request, error: Optional[str] = None):
    """Google Sign-In is the always-available fallback; an org's own SSO
    is reached by typing a work email, which routes by domain (Home
    Realm Discovery) rather than asking anyone to know their org_id.
    There is no password field - see auth/identity.py's module docstring
    for why a pasted API token is no longer how a human reaches this page."""
    return templates.TemplateResponse(request, "login.html", {
        "error": error,
        "google_available": oidc.google_login_available(),
        "invite_token": request.query_params.get(_INVITE_QUERY_PARAM),
    }, status_code=200)


def _start_oidc_redirect(url: str, handshake_cookie: str) -> RedirectResponse:
    response = RedirectResponse(url=url, status_code=303)
    response.set_cookie(
        _HANDSHAKE_COOKIE, handshake_cookie,
        httponly=True,
        # Lax, not Strict: this cookie must survive the IdP's top-level
        # redirect back to /auth/callback, which Strict would drop -
        # SameSite=Strict is only safe for the long-lived session cookie
        # above, which is never involved in a cross-site redirect.
        samesite="lax", secure=_secure_cookies(), path="/",
        max_age=oidc.HANDSHAKE_TTL_SECONDS,
    )
    return response


def _login_error_redirect(message: str, *, invite: Optional[str] = None) -> RedirectResponse:
    """Every dynamic component of a redirect Location header gets
    URL-encoded here, not interpolated raw - an IdP error string or an
    email-derived domain is attacker-influenced input by the time it
    reaches this function, and an unencoded '&' or newline in it could
    otherwise smuggle extra query parameters or split the response."""
    url = f"/login?error={quote(message)}"
    if invite:
        url += f"&{_INVITE_QUERY_PARAM}={quote(invite)}"
    return RedirectResponse(url=url, status_code=303)


@app.get("/auth/login/google")
def auth_login_google(request: Request, invite: Optional[str] = None, demo: bool = False):
    try:
        url, handshake = oidc.start_google_login(_base_url(request), invite_token=invite, demo=demo)
    except oidc.OidcError as exc:
        return _login_error_redirect(str(exc), invite=invite)
    return _start_oidc_redirect(url, handshake)


@app.post("/auth/login/org")
async def auth_login_org(request: Request):
    """Home Realm Discovery: a work email routes to that org's own IdP,
    if one is configured. No such org, or no SSO configured for it, is
    reported plainly rather than guessed around - Google Sign-In is
    always offered as the fallback on the same page."""
    form = await request.form()
    email = str(form.get("email") or "").strip().lower()
    invite = str(form.get("invite") or "").strip() or None
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""

    org = scope_store.find_organization_by_sso_domain_hint(domain) if domain else None
    if org is None or not org.get("sso"):
        return _login_error_redirect(
            f"no company sign-in configured for {domain or 'that address'}", invite=invite,
        )

    try:
        url, handshake = oidc.start_org_login(org["org_id"], org["sso"], _base_url(request), invite_token=invite)
    except oidc.OidcError as exc:
        return _login_error_redirect(str(exc), invite=invite)
    return _start_oidc_redirect(url, handshake)


@app.get("/auth/callback")
def auth_callback(request: Request):
    """Single callback for both Google and per-org SSO - which flow this
    is travels in the signed handshake cookie, not the URL, so both IdPs
    are registered with the same redirect_uri."""
    handshake_cookie = request.cookies.get(_HANDSHAKE_COOKIE)
    try:
        verified = oidc.complete_login(
            query_params=dict(request.query_params),
            handshake_cookie=handshake_cookie,
            base_url=_base_url(request),
        )
    except oidc.OidcError as exc:
        response = _login_error_redirect(str(exc))
        response.delete_cookie(_HANDSHAKE_COOKIE, path="/")
        return response

    outcome = provisioning.resolve_login(verified)

    if outcome.landed_org_id is not None:
        destination = f"/?org_id={outcome.landed_org_id}"
    elif outcome.memberships:
        destination = "/"  # multiple orgs - dashboard's own switcher/default handles it
    else:
        destination = "/onboarding"

    response = RedirectResponse(url=destination, status_code=303)
    _set_session_cookie(response, outcome.user_id)
    response.delete_cookie(_HANDSHAKE_COOKIE, path="/")
    return response


@app.get("/login/demo")
def login_demo_entry(request: Request):
    """The explicit, separate "view live demo" entry point (SIGN-IN
    requirement: a clearly isolated demo access path). Threads demo=1
    through the SAME Google login flow every other user takes - the only
    difference is auth/provisioning.py then auto-joins the one org
    flagged public_demo_auto_join. An ordinary login never takes this
    path, so a real employee signing in with a personal Gmail address by
    mistake lands on /onboarding, not silently inside the demo tenant."""
    return auth_login_google(request, invite=None, demo=True)


@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# --------------------------------------------------------------------------
# Onboarding: organization creation, membership, invitations, SSO config
# --------------------------------------------------------------------------

@app.get("/onboarding", response_class=HTMLResponse)
def onboarding_form(request: Request):
    principal = _require_session_principal(request)
    if principal.org_ids:
        return RedirectResponse(url="/", status_code=303)
    session = _current_session(request)
    return templates.TemplateResponse(request, "onboarding.html", {
        "csrf_token": session_module.csrf_token(session), "is_human": True,
    })


@app.post("/onboarding")
async def onboarding_create(request: Request):
    principal = _require_session_principal(request)
    form = await request.form()
    _verify_csrf(request, dict(form))

    display_name = str(form.get("display_name") or "").strip()
    if not display_name:
        raise HTTPException(status_code=400, detail="organization name is required")

    org = scope_store.create_organization(display_name, principal.user_id)
    response = RedirectResponse(url=f"/?org_id={org['org_id']}", status_code=303)
    return response


@app.get("/orgs/{org_id}/members", response_class=HTMLResponse)
def members_page(request: Request, org_id: str):
    principal = _require_admin(request, org_id)
    session = _current_session(request)
    members = scope_store.list_memberships_for_org(org_id)
    users_by_id = {m["user_id"]: (scope_store.get_user(m["user_id"]) or {}) for m in members}
    for m in members:
        m["_user"] = users_by_id.get(m["user_id"], {})
        m["_tone"] = "ok" if m.get("status") == "active" else "bad"
    members.sort(key=lambda m: (m.get("status") != "active", m.get("_user", {}).get("email", "")))
    return templates.TemplateResponse(request, "members.html", {
        "org_id": org_id, "members": members,
        "acting_user_id": principal.user_id,
        "csrf_token": session_module.csrf_token(session),
        "last_invite_link": request.query_params.get("invite_link"),
        **_header_context(principal, org_id),
    })


@app.post("/orgs/{org_id}/invite")
async def invite_member(request: Request, org_id: str):
    principal = _require_admin(request, org_id)
    form = await request.form()
    _verify_csrf(request, dict(form))

    email = str(form.get("email") or "").strip().lower()
    role = str(form.get("role") or "member")
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="a valid email is required")
    if role not in ("admin", "member"):
        raise HTTPException(status_code=400, detail="role must be admin or member")

    _invitation, token = scope_store.create_invitation(principal.user_id, org_id, email, role)
    invite_link = f"{_base_url(request)}/invite/{token}"
    # Shown once, in the redirect target's query string, then never again -
    # there is no email-sending integration in this deployment, so the
    # admin copies this link and shares it manually (Slack, email client).
    return RedirectResponse(
        url=f"/orgs/{org_id}/members?invite_link={invite_link}", status_code=303,
    )


@app.post("/orgs/{org_id}/members/{target_user_id}/revoke")
async def revoke_member(request: Request, org_id: str, target_user_id: str):
    principal = _require_admin(request, org_id)
    form = await request.form()
    _verify_csrf(request, dict(form))
    try:
        scope_store.revoke_membership(principal.user_id, org_id, target_user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RedirectResponse(url=f"/orgs/{org_id}/members", status_code=303)


@app.post("/orgs/{org_id}/members/{target_user_id}/role")
async def change_member_role(request: Request, org_id: str, target_user_id: str):
    principal = _require_admin(request, org_id)
    form = await request.form()
    _verify_csrf(request, dict(form))
    role = str(form.get("role") or "")
    if role not in ("admin", "member"):
        raise HTTPException(status_code=400, detail="role must be admin or member")
    try:
        scope_store.update_membership_role(principal.user_id, org_id, target_user_id, role)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return RedirectResponse(url=f"/orgs/{org_id}/members", status_code=303)


@app.get("/invite/{token}")
def invite_redeem_entry(request: Request, token: str):
    """Unauthenticated on purpose - most invitees are not yet signed in.
    Routes straight through Google Sign-In carrying the token; a
    same-domain org SSO login is still reachable from /login itself if
    the invitee prefers it, since the invite token also survives that
    path via the login form's hidden field."""
    cookie = request.cookies.get(SESSION_COOKIE)
    try:
        principal = identity.authenticate_session(cookie)
    except identity.AuthenticationError:
        return RedirectResponse(url=f"/login?{_INVITE_QUERY_PARAM}={token}", status_code=303)

    invitation = scope_store.find_invitation_by_token(token)
    user = scope_store.get_user(principal.user_id) if principal.user_id else None
    if invitation is None or user is None or invitation["email"] != user.get("email"):
        return RedirectResponse(url="/login?error=invite+link+is+invalid+or+expired", status_code=303)

    try:
        scope_store.redeem_invitation(invitation["invitation_id"], principal.user_id)
    except ValueError:
        pass  # already redeemed - fine, fall through to the org they're now a member of
    return RedirectResponse(url=f"/?org_id={invitation['org_id']}", status_code=303)


@app.get("/orgs/{org_id}/sso", response_class=HTMLResponse)
def sso_settings_form(request: Request, org_id: str):
    principal = _require_admin(request, org_id)
    session = _current_session(request)
    org = scope_store.get_organization(org_id)
    if org is None:
        raise HTTPException(status_code=404, detail="no such organization")
    return templates.TemplateResponse(request, "sso_settings.html", {
        "org_id": org_id, "org": org,
        "csrf_token": session_module.csrf_token(session),
        **_header_context(principal, org_id),
    })


@app.post("/orgs/{org_id}/sso")
async def sso_settings_save(request: Request, org_id: str):
    principal = _require_admin(request, org_id)
    form = await request.form()
    _verify_csrf(request, dict(form))

    if str(form.get("action")) == "clear":
        scope_store.set_organization_sso(principal.user_id, org_id, None)
        return RedirectResponse(url=f"/orgs/{org_id}/sso", status_code=303)

    issuer = str(form.get("issuer") or "").strip()
    client_id = str(form.get("client_id") or "").strip()
    client_secret_ref = str(form.get("client_secret_ref") or "").strip()
    if not (issuer.startswith("https://") and client_id and client_secret_ref):
        raise HTTPException(
            status_code=400,
            detail="issuer (https://...), client_id, and client_secret_ref are all required",
        )

    # domain_hint is deliberately NOT settable here. Regression, found in
    # a security self-review: it routes an email address's login flow to
    # whichever organization's SSO config claims that domain
    # (find_organization_by_sso_domain_hint), with no proof the claiming
    # org actually owns that domain. Org creation is open to anyone with
    # a Google account (see /onboarding), so a self-registered admin
    # could previously claim any company's domain here and capture that
    # company's employees' login attempts - a real, unauthenticated
    # phishing primitive, not a theoretical one. Preserving whatever hint
    # an existing config already carries (never introducing one from this
    # form) until real domain-ownership verification (DNS TXT challenge
    # or similar) exists; until then it's operator-set only, out of band.
    existing_sso = (scope_store.get_organization(org_id) or {}).get("sso") or {}
    sso = OrgSsoConfig(
        issuer=issuer, client_id=client_id, client_secret_ref=client_secret_ref,
        domain_hint=existing_sso.get("domain_hint"),
    )
    scope_store.set_organization_sso(principal.user_id, org_id, sso.model_dump(mode="json"))
    return RedirectResponse(url=f"/orgs/{org_id}/sso", status_code=303)


@app.get("/status")
def status() -> dict:
    """Unauthenticated by design - a liveness probe that requires a
    credential cannot distinguish "service is down" from "credential is
    misconfigured", which is exactly when you need the probe most.

    Not named /healthz: confirmed live (2026-08-31) that Google's own
    edge infrastructure intercepts that exact path ahead of Cloud Run -
    the request never reaches this container at all, so a route
    defined at that path is silently unreachable regardless of what it
    returns. Cloud Run's own startup probe here is a plain TCP check on
    the container port, not an HTTP path, so nothing GCP-side depends
    on any specific path name."""
    return {"status": "ok"}


@app.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request, org_id: Optional[str] = None,
              authorization: Optional[str] = Header(None)):
    principal = _authenticate_request(authorization, request)
    resolved_org = _authorize_and_rate_limit(principal, org_id)
    with otel_setup.span("mortemtrace.console", "audit_log", org_id=resolved_org):
        claim = _console_claim(resolved_org)
        entries = scope_store.try_query(
            claim, Collection.AUDIT, limit=RECENT_AUDIT_LIMIT,
            order_by="ts", descending=True,
        )
        entries = _with_tone(entries, "verdict")
    return templates.TemplateResponse(request, "audit.html", {
        "org_id": resolved_org, "entries": entries,
        **_header_context(principal, resolved_org),
    })
