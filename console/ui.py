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

Multi-tenant admin auth is out of scope for the hackathon demo: every
route accepts an `org_id` query param, defaulting to the
MORTEMTRACE_DEMO_ORG env var (see _resolve_org_id) rather than building
real cross-org session/auth handling.

Schema note (also called out in the implementation report): AuditEntry
and Run carry run_id/org_id but not incident_id in the current data
model, so "every audit entry for this incident" can't be expressed as a
single scope_store filter. _correlated_audit_entries() below is a
documented best-effort approximation, not a precise join - see its
docstring.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from data import scope_store
from data.models import Collection, new_id
from telemetry import otel_setup

CONSOLE_AGENT_NAME = "console"
CONSOLE_AGENT_VERSION = "1.0.0"

_DEMO_ORG_ENV = "MORTEMTRACE_DEMO_ORG"
_FALLBACK_ORG = "org_demo"

RECENT_RUNS_LIMIT = 20
RECENT_AUDIT_LIMIT = 100
INCIDENT_AUDIT_LIMIT = 50

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
}

otel_setup.init_telemetry("mortemtrace-console")

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

app = FastAPI(title="MortemTrace Operator Console")


# --------------------------------------------------------------------------
# Org resolution / identity
# --------------------------------------------------------------------------

def _resolve_org_id(org_id: Optional[str]) -> str:
    return org_id or os.environ.get(_DEMO_ORG_ENV) or _FALLBACK_ORG


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
    # scope_store.query() has no order_by (see ARCHITECTURE.md's data
    # layer - it exposes filters + limit only), so "most recent N" is
    # fetch-all-then-sort in application code rather than a server-side
    # order. Fine at hackathon demo scale; would need a real order_by (or
    # a denormalized "recent runs" index) at real scale.
    runs = scope_store.try_query(claim, Collection.RUNS)
    runs.sort(key=lambda r: r.get("created_at", ""), reverse=True)
    return _with_tone(runs[:limit], "status")


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
    remaining = deadline - datetime.now(timezone.utc)
    total_seconds = int(remaining.total_seconds())
    if total_seconds <= 0:
        return "deadline passed"
    hours, rem = divmod(total_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    return f"{hours}h {minutes}m {seconds}s"


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, org_id: Optional[str] = None):
    resolved_org = _resolve_org_id(org_id)
    with otel_setup.span("mortemtrace.console", "dashboard", org_id=resolved_org):
        claim = _console_claim(resolved_org)
        runs = _recent_runs(claim)
        incidents = _active_incidents(claim)
    return templates.TemplateResponse(request, "dashboard.html", {
        "org_id": resolved_org, "org_id_json": json.dumps(resolved_org),
        "runs": runs, "incidents": incidents,
    })


@app.get("/api/runs")
def api_runs(org_id: Optional[str] = None) -> list[dict]:
    resolved_org = _resolve_org_id(org_id)
    claim = _console_claim(resolved_org)
    return _recent_runs(claim)


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: str, org_id: Optional[str] = None):
    resolved_org = _resolve_org_id(org_id)
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

        drafts = scope_store.try_query(claim, Collection.DRAFTS, filters=[("incident_ref", "==", incident_id)])
        draft_rows = _department_drafts(drafts, classification)

        clock = scope_store.try_read(claim, Collection.CLOCKS, incident_id)
        clock_remaining = _format_remaining(clock.get("deadline_at")) if clock else None
        if clock:
            clock["_tone"] = _tone(clock.get("status"))

        signals = scope_store.try_query(claim, Collection.SIGNALS)
        correlated_signals = _correlated_signals(signals, incident.get("services_affected", []))

        all_audit = scope_store.try_query(claim, Collection.AUDIT)
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
    })


@app.get("/audit", response_class=HTMLResponse)
def audit_log(request: Request, org_id: Optional[str] = None):
    resolved_org = _resolve_org_id(org_id)
    with otel_setup.span("mortemtrace.console", "audit_log", org_id=resolved_org):
        claim = _console_claim(resolved_org)
        entries = scope_store.try_query(claim, Collection.AUDIT)
        entries.sort(key=lambda e: e.get("ts", ""), reverse=True)
        entries = _with_tone(entries[:RECENT_AUDIT_LIMIT], "verdict")
    return templates.TemplateResponse(request, "audit.html", {
        "org_id": resolved_org, "entries": entries,
    })
