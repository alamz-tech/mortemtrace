"""Pre- and post-flight governance wrapper around every Coordinator ->
worker dispatch.

Guardian does not reason about incidents and is not an LLM agent itself -
it is a deterministic policy checkpoint. Model Armor verdicts and scope
enforcement already live in gateway/model_armor.py and data/
scope_store.py; Guardian's distinct job is to screen an envelope's raw
payload *before* a worker is even invoked (catching an injection that
would otherwise only be caught if and when the worker happens to make a
model call), and to make every non-happy-path outcome visible in
/alerts without anyone having to reconstruct it from the audit log.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from data import scope_store
from data.models import AlertRecord, Collection, Envelope, OrgClaim, new_id
from gateway import model_armor

logger = logging.getLogger("mortemtrace.guardian")

_ESCALATE_ON = {"blocked", "denied", "dead_letter"}


@dataclass
class PreflightVerdict:
    allowed: bool
    reason: str = ""


def preflight(guardian_claim: OrgClaim, envelope: Envelope) -> PreflightVerdict:
    """Screens the envelope's raw payload text before dispatch. Pasted
    log lines are the highest-risk surface (R8): an attacker who can
    write to your logs can write to your incident agent's prompt, and
    this catches it even for a worker that reasons purely with tools and
    never makes it to a model call on a bad path."""
    raw_text = _flatten_payload_text(envelope.payload)
    if not raw_text:
        return PreflightVerdict(allowed=True)

    verdict = model_armor.screen_input(
        raw_text, run_id=envelope.run_id, org_id=envelope.org_id, agent_name="guardian",
    )
    if verdict.verdict == "block":
        _escalate(guardian_claim, envelope, alert_type="blocked", reason=f"preflight block: {verdict.reason}")
        return PreflightVerdict(allowed=False, reason=verdict.reason)
    return PreflightVerdict(allowed=True)


def postflight(guardian_claim: OrgClaim, envelope: Envelope, *, agent_name: str, status: str, detail: str) -> None:
    """Called after a worker returns. A judge (or an operator) should be
    able to find every blocked/denied/dead-lettered outcome in /alerts
    without reading the full audit trail - this is that index."""
    if status in _ESCALATE_ON:
        alert_type = "denied" if status == "denied" else "blocked"
        _escalate(guardian_claim, envelope, alert_type=alert_type, reason=f"{agent_name} returned {status}: {detail}")


def escalate_quarantine(guardian_claim: OrgClaim, envelope: Envelope, *, agent_name: str, reason: str) -> None:
    _escalate(guardian_claim, envelope, alert_type="quarantine", reason=f"{agent_name}: {reason}")


def _escalate(guardian_claim: OrgClaim, envelope: Envelope, *, alert_type: str, reason: str) -> None:
    alert = AlertRecord(
        alert_id=new_id("alert"),
        org_id=envelope.org_id,
        type=alert_type,
        severity="high" if alert_type in ("blocked", "quarantine") else "medium",
        payload={"run_id": envelope.run_id, "incident_id": envelope.incident_id, "reason": reason},
    )
    scope_store.write(guardian_claim, Collection.ALERTS, alert.alert_id, alert.model_dump(mode="json"))


def _flatten_payload_text(payload: dict) -> str:
    return "\n".join(v for v in payload.values() if isinstance(v, str))
