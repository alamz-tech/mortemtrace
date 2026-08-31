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
    """Screens the evidence a dispatch is about to act on, before the
    worker is invoked. Pasted log lines are the highest-risk surface
    (R8): an attacker who can write to your logs can write to your
    incident agent's prompt, and this catches it even for a worker that
    reasons purely with tools and never reaches a model call.

    Resolves `raw_evidence_id` and screens the stored evidence body.
    Screening only the envelope payload - which is what this did - was a
    no-op on every route in the system: every payload shape
    (EvidenceReceived, EvidenceStaged, TimelineCommitted,
    IncidentClassified) carries ids and metadata only, never the evidence
    text, which lives in Firestore under raw_evidence_id. So this
    function screened run_id, org_id and kind, found nothing, and
    reported itself as a working defence-in-depth layer while providing
    no depth at all. Injection was caught solely by the gateway's
    before-model callback, one layer later.
    """
    raw_text = _evidence_text(guardian_claim, envelope)
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


# Envelope payload keys that can carry free text originating outside the
# system. Everything else in every payload shape is a system-generated
# identifier or timestamp.
#
# This is an allowlist rather than "every string value in the payload",
# which is what it used to be. That version screened run_id, org_id,
# incident_id and committed_at on every dispatch - and since
# `timeline.committed` fans out to six agents, it meant six Model Armor
# calls per incident spent evaluating our own UUIDs for prompt injection.
# Paid, slow, and incapable of ever matching anything.
_FREE_TEXT_PAYLOAD_KEYS = frozenset({"question", "detail", "reason", "note"})


def _evidence_text(guardian_claim: OrgClaim, envelope: Envelope) -> str:
    """The actual attacker-controlled content for this dispatch.

    Resolves the referenced RawEvidence body - the part that matters,
    since that is what a person pasted - plus any known free-text payload
    field. Uses try_read so a missing scope or a deleted document degrades
    to "screen what we can" rather than failing the dispatch: Guardian
    must not become a new way for a run to die.
    """
    parts: list[str] = []

    raw_evidence_id = envelope.payload.get("raw_evidence_id")
    if raw_evidence_id:
        raw = scope_store.try_read(guardian_claim, Collection.RAW_EVIDENCE, raw_evidence_id)
        if raw:
            payload = raw.get("payload")
            # A base64 data: URI is an image, not prose - screening it
            # spends a Model Armor call on content the text filters cannot
            # meaningfully evaluate.
            if isinstance(payload, str) and not payload.startswith("data:"):
                parts.append(payload)
        else:
            logger.debug(
                "guardian could not read raw_evidence %s for run %s; screening payload only",
                raw_evidence_id, envelope.run_id,
            )

    parts.extend(
        value for key, value in envelope.payload.items()
        if key in _FREE_TEXT_PAYLOAD_KEYS and isinstance(value, str)
    )
    return "\n".join(p for p in parts if p)
