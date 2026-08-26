"""Legal/DPO's departmental drafting agent.

Read scope: timeline, classification. Write scope: drafts, clocks.

Branches on envelope.event_type because Compliance is the one
departmental agent that fans out from two different upstream events
(SPEC-postmortem.md section 6):

- timeline.committed only proves the raw_evidence denial - the real
  assessment can't happen yet, because classification hasn't run.
- incident.classified does the actual GDPR Article 33 work once
  Classifier has flagged whether customer data was touched.

Same scope-boundary proof as Comms on the raw_evidence read (see
comms.py's docstring): Compliance's registry entry does not grant it
that scope, so the call below is denied at data/scope_store.py
regardless of what this module's prompt says.

Per SPEC section 3's non-goals: "The Legal agent produces a structured
assessment and flags the clock. It does not decide whether to notify a
regulator." The model is explicitly instructed not to draft a
notification decision, and this module never asks it to.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from pydantic import BaseModel

from agents.contracts import RunResult
from data import scope_store
from data.models import (
    Collection,
    Envelope,
    GdprAssessmentDraft,
    GdprClock,
    OrgClaim,
    new_id,
    now,
)
from gateway import agent_gateway

logger = logging.getLogger("mortemtrace.compliance")

_GDPR_WINDOW = timedelta(hours=72)


class _GdprAssessmentOutput(BaseModel):
    body: str


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    incident_id = envelope.incident_id or envelope.payload.get("incident_id")
    if not incident_id:
        return RunResult(status="dead_letter", detail="envelope carried no incident_id")

    if envelope.event_type == "timeline.committed":
        return _on_timeline_committed(claim, incident_id)
    if envelope.event_type == "incident.classified":
        return _on_incident_classified(claim, incident_id)
    return RunResult(status="ok", detail=f"compliance has no handling for event_type={envelope.event_type!r}")


def _on_timeline_committed(claim: OrgClaim, incident_id: str) -> RunResult:
    # Compliance's registry scope does not include raw_evidence on either
    # of its triggering events. This call is expected to always be
    # denied - that is the point, same reasoning as Comms: it turns
    # "Compliance happens not to see log content" into "Compliance is
    # structurally unable to see log content," and it produces the
    # audit-log denial entry the demo shows on camera (SPEC section 10,
    # beat 2).
    log_detail = scope_store.try_read(claim, Collection.RAW_EVIDENCE, incident_id)
    if log_detail is not None:
        logger.warning(
            "compliance unexpectedly read raw_evidence for incident %s - "
            "scope misconfiguration? ignoring the content regardless.", incident_id,
        )
    # Nothing to draft yet - classification hasn't happened. The real
    # work (the GDPR assessment and the 72-hour clock) happens below on
    # incident.classified. This dispatch's only job is the denial proof.
    return RunResult(status="ok", detail="no-op: awaiting incident.classified before drafting")


def _on_incident_classified(claim: OrgClaim, incident_id: str) -> RunResult:
    classification = scope_store.read(claim, Collection.CLASSIFICATION, incident_id)
    if not classification:
        return RunResult(status="dead_letter", detail="no classification record found for incident")

    if not classification.get("data_touched"):
        # A non-data-touching incident leaves zero Legal artifacts - no
        # draft, no clock - rather than an empty or negative one.
        return RunResult(status="ok", detail="data_touched is False; no GDPR artifacts written")

    data_categories = classification.get("data_categories", [])
    prompt = _build_prompt(incident_id, classification)

    agent, outcome = agent_gateway.build_agent(
        name=claim.agent_name, run_id=claim.run_id, org_id=claim.org_id,
        instruction=(
            "You are the Legal/DPO department's GDPR Article 33 drafting "
            "assistant. Produce a structured assessment: which data "
            "category was touched, the incident severity, and recommended "
            "next steps for the DPO's own review. Do not decide or "
            "recommend whether to notify a regulator or any third party - "
            "that decision belongs to a human DPO and is out of scope for "
            "this draft. Return JSON matching the schema."
        ),
        output_schema=_GdprAssessmentOutput,
    )
    result = agent_gateway.invoke(agent, prompt, run_id=claim.run_id, org_id=claim.org_id)
    if outcome.blocked:
        return RunResult(status="blocked", detail=outcome.block_reason,
                          turns=result.turns, tokens_used=result.tokens_used)

    try:
        parsed = _GdprAssessmentOutput.model_validate_json(result.text)
    except ValueError as exc:
        return RunResult(status="dead_letter",
                          detail=f"gdpr assessment output failed schema validation: {exc}",
                          turns=result.turns, tokens_used=result.tokens_used)

    # Single now() call: the clock's deadline and the draft's mirrored
    # clock_deadline_at must agree to the microsecond, and two separate
    # now() calls would not.
    started_at = now()
    deadline_at = started_at + _GDPR_WINDOW

    clock = GdprClock(
        incident_id=incident_id, org_id=claim.org_id,
        gdpr_started_at=started_at, deadline_at=deadline_at, status="running",
    )
    scope_store.write(claim, Collection.CLOCKS, incident_id, clock.model_dump(mode="json"))

    draft = GdprAssessmentDraft(
        draft_id=new_id("draft"),
        incident_ref=incident_id,
        org_id=claim.org_id,
        body=parsed.body,
        data_categories=data_categories,
        clock_deadline_at=deadline_at,
        # Compliance can't cite raw timeline detail - it isn't in scope
        # on this branch either - so the classification record it did
        # read is the source of record for this draft.
        source_refs=[f"classification:{incident_id}"],
    )
    scope_store.write(claim, Collection.DRAFTS, draft.draft_id, draft.model_dump(mode="json"))
    logger.info("gdpr assessment draft %s + clock written for incident %s", draft.draft_id, incident_id)
    return RunResult(status="ok", turns=result.turns, tokens_used=result.tokens_used)


def _build_prompt(incident_id: str, classification: dict) -> str:
    lines = [
        f"Incident: {incident_id}",
        f"Severity: {classification.get('severity')}",
        f"Data categories touched: {', '.join(classification.get('data_categories', [])) or 'unspecified'}",
        f"Services affected: {', '.join(classification.get('services', []))}",
        "",
        "Write a structured GDPR Article 33 assessment body covering the "
        "data category, severity, and recommended next steps for the "
        "DPO's review. Do not recommend a notification decision. Return "
        "JSON matching the schema.",
    ]
    return "\n".join(lines)
