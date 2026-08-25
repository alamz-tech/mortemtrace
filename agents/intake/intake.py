"""Intake: normalises one piece of raw multimodal evidence into a staged
`IncidentEvent`.

Triggered on event_type="evidence.received"; envelope.payload matches
`data.models.EvidenceReceived` ({run_id, org_id, incident_ref,
raw_evidence_id, kind, received_at}). `incident_ref` is guaranteed
populated by the time Intake runs - incident lifecycle is api/ingest.py's
job, not Intake's.

Read scope: raw_evidence. Write scope: events.

R1's hallucination guard lives here at the extraction boundary: a
malformed model response never gets coerced into a record (dead-letter
instead), and a low-confidence extraction never gets committed as fact -
it raises exactly one clarification question instead. Intake never
infers a cause; it only stages one observation for Ledger to reconcile.
"""
from __future__ import annotations

import logging

from pydantic import BaseModel, Field, ValidationError

from agents.contracts import NextEvent, RunResult
from data import scope_store
from data.models import Collection, Envelope, EvidenceStaged, IncidentEvent, OrgClaim, new_id, now
from gateway import agent_gateway

logger = logging.getLogger("mortemtrace.intake")

# R1 acceptance: below this, the visible evidence still commits nowhere -
# Intake raises one clarification instead of inventing a confident but
# unsupported detail (e.g. a metric name it can't actually read).
_CONFIDENCE_THRESHOLD = 0.55

_INSTRUCTION = (
    "You extract a single structured incident-evidence observation from "
    "one piece of raw evidence: an alert payload, a pasted log line, a "
    "dashboard screenshot, or a Slack message. Identify the single most "
    "important action or event visible in the evidence - what changed, "
    "what spiked, what was restarted - and report your confidence in "
    "that extraction. Never invent a detail that is not actually visible "
    "in the evidence, such as a metric name, service name, or root "
    "cause: if the evidence is ambiguous, illegible, or incomplete, "
    "report a lower confidence rather than a specific guess. Respond "
    "with only the requested JSON, nothing else."
)


class Extraction(BaseModel):
    """Local structured-output schema for this one extraction call - not
    a persisted model, so it lives here rather than in data/models.py."""

    action: str
    confidence: float = Field(ge=0.0, le=1.0)


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    raw_evidence_id = envelope.payload.get("raw_evidence_id")
    if not raw_evidence_id:
        return RunResult(status="dead_letter", detail="raw_evidence_id missing from envelope")

    raw = scope_store.read(claim, Collection.RAW_EVIDENCE, raw_evidence_id)
    if raw is None:
        return RunResult(status="dead_letter", detail="raw_evidence not found")

    agent, outcome = agent_gateway.build_agent(
        name="intake",
        run_id=claim.run_id,
        org_id=claim.org_id,
        instruction=_INSTRUCTION,
        output_schema=Extraction,
    )
    invoke_result = agent_gateway.invoke(
        agent, _prompt_for(raw), run_id=claim.run_id, org_id=claim.org_id
    )

    # Model Armor runs inside build_agent's callbacks; a blocked run must
    # not act on the returned text (it's a canned policy message, not a
    # real extraction) and must not write anything.
    if outcome.blocked:
        return RunResult(
            status="blocked",
            detail=outcome.block_reason or "blocked by Model Armor",
            tokens_used=invoke_result.tokens_used,
            turns=invoke_result.turns,
        )

    try:
        extraction = Extraction.model_validate_json(invoke_result.text)
    except ValidationError as exc:
        logger.warning(
            "intake: malformed extraction for raw_evidence=%s (run=%s): %s",
            raw_evidence_id, claim.run_id, exc,
        )
        return RunResult(
            status="dead_letter",
            detail=f"malformed extraction output: {exc}",
            tokens_used=invoke_result.tokens_used,
            turns=invoke_result.turns,
        )

    if extraction.confidence < _CONFIDENCE_THRESHOLD:
        return RunResult(
            status="clarification_needed",
            detail=_clarification_question(extraction),
            tokens_used=invoke_result.tokens_used,
            turns=invoke_result.turns,
        )

    incident_ref = envelope.payload.get("incident_ref")
    event = IncidentEvent(
        event_id=new_id("evt"),
        org_id=claim.org_id,
        incident_ref=incident_ref,
        status="staged",
        confidence=extraction.confidence,
        extracted={"action": extraction.action},
        ts=envelope.payload.get("received_at") or now(),
        source_ref=raw_evidence_id,
    )
    scope_store.write(
        claim,
        Collection.EVENTS,
        event.event_id,
        event.model_dump(mode="json"),
        idempotency_key=f"{claim.run_id}:{event.event_id}",
    )

    next_event = NextEvent(
        topic="evidence.staged",
        payload=EvidenceStaged(
            run_id=claim.run_id,
            org_id=claim.org_id,
            incident_ref=incident_ref,
            event_id=event.event_id,
            confidence=extraction.confidence,
        ).model_dump(mode="json"),
    )
    return RunResult(
        status="ok",
        next_events=[next_event],
        tokens_used=invoke_result.tokens_used,
        turns=invoke_result.turns,
    )


def _prompt_for(raw: dict) -> str:
    parts = [
        f"Evidence kind: {raw.get('kind', 'unknown')}",
        f"Payload:\n{raw.get('payload', '')}",
    ]
    if raw.get("media_uri"):
        parts.append(f"Media: {raw['media_uri']}")
    return "\n\n".join(parts)


def _clarification_question(extraction: Extraction) -> str:
    return (
        f"Confidence in this extraction was only {extraction.confidence:.2f} "
        f"(below the {_CONFIDENCE_THRESHOLD} threshold) for the observed "
        f"action '{extraction.action}': can you confirm the specific "
        f"metric or service this evidence refers to?"
    )
