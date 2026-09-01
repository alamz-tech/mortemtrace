"""Engineering's departmental drafting agent.

Read scope: timeline, raw_evidence, hypotheses (SPEC-postmortem.md
section 6) - the broad-access department. Write scope: drafts.

Unlike Comms, Compliance, and Exposure, nothing here is expected to be
denied: Postmortem's registry entry genuinely grants it everything it
needs to write a grounded draft, so this module carries no
attempted-and-denied proof call. That pattern belongs to the three
narrower-scoped departments (see comms.py's docstring for why it
matters that the denial is real, not a prompt convention).
"""
from __future__ import annotations

import logging

from pydantic import BaseModel

from agents.contracts import RunResult
from data import scope_store
from data.models import Collection, Envelope, OrgClaim, PostmortemDraft, new_id
from gateway import agent_gateway

logger = logging.getLogger("mortemtrace.postmortem")

_MAX_GROUNDING_EVENTS = 3


class _PostmortemOutput(BaseModel):
    """Local schema for the model's structured response. Never persisted
    directly - its fields are copied into PostmortemDraft alongside the
    source_refs this module computes itself from the timeline and
    hypotheses, not from anything the model asserts."""

    body: str
    runbook_proposal: str


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    incident_id = envelope.incident_id or envelope.payload.get("incident_id")
    if not incident_id:
        return RunResult(status="dead_letter", detail="envelope carried no incident_id")

    timeline = scope_store.read(claim, Collection.TIMELINE, incident_id)
    if not timeline or not timeline.get("entries"):
        return RunResult(status="dead_letter", detail="no committed timeline entries to draft from")

    hypotheses = scope_store.try_query(
        claim, Collection.HYPOTHESES, filters=[("incident_ref", "==", incident_id)],
    )

    # Extra grounding, per SPEC section 6: Postmortem is the one
    # department with raw_evidence scope, so a couple of the source
    # events already cited in the timeline get pulled in verbatim rather
    # than relying on the timeline's summarized "evidence" field alone.
    raw_snippets = _grounding_snippets(claim, timeline)

    prompt = _build_prompt(incident_id, timeline, hypotheses, raw_snippets)

    agent, outcome = agent_gateway.build_agent(
        name=claim.agent_name, run_id=claim.run_id, org_id=claim.org_id,
        instruction=(
            "You are the Engineering department's postmortem drafting "
            "assistant. Using the committed timeline and diagnosis "
            "hypotheses provided, draft a postmortem body covering what "
            "happened, a timeline summary, the most likely root cause "
            "(citing hypothesis confidence), and the operational impact. "
            "Also propose exactly one concrete, actionable runbook "
            "update. Return JSON matching the schema."
        ),
        output_schema=_PostmortemOutput,
    )
    result = agent_gateway.invoke(agent, prompt, run_id=claim.run_id, org_id=claim.org_id)
    if outcome.blocked:
        return RunResult(status="blocked", detail=outcome.block_reason,
                          turns=result.turns, tokens_used=result.tokens_used)

    try:
        parsed = _PostmortemOutput.model_validate_json(result.text)
    except ValueError as exc:
        return RunResult(status="dead_letter",
                          detail=f"postmortem output failed schema validation: {exc}",
                          turns=result.turns, tokens_used=result.tokens_used)

    source_refs = _flatten_source_refs(timeline, hypotheses)
    if not source_refs:
        # R9's hallucination guard lives at the store layer too, but
        # there is no point building a DraftBase (min_length=1 on
        # source_refs) we already know will fail validation.
        return RunResult(status="dead_letter",
                          detail="no source_event_ids available; refusing a sourceless draft",
                          turns=result.turns, tokens_used=result.tokens_used)

    # Claimed after the model call, not before - see
    # scope_store.claim_idempotency_key's docstring. Guards against a
    # redelivered timeline.committed (the six-way departmental fan-out can
    # outrun the Pub/Sub ack deadline) writing a second, independent draft.
    if not scope_store.claim_idempotency_key(
        claim, Collection.DRAFTS, f"postmortem:{claim.run_id}:{incident_id}",
    ):
        logger.info(
            "postmortem: run %s for incident %s already has a draft "
            "(likely a Pub/Sub redelivery) - not writing a duplicate",
            claim.run_id, incident_id,
        )
        return RunResult(status="ok", turns=result.turns, tokens_used=result.tokens_used)

    draft = PostmortemDraft(
        draft_id=new_id("draft"),
        incident_ref=incident_id,
        org_id=claim.org_id,
        body=parsed.body,
        runbook_proposal=parsed.runbook_proposal,
        source_refs=source_refs,
    )
    scope_store.write(claim, Collection.DRAFTS, draft.draft_id, draft.model_dump(mode="json"))
    logger.info("postmortem draft %s written for incident %s", draft.draft_id, incident_id)
    return RunResult(status="ok", turns=result.turns, tokens_used=result.tokens_used)


def _grounding_snippets(claim: OrgClaim, timeline: dict) -> list[tuple[str, dict]]:
    event_ids = _cited_event_ids(timeline)[:_MAX_GROUNDING_EVENTS]
    snippets = []
    for event_id in event_ids:
        evidence = scope_store.read(claim, Collection.RAW_EVIDENCE, event_id)
        if evidence:
            snippets.append((event_id, evidence))
    return snippets


def _cited_event_ids(timeline: dict) -> list[str]:
    seen: list[str] = []
    for entry in timeline.get("entries", []):
        for event_id in entry.get("source_event_ids", []):
            if event_id not in seen:
                seen.append(event_id)
    return seen


def _flatten_source_refs(timeline: dict, hypotheses: list[dict]) -> list[str]:
    refs = _cited_event_ids(timeline)
    for hypothesis in hypotheses:
        for event_id in hypothesis.get("source_event_ids", []):
            if event_id not in refs:
                refs.append(event_id)
    return refs


def _build_prompt(incident_id: str, timeline: dict, hypotheses: list[dict],
                   raw_snippets: list[tuple[str, dict]]) -> str:
    lines = [f"Incident: {incident_id}", "", "Committed timeline:"]
    for entry in timeline.get("entries", []):
        lines.append(f"- {entry.get('ts')} [{entry.get('actor')}] {entry.get('action')}: {entry.get('evidence')}")

    lines.append("")
    lines.append("Diagnosis hypotheses:")
    if hypotheses:
        for hypothesis in hypotheses:
            lines.append(f"- (confidence {hypothesis.get('confidence', 0):.2f}) {hypothesis.get('statement')}")
    else:
        lines.append("- none available")

    if raw_snippets:
        lines.append("")
        lines.append("Supporting raw evidence:")
        for event_id, evidence in raw_snippets:
            lines.append(f"- [{event_id}] ({evidence.get('kind')}) {evidence.get('payload')}")

    lines.append("")
    lines.append("Write the postmortem draft body and one runbook_proposal. Return JSON matching the schema.")
    return "\n".join(lines)
