"""Support's departmental drafting agent.

Read scope: timeline only. Write scope: drafts. This is the sharpest
version of the scope-boundary proof (SPEC-postmortem.md section 6;
ARCHITECTURE.md section 2, "the scope boundary - this is the
differentiator"): Comms' registry entry simply does not grant it read
access to raw_evidence, so the attempted read below is denied by
data/scope_store.py regardless of anything this module or its prompt
says. Nothing in this file instructs the model to avoid log content as a
safety measure - that would make the boundary a suggestion. The
instruction below asking for plain, customer-facing language is a draft
quality nicety, not the security boundary. The boundary is the registry
scope grant (or its absence), enforced at the data layer, and the denial
this produces is what makes it into /audit for the demo to show.
"""
from __future__ import annotations

import logging

from pydantic import BaseModel

from agents.contracts import RunResult
from data import scope_store
from data.models import Collection, Envelope, OrgClaim, StatusUpdateDraft, new_id
from gateway import agent_gateway

logger = logging.getLogger("mortemtrace.comms")


class _StatusUpdateOutput(BaseModel):
    body: str


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    incident_id = envelope.incident_id or envelope.payload.get("incident_id")
    if not incident_id:
        return RunResult(status="dead_letter", detail="envelope carried no incident_id")

    timeline = scope_store.read(claim, Collection.TIMELINE, incident_id)

    # Comms' registry scope does not include raw_evidence. This call is
    # expected to always be denied - that is the point. It is what turns
    # "Comms happens not to show logs" into "Comms is structurally unable
    # to show logs," and it is what produces the audit-log denial entry
    # the demo shows on camera (SPEC section 10, beat 2).
    log_detail = scope_store.try_read(claim, Collection.RAW_EVIDENCE, incident_id)
    # try_read returns None here every time in practice, since Comms is
    # never granted that scope - don't branch on it succeeding, just
    # don't crash (and don't use the content) if scopes are ever
    # misconfigured and it doesn't.
    if log_detail is not None:
        logger.warning(
            "comms unexpectedly read raw_evidence for incident %s - scope "
            "misconfiguration? ignoring the content regardless.", incident_id,
        )

    if not timeline or not timeline.get("entries"):
        return RunResult(status="dead_letter", detail="no committed timeline entries to draft from")

    source_refs = _source_refs(timeline)
    if not source_refs:
        return RunResult(status="dead_letter",
                          detail="no source_event_ids on timeline; refusing a sourceless draft")

    prompt = _build_prompt(incident_id, timeline)

    agent, outcome = agent_gateway.build_agent(
        name=claim.agent_name, run_id=claim.run_id, org_id=claim.org_id,
        instruction=(
            "You are the Support department's status-update drafting "
            "assistant. Using only the committed incident timeline "
            "provided, write a customer-facing status update. Describe "
            "impact and resolution in plain terms a customer would "
            "understand, with no internal system names, log content, or "
            "technical detail beyond what a customer needs to know. "
            "Return JSON matching the schema."
        ),
        output_schema=_StatusUpdateOutput,
    )
    result = agent_gateway.invoke(agent, prompt, run_id=claim.run_id, org_id=claim.org_id)
    if outcome.blocked:
        return RunResult(status="blocked", detail=outcome.block_reason,
                          turns=result.turns, tokens_used=result.tokens_used)

    try:
        parsed = _StatusUpdateOutput.model_validate_json(result.text)
    except ValueError as exc:
        return RunResult(status="dead_letter",
                          detail=f"status update output failed schema validation: {exc}",
                          turns=result.turns, tokens_used=result.tokens_used)

    draft = StatusUpdateDraft(
        draft_id=new_id("draft"),
        incident_ref=incident_id,
        org_id=claim.org_id,
        body=parsed.body,
        source_refs=source_refs,
    )
    scope_store.write(claim, Collection.DRAFTS, draft.draft_id, draft.model_dump(mode="json"))
    logger.info("status update draft %s written for incident %s", draft.draft_id, incident_id)
    return RunResult(status="ok", turns=result.turns, tokens_used=result.tokens_used)


def _source_refs(timeline: dict) -> list[str]:
    refs: list[str] = []
    for entry in timeline.get("entries", []):
        for event_id in entry.get("source_event_ids", []):
            if event_id not in refs:
                refs.append(event_id)
    return refs


def _build_prompt(incident_id: str, timeline: dict) -> str:
    lines = [f"Incident: {incident_id}", "", "Committed timeline:"]
    for entry in timeline.get("entries", []):
        lines.append(f"- {entry.get('ts')} {entry.get('action')}: {entry.get('evidence')}")
    lines.append("")
    lines.append("Write the customer-facing status update body. Return JSON matching the schema.")
    return "\n".join(lines)
