"""Diagnosis: correlates the committed timeline against prior incident
signatures in Memory Bank and produces one hypothesis about root cause,
with confidence and a traceable source.

Triggered on two event types that both carry an incident, but under
different keys - `timeline.committed` (Ledger's commit) and
`upstream.matched` (Watcher's correlation). Neither is trusted blindly:
we read incident_id from envelope.payload["incident_id"] first (that is
where both TimelineCommitted and UpstreamSignalMatched put it) and fall
back to envelope.incident_id only if the payload omits it.

Never asserts a hypothesis without a traceable source. scope_store
already rejects a Hypothesis write with no source_event_ids (R9), but
that guard operates on whatever we hand it - if the model's cited
indices are all out of range, mapping them yields an empty list and we
must catch that *before* attempting the write, not let a client-side
KeyError or an opaque store rejection stand in for "the model didn't
actually cite anything."
"""
from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from agents.contracts import RunResult
from data import scope_store
from data.models import Collection, Envelope, Hypothesis, MemoryRecord, OrgClaim, Timeline, new_id
from gateway import agent_gateway
from memory import memory_bank

logger = logging.getLogger("mortemtrace.diagnosis")

AGENT_NAME = "diagnosis"
_MEMORY_LIMIT = 5

_INSTRUCTION = (
    "You are the Diagnosis agent in an on-call incident response system. "
    "You are given a committed incident timeline (a numbered list of "
    "entries) and, if any exist, prior incident signatures retrieved from "
    "Memory Bank. Produce exactly ONE hypothesis about the likely root "
    "cause.\n\n"
    "Rules:\n"
    "- source_entry_indices must list only the bracketed indices of "
    "timeline entries shown to you that actually support the hypothesis. "
    "Never invent an index that was not shown.\n"
    "- If, and only if, a prior incident signature's content plausibly "
    "matches this incident's failure pattern, copy its related_incident_ids "
    "into prior_incident_refs. Never invent an incident ID that was not "
    "listed in a memory signature shown to you. If nothing plausibly "
    "matches, leave prior_incident_refs empty.\n"
    "- confidence is a float between 0.0 and 1.0 reflecting how strongly "
    "the cited entries support the statement."
)


class HypothesisDraft(BaseModel):
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    source_entry_indices: list[int] = Field(default_factory=list)
    prior_incident_refs: list[str] = Field(default_factory=list)


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    incident_id = envelope.payload.get("incident_id") or envelope.incident_id
    if not incident_id:
        return RunResult(status="dead_letter", detail="envelope carries no incident_id")

    timeline_raw = scope_store.read(claim, Collection.TIMELINE, incident_id)
    if timeline_raw is None:
        return RunResult(
            status="dead_letter",
            detail=f"no committed timeline for incident {incident_id}; nothing to diagnose",
        )
    timeline = Timeline.model_validate(timeline_raw)

    memories = memory_bank.retrieve(claim, kind="incident_signature", limit=_MEMORY_LIMIT)

    agent, outcome = agent_gateway.build_agent(
        name=AGENT_NAME, run_id=claim.run_id, org_id=claim.org_id,
        instruction=_INSTRUCTION, output_schema=HypothesisDraft,
    )
    invoked = agent_gateway.invoke(
        agent, _build_prompt(timeline, memories), run_id=claim.run_id, org_id=claim.org_id,
    )

    if outcome.blocked:
        return RunResult(
            status="blocked", detail=outcome.block_reason or "blocked by Model Armor",
            tokens_used=invoked.tokens_used, turns=invoked.turns,
        )

    try:
        draft = HypothesisDraft.model_validate_json(invoked.text)
    except Exception as exc:
        return RunResult(
            status="dead_letter", detail=f"hypothesis output failed schema validation: {exc}",
            tokens_used=invoked.tokens_used, turns=invoked.turns,
        )

    source_event_ids = _resolve_source_event_ids(timeline, draft.source_entry_indices)
    if not source_event_ids:
        return RunResult(
            status="dead_letter", detail="hypothesis had no traceable source",
            tokens_used=invoked.tokens_used, turns=invoked.turns,
        )

    hypothesis = Hypothesis(
        hypothesis_id=new_id("hyp"),
        incident_ref=incident_id,
        org_id=claim.org_id,
        statement=draft.statement,
        confidence=draft.confidence,
        source_event_ids=source_event_ids,
        prior_incident_refs=draft.prior_incident_refs,
    )
    scope_store.write(claim, Collection.HYPOTHESES, hypothesis.hypothesis_id, hypothesis.model_dump(mode="json"))

    return RunResult(status="ok", tokens_used=invoked.tokens_used, turns=invoked.turns)


def _build_prompt(timeline: Timeline, memories: list[MemoryRecord]) -> str:
    lines = [f"Incident {timeline.incident_id} - committed timeline ({len(timeline.entries)} entries):"]
    for i, entry in enumerate(timeline.entries):
        lines.append(f"[{i}] ts={entry.ts.isoformat()} action={entry.action!r} evidence={entry.evidence!r}")

    lines.append("")
    if memories:
        lines.append("Prior incident signatures from Memory Bank:")
        for mem in memories:
            lines.append(
                f"- key={mem.key} related_incident_ids={mem.related_incident_ids} content={mem.content}"
            )
    else:
        lines.append("No prior incident signatures available in Memory Bank.")

    lines.append("")
    lines.append("Respond with exactly one hypothesis per the rules in your instructions.")
    return "\n".join(lines)


def _resolve_source_event_ids(timeline: Timeline, indices: list[int]) -> list[str]:
    """Maps model-cited entry indices back to the real source_event_ids
    those entries already carry, dropping any out-of-range index rather
    than raising - an out-of-range citation is treated the same as no
    citation at all, never coerced into a nearby valid one."""
    resolved: list[str] = []
    for i in indices:
        if 0 <= i < len(timeline.entries):
            resolved.extend(timeline.entries[i].source_event_ids)

    seen: set[str] = set()
    deduped: list[str] = []
    for event_id in resolved:
        if event_id not in seen:
            seen.add(event_id)
            deduped.append(event_id)
    return deduped
