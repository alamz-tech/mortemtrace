"""Classifier: severity, affected services, downtime windows, and -
critically - whether customer data was touched.

This is the single most consequential agent in the fan-out. data_touched
is what triggers Compliance's GDPR Article 33 clock (via the
incident.classified event this agent emits). Getting it wrong in either
direction is a real cost: silently false on a data-touching incident
means the 72-hour clock never starts; silently true on a clean incident
means the DPO chases a phantom breach. So `data_touched` carries no
Python-level default in ClassificationDraft on purpose - if the model's
output omits it, that is schema drift and this run dead-letters rather
than the field quietly resolving to False by accident. Whatever value
ends up in the written Classification was a value the model was forced
to actually emit, not one we defaulted on its behalf.
"""
from __future__ import annotations

import logging

from pydantic import BaseModel, Field

from agents.contracts import NextEvent, RunResult
from data import scope_store
from data.models import (
    Classification,
    Collection,
    DowntimeWindow,
    Envelope,
    IncidentClassified,
    OrgClaim,
    Severity,
    Timeline,
    now,
)
from gateway import agent_gateway

logger = logging.getLogger("mortemtrace.classifier")

AGENT_NAME = "classifier"

_INSTRUCTION = (
    "You are the Classifier agent in an on-call incident response system. "
    "You are given a committed incident timeline (a numbered list of "
    "entries). Classify the incident.\n\n"
    "Fields:\n"
    "- severity: exactly one of sev1 (critical, full outage), sev2 (major "
    "degradation), sev3 (minor or partial impact), sev4 (cosmetic, no "
    "customer impact).\n"
    "- services: the affected service names mentioned in the timeline.\n"
    "- downtime_windows: one entry per distinct outage window you can infer "
    "from the entries (start, end, services). If the incident has no clear "
    "resolution in the timeline, emit a single open-ended window (end "
    "omitted) starting at the first entry that shows impact.\n"
    "- data_touched: true ONLY if the timeline clearly mentions customer "
    "data, PII, a database, user records, exports, or similar being "
    "exposed, accessed, or leaked. This is a considered decision, not a "
    "guess: default to false on ambiguous or silent evidence, and you must "
    "always include this field explicitly - never omit it.\n"
    "- data_categories: only if data_touched is true, the kinds of data "
    "involved (e.g. \"email\", \"payment_card\", \"customer_pii\"); leave "
    "empty otherwise."
)


class ClassificationDraft(BaseModel):
    severity: Severity
    services: list[str] = Field(default_factory=list)
    downtime_windows: list[DowntimeWindow] = Field(default_factory=list)
    data_touched: bool
    data_categories: list[str] = Field(default_factory=list)


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    incident_id = envelope.payload.get("incident_id") or envelope.incident_id
    if not incident_id:
        return RunResult(status="dead_letter", detail="envelope carries no incident_id")

    timeline_raw = scope_store.read(claim, Collection.TIMELINE, incident_id)
    if timeline_raw is None:
        return RunResult(
            status="dead_letter",
            detail=f"no committed timeline for incident {incident_id}; nothing to classify",
        )
    timeline = Timeline.model_validate(timeline_raw)

    agent, outcome = agent_gateway.build_agent(
        name=AGENT_NAME, run_id=claim.run_id, org_id=claim.org_id,
        instruction=_INSTRUCTION, output_schema=ClassificationDraft,
    )
    invoked = agent_gateway.invoke(agent, _build_prompt(timeline), run_id=claim.run_id, org_id=claim.org_id)

    if outcome.blocked:
        return RunResult(
            status="blocked", detail=outcome.block_reason or "blocked by Model Armor",
            tokens_used=invoked.tokens_used, turns=invoked.turns,
        )

    try:
        draft = ClassificationDraft.model_validate_json(invoked.text)
    except Exception as exc:
        return RunResult(
            status="dead_letter", detail=f"classification output failed schema validation: {exc}",
            tokens_used=invoked.tokens_used, turns=invoked.turns,
        )

    classification = Classification(
        incident_id=incident_id,
        org_id=claim.org_id,
        severity=draft.severity,
        services=draft.services,
        downtime_windows=draft.downtime_windows,
        data_touched=draft.data_touched,
        # Belt-and-braces: never let a stray data_categories entry imply a
        # data-touching incident the model just told us was false.
        data_categories=draft.data_categories if draft.data_touched else [],
    )
    scope_store.write(claim, Collection.CLASSIFICATION, incident_id, classification.model_dump(mode="json"))
    if classification.data_touched:
        logger.warning(
            "incident %s classified data_touched=true (run=%s); GDPR clock trigger emitted to Compliance",
            incident_id, claim.run_id,
        )
    else:
        logger.info("classifier wrote classification for incident %s: severity=%s data_touched=false",
                     incident_id, classification.severity)

    return RunResult(
        status="ok",
        next_events=[NextEvent(
            topic="incident.classified",
            payload=IncidentClassified(
                run_id=claim.run_id, org_id=claim.org_id, incident_id=incident_id,
                severity=classification.severity, data_touched=classification.data_touched,
            ).model_dump(mode="json"),
        )],
        tokens_used=invoked.tokens_used, turns=invoked.turns,
    )


def _build_prompt(timeline: Timeline) -> str:
    lines = [f"Incident {timeline.incident_id} - committed timeline ({len(timeline.entries)} entries):"]
    for i, entry in enumerate(timeline.entries):
        lines.append(
            f"[{i}] ts={entry.ts.isoformat()} actor={entry.actor!r} "
            f"action={entry.action!r} evidence={entry.evidence!r}"
        )

    lines.append("")
    lines.append(f"Current time (use as the open end of an unresolved window): {now().isoformat()}")
    lines.append("")
    lines.append("Classify this incident per the fields in your instructions.")
    return "\n".join(lines)
