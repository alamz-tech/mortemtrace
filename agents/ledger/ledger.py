"""Ledger: reconciles staged `IncidentEvent`s into the committed incident
timeline. Sole writer of `timeline` (ARCHITECTURE.md section 6).

Triggered on event_type="evidence.staged"; envelope.payload matches
`data.models.EvidenceStaged` ({run_id, org_id, incident_ref, event_id,
confidence}).

Read scope: events, timeline. Write scope: timeline, events.

Deliberately deterministic - no model call. "Reconciles staged events by
recency and confidence" is a sort/merge over already-extracted data, not
a reasoning task, which keeps Ledger simpler, cheaper, and exhaustively
testable than routing it through the gateway. Every entry it builds
carries `source_event_ids`, which is what makes R9's hallucination guard
at the store layer (data/scope_store.py rejects a timeline write with an
entry missing source_event_ids) never actually trigger in practice.
"""
from __future__ import annotations

import logging

from agents.contracts import NextEvent, RunResult
from data import scope_store
from data.models import (
    Collection,
    Envelope,
    OrgClaim,
    Timeline,
    TimelineCommitted,
    TimelineEntry,
    now,
)

logger = logging.getLogger("mortemtrace.ledger")


def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    event_id = envelope.payload.get("event_id")
    if not event_id:
        return RunResult(status="dead_letter", detail="event_id missing from envelope")

    event = scope_store.read(claim, Collection.EVENTS, event_id)
    if event is None:
        return RunResult(status="dead_letter", detail="staged event not found")

    incident_ref = event.get("incident_ref")
    if not incident_ref:
        return RunResult(status="dead_letter", detail="staged event has no incident_ref")

    entry = _entry_from_event(event)

    def _append(current: dict | None) -> dict:
        """Runs inside a Firestore transaction, and may be retried on
        contention - so it must stay a pure function of `current` with no
        side effects of its own."""
        timeline = (
            Timeline.model_validate(current)
            if current is not None
            else Timeline(incident_id=incident_ref, org_id=claim.org_id)
        )
        if not _has_duplicate_source(timeline, entry):
            timeline.entries.append(entry)
            timeline.entries.sort(key=lambda e: e.ts)
        timeline.last_updated = now()
        return timeline.model_dump(mode="json")

    # Transactional because this is a read-modify-write on one shared
    # document under genuine concurrency: Pub/Sub delivers evidence for
    # the same incident in parallel and Cloud Run runs many instances.
    # The previous read-then-write pair silently lost entries - two
    # deliveries would each read the same timeline, each append their own
    # entry, and whichever wrote second discarded the other's work with
    # no error and no log. That is data loss on the single artifact this
    # product exists to produce.
    committed = scope_store.update_in_transaction(
        claim, Collection.TIMELINE, incident_ref, _append,
    )
    entry_count = len(committed.get("entries", []))

    # Re-read-and-flip rather than reusing the dict fetched above: this is
    # its own distinct store operation (status transition on the source
    # record), kept separate from the reconciliation step it follows.
    committed_event = scope_store.read(claim, Collection.EVENTS, event_id)
    if committed_event is not None:
        committed_event["status"] = "committed"
        scope_store.write(claim, Collection.EVENTS, event_id, committed_event)

    next_event = NextEvent(
        topic="timeline.committed",
        payload=TimelineCommitted(
            run_id=claim.run_id,
            org_id=claim.org_id,
            incident_id=incident_ref,
            entry_count=entry_count,
        ).model_dump(mode="json"),
    )
    return RunResult(status="ok", next_events=[next_event])


def _entry_from_event(event: dict) -> TimelineEntry:
    extracted = event.get("extracted") or {}
    action = extracted.get("action", "evidence recorded")
    actor = extracted.get("actor", "system")
    confidence = event.get("confidence", 0.0) or 0.0
    return TimelineEntry(
        ts=event["ts"],
        actor=actor,
        action=action,
        evidence=f"{action} (confidence {confidence:.2f}, source event {event['event_id']})",
        source_event_ids=[event["event_id"]],
    )


def _has_duplicate_source(timeline: Timeline, entry: TimelineEntry) -> bool:
    incoming = set(entry.source_event_ids)
    return any(set(existing.source_event_ids) == incoming for existing in timeline.entries)
