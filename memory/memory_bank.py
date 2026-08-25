"""Per-org persistent context that survives weeks of asynchronous
operation: prior incident signatures, service ownership, recurring
failure patterns, per-customer SLA terms, unresolved clarifications.

A thin, scoped wrapper over Collection.MEMORY - retrieval is structured
(filter by kind and/or a related incident id), never raw chat history,
so what gets injected into a prompt is always something a trace can cite
by memory key (R6 acceptance: "its trace cites the prior incident ID
from memory").
"""
from __future__ import annotations

from typing import Optional

from data import scope_store
from data.models import Collection, MemoryRecord, OrgClaim


def remember(claim: OrgClaim, record: MemoryRecord) -> None:
    scope_store.write(claim, Collection.MEMORY, record.key, record.model_dump(mode="json"))


def retrieve(
    claim: OrgClaim,
    *,
    kind: Optional[str] = None,
    related_incident_id: Optional[str] = None,
    limit: int = 10,
) -> list[MemoryRecord]:
    """Degrades to an empty list (not an error) if the caller's registry
    scope doesn't include MEMORY - most workers should treat "no memory
    context available" as reduced context, not a failure."""
    filters = []
    if kind is not None:
        filters.append(("kind", "==", kind))
    if related_incident_id is not None:
        filters.append(("related_incident_ids", "array_contains", related_incident_id))

    raw = scope_store.try_query(claim, Collection.MEMORY, filters=filters, limit=limit)
    return [MemoryRecord.model_validate(r) for r in raw]
