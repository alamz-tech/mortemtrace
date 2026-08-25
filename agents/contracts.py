"""The interface every worker agent module implements, and that
Coordinator dispatches against uniformly.

A worker module exposes exactly one entrypoint:

    def run(claim: OrgClaim, envelope: Envelope) -> RunResult

`claim` is minted fresh by the Coordinator for this specific invocation
(org_id + this agent's name and registry-resolved version + this run_id)
- the worker never signs its own claim. `envelope` carries the triggering
event's payload. The worker reads/writes exclusively through
data/scope_store.py using `claim`, reasons via gateway.build_agent()/
invoke(), and returns a RunResult describing what happened.

Workers never touch Pub/Sub directly and never decide *who* consumes
their output - that is Coordinator's routing table. A worker that wants
to trigger downstream work says so declaratively via next_event_type/
next_payload; Coordinator is the only thing that actually publishes.
This keeps "Coordinator routes events" true in code, not just in the
architecture doc, and keeps every worker testable as a pure function of
(claim, envelope) -> RunResult with a fake Firestore client and no
Pub/Sub involved at all.
"""
from __future__ import annotations

from typing import Literal, Optional, Protocol

from pydantic import BaseModel

from data.models import Envelope, OrgClaim

RunStatus = Literal[
    "ok",                     # succeeded, may carry a next event to publish
    "blocked",                 # Model Armor blocked input - fail closed, no next event
    "denied",                  # TenantViolation - forged claim, fail closed
    "clarification_needed",    # R1 - confidence too low, exactly one question raised
    "dead_letter",              # schema mismatch or missing source_event_ids - reject, don't coerce
    "degraded",                 # a ScopeDenied was caught and swallowed; run continued with less context
]


class RunResult(BaseModel):
    status: RunStatus
    detail: str = ""
    next_event_type: Optional[str] = None   # a Pub/Sub topic name, e.g. "evidence.staged"
    next_payload: Optional[dict] = None       # already matches that topic's Pydantic schema
    tokens_used: int = 0
    turns: int = 0


class WorkerModule(Protocol):
    def run(self, claim: OrgClaim, envelope: Envelope) -> RunResult: ...
