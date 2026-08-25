"""Supervisor: routes events by type, resolves agent versions from the
registry, enforces turn/token budgets, detects loops, quarantines
misbehaving agent versions, retries transient failures with backoff.
Never reasons about incidents itself - every actual decision about an
incident is made by a worker this module dispatches to.

`envelope.run_id` is shared across an entire ingest-to-drafts chain, not
one agent call, so the /runs/{run_id} record accumulates agents_invoked,
turns, and tokens across every dispatch in that chain rather than being
recreated each time.
"""
from __future__ import annotations

import logging
import random
import time
from typing import Callable, Optional

from data import scope_store
from data.models import Collection, Envelope, OrgClaim, Run, now
from agents.contracts import RunResult
from agents.guardian import guardian
from gateway.agent_gateway import LoopDetected
from registry import registry

logger = logging.getLogger("mortemtrace.coordinator")

COORDINATOR_NAME = "coordinator"
COORDINATOR_VERSION = "1.0.0"
GUARDIAN_NAME = "guardian"
GUARDIAN_VERSION = "1.0.0"

_MAX_TURNS = 20
_MAX_TOKENS = 200_000
_MAX_RETRIES = 3
_BACKOFF_BASE_SECONDS = 1.0

# Worst-first: used to decide whether a new dispatch's status should
# overwrite the run's recorded status. A run that had one blocked call
# stays "blocked" even if a later, unrelated dispatch in the same chain
# succeeds - the operator needs to see the worst thing that happened.
_STATUS_SEVERITY = {
    "dead_letter": 5, "denied": 4, "blocked": 3, "degraded": 2,
    "clarification_needed": 1, "ok": 0,
}

# event_type -> workers subscribed to it. A single incoming event can
# fan out to more than one worker - timeline.committed reaches Diagnosis,
# Classifier, and all four departmental agents independently, matching
# architecture.mermaid's `T3 --> PM & CM & CP & EXPO`.
_ROUTES: dict[str, list[str]] = {
    "evidence.received": ["intake"],
    "evidence.staged": ["ledger"],
    "timeline.committed": ["diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"],
    "incident.classified": ["compliance"],
    "upstream.matched": ["diagnosis"],
}

_WORKERS: dict[str, Callable[[OrgClaim, Envelope], RunResult]] = {}


def register_worker(agent_name: str, run_fn: Callable[[OrgClaim, Envelope], RunResult]) -> None:
    """Workers self-register at import time. This is Python wiring, not
    the registry - it says "this code exists and can be called," never
    "this code is active for this org," which is what the Firestore
    registry entry's `published` status controls. A new department's
    code still has to ship once; publishing it is what makes it live
    with no further redeploy (R4)."""
    _WORKERS[agent_name] = run_fn


def _coordinator_claim(org_id: str, run_id: str) -> OrgClaim:
    return scope_store.sign_claim(
        org_id=org_id, agent_name=COORDINATOR_NAME, agent_version=COORDINATOR_VERSION, run_id=run_id,
    )


def _guardian_claim(org_id: str, run_id: str) -> OrgClaim:
    return scope_store.sign_claim(
        org_id=org_id, agent_name=GUARDIAN_NAME, agent_version=GUARDIAN_VERSION, run_id=run_id,
    )


def route(event_type: str, envelope: Envelope, *, publish: Callable[[str, dict], None]) -> list[RunResult]:
    """Entry point called by api/ingest.py's Pub/Sub push handler, once
    per delivered message. Dispatches to every worker subscribed to this
    event type and publishes each one's declared next event through
    `publish` - the caller's real Pub/Sub client. Coordinator never
    imports pubsub itself, which is what makes route() testable with a
    plain list-appending stub instead of a broker."""
    agent_names = _ROUTES.get(event_type, [])
    if not agent_names:
        logger.warning("no route for event_type=%s (run=%s)", event_type, envelope.run_id)
        return []

    results = []
    for agent_name in agent_names:
        result = dispatch(agent_name, envelope)
        results.append(result)
        if result.status == "ok" and result.next_event_type and result.next_payload:
            publish(result.next_event_type, result.next_payload)
    return results


def dispatch(agent_name: str, envelope: Envelope) -> RunResult:
    """One worker, one envelope: quarantine check, Guardian pre-flight,
    retry/backoff on transient failure, budget + loop enforcement,
    Guardian post-flight. This is the unit Coordinator's own tests
    exercise directly - route() is a thin fan-out loop on top of it."""
    coordinator_claim = _coordinator_claim(envelope.org_id, envelope.run_id)
    guardian_claim = _guardian_claim(envelope.org_id, envelope.run_id)

    resolved = registry.resolve(coordinator_claim, agent_name)
    if resolved is None:
        result = RunResult(status="dead_letter", detail=f"no published version for {agent_name}")
        _touch_run(coordinator_claim, envelope, agent_name, result)
        return result

    if _is_quarantined(coordinator_claim, agent_name, resolved.version):
        result = RunResult(status="dead_letter", detail=f"{agent_name}@{resolved.version} is quarantined")
        _touch_run(coordinator_claim, envelope, agent_name, result)
        return result

    run_fn = _WORKERS.get(agent_name)
    if run_fn is None:
        result = RunResult(status="dead_letter", detail=f"{agent_name} has no registered implementation")
        _touch_run(coordinator_claim, envelope, agent_name, result)
        return result

    preflight = guardian.preflight(guardian_claim, envelope)
    if not preflight.allowed:
        result = RunResult(status="blocked", detail=preflight.reason)
        _touch_run(coordinator_claim, envelope, agent_name, result)
        guardian.postflight(guardian_claim, envelope, agent_name=agent_name, status=result.status, detail=result.detail)
        return result

    worker_claim = scope_store.sign_claim(
        org_id=envelope.org_id, agent_name=agent_name, agent_version=resolved.version, run_id=envelope.run_id,
    )

    result = _attempt_with_retry(agent_name, resolved.version, run_fn, worker_claim, coordinator_claim, envelope)
    _touch_run(coordinator_claim, envelope, agent_name, result)
    guardian.postflight(guardian_claim, envelope, agent_name=agent_name, status=result.status, detail=result.detail)
    return result


def _attempt_with_retry(
    agent_name: str,
    agent_version: str,
    run_fn: Callable[[OrgClaim, Envelope], RunResult],
    worker_claim: OrgClaim,
    coordinator_claim: OrgClaim,
    envelope: Envelope,
) -> RunResult:
    last_error: Optional[Exception] = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            result = run_fn(worker_claim, envelope)
            if result.turns > _MAX_TURNS or result.tokens_used > _MAX_TOKENS:
                _quarantine(coordinator_claim, agent_name, agent_version,
                            reason=f"budget exceeded: turns={result.turns} tokens={result.tokens_used}")
                return RunResult(status="dead_letter", detail="turn/token budget exceeded; quarantined",
                                  turns=result.turns, tokens_used=result.tokens_used)
            return result
        except LoopDetected as exc:
            _quarantine(coordinator_claim, agent_name, agent_version, reason=str(exc))
            return RunResult(status="dead_letter", detail=f"loop detected: {exc}")
        except scope_store.TenantViolation as exc:
            return RunResult(status="denied", detail=str(exc))
        except Exception as exc:  # transient failure path only
            last_error = exc
            if attempt < _MAX_RETRIES:
                backoff = _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, 0.5)
                logger.warning("attempt %d/%d for %s failed (%s), retrying in %.1fs",
                               attempt, _MAX_RETRIES, agent_name, exc, backoff)
                time.sleep(backoff)
    return RunResult(status="dead_letter", detail=f"exhausted retries: {last_error}")


def _is_quarantined(coordinator_claim: OrgClaim, agent_name: str, version: str) -> bool:
    hits = scope_store.try_query(
        coordinator_claim, Collection.QUARANTINE,
        filters=[("agent_name", "==", agent_name), ("version", "==", version)],
        limit=1,
    )
    return bool(hits)


def _quarantine(coordinator_claim: OrgClaim, agent_name: str, agent_version: str, *, reason: str) -> None:
    doc_id = f"{agent_name}__{agent_version}"
    scope_store.write(coordinator_claim, Collection.QUARANTINE, doc_id, {
        "agent_name": agent_name, "version": agent_version,
        "reason": reason, "quarantined_at": now().isoformat(),
    })
    logger.error("quarantined %s@%s: %s", agent_name, agent_version, reason)


def _touch_run(claim: OrgClaim, envelope: Envelope, agent_name: str, result: RunResult) -> None:
    existing = scope_store.try_read(claim, Collection.RUNS, envelope.run_id)
    if existing is None:
        existing = Run(run_id=envelope.run_id, org_id=envelope.org_id, status="running").model_dump(mode="json")

    invoked = set(existing.get("agents_invoked", []))
    invoked.add(agent_name)
    existing["agents_invoked"] = sorted(invoked)
    existing["turns_used"] = existing.get("turns_used", 0) + result.turns
    existing["tokens_used"] = existing.get("tokens_used", 0) + result.tokens_used

    current_status = existing.get("status", "running")
    current_status = "ok" if current_status == "running" else current_status
    if _STATUS_SEVERITY.get(result.status, 0) >= _STATUS_SEVERITY.get(current_status, 0):
        existing["status"] = result.status if result.status != "ok" else "running"
    else:
        existing["status"] = current_status if current_status != "ok" else "running"

    scope_store.write(claim, Collection.RUNS, envelope.run_id, existing)
