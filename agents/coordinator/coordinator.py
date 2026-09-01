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

import concurrent.futures
import logging
import random
import time
from typing import Callable, Optional

from agents.contracts import RunResult
from agents.guardian import guardian
from data import scope_store
from data.models import Collection, Envelope, OrgClaim, Run, now
from gateway.agent_gateway import LoopDetected
from registry import registry
from telemetry import otel_setup

logger = logging.getLogger("mortemtrace.coordinator")

COORDINATOR_NAME = "coordinator"
COORDINATOR_VERSION = "1.0.0"
GUARDIAN_NAME = "guardian"
GUARDIAN_VERSION = "1.0.0"

_MAX_TURNS = 20
_MAX_TOKENS = 200_000
_MAX_RETRIES = 3

# A worker raising one of these did not fail because of a transient
# network/quota blip - it failed because of malformed data or a
# programming error, and will raise the identical exception on every
# retry. Backing off and retrying it three times only spends ~24s of
# wall-clock time (see _BACKOFF_BASE_SECONDS) making the eventual
# dead-letter slower, which compounds the ack-deadline risk documented on
# _dispatch_concurrently - a KeyError from a malformed staged event
# (agents/ledger/ledger.py's `event["ts"]`) is exactly this case, found
# live. Deliberately conservative: only exception types that are never
# used by this codebase's own transient/network failure paths (Vertex
# AI's client raises google.api_core.exceptions.GoogleAPICallError
# subclasses, not these) are listed, so an exception type not seen before
# still gets the safe default of a retry.
_TERMINAL_EXCEPTION_TYPES = (KeyError, TypeError, AttributeError, ValueError, IndexError)
# 8s base -> backoffs of ~8s, ~16s (~24s total across 2 waits). Widened
# from an original 1s base (~3s total) after live-testing surfaced real
# 429 RESOURCE_EXHAUSTED responses from Vertex AI: a per-minute-style
# quota needs real wall-clock time to reset, and 3s of total backoff
# never gave it that chance - every retry was hitting the same still-
# exhausted window. Bounded to stay well under the 60s Pub/Sub
# ack-deadline (infra/setup_pubsub_push.sh) so this doesn't also trigger
# a redundant Pub/Sub-level redelivery on top of these retries.
_BACKOFF_BASE_SECONDS = 8.0

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
    # Cloud Scheduler hits an HTTP endpoint (api/ingest.py's /watcher/sweep),
    # not a Pub/Sub delivery, but routing it through the same table keeps
    # Watcher's dispatch - quarantine check, retry/backoff, budget, Guardian
    # pre/post-flight - identical to every other worker's instead of a
    # special-cased bypass.
    "watcher.sweep": ["watcher"],
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

    if len(agent_names) == 1:
        result = dispatch(agent_names[0], envelope)
        if result.status == "ok":
            for next_event in result.next_events:
                publish(next_event.topic, next_event.payload)
        return [result]

    results = _dispatch_concurrently(agent_names, envelope)
    for result in results:
        if result.status == "ok":
            for next_event in result.next_events:
                publish(next_event.topic, next_event.payload)
    return results


def _dispatch_concurrently(agent_names: list[str], envelope: Envelope) -> list[RunResult]:
    """Runs every worker subscribed to one event in parallel rather than
    one after another.

    Found live: timeline.committed fans out to six departments, each
    making a real, blocking Gemini call. In series that regularly runs
    past Pub/Sub's 60s push ack deadline (infra/setup_pubsub_push.sh),
    which redelivers the same message mid-fan-out and re-dispatches every
    department a second time - the actual cause behind the duplicate-
    draft bug found and fixed in agents/ledger/ledger.py, one hop
    earlier, and behind department-level idempotency guards added
    alongside this fix (diagnosis.py, classifier.py, and the four
    agents/departments/*.py writers).

    Threads, not asyncio: dispatch() is a synchronous blocking call chain
    (Firestore reads/writes, a Gemini call) end to end, the same shape as
    every other blocking-work boundary in this codebase (api/ingest.py's
    asyncio.to_thread). The six departments are independent of each other
    by construction - different scopes, different collections written -
    so there is no ordering dependency stopping them running at once, and
    Cloud Run already serves this many concurrent requests per instance
    by default, so concurrent use of the Firestore/Vertex AI clients here
    is not a new requirement this introduces.
    """
    results: list[Optional[RunResult]] = [None] * len(agent_names)
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(agent_names)) as pool:
        future_to_index = {
            pool.submit(dispatch, agent_name, envelope): i
            for i, agent_name in enumerate(agent_names)
        }
        for future in concurrent.futures.as_completed(future_to_index):
            index = future_to_index[future]
            agent_name = agent_names[index]
            try:
                results[index] = future.result()
            except Exception:
                # dispatch() already converts everything it knows how to
                # retry or dead-letter into a RunResult; anything that
                # still escapes here is unexpected. One department's
                # unexpected failure must not take the other five down
                # with it - the same "degrade, don't fail the whole run"
                # posture used everywhere else in this fan-out.
                logger.exception(
                    "dispatch of %s raised unexpectedly (run=%s); other "
                    "departments in this fan-out are unaffected",
                    agent_name, envelope.run_id,
                )
                results[index] = RunResult(
                    status="dead_letter", detail=f"unexpected exception dispatching {agent_name}",
                )
    return results


def dispatch(agent_name: str, envelope: Envelope) -> RunResult:
    """One worker, one envelope: quarantine check, Guardian pre-flight,
    retry/backoff on transient failure, budget + loop enforcement,
    Guardian post-flight. This is the unit Coordinator's own tests
    exercise directly - route() is a thin fan-out loop on top of it.

    Wrapped in an agent-invocation span. R10 requires one per agent call,
    and there was none: this module imported no telemetry at all, so
    telemetry.agent_invocation() existed but was never called from
    anywhere, and a trace showed the ingest span jumping straight to a
    model call with no record of which agent ran or what it returned.
    """
    coordinator_claim = _coordinator_claim(envelope.org_id, envelope.run_id)
    guardian_claim = _guardian_claim(envelope.org_id, envelope.run_id)

    resolved = registry.resolve(coordinator_claim, agent_name)
    version = resolved.version if resolved else "unresolved"

    with otel_setup.agent_invocation(
        agent_name, version, envelope.run_id, envelope.org_id, envelope.incident_id,
    ) as span:
        result = _dispatch_inner(
            agent_name, resolved, envelope, coordinator_claim, guardian_claim,
        )
        span.set_attribute("mortemtrace.status", result.status)
        span.set_attribute("mortemtrace.tokens.total", result.tokens_used)
        span.set_attribute("mortemtrace.turns", result.turns)

    _record_outcome(agent_name, version, envelope, result)
    return result


def _record_outcome(agent_name: str, version: str, envelope: Envelope, result: RunResult) -> None:
    """One structured, alertable record per dispatch outcome.

    Non-`ok` statuses become countable metrics rather than something an
    operator only discovers by noticing missing drafts - there were no
    metrics of any kind before this, so nothing could page on a rising
    dead-letter rate."""
    otel_setup.record_metric(
        "agent_dispatch",
        labels_status=result.status,
        agent_name=agent_name,
        run_id=envelope.run_id,
        org_id=envelope.org_id,
        status=result.status,
    )
    if result.status != "ok":
        logger.warning(
            "dispatch of %s@%s finished as %s: %s",
            agent_name, version, result.status, result.detail,
            extra={
                "run_id": envelope.run_id, "org_id": envelope.org_id,
                "incident_id": envelope.incident_id, "agent_name": agent_name,
                "status": result.status,
            },
        )


def _dispatch_inner(
    agent_name: str,
    resolved,
    envelope: Envelope,
    coordinator_claim: OrgClaim,
    guardian_claim: OrgClaim,
) -> RunResult:
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

    result = _attempt_with_retry(
        agent_name, resolved.version, run_fn, worker_claim, coordinator_claim, envelope, guardian_claim,
    )
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
    guardian_claim: OrgClaim,
) -> RunResult:
    last_error: Optional[Exception] = None
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            result = run_fn(worker_claim, envelope)
            if result.turns > _MAX_TURNS or result.tokens_used > _MAX_TOKENS:
                _quarantine(coordinator_claim, agent_name, agent_version, envelope, guardian_claim,
                            reason=f"budget exceeded: turns={result.turns} tokens={result.tokens_used}")
                return RunResult(status="dead_letter", detail="turn/token budget exceeded; quarantined",
                                  turns=result.turns, tokens_used=result.tokens_used)
            return result
        except LoopDetected as exc:
            _quarantine(coordinator_claim, agent_name, agent_version, envelope, guardian_claim,
                        reason=str(exc))
            return RunResult(status="dead_letter", detail=f"loop detected: {exc}")
        except scope_store.TenantViolation as exc:
            return RunResult(status="denied", detail=str(exc))
        except _TERMINAL_EXCEPTION_TYPES as exc:
            otel_setup.record_metric(
                "agent_attempt_failed", agent_name=agent_name,
                run_id=envelope.run_id, org_id=envelope.org_id,
            )
            logger.warning(
                "%s raised a terminal %s (not retrying): %s",
                agent_name, type(exc).__name__, exc,
                extra={"run_id": envelope.run_id, "org_id": envelope.org_id, "agent_name": agent_name},
            )
            return RunResult(status="dead_letter", detail=f"terminal {type(exc).__name__}: {exc}")
        except Exception as exc:  # transient failure path only
            last_error = exc
            otel_setup.record_metric(
                "agent_attempt_failed", agent_name=agent_name,
                run_id=envelope.run_id, org_id=envelope.org_id,
            )
            if attempt < _MAX_RETRIES:
                # Jitter only - decorrelates retries across instances so they do
                # not all wake together. Not a security primitive.
                backoff = _BACKOFF_BASE_SECONDS * (2 ** (attempt - 1)) + random.uniform(0, 0.5)  # noqa: S311
                logger.warning(
                    "attempt %d/%d for %s failed (%s), retrying in %.1fs",
                    attempt, _MAX_RETRIES, agent_name, exc, backoff,
                    extra={"run_id": envelope.run_id, "org_id": envelope.org_id,
                           "agent_name": agent_name},
                )
                time.sleep(backoff)
    return RunResult(status="dead_letter", detail=f"exhausted retries: {last_error}")


def _is_quarantined(coordinator_claim: OrgClaim, agent_name: str, version: str) -> bool:
    hits = scope_store.try_query(
        coordinator_claim, Collection.QUARANTINE,
        filters=[("agent_name", "==", agent_name), ("version", "==", version)],
        limit=1,
    )
    return bool(hits)


def _quarantine(coordinator_claim: OrgClaim, agent_name: str, agent_version: str,
                envelope: Envelope, guardian_claim: OrgClaim, *, reason: str) -> None:
    doc_id = f"{agent_name}__{agent_version}"
    scope_store.write(coordinator_claim, Collection.QUARANTINE, doc_id, {
        "agent_name": agent_name, "version": agent_version,
        "reason": reason, "quarantined_at": now().isoformat(),
    })
    # Guardian's docstring promises /alerts indexes every non-happy-path
    # outcome, and quarantine is the most severe of them - but
    # escalate_quarantine() had zero call sites, so quarantines were the
    # one outcome missing from the index that claimed to be complete.
    guardian.escalate_quarantine(guardian_claim, envelope, agent_name=agent_name, reason=reason)
    otel_setup.record_metric(
        "agent_quarantined", agent_name=agent_name,
        run_id=envelope.run_id, org_id=envelope.org_id,
    )
    logger.error(
        "quarantined %s@%s: %s", agent_name, agent_version, reason,
        extra={"run_id": envelope.run_id, "org_id": envelope.org_id, "agent_name": agent_name},
    )


def _touch_run(claim: OrgClaim, envelope: Envelope, agent_name: str, result: RunResult) -> None:
    """Accumulates one dispatch's outcome into the shared run record.

    Transactional: a run_id spans an entire ingest-to-drafts chain, and
    `timeline.committed` fans out to six workers that Pub/Sub delivers
    concurrently. The previous read-then-write lost agents_invoked
    entries and token counts the same way the timeline lost entries, just
    less visibly - the run record simply under-reported what had run.
    """
    def _merge(existing: Optional[dict]) -> dict:
        record = existing or Run(
            run_id=envelope.run_id, org_id=envelope.org_id, status="running",
        ).model_dump(mode="json")

        invoked = set(record.get("agents_invoked", []))
        invoked.add(agent_name)
        record["agents_invoked"] = sorted(invoked)
        record["turns_used"] = record.get("turns_used", 0) + result.turns
        record["tokens_used"] = record.get("tokens_used", 0) + result.tokens_used
        record["updated_at"] = now().isoformat()

        current_status = record.get("status", "running")
        current_status = "ok" if current_status == "running" else current_status
        if _STATUS_SEVERITY.get(result.status, 0) >= _STATUS_SEVERITY.get(current_status, 0):
            record["status"] = result.status if result.status != "ok" else "running"
        else:
            record["status"] = current_status if current_status != "ok" else "running"

        # Validate before persisting. data/models.py claims every document
        # is schema-checked at the boundary; for runs that was not true,
        # which is how "dead_letter" (not a legal RunStatus at the time)
        # ended up stored. Round-tripping through the model makes the
        # claim hold and would have surfaced that drift immediately.
        return Run.model_validate(record).model_dump(mode="json")

    scope_store.update_in_transaction(claim, Collection.RUNS, envelope.run_id, _merge)
