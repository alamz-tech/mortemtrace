"""Watcher: reacts to the world changing, not only to inbound alerts.

Per SPEC-postmortem.md R3 and ARCHITECTURE.md section 4 ("The Watcher,
correlated not broadcast"), Watcher polls external feeds on a schedule
(cloud provider status, dependency changelogs, CVE feed), correlates each
signal against active incidents by affected service and dependency graph,
and emits `UpstreamSignalMatched` **only** for incidents that are
genuinely affected. Everything else must stay untouched: no event, no
write, no side effect referencing an unaffected incident. The demo's
Watcher beat (SPEC section 10, beat 5) is judged on exactly this negative
case - three active incidents, one correlated, two visibly untouched.

Trigger: Cloud Scheduler hits an HTTP endpoint (built elsewhere), not a
Pub/Sub event, but this module still exposes the same
`run(claim, envelope) -> RunResult` contract as every other worker
(agents/contracts.py) for consistency with how Coordinator dispatches.
`envelope.event_type` is "watcher.sweep"; `envelope.payload` is normally
`{}` since the sweep decides what to check on its own, but may carry an
"injected_signal" (a Signal-shaped dict) so a demo operator can force a
specific, deterministic correlation instead of whatever the mock feed
returns - see `_poll_mock_feed` and `_sweep` below.

No LLM call. Matching a signal's (provider, region, service) against a
dependency graph is a lookup/graph-traversal problem, not a reasoning
one, and per ARCHITECTURE.md section 3 rule 4, Watcher never touches
incident *state* - it reads the incident index (status, services_affected)
and the service dependency graph purely to correlate, and writes only to
`signals`. It never writes to `incidents`, `timeline`, or any other
incident-content collection.

Known limitation, deliberately not worked around: `data/models.py`'s
`Service` record carries no `region` or `provider` field, so a signal's
region/provider cannot be cross-checked against where the affected
service actually runs - correlation here is by service/dependency name
only. Inventing a field that isn't in the model to fake that precision
would be worse than stating the limitation.
"""
from __future__ import annotations

import logging
from typing import Optional

from data import scope_store
from data.models import (
    Collection,
    DowntimeWindow,
    Envelope,
    OrgClaim,
    Signal,
    UpstreamSignalMatched,
    new_id,
    now,
)
from agents.contracts import NextEvent, RunResult

logger = logging.getLogger("mortemtrace.watcher")

# How many depends_on hops past an incident's directly affected service to
# walk looking for a match. SPEC/ARCHITECTURE call for "one or two levels"
# / "2-3 levels" - bounded and cycle-protected (see _find_match_chain) is
# the point: a real service graph can have cycles from bad seed data, and
# an unbounded walk has no place on the path the demo's negative case
# depends on.
_MAX_DEPENDENCY_DEPTH = 2


# --------------------------------------------------------------------------
# Mock external feed
# --------------------------------------------------------------------------

def _poll_mock_feed() -> list[Signal]:
    """Stand-in for a live provider-status / changelog / CVE feed - a live
    integration is explicitly a non-goal (SPEC section 3: "No live
    PagerDuty, Datadog, or Slack integrations"). Shapes signals like the
    three feed kinds R3 names. Deterministic on purpose (no randomness):
    a demo or a test that needs one exact signal should pass
    `injected_signal` to `_sweep`/`run` instead of relying on this feed,
    which is the whole reason this is a separate, overridable function.
    """
    return [
        Signal(
            signal_id=new_id("sig"), source="provider_status", provider="aws",
            region="us-east-1", service="rds", severity="degraded",
            window=DowntimeWindow(start=now()),
        ),
        Signal(
            signal_id=new_id("sig"), source="dependency_changelog", provider="github",
            region="global", service="stripe-sdk", severity="breaking_change",
            window=DowntimeWindow(start=now()),
        ),
        Signal(
            signal_id=new_id("sig"), source="cve_feed", provider="nvd",
            region="global", service="openssl", severity="critical",
            window=DowntimeWindow(start=now()),
        ),
    ]


# --------------------------------------------------------------------------
# Dependency-graph correlation
# --------------------------------------------------------------------------

def _norm(identifier: str) -> str:
    return (identifier or "").strip().lower()


def _identifiers_match(a: str, b: str) -> bool:
    return _norm(a) == _norm(b)


def _index_services(services: list[dict]) -> dict[str, dict]:
    """Keyed by both `service_id` and `name` (normalized). `services_
    affected` and `depends_on` entries aren't guaranteed to use one
    convention consistently, and silently picking the wrong one would
    turn a real dependency match into a false negative - exactly the
    failure mode the demo's positive case can't afford.
    """
    index: dict[str, dict] = {}
    for svc in services:
        for identifier in (svc.get("service_id"), svc.get("name")):
            if identifier:
                index[_norm(identifier)] = svc
    return index


def _find_match_chain(
    root: str,
    signal: Signal,
    services_by_key: dict[str, dict],
    *,
    max_depth: int = _MAX_DEPENDENCY_DEPTH,
) -> Optional[list[str]]:
    """BFS outward from one entry of an incident's `services_affected`,
    following `depends_on` edges, looking for something whose identifier
    matches `signal.service`. Returns the chain from `root` to the match
    (inclusive), or None if nothing within `max_depth` hops matches.

    Cycle-protected via a `visited` set of normalized identifiers and
    bounded to `max_depth` hops past the root - sufficient per SPEC's own
    guidance ("2-3 levels") and deliberately not a general graph
    algorithm, since a full unbounded traversal is both unnecessary here
    and a way to accidentally correlate something three services removed
    that no one would call "genuinely affected."
    """
    if _identifiers_match(root, signal.service):
        return [root]

    visited = {_norm(root)}
    frontier: list[tuple[str, list[str]]] = [(root, [root])]
    for _ in range(max_depth):
        next_frontier: list[tuple[str, list[str]]] = []
        for key, path in frontier:
            service = services_by_key.get(_norm(key))
            if service is None:
                continue  # unknown identifier (e.g. a provider-side name
                          # we have no Service doc for) - nothing to expand
            for dep in service.get("depends_on", []):
                if _norm(dep) in visited:
                    continue  # cycle protection
                visited.add(_norm(dep))
                new_path = path + [dep]
                if _identifiers_match(dep, signal.service):
                    return new_path
                next_frontier.append((dep, new_path))
        frontier = next_frontier
        if not frontier:
            break
    return None


def _match_incident(
    incident: dict, signal: Signal, services_by_key: dict[str, dict],
) -> Optional[tuple[str, list[str]]]:
    """Checks every service in this incident's `services_affected` against
    the signal, direct match first, then its dependency graph. Returns the
    first (matched_root, chain) found, or None - an incident either is or
    isn't genuinely affected by a given signal, one match is enough to
    correlate it, and R3 doesn't ask for a ranked or exhaustive match set.
    """
    for svc_ref in incident.get("services_affected", []):
        chain = _find_match_chain(svc_ref, signal, services_by_key)
        if chain is not None:
            return svc_ref, chain
    return None


def _correlation_reason(matched_root: str, chain: list[str], signal: Signal) -> str:
    if len(chain) == 1:
        return (
            f"incident's service '{matched_root}' matches the signal directly "
            f"({signal.provider}/{signal.region}, service='{signal.service}', "
            f"severity={signal.severity})"
        )
    path = " -> ".join(chain)
    return (
        f"incident's service '{matched_root}' depends on '{chain[-1]}' "
        f"(dependency path: {path}), which the sweep found {signal.severity} "
        f"in {signal.provider}/{signal.region}"
    )


# --------------------------------------------------------------------------
# Sweep
# --------------------------------------------------------------------------

def _sweep(
    claim: OrgClaim, *, injected_signal: Optional[Signal] = None,
) -> tuple[list[Signal], list[NextEvent]]:
    """The correlation core, factored out from `run()` so a test - or a
    demo operator wiring the HTTP endpoint - can inject one specific,
    deterministic signal instead of the mock feed. This is what lets
    someone "inject a provider status degradation" live in the demo
    (SPEC section 10, beat 5) rather than hoping the mock feed happens to
    produce the right thing on cue.

    Every polled/injected signal is written to `signals` regardless of
    whether anything correlates - the write and the correlation are
    independent, and R3's negative case is about which *incidents* get
    touched, not about withholding the signal record itself.
    """
    signals = [injected_signal] if injected_signal is not None else _poll_mock_feed()

    for signal in signals:
        scope_store.write(
            claim, Collection.SIGNALS, signal.signal_id, signal.model_dump(mode="json"),
        )

    # Active-incident index only (status + services_affected) - not raw
    # evidence, timeline, or hypotheses. Org scoping is automatic via the
    # claim/path in scope_store; no org_id filter needed here.
    incidents = scope_store.try_query(
        claim, Collection.INCIDENTS, filters=[("status", "==", "open")],
    )
    services_by_key = _index_services(
        scope_store.try_query(claim, Collection.SERVICES, filters=[])
    )

    next_events: list[NextEvent] = []
    for incident in incidents:
        if incident.get("status") != "open":
            continue  # belt-and-suspenders - try_query already filtered on this

        for signal in signals:
            match = _match_incident(incident, signal, services_by_key)
            if match is None:
                continue  # the negative case: no event, no write, nothing
            matched_root, chain = match
            next_events.append(NextEvent(
                topic="upstream.matched",
                payload=UpstreamSignalMatched(
                    run_id=claim.run_id,
                    org_id=claim.org_id,
                    incident_id=incident["incident_id"],
                    signal_id=signal.signal_id,
                    correlation_reason=_correlation_reason(matched_root, chain, signal),
                ).model_dump(mode="json"),
            ))

    logger.info(
        "watcher sweep: %d signal(s) polled, %d incident(s) correlated",
        len(signals), len(next_events),
    )
    return signals, next_events


def _extract_injected_signal(envelope: Envelope) -> Optional[Signal]:
    raw = envelope.payload.get("injected_signal")
    if raw is None:
        return None
    return Signal.model_validate(raw)


# --------------------------------------------------------------------------
# Worker entrypoint
# --------------------------------------------------------------------------

def run(claim: OrgClaim, envelope: Envelope) -> RunResult:
    injected_signal = _extract_injected_signal(envelope)
    signals, next_events = _sweep(claim, injected_signal=injected_signal)
    detail = f"{len(signals)} signal(s) polled, {len(next_events)} incident(s) correlated"
    return RunResult(status="ok", detail=detail, next_events=next_events)
