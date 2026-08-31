"""R3 acceptance made executable: "Given three active incidents of which
one involves a service that depends on the newly-degraded provider
region, when the sweep runs, then exactly one incident receives an
upstream correlation and the other two are untouched."

The negative case is the point (ARCHITECTURE.md section 4: "Judges look
for the negative case"), so it gets tested explicitly and more than once,
not just implied by the positive case passing.

No LLM/Model Armor involved - Watcher makes no model call - so these
tests are fast and purely deterministic against the fake Firestore, same
approach as tests/test_scope_store.py.
"""
from __future__ import annotations

from agents.watcher import watcher
from data import scope_store
from data.models import Collection, DowntimeWindow, Envelope, Signal, now
from tests.conftest import TEST_ORG, seed_agent


def _watcher_claim(run_id: str = "run_1"):
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="watcher", agent_version="1.0.0", run_id=run_id)


def _seed_watcher(fake_db) -> None:
    seed_agent(
        fake_db, "watcher", "1.0.0",
        read_scopes=[Collection.SIGNALS, Collection.INCIDENTS, Collection.SERVICES],
        write_scopes=[Collection.SIGNALS],
    )


def _seed_service(fake_db, service_id: str, name: str, depends_on: list[str] | None = None) -> None:
    fake_db.seed(f"tenants/{TEST_ORG}/services/{service_id}", {
        "service_id": service_id, "org_id": TEST_ORG, "name": name,
        "owner_team": "platform", "depends_on": depends_on or [], "criticality": "medium",
    })


def _seed_incident(fake_db, incident_id: str, services_affected: list[str], status: str = "open") -> None:
    fake_db.seed(f"tenants/{TEST_ORG}/incidents/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG,
        "opened_at": "2026-08-25T03:00:00+00:00", "status": status,
        "services_affected": services_affected,
    })


def _rds_signal(signal_id: str = "sig_rds_test") -> Signal:
    return Signal(
        signal_id=signal_id, source="provider_status", provider="aws",
        region="us-east-1", service="rds", severity="degraded",
        window=DowntimeWindow(start=now()),
    )


# --------------------------------------------------------------------------
# R3 acceptance, verbatim
# --------------------------------------------------------------------------

def test_sweep_correlates_exactly_one_of_three_incidents(fake_db):
    """Three active incidents, one involves a service that depends on the
    newly-degraded provider region: exactly one gets correlated, the
    other two receive nothing at all."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_checkout", "checkout-api", depends_on=["rds"])
    _seed_service(fake_db, "svc_billing", "billing-api", depends_on=["postgres-self-hosted"])
    _seed_service(fake_db, "svc_notify", "notifications-worker", depends_on=[])
    _seed_incident(fake_db, "inc_affected", ["checkout-api"])
    _seed_incident(fake_db, "inc_unrelated_1", ["billing-api"])
    _seed_incident(fake_db, "inc_unrelated_2", ["notifications-worker"])
    signal = _rds_signal()

    signals, next_events = watcher._sweep(claim, injected_signal=signal)

    assert len(next_events) == 1
    assert next_events[0].topic == "upstream.matched"
    payload = next_events[0].payload
    assert payload["incident_id"] == "inc_affected"
    assert payload["signal_id"] == signal.signal_id
    assert payload["run_id"] == claim.run_id
    assert payload["org_id"] == TEST_ORG
    assert "checkout-api" in payload["correlation_reason"]
    assert "rds" in payload["correlation_reason"]


# --------------------------------------------------------------------------
# Dependency-graph matching
# --------------------------------------------------------------------------

def test_depends_on_transitive_match(fake_db):
    """The incident's own service name doesn't equal the signal's service,
    but one level of depends_on does - the graph-traversal half of R3,
    not just a same-name match."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_checkout", "checkout-api", depends_on=["rds"])
    _seed_incident(fake_db, "inc_1", ["checkout-api"])
    signal = _rds_signal()

    _, next_events = watcher._sweep(claim, injected_signal=signal)

    assert len(next_events) == 1
    assert next_events[0].payload["incident_id"] == "inc_1"


def test_direct_service_match_needs_no_dependency_hop(fake_db):
    """services_affected can name the degraded thing directly, with no
    Service record or depends_on hop involved at all."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_incident(fake_db, "inc_1", ["rds"])
    signal = _rds_signal()

    _, next_events = watcher._sweep(claim, injected_signal=signal)

    assert len(next_events) == 1
    assert next_events[0].payload["incident_id"] == "inc_1"


def test_dependency_match_beyond_max_depth_is_not_correlated(fake_db):
    """A chain longer than the bounded walk (checkout -> gateway -> queue
    -> rds, three hops) must not be treated as "genuinely affected" -
    the bound exists precisely so a distant, tenuous relationship doesn't
    light up as a false positive."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_checkout", "checkout-api", depends_on=["gateway"])
    _seed_service(fake_db, "svc_gateway", "gateway", depends_on=["queue"])
    _seed_service(fake_db, "svc_queue", "queue", depends_on=["rds"])
    _seed_incident(fake_db, "inc_far", ["checkout-api"])
    signal = _rds_signal()

    _, next_events = watcher._sweep(claim, injected_signal=signal)

    assert next_events == []


def test_cyclic_depends_on_does_not_hang_or_crash(fake_db):
    """A <-> B is bad seed data, not an impossible one; the visited-set
    cycle protection must keep the walk finite regardless."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_a", "service-a", depends_on=["service-b"])
    _seed_service(fake_db, "svc_b", "service-b", depends_on=["service-a"])
    _seed_incident(fake_db, "inc_cyclic", ["service-a"])
    signal = _rds_signal()  # unrelated to the a/b cycle

    _, next_events = watcher._sweep(claim, injected_signal=signal)

    assert next_events == []


# --------------------------------------------------------------------------
# Negative cases - the part the demo has to visibly prove
# --------------------------------------------------------------------------

def test_unrelated_incident_produces_zero_events_and_is_never_written(fake_db):
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_unrelated", "totally-unrelated-service", depends_on=[])
    _seed_incident(fake_db, "inc_unrelated", ["totally-unrelated-service"])
    signal = _rds_signal()
    before_keys = set(fake_db._docs.keys())

    signals, next_events = watcher._sweep(claim, injected_signal=signal)

    assert next_events == []
    new_keys = set(fake_db._docs.keys()) - before_keys
    # Everything newly written is a signal or an audit trail entry -
    # Watcher never writes to incidents, and nothing new mentions this
    # incident's id anywhere.
    for path in new_keys:
        assert path[2] in ("signals", "audit")
    assert not any("inc_unrelated" in str(fake_db._docs[path]) for path in new_keys)


def test_resolved_incident_never_matched(fake_db):
    """Even though its service would otherwise qualify, a non-open
    incident must never be matched."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_checkout", "checkout-api", depends_on=["rds"])
    _seed_incident(fake_db, "inc_resolved", ["checkout-api"], status="resolved")
    signal = _rds_signal()

    _, next_events = watcher._sweep(claim, injected_signal=signal)

    assert next_events == []


# --------------------------------------------------------------------------
# Signal persistence is independent of correlation outcome
# --------------------------------------------------------------------------

def test_signals_written_even_when_nothing_matches(fake_db):
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    signal = _rds_signal(signal_id="sig_no_match_test")
    # deliberately no incidents seeded at all

    signals, next_events = watcher._sweep(claim, injected_signal=signal)

    assert next_events == []
    assert signals == [signal]
    stored = fake_db._docs[("tenants", TEST_ORG, "signals", "sig_no_match_test")]
    assert stored["service"] == "rds"
    assert stored["provider"] == "aws"


def test_sweep_without_injection_uses_mock_feed(fake_db):
    """No injected_signal: falls back to the mock feed, which returns 1-3
    signals per SPEC's framing, each of which gets written."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()

    signals, next_events = watcher._sweep(claim)

    assert 1 <= len(signals) <= 3
    for signal in signals:
        stored = fake_db._docs[("tenants", TEST_ORG, "signals", signal.signal_id)]
        assert stored["signal_id"] == signal.signal_id
    assert next_events == []  # no incidents seeded


# --------------------------------------------------------------------------
# run() contract - the envelope-level entrypoint Coordinator dispatches to
# --------------------------------------------------------------------------

def test_run_extracts_injected_signal_from_envelope_payload(fake_db):
    """The HTTP endpoint Cloud Scheduler hits (or a demo operator) injects
    a specific signal via envelope.payload["injected_signal"] - this is
    the wiring that lets someone force a deterministic correlation live
    in the demo instead of relying on the mock feed."""
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    _seed_service(fake_db, "svc_checkout", "checkout-api", depends_on=["rds"])
    _seed_incident(fake_db, "inc_1", ["checkout-api"])
    signal = _rds_signal(signal_id="sig_injected_via_envelope")
    envelope = Envelope(run_id="run_1", org_id=TEST_ORG, claim=claim,
                         event_type="watcher.sweep",
                         payload={"injected_signal": signal.model_dump(mode="json")})

    result = watcher.run(claim, envelope)

    assert result.status == "ok"
    assert len(result.next_events) == 1
    assert result.next_events[0].payload["incident_id"] == "inc_1"
    assert result.next_events[0].payload["signal_id"] == "sig_injected_via_envelope"


def test_run_with_empty_payload_falls_back_to_mock_feed(fake_db):
    _seed_watcher(fake_db)
    claim = _watcher_claim()
    envelope = Envelope(run_id="run_1", org_id=TEST_ORG, claim=claim,
                         event_type="watcher.sweep", payload={})

    result = watcher.run(claim, envelope)

    assert result.status == "ok"
    assert result.next_events == []  # no incidents seeded, but must not error
