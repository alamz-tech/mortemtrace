from __future__ import annotations

from data import scope_store
from data.models import AgentVersionRecord, Collection, Envelope
from agents.contracts import RunResult
from agents.coordinator import coordinator
from registry import registry
from tests.conftest import TEST_ORG, seed_agent


def _admin_claim():
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="platform-admin", agent_version="1.0.0", run_id="run_admin")


def _envelope(run_id: str = "run_1", event_type: str = "evidence.received") -> Envelope:
    claim = scope_store.sign_claim(org_id=TEST_ORG, agent_name="intake", agent_version="1.0.0", run_id=run_id)
    return Envelope(run_id=run_id, org_id=TEST_ORG, incident_id="inc_1", claim=claim,
                     event_type=event_type, payload={})


def _publish_governance_agents(fake_db):
    # Coordinator needs RUNS in *both* scopes: _touch_run reads the
    # existing record before writing so it can accumulate across a
    # multi-agent chain instead of overwriting it on every dispatch.
    seed_agent(fake_db, "coordinator", "1.0.0",
               read_scopes=[Collection.REGISTRY, Collection.QUARANTINE, Collection.RUNS],
               write_scopes=[Collection.RUNS, Collection.QUARANTINE])
    seed_agent(fake_db, "guardian", "1.0.0", read_scopes=[], write_scopes=[Collection.ALERTS])


def test_dispatch_unpublished_agent_dead_letters(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)

    result = coordinator.dispatch("intake", _envelope())

    assert result.status == "dead_letter"
    assert "no published version" in result.detail


def test_dispatch_success_updates_run_record(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[Collection.RAW_EVIDENCE], write_scopes=[Collection.EVENTS])
    clean_coordinator.register_worker("intake", lambda claim, env: RunResult(status="ok", turns=2, tokens_used=500))
    envelope = _envelope()

    result = coordinator.dispatch("intake", envelope)

    assert result.status == "ok"
    run = fake_db._docs[("tenants", TEST_ORG, "runs", envelope.run_id)]
    assert run["agents_invoked"] == ["intake"]
    assert run["turns_used"] == 2
    assert run["tokens_used"] == 500


def test_run_record_accumulates_across_chained_dispatches(fake_db, clean_coordinator):
    """R2/R10: run_id spans the whole ingest-to-drafts chain, so a run
    record must accumulate across multiple agents sharing one run_id,
    not get overwritten by the second dispatch."""
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[Collection.EVENTS])
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[], write_scopes=[Collection.TIMELINE])
    clean_coordinator.register_worker("intake", lambda claim, env: RunResult(status="ok", turns=1, tokens_used=100))
    clean_coordinator.register_worker("ledger", lambda claim, env: RunResult(status="ok", turns=3, tokens_used=200))
    envelope = _envelope()

    coordinator.dispatch("intake", envelope)
    coordinator.dispatch("ledger", envelope)

    run = fake_db._docs[("tenants", TEST_ORG, "runs", envelope.run_id)]
    assert set(run["agents_invoked"]) == {"intake", "ledger"}
    assert run["turns_used"] == 4
    assert run["tokens_used"] == 300


def test_worst_status_wins_across_chained_dispatches(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[Collection.EVENTS])
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[], write_scopes=[Collection.TIMELINE])
    clean_coordinator.register_worker("intake", lambda claim, env: RunResult(status="ok"))
    clean_coordinator.register_worker("ledger", lambda claim, env: RunResult(status="dead_letter", detail="no source"))
    envelope = _envelope()

    coordinator.dispatch("intake", envelope)
    coordinator.dispatch("ledger", envelope)

    run = fake_db._docs[("tenants", TEST_ORG, "runs", envelope.run_id)]
    assert run["status"] == "dead_letter"


def test_quarantined_version_short_circuits_without_invoking(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[])
    calls = []
    clean_coordinator.register_worker("intake", lambda claim, env: calls.append(1) or RunResult(status="ok"))
    fake_db.seed(f"tenants/{TEST_ORG}/quarantine/intake__1.0.0",
                 {"agent_name": "intake", "version": "1.0.0", "reason": "test"})

    result = coordinator.dispatch("intake", _envelope())

    assert result.status == "dead_letter"
    assert "quarantined" in result.detail
    assert calls == []  # never invoked


def test_loop_detected_quarantines_and_dead_letters(fake_db, clean_coordinator):
    from gateway.agent_gateway import LoopDetected

    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[])

    def _looping(claim, env):
        raise LoopDetected("query_timeline repeated 3x with identical args")

    clean_coordinator.register_worker("diagnosis", _looping)

    result = coordinator.dispatch("diagnosis", _envelope())

    assert result.status == "dead_letter"
    assert "loop" in result.detail.lower()
    quarantine = fake_db._docs[("tenants", TEST_ORG, "quarantine", "diagnosis__1.0.0")]
    assert quarantine["reason"].startswith("query_timeline")


def test_budget_exceeded_quarantines(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[])
    clean_coordinator.register_worker(
        "diagnosis", lambda claim, env: RunResult(status="ok", turns=999, tokens_used=1)
    )

    result = coordinator.dispatch("diagnosis", _envelope())

    assert result.status == "dead_letter"
    assert "budget" in result.detail
    assert ("tenants", TEST_ORG, "quarantine", "diagnosis__1.0.0") in fake_db._docs


def test_route_fans_out_to_all_subscribed_workers(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    for name in ["diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"]:
        seed_agent(fake_db, name, "1.0.0", read_scopes=[], write_scopes=[])
        clean_coordinator.register_worker(name, lambda claim, env: RunResult(status="ok"))

    published = []
    coordinator.route("timeline.committed", _envelope(event_type="timeline.committed"),
                       publish=lambda topic, payload: published.append((topic, payload)))

    run = fake_db._docs[("tenants", TEST_ORG, "runs", "run_1")]
    assert set(run["agents_invoked"]) == {"diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"}


def test_route_publishes_declared_next_event(fake_db, clean_coordinator):
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[])
    clean_coordinator.register_worker(
        "intake",
        lambda claim, env: RunResult(status="ok", next_event_type="evidence.staged", next_payload={"event_id": "evt_1"}),
    )
    published = []

    coordinator.route("evidence.received", _envelope(),
                       publish=lambda topic, payload: published.append((topic, payload)))

    assert published == [("evidence.staged", {"event_id": "evt_1"})]


def test_new_department_consumes_with_no_coordinator_change(fake_db, clean_coordinator):
    """R4 acceptance, at the Coordinator level: Exposure is already in
    the static route table for timeline.committed (it ships with the
    code), but it only actually runs once its registry entry is
    published - publishing is the only step, no Coordinator edit."""
    _publish_governance_agents(fake_db)
    clean_coordinator.register_worker("exposure", lambda claim, env: RunResult(status="ok"))
    admin = _admin_claim()
    seed_agent(fake_db, "platform-admin", "1.0.0", read_scopes=[Collection.REGISTRY], write_scopes=[Collection.REGISTRY])

    before = coordinator.dispatch("exposure", _envelope(event_type="timeline.committed"))
    assert before.status == "dead_letter"  # not published yet

    registry.publish(admin, AgentVersionRecord(
        agent_name="exposure", version="1.0.0", input_schema="Timeline", output_schema="SlaExposureDraft",
        read_scopes=[Collection.CUSTOMERS], write_scopes=[Collection.DRAFTS], department="finance",
    ))

    after = coordinator.dispatch("exposure", _envelope(run_id="run_2", event_type="timeline.committed"))
    assert after.status == "ok"
