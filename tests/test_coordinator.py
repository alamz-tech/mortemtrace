from __future__ import annotations

import time

from agents.contracts import NextEvent, RunResult
from agents.coordinator import coordinator
from data import scope_store
from data.models import AgentVersionRecord, Collection, Envelope
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


def test_transient_failure_retries_then_succeeds(fake_db, clean_coordinator, monkeypatch):
    """The retry-with-backoff path itself had zero coverage before this -
    a real gap, given a live 429 RESOURCE_EXHAUSTED from Vertex AI is
    exactly what this path exists to ride out. monkeypatches time.sleep
    so the test doesn't actually wait through the real backoff."""
    sleeps = []
    monkeypatch.setattr(coordinator.time, "sleep", lambda s: sleeps.append(s))
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[])

    attempts = []

    def _flaky(claim, env):
        attempts.append(1)
        if len(attempts) < 3:
            raise RuntimeError("429 RESOURCE_EXHAUSTED")
        return RunResult(status="ok")

    clean_coordinator.register_worker("diagnosis", _flaky)

    result = coordinator.dispatch("diagnosis", _envelope())

    assert result.status == "ok"
    assert len(attempts) == 3
    assert len(sleeps) == 2  # backoff before attempt 2 and attempt 3, none after the last success


def test_retries_exhausted_dead_letters_with_last_error_in_detail(fake_db, clean_coordinator, monkeypatch):
    monkeypatch.setattr(coordinator.time, "sleep", lambda s: None)
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[])

    def _always_fails(claim, env):
        raise RuntimeError("429 RESOURCE_EXHAUSTED")

    clean_coordinator.register_worker("diagnosis", _always_fails)

    result = coordinator.dispatch("diagnosis", _envelope())

    assert result.status == "dead_letter"
    assert "RESOURCE_EXHAUSTED" in result.detail


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
        lambda claim, env: RunResult(
            status="ok", next_events=[NextEvent(topic="evidence.staged", payload={"event_id": "evt_1"})]
        ),
    )
    published = []

    coordinator.route("evidence.received", _envelope(),
                       publish=lambda topic, payload: published.append((topic, payload)))

    assert published == [("evidence.staged", {"event_id": "evt_1"})]


def test_route_dispatches_fan_out_workers_in_parallel_not_serially(fake_db, clean_coordinator):
    """Regression for the finding behind the ledger.py and department
    idempotency fixes: six real, blocking Gemini calls run one after
    another easily exceed Pub/Sub's 60s push ack deadline
    (infra/setup_pubsub_push.sh), which redelivers the message mid-fan-out.
    Six 0.2s workers in series would take >=1.2s. Classifier (a "leader",
    per _MUST_PRECEDE_PEERS) still runs first and alone, so the floor here
    is two 0.2s phases, not one - well under the six-way serial total."""
    _publish_governance_agents(fake_db)
    names = ["diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"]
    for name in names:
        seed_agent(fake_db, name, "1.0.0", read_scopes=[], write_scopes=[])
        clean_coordinator.register_worker(name, lambda claim, env: (time.sleep(0.2), RunResult(status="ok"))[1])

    start = time.monotonic()
    coordinator.route("timeline.committed", _envelope(event_type="timeline.committed"),
                       publish=lambda topic, payload: None)
    elapsed = time.monotonic() - start

    assert elapsed < 0.7


def test_route_publish_order_matches_route_table_not_completion_order(fake_db, clean_coordinator):
    """Concurrent dispatch must not turn into out-of-order publishing:
    whichever follower happens to finish first must not jump the queue.
    Classifier (a "leader") publishes first regardless, since it runs to
    completion before the followers start at all - see
    _MUST_PRECEDE_PEERS."""
    _publish_governance_agents(fake_db)
    names = ["diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"]
    delays = {"diagnosis": 0.05, "classifier": 0.0, "postmortem": 0.03,
              "comms": 0.0, "compliance": 0.04, "exposure": 0.0}

    def _make_worker(name: str):
        def _worker(claim, env):
            time.sleep(delays[name])
            return RunResult(status="ok", next_events=[NextEvent(topic=f"{name}.done", payload={})])
        return _worker

    for name in names:
        seed_agent(fake_db, name, "1.0.0", read_scopes=[], write_scopes=[])
        clean_coordinator.register_worker(name, _make_worker(name))

    published = []
    coordinator.route("timeline.committed", _envelope(event_type="timeline.committed"),
                       publish=lambda topic, payload: published.append(topic))

    expected_order = ["classifier"] + [n for n in names if n != "classifier"]
    assert published == [f"{name}.done" for name in expected_order]


def test_classifier_always_completes_before_exposure_starts(fake_db, clean_coordinator):
    """Regression, found live in production the day concurrent dispatch
    shipped: Exposure reads Collection.CLASSIFICATION, which Classifier
    writes, both dispatched from the same timeline.committed event.
    Naive concurrent dispatch raced the two and Exposure dead-lettered
    with "no classification record found for incident" whenever it won
    the race. Runs several iterations since a race that only sometimes
    loses would still sometimes pass."""
    _publish_governance_agents(fake_db)
    names = ["diagnosis", "classifier", "postmortem", "comms", "compliance", "exposure"]
    for name in names:
        seed_agent(fake_db, name, "1.0.0", read_scopes=[], write_scopes=[])

    def _make_classifier(state: dict):
        def _classifier(claim, env):
            time.sleep(0.01)
            state["classified"] = True
            return RunResult(status="ok")
        return _classifier

    def _make_exposure(state: dict, sightings: list):
        def _exposure(claim, env):
            sightings.append(state["classified"])
            return RunResult(status="ok")
        return _exposure

    for i in range(20):
        state = {"classified": False}
        exposure_saw_classified: list = []
        _classifier = _make_classifier(state)
        _exposure = _make_exposure(state, exposure_saw_classified)

        for name in names:
            clean_coordinator.register_worker(
                name, _classifier if name == "classifier" else (
                    _exposure if name == "exposure" else (lambda claim, env: RunResult(status="ok"))
                ),
            )

        coordinator.route("timeline.committed", _envelope(run_id=f"run_race_{i}", event_type="timeline.committed"),
                           publish=lambda topic, payload: None)

        assert exposure_saw_classified == [True]


def test_dispatch_concurrently_isolates_one_workers_unexpected_exception(clean_coordinator, monkeypatch):
    """dispatch() already converts everything it knows how to handle into
    a RunResult, so an exception escaping it (e.g. from guardian.preflight
    or _touch_run, outside _attempt_with_retry's own try/except) is
    unexpected - but one department's unexpected failure must not lose
    the other five departments' real results."""
    def _fake_dispatch(agent_name, envelope):
        if agent_name == "compliance":
            raise RuntimeError("boom")
        return RunResult(status="ok")

    monkeypatch.setattr(coordinator, "dispatch", _fake_dispatch)
    names = ["diagnosis", "compliance", "exposure"]

    results = coordinator._dispatch_concurrently(names, _envelope(event_type="timeline.committed"))

    by_name = dict(zip(names, results, strict=True))
    assert by_name["diagnosis"].status == "ok"
    assert by_name["exposure"].status == "ok"
    assert by_name["compliance"].status == "dead_letter"


def test_terminal_exception_dead_letters_immediately_without_retry(fake_db, clean_coordinator, monkeypatch):
    """Regression, found live: a malformed staged event raises a bare
    KeyError (agents/ledger/ledger.py's event['ts']/event['event_id']
    indexing), which is deterministic - identical on every retry. Before
    the retryable/terminal exception taxonomy, this still burned the full
    ~24s of backoff before dead-lettering, compounding the ack-deadline
    risk on top of it."""
    sleeps = []
    monkeypatch.setattr(coordinator.time, "sleep", lambda s: sleeps.append(s))
    _publish_governance_agents(fake_db)
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[], write_scopes=[])

    attempts = []

    def _malformed(claim, env):
        attempts.append(1)
        raise KeyError("event_id")

    clean_coordinator.register_worker("ledger", _malformed)

    result = coordinator.dispatch("ledger", _envelope())

    assert result.status == "dead_letter"
    assert "terminal KeyError" in result.detail
    assert len(attempts) == 1
    assert sleeps == []


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
