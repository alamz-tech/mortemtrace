"""Validates seed/generate.py: every record round-trips through its real
Pydantic model, every timeline source_event_id traces to a real seeded
event, and - the one that actually matters for the demo - running
Watcher's real correlation logic (not a re-implementation of it) against
this seed data correlates exactly incident 1 and leaves the other two
untouched, using Watcher's own default mock feed with no signal
injection. If this test ever goes red, the live demo's Watcher beat
would too.
"""
from __future__ import annotations

from data import scope_store
from data.models import Classification, Collection, Customer, Incident, Service, Timeline
from seed.generate import generate
from tests.conftest import TEST_ORG, seed_agent


def test_every_seeded_record_validates_against_its_model(fake_db):
    summary = generate(TEST_ORG)

    assert summary == {
        "services": 5, "customers": 3, "incidents": 3,
        "raw_evidence": 2, "events": 2, "timelines": 1, "classifications": 3,
    }

    for path, data in fake_db._docs.items():
        if path[:2] != ("tenants", TEST_ORG):
            continue
        collection = path[2]
        if collection == "services":
            Service.model_validate(data)
        elif collection == "customers":
            Customer.model_validate(data)
        elif collection == "incidents":
            Incident.model_validate(data)
        elif collection == "timeline":
            Timeline.model_validate(data)
        elif collection == "classification":
            Classification.model_validate(data)


def test_timeline_source_event_ids_all_trace_to_real_events(fake_db):
    generate(TEST_ORG)

    timeline_doc = fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_seed_checkout_outage")]
    timeline = Timeline.model_validate(timeline_doc)
    real_event_ids = {
        doc["event_id"] for path, doc in fake_db._docs.items()
        if path[:3] == ("tenants", TEST_ORG, "events")
    }

    for entry in timeline.entries:
        for source_id in entry.source_event_ids:
            assert source_id in real_event_ids, f"dangling source_event_id: {source_id}"


def test_public_demo_flag_writes_an_organization_record(fake_db):
    generate(TEST_ORG, public_demo=True)

    org = scope_store.get_organization(TEST_ORG)
    assert org is not None
    assert org["public_demo_auto_join"] is True


def test_without_the_flag_no_organization_record_is_written(fake_db):
    """The default, unflagged path must not accidentally make ANY org
    public-demo-joinable - this is the control for the test above."""
    generate(TEST_ORG, public_demo=False)

    assert scope_store.get_organization(TEST_ORG) is None


def test_exactly_one_incident_matches_watchers_real_default_sweep(fake_db):
    """The actual proof: import Watcher's real _sweep, run it against
    this seed data with no injected_signal (Watcher's default mock feed
    only), and check what a live demo run would actually produce."""
    from agents.watcher.watcher import _sweep

    generate(TEST_ORG)
    seed_agent(fake_db, "watcher", "1.0.0",
               read_scopes=[Collection.SIGNALS, Collection.INCIDENTS, Collection.SERVICES],
               write_scopes=[Collection.SIGNALS])
    claim = scope_store.sign_claim(org_id=TEST_ORG, agent_name="watcher", agent_version="1.0.0", run_id="run_demo_sweep")

    signals, next_events = _sweep(claim)

    assert len(signals) == 3  # Watcher's default mock feed: provider_status, changelog, cve
    matched_incident_ids = {e.payload["incident_id"] for e in next_events}
    assert matched_incident_ids == {"inc_seed_checkout_outage"}
    assert "inc_seed_search_degraded" not in matched_incident_ids
    assert "inc_seed_billing_delay" not in matched_incident_ids
