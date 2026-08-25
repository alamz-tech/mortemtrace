from __future__ import annotations

from data import scope_store
from data.models import AgentVersionRecord, Collection
from registry import registry
from tests.conftest import TEST_ORG, seed_agent


def _admin_claim():
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="platform-admin", agent_version="1.0.0", run_id="run_admin")


def test_publish_then_resolve_latest(fake_db):
    seed_agent(fake_db, "platform-admin", "1.0.0", read_scopes=[Collection.REGISTRY], write_scopes=[Collection.REGISTRY])
    claim = _admin_claim()
    registry.publish(claim, AgentVersionRecord(
        agent_name="watcher", version="1.0.0", input_schema="Signal", output_schema="UpstreamSignalMatched",
        read_scopes=[Collection.SIGNALS], write_scopes=[Collection.SIGNALS],
    ))
    registry.publish(claim, AgentVersionRecord(
        agent_name="watcher", version="1.1.0", input_schema="Signal", output_schema="UpstreamSignalMatched",
        read_scopes=[Collection.SIGNALS], write_scopes=[Collection.SIGNALS],
    ))

    resolved = registry.resolve(claim, "watcher")

    assert resolved is not None
    assert resolved.version == "1.1.0"  # highest published semver, not last-written


def test_new_department_resolves_with_no_redeploy(fake_db):
    """R4 acceptance: publish Exposure mid-run, next event resolves it at
    its declared scope with no code change on the Coordinator's part."""
    seed_agent(fake_db, "platform-admin", "1.0.0", read_scopes=[Collection.REGISTRY], write_scopes=[Collection.REGISTRY])
    claim = _admin_claim()

    assert registry.resolve(claim, "exposure") is None  # not published yet

    registry.publish(claim, AgentVersionRecord(
        agent_name="exposure", version="1.0.0", input_schema="Timeline", output_schema="SlaExposureDraft",
        read_scopes=[Collection.CUSTOMERS], write_scopes=[Collection.DRAFTS], department="finance",
    ))

    resolved = registry.resolve(claim, "exposure")
    assert resolved is not None
    assert resolved.department == "finance"


def test_deprecate_removes_from_latest_resolution(fake_db):
    seed_agent(fake_db, "platform-admin", "1.0.0", read_scopes=[Collection.REGISTRY], write_scopes=[Collection.REGISTRY])
    claim = _admin_claim()
    registry.publish(claim, AgentVersionRecord(
        agent_name="classifier", version="1.0.0", input_schema="Timeline", output_schema="Classification",
        read_scopes=[Collection.TIMELINE], write_scopes=[Collection.CLASSIFICATION],
    ))

    registry.deprecate(claim, "classifier", "1.0.0")

    assert registry.resolve(claim, "classifier") is None  # no published versions left
    exact = registry.resolve(claim, "classifier", version="1.0.0")
    assert exact is not None and exact.status == "deprecated"
