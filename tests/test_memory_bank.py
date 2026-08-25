from __future__ import annotations

from data import scope_store
from data.models import Collection, MemoryRecord
from memory import memory_bank
from tests.conftest import TEST_ORG, seed_agent


def _claim():
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name="diagnosis", agent_version="1.0.0", run_id="run_1")


def test_remember_then_retrieve_by_kind(fake_db):
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[Collection.MEMORY], write_scopes=[Collection.MEMORY])
    claim = _claim()
    memory_bank.remember(claim, MemoryRecord(
        key="sig_db_timeout", org_id=TEST_ORG, kind="incident_signature",
        content={"pattern": "db connection timeout"}, related_incident_ids=["inc_old_1"],
    ))

    results = memory_bank.retrieve(claim, kind="incident_signature")

    assert len(results) == 1
    assert results[0].key == "sig_db_timeout"


def test_retrieve_by_related_incident(fake_db):
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[Collection.MEMORY], write_scopes=[Collection.MEMORY])
    claim = _claim()
    memory_bank.remember(claim, MemoryRecord(
        key="sig_1", org_id=TEST_ORG, kind="incident_signature",
        content={}, related_incident_ids=["inc_old_1", "inc_old_2"],
    ))
    memory_bank.remember(claim, MemoryRecord(
        key="sig_2", org_id=TEST_ORG, kind="incident_signature", content={}, related_incident_ids=["inc_other"],
    ))

    results = memory_bank.retrieve(claim, related_incident_id="inc_old_1")

    assert [r.key for r in results] == ["sig_1"]


def test_retrieve_degrades_to_empty_without_scope(fake_db):
    seed_agent(fake_db, "comms", "1.0.0", read_scopes=[], write_scopes=[])
    claim = scope_store.sign_claim(org_id=TEST_ORG, agent_name="comms", agent_version="1.0.0", run_id="run_1")

    results = memory_bank.retrieve(claim, kind="incident_signature")

    assert results == []
