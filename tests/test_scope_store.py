"""These tests exist to make SPEC-postmortem.md's acceptance criteria for
R5 (scope enforcement) and R7 (tenant isolation) executable, not just
documented. If one of these goes red, the architecture's core claim -
"scopes enforced at the data layer, not in prompts" - is no longer true.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from data import scope_store
from data.models import Collection, OrgClaim
from tests.conftest import OTHER_ORG, TEST_ORG, seed_agent


def _claim(agent_name: str, version: str = "1.0.0", org_id: str = TEST_ORG, run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=org_id, agent_name=agent_name, agent_version=version, run_id=run_id)


# --------------------------------------------------------------------------
# R5 - scope enforcement at the data layer
# --------------------------------------------------------------------------

def test_comms_cannot_read_raw_evidence(fake_db):
    """R5 acceptance: Comms requests raw_evidence, the store denies it, the
    run continues (caller decides that), and the denial is audited."""
    seed_agent(fake_db, "comms", "1.0.0", read_scopes=[Collection.TIMELINE], write_scopes=[Collection.DRAFTS])
    claim = _claim("comms")

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(claim, Collection.RAW_EVIDENCE, "evt_1")

    entries = [
        d for path, d in fake_db._docs.items()
        if path[:3] == ("tenants", TEST_ORG, "audit")
    ]
    assert any(e["verdict"] == "deny" and "raw_evidence" in e["path"] for e in entries)


def test_try_read_degrades_instead_of_raising(fake_db):
    """The convenience wrapper callers use for the degrade-not-fail path."""
    seed_agent(fake_db, "comms", "1.0.0", read_scopes=[Collection.TIMELINE], write_scopes=[])
    claim = _claim("comms")

    result = scope_store.try_read(claim, Collection.RAW_EVIDENCE, "evt_1")

    assert result is None  # degraded, not an exception the caller has to handle


def test_postmortem_can_read_raw_evidence(fake_db):
    """Engineering's agent has the broad scope; same call, opposite verdict."""
    seed_agent(
        fake_db, "postmortem", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.HYPOTHESES],
        write_scopes=[Collection.DRAFTS],
        department="engineering",
    )
    fake_db.seed(f"tenants/{TEST_ORG}/raw_evidence/evt_1", {"event_id": "evt_1", "payload": "log line"})
    claim = _claim("postmortem")

    result = scope_store.read(claim, Collection.RAW_EVIDENCE, "evt_1")

    assert result == {"event_id": "evt_1", "payload": "log line"}


def test_exposure_denied_timeline_detail(fake_db):
    """Finance gets downtime windows and SLA terms, not timeline detail."""
    seed_agent(fake_db, "exposure", "1.0.0", read_scopes=[Collection.CUSTOMERS], write_scopes=[Collection.DRAFTS])
    claim = _claim("exposure")

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(claim, Collection.TIMELINE, "inc_1")


def test_unpublished_agent_has_no_scopes(fake_db):
    """An agent name with no registry entry at all is denied everything -
    fail closed on the absence of a grant, not open."""
    claim = _claim("nonexistent-agent")

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.read(claim, Collection.TIMELINE, "inc_1")


# --------------------------------------------------------------------------
# R7 - tenant isolation / forged claims
# --------------------------------------------------------------------------

def test_forged_org_claim_denied_and_fails_closed(fake_db):
    """R7 acceptance: a claim for org A used against org B's path is
    denied, and the caller must treat this as fail-closed (a different
    exception type than a scope denial, on purpose)."""
    seed_agent(fake_db, "postmortem", "1.0.0",
               read_scopes=[Collection.TIMELINE], write_scopes=[], department="engineering")
    claim = _claim("postmortem", org_id=TEST_ORG)

    with pytest.raises(scope_store.TenantViolation):
        scope_store.read(claim, Collection.TIMELINE, "inc_1", path_org_id=OTHER_ORG)


def test_tenant_violation_is_not_a_scope_denied(fake_db):
    """These two failure modes must stay distinguishable so callers can
    catch ScopeDenied (degrade) without accidentally swallowing a forged
    claim (must fail closed)."""
    assert not issubclass(scope_store.TenantViolation, scope_store.ScopeDenied)
    assert not issubclass(scope_store.ScopeDenied, scope_store.TenantViolation)


def test_expired_claim_denied(fake_db):
    seed_agent(fake_db, "postmortem", "1.0.0", read_scopes=[Collection.TIMELINE], write_scopes=[])
    claim = _claim("postmortem")
    claim.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)

    with pytest.raises(scope_store.TenantViolation):
        scope_store.read(claim, Collection.TIMELINE, "inc_1")


def test_tampered_signature_denied(fake_db):
    seed_agent(fake_db, "postmortem", "1.0.0", read_scopes=[Collection.TIMELINE], write_scopes=[])
    claim = _claim("postmortem")
    claim.org_id = OTHER_ORG  # mutate a signed field without re-signing

    with pytest.raises(scope_store.TenantViolation):
        scope_store.read(claim, Collection.TIMELINE, "inc_1")


# --------------------------------------------------------------------------
# R9 - hallucination guard: no commit without source_event_ids
# --------------------------------------------------------------------------

def test_timeline_commit_without_source_rejected(fake_db):
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[Collection.EVENTS], write_scopes=[Collection.TIMELINE])
    claim = _claim("ledger")
    bad_timeline = {
        "incident_id": "inc_1",
        "org_id": TEST_ORG,
        "entries": [{"ts": "2026-08-25T00:00:00Z", "actor": "ledger", "action": "x",
                     "evidence": "y", "source_event_ids": []}],
    }

    with pytest.raises(scope_store.SourceRequired):
        scope_store.write(claim, Collection.TIMELINE, "inc_1", bad_timeline)


def test_timeline_commit_with_source_accepted(fake_db):
    seed_agent(fake_db, "ledger", "1.0.0", read_scopes=[Collection.EVENTS], write_scopes=[Collection.TIMELINE])
    claim = _claim("ledger")
    good_timeline = {
        "incident_id": "inc_1",
        "org_id": TEST_ORG,
        "entries": [{"ts": "2026-08-25T00:00:00Z", "actor": "ledger", "action": "x",
                     "evidence": "y", "source_event_ids": ["evt_1"]}],
    }

    written = scope_store.write(claim, Collection.TIMELINE, "inc_1", good_timeline)

    assert written is True
    assert fake_db._docs[("tenants", TEST_ORG, "timeline", "inc_1")] == good_timeline


def test_hypothesis_without_source_rejected(fake_db):
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[Collection.TIMELINE], write_scopes=[Collection.HYPOTHESES])
    claim = _claim("diagnosis")

    with pytest.raises(scope_store.SourceRequired):
        scope_store.write(claim, Collection.HYPOTHESES, "hyp_1",
                           {"hypothesis_id": "hyp_1", "statement": "guess", "source_event_ids": []})


# --------------------------------------------------------------------------
# Idempotency
# --------------------------------------------------------------------------

def test_duplicate_write_is_a_noop(fake_db):
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[Collection.EVENTS])
    claim = _claim("intake", run_id="run_dup")

    first = scope_store.write(claim, Collection.EVENTS, "evt_1", {"v": 1}, idempotency_key="run_dup:evt_1")
    fake_db.seed(f"tenants/{TEST_ORG}/events/evt_1", {"v": 999})  # simulate a later mutation
    second = scope_store.write(claim, Collection.EVENTS, "evt_1", {"v": 2}, idempotency_key="run_dup:evt_1")

    assert first is True
    assert second is False
    assert fake_db._docs[("tenants", TEST_ORG, "events", "evt_1")] == {"v": 999}
