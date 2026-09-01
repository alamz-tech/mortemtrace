"""Concurrency regressions.

These are the failure modes the previous test suite could not express at
all: the in-memory fake was single-threaded and had no transaction
support, so a lost update and a check-then-act race both passed every
test while silently losing data in production.

Each test here drives genuine threads through the same code path
production uses. tests/fakes.py serialises transactions and makes
create() atomic precisely so these can be written.
"""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from agents.ledger import ledger
from data import scope_store
from data.models import Collection, Envelope
from tests.conftest import TEST_ORG, seed_agent


def _claim(agent: str = "ledger", run_id: str = "run_c"):
    return scope_store.sign_claim(
        org_id=TEST_ORG, agent_name=agent, agent_version="1.0.0", run_id=run_id,
    )


def _seed_ledger(fake_db):
    seed_agent(fake_db, "ledger", "1.0.0",
               read_scopes=[Collection.EVENTS, Collection.TIMELINE],
               write_scopes=[Collection.TIMELINE, Collection.EVENTS])


# --------------------------------------------------------------------------
# Lost update on the timeline (the product's central artifact)
# --------------------------------------------------------------------------

def test_concurrent_timeline_appends_do_not_lose_entries(fake_db):
    """Before update_in_transaction, ledger did read -> append -> write
    with no transaction. Two concurrent evidence items for one incident
    would each read the same timeline, each append their own entry, and
    the second write would silently discard the first.

    Twenty concurrent appends must produce twenty entries.
    """
    _seed_ledger(fake_db)
    incident_id = "inc_race"
    entry_count = 20

    def _append(index: int) -> None:
        def mutate(current):
            timeline = current or {
                "incident_id": incident_id, "org_id": TEST_ORG,
                "entries": [], "downtime_windows": [],
                "last_updated": "2026-08-26T00:00:00+00:00",
            }
            timeline["entries"] = list(timeline["entries"]) + [{
                "ts": "2026-08-26T00:00:00+00:00", "actor": "system",
                "action": f"event-{index}", "evidence": f"evidence-{index}",
                "source_event_ids": [f"evt_{index}"],
            }]
            return timeline

        scope_store.update_in_transaction(
            _claim(run_id=f"run_{index}"), Collection.TIMELINE, incident_id, mutate,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_append, range(entry_count)))

    stored = fake_db._docs[("tenants", TEST_ORG, "timeline", incident_id)]
    assert len(stored["entries"]) == entry_count
    assert {e["source_event_ids"][0] for e in stored["entries"]} == {
        f"evt_{i}" for i in range(entry_count)
    }


def test_ledger_run_under_concurrency_keeps_every_committed_event(fake_db):
    """The same property through ledger.run() itself rather than the
    store primitive, so the agent's own code path is covered."""
    _seed_ledger(fake_db)
    incident_id = "inc_ledger_race"
    event_ids = [f"evt_{i}" for i in range(12)]

    for i, event_id in enumerate(event_ids):
        fake_db.seed(f"tenants/{TEST_ORG}/events/{event_id}", {
            "event_id": event_id, "org_id": TEST_ORG, "incident_ref": incident_id,
            "status": "staged", "confidence": 0.9,
            "extracted": {"action": f"action-{i}"},
            "ts": "2026-08-26T00:00:00+00:00", "source_ref": f"raw_{i}",
        })

    def _run(event_id: str):
        envelope = Envelope(
            run_id=f"run_{event_id}", org_id=TEST_ORG, incident_id=incident_id,
            claim=_claim(run_id=f"run_{event_id}"), event_type="evidence.staged",
            payload={"event_id": event_id},
        )
        return ledger.run(_claim(run_id=f"run_{event_id}"), envelope)

    with ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_run, event_ids))

    assert all(r.status == "ok" for r in results)
    stored = fake_db._docs[("tenants", TEST_ORG, "timeline", incident_id)]
    assert len(stored["entries"]) == len(event_ids)


def test_timeline_transaction_still_rejects_entries_without_sources(fake_db):
    """R9's hallucination guard must hold on the transactional path too -
    moving the write into a transaction must not route around it."""
    _seed_ledger(fake_db)

    def mutate(current):
        return {
            "incident_id": "inc_x", "org_id": TEST_ORG,
            "entries": [{
                "ts": "2026-08-26T00:00:00+00:00", "actor": "system",
                "action": "unsourced", "evidence": "none", "source_event_ids": [],
            }],
            "downtime_windows": [], "last_updated": "2026-08-26T00:00:00+00:00",
        }

    with pytest.raises(scope_store.SourceRequired):
        scope_store.update_in_transaction(_claim(), Collection.TIMELINE, "inc_x", mutate)


def test_transactional_write_is_scope_enforced(fake_db):
    """The new write path must be subject to the same authorization as
    write() - a new door into Firestore that skipped scope checks would
    undo the property the whole architecture rests on."""
    seed_agent(fake_db, "comms", "1.0.0", read_scopes=[], write_scopes=[Collection.DRAFTS])

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.update_in_transaction(
            _claim(agent="comms"), Collection.TIMELINE, "inc_x", lambda cur: {"entries": []},
        )


# --------------------------------------------------------------------------
# Idempotency key: check-then-act race
# --------------------------------------------------------------------------

def test_concurrent_writes_with_one_idempotency_key_apply_once(fake_db):
    """Pub/Sub is at-least-once, so duplicate concurrent delivery is
    expected rather than exotic. The previous get()-then-set() let two
    callers both observe "not present" and both proceed."""
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[Collection.EVENTS])
    barrier = threading.Barrier(8)
    results: list[bool] = []
    results_lock = threading.Lock()

    def _write(i: int) -> None:
        barrier.wait()  # maximise the overlap window
        written = scope_store.write(
            _claim(agent="intake", run_id=f"run_{i}"), Collection.EVENTS, "evt_dup",
            {"event_id": "evt_dup", "org_id": TEST_ORG, "writer": i},
            idempotency_key="the-same-key",
        )
        with results_lock:
            results.append(written)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_write, range(8)))

    assert sum(results) == 1, "exactly one writer may win the idempotency key"
    assert results.count(False) == 7


def test_distinct_idempotency_keys_all_apply(fake_db):
    seed_agent(fake_db, "intake", "1.0.0", read_scopes=[], write_scopes=[Collection.EVENTS])

    written = [
        scope_store.write(
            _claim(agent="intake"), Collection.EVENTS, f"evt_{i}",
            {"event_id": f"evt_{i}", "org_id": TEST_ORG},
            idempotency_key=f"key-{i}",
        )
        for i in range(5)
    ]

    assert all(written)


# --------------------------------------------------------------------------
# Idempotency claim (no accompanying document write): check-then-act race
# --------------------------------------------------------------------------

def test_concurrent_idempotency_key_claims_apply_once(fake_db):
    """claim_idempotency_key's own version of the same check-then-act race
    test_concurrent_writes_with_one_idempotency_key_apply_once covers for
    write()'s built-in idempotency_key - used by the department agents
    (diagnosis.py, classifier.py, agents/departments/*.py) to gate
    multiple writes together rather than piggyback on one document's
    write() call."""
    seed_agent(fake_db, "diagnosis", "1.0.0", read_scopes=[], write_scopes=[Collection.HYPOTHESES])
    barrier = threading.Barrier(8)
    results: list[bool] = []
    results_lock = threading.Lock()

    def _claim_key(i: int) -> None:
        barrier.wait()
        claimed = scope_store.claim_idempotency_key(
            _claim(agent="diagnosis", run_id=f"run_{i}"), Collection.HYPOTHESES, "the-same-key",
        )
        with results_lock:
            results.append(claimed)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_claim_key, range(8)))

    assert sum(results) == 1, "exactly one caller may win the idempotency claim"
    assert results.count(False) == 7


# --------------------------------------------------------------------------
# Last-admin guard: TOCTOU on concurrent revoke/demote
# --------------------------------------------------------------------------

def test_concurrent_revokes_of_both_admins_cannot_leave_the_org_with_zero(fake_db):
    """Before this was transactional, update_membership_role/
    revoke_membership did get() -> _count_active_admins() -> set() with no
    atomicity between the count check and the write. With exactly two
    active admins, two concurrent revokes (each admin revoking the other,
    maximizing overlap via a barrier) could each read the count as 2, each
    pass the "would leave more than zero" check, and both commit - leaving
    the org with zero admins despite the guard existing specifically to
    prevent that."""
    org = scope_store.create_organization("Acme Inc.", "admin_a")
    scope_store.create_membership("admin_b", org["org_id"], "admin")
    barrier = threading.Barrier(2)
    outcomes: list[str] = []
    outcomes_lock = threading.Lock()

    def _revoke(acting: str, target: str) -> None:
        barrier.wait()
        try:
            scope_store.revoke_membership(acting, org["org_id"], target)
            outcome = "succeeded"
        except (scope_store.LastAdminError, scope_store.PermissionDenied):
            # Both are a safe refusal here, not a bug: LastAdminError is
            # the guard this test targets; PermissionDenied is
            # _require_admin's own live re-check noticing the ACTOR's own
            # admin status was revoked by the other concurrent call before
            # they got to act - equally conservative, since only two
            # admins exist and each revoke targets the other.
            outcome = "refused"
        with outcomes_lock:
            outcomes.append(outcome)

    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda args: _revoke(*args), [("admin_a", "admin_b"), ("admin_b", "admin_a")]))

    assert sorted(outcomes) == ["refused", "succeeded"], (
        "exactly one of the two concurrent revokes may succeed"
    )
    remaining_admins = [
        m for m in scope_store.list_memberships_for_org(org["org_id"])
        if m["status"] == "active" and m["role"] == "admin"
    ]
    assert len(remaining_admins) == 1


def test_transactional_write_requires_read_scope_too(fake_db):
    """A read-modify-write hands the current document to `mutate`, so
    authorizing only the write would let an agent with write-but-not-read
    scope observe content it is denied. Both scopes are required."""
    seed_agent(fake_db, "write_only", "1.0.0",
               read_scopes=[], write_scopes=[Collection.TIMELINE])
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/inc_secret", {
        "incident_id": "inc_secret", "org_id": TEST_ORG,
        "entries": [{"ts": "2026-08-26T00:00:00+00:00", "actor": "a", "action": "sensitive",
                     "evidence": "secret detail", "source_event_ids": ["evt_1"]}],
        "downtime_windows": [], "last_updated": "2026-08-26T00:00:00+00:00",
    })
    seen: list = []

    with pytest.raises(scope_store.ScopeDenied):
        scope_store.update_in_transaction(
            _claim(agent="write_only"), Collection.TIMELINE, "inc_secret",
            lambda current: (seen.append(current), current or {})[1],
        )

    assert seen == [], "mutate must never be handed a document the caller cannot read"
