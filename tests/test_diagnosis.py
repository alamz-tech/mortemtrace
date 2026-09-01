"""Diagnosis: one hypothesis per run, always traceable to a real
source_event_id, and citing memory's related_incident_ids as structured
data (R6) rather than trusting prose. gateway.agent_gateway.invoke is
always monkeypatched here - these tests must never call real Gemini.
"""
from __future__ import annotations

import json

from agents.diagnosis import diagnosis
from data import scope_store
from data.models import Collection, Envelope, MemoryRecord, OrgClaim
from gateway import agent_gateway
from tests.conftest import TEST_ORG, seed_agent


def _claim(agent_name: str = "diagnosis", version: str = "1.0.0", run_id: str = "run_1") -> OrgClaim:
    return scope_store.sign_claim(org_id=TEST_ORG, agent_name=agent_name, agent_version=version, run_id=run_id)


def _envelope(event_type: str = "timeline.committed", incident_id: str = "inc_1", run_id: str = "run_1") -> Envelope:
    """payload carries incident_id under the same key regardless of
    event_type, matching TimelineCommitted.incident_id and
    UpstreamSignalMatched.incident_id per SPEC/ARCHITECTURE."""
    publisher_claim = scope_store.sign_claim(
        org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id=run_id,
    )
    return Envelope(
        run_id=run_id, org_id=TEST_ORG, incident_id=incident_id, claim=publisher_claim,
        event_type=event_type, payload={"incident_id": incident_id},
    )


def _seed_timeline(fake_db, incident_id: str = "inc_1", entries: list[dict] | None = None) -> None:
    if entries is None:
        entries = [
            {"ts": "2026-08-25T03:00:00Z", "actor": "alert", "action": "pods crash-looping",
             "evidence": "CrashLoopBackOff x12 on checkout-worker", "source_event_ids": ["evt_1"]},
            {"ts": "2026-08-25T03:05:00Z", "actor": "oncall", "action": "restarted deployment",
             "evidence": "kubectl rollout restart checkout-worker", "source_event_ids": ["evt_2"]},
        ]
    fake_db.seed(f"tenants/{TEST_ORG}/timeline/{incident_id}", {
        "incident_id": incident_id, "org_id": TEST_ORG, "entries": entries,
        "downtime_windows": [], "last_updated": "2026-08-25T03:10:00Z",
    })


def _seed_diagnosis_agent(fake_db) -> None:
    seed_agent(
        fake_db, "diagnosis", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.MEMORY],
        write_scopes=[Collection.HYPOTHESES, Collection.MEMORY],
    )


def _hypotheses(fake_db) -> list[dict]:
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "hypotheses")]


def _memory_records(fake_db) -> list[dict]:
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "memory")]


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------

def test_diagnosis_happy_path_writes_hypothesis_with_resolved_source(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "pods OOM-killed under load", "confidence": 0.8, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"
    written = _hypotheses(fake_db)
    assert len(written) == 1
    assert written[0]["incident_ref"] == "inc_1"
    assert written[0]["confidence"] == 0.8
    # index 0 maps back to that timeline entry's own source_event_ids -
    # never an invented ID.
    assert written[0]["source_event_ids"] == ["evt_1"]


def test_diagnosis_redelivery_of_the_same_run_does_not_write_a_second_hypothesis(fake_db, monkeypatch):
    """Regression: timeline.committed's six-way departmental fan-out can
    outrun Pub/Sub's ack deadline and get redelivered
    (agents/coordinator/coordinator.py's _dispatch_concurrently docstring).
    Before the idempotency guard, calling run() again with the SAME
    run_id/incident_id (what a redelivery looks like from Diagnosis' own
    perspective - a fresh dispatch, identical envelope) wrote a second,
    independent Hypothesis with its own new_id()."""
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "pods OOM-killed under load", "confidence": 0.8, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )
    envelope = _envelope()

    first = diagnosis.run(_claim(), envelope)
    second = diagnosis.run(_claim(), envelope)

    assert first.status == "ok"
    assert second.status == "ok"
    assert len(_hypotheses(fake_db)) == 1


def test_diagnosis_flattens_multiple_cited_entries(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "crash then restart", "confidence": 0.6, '
                 '"source_entry_indices": [0, 1], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"
    assert _hypotheses(fake_db)[0]["source_event_ids"] == ["evt_1", "evt_2"]


# --------------------------------------------------------------------------
# R6 - the WRITE side: a diagnosis must actually land in Memory Bank
#
# Regression, found in a security/reliability self-review: retrieve() was
# called on every run and always ran correctly, but remember() had zero
# call sites anywhere in the non-test codebase - R6's "learns across
# incidents" was structurally unimplemented. Every Diagnosis prompt
# always said "No prior incident signatures available," no matter how
# many incidents had actually been diagnosed.
# --------------------------------------------------------------------------

def test_diagnosis_writes_an_incident_signature_to_memory_bank(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "pods OOM-killed under load", "confidence": 0.8, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope(incident_id="inc_1"))

    assert result.status == "ok"
    records = _memory_records(fake_db)
    assert len(records) == 1
    assert records[0]["kind"] == "incident_signature"
    assert records[0]["related_incident_ids"] == ["inc_1"]
    assert records[0]["content"]["statement"] == "pods OOM-killed under load"


def test_a_later_incidents_diagnosis_actually_sees_the_earlier_signature(fake_db, monkeypatch):
    """The actual end-to-end proof, not just 'a record got written':
    diagnose incident 1, then diagnose an UNRELATED incident 2, and
    confirm incident 1's real signature - written by a real run of this
    same function, not seeded by hand - appears in incident 2's prompt.
    This is the exact gap that made R6 permanently unreachable: retrieve()
    worked fine in isolation, but nothing upstream of it had ever
    written anything for it to find."""
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db, incident_id="inc_1")
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "checkout-worker OOM-killed under load", "confidence": 0.8, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )
    first = diagnosis.run(_claim(run_id="run_1"), _envelope(incident_id="inc_1", run_id="run_1"))
    assert first.status == "ok"

    _seed_timeline(fake_db, incident_id="inc_2", entries=[
        {"ts": "2026-08-26T03:00:00Z", "actor": "alert", "action": "pods crash-looping again",
         "evidence": "CrashLoopBackOff on checkout-worker, second time this week",
         "source_event_ids": ["evt_9"]},
    ])
    captured_prompt = {}

    def _capture_and_respond(agent, prompt, **kw):
        captured_prompt["text"] = prompt
        return agent_gateway.InvokeResult(
            text='{"statement": "recurrence of prior OOM pattern", "confidence": 0.7, '
                 '"source_entry_indices": [0], "prior_incident_refs": ["inc_1"]}',
            tokens_used=80, turns=1,
        )

    monkeypatch.setattr("gateway.agent_gateway.invoke", _capture_and_respond)

    second = diagnosis.run(_claim(run_id="run_2"), _envelope(incident_id="inc_2", run_id="run_2"))

    assert second.status == "ok"
    assert "No prior incident signatures available" not in captured_prompt["text"]
    assert "checkout-worker OOM-killed under load" in captured_prompt["text"]
    assert _hypotheses(fake_db)[1]["prior_incident_refs"] == ["inc_1"]


def test_rediagnosing_the_same_incident_updates_its_signature_not_duplicates_it(fake_db, monkeypatch):
    """key=f"sig_{incident_id}" is deterministic, not new_id() - a
    redelivery or a second trigger (Watcher's upstream.matched re-firing
    Diagnosis after timeline.committed already did) for the SAME
    incident must update its own signature, not accumulate duplicates
    that would all independently match a future query."""
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "first pass diagnosis", "confidence": 0.5, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )
    diagnosis.run(_claim(run_id="run_1"), _envelope(incident_id="inc_1", run_id="run_1"))

    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "revised diagnosis after more evidence", "confidence": 0.9, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )
    diagnosis.run(_claim(run_id="run_2"), _envelope(incident_id="inc_1", run_id="run_2"))

    records = _memory_records(fake_db)
    assert len(records) == 1
    assert records[0]["content"]["statement"] == "revised diagnosis after more evidence"


def test_memory_write_failure_does_not_fail_an_otherwise_successful_run(fake_db, monkeypatch):
    """Degrade-not-fail: the hypothesis is already durably written and is
    the source of truth for this incident. A Memory Bank write failure
    must cost future incidents an enrichment, not this run its result."""
    seed_agent(
        fake_db, "diagnosis", "1.0.0",
        read_scopes=[Collection.TIMELINE, Collection.RAW_EVIDENCE, Collection.MEMORY],
        write_scopes=[Collection.HYPOTHESES],  # deliberately NO Collection.MEMORY
    )
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "pods OOM-killed under load", "confidence": 0.8, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"  # not dead_letter, despite the memory write being denied
    assert len(_hypotheses(fake_db)) == 1
    assert _memory_records(fake_db) == []


# --------------------------------------------------------------------------
# R6 - memory citation lands in structured prior_incident_refs
# --------------------------------------------------------------------------

def test_diagnosis_cites_prior_incident_from_memory(fake_db, monkeypatch):
    """R6 acceptance: a failure signature matching an incident from
    memory must end up in Hypothesis.prior_incident_refs, not just
    described in the statement's prose."""
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    # Seeded directly (not via memory_bank.remember) since diagnosis's
    # own declared write scope is hypotheses only, per spec - it must
    # never need MEMORY write access to read a pre-existing signature.
    fake_db.seed(
        f"tenants/{TEST_ORG}/memory/sig_crashloop",
        MemoryRecord(
            key="sig_crashloop", org_id=TEST_ORG, kind="incident_signature",
            content={"pattern": "OOMKilled crash loop on checkout-worker"},
            related_incident_ids=["inc_three_weeks_ago"],
        ).model_dump(mode="json"),
    )
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "matches a known OOM crash loop signature", "confidence": 0.9, '
                 '"source_entry_indices": [0], "prior_incident_refs": ["inc_three_weeks_ago"]}',
            tokens_used=95, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"
    assert _hypotheses(fake_db)[0]["prior_incident_refs"] == ["inc_three_weeks_ago"]


def test_diagnosis_no_memory_match_leaves_prior_refs_empty(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "novel failure", "confidence": 0.4, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=80, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"
    assert _hypotheses(fake_db)[0]["prior_incident_refs"] == []


# --------------------------------------------------------------------------
# R9 - never invent a source
# --------------------------------------------------------------------------

def test_diagnosis_out_of_range_index_dead_letters_never_invents_source(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "guessing", "confidence": 0.3, '
                 '"source_entry_indices": [99], "prior_incident_refs": []}',
            tokens_used=50, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert "no traceable source" in result.detail
    assert _hypotheses(fake_db) == []


def test_diagnosis_empty_indices_dead_letters(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "guessing", "confidence": 0.3, '
                 '"source_entry_indices": [], "prior_incident_refs": []}',
            tokens_used=50, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _hypotheses(fake_db) == []


def test_diagnosis_no_committed_timeline_dead_letters(fake_db):
    _seed_diagnosis_agent(fake_db)
    # No timeline seeded for inc_1.

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "dead_letter"
    assert _hypotheses(fake_db) == []


# --------------------------------------------------------------------------
# Dual trigger + incident_id resolution
# --------------------------------------------------------------------------

def test_diagnosis_triggers_on_upstream_matched(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "upstream provider degradation", "confidence": 0.7, '
                 '"source_entry_indices": [1], "prior_incident_refs": []}',
            tokens_used=60, turns=1,
        ),
    )

    result = diagnosis.run(_claim(), _envelope(event_type="upstream.matched"))

    assert result.status == "ok"


def test_diagnosis_falls_back_to_envelope_incident_id_when_payload_omits_it(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(
            text='{"statement": "x", "confidence": 0.5, '
                 '"source_entry_indices": [0], "prior_incident_refs": []}',
            tokens_used=40, turns=1,
        ),
    )
    publisher_claim = scope_store.sign_claim(org_id=TEST_ORG, agent_name="ledger", agent_version="1.0.0", run_id="run_1")
    envelope = Envelope(run_id="run_1", org_id=TEST_ORG, incident_id="inc_1", claim=publisher_claim,
                         event_type="timeline.committed", payload={})  # no "incident_id" key in payload

    result = diagnosis.run(_claim(), envelope)

    assert result.status == "ok"
    assert _hypotheses(fake_db)[0]["incident_ref"] == "inc_1"


# --------------------------------------------------------------------------
# Model Armor
# --------------------------------------------------------------------------

def test_diagnosis_model_armor_block_writes_nothing(fake_db, monkeypatch):
    _seed_diagnosis_agent(fake_db)
    _seed_timeline(fake_db)
    monkeypatch.setattr(
        "gateway.agent_gateway.build_agent",
        lambda **kw: ("fake-agent", agent_gateway.InvocationOutcome(
            blocked=True, block_reason="Model Armor: injection pattern matched",
        )),
    )
    monkeypatch.setattr(
        "gateway.agent_gateway.invoke",
        lambda agent, prompt, **kw: agent_gateway.InvokeResult(text="", tokens_used=5, turns=1),
    )

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "blocked"
    assert "injection" in result.detail.lower()
    assert _hypotheses(fake_db) == []


# --------------------------------------------------------------------------
# Change correlation: "what shipped just before this broke?"
# --------------------------------------------------------------------------

def _seed_change(fake_db, change_id, occurred_at, service="checkout-api", summary="deploy"):
    fake_db.seed(f"tenants/{TEST_ORG}/change_events/{change_id}", {
        "change_id": change_id, "org_id": TEST_ORG, "source": "github",
        "kind": "deploy", "service": service, "ref": "abc123", "actor": "alice",
        "summary": summary, "occurred_at": occurred_at, "raw": {},
    })


def test_recent_changes_included_in_the_prompt(fake_db, monkeypatch):
    seed_agent(fake_db, "diagnosis", "1.0.0",
               read_scopes=[Collection.TIMELINE, Collection.MEMORY, Collection.CHANGE_EVENTS],
               write_scopes=[Collection.HYPOTHESES])
    _seed_timeline(fake_db)
    _seed_change(fake_db, "chg_before", "2026-08-25T03:00:00+00:00", summary="deployed build 42")

    captured = {}

    def _capture(agent, prompt, *, run_id, org_id):
        captured["prompt"] = prompt
        return agent_gateway.InvokeResult(
            text=json.dumps({"statement": "OOM after deploy", "confidence": 0.8,
                             "source_entry_indices": [0], "prior_incident_refs": []}),
            tokens_used=10, turns=1,
        )

    monkeypatch.setattr(agent_gateway, "build_agent",
                        lambda **kw: (object(), agent_gateway.InvocationOutcome()))
    monkeypatch.setattr(agent_gateway, "invoke", _capture)

    result = diagnosis.run(_claim(), _envelope())

    assert result.status == "ok"
    assert "deployed build 42" in captured["prompt"]
    assert "Changes deployed shortly BEFORE" in captured["prompt"]


def test_changes_after_the_incident_are_excluded(fake_db, monkeypatch):
    """A deploy that happened *after* the incident opened cannot have
    caused it; including it invites a confident wrong hypothesis."""
    seed_agent(fake_db, "diagnosis", "1.0.0",
               read_scopes=[Collection.TIMELINE, Collection.MEMORY, Collection.CHANGE_EVENTS],
               write_scopes=[Collection.HYPOTHESES])
    _seed_timeline(fake_db)
    _seed_change(fake_db, "chg_after", "2026-08-25T09:00:00+00:00", summary="LATER deploy")

    captured = {}
    monkeypatch.setattr(agent_gateway, "build_agent",
                        lambda **kw: (object(), agent_gateway.InvocationOutcome()))
    monkeypatch.setattr(agent_gateway, "invoke",
                        lambda a, p, *, run_id, org_id: captured.update(prompt=p) or
                        agent_gateway.InvokeResult(
                            text=json.dumps({"statement": "s", "confidence": 0.5,
                                             "source_entry_indices": [0], "prior_incident_refs": []}),
                            tokens_used=1, turns=1))

    diagnosis.run(_claim(), _envelope())

    assert "LATER deploy" not in captured["prompt"]
    assert "No change events recorded" in captured["prompt"]


def test_missing_change_scope_degrades_rather_than_failing(fake_db, monkeypatch):
    """An org with no change connector configured is the common case and
    must not fail the run - correlation is enrichment, not a prerequisite."""
    seed_agent(fake_db, "diagnosis", "1.0.0",
               read_scopes=[Collection.TIMELINE, Collection.MEMORY],  # no CHANGE_EVENTS
               write_scopes=[Collection.HYPOTHESES])
    _seed_timeline(fake_db)

    monkeypatch.setattr(agent_gateway, "build_agent",
                        lambda **kw: (object(), agent_gateway.InvocationOutcome()))
    monkeypatch.setattr(agent_gateway, "invoke",
                        lambda a, p, *, run_id, org_id: agent_gateway.InvokeResult(
                            text=json.dumps({"statement": "s", "confidence": 0.5,
                                             "source_entry_indices": [0], "prior_incident_refs": []}),
                            tokens_used=1, turns=1))

    assert diagnosis.run(_claim(), _envelope()).status == "ok"


def test_mixed_timezone_formats_are_ordered_correctly(fake_db, monkeypatch):
    """A change written with a 'Z' suffix and one with '+00:00' represent
    the same kind of instant, but sort differently as raw strings. The
    window must be decided on parsed datetimes, not lexicographically."""
    seed_agent(fake_db, "diagnosis", "1.0.0",
               read_scopes=[Collection.TIMELINE, Collection.MEMORY, Collection.CHANGE_EVENTS],
               write_scopes=[Collection.HYPOTHESES])
    _seed_timeline(fake_db)
    _seed_change(fake_db, "chg_z", "2026-08-25T02:30:00Z", summary="Z-suffixed deploy")
    _seed_change(fake_db, "chg_offset", "2026-08-25T02:45:00+00:00", summary="offset deploy")

    captured = {}
    monkeypatch.setattr(agent_gateway, "build_agent",
                        lambda **kw: (object(), agent_gateway.InvocationOutcome()))
    monkeypatch.setattr(agent_gateway, "invoke",
                        lambda a, p, *, run_id, org_id: captured.update(prompt=p) or
                        agent_gateway.InvokeResult(
                            text=json.dumps({"statement": "s", "confidence": 0.5,
                                             "source_entry_indices": [0], "prior_incident_refs": []}),
                            tokens_used=1, turns=1))

    diagnosis.run(_claim(), _envelope())

    assert "offset deploy" in captured["prompt"]
