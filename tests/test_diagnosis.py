"""Diagnosis: one hypothesis per run, always traceable to a real
source_event_id, and citing memory's related_incident_ids as structured
data (R6) rather than trusting prose. gateway.agent_gateway.invoke is
always monkeypatched here - these tests must never call real Gemini.
"""
from __future__ import annotations

from data import scope_store
from data.models import Collection, Envelope, MemoryRecord, OrgClaim
from agents.diagnosis import diagnosis
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
        write_scopes=[Collection.HYPOTHESES],
    )


def _hypotheses(fake_db) -> list[dict]:
    return [d for path, d in fake_db._docs.items() if path[:3] == ("tenants", TEST_ORG, "hypotheses")]


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
