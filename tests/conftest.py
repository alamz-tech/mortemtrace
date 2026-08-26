from __future__ import annotations

import os

import pytest

from data import scope_store
from data.models import Collection
from gateway import agent_gateway
from tests.fakes import FakeFirestore

TEST_ORG = "org_test"
OTHER_ORG = "org_other"


@pytest.fixture(autouse=True)
def _claim_secret(monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_CLAIM_SECRET", "test-secret-not-for-deploy")


@pytest.fixture(scope="session", autouse=True)
def _shutdown_telemetry():
    """api/ingest.py and console/ui.py call init_telemetry() at import
    time, correctly, since a real Cloud Run entrypoint should initialize
    tracing once at container startup. Importing those modules during
    test collection installs a real BatchSpanProcessor whose background
    thread otherwise tries to flush to stdout after pytest has already
    closed its captured output at session end - harmless, but noisy.
    Flushing here, before that teardown, keeps `pytest` output clean."""
    yield
    from opentelemetry import trace

    provider = trace.get_tracer_provider()
    shutdown = getattr(provider, "shutdown", None)
    if callable(shutdown):
        shutdown()


@pytest.fixture
def fake_db():
    fake = FakeFirestore()
    scope_store.set_client(fake)
    yield fake
    scope_store.set_client(None)  # force re-creation next test, avoid cross-test leakage


@pytest.fixture
def clean_coordinator():
    """Coordinator's worker registry is process-global (workers
    self-register at import time in the real app). Tests that register
    fakes must not leak them into other tests."""
    from agents.coordinator import coordinator

    saved = dict(coordinator._WORKERS)
    coordinator._WORKERS.clear()
    yield coordinator
    coordinator._WORKERS.clear()
    coordinator._WORKERS.update(saved)


def seed_agent(fake_db: FakeFirestore, agent_name: str, version: str,
                read_scopes: list[Collection], write_scopes: list[Collection],
                department: str | None = None) -> None:
    fake_db.seed(
        f"registry/{agent_name}/versions/{version}",
        {
            "agent_name": agent_name,
            "version": version,
            "input_schema": "n/a",
            "output_schema": "n/a",
            "allowed_tools": [],
            "read_scopes": [c.value for c in read_scopes],
            "write_scopes": [c.value for c in write_scopes],
            "department": department,
            "status": "published",
        },
    )


def stub_gateway(monkeypatch, *, text: str, blocked: bool = False,
                  block_reason: str = "blocked for test",
                  tokens_used: int = 10, turns: int = 1) -> None:
    """Test double for the gateway boundary, used by the four
    departmental agent tests. Replaces build_agent()/invoke() so a
    worker's own draft-building logic is exercised against a canned
    model response instead of a real Gemini call - never call real
    Gemini in tests. Model Armor's actual screening logic is exercised
    directly in tests/test_gateway.py; here we only need to control
    whether the *outcome* a worker sees is blocked, so build_agent's
    returned InvocationOutcome is set directly rather than earned by
    routing a crafted prompt through the real callback.

    Patches the `gateway.agent_gateway` module object, not the names
    imported into it - worker modules call `agent_gateway.build_agent(...)`
    / `agent_gateway.invoke(...)` at call time (per the ADK usage pattern
    every departmental agent follows), so patching the module attribute
    here is what makes the fake take effect there.
    """
    def fake_build_agent(*, name, run_id, org_id, instruction, tools=None,
                          output_schema=None, model=None, **kwargs):
        outcome = agent_gateway.InvocationOutcome(
            blocked=blocked, block_reason=block_reason if blocked else None,
        )
        return object(), outcome

    def fake_invoke(agent, prompt, *, run_id, org_id):
        return agent_gateway.InvokeResult(text=text, tokens_used=tokens_used, turns=turns)

    monkeypatch.setattr(agent_gateway, "build_agent", fake_build_agent)
    monkeypatch.setattr(agent_gateway, "invoke", fake_invoke)
