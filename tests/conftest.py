from __future__ import annotations

import hashlib
import json
import sys

import pytest

from auth import identity
from data import scope_store
from data.models import Collection
from gateway import agent_gateway
from tests.fakes import FakeFirestore

TEST_ORG = "org_test"
OTHER_ORG = "org_other"

# Real tokens used by HTTP-level tests. These exercise the genuine
# authentication path rather than monkeypatching it away, so a regression
# that reopens the unauthenticated hole fails the suite.
TEST_TOKEN = "test-token-for-org-test"
OTHER_TOKEN = "test-token-for-org-other"
MULTI_ORG_TOKEN = "test-token-for-both-orgs"


def auth_header(token: str = TEST_TOKEN) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _claim_secret(monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_CLAIM_SECRET", "test-secret-not-for-deploy")


@pytest.fixture(autouse=True)
def _session_secret(monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_SESSION_SECRET", "test-session-secret-not-for-deploy")


@pytest.fixture(autouse=True)
def _api_tokens(monkeypatch):
    """Configures the token table for every test, and asserts the default
    posture is closed by leaving anonymous demo mode off unless a test
    turns it on explicitly."""
    monkeypatch.setenv(identity._TOKENS_ENV, json.dumps({
        _digest(TEST_TOKEN): {"org_ids": [TEST_ORG], "subject": "test-single-org"},
        _digest(OTHER_TOKEN): {"org_ids": [OTHER_ORG], "subject": "test-other-org"},
        _digest(MULTI_ORG_TOKEN): {"org_ids": [TEST_ORG, OTHER_ORG], "subject": "test-multi-org"},
    }))
    monkeypatch.delenv(identity._ANON_DEMO_ENV, raising=False)


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Limiter state is per-process and would otherwise carry request
    counts from one test into the next. The pre-auth limiters in
    particular (a tight budget by design - see auth/identity.py's
    build_pre_auth_limiter) exhaust within a single test FILE's worth of
    requests if left unreset, not just across a long-running deployment -
    the exact failure mode that surfaced when they were added and this
    list wasn't updated to match."""
    yield
    for module_name, attr in (
        ("api.ingest", "_INGEST_LIMITER"),
        ("api.ingest", "_WEBHOOK_LIMITER"),
        ("api.ingest", "_PRE_LOOKUP_WEBHOOK_LIMITER"),
        ("console.ui", "_CONSOLE_LIMITER"),
        ("console.ui", "_PRE_AUTH_LIMITER"),
    ):
        module = sys.modules.get(module_name)
        limiter = getattr(module, attr, None) if module else None
        if limiter is not None:
            limiter.reset()


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
    # The registry scope cache is process-global and keyed only by
    # (agent_name, version), so without this a scope resolved against one
    # test's fake store stays visible to the next test's - including the
    # empty "unregistered agent" result, which then denies an agent the
    # later test did seed.
    scope_store.clear_scope_cache()
    yield fake
    scope_store.clear_scope_cache()
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


def seed_membership(fake_db: FakeFirestore, user_id: str, org_id: str, role: str = "member",
                     *, email: str = "person@example.com", status: str = "active") -> None:
    """Seeds a human identity + org membership directly, mirroring
    seed_agent's role for the agent-scope system: enough for a test to
    exercise session-based authorization without a real OIDC round trip."""
    fake_db.seed(f"users/{user_id}", {
        "user_id": user_id, "email": email, "display_name": email,
        "created_at": "2026-01-01T00:00:00+00:00", "last_login_at": "2026-01-01T00:00:00+00:00",
    })
    fake_db.seed(f"memberships/{user_id}__{org_id}", {
        "membership_id": f"{user_id}__{org_id}", "user_id": user_id, "org_id": org_id,
        "role": role, "status": status, "invited_by": None,
        "created_at": "2026-01-01T00:00:00+00:00",
    })


def mint_test_session_cookie(user_id: str) -> str:
    from auth import session as session_module
    return session_module.mint_session(user_id)


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
