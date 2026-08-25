from __future__ import annotations

import os

import pytest

from data import scope_store
from data.models import Collection
from tests.fakes import FakeFirestore

TEST_ORG = "org_test"
OTHER_ORG = "org_other"


@pytest.fixture(autouse=True)
def _claim_secret(monkeypatch):
    monkeypatch.setenv("MORTEMTRACE_CLAIM_SECRET", "test-secret-not-for-deploy")


@pytest.fixture
def fake_db():
    fake = FakeFirestore()
    scope_store.set_client(fake)
    yield fake
    scope_store.set_client(None)  # force re-creation next test, avoid cross-test leakage


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
