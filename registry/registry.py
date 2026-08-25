"""Publish, resolve, and deprecate agent versions.

This module never touches Firestore directly - it calls the registry_*
functions in data/scope_store.py like any other caller, so publishing and
resolving are themselves subject to the same claim/scope enforcement as
every other read and write in the system. The Coordinator resolves an
agent's current version and declared scopes here at dispatch time; a new
version or a brand-new department is picked up on the next event with no
redeploy, because nothing downstream hardcodes a version number.
"""
from __future__ import annotations

from typing import Optional

from data import scope_store
from data.models import AgentVersionRecord, OrgClaim

LATEST = "latest"


def _semver_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(p) for p in version.split("."))
    except ValueError:
        return (0,)


def list_versions(claim: OrgClaim, agent_name: str) -> list[AgentVersionRecord]:
    raw = scope_store.registry_list_versions(claim, agent_name)
    return [AgentVersionRecord.model_validate(r) for r in raw]


def resolve(claim: OrgClaim, agent_name: str, version: str = LATEST) -> Optional[AgentVersionRecord]:
    """Resolve a specific semver, or the highest published version if
    version="latest". Returns None if nothing matches; callers (the
    Coordinator) decide whether that is dead-letter-worthy."""
    if version != LATEST:
        raw = scope_store.registry_get(claim, agent_name, version)
        return AgentVersionRecord.model_validate(raw) if raw else None

    published = [v for v in list_versions(claim, agent_name) if v.status == "published"]
    if not published:
        return None
    return max(published, key=lambda v: _semver_key(v.version))


def publish(claim: OrgClaim, record: AgentVersionRecord) -> None:
    scope_store.registry_put(
        claim, record.agent_name, record.version, record.model_dump(mode="json")
    )


def deprecate(claim: OrgClaim, agent_name: str, version: str) -> None:
    raw = scope_store.registry_get(claim, agent_name, version)
    if raw is None:
        raise ValueError(f"no such registry entry: {agent_name}@{version}")
    raw["status"] = "deprecated"
    scope_store.registry_put(claim, agent_name, version, raw)
