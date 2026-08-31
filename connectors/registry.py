"""Loading connector configuration, and turning an arbitrary webhook body
into either incident evidence or a change event.

Lookup is a direct, unauthenticated document read - deliberately, and for
the same structural reason `scope_store._resolve_scopes` reads the agent
registry directly: there is a chicken-and-egg. A webhook arrives with a
vendor signature, not one of our API tokens, so we cannot know which
tenant it belongs to until we have read the connector document that says
so. The connector_id is unguessable and the signature is what actually
authorises; the read only establishes *which* signature to check.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any, Optional

from data import scope_store
from data.models import ChangeEvent, ChangeKind, ConnectorConfig, new_id, now

logger = logging.getLogger("mortemtrace.connectors.registry")

# Same shape as the id generator, so a scan of the URL space is infeasible.
_CONNECTOR_ID_RE = re.compile(r"^conn_[0-9a-f]{12,32}$")


class UnknownConnector(Exception):
    """No such connector, or it is disabled."""


def valid_connector_id(connector_id: str) -> bool:
    return bool(_CONNECTOR_ID_RE.match(connector_id))


def load(org_hint: Optional[str], connector_id: str) -> ConnectorConfig:
    """Resolves a connector by id.

    Connectors are stored per tenant at
    /tenants/{org_id}/connectors/{connector_id}, so resolving one without
    already knowing the tenant needs a collection-group lookup. The
    connector document carries its own org_id, which is what the rest of
    the request then acts as.
    """
    if not valid_connector_id(connector_id):
        raise UnknownConnector("malformed connector id")

    raw = scope_store.find_connector(connector_id, org_hint=org_hint)
    if raw is None:
        raise UnknownConnector("no such connector")

    config = ConnectorConfig.model_validate(raw)
    if not config.enabled:
        raise UnknownConnector("connector is disabled")
    return config


# --------------------------------------------------------------------------
# Turning an arbitrary payload into something the pipeline understands
# --------------------------------------------------------------------------

# Field names commonly used across CI/CD and alerting tools. This is a
# best-effort convenience for populating change-event metadata, NOT a
# parser: anything not recognised still lands in `raw` and in the
# human-readable summary, so nothing is lost by failing to match.
_SERVICE_KEYS = (
    "service", "service_name", "repository", "repo", "app", "application",
    "project", "job_name", "job", "workspace", "pipeline", "stack", "cluster",
)
_REF_KEYS = ("sha", "commit", "commit_sha", "head_sha", "build_number", "number", "id", "version")
_ACTOR_KEYS = ("actor", "user", "username", "sender", "triggered_by", "author", "login")
_KIND_HINTS: dict[str, ChangeKind] = {
    "deploy": "deploy", "deployment": "deploy", "release": "deploy",
    "merge": "merge", "pull_request": "merge", "push": "merge",
    "rollback": "rollback", "revert": "rollback",
    "apply": "infra_apply", "terraform": "infra_apply",
    "config": "config_change",
}


def _walk(payload: Any, depth: int = 0, prefix: str = ""):
    """Yields (dotted_path, value) for scalar leaves, a few levels deep.

    Bounded depth and breadth on purpose: a webhook body is attacker-
    influenced, and an unbounded walk over a deeply nested or very wide
    payload is a denial-of-service vector on our own ingest path.
    """
    if depth > 4:
        return
    if isinstance(payload, dict):
        for key, value in list(payload.items())[:200]:
            path = f"{prefix}.{str(key).lower()}" if prefix else str(key).lower()
            if isinstance(value, (str, int, float)) and value != "":
                yield path, value
            else:
                yield from _walk(value, depth + 1, path)
    elif isinstance(payload, list):
        for item in payload[:50]:
            yield from _walk(item, depth + 1, prefix)


# When a semantic field is an *object* rather than a scalar - GitHub's
# `repository: {name: ...}`, PagerDuty's `service: {summary: ...}`,
# GitHub's `sender: {login: ...}` - the human-meaningful value is one of
# a small, near-universal set of child keys. Checking for these is what
# makes extraction work across tools without knowing any of them.
_NAME_CHILD_KEYS = ("name", "login", "full_name", "title", "summary", "slug", "id")


def _first_match(payload: Any, keys: tuple[str, ...]) -> Optional[str]:
    """Best-effort lookup of a semantic field across an unknown payload.

    Tries, in order of decreasing confidence: an exact path, any path
    ending in the key, and the key as an object whose value is carried by
    a conventional child field. Returns None rather than guessing wildly -
    an absent field is honest, and the full payload is retained in `raw`
    and the summary regardless.
    """
    found = dict(_walk(payload))

    for key in keys:
        if key in found:
            return str(found[key])[:200]

    for key in keys:
        for child in _NAME_CHILD_KEYS:
            candidate = f"{key}.{child}"
            for path, value in found.items():
                if path == candidate or path.endswith(f".{candidate}"):
                    return str(value)[:200]

    for key in keys:
        for path, value in found.items():
            if path.split(".")[-1] == key:
                return str(value)[:200]

    return None


def _infer_kind(source: str, payload: Any) -> ChangeKind:
    haystack = f"{source} {str(payload)[:2000]}".lower()
    for hint, kind in _KIND_HINTS.items():
        if hint in haystack:
            return kind
    return "unknown"


def _parse_timestamp(payload: Any) -> datetime:
    for key in ("timestamp", "occurred_at", "created_at", "updated_at", "time"):
        value = _first_match(payload, (key,))
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
    return now()


def to_change_event(config: ConnectorConfig, payload: dict) -> ChangeEvent:
    """Best-effort structured change record.

    Every field is optional except the summary and the raw payload, so a
    completely unrecognised tool still produces a usable, correlatable
    record rather than being rejected. Correlation is by time and (when
    found) service; the raw body is always retained so a human can read
    what actually happened.
    """
    return ChangeEvent(
        change_id=new_id("chg"),
        org_id=config.org_id,
        source=config.source,
        kind=_infer_kind(config.source, payload),
        service=_first_match(payload, _SERVICE_KEYS),
        ref=_first_match(payload, _REF_KEYS),
        actor=_first_match(payload, _ACTOR_KEYS),
        summary=summarize(config.source, payload),
        occurred_at=_parse_timestamp(payload),
        raw=payload,
    )


def summarize(source: str, payload: dict, limit: int = 400) -> str:
    """A short human- and model-readable line describing the payload.

    Used as the change-event summary and as the evidence text handed to
    Intake. Deliberately lossy and deliberately not a schema: Intake's job
    is extracting meaning from unstructured evidence, so the correct thing
    to hand it is the content, not a guess at its structure.
    """
    parts = []
    for path, value in _walk(payload):
        leaf = path.split(".")[-1]
        # Never echo credential-shaped fields into evidence - this text
        # reaches a model and then a draft a human may circulate. Matched
        # on the leaf name so a nested `auth.token` is caught too.
        if any(marker in leaf for marker in
               ("password", "token", "secret", "authorization", "api_key", "apikey", "credential")):
            continue
        parts.append(f"{path}={value}")
        if len(parts) >= 40:
            break
    body = ", ".join(parts)
    text = f"[{source}] {body}"
    return text[:limit]
