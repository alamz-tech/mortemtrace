"""The sole Firestore access path in MortemTrace.

Every read and write in the system - agents, registry, memory, console -
goes through the functions in this module. Nothing else in the codebase
may import `google.cloud.firestore` directly; `tests/
test_firestore_access_boundary.py` greps the tree and fails the build if
it finds a second entry point.

Two failure modes are deliberately different:
  - A forged org claim (tenant mismatch, or a bad/expired signature)
    fails the run closed via TenantViolation. Produce nothing rather
    than something that crossed a tenant boundary.
  - An out-of-scope read (e.g. Comms asking for raw_evidence) raises
    ScopeDenied, which callers are expected to catch and continue on
    with reduced context. A Support draft with no log content is the
    correct outcome of that request, not an error.
Both are audited either way, and the audit write itself bypasses scope
checks - the store must always be able to record what it just denied.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from google.cloud import firestore

from data.models import (
    AuditEntry,
    Collection,
    OrgClaim,
    TENANT_SCOPED_COLLECTIONS,
    new_id,
)
from telemetry.otel_setup import record_audit_event

logger = logging.getLogger("mortemtrace.scope_store")

_CLAIM_SECRET_ENV = "MORTEMTRACE_CLAIM_SECRET"
_DEV_FALLBACK_SECRET = "dev-only-insecure-secret-do-not-deploy"
_CLAIM_TTL = timedelta(minutes=15)

_REGISTRY_ROOT = "registry"

_CLIENT: Optional[firestore.Client] = None
_CLIENT_LOCK = threading.Lock()


class ScopeDenied(Exception):
    """Out-of-scope read/write. Callers should treat this as a degrade
    signal, not a crash: catch it, continue with reduced context."""


class TenantViolation(Exception):
    """Forged, mismatched, or expired org claim. Callers must fail the
    run closed - do not catch-and-continue on this one."""


class SourceRequired(Exception):
    """Attempted commit to timeline/hypotheses without source_event_ids.
    R9's hallucination guard: enforced here, not in the agent layer."""


# --------------------------------------------------------------------------
# Client
# --------------------------------------------------------------------------

def _client() -> firestore.Client:
    global _CLIENT
    if _CLIENT is None:
        with _CLIENT_LOCK:
            if _CLIENT is None:
                # FIRESTORE_EMULATOR_HOST, if set, is honored automatically
                # by the underlying client library - this is what lets
                # tests and local dev run without live GCP credentials.
                _CLIENT = firestore.Client()
    return _CLIENT


def set_client(client: firestore.Client) -> None:
    """Test/emulator injection point. Production code never calls this."""
    global _CLIENT
    with _CLIENT_LOCK:
        _CLIENT = client


# --------------------------------------------------------------------------
# Claim signing and verification
# --------------------------------------------------------------------------

def _secret() -> bytes:
    secret = os.environ.get(_CLAIM_SECRET_ENV)
    if not secret:
        logger.warning(
            "%s not set; using an insecure development default. "
            "Never deploy this state - set a real secret via Secret Manager.",
            _CLAIM_SECRET_ENV,
        )
        secret = _DEV_FALLBACK_SECRET
    return secret.encode("utf-8")


def _claim_signing_input(
    org_id: str, agent_name: str, agent_version: str, run_id: str,
    issued_at: datetime, expires_at: datetime,
) -> bytes:
    return "|".join([
        org_id, agent_name, agent_version, run_id,
        issued_at.isoformat(), expires_at.isoformat(),
    ]).encode("utf-8")


def sign_claim(org_id: str, agent_name: str, agent_version: str, run_id: str) -> OrgClaim:
    """Minted by the Coordinator when it dispatches a worker. HMAC over the
    claim fields is the trust boundary for this deployment; a multi-signer
    production system would move this to Secret Manager-backed per-service-
    account keys (see ARCHITECTURE.md section 9)."""
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + _CLAIM_TTL
    sig = hmac.new(
        _secret(),
        _claim_signing_input(org_id, agent_name, agent_version, run_id, issued_at, expires_at),
        hashlib.sha256,
    ).hexdigest()
    return OrgClaim(
        org_id=org_id, agent_name=agent_name, agent_version=agent_version,
        run_id=run_id, issued_at=issued_at, expires_at=expires_at, signature=sig,
    )


def verify_claim(claim: OrgClaim) -> bool:
    if datetime.now(timezone.utc) > claim.expires_at:
        return False
    expected = hmac.new(
        _secret(),
        _claim_signing_input(
            claim.org_id, claim.agent_name, claim.agent_version,
            claim.run_id, claim.issued_at, claim.expires_at,
        ),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, claim.signature)


# --------------------------------------------------------------------------
# Scope resolution
# --------------------------------------------------------------------------

def _resolve_scopes(agent_name: str, agent_version: str) -> tuple[list[Collection], list[Collection]]:
    """Reads the registry-declared scopes directly against Firestore. This
    is the one place scope_store touches `/registry` itself rather than via
    registry.py - registry.py is a thin wrapper that calls read()/write()
    below like everyone else, so it cannot be the thing scope_store calls
    back into (that would be circular).

    Deliberately does not trust a caller-supplied scope list: the data
    layer decides what an agent may touch by looking it up itself, never
    by asking the agent what it thinks it's allowed to do.
    """
    doc = (
        _client()
        .collection(_REGISTRY_ROOT)
        .document(agent_name)
        .collection("versions")
        .document(agent_version)
        .get()
    )
    if not doc.exists:
        return [], []
    data = doc.to_dict() or {}
    reads = [Collection(c) for c in data.get("read_scopes", [])]
    writes = [Collection(c) for c in data.get("write_scopes", [])]
    return reads, writes


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def _audit(org_id: str, actor_agent: str, version: str, verdict: str,
           reason: str, path: str, run_id: str) -> None:
    entry = AuditEntry(
        entry_id=new_id("audit"), org_id=org_id, actor_agent=actor_agent,
        version=version, verdict=verdict, reason=reason, path=path, run_id=run_id,
    )
    _client().collection("tenants").document(org_id).collection("audit").document(
        entry.entry_id
    ).set(entry.model_dump(mode="json"))
    # Firestore /audit is the permanent structured record; this mirrors the
    # same event onto whatever OTel span is active so R10's "scope denial
    # visible in the same trace as the commit it affected" holds without
    # every caller having to remember to instrument both.
    record_audit_event(verdict, reason, path, actor_agent, run_id, org_id)


# --------------------------------------------------------------------------
# Path construction
# --------------------------------------------------------------------------

def _collection_ref(org_id: str, collection: Collection):
    if collection == Collection.REGISTRY:
        return _client().collection(_REGISTRY_ROOT)
    return _client().collection("tenants").document(org_id).collection(collection.value)


# --------------------------------------------------------------------------
# Authorization - shared by read / write / query
# --------------------------------------------------------------------------

def _authorize(claim: OrgClaim, collection: Collection, mode: str, target_org: str) -> None:
    """mode is 'read' or 'write'. Raises TenantViolation or ScopeDenied,
    auditing the denial before raising either way. Callers must not
    swallow TenantViolation; ScopeDenied is the one meant to be caught."""
    if not verify_claim(claim):
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "deny",
               "invalid or expired claim signature", collection.value, claim.run_id)
        raise TenantViolation("claim failed verification")

    if collection in TENANT_SCOPED_COLLECTIONS and target_org != claim.org_id:
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "deny",
               f"forged claim: org mismatch ({claim.org_id} vs {target_org})",
               collection.value, claim.run_id)
        raise TenantViolation(
            f"org claim {claim.org_id} does not match path org {target_org}"
        )

    read_scopes, write_scopes = _resolve_scopes(claim.agent_name, claim.agent_version)
    allowed = read_scopes if mode == "read" else write_scopes
    if collection not in allowed:
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "deny",
               f"{claim.agent_name}@{claim.agent_version} has no {mode} scope for {collection.value}",
               collection.value, claim.run_id)
        raise ScopeDenied(f"{claim.agent_name} cannot {mode} {collection.value}")


# --------------------------------------------------------------------------
# Public read / write / query
# --------------------------------------------------------------------------

def read(
    claim: OrgClaim,
    collection: Collection,
    doc_id: Optional[str] = None,
    *,
    path_org_id: Optional[str] = None,
) -> Any:
    """Read one document (doc_id given) or list an entire collection."""
    target_org = path_org_id or claim.org_id
    _authorize(claim, collection, "read", target_org)

    ref = _collection_ref(target_org, collection)
    if doc_id is not None:
        snap = ref.document(doc_id).get()
        result = snap.to_dict() if snap.exists else None
    else:
        result = [d.to_dict() for d in ref.stream()]

    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "read granted", f"{collection.value}/{doc_id or '*'}", claim.run_id)
    return result


def try_read(
    claim: OrgClaim,
    collection: Collection,
    doc_id: Optional[str] = None,
    *,
    path_org_id: Optional[str] = None,
) -> Any:
    """Convenience wrapper for the degrade-not-fail path: returns None on
    ScopeDenied instead of raising. TenantViolation still propagates -
    that one must always fail the run closed."""
    try:
        return read(claim, collection, doc_id, path_org_id=path_org_id)
    except ScopeDenied as exc:
        logger.info("degraded read: %s", exc)
        return None


def query(
    claim: OrgClaim,
    collection: Collection,
    filters: Iterable[tuple[str, str, Any]] = (),
    *,
    path_org_id: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[dict]:
    """Filtered read. Same scope/tenant enforcement as read()."""
    target_org = path_org_id or claim.org_id
    _authorize(claim, collection, "read", target_org)

    q = _collection_ref(target_org, collection)
    for field, op, value in filters:
        q = q.where(field, op, value)
    if limit:
        q = q.limit(limit)
    docs = [d.to_dict() for d in q.stream()]

    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           f"query granted ({len(docs)} docs)", collection.value, claim.run_id)
    return docs


def try_query(
    claim: OrgClaim,
    collection: Collection,
    filters: Iterable[tuple[str, str, Any]] = (),
    *,
    path_org_id: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[dict]:
    """query(), degraded to an empty list on ScopeDenied instead of raising."""
    try:
        return query(claim, collection, filters, path_org_id=path_org_id, limit=limit)
    except ScopeDenied as exc:
        logger.info("degraded query: %s", exc)
        return []


def write(
    claim: OrgClaim,
    collection: Collection,
    doc_id: str,
    data: dict,
    *,
    path_org_id: Optional[str] = None,
    idempotency_key: Optional[str] = None,
) -> bool:
    """Write one document. Returns True if written, False if skipped as a
    duplicate (idempotency_key already seen for this org).

    Timeline and hypothesis writes are rejected here, not upstream, if
    they lack source_event_ids - R9's hallucination guard lives at the
    store layer on purpose.
    """
    target_org = path_org_id or claim.org_id
    _authorize(claim, collection, "write", target_org)

    if collection in (Collection.TIMELINE, Collection.HYPOTHESES):
        _require_source_event_ids(collection, data)

    if idempotency_key is not None:
        marker_ref = (
            _client().collection("tenants").document(target_org)
            .collection("_idempotency").document(idempotency_key)
        )
        if marker_ref.get().exists:
            _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
                   "duplicate write skipped (idempotent)",
                   f"{collection.value}/{doc_id}", claim.run_id)
            return False
        marker_ref.set({"run_id": claim.run_id, "at": firestore.SERVER_TIMESTAMP})

    _collection_ref(target_org, collection).document(doc_id).set(data)
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "write granted", f"{collection.value}/{doc_id}", claim.run_id)
    return True


def _require_source_event_ids(collection: Collection, data: dict) -> None:
    if collection == Collection.TIMELINE:
        entries = data.get("entries", [])
        for entry in entries:
            if not entry.get("source_event_ids"):
                raise SourceRequired(
                    "timeline entry missing source_event_ids; commit rejected"
                )
    elif collection == Collection.HYPOTHESES:
        if not data.get("source_event_ids"):
            raise SourceRequired(
                "hypothesis missing source_event_ids; commit rejected"
            )


# --------------------------------------------------------------------------
# Registry - the one collection with a nested shape
# (/registry/{agent_name}/versions/{semver}, per ARCHITECTURE.md section 6),
# so it gets its own three functions rather than overloading the flat
# collection helpers above. Same claim/scope enforcement either way -
# registry.py calls these instead of touching Firestore itself.
# --------------------------------------------------------------------------

def registry_get(claim: OrgClaim, agent_name: str, version: str) -> Optional[dict]:
    _authorize(claim, Collection.REGISTRY, "read", claim.org_id)
    doc = (
        _client().collection(_REGISTRY_ROOT).document(agent_name)
        .collection("versions").document(version).get()
    )
    result = doc.to_dict() if doc.exists else None
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "registry read granted", f"registry/{agent_name}/versions/{version}", claim.run_id)
    return result


def registry_list_versions(claim: OrgClaim, agent_name: str) -> list[dict]:
    _authorize(claim, Collection.REGISTRY, "read", claim.org_id)
    docs = (
        _client().collection(_REGISTRY_ROOT).document(agent_name)
        .collection("versions").stream()
    )
    result = [d.to_dict() for d in docs]
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           f"registry list granted ({len(result)})", f"registry/{agent_name}/versions/*", claim.run_id)
    return result


def registry_put(claim: OrgClaim, agent_name: str, version: str, data: dict) -> None:
    _authorize(claim, Collection.REGISTRY, "write", claim.org_id)
    (
        _client().collection(_REGISTRY_ROOT).document(agent_name)
        .collection("versions").document(version).set(data)
    )
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "registry write granted", f"registry/{agent_name}/versions/{version}", claim.run_id)


# --------------------------------------------------------------------------
# Bootstrap - infra/init_firestore.py only
# --------------------------------------------------------------------------

def bootstrap_write(collection: Collection, doc_id: str, data: dict, *, org_id: Optional[str] = None) -> None:
    """Unauthenticated write used only during one-time environment
    initialization (seed data for services/customers/etc.) - there is no
    claim to check yet because nothing has been registered. Never called
    from agent code; `tests/test_firestore_access_boundary.py` checks this
    stays true by grepping for callers outside infra/."""
    _collection_ref(org_id or "_bootstrap", collection).document(doc_id).set(data)


def bootstrap_registry_write(agent_name: str, version: str, data: dict) -> None:
    """Unauthenticated write for the registry's own bootstrap entries -
    the platform-admin identity that will publish everyone else, and the
    Coordinator's own entry (nothing can resolve its own scopes before it
    exists). infra/init_firestore.py only, same rule as bootstrap_write."""
    (
        _client().collection(_REGISTRY_ROOT).document(agent_name)
        .collection("versions").document(version).set(data)
    )
