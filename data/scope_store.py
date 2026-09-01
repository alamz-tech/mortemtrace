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
import secrets
import threading
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Callable, Iterable, Optional

from google.api_core.exceptions import AlreadyExists
from google.cloud import firestore
from google.cloud.firestore_v1.base_query import FieldFilter

from data.models import (
    TENANT_SCOPED_COLLECTIONS,
    AuditEntry,
    Collection,
    Invitation,
    Membership,
    Organization,
    OrgClaim,
    User,
    new_id,
    now,
)
from telemetry.otel_setup import record_audit_event

logger = logging.getLogger("mortemtrace.scope_store")

_CLAIM_SECRET_ENV = "MORTEMTRACE_CLAIM_SECRET"
_DEV_FALLBACK_SECRET = "dev-only-insecure-secret-do-not-deploy"
_CLAIM_TTL = timedelta(minutes=15)

_REGISTRY_ROOT = "registry"

# Every Firestore call carries this. Without it a hung backend holds a
# Cloud Run request until the platform's own 300s ceiling, tying up an
# instance the whole time; under any concurrency that exhausts the
# instance pool from a single slow dependency.
_OP_TIMEOUT_SECONDS = float(os.environ.get("MORTEMTRACE_FIRESTORE_TIMEOUT", "10"))

_CLIENT: Optional[firestore.Client] = None
_CLIENT_LOCK = threading.Lock()

# Registry scope lookups happen on *every* authorize, i.e. every read and
# every write. The registry is near-static (it changes only when someone
# publishes an agent version), so re-fetching it per operation was pure
# overhead: it made a single logical read cost two reads plus an audit
# write. Cached with a short TTL so a publish still takes effect without
# a redeploy - R4's "no redeploy" property is preserved, just with up to
# _SCOPE_CACHE_TTL of delay instead of zero.
_SCOPE_CACHE_TTL = float(os.environ.get("MORTEMTRACE_SCOPE_CACHE_TTL", "30"))
_SCOPE_CACHE: dict[tuple[str, str], tuple[float, tuple[list, list]]] = {}
_SCOPE_CACHE_LOCK = threading.Lock()


def clear_scope_cache() -> None:
    """Invalidates the scope cache. Called after a registry write so a
    publish is visible immediately in the process that made it, and used
    by tests to keep cases independent."""
    with _SCOPE_CACHE_LOCK:
        _SCOPE_CACHE.clear()


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
    issued_at = datetime.now(UTC)
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
    if datetime.now(UTC) > claim.expires_at:
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

    Cached for _SCOPE_CACHE_TTL seconds - see the cache declaration above
    for why, and for why a short TTL rather than permanent memoisation.
    An unknown agent's empty result is cached too: that is the deny path,
    and leaving it uncached would let an unregistered agent hammer the
    registry on every attempt.
    """
    key = (agent_name, agent_version)
    nowt = time.monotonic()
    with _SCOPE_CACHE_LOCK:
        entry = _SCOPE_CACHE.get(key)
        if entry is not None and entry[0] > nowt:
            return entry[1]

    doc = (
        _client()
        .collection(_REGISTRY_ROOT)
        .document(agent_name)
        .collection("versions")
        .document(agent_version)
        .get(timeout=_OP_TIMEOUT_SECONDS)
    )
    if not doc.exists:
        resolved: tuple[list, list] = ([], [])
    else:
        data = doc.to_dict() or {}
        # An unrecognised collection name in a registry entry must deny,
        # not explode: a typo (or an entry written by a newer version of
        # the code) would otherwise raise ValueError out of the authorize
        # path and surface as a 500 rather than a clean denial.
        resolved = (
            _coerce_collections(data.get("read_scopes", []), agent_name, "read"),
            _coerce_collections(data.get("write_scopes", []), agent_name, "write"),
        )

    with _SCOPE_CACHE_LOCK:
        _SCOPE_CACHE[key] = (nowt + _SCOPE_CACHE_TTL, resolved)
    return resolved


def _coerce_collections(raw: Iterable[Any], agent_name: str, mode: str) -> list[Collection]:
    out: list[Collection] = []
    for value in raw or []:
        try:
            out.append(Collection(value))
        except ValueError:
            logger.error(
                "registry entry for %s declares unknown %s scope %r; ignoring it "
                "(the grant is dropped, so this fails closed)", agent_name, mode, value,
            )
    return out


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

# Audit entries are written on every allow and every deny, so the
# collection grows roughly three documents per agent operation and, left
# alone, forever. Firestore's TTL policy deletes them server-side once
# `expires_at` passes - see infra/firestore.indexes.json and
# infra/README.md for the one-time enablement command.
#
# The retention default is deliberately long: this is a compliance audit
# trail, and shortening it is a policy decision, not a performance one.
_AUDIT_RETENTION_DAYS = int(os.environ.get("MORTEMTRACE_AUDIT_RETENTION_DAYS", "400"))


def _audit(org_id: str, actor_agent: str, version: str, verdict: str,
           reason: str, path: str, run_id: str) -> None:
    entry = AuditEntry(
        entry_id=new_id("audit"), org_id=org_id, actor_agent=actor_agent,
        version=version, verdict=verdict, reason=reason, path=path, run_id=run_id,
    )
    document = entry.model_dump(mode="json")
    # Written as a native datetime, not the ISO string model_dump produces:
    # Firestore's TTL only acts on a real Timestamp field, so serialising
    # this one to a string would leave the policy silently inert.
    document["expires_at"] = datetime.now(UTC) + timedelta(days=_AUDIT_RETENTION_DAYS)
    _client().collection("tenants").document(org_id).collection("audit").document(
        entry.entry_id
    ).set(document)
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
        snap = ref.document(doc_id).get(timeout=_OP_TIMEOUT_SECONDS)
        result = snap.to_dict() if snap.exists else None
    else:
        result = [d.to_dict() for d in ref.stream(timeout=_OP_TIMEOUT_SECONDS)]

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


_DEMO_PROOFS_ENV = "MORTEMTRACE_DEMO_SCOPE_PROOFS"


def demo_scope_proof(claim: OrgClaim, collection: Collection, doc_id: str) -> None:
    """Performs a read that is *expected* to be denied, to produce a
    visible denial in the audit trail.

    Comms, Compliance and Exposure each did this inline to generate the
    on-camera scope-denial proof (SPEC section 10, beat 2). It is a good
    demo device and a bad production default: it costs a registry lookup
    plus an audit write on every single agent run, and it fills the audit
    log with self-inflicted denials that a real security reviewer has to
    triage as noise before finding a genuine one.

    Off unless MORTEMTRACE_DEMO_SCOPE_PROOFS=1. The boundary itself is
    unchanged either way - it is enforced by _authorize() whether or not
    anyone deliberately walks into it.
    """
    if os.environ.get(_DEMO_PROOFS_ENV) != "1":
        return
    result = try_read(claim, collection, doc_id)
    if result is not None:
        logger.warning(
            "%s unexpectedly read %s for %s - scope misconfiguration? "
            "ignoring the content regardless.",
            claim.agent_name, collection.value, doc_id,
        )


def query(
    claim: OrgClaim,
    collection: Collection,
    filters: Iterable[tuple[str, str, Any]] = (),
    *,
    path_org_id: Optional[str] = None,
    limit: Optional[int] = None,
    order_by: Optional[str] = None,
    descending: bool = False,
) -> list[dict]:
    """Filtered read. Same scope/tenant enforcement as read().

    `order_by`/`descending` exist so callers can get "the most recent N"
    from the server rather than fetching an entire collection and sorting
    in Python. The console did the latter for runs and for the audit log -
    audit grows by roughly three entries per agent operation, so that page
    got monotonically slower forever and would eventually time out.
    """
    target_org = path_org_id or claim.org_id
    _authorize(claim, collection, "read", target_org)

    q = _collection_ref(target_org, collection)
    for field, op, value in filters:
        # Keyword FieldFilter, not the positional where(field, op, value)
        # form: the positional signature is deprecated and emitted a
        # UserWarning on every query, which showed up in production logs
        # as recurring noise around every genuine log line.
        q = q.where(filter=FieldFilter(field, op, value))
    if order_by:
        q = q.order_by(order_by, direction="DESCENDING" if descending else "ASCENDING")
    if limit:
        q = q.limit(limit)
    docs = [d.to_dict() for d in q.stream(timeout=_OP_TIMEOUT_SECONDS)]

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
    order_by: Optional[str] = None,
    descending: bool = False,
) -> list[dict]:
    """query(), degraded to an empty list on ScopeDenied instead of raising."""
    try:
        return query(claim, collection, filters, path_org_id=path_org_id, limit=limit,
                     order_by=order_by, descending=descending)
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
        # create() fails if the document already exists, atomically, in a
        # single round trip. The previous get()-then-set() was a
        # check-then-act race: two concurrent deliveries of the same
        # Pub/Sub message (at-least-once is the guarantee, so this is
        # expected, not exotic) could both observe "not present" and both
        # proceed - defeating the exact duplicate-suppression this key
        # exists to provide.
        try:
            marker_ref.create(
                {"run_id": claim.run_id, "at": firestore.SERVER_TIMESTAMP},
                timeout=_OP_TIMEOUT_SECONDS,
            )
        except AlreadyExists:
            _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
                   "duplicate write skipped (idempotent)",
                   f"{collection.value}/{doc_id}", claim.run_id)
            return False

    _collection_ref(target_org, collection).document(doc_id).set(data, timeout=_OP_TIMEOUT_SECONDS)
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "write granted", f"{collection.value}/{doc_id}", claim.run_id)
    return True


def claim_idempotency_key(
    claim: OrgClaim,
    collection: Collection,
    key: str,
    *,
    path_org_id: Optional[str] = None,
) -> bool:
    """Atomically claims a namespaced idempotency key with no accompanying
    document write. Returns True the first time a key is claimed (the
    caller should proceed) or False if it was already claimed (the caller
    should treat this as a duplicate dispatch - most likely a Pub/Sub
    redelivery - and skip its writes without erroring).

    Distinct from write()'s own `idempotency_key` parameter, which
    protects exactly one document. This exists for callers whose "did I
    already do this" guard must gate MULTIPLE writes together - e.g.
    Compliance's GDPR clock + draft pair, where redelivery must skip both
    or neither, not dedup the draft while silently re-stamping the clock's
    deadline forward on every redelivery.

    Callers should claim right before their real (post-model-call)
    writes, not before invoking the model: claiming first would make a
    coordinator-level retry-on-transient-failure (a same-request retry of
    an agent that raised, not a genuine redelivery) see its own earlier
    claim and skip, turning a retryable failure into a silent no-op that
    never actually completes the work.
    """
    target_org = path_org_id or claim.org_id
    _authorize(claim, collection, "write", target_org)
    marker_ref = (
        _client().collection("tenants").document(target_org)
        .collection("_idempotency").document(key)
    )
    try:
        marker_ref.create(
            {"run_id": claim.run_id, "at": firestore.SERVER_TIMESTAMP},
            timeout=_OP_TIMEOUT_SECONDS,
        )
    except AlreadyExists:
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
               "duplicate dispatch skipped (idempotent)",
               f"{collection.value}/_idempotency/{key}", claim.run_id)
        return False
    return True


def update_in_transaction(
    claim: OrgClaim,
    collection: Collection,
    doc_id: str,
    mutate: Callable[[Optional[dict]], dict],
    *,
    path_org_id: Optional[str] = None,
) -> dict:
    """Read-modify-write a single document atomically.

    `mutate` receives the current document (or None) and returns the
    document to store. It may be called more than once: Firestore retries
    the transaction on contention, so `mutate` must be a pure function of
    its argument and must not have side effects.

    This exists because the plain read()/write() pair is a lost-update
    race whenever two writers touch the same document concurrently, which
    is routine here - Pub/Sub delivers concurrently and Cloud Run runs
    many instances. agents/ledger/ledger.py appending to a single
    timeline document was the case that mattered: two evidence items for
    one incident could each read the same timeline, each append their own
    entry, and the second write would silently discard the first. No
    error, no log - just a missing entry in the artifact the whole
    product is built around.
    """
    target_org = path_org_id or claim.org_id
    # BOTH scopes, not just write. `mutate` is handed the current document,
    # so authorizing only the write would have turned this into a way for
    # an agent with write-but-not-read scope to see content it is denied -
    # a read-modify-write genuinely requires both, and checking only one
    # would have quietly weakened the boundary this module exists to hold.
    _authorize(claim, collection, "read", target_org)
    _authorize(claim, collection, "write", target_org)

    doc_ref = _collection_ref(target_org, collection).document(doc_id)
    client = _client()

    def _body(transaction):
        snapshot = doc_ref.get(transaction=transaction)
        current = snapshot.to_dict() if snapshot.exists else None
        updated = mutate(current)
        if collection in (Collection.TIMELINE, Collection.HYPOTHESES):
            _require_source_event_ids(collection, updated)
        transaction.set(doc_ref, updated)
        return updated

    # The in-memory test double implements run_transaction() with real
    # serialisation, so the concurrency behaviour this function exists for
    # is exercised by the unit suite rather than only in production
    # against the real backend.
    run_transaction = getattr(client, "run_transaction", None)
    if run_transaction is not None:
        result = run_transaction(_body)
    else:
        result = firestore.transactional(_body)(client.transaction())

    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "transactional write granted", f"{collection.value}/{doc_id}", claim.run_id)
    return result


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


_PLATFORM_ORG_ENV = "MORTEMTRACE_PLATFORM_ORG"


def _platform_org() -> Optional[str]:
    return os.environ.get(_PLATFORM_ORG_ENV)


def registry_put(claim: OrgClaim, agent_name: str, version: str, data: dict) -> None:
    """Publishes an agent version.

    `/registry` is deliberately global rather than tenant-scoped - agent
    definitions are platform infrastructure, shared by every tenant. That
    is the right model, but it made registry writes a cross-tenant
    privilege escalation path: _authorize() skips the tenant check for
    REGISTRY (correctly, since there is no tenant in the path), so *any*
    tenant's identity holding REGISTRY write scope could rewrite the
    scope grants governing every other tenant - for example granting
    `comms` read access to raw_evidence globally.

    When MORTEMTRACE_PLATFORM_ORG is configured, writes are restricted to
    that org. Left unset it stays permissive, which preserves existing
    single-tenant behaviour, and warns so the gap is visible.
    """
    platform_org = _platform_org()
    if platform_org is not None and claim.org_id != platform_org:
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "deny",
               f"registry write refused: {claim.org_id} is not the platform org",
               f"registry/{agent_name}/versions/{version}", claim.run_id)
        raise TenantViolation(
            f"registry writes are restricted to the platform org; {claim.org_id} is not it"
        )
    if platform_org is None:
        logger.warning(
            "%s is not set: any tenant holding registry write scope can modify agent "
            "definitions for every tenant. Set it to close this.", _PLATFORM_ORG_ENV,
        )

    _authorize(claim, Collection.REGISTRY, "write", claim.org_id)
    (
        _client().collection(_REGISTRY_ROOT).document(agent_name)
        .collection("versions").document(version)
        .set(data, timeout=_OP_TIMEOUT_SECONDS)
    )
    # Publishing must take effect immediately in the publishing process
    # rather than after the cache TTL - R4's "publish with no redeploy"
    # should not read as "publish, then wait".
    clear_scope_cache()
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "registry write granted", f"registry/{agent_name}/versions/{version}", claim.run_id)


# --------------------------------------------------------------------------
# Connectors
#
# Stored in a GLOBAL /connectors collection rather than under
# /tenants/{org}/..., for the same reason the registry is global: the only
# lookup that matters happens before the tenant is known. A webhook
# arrives carrying a connector_id in its URL and a vendor signature - not
# one of our API tokens - so the document that says which tenant it
# belongs to has to be findable without already knowing the tenant.
#
# Because the path is not tenant-scoped, _authorize()'s automatic tenant
# check does not apply, so the org check is made explicitly below. Getting
# this wrong would let one tenant register a connector into another's
# namespace.
# --------------------------------------------------------------------------

_CONNECTOR_ROOT = "connectors"


def find_connector(connector_id: str, org_hint: Optional[str] = None) -> Optional[dict]:
    """Unauthenticated read of one connector document.

    Deliberately unauthenticated - see the section comment above for the
    chicken-and-egg that forces it. This read establishes only *which*
    signature to verify; connectors/verification.py is what actually
    authorises the request, and the connector_id is unguessable.
    """
    doc = (
        _client().collection(_CONNECTOR_ROOT).document(connector_id)
        .get(timeout=_OP_TIMEOUT_SECONDS)
    )
    if not doc.exists:
        return None
    data = doc.to_dict() or {}
    if org_hint is not None and data.get("org_id") != org_hint:
        return None
    return data


def connector_put(claim: OrgClaim, connector_id: str, data: dict) -> None:
    """Registers or updates a connector. Scope-enforced, plus an explicit
    tenant check the global path would otherwise skip."""
    _authorize(claim, Collection.CONNECTORS, "write", claim.org_id)
    if data.get("org_id") != claim.org_id:
        _audit(claim.org_id, claim.agent_name, claim.agent_version, "deny",
               f"connector write refused: document org {data.get('org_id')!r} "
               f"does not match claim org {claim.org_id!r}",
               f"connectors/{connector_id}", claim.run_id)
        raise TenantViolation("connector org_id does not match the claim")

    (
        _client().collection(_CONNECTOR_ROOT).document(connector_id)
        .set(data, timeout=_OP_TIMEOUT_SECONDS)
    )
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           "connector write granted", f"connectors/{connector_id}", claim.run_id)


def connector_list(claim: OrgClaim) -> list[dict]:
    """Every connector belonging to the claim's tenant."""
    _authorize(claim, Collection.CONNECTORS, "read", claim.org_id)
    docs = (
        _client().collection(_CONNECTOR_ROOT)
        .where(filter=FieldFilter("org_id", "==", claim.org_id))
        .stream(timeout=_OP_TIMEOUT_SECONDS)
    )
    result = [d.to_dict() for d in docs]
    _audit(claim.org_id, claim.agent_name, claim.agent_version, "allow",
           f"connector list granted ({len(result)})", "connectors/*", claim.run_id)
    return result


def bootstrap_connector_write(connector_id: str, data: dict) -> None:
    """Unauthenticated connector registration, for infra scripts only -
    same rule and same reasoning as bootstrap_write below."""
    _client().collection(_CONNECTOR_ROOT).document(connector_id).set(data)


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


# --------------------------------------------------------------------------
# Human identity / organizations / memberships / invitations
#
# A separate trust model from the OrgClaim system above. OrgClaim answers
# "may this AGENT touch this TENANT's incident data"; the functions below
# answer "which org(s) does this AUTHENTICATED HUMAN belong to, and what
# may they administer there" - a question the agent-scope system has no
# concept of at all.
#
# No OrgClaim is threaded through these functions, and none can be: a
# brand-new user creating their first organization has no tenant
# membership yet to mint one from. This is the same structural
# chicken-and-egg /registry and /connectors already solve by living in
# their own global collections with authorization enforced explicitly in
# each function, rather than relying on _authorize()'s automatic tenant
# match. Every caller here has already had its identity verified by
# auth/ (a signature-checked OIDC ID token) before scope_store is ever
# reached; nothing here trusts a client-supplied value on its own -
# `acting_user_id` on a mutating call is re-checked against a live
# Membership row inside the function, never assumed from the caller.
# --------------------------------------------------------------------------

_ORGANIZATIONS_ROOT = "organizations"
_USERS_ROOT = "users"
_MEMBERSHIPS_ROOT = "memberships"
_INVITATIONS_ROOT = "invitations"

_INVITATION_TTL = timedelta(days=14)


class PermissionDenied(Exception):
    """The acting user is authenticated but lacks the role required for
    this action (e.g. a member trying to invite someone). HTTP 403."""


def _membership_id(user_id: str, org_id: str) -> str:
    return f"{user_id}__{org_id}"


def get_organization(org_id: str) -> Optional[dict]:
    doc = _client().collection(_ORGANIZATIONS_ROOT).document(org_id).get(timeout=_OP_TIMEOUT_SECONDS)
    return doc.to_dict() if doc.exists else None


def create_organization(display_name: str, created_by_user_id: str) -> dict:
    """Creates a brand-new organization with `created_by_user_id` as its
    founding admin. Atomic: the org document and the admin membership are
    the same transaction, so a crash between the two can never leave an
    organization with zero members able to administer it."""
    org_id = new_id("org")
    org = Organization(org_id=org_id, display_name=display_name, created_by=created_by_user_id)
    membership = Membership(
        membership_id=_membership_id(created_by_user_id, org_id),
        user_id=created_by_user_id, org_id=org_id, role="admin",
    )

    client = _client()

    def _body(transaction):
        transaction.set(
            client.collection(_ORGANIZATIONS_ROOT).document(org_id),
            org.model_dump(mode="json"),
        )
        transaction.set(
            client.collection(_MEMBERSHIPS_ROOT).document(membership.membership_id),
            membership.model_dump(mode="json"),
        )

    run_transaction = getattr(client, "run_transaction", None)
    if run_transaction is not None:
        run_transaction(_body)
    else:
        firestore.transactional(_body)(client.transaction())

    logger.info("organization %s (%r) created by %s", org_id, display_name, created_by_user_id)
    return org.model_dump(mode="json")


def get_user(user_id: str) -> Optional[dict]:
    doc = _client().collection(_USERS_ROOT).document(user_id).get(timeout=_OP_TIMEOUT_SECONDS)
    return doc.to_dict() if doc.exists else None


def upsert_user(user_id: str, *, email: str, display_name: str) -> dict:
    """Creates or refreshes a user's profile. Called after every
    successful OIDC login - `last_login_at` is what an admin's member
    list shows to distinguish an active teammate from one who was invited
    and never signed in."""
    existing = get_user(user_id)
    user = User(
        user_id=user_id, email=email, display_name=display_name,
        created_at=existing["created_at"] if existing else now(),
        last_login_at=now(),
    )
    document = user.model_dump(mode="json")
    _client().collection(_USERS_ROOT).document(user_id).set(document, timeout=_OP_TIMEOUT_SECONDS)
    return document


def get_membership(user_id: str, org_id: str) -> Optional[dict]:
    doc = (
        _client().collection(_MEMBERSHIPS_ROOT).document(_membership_id(user_id, org_id))
        .get(timeout=_OP_TIMEOUT_SECONDS)
    )
    data = doc.to_dict() if doc.exists else None
    return data if data and data.get("status") == "active" else None


def get_membership_any_status(user_id: str, org_id: str) -> Optional[dict]:
    """Like get_membership, but returns a revoked row too instead of
    treating it as absent.

    Exists specifically for the auto-join call sites in
    auth/provisioning.py: they need to tell "never a member" (auto-join
    is correct) apart from "was a member, an admin revoked them" (auto-
    join must NOT silently undo that decision). get_membership()
    deliberately can't make that distinction - collapsing revoked to
    None is exactly right for every other caller, which only ever wants
    to know "may this person act right now."
    """
    doc = (
        _client().collection(_MEMBERSHIPS_ROOT).document(_membership_id(user_id, org_id))
        .get(timeout=_OP_TIMEOUT_SECONDS)
    )
    return doc.to_dict() if doc.exists else None


def list_memberships_for_user(user_id: str) -> list[dict]:
    """Every org this user may act as - what the login/org-switcher flow
    resolves a session down to. Excludes revoked rows: deprovisioning
    takes effect on this user's very next request, since nothing caches
    membership across requests the way the (much more static) agent
    registry scope cache does."""
    docs = (
        _client().collection(_MEMBERSHIPS_ROOT)
        .where(filter=FieldFilter("user_id", "==", user_id))
        .where(filter=FieldFilter("status", "==", "active"))
        .stream(timeout=_OP_TIMEOUT_SECONDS)
    )
    return [d.to_dict() for d in docs]


def list_memberships_for_org(org_id: str) -> list[dict]:
    """An admin's "members" view. Includes revoked rows so the page can
    show who used to have access, not just who currently does."""
    docs = (
        _client().collection(_MEMBERSHIPS_ROOT)
        .where(filter=FieldFilter("org_id", "==", org_id))
        .stream(timeout=_OP_TIMEOUT_SECONDS)
    )
    return [d.to_dict() for d in docs]


def _require_admin(acting_user_id: str, org_id: str) -> None:
    membership = get_membership(acting_user_id, org_id)
    if membership is None or membership.get("role") != "admin":
        raise PermissionDenied(f"{acting_user_id} is not an admin of {org_id}")


class LastAdminError(Exception):
    """Refused: this would leave org_id with zero active admins. Not a
    security check - a lockout guard. Nobody gains unauthorized access
    by this being refused; the org would simply become unadministerable
    by anyone, including whoever just tried."""


def _count_active_admins(org_id: str) -> int:
    return sum(
        1 for m in list_memberships_for_org(org_id)
        if m.get("status") == "active" and m.get("role") == "admin"
    )


def create_membership(user_id: str, org_id: str, role: str, *, invited_by: Optional[str] = None) -> dict:
    """Grants org_id/role to user_id directly - used for domain-based and
    demo auto-join, where the "invitation" is the organization's own
    configuration rather than a per-person Invitation record. Idempotent:
    re-running (e.g. the same person logging in twice before any explicit
    revoke) overwrites with the same values rather than erroring."""
    membership = Membership(
        membership_id=_membership_id(user_id, org_id),
        user_id=user_id, org_id=org_id, role=role, invited_by=invited_by,
    )
    document = membership.model_dump(mode="json")
    _client().collection(_MEMBERSHIPS_ROOT).document(membership.membership_id).set(
        document, timeout=_OP_TIMEOUT_SECONDS,
    )
    return document


def _last_admin_guarded_update(
    org_id: str, membership_id: str, target_user_id: str,
    mutate: Callable[[dict, int], dict],
) -> dict:
    """Reads the target membership and re-counts org_id's active admins
    inside ONE Firestore transaction, then applies `mutate` and writes the
    result - all atomically.

    Closes a TOCTOU window that plain get() -> _count_active_admins() ->
    set() left open: with exactly two active admins, two concurrent
    revoke/demote requests could each read the count as 2, each pass the
    "would leave more than zero" check, and both commit - leaving the org
    with zero admins despite the guard existing specifically to prevent
    that. update_in_transaction() closes the identical class of lost-
    update race for tenant-scoped documents (see agents/ledger/ledger.py);
    membership documents live outside any tenant path, at
    _MEMBERSHIPS_ROOT, so that helper's Collection-based addressing does
    not apply here and this is its own small transactional counterpart.
    """
    client = _client()
    doc_ref = client.collection(_MEMBERSHIPS_ROOT).document(membership_id)

    def _body(transaction):
        snap = doc_ref.get(transaction=transaction, timeout=_OP_TIMEOUT_SECONDS)
        if not snap.exists:
            raise ValueError(f"no such membership: {target_user_id} in {org_id}")
        data = snap.to_dict()
        admins = (
            client.collection(_MEMBERSHIPS_ROOT)
            .where(filter=FieldFilter("org_id", "==", org_id))
            .where(filter=FieldFilter("status", "==", "active"))
            .where(filter=FieldFilter("role", "==", "admin"))
            .stream(transaction=transaction, timeout=_OP_TIMEOUT_SECONDS)
        )
        active_admin_count = sum(1 for _ in admins)
        updated = mutate(data, active_admin_count)
        transaction.set(doc_ref, updated)
        return updated

    run_transaction = getattr(client, "run_transaction", None)
    if run_transaction is not None:
        return run_transaction(_body)
    return firestore.transactional(_body)(client.transaction())


def update_membership_role(acting_user_id: str, org_id: str, target_user_id: str, role: str) -> dict:
    """Admin-only. Re-checks the acting user's role against a live
    Membership row rather than trusting the caller's session claims -
    the same "the data layer decides, never the caller" rule
    _resolve_scopes already applies to agent scopes.

    Refuses (LastAdminError) a demotion that would leave zero active
    admins - not a security boundary, a lockout guard: past this point
    nobody, including the person who just did it, could administer the
    org at all."""
    _require_admin(acting_user_id, org_id)
    membership_id = _membership_id(target_user_id, org_id)

    def _mutate(data: dict, active_admin_count: int) -> dict:
        if data.get("role") == "admin" and role != "admin" and active_admin_count <= 1:
            raise LastAdminError(f"{org_id} would have zero admins left")
        data["role"] = role
        return data

    return _last_admin_guarded_update(org_id, membership_id, target_user_id, _mutate)


def revoke_membership(acting_user_id: str, org_id: str, target_user_id: str) -> None:
    """Admin-only. Sets status=revoked rather than deleting: the record
    of who used to have access, and who removed them, is itself an
    audit-relevant fact. Same last-admin guard as update_membership_role."""
    _require_admin(acting_user_id, org_id)
    membership_id = _membership_id(target_user_id, org_id)

    def _mutate(data: dict, active_admin_count: int) -> dict:
        if data.get("role") == "admin" and data.get("status") == "active" and active_admin_count <= 1:
            raise LastAdminError(f"{org_id} would have zero admins left")
        data["status"] = "revoked"
        return data

    _last_admin_guarded_update(org_id, membership_id, target_user_id, _mutate)


def create_invitation(acting_user_id: str, org_id: str, email: str, role: str) -> tuple[dict, str]:
    """Admin-only. Returns (invitation document, raw token) - the raw
    token is shown exactly once by the caller and only its digest is
    persisted, the same pattern infra/mint_token.py uses for API tokens.
    There is no email-sending integration in this deployment, so the
    admin shares the resulting link manually (Slack, email client) rather
    than one being sent server-side."""
    _require_admin(acting_user_id, org_id)
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    invitation = Invitation(
        invitation_id=new_id("inv"), org_id=org_id, email=email.strip().lower(),
        role=role, invited_by=acting_user_id, token_hash=token_hash,
        expires_at=now() + _INVITATION_TTL,
    )
    document = invitation.model_dump(mode="json")
    _client().collection(_INVITATIONS_ROOT).document(invitation.invitation_id).set(
        document, timeout=_OP_TIMEOUT_SECONDS,
    )
    return document, token


def find_invitation_by_token(token: str) -> Optional[dict]:
    """Constant-time-ish lookup over pending invitations, mirroring
    auth/identity.py's API-token lookup: compares every candidate with
    compare_digest rather than a plain dict-get on the digest, so the
    match itself is not a timing oracle. Invitations are created rarely
    enough that scanning all pending ones costs nothing meaningful."""
    presented = hashlib.sha256(token.encode("utf-8")).hexdigest()
    docs = (
        _client().collection(_INVITATIONS_ROOT)
        .where(filter=FieldFilter("status", "==", "pending"))
        .stream(timeout=_OP_TIMEOUT_SECONDS)
    )
    for doc in docs:
        data = doc.to_dict()
        if hmac.compare_digest(str(data.get("token_hash", "")), presented):
            expires_at = data.get("expires_at")
            if isinstance(expires_at, str):
                expires_at = datetime.fromisoformat(expires_at)
            if expires_at is not None and expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            if expires_at is not None and now() > expires_at:
                return None
            return data
    return None


def redeem_invitation(invitation_id: str, redeeming_user_id: str) -> dict:
    """Atomically marks one invitation redeemed and creates the
    membership it grants. Transactional so two near-simultaneous redeem
    attempts (a double click, or two tabs) cannot both succeed - the
    second observes status != "pending" inside the same transaction and
    is rejected rather than silently creating a duplicate membership."""
    client = _client()
    invitation_ref = client.collection(_INVITATIONS_ROOT).document(invitation_id)

    def _body(transaction):
        snap = invitation_ref.get(transaction=transaction)
        if not snap.exists:
            raise ValueError("no such invitation")
        data = snap.to_dict()
        if data.get("status") != "pending":
            raise ValueError(f"invitation is {data.get('status')}, not pending")

        membership = Membership(
            membership_id=_membership_id(redeeming_user_id, data["org_id"]),
            user_id=redeeming_user_id, org_id=data["org_id"],
            role=data["role"], invited_by=data["invited_by"],
        )
        transaction.set(
            client.collection(_MEMBERSHIPS_ROOT).document(membership.membership_id),
            membership.model_dump(mode="json"),
        )
        data["status"] = "redeemed"
        transaction.set(invitation_ref, data)
        return membership.model_dump(mode="json")

    run_transaction = getattr(client, "run_transaction", None)
    if run_transaction is not None:
        return run_transaction(_body)
    return firestore.transactional(_body)(client.transaction())


def set_organization_sso(acting_user_id: str, org_id: str, sso: Optional[dict]) -> dict:
    """Admin-only. `sso=None` clears the org's SSO configuration, falling
    every member back to the Google sign-in path."""
    _require_admin(acting_user_id, org_id)
    org_ref = _client().collection(_ORGANIZATIONS_ROOT).document(org_id)
    snap = org_ref.get(timeout=_OP_TIMEOUT_SECONDS)
    if not snap.exists:
        raise ValueError(f"no such organization: {org_id}")
    data = snap.to_dict()
    data["sso"] = sso
    org_ref.set(data, timeout=_OP_TIMEOUT_SECONDS)
    return data


def find_organization_by_domain(email_domain: str) -> Optional[dict]:
    """Home Realm Discovery: which org (if any) has `email_domain` in its
    verified auto-join list. Used both to route a login to that org's own
    IdP (when sso.domain_hint matches) and, after any successful login,
    to auto-join a first-time user whose email domain matches.

    A full collection scan, not a query: Firestore has no
    array-contains-with-arbitrary-string-match, and `auto_join_domains`
    lists are short and organizations are not high-cardinality at this
    scale. Revisit with a denormalized `domain -> org_id` lookup
    collection if that stops being true.
    """
    domain = email_domain.strip().lower()
    for doc in _client().collection(_ORGANIZATIONS_ROOT).stream(timeout=_OP_TIMEOUT_SECONDS):
        data = doc.to_dict() or {}
        if domain in [d.lower() for d in data.get("auto_join_domains", [])]:
            return data
    return None


def find_organization_by_sso_domain_hint(email_domain: str) -> Optional[dict]:
    """Home Realm Discovery's OTHER half: which org's *own IdP* an email
    domain should be routed to, distinct from find_organization_by_domain
    above. The two are deliberately separate fields, not one: an org can
    set auto_join_domains with no sso configured at all (its employees
    just use the Google fallback, and still auto-join as members), so
    "should this email auto-join" and "which non-Google IdP should this
    email be redirected to" are genuinely different questions that happen
    to often (not always) share the same domain string.
    """
    domain = email_domain.strip().lower()
    for doc in _client().collection(_ORGANIZATIONS_ROOT).stream(timeout=_OP_TIMEOUT_SECONDS):
        data = doc.to_dict() or {}
        sso = data.get("sso") or {}
        if sso.get("domain_hint", "").lower() == domain:
            return data
    return None


def find_public_demo_organization() -> Optional[dict]:
    """The one organization (if any) flagged public_demo_auto_join. Used
    only by the explicit "view live demo" entry point - never consulted
    during an ordinary login, so an org configuring this can never be
    stumbled into by accident."""
    docs = (
        _client().collection(_ORGANIZATIONS_ROOT)
        .where(filter=FieldFilter("public_demo_auto_join", "==", True))
        .limit(1)
        .stream(timeout=_OP_TIMEOUT_SECONDS)
    )
    for doc in docs:
        return doc.to_dict()
    return None


def bootstrap_organization_write(org_id: str, data: dict) -> None:
    """Unauthenticated write for seeding the demo organization itself.
    infra/seed_data.py only, same rule as bootstrap_write."""
    _client().collection(_ORGANIZATIONS_ROOT).document(org_id).set(data)
