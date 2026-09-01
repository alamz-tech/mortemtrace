"""R1/R2's actual entry point.

A single POST endpoint that validates input minimally, writes one
RawEvidence doc, resolves/creates the parent Incident, publishes one
evidence.received message, and returns within the 500ms budget. All real
extraction/reasoning happens downstream (Intake, via Coordinator) -
this module never imports Vertex/Gemini and never reasons about
incident content itself.

Identity: the caller is authenticated first (auth/identity.py), and the
tenant is taken from the resulting Principal - never from the request
body. Only then is an "ingest-api" claim minted via
scope_store.sign_claim() for that verified tenant. The claim signature
gives integrity to the org_id; authentication is what establishes that
the caller was entitled to that org_id in the first place. Before the
two were separated, `org_id` was an unauthenticated form field that the
server dutifully signed, so any caller could write into any tenant.

    ingest-api @ 1.0.0 needs:
        write_scopes: [Collection.INCIDENTS, Collection.RAW_EVIDENCE]
        read_scopes:  [] (ingest never reads incident state back)

Dispatch: set MORTEMTRACE_SYNC_DISPATCH=1 to run the whole pipeline
in-process (local dev / a quick manual test - never the deployed
service: it makes /ingest block on the full agent cascade, which
directly violates R2's "under 500ms... never in the request path").
Leave it unset in production, which publishes to real Pub/Sub instead -
POST /pubsub/push/{event_type} below is where each of those hops
actually lands, one HTTP request per message, which is what makes
"never in the request path" true rather than aspirational.
"""
from __future__ import annotations

import asyncio
import base64
import concurrent.futures
import json
import logging
import os
import re
import threading
from typing import Optional

from fastapi import Body, FastAPI, File, Form, Header, HTTPException, Request, UploadFile
from google.cloud import pubsub_v1

from agents import wiring
from agents.coordinator import coordinator
from auth import identity
from connectors import registry as connector_registry
from connectors import verification
from data import scope_store
from data.models import (
    Collection,
    Envelope,
    EvidenceKind,
    EvidenceReceived,
    Incident,
    RawEvidence,
    new_id,
    now,
)
from telemetry import otel_setup

_WATCHER_SWEEP_TOPIC = "watcher.sweep"

logger = logging.getLogger("mortemtrace.api.ingest")

INGEST_AGENT_NAME = "ingest-api"
INGEST_AGENT_VERSION = "1.0.0"

_EVIDENCE_RECEIVED_TOPIC = "evidence.received"
_SYNC_DISPATCH_ENV = "MORTEMTRACE_SYNC_DISPATCH"
_PUSH_AUDIENCE_ENV = "MORTEMTRACE_PUSH_AUDIENCE"

# Small images only: base64-encoded straight into RawEvidence.payload as a
# data: URI. A real deployment would stream the upload to Cloud Storage
# and store a media_uri instead; base64-into-payload is a deliberate
# hackathon-scope shortcut, not an oversight - it keeps ingest.py free of
# a second infra dependency (bucket provisioning, signed URLs) for a P0
# endpoint that must respond in under 500ms.
#
# The ceiling is derived from Firestore's hard 1 MiB document limit, not
# picked: base64 inflates by 4/3, and the surrounding RawEvidence fields
# and the "data:<mime>;base64," prefix also count against the same limit.
# This previously truncated at 5 MB, which silently guaranteed failure -
# a 5 MB file becomes ~7 MB of base64, ~6.7x over the limit, so every
# upload above ~768 KB (a normal dashboard screenshot) produced an opaque
# 500 from the Firestore write. Oversized uploads are now rejected at the
# boundary with a 413 that says the actual limit, instead of truncating
# into a payload that cannot be stored.
_FIRESTORE_MAX_DOC_BYTES = 1_048_576
_DOC_OVERHEAD_BYTES = 4096  # other RawEvidence fields + data: URI prefix + Firestore field overhead
_MAX_INLINE_FILE_BYTES = ((_FIRESTORE_MAX_DOC_BYTES - _DOC_OVERHEAD_BYTES) * 3) // 4

# Same reasoning for the text path: a pasted log body is stored in the
# same single Firestore field and is just as capable of exceeding 1 MiB.
_MAX_TEXT_PAYLOAD_BYTES = _FIRESTORE_MAX_DOC_BYTES - _DOC_OVERHEAD_BYTES

otel_setup.init_telemetry("mortemtrace-ingest-api")
otel_setup.configure_logging("mortemtrace-ingest-api")
identity.enforce_production_secrets()
identity.warn_if_open()
wiring.register_all()

app = FastAPI(title="MortemTrace Ingest API")

_INGEST_LIMITER = identity.build_ingest_limiter()
# Webhooks come from machines, not people, so a legitimate source can
# burst far higher than an operator would - but it still fans out into
# paid model calls, so it is bounded rather than unlimited.
_WEBHOOK_LIMITER = identity.build_webhook_limiter()
_PRE_LOOKUP_WEBHOOK_LIMITER = identity.build_pre_auth_limiter()


def _authenticate(authorization: Optional[str], requested_org: Optional[str]) -> str:
    """Authenticate, then resolve the tenant. Returns the org_id this
    request is entitled to act as, which is the only org_id anything
    downstream is allowed to see."""
    try:
        principal = identity.authenticate(authorization)
        org_id = principal.authorize_org(requested_org)
    except identity.AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except identity.AuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except identity.InvalidOrgId as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        _INGEST_LIMITER.check(org_id)
    except identity.RateLimitExceeded as exc:
        # Ingest fans out into a chain of paid model calls, so an
        # unbounded caller is a cost-exhaustion vector, not just a load one.
        raise HTTPException(status_code=429, detail=str(exc)) from exc
    return org_id


# A caller-supplied incident_id is written straight into a Firestore
# document path, so it needs the same slash/charset guard as org_id -
# Firestore reads "a/b" as two path segments, which silently re-points
# the write rather than failing loudly.
_INCIDENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


def _validate_incident_id(incident_id: str) -> str:
    if not _INCIDENT_ID_RE.match(incident_id):
        raise HTTPException(status_code=400, detail=f"invalid incident_id: {incident_id!r}")
    return incident_id


# --------------------------------------------------------------------------
# Dispatch: real Pub/Sub, or synchronous in-process fallback for local/test
# --------------------------------------------------------------------------

def _sync_dispatch_enabled() -> bool:
    return os.environ.get(_SYNC_DISPATCH_ENV) == "1"


def _publish(topic: str, payload: dict) -> None:
    """The single publish path for every hop in the chain, not just the
    first one: this is the exact `publish=` callback Coordinator.route()
    invokes for *every* worker's declared next_events, at every hop, so
    branching here on sync-dispatch mode is what makes
    MORTEMTRACE_SYNC_DISPATCH=1 actually run the whole ingest-to-drafts
    pipeline in-process rather than only its first hop. Without this
    branch here specifically, ingest->Intake would run synchronously but
    Intake's own evidence.staged (and everything after it) would still
    need a real Pub/Sub subscriber that, per the architecture, nobody
    has deployed yet - "whole pipeline in-process" would be true only
    for one hop.
    """
    if _sync_dispatch_enabled():
        _route_sync(topic, payload)
    else:
        _publish_pubsub(topic, payload)


def _route_sync(topic: str, payload: dict) -> None:
    """Reconstructs an Envelope from a published payload and dispatches
    it through Coordinator immediately, recursing into `_publish` again
    for whatever *that* hop declares next - this is the cascade. The
    claim minted here is a required Envelope field Coordinator never
    actually reads (it mints its own coordinator/guardian/worker claims
    internally for every real read or write), so reusing the ingest
    identity for it is fine at every hop, not just the first."""
    run_id = payload.get("run_id")
    org_id = payload.get("org_id")
    if not run_id or not org_id:
        logger.warning(
            "sync dispatch: payload for topic=%s missing run_id/org_id, dropping: %r", topic, payload,
        )
        return
    incident_id = payload.get("incident_id") or payload.get("incident_ref")
    claim = _ingest_claim(org_id, run_id)
    envelope = Envelope(
        run_id=run_id, org_id=org_id, incident_id=incident_id, claim=claim,
        event_type=topic, payload=payload,
    )
    coordinator.route(topic, envelope, publish=_publish)


_PUBSUB_CLIENT: Optional[pubsub_v1.PublisherClient] = None
_PUBSUB_CLIENT_LOCK = threading.Lock()

# Reused, not built per request: a ThreadPoolExecutor spins up its worker
# threads on construction, so creating and joining a fresh one on every
# new-incident /ingest call added real per-request overhead this file
# already went to some trouble to eliminate elsewhere (see
# _pubsub_client's own docstring on caching the gRPC client instead of
# rebuilding it per call). max_workers=2 matches the two tasks actually
# submitted below (_write_incident, _write_raw_evidence); a shared pool
# this small easily keeps up since each task holds a worker only for one
# Firestore write.
_INGEST_WRITE_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="ingest-write")


def _pubsub_client() -> pubsub_v1.PublisherClient:
    """Cached, not constructed per call. This used to be a fresh
    PublisherClient (a fresh gRPC channel plus a fresh credential/token
    exchange) on every single publish - defensible when this path
    "wasn't on the demo's critical path" under MORTEMTRACE_SYNC_DISPATCH,
    genuinely wrong now that it's the real production dispatch path for
    every hop. Caching the client is what an instance's stateless-NFR
    exemption for "the telemetry/gateway singletons that already exist"
    was always meant to cover - a connection/credential cache is not
    per-incident state, the same way data/scope_store.py's own cached
    Firestore client isn't."""
    global _PUBSUB_CLIENT
    if _PUBSUB_CLIENT is None:
        with _PUBSUB_CLIENT_LOCK:
            if _PUBSUB_CLIENT is None:
                _PUBSUB_CLIENT = pubsub_v1.PublisherClient()
    return _PUBSUB_CLIENT


def _publish_pubsub(topic: str, payload: dict) -> None:
    """Real Pub/Sub publish. Project comes from GOOGLE_CLOUD_PROJECT;
    topic path is projects/{project}/topics/{topic}.

    Does not block on the publish Future's result(): the client library
    confirms delivery asynchronously in its own background thread, and
    waiting for that confirmation synchronously here was real,
    measurable latency on /ingest's critical path for zero benefit the
    caller can act on (the HTTP response only ever returns run_id/
    incident_id regardless of whether the publish confirmation has
    landed yet). A failure is still observable - the done-callback logs
    it - rather than silently discarded; it just doesn't block the
    request that triggered it."""
    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        logger.warning(
            "GOOGLE_CLOUD_PROJECT not set; dropping publish to topic=%s payload=%r",
            topic, payload,
        )
        return
    client = _pubsub_client()
    topic_path = client.topic_path(project, topic)
    data = json.dumps(payload, default=str).encode("utf-8")

    # W3C trace context travels as message attributes so the whole
    # ingest-to-drafts chain is one trace. Without this, each Pub/Sub hop
    # started a fresh root span and a single incident appeared in Cloud
    # Trace as five unrelated traces - R10's "one trace for the chain"
    # was unachievable no matter how consistent the span attributes were.
    attributes = otel_setup.inject_trace_context({})
    future = client.publish(topic_path, data, **attributes)
    future.add_done_callback(lambda f: _log_publish_failure(f, topic))


def _log_publish_failure(future, topic: str) -> None:
    exc = future.exception()
    if exc is not None:
        logger.error("Pub/Sub publish to topic=%s failed after the request already returned: %s", topic, exc)


def _dispatch_evidence_received(envelope: Envelope) -> None:
    """Entry point for the very first hop. Delegates to the same
    `_publish` path every later hop uses, so all of them - including
    this one - share one sync-vs-real-Pub/Sub decision point."""
    _publish(_EVIDENCE_RECEIVED_TOPIC, envelope.payload)


def _ingest_claim(org_id: str, run_id: str):
    return scope_store.sign_claim(
        org_id=org_id, agent_name=INGEST_AGENT_NAME, agent_version=INGEST_AGENT_VERSION, run_id=run_id,
    )


async def _resolve_payload(payload: Optional[str], file: Optional[UploadFile]) -> str:
    """Returns the text to store in RawEvidence.payload. Exactly one of
    `payload` (alert JSON / pasted logs / Slack text) or `file` (a
    dashboard screenshot) is expected per the request; a screenshot is
    base64-encoded directly into `payload` as a data: URI rather than
    written to Cloud Storage - see the module docstring.

    Raises HTTPException(413) rather than truncating: a truncated
    screenshot is both unusable evidence and, above ~768 KB, still too
    large for Firestore once base64-encoded, so truncation traded a clear
    4xx for an opaque 500.
    """
    if file is not None:
        raw = await file.read()
        if len(raw) > _MAX_INLINE_FILE_BYTES:
            raise HTTPException(
                status_code=413,
                detail=(
                    f"file is {len(raw)} bytes; the maximum is {_MAX_INLINE_FILE_BYTES} "
                    f"bytes (~{_MAX_INLINE_FILE_BYTES // 1024} KB) because evidence is "
                    "stored base64-encoded inside a single Firestore document (1 MiB limit)"
                ),
            )
        encoded = base64.b64encode(raw).decode("ascii")
        content_type = file.content_type or "application/octet-stream"
        return f"data:{content_type};base64,{encoded}"

    text = payload or ""
    encoded_len = len(text.encode("utf-8"))
    if encoded_len > _MAX_TEXT_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=(
                f"payload is {encoded_len} bytes; the maximum is "
                f"{_MAX_TEXT_PAYLOAD_BYTES} bytes (Firestore 1 MiB document limit)"
            ),
        )
    return text


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/status")
def status() -> dict:
    """Not /healthz: confirmed live (2026-08-31) that Google's own edge
    infrastructure intercepts that exact path ahead of Cloud Run, so a
    route there is silently unreachable regardless of what it returns -
    see console/ui.py's matching route for the full explanation."""
    return {"status": "ok"}


def _handle_ingest(org_id: str, kind: EvidenceKind, incident_id: Optional[str], body_text: str) -> dict:
    """The actual blocking work: Firestore writes and a Pub/Sub publish,
    all synchronous SDK calls. Split out from the async route below and
    run via asyncio.to_thread so it can't block FastAPI's event loop -
    an async def route that calls blocking I/O directly blocks every
    other concurrent request on the same worker/instance for its
    duration, which is exactly the kind of thing that reads as "under
    500ms in isolation" and falls over under any real concurrent load
    (a demo request landing alongside a Cloud Scheduler sweep, for
    instance). Caught by timing concurrent requests live, not by any
    unit test - the TestClient in tests/test_ingest.py runs everything
    synchronously and has no concurrency to expose this."""
    run_id = new_id("run")
    with otel_setup.span("mortemtrace.api", "ingest", run_id=run_id, org_id=org_id, incident_id=incident_id) as current_span:
        claim = _ingest_claim(org_id, run_id)

        # incident_id is generated up front (not read back from a write
        # result) specifically so the Incident write, when needed, and the
        # RawEvidence write can run concurrently instead of sequentially -
        # they're independent documents in independent collections, and
        # RawEvidence only needs incident_id as a *value* to reference, not
        # as proof the Incident write already landed. This is the second
        # half of closing the gap on R2's <500ms: caching clients and
        # moving off the event loop got a live request from 60+s to ~1-2s,
        # and two sequential Firestore round-trips were the rest of it.
        creating_incident = incident_id is None
        if creating_incident:
            incident_id = new_id("inc")
        current_span.set_attribute("mortemtrace.incident_id", incident_id)

        raw_evidence = RawEvidence(
            event_id=new_id("eventraw"), org_id=org_id, incident_ref=incident_id,
            kind=kind, payload=body_text, received_at=now(),
        )

        def _write_incident() -> None:
            incident = Incident(incident_id=incident_id, org_id=org_id, opened_at=now(), status="open")
            scope_store.write(claim, Collection.INCIDENTS, incident.incident_id, incident.model_dump(mode="json"))

        def _write_raw_evidence() -> None:
            scope_store.write(
                claim, Collection.RAW_EVIDENCE, raw_evidence.event_id, raw_evidence.model_dump(mode="json"),
            )

        # else (not creating_incident): reuse the given incident_id as-is,
        # only the RawEvidence write happens. Deliberately no synchronous
        # existence check on a caller-supplied incident_id - staying under
        # budget matters more than validating it before handing off to Intake.
        if creating_incident:
            futures = [
                _INGEST_WRITE_POOL.submit(_write_incident),
                _INGEST_WRITE_POOL.submit(_write_raw_evidence),
            ]
            for future in futures:
                future.result()
        else:
            _write_raw_evidence()

        evidence_received = EvidenceReceived(
            run_id=claim.run_id, org_id=org_id, incident_ref=incident_id,
            raw_evidence_id=raw_evidence.event_id, kind=kind, received_at=raw_evidence.received_at,
        )
        envelope = Envelope(
            run_id=claim.run_id, org_id=org_id, incident_id=incident_id, claim=claim,
            event_type=_EVIDENCE_RECEIVED_TOPIC, payload=evidence_received.model_dump(mode="json"),
        )
        _dispatch_evidence_received(envelope)

        return {"run_id": claim.run_id, "incident_id": incident_id}


@app.post("/ingest")
async def ingest(
    kind: EvidenceKind = Form(...),
    org_id: Optional[str] = Form(None),
    incident_id: Optional[str] = Form(None),
    payload: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
    authorization: Optional[str] = Header(None),
):
    """`org_id` is now optional and, when supplied, may only *select*
    among tenants the presented credential already grants - it can never
    introduce one. A single-tenant credential resolves it implicitly."""
    resolved_org = _authenticate(authorization, org_id)
    if incident_id is not None:
        _validate_incident_id(incident_id)
    body_text = await _resolve_payload(payload, file)
    return await asyncio.to_thread(_handle_ingest, resolved_org, kind, incident_id, body_text)


def _handle_webhook(config, payload: dict) -> dict:
    """Blocking work for one inbound webhook, off the event loop.

    Two destinations, chosen by the connector's own configuration:

    * A change source (GitHub Actions, Jenkins, Terraform) writes a
      ChangeEvent. It does not open an incident - a deploy is not an
      outage - but it becomes correlatable history for whichever incident
      opens next.
    * Everything else becomes RawEvidence and enters the normal
      Intake -> Ledger -> fan-out pipeline, exactly as a /ingest call
      would. No vendor-specific parsing: the payload is summarised into
      evidence text and Intake extracts meaning from it, which is the
      whole reason this receiver does not need an adapter per tool.
    """
    org_id = config.org_id
    run_id = new_id("run")
    claim = _ingest_claim(org_id, run_id)

    if config.is_change_source:
        change = connector_registry.to_change_event(config, payload)
        scope_store.write(
            claim, Collection.CHANGE_EVENTS, change.change_id, change.model_dump(mode="json"),
        )
        otel_setup.record_metric(
            "change_event_received", source=config.source, org_id=org_id, run_id=run_id,
        )
        logger.info(
            "change event %s recorded from %s", change.change_id, config.source,
            extra={"run_id": run_id, "org_id": org_id},
        )
        return {"status": "recorded", "change_id": change.change_id, "kind": change.kind}

    body_text = connector_registry.summarize(config.source, payload, limit=_MAX_TEXT_PAYLOAD_BYTES)
    result = _handle_ingest(org_id, config.kind, None, body_text)
    otel_setup.record_metric(
        "webhook_ingested", source=config.source, org_id=org_id, run_id=result["run_id"],
    )
    return result


@app.post("/webhook/{connector_id}")
async def webhook(connector_id: str, request: Request):
    """The universal inbound receiver: any tool, any JSON, no adapter.

    Authentication here is the connector's configured signature strategy
    (connectors/verification.py), not an API token - a third-party tool
    cannot present one of ours. The tenant comes from the connector
    document, so it is never taken from the request body.

    The raw body is read before parsing because HMAC strategies sign the
    exact bytes sent; re-serialising a parsed dict would not reproduce
    them (key order, separators and unicode escaping all differ) and every
    signature check would fail.
    """
    if not connector_registry.valid_connector_id(connector_id):
        raise HTTPException(status_code=404, detail="no such connector")

    # Checked before the Firestore lookup below, not after: found in a
    # security self-review that connector_registry.load() - a real read -
    # ran with NO rate limit at all, since _WEBHOOK_LIMITER is keyed by
    # config.org_id and that value doesn't exist until AFTER the lookup
    # succeeds. An unauthenticated caller hammering /webhook/{any-id} paid
    # for and unlimited-ly triggered Firestore reads regardless of
    # whether the id was even real. IP-keyed, not org-keyed, since there
    # is no tenant identity yet at this point - this is a coarser,
    # earlier backstop; the org-keyed check below still runs once one is
    # known, as the real per-connector budget.
    client_ip = identity.resolve_client_address(request.headers) or "unknown"
    try:
        _PRE_LOOKUP_WEBHOOK_LIMITER.check(client_ip)
    except identity.RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    raw_body = await request.body()
    if len(raw_body) > _MAX_TEXT_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"webhook body exceeds {_MAX_TEXT_PAYLOAD_BYTES} bytes",
        )
    headers = {k.lower(): v for k, v in request.headers.items()}

    try:
        config = await asyncio.to_thread(connector_registry.load, None, connector_id)
    except connector_registry.UnknownConnector:
        # Same response for "no such connector" and "disabled", so the
        # endpoint is not an oracle for which ids exist.
        raise HTTPException(status_code=404, detail="no such connector") from None

    try:
        verification.verify(config, headers, raw_body)
    except verification.VerificationFailed as exc:
        logger.warning(
            "rejected webhook for connector %s: %s", connector_id, exc,
            extra={"org_id": config.org_id},
        )
        otel_setup.record_metric(
            "webhook_rejected", source=config.source, org_id=config.org_id,
        )
        raise HTTPException(status_code=401, detail="signature verification failed") from exc
    except verification.VerificationMisconfigured as exc:
        logger.error("connector %s is misconfigured: %s", connector_id, exc)
        raise HTTPException(status_code=500, detail="connector misconfigured") from exc

    try:
        _WEBHOOK_LIMITER.check(config.org_id)
    except identity.RateLimitExceeded as exc:
        raise HTTPException(status_code=429, detail=str(exc)) from exc

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
    except (json.JSONDecodeError, UnicodeDecodeError):
        # Not JSON (a form post, plain text, XML). Still ingestable - the
        # extraction layer reads text - so this degrades rather than 400s.
        payload = {"body": raw_body.decode("utf-8", errors="replace")[:_MAX_TEXT_PAYLOAD_BYTES]}
    if not isinstance(payload, dict):
        payload = {"body": payload}

    return await asyncio.to_thread(_handle_webhook, config, payload)


def _handle_watcher_sweep(org_id: str, body: dict) -> dict:
    """Blocking work (coordinator.route -> Firestore reads/writes, plus
    a real Gemini call via Diagnosis on any match) - run via
    asyncio.to_thread, same reasoning as _handle_ingest above.

    `org_id` is resolved from the authenticated principal by the route,
    never read out of `body` - a sweep triggers real model calls, so an
    unauthenticated caller naming a tenant here was the same cost and
    cross-tenant problem /ingest had."""
    run_id = new_id("run")

    with otel_setup.span("mortemtrace.api", "watcher_sweep", run_id=run_id, org_id=org_id):
        claim = _ingest_claim(org_id, run_id)
        payload: dict = {}
        if "injected_signal" in body:
            payload["injected_signal"] = body["injected_signal"]

        envelope = Envelope(
            run_id=run_id, org_id=org_id, claim=claim,
            event_type=_WATCHER_SWEEP_TOPIC, payload=payload,
        )
        results = coordinator.route(_WATCHER_SWEEP_TOPIC, envelope, publish=_publish)

    detail = results[0].detail if results else "no watcher worker registered"
    return {"run_id": run_id, "org_id": org_id, "detail": detail}


@app.post("/watcher/sweep")
async def watcher_sweep(
    body: Optional[dict] = Body(default=None),
    authorization: Optional[str] = Header(None),
):
    """Cloud Scheduler's target (see infra/schedule.sh) for the periodic
    Watcher sweep (R2, R3). Routed through coordinator.route() exactly
    like every Pub/Sub-originated event - same quarantine check,
    retry/backoff, budget enforcement, and Guardian pre/post-flight - so
    a scheduled trigger isn't a special-cased bypass of any of that.

    Authenticated like /ingest: Cloud Scheduler is configured with an
    API token (infra/schedule.sh). The tenant comes from that credential;
    `body.org_id` may only select among tenants it already grants.

    Body is optional and JSON: {"org_id": "...", "injected_signal": {...}}.
    injected_signal (a Signal-shaped dict) lets a demo operator force one
    specific, deterministic correlation live instead of relying on
    Watcher's mock feed timing (see agents/watcher/watcher.py's module
    docstring) - this is what makes "inject a provider status
    degradation" (SPEC section 10, beat 5) an actual button to press
    rather than a hope that the mock feed cooperates.
    """
    payload = body or {}
    resolved_org = _authenticate(authorization, payload.get("org_id"))
    return await asyncio.to_thread(_handle_watcher_sweep, resolved_org, payload)


def _verify_push_token(authorization_header: Optional[str]) -> None:
    """Raises HTTPException(401) unless this is a legitimately
    Pub/Sub-signed push delivery from *our* pusher service account.

    The service stays --allow-unauthenticated overall (Cloud Run's IAM
    invoker check is service-wide, not per-route), so this route does its
    own verification. Delegates to auth.identity.verify_google_oidc,
    which checks the issuing service-account email and not only the
    audience: audience alone is not an authorization decision, because
    any Google principal can mint an ID token with an arbitrary `aud`.
    """
    try:
        identity.verify_google_oidc(authorization_header)
    except identity.AuthenticationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc
    except RuntimeError as exc:
        # Missing server-side configuration - a 500 so it is never
        # mistaken for "the caller was unauthorized".
        logger.error("push route is misconfigured: %s", exc)
        raise HTTPException(status_code=500, detail="push route misconfigured") from exc


@app.post("/pubsub/push/{event_type}")
async def pubsub_push(event_type: str, request: Request):
    """The real Pub/Sub push delivery target - one HTTP request per
    message, per hop. This is what makes the deployed service genuinely
    asynchronous rather than just claiming to be: /ingest (and every
    other dispatch) publishes and returns immediately, and each
    downstream agent invocation happens as its own separate delivery
    here, off the original request entirely (R2: "under 500ms ...
    never in the request path"). infra/setup_pubsub_subscriptions.py
    creates one push subscription per topic against this same path,
    each with a push-auth-service-account so the request carries a
    token _verify_push_token can check.

    Known limitation, not worked around: Pub/Sub's delivery guarantee
    is at-least-once, and a duplicate delivery here would re-run a
    worker (scope_store's idempotency_key covers the write itself, but
    not a second, wastefully-real Gemini call before that write).
    Message-level dedup (tracking seen message IDs) is a real
    "what I'd revisit at scale" item, not implemented here - acceptable
    at hackathon-demo volume, where duplicate deliveries are rare.
    """
    _verify_push_token(request.headers.get("authorization"))
    body = await request.json()
    return await asyncio.to_thread(_handle_pubsub_push, event_type, body)


def _handle_pubsub_push(event_type: str, body: dict) -> dict:
    """Decode plus the actual dispatch - both fast to write, but
    coordinator.route() inside is blocking Firestore I/O and, on most
    hops, a real Gemini call, so this whole thing runs via
    asyncio.to_thread from the route above rather than directly on the
    event loop (same reasoning as _handle_ingest)."""
    message = body.get("message", {})
    raw_data = message.get("data", "")
    try:
        payload = json.loads(base64.b64decode(raw_data).decode("utf-8")) if raw_data else {}
    except Exception as exc:
        logger.error("could not decode push message data for topic=%s: %s", event_type, exc)
        # Ack it anyway (2xx) rather than let Pub/Sub retry something
        # that can never parse - the subscription's dead-letter policy
        # is the real safety net for a genuinely malformed message, not
        # infinite redelivery of one that will never succeed.
        return {"status": "dropped", "reason": "undecodable message data"}

    run_id = payload.get("run_id")
    org_id = payload.get("org_id")
    if not run_id or not org_id:
        logger.error("push message for topic=%s missing run_id/org_id: %r", event_type, payload)
        return {"status": "dropped", "reason": "missing run_id/org_id"}

    # These values originate from our own publisher, but they are still
    # re-validated here: this is the point where an org_id becomes a
    # Firestore path segment, and "it came from inside the system" is an
    # assumption worth checking rather than trusting once a message has
    # round-tripped through a broker.
    try:
        identity.validate_org_id(org_id)
    except identity.InvalidOrgId:
        logger.error("push message for topic=%s carried an invalid org_id: %r", event_type, org_id)
        return {"status": "dropped", "reason": "invalid org_id"}

    incident_id = payload.get("incident_id") or payload.get("incident_ref")
    claim = _ingest_claim(org_id, run_id)
    envelope = Envelope(
        run_id=run_id, org_id=org_id, incident_id=incident_id, claim=claim,
        event_type=event_type, payload=payload,
    )
    # Continue the trace the publisher started rather than beginning a new
    # root span - the other half of end-to-end tracing across Pub/Sub.
    parent = otel_setup.extract_trace_context(message.get("attributes"))
    with otel_setup.span(
        "mortemtrace.api", "pubsub_push", run_id=run_id, org_id=org_id,
        incident_id=incident_id, event_type=event_type, context=parent,
    ):
        coordinator.route(event_type, envelope, publish=_publish)

    return {"status": "processed"}
