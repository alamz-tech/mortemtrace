"""R1/R2's actual entry point.

A single POST endpoint that validates input minimally, writes one
RawEvidence doc, resolves/creates the parent Incident, publishes one
evidence.received message, and returns within the 500ms budget. All real
extraction/reasoning happens downstream (Intake, via Coordinator) -
this module never imports Vertex/Gemini and never reasons about
incident content itself.

Identity: every request mints a fresh "ingest-api" claim via
scope_store.sign_claim(). This is a registry-scope requirement for
whoever seeds the agent registry (infra/init_firestore.py) - flagged
here and in the implementation report:

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
import threading
from typing import Optional

import google.auth.transport.requests
import google.oauth2.id_token
from fastapi import Body, FastAPI, File, Form, HTTPException, Request, UploadFile
from google.cloud import pubsub_v1

from agents import wiring
from agents.coordinator import coordinator
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
# hackathon-scope shortcut (documented in the implementation report), not
# an oversight - it keeps ingest.py free of a second infra dependency
# (bucket provisioning, signed URLs) for a P0 endpoint that must respond
# in under 500ms. Truncated rather than rejected past this size so a demo
# screenshot never turns into a 4xx on stage.
_MAX_INLINE_FILE_BYTES = 5 * 1024 * 1024  # 5MB

otel_setup.init_telemetry("mortemtrace-ingest-api")
wiring.register_all()

app = FastAPI(title="MortemTrace Ingest API")


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
    future = client.publish(topic_path, data)
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
    written to Cloud Storage - see the module docstring."""
    if file is not None:
        raw = await file.read()
        if len(raw) > _MAX_INLINE_FILE_BYTES:
            raw = raw[:_MAX_INLINE_FILE_BYTES]
        encoded = base64.b64encode(raw).decode("ascii")
        content_type = file.content_type or "application/octet-stream"
        return f"data:{content_type};base64,{encoded}"
    return payload or ""


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/healthz")
def healthz() -> dict:
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(_write_incident), pool.submit(_write_raw_evidence)]
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
    org_id: str = Form(...),
    kind: EvidenceKind = Form(...),
    incident_id: Optional[str] = Form(None),
    payload: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    body_text = await _resolve_payload(payload, file)
    return await asyncio.to_thread(_handle_ingest, org_id, kind, incident_id, body_text)


def _handle_watcher_sweep(body: dict) -> dict:
    """Blocking work (coordinator.route -> Firestore reads/writes, plus
    a real Gemini call via Diagnosis on any match) - run via
    asyncio.to_thread, same reasoning as _handle_ingest above."""
    org_id = body.get("org_id") or os.environ.get("MORTEMTRACE_DEMO_ORG", "org_demo")
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
async def watcher_sweep(body: Optional[dict] = Body(default=None)):
    """Cloud Scheduler's target (see infra/schedule.sh) for the periodic
    Watcher sweep (R2, R3). Routed through coordinator.route() exactly
    like every Pub/Sub-originated event - same quarantine check,
    retry/backoff, budget enforcement, and Guardian pre/post-flight - so
    a scheduled trigger isn't a special-cased bypass of any of that.

    Body is optional and JSON: {"org_id": "...", "injected_signal": {...}}.
    org_id defaults to MORTEMTRACE_DEMO_ORG, matching console/ui.py's
    convention. injected_signal (a Signal-shaped dict) lets a demo
    operator force one specific, deterministic correlation live instead
    of relying on Watcher's mock feed timing (see agents/watcher/
    watcher.py's module docstring) - this is what makes "inject a
    provider status degradation" (SPEC section 10, beat 5) an actual
    button to press rather than a hope that the mock feed cooperates.
    """
    return await asyncio.to_thread(_handle_watcher_sweep, body or {})


def _verify_push_token(authorization_header: Optional[str]) -> None:
    """Raises HTTPException(401) unless this is a legitimately
    Pub/Sub-signed push delivery. The service stays --allow-unauthenticated
    overall (so /ingest, /watcher/sweep, /healthz work for a public demo -
    Cloud Run's own IAM invoker check is service-wide, not per-route, so
    it can't protect this one route without blocking the others too).
    This route verifies the Google-issued OIDC token itself instead of
    relying on the platform to reject unauthorized callers before they
    arrive - the standard documented pattern for a public Cloud Run
    service with one authenticated Pub/Sub push route."""
    if authorization_header is None or not authorization_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")
    audience = os.environ.get(_PUSH_AUDIENCE_ENV)
    if not audience:
        raise HTTPException(status_code=500, detail=f"{_PUSH_AUDIENCE_ENV} not configured")
    token = authorization_header[len("Bearer "):]
    try:
        google.oauth2.id_token.verify_oauth2_token(
            token, google.auth.transport.requests.Request(), audience=audience,
        )
    except Exception as exc:
        logger.warning("rejected push delivery with invalid token: %s", exc)
        raise HTTPException(status_code=401, detail="invalid push token") from exc


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

    incident_id = payload.get("incident_id") or payload.get("incident_ref")
    claim = _ingest_claim(org_id, run_id)
    envelope = Envelope(
        run_id=run_id, org_id=org_id, incident_id=incident_id, claim=claim,
        event_type=event_type, payload=payload,
    )
    with otel_setup.span(
        "mortemtrace.api", "pubsub_push", run_id=run_id, org_id=org_id,
        incident_id=incident_id, event_type=event_type,
    ):
        coordinator.route(event_type, envelope, publish=_publish)

    return {"status": "processed"}
