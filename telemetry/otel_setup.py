"""OpenTelemetry setup and span helpers.

R10 requires every trace to be queryable by run_id, incident_id, and
org_id, and requires spans across ingest, each agent invocation, each
tool call, each model call, and each read/write (including denials). The
attribute names below (`mortemtrace.run_id` etc.) are applied consistently
everywhere a span opens, specifically so Cloud Trace filtering by any of
the three works no matter which agent or layer emitted the span.

Denials are not separate spans - they are events on whichever span is
active when the denial happens (typically an agent-invocation span), which
is what makes "a scope denial inside the same trace as the commit it
affected" (SPEC R10 acceptance) true instead of just plausible.
"""
from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from opentelemetry import trace
from opentelemetry.propagate import extract, inject
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger("mortemtrace.telemetry")

_ATTR_PREFIX = "mortemtrace"
_INITIALIZED = False
_LOGGING_CONFIGURED = False
_INIT_LOCK = threading.Lock()


def init_telemetry(service_name: str) -> None:
    """Idempotent. Call once per process (Cloud Run entrypoint, or a
    script's __main__). Exports to Cloud Trace when running on GCP with
    credentials available; falls back to console export otherwise so
    local runs still show spans instead of failing silently."""
    global _INITIALIZED
    with _INIT_LOCK:
        if _INITIALIZED:
            return

        resource = Resource.create({SERVICE_NAME: service_name})
        provider = TracerProvider(resource=resource)

        exporter = _build_exporter()
        provider.add_span_processor(BatchSpanProcessor(exporter))
        trace.set_tracer_provider(provider)
        _INITIALIZED = True


class _StructuredFormatter(logging.Formatter):
    """Emits one JSON object per line, in the field names Cloud Logging
    parses natively.

    `logging.trace` / `logging.spanId` are the two Cloud Logging looks for
    to associate a log line with a Cloud Trace span; without them, logs
    and traces stay two disconnected systems. This is what makes "show me
    every log line for run X" a query rather than a timestamp-matching
    exercise against unstructured text - which is what diagnosing this
    system actually required before this existed.
    """

    def __init__(self, service_name: str, project_id: Optional[str]):
        super().__init__()
        self._service = service_name
        self._project = project_id

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "severity": record.levelname,
            "message": record.getMessage(),
            "logger": record.name,
            "service": self._service,
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx is not None and ctx.is_valid:
            trace_id = format(ctx.trace_id, "032x")
            payload["logging.googleapis.com/spanId"] = format(ctx.span_id, "016x")
            payload["logging.googleapis.com/trace"] = (
                f"projects/{self._project}/traces/{trace_id}" if self._project else trace_id
            )

        # Correlation identifiers attached via `logger.info(..., extra={...})`
        # so an operator can filter by run without parsing message text.
        for field in ("run_id", "org_id", "incident_id", "agent_name",
                      "metric_name", "metric_value", "event_type", "status"):
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value

        return json.dumps(payload, default=str)


def configure_logging(service_name: str) -> None:
    """Installs structured JSON logging on the root logger. Idempotent.

    Skipped when MORTEMTRACE_PLAIN_LOGS=1, which keeps local runs and test
    output human-readable.
    """
    global _LOGGING_CONFIGURED
    with _INIT_LOCK:
        if _LOGGING_CONFIGURED or os.environ.get("MORTEMTRACE_PLAIN_LOGS") == "1":
            return

        project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
        handler = logging.StreamHandler()
        handler.setFormatter(_StructuredFormatter(service_name, project))

        root = logging.getLogger()
        for existing in list(root.handlers):
            root.removeHandler(existing)
        root.addHandler(handler)
        root.setLevel(os.environ.get("MORTEMTRACE_LOG_LEVEL", "INFO"))

        # These emit a full stack trace per retried 429 at WARNING, which
        # is the single noisiest thing in this system's logs and says
        # nothing the gateway's own structured warning doesn't.
        logging.getLogger("google_adk.google.adk.models.google_llm").setLevel(logging.ERROR)
        _LOGGING_CONFIGURED = True


def inject_trace_context(carrier: dict) -> dict:
    """Writes W3C traceparent into a Pub/Sub message attribute dict.

    Without this each Pub/Sub hop began a brand-new root trace, so an
    ingest-to-drafts chain appeared in Cloud Trace as five unrelated
    traces and R10's "one trace for the whole chain" was not achievable
    however consistent the attributes were.
    """
    inject(carrier)
    return carrier


def extract_trace_context(carrier: Optional[dict]):
    """Inverse of inject_trace_context, for the push handler."""
    return extract(carrier or {})


def _build_exporter():
    project = os.environ.get("GOOGLE_CLOUD_PROJECT") or os.environ.get("GCP_PROJECT")
    if project:
        try:
            from opentelemetry.exporter.cloud_trace import CloudTraceSpanExporter

            return CloudTraceSpanExporter(project_id=project)
        except Exception:  # pragma: no cover - falls back to console locally
            logger.warning("Cloud Trace exporter unavailable, falling back to console export", exc_info=True)
    return ConsoleSpanExporter()


def get_tracer(name: str) -> trace.Tracer:
    return trace.get_tracer(name)


def _prefixed(attributes: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in attributes.items():
        if v is None:
            continue
        out[f"{_ATTR_PREFIX}.{k}"] = v
    return out


@contextmanager
def span(
    tracer_name: str,
    span_name: str,
    *,
    run_id: Optional[str] = None,
    org_id: Optional[str] = None,
    incident_id: Optional[str] = None,
    context: Any = None,
    **extra_attributes: Any,
) -> Iterator[trace.Span]:
    """General-purpose span context manager. Sets the three queryable
    identifiers plus whatever else the caller passes, records exceptions
    with ERROR status instead of swallowing them, and always closes the
    span (including on the exception path).

    `context` accepts an extracted remote trace context so a span can
    continue a trace started in another process (see
    extract_trace_context) instead of starting a new root."""
    tracer = get_tracer(tracer_name)
    attrs = _prefixed({"run_id": run_id, "org_id": org_id, "incident_id": incident_id, **extra_attributes})
    with tracer.start_as_current_span(span_name, context=context, attributes=attrs) as s:
        try:
            yield s
        except Exception as exc:
            s.set_status(Status(StatusCode.ERROR, str(exc)))
            s.record_exception(exc)
            raise


def agent_invocation(agent_name: str, agent_version: str, run_id: str, org_id: str,
                      incident_id: Optional[str] = None):
    return span(
        "mortemtrace.agents", f"agent_invocation:{agent_name}",
        run_id=run_id, org_id=org_id, incident_id=incident_id,
        agent_name=agent_name, agent_version=agent_version,
    )


# NOTE: there is deliberately no tool_call() span helper.
#
# One existed, unused, for R10's "spans across ... each tool call". No
# agent in this system passes `tools=` to build_agent - every worker uses
# a structured output_schema and does its own Firestore access through
# scope_store - so there are no tool calls to instrument. An unused
# helper implied a layer of instrumentation that did not exist; if tool-
# using agents are added later, add the span with them rather than
# keeping scaffolding that suggests coverage the system does not have.


def model_call(agent_name: str, run_id: str, org_id: str, model: str):
    return span(
        "mortemtrace.gateway", "model_call",
        run_id=run_id, org_id=org_id, agent_name=agent_name, model=model,
    )


def record_model_usage(s: trace.Span, *, tokens_used: int, turns: int, model: str) -> None:
    """Attaches what a model call actually cost to its span.

    Previously took separate input/output token counts, which the ADK
    runner does not expose separately - so it could not be called, and
    was not: it sat unused while spans carried no cost data at all.
    Signature now matches what invoke() genuinely has.
    """
    s.set_attributes(_prefixed({
        "tokens.total": tokens_used, "turns": turns, "model": model,
    }))


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------

_metrics_logger = logging.getLogger("mortemtrace.metrics")


def record_metric(name: str, value: float = 1.0, **labels: Any) -> None:
    """Emits a counter/gauge observation as a structured log record.

    Deliberately log-based rather than an OTel MetricExporter: Cloud
    Logging turns these into log-based metrics (and alerting policies)
    with no extra exporter, no extra dependency, and no metric pipeline
    to operate - which is the right trade at this size. The important
    property is that dead-letters, blocks, denials and quota exhaustion
    become *alertable numbers* instead of things you only discover by
    reading logs after someone notices missing drafts.
    """
    _metrics_logger.info(
        "metric %s=%s", name, value,
        extra={"metric_name": name, "metric_value": value, **labels},
    )


def record_audit_event(verdict: str, reason: str, path: str, actor_agent: str, run_id: str, org_id: str) -> None:
    """Called by data/scope_store.py on every allow/deny so a denial shows
    up as an event on the currently-active span - typically the agent
    invocation span that attempted the read or write. Safe to call with no
    active span: OTel's no-op span silently absorbs add_event()."""
    current = trace.get_current_span()
    current.add_event(
        f"scope_check:{verdict}",
        attributes=_prefixed({
            "verdict": verdict, "reason": reason, "path": path,
            "actor_agent": actor_agent, "run_id": run_id, "org_id": org_id,
        }),
    )
