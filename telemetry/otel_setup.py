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

import logging
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional

from opentelemetry import trace
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Status, StatusCode

logger = logging.getLogger("mortemtrace.telemetry")

_ATTR_PREFIX = "mortemtrace"
_INITIALIZED = False


def init_telemetry(service_name: str) -> None:
    """Idempotent. Call once per process (Cloud Run entrypoint, or a
    script's __main__). Exports to Cloud Trace when running on GCP with
    credentials available; falls back to console export otherwise so
    local runs still show spans instead of failing silently."""
    global _INITIALIZED
    if _INITIALIZED:
        return

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    exporter = _build_exporter()
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)
    _INITIALIZED = True


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
    **extra_attributes: Any,
) -> Iterator[trace.Span]:
    """General-purpose span context manager. Sets the three queryable
    identifiers plus whatever else the caller passes, records exceptions
    with ERROR status instead of swallowing them, and always closes the
    span (including on the exception path)."""
    tracer = get_tracer(tracer_name)
    attrs = _prefixed({"run_id": run_id, "org_id": org_id, "incident_id": incident_id, **extra_attributes})
    with tracer.start_as_current_span(span_name, attributes=attrs) as s:
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


def tool_call(tool_name: str, agent_name: str, run_id: str, org_id: str):
    return span(
        "mortemtrace.tools", f"tool_call:{tool_name}",
        run_id=run_id, org_id=org_id, tool_name=tool_name, agent_name=agent_name,
    )


def model_call(agent_name: str, run_id: str, org_id: str, model: str):
    return span(
        "mortemtrace.gateway", "model_call",
        run_id=run_id, org_id=org_id, agent_name=agent_name, model=model,
    )


def record_model_usage(s: trace.Span, *, input_tokens: int, output_tokens: int, latency_ms: float) -> None:
    s.set_attributes(_prefixed({
        "tokens.input": input_tokens, "tokens.output": output_tokens, "latency_ms": latency_ms,
    }))


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
