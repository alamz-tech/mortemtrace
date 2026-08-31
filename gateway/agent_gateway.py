"""The sole Vertex AI / ADK path in MortemTrace.

No agent module may construct an LlmAgent, a Runner, or touch
google.genai/vertexai directly - `tests/test_no_direct_vertex_access.py`
greps the tree for that. Agent modules call build_agent(...) to get a
configured LlmAgent, then invoke(...) to run one turn and get back plain
text; they check the InvocationOutcome returned alongside the agent for
a Model Armor block before acting on any tool result or committing
anything to scope_store.

ADK session state does not need to survive past one invoke() call - each
call gets a fresh in-memory session that is discarded afterward. Anything
that must survive past one agent turn goes through data/scope_store.py
into Firestore, which is what keeps every Cloud Run instance stateless
(NFR: "No in-memory state survives a Cloud Run instance").

Requires three environment variables at runtime (see infra/deploy.sh),
confirmed against this project's actual Vertex AI access, not assumed:
  GOOGLE_GENAI_USE_VERTEXAI=true   - without this, google-genai defaults
                                     to the Gemini Developer API (needs
                                     an API key) instead of Vertex AI
                                     (ADC/service-account auth), which
                                     both breaks and is architecturally
                                     wrong per the compliance checklist.
  GOOGLE_CLOUD_PROJECT             - already required elsewhere.
  GOOGLE_CLOUD_LOCATION=global      - see below for why "global" and not
                                     a specific region.

DEFAULT_MODEL is "gemini-3.5-flash", matching SPEC-postmortem.md's
non-goals section ("Off-the-shelf Gemini 3.5 and Gemma only"). Getting
there took two real findings, not one, both confirmed directly against
this project's live Vertex AI access rather than assumed:
  1. Every *regional* Vertex AI endpoint tried (us-central1, us-east1,
     us-east4, us-west1, europe-west1, europe-west4) 404s on every
     gemini-3.x candidate ID. This looked at first like the project
     genuinely lacked 3.5 access.
  2. It doesn't - gemini-3.5-flash works on the *global* endpoint
     (GOOGLE_CLOUD_LOCATION=global), which is the common rollout pattern
     for a newly-released Vertex AI model before regional availability
     catches up. This is independent of MODEL_ARMOR_LOCATION (gateway/
     model_armor.py), which stays regional (us-central1) - Model Armor
     and the Gemini model call are two separate location settings, not
     one, and only the latter needed to move.
Override via MORTEMTRACE_MODEL/GOOGLE_CLOUD_LOCATION if regional 3.5
access lands before demo day and you'd rather pin to a specific region.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from dataclasses import dataclass, field
from typing import Callable, Optional

from google.adk.agents import LlmAgent
from google.adk.agents.context import Context
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.runners import InMemoryRunner
from google.genai import types as genai_types

from gateway import model_armor
from telemetry.otel_setup import model_call as _model_call_span
from telemetry.otel_setup import record_metric as _record_metric
from telemetry.otel_setup import record_model_usage as _record_model_usage

logger = logging.getLogger("mortemtrace.gateway")

DEFAULT_MODEL = os.environ.get("MORTEMTRACE_MODEL", "gemini-3.5-flash")
# Live-testing (2026-08-26) hit real 429 RESOURCE_EXHAUSTED from Vertex AI
# twice, 29 minutes apart, then none for 30+ minutes after - consistent
# with a short per-minute-style quota on this trial project, not a daily
# one. But the error body Google returns carries no quota dimension
# ("Resource exhausted. Please try again later." - that's the whole
# message), so which quota tripped is never actually knowable from here,
# and a free-trial project can also have a per-day cap behind the
# per-minute one that would look identical but not clear for hours.
# Coordinator's retry/backoff (agents/coordinator/coordinator.py) only
# helps if the window is short; falling back to a second model - a
# different quota pool entirely - helps regardless of which window this
# actually is, and resolves within the same request instead of waiting
# out a backoff.
FALLBACK_MODEL = os.environ.get("MORTEMTRACE_FALLBACK_MODEL", "gemini-2.5-flash")
_RESOURCE_EXHAUSTION_MARKERS = ("RESOURCE_EXHAUSTED", "429", "UNAVAILABLE", "503")
_LOOP_THRESHOLD = 3


class LoopDetected(Exception):
    """R9: the same (tool_name, args) signature appeared three times in
    one invocation. Coordinator catches this, quarantines the agent
    version, and routes the run to dead-letter - it never retries a loop
    into existing, it terminates it."""


@dataclass
class InvokeResult:
    text: str
    tokens_used: int
    turns: int


@dataclass
class InvocationOutcome:
    """Mutated by the Model Armor callbacks during invoke(). Callers check
    this after every invoke() - a blocked run must not act on any tool
    result or write anything; a redacted run should attach the redaction
    note to whatever gets written (see data/models.py DraftBase.redaction_note)."""

    blocked: bool = False
    block_reason: Optional[str] = None
    redacted: bool = False
    redaction_notes: list[str] = field(default_factory=list)


def build_agent(
    *,
    name: str,
    run_id: str,
    org_id: str,
    instruction: str,
    tools: Optional[list[Callable]] = None,
    output_schema: Optional[type] = None,
    model: str = DEFAULT_MODEL,
) -> tuple[LlmAgent, InvocationOutcome]:
    """Build an ADK LlmAgent wired with Model Armor input/output
    screening. Call once per invocation (run_id/org_id are baked into the
    callbacks via closure, which is simpler and more predictable than
    threading them through ADK's session state)."""
    outcome = InvocationOutcome()

    def _before_model(callback_context: Context, llm_request: LlmRequest):
        # ADK invokes before/after-model callbacks by keyword, not
        # position, despite the type aliases being declared positionally
        # (confirmed against the installed ADK 2.7.1 source,
        # base_llm_flow.py's own comment says so) - the parameter names
        # here must be exactly callback_context/llm_request(/llm_response)
        # or the call raises TypeError: got an unexpected keyword argument.
        text = _extract_request_text(llm_request)
        if not text:
            return None
        verdict = model_armor.screen_input(text, run_id=run_id, org_id=org_id, agent_name=name)
        if verdict.verdict == "block":
            outcome.blocked = True
            outcome.block_reason = verdict.reason
            logger.warning("Model Armor blocked input for %s (run=%s): %s", name, run_id, verdict.reason)
            return LlmResponse(
                content=genai_types.Content(
                    role="model",
                    parts=[genai_types.Part(
                        text="Request blocked by policy: potential prompt injection detected."
                    )],
                ),
                turn_complete=True,
            )
        return None

    def _after_model(callback_context: Context, llm_response: LlmResponse):
        text = _extract_response_text(llm_response)
        if not text:
            return None
        verdict = model_armor.screen_output(text, run_id=run_id, org_id=org_id, agent_name=name)
        if verdict.verdict == "redact":
            outcome.redacted = True
            outcome.redaction_notes.append(verdict.reason)
            logger.info("Model Armor redacted output for %s (run=%s): %s", name, run_id, verdict.reason)
            return LlmResponse(
                content=genai_types.Content(
                    role="model",
                    parts=[genai_types.Part(text=verdict.sanitized_text or text)],
                ),
                turn_complete=llm_response.turn_complete,
            )
        return None

    agent = LlmAgent(
        name=name,
        model=model,
        instruction=instruction,
        tools=tools or [],
        output_schema=output_schema,
        before_model_callback=_before_model,
        after_model_callback=_after_model,
    )
    return agent, outcome


def invoke(agent: LlmAgent, prompt: str, *, run_id: str, org_id: str) -> InvokeResult:
    """Runs one turn to completion against a throwaway in-memory session.
    Check the InvocationOutcome from build_agent() afterward - a blocked
    verdict means the returned text is the canned policy message, not a
    real model response, and the caller must not treat it as one.

    On a resource-exhaustion/unavailable-shaped error from `agent.model`,
    retries once against FALLBACK_MODEL before giving up - a different
    model is a different quota pool, so this resolves within the same
    request rather than waiting out Coordinator's backoff for a quota
    window of unknown length. Rebuilds via model_copy() so the same
    Model Armor before/after callbacks (and the InvocationOutcome they
    mutate) stay wired to whichever model actually serves the call.

    Raises LoopDetected if the same tool-call signature repeats three
    times (R9) - Coordinator is expected to catch this specifically and
    quarantine rather than retry, since retrying a loop just repeats it.
    """
    try:
        return _invoke_once(agent, prompt, run_id=run_id, org_id=org_id)
    except LoopDetected:
        raise
    except Exception as exc:
        current_model = agent.model if isinstance(agent.model, str) else None
        if current_model is None or current_model == FALLBACK_MODEL or not _is_resource_exhausted(exc):
            raise
        logger.warning(
            "model %s exhausted/unavailable for %s (run=%s), falling back to %s: %s",
            current_model, agent.name, run_id, FALLBACK_MODEL, exc,
            extra={"run_id": run_id, "org_id": org_id, "agent_name": agent.name},
        )
        # Countable, so a sustained quota problem can page someone rather
        # than being inferred later from missing drafts.
        _record_metric(
            "model_fallback", agent_name=agent.name, run_id=run_id, org_id=org_id,
        )
        fallback_agent = agent.model_copy(update={"model": FALLBACK_MODEL})
        return _invoke_once(fallback_agent, prompt, run_id=run_id, org_id=org_id)


def _is_resource_exhausted(exc: BaseException) -> bool:
    """String-matches rather than isinstance-checks a specific exception
    type: the real error arrives wrapped several layers deep (ADK's
    runner -> google.genai's retry wrapper -> ClientError/ServerError),
    and which wrapper type surfaces can shift across ADK/genai versions.
    Matching the rendered message across the whole __cause__/__context__
    chain is more robust than pinning to one wrapper class we don't
    control - confirmed against a live 429 RESOURCE_EXHAUSTED chain
    (2026-08-26) where the markers below were present in the message."""
    text_parts = []
    seen, hops = exc, 0
    while seen is not None and hops < 8:
        text_parts.append(str(seen))
        seen = seen.__cause__ or seen.__context__
        hops += 1
    text = " ".join(text_parts)
    return any(marker in text for marker in _RESOURCE_EXHAUSTION_MARKERS)


def _invoke_once(agent: LlmAgent, prompt: str, *, run_id: str, org_id: str) -> InvokeResult:
    """Drives ADK's *async* Runner API directly via one asyncio.run(), not
    the sync Runner.run() convenience wrapper - confirmed live (2026-08-26)
    that wrapper silently swallows a real model-call exception instead of
    raising it here. Its own docstring already says "only for local
    testing... consider using run_async for production", and the reason
    showed up under a genuine 429: Runner.run() bridges to async by
    running asyncio.run() on a background thread and shuttling events
    back through a queue.Queue, whose producer side is
    `try: ... finally: event_queue.put(None)` (runners.py) - that
    unconditionally signals "done" to the consuming generator even when
    the coroutine raised, so the exception's only real destination is
    Python's default uncaught-thread-exception hook (a stderr printout,
    "Exception in thread Thread-N"), never this function's try/except.
    The practical effect was silent: invoke() returned normally with
    final_text="" instead of raising, so neither the model-fallback in
    invoke() above nor Coordinator's retry-with-backoff ever ran - the
    call site just saw an empty string and (for diagnosis.py, e.g.)
    dead-lettered on schema validation instead, which looks like an
    unrelated failure unless you trace it back this far.
    run_async() is a plain async generator with no cross-thread queue in
    front of it, so driving it with our own asyncio.run() (safe here:
    _invoke_once always runs inside asyncio.to_thread from api/ingest.py,
    a worker thread with no event loop of its own already running)
    propagates a real exception exactly like a normal function call.
    """
    model_name = agent.model if isinstance(agent.model, str) else "unknown"
    seen_signatures: dict[tuple, int] = {}
    tokens_used = 0
    turns = 0
    final_text = ""

    async def _run() -> None:
        nonlocal tokens_used, turns, final_text
        runner = InMemoryRunner(agent=agent, app_name="mortemtrace")
        session_id = f"session_{uuid.uuid4().hex[:12]}"
        await runner.session_service.create_session(
            app_name="mortemtrace", user_id=org_id, session_id=session_id,
        )
        async for event in runner.run_async(
            user_id=org_id,
            session_id=session_id,
            new_message=genai_types.Content(role="user", parts=[genai_types.Part(text=prompt)]),
        ):
            turns += 1
            usage = getattr(event, "usage_metadata", None)
            if usage is not None and getattr(usage, "total_token_count", None):
                tokens_used += usage.total_token_count

            for call in event.get_function_calls():
                signature = (call.name, tuple(sorted((call.args or {}).items())))
                seen_signatures[signature] = seen_signatures.get(signature, 0) + 1
                if seen_signatures[signature] >= _LOOP_THRESHOLD:
                    logger.warning(
                        "loop detected for %s (run=%s): %s called %d times with identical args",
                        agent.name, run_id, call.name, seen_signatures[signature],
                    )
                    raise LoopDetected(
                        f"{call.name} repeated {seen_signatures[signature]}x with identical args"
                    )

            if event.is_final_response() and event.content:
                final_text = "\n".join(
                    p.text for p in event.content.parts if getattr(p, "text", None)
                )

    with _model_call_span(agent.name, run_id, org_id, model_name) as span:
        asyncio.run(_run())
        # Attach what the call actually cost. record_model_usage() existed
        # but had no call sites, so model_call spans carried no token or
        # turn data at all and per-run spend was invisible in a trace.
        _record_model_usage(span, tokens_used=tokens_used, turns=turns, model=model_name)

    return InvokeResult(text=final_text, tokens_used=tokens_used, turns=turns)


def _extract_request_text(llm_request: LlmRequest) -> str:
    try:
        parts = []
        for content in llm_request.contents or []:
            for part in getattr(content, "parts", None) or []:
                if getattr(part, "text", None):
                    parts.append(part.text)
        return "\n".join(parts)
    except Exception:
        logger.debug("could not extract text from LlmRequest", exc_info=True)
        return ""


def _extract_response_text(llm_response: LlmResponse) -> str:
    try:
        content = llm_response.content
        if not content or not content.parts:
            return ""
        return "\n".join(p.text for p in content.parts if getattr(p, "text", None))
    except Exception:
        logger.debug("could not extract text from LlmResponse", exc_info=True)
        return ""
