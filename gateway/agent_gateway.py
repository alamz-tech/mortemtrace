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
"""
from __future__ import annotations

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

logger = logging.getLogger("mortemtrace.gateway")

DEFAULT_MODEL = os.environ.get("MORTEMTRACE_MODEL", "gemini-3.5-flash")
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

    def _before_model(ctx: Context, llm_request: LlmRequest):
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

    def _after_model(ctx: Context, llm_response: LlmResponse):
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

    Raises LoopDetected if the same tool-call signature repeats three
    times (R9) - Coordinator is expected to catch this specifically and
    quarantine rather than retry, since retrying a loop just repeats it.
    """
    model_name = agent.model if isinstance(agent.model, str) else "unknown"
    seen_signatures: dict[tuple, int] = {}
    tokens_used = 0
    turns = 0
    final_text = ""

    with _model_call_span(agent.name, run_id, org_id, model_name):
        runner = InMemoryRunner(agent=agent, app_name="mortemtrace")
        session_id = f"session_{uuid.uuid4().hex[:12]}"
        runner.session_service.create_session_sync(
            app_name="mortemtrace", user_id=org_id, session_id=session_id,
        )
        for event in runner.run(
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
