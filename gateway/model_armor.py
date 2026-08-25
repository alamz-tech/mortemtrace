"""Model Armor: injection/jailbreak screening on input, secret/PII
screening on output. This is the P0 governance surface - R8 requires it
to fail the run closed on a block verdict and to redact-and-audit on a
sensitive-data verdict, on both a live pasted-log injection attempt and a
leaked API key, on camera.

If the real Model Armor API errors (region/template misconfigured,
transient outage), this falls back to a local heuristic screener rather
than either hard-failing the whole run or silently skipping screening -
the build brief explicitly sanctions this: "If Vertex Model Armor is
unavailable in your region, use the Guardian agent to implement injection
and secret screening directly." Every verdict records which path
produced it, so a fallback screen is never mistaken for the real thing
in the audit trail.
"""
from __future__ import annotations

import logging
import os
import re
from typing import Literal, Optional

from pydantic import BaseModel

logger = logging.getLogger("mortemtrace.model_armor")

Verdict = Literal["allow", "block", "redact"]
Source = Literal["model_armor", "local_fallback"]

_TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "mortemtrace-guardian")
_LOCATION = os.environ.get("MODEL_ARMOR_LOCATION", "us-central1")


class ArmorResult(BaseModel):
    verdict: Verdict
    reason: str
    source: Source
    sanitized_text: Optional[str] = None


# --------------------------------------------------------------------------
# Local fallback screener
# --------------------------------------------------------------------------

_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"ignore (all|any|the)?\s*(previous|prior|above)\s*instructions",
        r"disregard (all|any|the)?\s*(previous|prior|above)\s*(instructions|prompt)",
        r"you are now\s+\w+",
        r"system prompt",
        r"reveal (your|the)\s+(instructions|prompt|system message)",
        r"include (all\s+)?environment variables",
        r"\bDAN\b.{0,20}\bmode\b",
        r"forget (everything|all)\s+(you|above)",
        r"act as (if you|though)\s+(are|have)\s+no\s+(restrictions|rules)",
    ]
]

_SECRET_PATTERNS = [
    re.compile(p) for p in [
        r"AKIA[0-9A-Z]{16}",                                   # AWS access key
        r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9/_\-\.]{12,}",
        r"sk-[A-Za-z0-9]{20,}",                                 # generic "sk-" style key
        r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
        r"ghp_[A-Za-z0-9]{36}",                                 # GitHub PAT
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",  # JWT-shaped
    ]
]


def _local_screen_input(text: str) -> ArmorResult:
    for pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return ArmorResult(
                verdict="block",
                reason=f"local fallback: injection pattern matched ({pattern.pattern})",
                source="local_fallback",
            )
    return ArmorResult(verdict="allow", reason="local fallback: no injection pattern matched", source="local_fallback")


def _local_screen_output(text: str) -> ArmorResult:
    redacted = text
    hit = False
    for pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            hit = True
            redacted = pattern.sub("[REDACTED]", redacted)
    if hit:
        return ArmorResult(
            verdict="redact", reason="local fallback: secret-shaped content redacted",
            source="local_fallback", sanitized_text=redacted,
        )
    return ArmorResult(verdict="allow", reason="local fallback: no secret pattern matched", source="local_fallback")


# --------------------------------------------------------------------------
# Real Model Armor
# --------------------------------------------------------------------------

def _template_name() -> str:
    project = os.environ["GOOGLE_CLOUD_PROJECT"]
    return f"projects/{project}/locations/{_LOCATION}/templates/{_TEMPLATE_ID}"


def _client():
    from google.cloud import modelarmor_v1beta

    api_endpoint = f"modelarmor.{_LOCATION}.rep.googleapis.com"
    return modelarmor_v1beta.ModelArmorClient(
        client_options={"api_endpoint": api_endpoint}
    )


def screen_input(text: str, *, run_id: str, org_id: str, agent_name: str) -> ArmorResult:
    """Screens content headed INTO the model: injection, jailbreak,
    tool-poisoning. Pasted log lines are the highest-risk surface here -
    an attacker who can write to your logs can write to your prompt."""
    try:
        from google.cloud import modelarmor_v1beta

        client = _client()
        request = modelarmor_v1beta.SanitizeUserPromptRequest(
            name=_template_name(),
            user_prompt_data=modelarmor_v1beta.DataItem(text=text),
        )
        response = client.sanitize_user_prompt(request=request)
        return _interpret(response.sanitization_result, text, is_input=True)
    except Exception:
        logger.warning(
            "Model Armor input screen unavailable (agent=%s run=%s), using local fallback",
            agent_name, run_id, exc_info=True,
        )
        return _local_screen_input(text)


def screen_output(text: str, *, run_id: str, org_id: str, agent_name: str) -> ArmorResult:
    """Screens content coming OUT of the model: secrets and PII in a
    generated draft. A block never applies here - the correct response to
    a leaked secret in a draft is redaction, not discarding the draft."""
    try:
        from google.cloud import modelarmor_v1beta

        client = _client()
        request = modelarmor_v1beta.SanitizeModelResponseRequest(
            name=_template_name(),
            model_response_data=modelarmor_v1beta.DataItem(text=text),
        )
        response = client.sanitize_model_response(request=request)
        return _interpret(response.sanitization_result, text, is_input=False)
    except Exception:
        logger.warning(
            "Model Armor output screen unavailable (agent=%s run=%s), using local fallback",
            agent_name, run_id, exc_info=True,
        )
        return _local_screen_output(text)


def _interpret(sanitization_result, original_text: str, *, is_input: bool) -> ArmorResult:
    """Model Armor's exact response shape can shift between client
    versions; this reads it defensively and falls back locally rather
    than raising if a field isn't where expected."""
    try:
        match_state = str(getattr(sanitization_result, "filter_match_state", ""))
        matched = "MATCH_FOUND" in match_state

        if not matched:
            return ArmorResult(verdict="allow", reason="Model Armor: no filter matched", source="model_armor")

        filter_results = getattr(sanitization_result, "filter_results", {}) or {}
        matched_filters = [name for name, result in dict(filter_results).items()
                            if "MATCH_FOUND" in str(getattr(result, "match_state", result))]

        if is_input:
            return ArmorResult(
                verdict="block",
                reason=f"Model Armor blocked: {', '.join(matched_filters) or 'unspecified filter'}",
                source="model_armor",
            )

        # Output side: sensitive-data matches redact rather than block.
        sanitized = getattr(sanitization_result, "sanitized_text", None) or original_text
        return ArmorResult(
            verdict="redact",
            reason=f"Model Armor flagged: {', '.join(matched_filters) or 'unspecified filter'}",
            source="model_armor",
            sanitized_text=sanitized,
        )
    except Exception:
        logger.warning("Could not interpret Model Armor response shape, using local fallback", exc_info=True)
        return _local_screen_input(original_text) if is_input else _local_screen_output(original_text)
