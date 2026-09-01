"""Model Armor: injection/jailbreak screening on input, secret/PII
screening on output. This is the P0 governance surface - R8 requires it
to fail the run closed on a block verdict and to redact-and-audit on a
sensitive-data verdict, on both a live pasted-log injection attempt and a
leaked API key, on camera.

Two distinct roles for the local heuristic screener, confirmed by testing
both live against the real API, not assumed:

1. Exception fallback - if the real Model Armor API errors (region/
   template misconfigured, transient outage), this runs instead of
   either hard-failing the whole run or silently skipping screening -
   the build brief explicitly sanctions this: "If Vertex Model Armor is
   unavailable in your region, use the Guardian agent to implement
   injection and secret screening directly."
2. Always-on supplementary check, even when the real API succeeds. This
   is not redundant: live-tested against the real API, the configured
   template's SDP (sensitive-data) filter does not flag a bare
   `api_key: sk-...`-shaped string - basic_config's preset categories
   are tuned for standard PII (SSN, credit cards, etc.), not free-form
   secret tokens, which is a real, narrow gap in Model Armor's default
   coverage rather than a misconfiguration. screen_output() therefore
   always runs the local secret patterns on top of whatever Model Armor
   already found, and merges them, rather than trusting a real "allow"
   as the final word. screen_input()'s injection filter, by contrast,
   IS correctly caught by Model Armor once configured with
   pi_and_jailbreak enabled (confirmed against SPEC R8's exact
   acceptance-criterion string) - the local check still runs there too,
   purely as defense in depth, but isn't compensating for a known gap
   the way the output side is.

Every verdict records which path(s) produced it, so a fallback or
supplementary screen is never mistaken for the real API's own verdict in
the audit trail.
"""
from __future__ import annotations

import logging
import os
import re
import threading
from typing import Literal, Optional

from pydantic import BaseModel

logger = logging.getLogger("mortemtrace.model_armor")

Verdict = Literal["allow", "block", "redact"]
Source = Literal["model_armor", "local_fallback", "model_armor+local_fallback"]

_TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "mortemtrace-guardian")
_LOCATION = os.environ.get("MODEL_ARMOR_LOCATION", "us-central1")

# Every Firestore call in this codebase is explicitly bounded
# (data/scope_store.py's _OP_TIMEOUT_SECONDS) for exactly the same reason
# this is: an unbounded gRPC call lets a hung backend hold a Cloud Run
# request until the platform's own 300s ceiling. These two calls run on
# every single model turn in every dispatch, so a hung Model Armor
# backend compounds the ack-deadline risk documented on
# coordinator._dispatch_concurrently - both are wrapped in a broad
# `except Exception` already, so a timeout here degrades to the local
# fallback screener exactly like any other Model Armor failure, not a new
# failure mode.
_ARMOR_TIMEOUT_SECONDS = float(os.environ.get("MODEL_ARMOR_TIMEOUT", "10"))


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


def _redact_secret_patterns(text: str) -> tuple[str, bool]:
    """Pure redaction pass, shared by _local_screen_output (exception-
    fallback path) and screen_output's always-on supplementary check
    (real-API-succeeded path)."""
    redacted = text
    hit = False
    for pattern in _SECRET_PATTERNS:
        if pattern.search(redacted):
            hit = True
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted, hit


def _local_screen_output(text: str) -> ArmorResult:
    redacted, hit = _redact_secret_patterns(text)
    if hit:
        return ArmorResult(
            verdict="redact", reason="local fallback: secret-shaped content redacted",
            source="local_fallback", sanitized_text=redacted,
        )
    return ArmorResult(verdict="allow", reason="local fallback: no secret pattern matched", source="local_fallback")


# --------------------------------------------------------------------------
# Real Model Armor
# --------------------------------------------------------------------------

class ModelArmorNotConfigured(RuntimeError):
    """GOOGLE_CLOUD_PROJECT is unset, so the real API cannot be addressed."""


def _template_name() -> str:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        # Raised as a named type rather than a bare KeyError so the
        # fallback path can log "misconfigured" distinctly from "the API
        # call failed". Both still fall back to local screening, but a
        # permanently-misconfigured deployment silently running on regex
        # heuristics while believing it has Model Armor is exactly the
        # kind of thing that should be loud.
        raise ModelArmorNotConfigured(
            "GOOGLE_CLOUD_PROJECT is not set; cannot address a Model Armor template"
        )
    return f"projects/{project}/locations/{_LOCATION}/templates/{_TEMPLATE_ID}"


_CLIENT = None
_CLIENT_LOCK = threading.Lock()


def _client():
    """Cached, not constructed per call - a fresh ModelArmorClient means a
    fresh gRPC channel and a fresh credential/token exchange on every
    single screen_input()/screen_output(), which is called on every
    agent's every model call. Found this the same way as the ingest
    latency bug it's a sibling of: timing a live request and seeing
    seconds where there should have been milliseconds. Matches the
    caching pattern data/scope_store.py's own _client() already uses -
    this file just hadn't followed it."""
    global _CLIENT
    if _CLIENT is None:
        with _CLIENT_LOCK:
            if _CLIENT is None:
                from google.cloud import modelarmor_v1beta

                api_endpoint = f"modelarmor.{_LOCATION}.rep.googleapis.com"
                _CLIENT = modelarmor_v1beta.ModelArmorClient(
                    client_options={"api_endpoint": api_endpoint}
                )
    return _CLIENT


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
        response = client.sanitize_user_prompt(request=request, timeout=_ARMOR_TIMEOUT_SECONDS)
        remote = _interpret(response.sanitization_result, text, is_input=True)
    except ModelArmorNotConfigured as exc:
        logger.error(
            "Model Armor is not configured (%s); input screening is running on local "
            "heuristics only. This is a configuration failure, not a transient outage.",
            exc, extra={"run_id": run_id, "org_id": org_id, "agent_name": agent_name},
        )
        return _local_screen_input(text)
    except Exception:
        logger.warning(
            "Model Armor input screen unavailable (agent=%s run=%s), using local fallback",
            agent_name, run_id, exc_info=True,
            extra={"run_id": run_id, "org_id": org_id, "agent_name": agent_name},
        )
        return _local_screen_input(text)

    if remote.verdict == "block":
        return remote

    # Defense in depth, not compensating for a known gap on this side
    # (unlike screen_output below) - the real API correctly catches the
    # injection patterns this local check also knows about. Still run it,
    # since a local block should never be silently overridden by a
    # remote allow.
    local = _local_screen_input(text)
    if local.verdict == "block":
        return local
    return remote


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
        response = client.sanitize_model_response(request=request, timeout=_ARMOR_TIMEOUT_SECONDS)
        remote = _interpret(response.sanitization_result, text, is_input=False)
    except ModelArmorNotConfigured as exc:
        logger.error(
            "Model Armor is not configured (%s); output screening is running on local "
            "heuristics only. This is a configuration failure, not a transient outage.",
            exc, extra={"run_id": run_id, "org_id": org_id, "agent_name": agent_name},
        )
        return _local_screen_output(text)
    except Exception:
        logger.warning(
            "Model Armor output screen unavailable (agent=%s run=%s), using local fallback",
            agent_name, run_id, exc_info=True,
            extra={"run_id": run_id, "org_id": org_id, "agent_name": agent_name},
        )
        return _local_screen_output(text)

    # Always run the local secret patterns too, on top of whatever the
    # real API already returned - see module docstring for why this one
    # (unlike screen_input above) is a real, live-tested gap and not just
    # extra caution: the configured template's SDP filter does not flag a
    # bare "api_key: sk-..."-shaped string.
    base_text = remote.sanitized_text or text
    redacted_text, local_hit = _redact_secret_patterns(base_text)
    if not local_hit:
        return remote

    if remote.verdict == "redact":
        return ArmorResult(
            verdict="redact",
            reason=f"{remote.reason}; local fallback also redacted secret-shaped content",
            source="model_armor+local_fallback",
            sanitized_text=redacted_text,
        )
    return ArmorResult(
        verdict="redact",
        reason="local fallback: secret-shaped content redacted (Model Armor did not flag it)",
        source="model_armor+local_fallback",
        sanitized_text=redacted_text,
    )


# filter_results is keyed by these filter names; each value's actual
# verdict lives in exactly one of these nested fields, and the mapping
# from key to field name is not a fully regular pattern (malicious_uris
# -> malicious_uri_filter_result, singular; csam -> csam_filter_filter_result,
# doubled) - confirmed against a live API response, not guessed.
_NESTED_RESULT_FIELD_BY_KEY = {
    "pi_and_jailbreak": "pi_and_jailbreak_filter_result",
    "sdp": "sdp_filter_result",
    "malicious_uris": "malicious_uri_filter_result",
    "csam": "csam_filter_filter_result",
    "rai": "rai_filter_result",
}


def _nested_result_matched(nested) -> bool:
    """Different filter result types nest their verdict differently:
    pi_and_jailbreak_filter_result has match_state directly on itself;
    sdp_filter_result nests it one level deeper under inspect_result
    (confirmed against a live API response for both shapes - the SDP
    result type has room for a separate advanced/deidentify result this
    template doesn't enable). Tries both shapes, returns False rather
    than raising if neither matches - this only feeds the human-readable
    reason string, not the actual block/allow/redact decision, which is
    already settled by the top-level filter_match_state before this
    function is ever called."""
    for candidate in (nested, getattr(nested, "inspect_result", None)):
        state = getattr(candidate, "match_state", None)
        if state is not None:
            return state.name == "MATCH_FOUND"
    return False


def _interpret(sanitization_result, original_text: str, *, is_input: bool) -> ArmorResult:
    """Model Armor's response is a nested protobuf. filter_match_state is
    a bare enum whose str() gives its ordinal ("2"), not its name
    ("MATCH_FOUND") - checking `"MATCH_FOUND" in str(enum_value)` is
    always False and silently allows everything through. This cost a
    real, live-tested block: confirmed against the real API that a
    template with pi_and_jailbreak fully enabled correctly returns
    MATCH_FOUND for the exact SPEC R8 acceptance-criterion injection
    string, and the old code here still returned "allow" for it. Compare
    via `.name` (or the enum member itself), never str(), for any proto
    enum field - true for filter_match_state here and for each nested
    filter result's own match_state below.
    """
    try:
        matched = sanitization_result.filter_match_state.name == "MATCH_FOUND"

        if not matched:
            return ArmorResult(verdict="allow", reason="Model Armor: no filter matched", source="model_armor")

        matched_filters = []
        for key, result in dict(sanitization_result.filter_results).items():
            field_name = _NESTED_RESULT_FIELD_BY_KEY.get(key)
            nested = getattr(result, field_name, None) if field_name else None
            if nested is not None and _nested_result_matched(nested):
                matched_filters.append(key)

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
