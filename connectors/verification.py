"""Webhook signature verification.

This is the one part of inbound ingestion that cannot be made generic:
there is no cross-vendor standard for signing a webhook. GitHub sends
`X-Hub-Signature-256: sha256=<hex hmac of the raw body>`; Datadog and
PagerDuty use their own schemes; some tools cannot sign at all.

It does not follow that each vendor needs its own adapter. The variation
is in a few parameters - which header, which hash, hex or base64, what
prefix - so four configurable strategies cover the overwhelming majority
of tools, and a new one is a configuration change rather than a release.

Every comparison here is constant-time. A byte-by-byte early return on a
signature check leaks enough timing information to forge one.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from typing import Optional

from data.models import ConnectorConfig

logger = logging.getLogger("mortemtrace.connectors.verification")

_SECRETS_ENV = "MORTEMTRACE_CONNECTOR_SECRETS"


class VerificationFailed(Exception):
    """The request did not prove it came from the configured source."""


class VerificationMisconfigured(Exception):
    """The connector's own configuration is unusable - a server-side
    problem, reported separately so it is never mistaken for a caller
    presenting bad credentials."""


def _secret_for(secret_ref: str) -> Optional[str]:
    """Resolves a signing secret by reference.

    Secrets live in one Secret Manager-backed env var keyed by ref, not in
    the connector document: that document is readable by anything with
    `connectors` read scope, and a signing key stored there would make
    read access equivalent to the ability to forge events.
    """
    raw = os.environ.get(_SECRETS_ENV)
    if not raw:
        return None
    try:
        table = json.loads(raw)
    except json.JSONDecodeError:
        logger.error("%s is not valid JSON; no connector secret can be resolved", _SECRETS_ENV)
        return None
    if not isinstance(table, dict):
        logger.error("%s must be a JSON object of secret_ref -> secret", _SECRETS_ENV)
        return None
    value = table.get(secret_ref)
    return str(value) if value is not None else None


def _compute_hmac(secret: str, body: bytes, algorithm: str, encoding: str) -> str:
    digestmod = hashlib.sha256 if algorithm == "sha256" else hashlib.sha1
    mac = hmac.new(secret.encode("utf-8"), body, digestmod)
    if encoding == "base64":
        return base64.b64encode(mac.digest()).decode("ascii")
    return mac.hexdigest()


def _verify_hmac(config: ConnectorConfig, headers: dict, body: bytes) -> None:
    v = config.verification
    if not v.header:
        raise VerificationMisconfigured("hmac strategy requires a header name")
    if not v.secret_ref:
        raise VerificationMisconfigured("hmac strategy requires a secret_ref")

    secret = _secret_for(v.secret_ref)
    if secret is None:
        raise VerificationMisconfigured(
            f"no secret configured for secret_ref={v.secret_ref!r} in {_SECRETS_ENV}"
        )

    presented = headers.get(v.header.lower())
    if not presented:
        raise VerificationFailed(f"missing {v.header} header")

    if v.prefix:
        if not presented.startswith(v.prefix):
            raise VerificationFailed("signature header has an unexpected format")
        presented = presented[len(v.prefix):]

    # Computed over the RAW body, not a re-serialised dict: json.dumps of a
    # parsed payload will not reproduce the sender's exact bytes (key
    # order, separators, unicode escaping all differ), so any signature
    # over re-serialised JSON is guaranteed to mismatch.
    expected = _compute_hmac(secret, body, v.algorithm, v.encoding)
    if not hmac.compare_digest(expected, presented):
        raise VerificationFailed("signature mismatch")


def _verify_bearer(config: ConnectorConfig, headers: dict, body: bytes) -> None:
    v = config.verification
    if not v.secret_ref:
        raise VerificationMisconfigured("bearer strategy requires a secret_ref")
    secret = _secret_for(v.secret_ref)
    if secret is None:
        raise VerificationMisconfigured(
            f"no secret configured for secret_ref={v.secret_ref!r} in {_SECRETS_ENV}"
        )

    header_name = (v.header or "authorization").lower()
    presented = headers.get(header_name, "")
    if header_name == "authorization" and presented.lower().startswith("bearer "):
        presented = presented[len("bearer "):]
    if not presented or not hmac.compare_digest(secret, presented.strip()):
        raise VerificationFailed("bearer token mismatch")


def _client_address(headers: dict) -> str:
    """Thin wrapper over auth.identity.resolve_client_address, which is
    now the single implementation of "which X-Forwarded-For entry is the
    real client" - shared with the pre-auth rate limiters in console/ui.py
    and api/ingest.py, rather than a second copy of logic that was
    already wrong here once (see git history: it originally trusted the
    LEFTMOST entry, which a caller fully controls)."""
    from auth import identity

    resolved = identity.resolve_client_address(headers)
    if resolved is None:
        raise VerificationFailed(
            "no client address available (missing, empty, or too-short X-Forwarded-For) "
            "to match against the allowlist"
        )
    return resolved


def _verify_ip_allowlist(config: ConnectorConfig, headers: dict, body: bytes) -> None:
    """Weakest of the strategies: source IPs are coarse, and many SaaS
    tools publish wide egress ranges. Prefer hmac wherever the sending
    tool supports it."""
    v = config.verification
    if not v.allowed_ips:
        raise VerificationMisconfigured("ip_allowlist strategy requires allowed_ips")

    client = _client_address(headers)
    try:
        address = ipaddress.ip_address(client)
    except ValueError as exc:
        raise VerificationFailed(f"unparseable client address {client!r}") from exc

    for entry in v.allowed_ips:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return
        except ValueError:
            logger.error("connector %s has an invalid allowed_ips entry %r", config.connector_id, entry)
    raise VerificationFailed("client address is not in the allowlist")


def _verify_none(config: ConnectorConfig, headers: dict, body: bytes) -> None:
    """No signature. The unguessable connector_id in the URL is then the
    only credential - the same security model as a Slack incoming-webhook
    URL. Legitimate for tools that cannot sign, but it means anyone who
    learns the URL can inject events, so infra/register_connector.py warns
    when this is selected and it is never the default."""
    logger.info(
        "connector %s accepted an unsigned payload (strategy=none); the URL is the only credential",
        config.connector_id,
    )


_STRATEGIES = {
    "hmac": _verify_hmac,
    "bearer": _verify_bearer,
    "ip_allowlist": _verify_ip_allowlist,
    "none": _verify_none,
}


def verify(config: ConnectorConfig, headers: dict, body: bytes) -> None:
    """Raises VerificationFailed (401) or VerificationMisconfigured (500).

    `headers` must be lower-cased keys.
    """
    strategy = _STRATEGIES.get(config.verification.strategy)
    if strategy is None:
        raise VerificationMisconfigured(
            f"unknown verification strategy {config.verification.strategy!r}"
        )
    strategy(config, headers, body)
