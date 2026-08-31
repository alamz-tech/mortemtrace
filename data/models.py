"""Shared data schemas for MortemTrace.

Every Firestore document and Pub/Sub payload in the system is validated
against one of these models before it is written or acted on. Agents
never construct ad-hoc dicts for persisted state; schema drift is caught
here, at the boundary, and routed to dead-letter rather than coerced.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


def now() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------
# Collections - the canonical set of Firestore collection names. Scope
# grants in the registry reference these, never raw strings, so a typo in
# a scope declaration fails at import time instead of silently denying
# (or worse, silently allowing) everything.
# --------------------------------------------------------------------------

class Collection(str, Enum):
    SERVICES = "services"
    CUSTOMERS = "customers"
    INCIDENTS = "incidents"
    RAW_EVIDENCE = "raw_evidence"
    EVENTS = "events"
    TIMELINE = "timeline"
    HYPOTHESES = "hypotheses"
    CLASSIFICATION = "classification"
    DRAFTS = "drafts"
    CLOCKS = "clocks"
    SIGNALS = "signals"
    MEMORY = "memory"
    ALERTS = "alerts"
    AUDIT = "audit"
    RUNS = "runs"
    QUARANTINE = "quarantine"
    CONNECTORS = "connectors"
    CHANGE_EVENTS = "change_events"
    REGISTRY = "registry"  # global, not tenant-prefixed


TENANT_SCOPED_COLLECTIONS = frozenset(c for c in Collection if c != Collection.REGISTRY)


Severity = Literal["sev1", "sev2", "sev3", "sev4"]
IncidentStatus = Literal["open", "monitoring", "resolved"]
EvidenceKind = Literal["alert", "log", "screenshot", "slack"]
EventStatus = Literal["staged", "committed", "rejected"]
Department = Literal["engineering", "support", "legal", "finance"]
DraftKind = Literal["postmortem", "status_update", "gdpr_assessment", "sla_exposure"]
DraftStatus = Literal["draft", "approved", "rejected"]
Verdict = Literal["allow", "deny", "block", "redact"]
RunStatus = Literal[
    "running", "completed", "failed", "quarantined",
    # Statuses Coordinator actually writes, previously missing:
    "ok", "blocked", "denied", "degraded", "clarification_needed", "dead_letter",
]
AlertType = Literal["classified", "blocked", "denied", "quarantine"]
AgentStatus = Literal["published", "deprecated"]

# The set of statuses a *worker* can return (agents/contracts.py RunStatus)
# is not the same set a *run record* can hold, but they overlap and the
# run record must be able to store every one of them. RunStatus below
# previously omitted "dead_letter", "degraded" and "clarification_needed"
# entirely, while Coordinator wrote exactly those values - it got away
# with it only because _touch_run() wrote a raw dict and skipped
# validation. Firestore therefore held run documents that this model
# declared illegal, and Run.model_validate() raised on precisely the runs
# an operator most needs to inspect.


# --------------------------------------------------------------------------
# Identity / trust boundary
# --------------------------------------------------------------------------

class OrgClaim(BaseModel):
    """Signed identity attached to every envelope. Verified by scope_store
    on every read and write; never trusted from the caller alone."""

    org_id: str
    agent_name: str
    agent_version: str
    run_id: str
    issued_at: datetime = Field(default_factory=now)
    expires_at: datetime
    signature: str


class Envelope(BaseModel):
    """The wrapper every Pub/Sub message and every agent invocation carries."""

    run_id: str
    org_id: str
    incident_id: Optional[str] = None
    claim: OrgClaim
    event_type: str
    payload: dict = Field(default_factory=dict)
    ts: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Core domain records
# --------------------------------------------------------------------------

class Service(BaseModel):
    service_id: str
    org_id: str
    name: str
    owner_team: str
    depends_on: list[str] = Field(default_factory=list)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"


class SlaTerms(BaseModel):
    uptime_target: float
    credit_rate: float


class Customer(BaseModel):
    customer_id: str
    org_id: str
    name: str
    sla_terms: SlaTerms
    data_region: str
    services_subscribed: list[str] = Field(default_factory=list)
    """Which services this customer depends on - lets Exposure (Finance)
    cross-reference Classification.services against customers without
    ever reading Timeline or raw_evidence (its scope denies both)."""


class Incident(BaseModel):
    incident_id: str
    org_id: str
    opened_at: datetime
    resolved_at: Optional[datetime] = None
    status: IncidentStatus = "open"
    severity: Optional[Severity] = None
    services_affected: list[str] = Field(default_factory=list)
    alert_source: Optional[str] = None


class RawEvidence(BaseModel):
    """RESTRICTED. Only Postmortem (Engineering), Diagnosis, and Classifier
    declare read scope on this collection. Comms, Compliance, and Exposure
    are denied at the store layer regardless of what a prompt says."""

    event_id: str
    org_id: str
    incident_ref: str
    kind: EvidenceKind
    payload: str
    media_uri: Optional[str] = None
    received_at: datetime = Field(default_factory=now)


class IncidentEvent(BaseModel):
    """A staged, extracted evidence record. Intake's sole output."""

    event_id: str
    org_id: str
    incident_ref: str
    status: EventStatus = "staged"
    confidence: float = Field(ge=0.0, le=1.0)
    extracted: dict
    ts: datetime
    source_ref: str  # -> RawEvidence.event_id


class ClarificationNeeded(BaseModel):
    """Raised by Intake when confidence falls below threshold. Carries
    exactly one question, never a confident but invented extraction."""

    incident_ref: str
    org_id: str
    run_id: str
    question: str
    ts: datetime = Field(default_factory=now)


class TimelineEntry(BaseModel):
    ts: datetime
    actor: str
    action: str
    evidence: str
    source_event_ids: list[str] = Field(min_length=1)

    @field_validator("source_event_ids")
    @classmethod
    def _must_have_source(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("timeline entries must carry at least one source_event_id")
        return v


class DowntimeWindow(BaseModel):
    start: datetime
    end: Optional[datetime] = None
    services: list[str] = Field(default_factory=list)


class Timeline(BaseModel):
    incident_id: str
    org_id: str
    entries: list[TimelineEntry] = Field(default_factory=list)
    downtime_windows: list[DowntimeWindow] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=now)


class Hypothesis(BaseModel):
    hypothesis_id: str
    incident_ref: str
    org_id: str
    statement: str
    confidence: float = Field(ge=0.0, le=1.0)
    source_event_ids: list[str] = Field(min_length=1)
    prior_incident_refs: list[str] = Field(default_factory=list)


class Classification(BaseModel):
    incident_id: str
    org_id: str
    severity: Severity
    services: list[str]
    downtime_windows: list[DowntimeWindow] = Field(default_factory=list)
    data_touched: bool
    data_categories: list[str] = Field(default_factory=list)
    classified_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Departmental drafts - same base, four distinct kinds
# --------------------------------------------------------------------------

class DraftBase(BaseModel):
    draft_id: str
    incident_ref: str
    org_id: str
    department: Department
    kind: DraftKind
    status: DraftStatus = "draft"
    body: str
    source_refs: list[str] = Field(min_length=1)
    redaction_note: Optional[str] = None
    created_at: datetime = Field(default_factory=now)


class PostmortemDraft(DraftBase):
    department: Literal["engineering"] = "engineering"
    kind: Literal["postmortem"] = "postmortem"
    runbook_proposal: Optional[str] = None


class StatusUpdateDraft(DraftBase):
    department: Literal["support"] = "support"
    kind: Literal["status_update"] = "status_update"


class GdprAssessmentDraft(DraftBase):
    department: Literal["legal"] = "legal"
    kind: Literal["gdpr_assessment"] = "gdpr_assessment"
    data_categories: list[str] = Field(default_factory=list)
    clock_deadline_at: Optional[datetime] = None


class SlaExposureDraft(DraftBase):
    department: Literal["finance"] = "finance"
    kind: Literal["sla_exposure"] = "sla_exposure"
    exposure_by_customer: dict[str, float] = Field(default_factory=dict)


class GdprClock(BaseModel):
    incident_id: str
    org_id: str
    gdpr_started_at: datetime
    deadline_at: datetime
    status: Literal["running", "met", "missed"] = "running"


# --------------------------------------------------------------------------
# Watcher / signals
# --------------------------------------------------------------------------

class Signal(BaseModel):
    signal_id: str
    source: str
    provider: str
    region: str
    service: str
    severity: str
    window: DowntimeWindow
    seen_at: datetime = Field(default_factory=now)


class UpstreamSignalMatched(BaseModel):
    run_id: str
    org_id: str
    incident_id: str
    signal_id: str
    correlation_reason: str
    matched_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Memory Bank
# --------------------------------------------------------------------------

class MemoryRecord(BaseModel):
    key: str
    org_id: str
    kind: Literal[
        "incident_signature", "service_ownership", "failure_pattern",
        "customer_terms", "open_clarification",
    ]
    content: dict
    related_incident_ids: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Governance / audit / runs
# --------------------------------------------------------------------------

class AlertRecord(BaseModel):
    alert_id: str
    org_id: str
    type: AlertType
    severity: str
    payload: dict = Field(default_factory=dict)
    ts: datetime = Field(default_factory=now)


class AuditEntry(BaseModel):
    entry_id: str
    org_id: str
    actor_agent: str
    version: str
    verdict: Verdict
    reason: str
    path: str
    run_id: str
    ts: datetime = Field(default_factory=now)


class Run(BaseModel):
    run_id: str
    org_id: str
    status: RunStatus = "running"
    turns_used: int = 0
    tokens_used: int = 0
    span_id: Optional[str] = None
    agents_invoked: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=now)
    updated_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

class AgentVersionRecord(BaseModel):
    agent_name: str
    version: str  # semver
    input_schema: str
    output_schema: str
    allowed_tools: list[str] = Field(default_factory=list)
    read_scopes: list[Collection] = Field(default_factory=list)
    write_scopes: list[Collection] = Field(default_factory=list)
    department: Optional[Department] = None
    status: AgentStatus = "published"
    published_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Pub/Sub topic payloads
# --------------------------------------------------------------------------

class EvidenceReceived(BaseModel):
    run_id: str
    org_id: str
    incident_ref: Optional[str] = None
    raw_evidence_id: str
    kind: EvidenceKind
    received_at: datetime = Field(default_factory=now)


class EvidenceStaged(BaseModel):
    run_id: str
    org_id: str
    incident_ref: str
    event_id: str
    confidence: float


class TimelineCommitted(BaseModel):
    run_id: str
    org_id: str
    incident_id: str
    entry_count: int
    committed_at: datetime = Field(default_factory=now)


class IncidentClassified(BaseModel):
    run_id: str
    org_id: str
    incident_id: str
    severity: Severity
    data_touched: bool
    classified_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Connectors - vendor-agnostic inbound ingestion
#
# Deliberately NOT one adapter class per vendor. A per-vendor adapter makes
# every tool a customer already uses into a support request, which does not
# scale past the tools we happened to anticipate.
#
# Instead the receiver accepts arbitrary JSON and stores it verbatim as
# RawEvidence, and Intake - which already extracts structure from
# unstructured evidence (alerts, logs, screenshots, Slack) - does the
# normalisation. That is only viable because this system already has an
# extraction agent; a platform doing deterministic field parsing genuinely
# would need per-vendor code.
#
# What cannot be made generic is signature verification: there is no
# standard, and GitHub, Datadog and Stripe each differ. That collapses to
# a handful of configurable *strategies* rather than N adapters - see
# connectors/verification.py.
# --------------------------------------------------------------------------

VerificationStrategy = Literal["hmac", "bearer", "ip_allowlist", "none"]


class VerificationConfig(BaseModel):
    """How to prove an inbound webhook really came from the configured tool.

    The shared secret is NEVER stored here. This document lives in
    Firestore and is readable by any identity with `connectors` read
    scope; putting the signing key in it would make a read-scope grant
    equivalent to the ability to forge events. `secret_ref` names an entry
    in MORTEMTRACE_CONNECTOR_SECRETS (Secret Manager-backed), same
    indirection the API token table uses.
    """

    strategy: VerificationStrategy = "hmac"
    header: Optional[str] = None          # e.g. "X-Hub-Signature-256"
    algorithm: Literal["sha256", "sha1"] = "sha256"
    encoding: Literal["hex", "base64"] = "hex"
    prefix: Optional[str] = None          # e.g. "sha256=" (GitHub)
    secret_ref: Optional[str] = None      # key into MORTEMTRACE_CONNECTOR_SECRETS
    allowed_ips: list[str] = Field(default_factory=list)


class ConnectorConfig(BaseModel):
    """One configured inbound webhook. Created as data, never as code.

    `connector_id` is unguessable and forms part of the credential: the
    URL alone is not sufficient when a signature strategy is configured,
    but with strategy="none" it IS the only secret, which is why that
    choice is warned about at registration time.
    """

    connector_id: str
    org_id: str
    name: str
    source: str                            # "datadog", "github", or anything
    kind: EvidenceKind = "alert"
    verification: VerificationConfig = Field(default_factory=VerificationConfig)
    # True routes the payload to change_events (deploy/merge/apply history)
    # instead of opening or attaching to an incident.
    is_change_source: bool = False
    enabled: bool = True
    created_at: datetime = Field(default_factory=now)


ChangeKind = Literal["deploy", "merge", "rollback", "config_change", "infra_apply", "unknown"]


class ChangeEvent(BaseModel):
    """A deploy, merge, rollback, or infrastructure apply.

    Most outages follow a change, and "what shipped just before this
    broke?" was previously unanswerable by this system - there was nowhere
    to record it. Diagnosis correlates these by time window against an
    incident's opening.
    """

    change_id: str
    org_id: str
    source: str
    kind: ChangeKind = "unknown"
    service: Optional[str] = None
    ref: Optional[str] = None              # commit sha, build number, PR id
    actor: Optional[str] = None
    summary: str
    occurred_at: datetime = Field(default_factory=now)
    raw: dict = Field(default_factory=dict)


class DeadLetter(BaseModel):
    original_topic: str
    run_id: str
    org_id: str
    reason: str
    payload: dict
    attempt_count: int = 0
    failed_at: datetime = Field(default_factory=now)


# --------------------------------------------------------------------------
# Human identity, organizations, and membership
#
# A deliberately separate trust model from OrgClaim above. OrgClaim
# answers "may this AGENT touch this TENANT's incident data" for the
# multi-agent fleet - a question with no concept of an individual person.
# The models below answer "which org(s) does this AUTHENTICATED HUMAN
# belong to, and what may they administer there" - resolved once, at the
# console's login boundary, before an ordinary OrgClaim is minted for
# whichever org that resolves to. Neither system trusts the other; the
# console is what sits between them.
#
# Stored in global (non-tenant-scoped) Firestore collections, the same
# pattern already used for /registry and /connectors and for the same
# reason: a user or an invitation is not naturally owned by one tenant
# the way incident data is, so authorization here is enforced by explicit
# checks in data/scope_store.py's identity functions, not by the
# claim-based tenant match every other collection gets automatically.
# --------------------------------------------------------------------------

MembershipRole = Literal["admin", "member"]
MembershipStatus = Literal["active", "revoked"]
InvitationStatus = Literal["pending", "redeemed", "revoked"]


class OrgSsoConfig(BaseModel):
    """One organization's own OIDC identity provider (Entra ID, Okta,
    Auth0, a private Keycloak - anything OIDC-compliant).

    Optional: an org with no SsoConfig simply has no entry here, and its
    members authenticate via the Google fallback instead. `client_secret_ref`
    names an entry in MORTEMTRACE_OIDC_CLIENT_SECRETS (Secret Manager-backed),
    the same indirection connectors and API tokens already use - never a
    plaintext secret sitting in a Firestore document.
    """

    issuer: str                            # e.g. "https://login.microsoftonline.com/{tenant}/v2.0"
    client_id: str
    client_secret_ref: str
    domain_hint: Optional[str] = None      # e.g. "acme.com" - drives Home Realm Discovery


class Organization(BaseModel):
    """One customer tenant's identity/membership record.

    `org_id` is server-generated (never a human-chosen slug) so it can
    double as the Firestore path segment every tenant-scoped collection
    already keys on, with no separate mapping table and no squatting
    concern. `display_name` is the free-form human-facing name instead.
    """

    org_id: str
    display_name: str
    created_at: datetime = Field(default_factory=now)
    created_by: str                        # user_id of the founding admin
    sso: Optional[OrgSsoConfig] = None
    # Verified corporate email domains (lowercase, no leading "@") that
    # auto-join as "member" on first login - the standard enterprise SSO
    # pattern of "anyone with a company address is already trusted to be
    # an employee." Admins still have to be promoted explicitly.
    auto_join_domains: list[str] = Field(default_factory=list)
    # Exactly one organization in a real deployment should ever set this:
    # the seeded demo tenant. Grants "member" (never higher, regardless of
    # any other configuration) to any authenticated identity that
    # explicitly chose the "view live demo" entry point - never a silent
    # side effect of an ordinary login landing on this org by coincidence.
    public_demo_auto_join: bool = False


class User(BaseModel):
    """One human, identified by a stable hash of their IdP identity - not
    by email, which can be reassigned or changed at the IdP."""

    user_id: str                           # sha256(f"{issuer}|{sub}")[:24]
    email: str
    display_name: str
    created_at: datetime = Field(default_factory=now)
    last_login_at: datetime = Field(default_factory=now)


class Membership(BaseModel):
    """One (user, org) grant. A user with memberships in several orgs is
    simply several of these rows - the multi-org case needs no separate
    modelling."""

    membership_id: str                     # f"{user_id}__{org_id}"
    user_id: str
    org_id: str
    role: MembershipRole
    status: MembershipStatus = "active"
    invited_by: Optional[str] = None       # user_id, None for the founding admin
    created_at: datetime = Field(default_factory=now)


class Invitation(BaseModel):
    """A pending grant, redeemable by whoever authenticates with the
    invited email address. `token_hash` only - the same digest-not-secret
    pattern MORTEMTRACE_API_TOKENS uses, so a Firestore export never hands
    out a live invite."""

    invitation_id: str
    org_id: str
    email: str                             # lowercased at creation
    role: MembershipRole
    invited_by: str                        # user_id
    token_hash: str
    status: InvitationStatus = "pending"
    created_at: datetime = Field(default_factory=now)
    expires_at: datetime
