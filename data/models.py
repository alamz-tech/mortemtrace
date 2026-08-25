"""Shared data schemas for MortemTrace.

Every Firestore document and Pub/Sub payload in the system is validated
against one of these models before it is written or acted on. Agents
never construct ad-hoc dicts for persisted state; schema drift is caught
here, at the boundary, and routed to dead-letter rather than coerced.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


def now() -> datetime:
    return datetime.now(timezone.utc)


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
RunStatus = Literal["running", "completed", "failed", "blocked", "denied", "quarantined"]
AlertType = Literal["classified", "blocked", "denied", "quarantine"]
AgentStatus = Literal["published", "deprecated"]


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


class DeadLetter(BaseModel):
    original_topic: str
    run_id: str
    org_id: str
    reason: str
    payload: dict
    attempt_count: int = 0
    failed_at: datetime = Field(default_factory=now)
