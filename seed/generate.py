"""Synthetic demo data for MortemTrace: services, customers, and three
active incidents.

Run via `python -m infra.seed_data` (thin wrapper around `main()` here).

Every record is built through its real Pydantic model (data/models.py)
and validated before it's written - a seed script that writes a dict
that wouldn't pass the same validation every agent's output has to pass
would be lying about what the system actually accepts. Writes go through
`scope_store.bootstrap_write()`, the unauthenticated path documented for
exactly this purpose (one-time environment init, before any registry
identity could plausibly own write scope across every collection this
touches).

IDs are deterministic (`svc_checkout_api`, not `new_id("svc")`), so
re-running this script overwrites the same documents instead of
duplicating them.

Data sources, stated honestly (SPEC-postmortem.md section 9): the one
alert-shaped RawEvidence payload below follows PagerDuty's public
webhook payload shape as a structural reference. Nothing else here is
modeled on a specific public schema. All content - service names,
customer names, log lines, incident narratives - is synthetic, invented
for this demo. No real customer data, logs, or credentials appear here.

The dependency chain and the first incident's affected service are
deliberately built to match Watcher's own default mock feed
(agents/watcher/watcher.py's `_poll_mock_feed`, signal
provider="aws"/service="rds") with no signal injection required:
checkout-api -> orders-db -> rds is a two-hop chain, landing exactly at
Watcher's `_MAX_DEPENDENCY_DEPTH`. The other two incidents' services
have no relationship to any of the three mock signals (rds,
stripe-sdk, openssl), so a plain sweep with no injected_signal
correlates incident 1 only - the exact live demo beat (SPEC section 10,
beat 5), not just a test fixture for it.
"""
from __future__ import annotations

import json
from datetime import timedelta

from data import scope_store
from data.models import (
    Classification,
    Collection,
    Customer,
    Incident,
    IncidentEvent,
    RawEvidence,
    Service,
    SlaTerms,
    Timeline,
    TimelineEntry,
    now,
)

DEMO_ORG_ID_DEFAULT = "org_demo"


# --------------------------------------------------------------------------
# Services - the dependency graph Watcher correlates against
# --------------------------------------------------------------------------

def _services(org_id: str) -> list[Service]:
    return [
        Service(
            service_id="svc_checkout_api", org_id=org_id, name="checkout-api",
            owner_team="commerce", depends_on=["svc_orders_db"], criticality="critical",
        ),
        Service(
            service_id="svc_orders_db", org_id=org_id, name="orders-db",
            owner_team="commerce", depends_on=["rds"], criticality="high",
            # "rds" is deliberately not its own Service document - it's an
            # external AWS resource our own service depends on, and
            # Watcher's dependency walk matches on the raw depends_on
            # identifier string, not a resolved Service record (see
            # agents/watcher/watcher.py's _find_match_chain).
        ),
        Service(
            service_id="svc_search_api", org_id=org_id, name="search-api",
            owner_team="discovery", depends_on=["svc_elasticsearch"], criticality="medium",
        ),
        Service(
            service_id="svc_elasticsearch", org_id=org_id, name="elasticsearch",
            owner_team="platform", depends_on=[], criticality="medium",
        ),
        Service(
            service_id="svc_billing_service", org_id=org_id, name="billing-service",
            owner_team="finance-eng", depends_on=[], criticality="high",
        ),
    ]


# --------------------------------------------------------------------------
# Customers
# --------------------------------------------------------------------------

def _customers(org_id: str) -> list[Customer]:
    return [
        Customer(
            customer_id="cust_acme", org_id=org_id, name="Acme Corp",
            sla_terms=SlaTerms(uptime_target=0.999, credit_rate=750.0),
            data_region="us", services_subscribed=["checkout-api", "orders-db"],
        ),
        Customer(
            customer_id="cust_globex", org_id=org_id, name="Globex Retail",
            sla_terms=SlaTerms(uptime_target=0.995, credit_rate=250.0),
            data_region="eu", services_subscribed=["search-api"],
        ),
        Customer(
            customer_id="cust_initech", org_id=org_id, name="Initech",
            sla_terms=SlaTerms(uptime_target=0.995, credit_rate=400.0),
            data_region="us", services_subscribed=["checkout-api", "billing-service"],
        ),
    ]


# --------------------------------------------------------------------------
# Incident 1 - the rich one: full evidence trail, committed timeline,
# data-touching classification. Matches Watcher's default sweep. Also
# doubles as a pre-processed fallback to browse in the console if a live
# demo run hits a snag.
# --------------------------------------------------------------------------

_PAGERDUTY_SHAPED_ALERT = json.dumps({
    "event": "trigger",
    "incident": {
        "id": "PD-SEED-001",
        "title": "checkout-api: elevated 5xx rate on /checkout",
        "urgency": "high",
        "service": {"name": "checkout-api"},
    },
    "messages": [
        {"type": "trigger", "log_entries": [{"summary": "5xx rate above threshold (12% over 5m)"}]},
    ],
}, indent=2)

_LOG_LINE = (
    "2026-08-24T21:14:03Z checkout-api ERROR db.orders_db connection pool "
    "exhausted, 0/20 connections available, upstream=rds.us-east-1"
)


def _incident_1_bundle(claim_org: str):
    incident = Incident(
        incident_id="inc_seed_checkout_outage", org_id=claim_org,
        opened_at=now() - timedelta(hours=6), status="open", severity="sev1",
        services_affected=["checkout-api"], alert_source="pagerduty",
    )

    raw_alert = RawEvidence(
        event_id="eventraw_seed_alert_1", org_id=claim_org, incident_ref=incident.incident_id,
        kind="alert", payload=_PAGERDUTY_SHAPED_ALERT, received_at=incident.opened_at,
    )
    raw_log = RawEvidence(
        event_id="eventraw_seed_log_1", org_id=claim_org, incident_ref=incident.incident_id,
        kind="log", payload=_LOG_LINE, received_at=incident.opened_at + timedelta(minutes=3),
    )

    event_alert = IncidentEvent(
        event_id="evt_seed_alert_1", org_id=claim_org, incident_ref=incident.incident_id,
        status="committed", confidence=0.92,
        extracted={"action": "checkout-api 5xx rate spiked above threshold"},
        ts=raw_alert.received_at, source_ref=raw_alert.event_id,
    )
    event_log = IncidentEvent(
        event_id="evt_seed_log_1", org_id=claim_org, incident_ref=incident.incident_id,
        status="committed", confidence=0.88,
        extracted={"action": "orders-db connection pool exhausted, upstream RDS involved"},
        ts=raw_log.received_at, source_ref=raw_log.event_id,
    )

    timeline = Timeline(
        incident_id=incident.incident_id, org_id=claim_org,
        entries=[
            TimelineEntry(
                ts=event_alert.ts, actor="pagerduty", action=event_alert.extracted["action"],
                evidence="5xx rate above threshold (12% over 5m) on /checkout",
                source_event_ids=[event_alert.event_id],
            ),
            TimelineEntry(
                ts=event_log.ts, actor="checkout-api", action=event_log.extracted["action"],
                evidence=_LOG_LINE,
                source_event_ids=[event_log.event_id],
            ),
        ],
        last_updated=event_log.ts,
    )

    classification = Classification(
        incident_id=incident.incident_id, org_id=claim_org,
        severity="sev1", services=["checkout-api", "orders-db"],
        downtime_windows=[{
            "start": incident.opened_at.isoformat(), "end": None, "services": ["checkout-api"],
        }],
        data_touched=True, data_categories=["payment_card", "customer_pii"],
    )

    return incident, [raw_alert, raw_log], [event_alert, event_log], timeline, classification


# --------------------------------------------------------------------------
# Incidents 2 and 3 - lighter: prove severity/data-touched variance and
# give Watcher two genuinely unrelated active incidents to leave untouched.
# --------------------------------------------------------------------------

def _incident_2_bundle(claim_org: str):
    incident = Incident(
        incident_id="inc_seed_search_degraded", org_id=claim_org,
        opened_at=now() - timedelta(hours=2), status="open", severity="sev3",
        services_affected=["search-api"], alert_source="datadog",
    )
    classification = Classification(
        incident_id=incident.incident_id, org_id=claim_org,
        severity="sev3", services=["search-api"],
        downtime_windows=[{"start": incident.opened_at.isoformat(), "end": None, "services": ["search-api"]}],
        data_touched=False, data_categories=[],
    )
    return incident, classification


def _incident_3_bundle(claim_org: str):
    incident = Incident(
        incident_id="inc_seed_billing_delay", org_id=claim_org,
        opened_at=now() - timedelta(hours=1), status="open", severity="sev2",
        services_affected=["billing-service"], alert_source="datadog",
    )
    classification = Classification(
        incident_id=incident.incident_id, org_id=claim_org,
        severity="sev2", services=["billing-service"],
        downtime_windows=[{"start": incident.opened_at.isoformat(), "end": None, "services": ["billing-service"]}],
        data_touched=False, data_categories=[],
    )
    return incident, classification


# --------------------------------------------------------------------------
# Write
# --------------------------------------------------------------------------

def generate(org_id: str = DEMO_ORG_ID_DEFAULT) -> dict:
    written = {"services": 0, "customers": 0, "incidents": 0, "raw_evidence": 0, "events": 0,
               "timelines": 0, "classifications": 0}

    for service in _services(org_id):
        scope_store.bootstrap_write(Collection.SERVICES, service.service_id, service.model_dump(mode="json"), org_id=org_id)
        written["services"] += 1

    for customer in _customers(org_id):
        scope_store.bootstrap_write(Collection.CUSTOMERS, customer.customer_id, customer.model_dump(mode="json"), org_id=org_id)
        written["customers"] += 1

    incident_1, raw_list, event_list, timeline, classification_1 = _incident_1_bundle(org_id)
    scope_store.bootstrap_write(Collection.INCIDENTS, incident_1.incident_id, incident_1.model_dump(mode="json"), org_id=org_id)
    written["incidents"] += 1
    for raw in raw_list:
        scope_store.bootstrap_write(Collection.RAW_EVIDENCE, raw.event_id, raw.model_dump(mode="json"), org_id=org_id)
        written["raw_evidence"] += 1
    for event in event_list:
        scope_store.bootstrap_write(Collection.EVENTS, event.event_id, event.model_dump(mode="json"), org_id=org_id)
        written["events"] += 1
    scope_store.bootstrap_write(Collection.TIMELINE, incident_1.incident_id, timeline.model_dump(mode="json"), org_id=org_id)
    written["timelines"] += 1
    scope_store.bootstrap_write(Collection.CLASSIFICATION, incident_1.incident_id, classification_1.model_dump(mode="json"), org_id=org_id)
    written["classifications"] += 1

    for bundle_fn in (_incident_2_bundle, _incident_3_bundle):
        incident, classification = bundle_fn(org_id)
        scope_store.bootstrap_write(Collection.INCIDENTS, incident.incident_id, incident.model_dump(mode="json"), org_id=org_id)
        written["incidents"] += 1
        scope_store.bootstrap_write(Collection.CLASSIFICATION, incident.incident_id, classification.model_dump(mode="json"), org_id=org_id)
        written["classifications"] += 1

    return written


def main() -> None:
    import os

    org_id = os.environ.get("MORTEMTRACE_DEMO_ORG", DEMO_ORG_ID_DEFAULT)
    summary = generate(org_id)
    print(f"seeded demo org: {org_id}")
    for key, count in summary.items():
        print(f"  {key}: {count}")
    print(
        "\nincidents: inc_seed_checkout_outage (sev1, data_touched=True, "
        "services_affected=[checkout-api] -> orders-db -> rds, matches "
        "Watcher's default sweep), inc_seed_search_degraded (sev3, "
        "data_touched=False, unrelated), inc_seed_billing_delay (sev2, "
        "data_touched=False, unrelated)."
    )


if __name__ == "__main__":
    main()
