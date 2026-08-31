"""Wipe a demo tenant's incident data back to a clean, presentable state.

    python -m infra.reset_demo_org --org org_demo --dry-run
    python -m infra.reset_demo_org --org org_demo --confirm

Why this exists: a tenant used for live testing accumulates artifacts
that are indistinguishable, to anyone who wasn't there, from bugs -
half-finished incidents from a deploy that was mid-rollout, deliberately
blocked injection probes with no drafts, evidence strings like
"final-timing-4: quick check". Someone evaluating the system reads that
pile as broken rather than as debugging residue.

SAFETY. This deletes data irreversibly, so it is deliberately awkward to
point at the wrong place:

  * It refuses to run against an organization that is not explicitly
    marked as a demo tenant (`public_demo_auto_join`), unless
    --i-know-this-is-not-a-demo-org is passed. The failure mode this
    guards against - running it against a real customer tenant because
    an env var was set from a previous shell - destroys data that has no
    backup.
  * It requires --confirm. Without it, --dry-run behaviour is the
    default: it reports what it *would* delete and exits.
  * It never touches the global /registry collection, which is not
    tenant-scoped: wiping that would unpublish every agent for every
    org, not just this one.

By default it PRESERVES `audit` and `runs`. Those are the governance
trail the product is partly about, they carry no incident content
themselves (only path strings and status), and keeping them means the
audit page still demonstrates real scope denials after a reset. Pass
--include-history to drop them too.
"""
from __future__ import annotations

import argparse
import sys

from data import scope_store

# Everything derived from ingesting and reasoning about an incident.
# Order is irrelevant (no referential integrity in Firestore), but it is
# grouped by pipeline stage to stay readable as the schema grows.
_INCIDENT_SCOPED = [
    "incidents", "raw_evidence", "events", "timeline", "hypotheses",
    "classification", "drafts", "clocks", "alerts", "change_events",
    # Signals are Watcher's polled upstream-status feed. Not incident
    # scoped, but they accumulate every sweep and a stale backlog produces
    # correlations against incidents that no longer exist.
    "signals",
    # Idempotency markers keyed by run_id. Retaining them after the runs
    # they refer to are gone serves no purpose and would suppress a
    # legitimate replay that happened to reuse an id.
    "_idempotency",
]

# Reference data seed/generate.py rewrites deterministically anyway.
_REFERENCE = ["services", "customers"]

# The governance trail. Preserved by default - see module docstring.
_HISTORY = ["audit", "runs"]

# Identity. NEVER wiped by this script: memberships and users are how
# real people (including whoever is running this) get back in. Losing
# them would lock every existing member out of the tenant.
_NEVER_WIPE = {"members", "users", "organizations", "invitations"}


def _collection_counts(org_id: str, names: list[str]) -> dict[str, int]:
    client = scope_store._client()
    org_ref = client.collection("tenants").document(org_id)
    counts = {}
    for name in names:
        counts[name] = sum(1 for _ in org_ref.collection(name).stream())
    return counts


def _delete_collection(org_id: str, name: str, *, batch_size: int = 400) -> int:
    """Deletes every document in one tenant subcollection.

    Batched because Firestore caps a write batch at 500 operations;
    streaming the whole collection into one batch works right up until a
    demo tenant has been used enough to matter, then fails.
    """
    client = scope_store._client()
    coll = client.collection("tenants").document(org_id).collection(name)
    deleted = 0
    while True:
        docs = list(coll.limit(batch_size).stream())
        if not docs:
            return deleted
        batch = client.batch()
        for doc in docs:
            batch.delete(doc.reference)
        batch.commit()
        deleted += len(docs)


def _is_demo_org(org_id: str) -> bool:
    org = scope_store.get_organization(org_id)
    return bool(org and org.get("public_demo_auto_join"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Reset a demo tenant's incident data.")
    parser.add_argument("--org", required=True, help="tenant to reset")
    parser.add_argument("--confirm", action="store_true",
                        help="actually delete; without this, only reports what would go")
    parser.add_argument("--dry-run", action="store_true", help="explicit no-op (the default)")
    parser.add_argument("--include-history", action="store_true",
                        help="also wipe audit and runs (default: preserved)")
    parser.add_argument("--include-reference", action="store_true",
                        help="also wipe services and customers (seed rewrites these anyway)")
    parser.add_argument("--i-know-this-is-not-a-demo-org", action="store_true",
                        help="override the demo-tenant safety check")
    args = parser.parse_args()

    org_id = args.org
    if not _is_demo_org(org_id) and not args.i_know_this_is_not_a_demo_org:
        print(
            f"Refusing to reset {org_id!r}: it is not flagged public_demo_auto_join.\n"
            "This script deletes incident data irreversibly. If you genuinely mean to "
            "run it against this tenant, pass --i-know-this-is-not-a-demo-org.",
            file=sys.stderr,
        )
        return 2

    targets = list(_INCIDENT_SCOPED)
    if args.include_history:
        targets += _HISTORY
    if args.include_reference:
        targets += _REFERENCE

    overlap = _NEVER_WIPE.intersection(targets)
    if overlap:  # pragma: no cover - guards against a careless edit above
        print(f"Refusing to run: {sorted(overlap)} are identity collections.", file=sys.stderr)
        return 2

    counts = _collection_counts(org_id, targets)
    total = sum(counts.values())

    print(f"tenant: {org_id}")
    for name, n in counts.items():
        if n:
            print(f"  {name:20s} {n}")
    print(f"  {'TOTAL':20s} {total}")

    preserved = [c for c in _HISTORY if not args.include_history]
    if preserved:
        kept = _collection_counts(org_id, preserved)
        print("\npreserved:")
        for name, n in kept.items():
            print(f"  {name:20s} {n}")

    if not args.confirm:
        print("\nDry run - nothing deleted. Re-run with --confirm to apply.")
        return 0

    print("\ndeleting...")
    for name in targets:
        if counts.get(name):
            n = _delete_collection(org_id, name)
            print(f"  {name:20s} {n} deleted")

    print("\nDone. Now reseed:\n  MORTEMTRACE_SEED_PUBLIC_DEMO=1 python -m infra.seed_data")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
