"""Sets (or clears) an organization's email-domain routing hint for SSO -
the value that sends someone typing "name@acme.com" at /login straight to
Acme's own IdP instead of Google Sign-In.

    python -m infra.set_sso_domain_hint --org org_acme --domain acme.com
    python -m infra.set_sso_domain_hint --org org_acme --clear

Deliberately an offline, operator-run script and NOT a field on the
console's self-service /orgs/{org_id}/sso form. Found in a security self-
review: org creation is open to anyone with a Google account
(console/ui.py's /onboarding), and domain_hint was previously admin-
settable through that same self-service form with no proof the claiming
org actually owns the domain - so a self-registered admin could claim
any company's domain and capture that company's employees' login
attempts. This script doesn't add domain-ownership verification either
(a DNS TXT challenge is the real fix, not yet built) - what it does add
is a much smaller blast radius: only someone who already has direct
Firestore/gcloud access to this project can set a hint at all, the same
trust level infra/reset_demo_org.py and infra/mint_token.py already
assume. Confirm you actually control the domain before running this.

Refuses to run if the domain is already claimed by a DIFFERENT org - the
same collision the self-service form could previously create silently.
"""
from __future__ import annotations

import argparse
import re
import sys

sys.path.insert(0, ".")

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Set or clear an organization's SSO domain_hint.")
    parser.add_argument("--org", required=True, help="org_id to update")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain", help="the email domain to route to this org's SSO, e.g. acme.com")
    group.add_argument("--clear", action="store_true", help="remove the domain hint")
    args = parser.parse_args()

    from data import scope_store

    org = scope_store.get_organization(args.org)
    if org is None:
        parser.error(f"no such organization: {args.org}")

    if args.clear:
        domain = None
    else:
        domain = args.domain.strip().lower()
        if not _DOMAIN_RE.match(domain):
            parser.error(f"{domain!r} doesn't look like a valid domain")
        existing = scope_store.find_organization_by_sso_domain_hint(domain)
        if existing is not None and existing["org_id"] != args.org:
            parser.error(
                f"{domain!r} is already claimed by {existing['org_id']!r} "
                f"({existing.get('display_name')!r}) - clear it there first if this is deliberate"
            )

    sso = dict(org.get("sso") or {})
    if not sso and domain is not None:
        parser.error(
            f"{args.org} has no SSO issuer/client_id configured yet - "
            "set that up via the console's /orgs/{org_id}/sso page first"
        )
    sso["domain_hint"] = domain

    # Direct Firestore write, not scope_store.set_organization_sso(): that
    # function requires a real admin membership (_require_admin), which
    # an offline operator script correctly has no way to hold - the same
    # reasoning infra/reset_demo_org.py and infra/init_firestore.py's own
    # bootstrap writes already document. Whoever can run this script
    # already has direct gcloud/Firestore access to the project, which is
    # the actual trust boundary here, not an application-level role.
    org_ref = scope_store._client().collection(scope_store._ORGANIZATIONS_ROOT).document(args.org)
    data = org_ref.get().to_dict()
    data["sso"] = sso if sso.get("issuer") else None
    org_ref.set(data)
    print(f"org {args.org}: domain_hint = {domain!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
