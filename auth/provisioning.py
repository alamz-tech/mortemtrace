"""Turns a freshly-verified OIDC identity into org membership: resolves
or creates the User record, and applies any pending invitation or
domain/demo auto-join rule.

Sits between auth/oidc.py (verifies who someone is) and console/ui.py
(the HTTP layer) - the business rules for "what happens the first time
this person logs in" live here as one unit, not scattered across the
callback route.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from auth import oidc
from data import scope_store


@dataclass(frozen=True)
class LoginOutcome:
    user_id: str
    email: str
    memberships: list[dict]

    @property
    def landed_org_id(self) -> Optional[str]:
        """Where to send the browser right after login, if unambiguous.
        None means: show the org picker/creation screen - never guess
        which of several orgs, or invent one, on the caller's behalf."""
        return self.memberships[0]["org_id"] if len(self.memberships) == 1 else None


def resolve_login(identity: oidc.VerifiedIdentity) -> LoginOutcome:
    user_id = oidc.stable_user_id(identity.issuer, identity.subject)
    scope_store.upsert_user(user_id, email=identity.email, display_name=identity.display_name)

    # Each of these is independently idempotent (checks for an existing
    # membership before creating one), so all three can run unconditionally
    # without needing to reason about ordering between them - a user
    # redeeming a partner's invite and separately belonging to their own
    # company's SSO-verified domain are not mutually exclusive.
    if identity.invite_token:
        _redeem_invite_if_valid(identity.invite_token, identity, user_id)
    if identity.demo:
        _join_public_demo(user_id)
    _apply_domain_auto_join(identity.email, user_id)

    memberships = scope_store.list_memberships_for_user(user_id)
    return LoginOutcome(user_id=user_id, email=identity.email, memberships=memberships)


def _redeem_invite_if_valid(token: str, identity: oidc.VerifiedIdentity, user_id: str) -> None:
    invitation = scope_store.find_invitation_by_token(token)
    if invitation is None:
        return  # expired, revoked, already redeemed, or simply wrong - not fatal
    if invitation["email"] != identity.email:
        # The invite was issued to a specific email address. Possessing
        # the link is not proof of identity - a forwarded or leaked link
        # must not let a different person redeem someone else's invite.
        return
    try:
        scope_store.redeem_invitation(invitation["invitation_id"], user_id)
    except ValueError:
        pass  # redeemed/revoked by someone else between the lookup and here


def _join_public_demo(user_id: str) -> None:
    demo_org = scope_store.find_public_demo_organization()
    if demo_org is None:
        return
    if scope_store.get_membership(user_id, demo_org["org_id"]) is None:
        scope_store.create_membership(user_id, demo_org["org_id"], role="member")


def _apply_domain_auto_join(email: str, user_id: str) -> None:
    domain = email.rsplit("@", 1)[-1] if "@" in email else ""
    if not domain:
        return
    org = scope_store.find_organization_by_domain(domain)
    if org is None:
        return
    if scope_store.get_membership(user_id, org["org_id"]) is None:
        scope_store.create_membership(user_id, org["org_id"], role="member")
