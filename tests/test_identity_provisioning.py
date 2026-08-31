"""Tests for the human identity/organization/membership functions in
data/scope_store.py, and for auth/provisioning.py's login-time
auto-join rules.

This is the layer that decides which organization a real person may act
as - a defect here is a cross-tenant access bug of exactly the kind
tests/test_scope_store.py's R5/R7 tests exist to catch for the agent
side, so the same rigor applies: verify the denial, not just the allow.
"""
from __future__ import annotations

import pytest

from auth import oidc, provisioning
from data import scope_store

# --------------------------------------------------------------------------
# Organization creation
# --------------------------------------------------------------------------

def test_create_organization_makes_creator_an_admin(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")

    membership = scope_store.get_membership("user_founder", org["org_id"])
    assert membership is not None
    assert membership["role"] == "admin"


def test_create_organization_is_atomic_org_and_membership_together(fake_db):
    """The whole point of doing this in one transaction: an organization
    must never exist with zero members able to administer it."""
    org = scope_store.create_organization("Acme Inc.", "user_founder")

    assert scope_store.get_organization(org["org_id"]) is not None
    assert scope_store.list_memberships_for_org(org["org_id"]) != []


def test_users_can_belong_to_more_than_one_organization(fake_db):
    org_a = scope_store.create_organization("Org A", "user_multi")
    org_b = scope_store.create_organization("Org B", "user_multi")

    memberships = scope_store.list_memberships_for_user("user_multi")
    org_ids = {m["org_id"] for m in memberships}
    assert org_ids == {org_a["org_id"], org_b["org_id"]}


# --------------------------------------------------------------------------
# Admin enforcement - every mutating membership/SSO action re-checks a
# live Membership row, never trusting the caller's say-so.
# --------------------------------------------------------------------------

def test_member_cannot_invite(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_admin")
    scope_store.create_membership("user_regular", org["org_id"], "member")

    with pytest.raises(scope_store.PermissionDenied):
        scope_store.create_invitation("user_regular", org["org_id"], "new@acme.com", "member")


def test_member_cannot_revoke_another_member(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_admin")
    scope_store.create_membership("user_regular", org["org_id"], "member")
    scope_store.create_membership("user_victim", org["org_id"], "member")

    with pytest.raises(scope_store.PermissionDenied):
        scope_store.revoke_membership("user_regular", org["org_id"], "user_victim")


def test_admin_of_a_different_org_cannot_administer_this_one(fake_db):
    """The most important case: being an admin somewhere does not make
    you an admin everywhere."""
    scope_store.create_organization("Org A", "user_admin_a")
    org_b = scope_store.create_organization("Org B", "user_admin_b")

    with pytest.raises(scope_store.PermissionDenied):
        scope_store.create_invitation("user_admin_a", org_b["org_id"], "new@example.com", "member")


def test_revoked_admin_immediately_loses_admin_actions(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    scope_store.create_membership("user_second_admin", org["org_id"], "admin")
    scope_store.revoke_membership("user_founder", org["org_id"], "user_second_admin")

    with pytest.raises(scope_store.PermissionDenied):
        scope_store.create_invitation("user_second_admin", org["org_id"], "new@example.com", "member")


def test_cannot_revoke_the_last_admin(fake_db):
    """A lockout guard, not a security boundary: nothing is gained by an
    attacker here - the org would simply become unadministerable by
    anyone, including the admin who just did it."""
    org = scope_store.create_organization("Acme Inc.", "user_only_admin")

    with pytest.raises(scope_store.LastAdminError):
        scope_store.revoke_membership("user_only_admin", org["org_id"], "user_only_admin")

    assert scope_store.get_membership("user_only_admin", org["org_id"]) is not None


def test_cannot_demote_the_last_admin(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_only_admin")

    with pytest.raises(scope_store.LastAdminError):
        scope_store.update_membership_role("user_only_admin", org["org_id"], "user_only_admin", "member")


def test_can_revoke_an_admin_when_another_admin_remains(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_admin_a")
    scope_store.create_membership("user_admin_b", org["org_id"], "admin")

    scope_store.revoke_membership("user_admin_a", org["org_id"], "user_admin_b")  # must not raise

    assert scope_store.get_membership("user_admin_b", org["org_id"]) is None


def test_revoked_member_excluded_from_active_membership_list(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    scope_store.create_membership("user_leaving", org["org_id"], "member")
    scope_store.revoke_membership("user_founder", org["org_id"], "user_leaving")

    assert scope_store.get_membership("user_leaving", org["org_id"]) is None
    active = {m["user_id"] for m in scope_store.list_memberships_for_user("user_leaving")}
    assert org["org_id"] not in active
    # ... but still visible on the admin's roster, as a former member.
    roster = {m["user_id"]: m for m in scope_store.list_memberships_for_org(org["org_id"])}
    assert roster["user_leaving"]["status"] == "revoked"


# --------------------------------------------------------------------------
# Invitations
# --------------------------------------------------------------------------

def test_invitation_redemption_grants_the_configured_role(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    invitation, token = scope_store.create_invitation(
        "user_founder", org["org_id"], "new@acme.com", "admin",
    )

    found = scope_store.find_invitation_by_token(token)
    assert found is not None
    assert found["invitation_id"] == invitation["invitation_id"]

    membership = scope_store.redeem_invitation(invitation["invitation_id"], "user_new")
    assert membership["role"] == "admin"
    assert scope_store.get_membership("user_new", org["org_id"]) is not None


def test_invitation_cannot_be_redeemed_twice(fake_db):
    """Race-safety: a double click, or two tabs, must not both succeed -
    tested at the API level in tests/test_concurrency.py's spirit, here
    at the direct redeem_invitation() boundary."""
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    invitation, _token = scope_store.create_invitation(
        "user_founder", org["org_id"], "new@acme.com", "member",
    )

    scope_store.redeem_invitation(invitation["invitation_id"], "user_first")
    with pytest.raises(ValueError):
        scope_store.redeem_invitation(invitation["invitation_id"], "user_second")


def test_wrong_token_does_not_find_an_invitation(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    scope_store.create_invitation("user_founder", org["org_id"], "new@acme.com", "member")

    assert scope_store.find_invitation_by_token("not-the-real-token") is None


def test_expired_invitation_is_not_found(fake_db, monkeypatch):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    monkeypatch.setattr(scope_store, "_INVITATION_TTL", __import__("datetime").timedelta(seconds=-1))
    _invitation, token = scope_store.create_invitation(
        "user_founder", org["org_id"], "new@acme.com", "member",
    )

    assert scope_store.find_invitation_by_token(token) is None


# --------------------------------------------------------------------------
# auth/provisioning.py - login-time auto-join rules
# --------------------------------------------------------------------------

def _identity(email: str, *, invite_token=None, demo=False) -> oidc.VerifiedIdentity:
    return oidc.VerifiedIdentity(
        issuer="https://accounts.google.com", subject="sub-" + email,
        email=email, display_name=email, invite_token=invite_token, demo=demo,
    )


def test_login_with_no_matching_anything_lands_with_zero_memberships(fake_db):
    outcome = provisioning.resolve_login(_identity("nobody@nowhere.example"))
    assert outcome.memberships == []
    assert outcome.landed_org_id is None


def test_domain_auto_join_grants_member_not_admin(fake_db):
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    scope_store.get_organization(org["org_id"])
    fake_db.seed(f"organizations/{org['org_id']}", {**org, "auto_join_domains": ["acme.com"]})

    outcome = provisioning.resolve_login(_identity("newhire@acme.com"))

    assert outcome.landed_org_id == org["org_id"]
    assert scope_store.get_membership(outcome.user_id, org["org_id"])["role"] == "member"


def test_domain_auto_join_does_not_match_a_lookalike_domain(fake_db):
    """acme.com.evil.example must not match an auto_join_domains entry
    of "acme.com" - a naive substring/suffix check would be exploitable
    by anyone able to register a lookalike domain."""
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    fake_db.seed(f"organizations/{org['org_id']}", {**org, "auto_join_domains": ["acme.com"]})

    outcome = provisioning.resolve_login(_identity("attacker@acme.com.evil.example"))

    assert outcome.memberships == []


def test_public_demo_auto_join_requires_the_explicit_demo_flag(fake_db):
    """An ordinary login (demo=False) must NEVER land in the demo org,
    even though one exists and is flagged - only the explicit
    "view live demo" entry point (demo=True) may."""
    demo_org = scope_store.create_organization("Demo Org", "user_founder")
    fake_db.seed(f"organizations/{demo_org['org_id']}", {**demo_org, "public_demo_auto_join": True})

    ordinary = provisioning.resolve_login(_identity("someone@personal-email.example", demo=False))
    assert ordinary.memberships == []

    demo_visitor = provisioning.resolve_login(_identity("judge@personal-email.example", demo=True))
    assert demo_visitor.landed_org_id == demo_org["org_id"]
    assert scope_store.get_membership(demo_visitor.user_id, demo_org["org_id"])["role"] == "member"


def test_invite_redemption_requires_matching_email(fake_db):
    """Possessing an invite link is not proof of identity - only the
    person who authenticates AS the invited email may redeem it."""
    org = scope_store.create_organization("Acme Inc.", "user_founder")
    _invitation, token = scope_store.create_invitation(
        "user_founder", org["org_id"], "intended@acme.com", "member",
    )

    wrong_person = provisioning.resolve_login(_identity("attacker@elsewhere.example", invite_token=token))
    assert wrong_person.memberships == []

    right_person = provisioning.resolve_login(_identity("intended@acme.com", invite_token=token))
    assert right_person.landed_org_id == org["org_id"]


def test_login_outcome_never_guesses_among_multiple_orgs():
    """landed_org_id must be None, not an arbitrary pick, whenever more
    than one membership exists - the console route decides what to do
    with ambiguity (default view + a switcher), but resolve_login itself
    must never silently choose on the caller's behalf."""
    outcome = provisioning.LoginOutcome(
        user_id="user_x", email="x@example.com",
        memberships=[{"org_id": "org_a"}, {"org_id": "org_b"}],
    )
    assert outcome.landed_org_id is None


def test_login_outcome_lands_directly_when_exactly_one_membership():
    outcome = provisioning.LoginOutcome(
        user_id="user_x", email="x@example.com", memberships=[{"org_id": "org_a"}],
    )
    assert outcome.landed_org_id == "org_a"
