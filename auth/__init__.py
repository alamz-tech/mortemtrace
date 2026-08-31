"""Caller authentication and tenant resolution.

Separate from data/scope_store.py on purpose: scope_store answers
"may agent X touch collection Y for tenant Z", which is *authorization*
and was always implemented correctly. This package answers the question
that sat above it and had no implementation at all - "is this caller
actually entitled to act as tenant Z" - which is *authentication*.

Signing an org claim (scope_store.sign_claim) gives integrity to a value;
it never established where that value came from. Until this package
existed, `org_id` arrived as an HTTP form field or query parameter and
was signed as-is, so any caller could name any tenant.
"""
