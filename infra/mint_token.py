"""Mints an API token and prints the token table entry for it.

    python infra/mint_token.py --org org_demo --subject alice
    python infra/mint_token.py --org org_a --org org_b --subject ci-pipeline

Prints the plaintext token once (it is not recoverable from the stored
digest) and the JSON entry to merge into MORTEMTRACE_API_TOKENS.

Only the sha256 digest is ever persisted, so the configured secret is not
itself a usable credential if it is exposed - which matters because env
vars leak into process listings, crash dumps, and support bundles far
more readily than a dedicated credential store does.

With --merge-into, reads an existing token table on stdin and emits the
combined table, so adding a token never means hand-editing JSON:

    gcloud secrets versions access latest --secret=mortemtrace-api-tokens \\
      | python infra/mint_token.py --org org_demo --subject bob --merge-into - \\
      | gcloud secrets versions add mortemtrace-api-tokens --data-file=-
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import sys

_ORG_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def main() -> int:
    parser = argparse.ArgumentParser(description="Mint a MortemTrace API token.")
    # --org-id is an accepted alias: every other tenant-scoped flag and env
    # var in this repo spells it "org_id", so reaching for --org-id here is
    # the natural guess rather than a user error.
    parser.add_argument("--org", "--org-id", action="append", required=True, dest="orgs",
                        help="tenant this token may act as; repeat for multi-tenant access")
    parser.add_argument("--subject", required=True,
                        help="human-readable label for who holds this token (appears in logs)")
    parser.add_argument("--merge-into", metavar="PATH",
                        help="existing token table to merge into ('-' for stdin)")
    args = parser.parse_args()

    for org in args.orgs:
        if not _ORG_ID_RE.match(org):
            parser.error(
                f"invalid org id {org!r}: must match {_ORG_ID_RE.pattern} "
                "(it becomes a Firestore path segment)"
            )

    token = secrets.token_urlsafe(32)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    entry = {"org_ids": args.orgs, "subject": args.subject}

    if args.merge_into:
        raw = sys.stdin.read() if args.merge_into == "-" else open(args.merge_into).read()
        try:
            table = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError as exc:
            print(f"existing token table is not valid JSON: {exc}", file=sys.stderr)
            return 1
        if not isinstance(table, dict):
            print("existing token table must be a JSON object", file=sys.stderr)
            return 1
        table[digest] = entry
        # Token to stderr, table to stdout, so the table can be piped
        # straight into `gcloud secrets versions add` without the secret
        # ending up in the piped payload.
        print(f"\nToken for {args.subject} ({', '.join(args.orgs)}) - store it now:\n\n  {token}\n",
              file=sys.stderr)
        print(json.dumps(table, indent=2))
        return 0

    print("Token (shown once - it cannot be recovered from the digest):\n")
    print(f"  {token}\n")
    print("Add this entry to MORTEMTRACE_API_TOKENS:\n")
    print(json.dumps({digest: entry}, indent=2))
    print("\nUse as:  Authorization: Bearer <token>")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
