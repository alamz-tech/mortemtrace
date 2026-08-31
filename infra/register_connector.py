"""Registers an inbound webhook connector.

    # From a preset
    python infra/register_connector.py --org org_demo --preset github-actions

    # Fully custom - any tool, no preset needed
    python infra/register_connector.py --org org_demo \\
        --name "Grafana prod" --source grafana --strategy hmac \\
        --header X-Grafana-Signature

    # A tool that cannot sign (the URL becomes the credential)
    python infra/register_connector.py --org org_demo \\
        --name "Legacy cron" --source cron --strategy none

Prints the webhook URL and, for signed strategies, a generated signing
secret to add to MORTEMTRACE_CONNECTOR_SECRETS. The secret is shown once.

Presets are DATA (connectors/presets/*.json), not code. Supporting a new
tool means adding a JSON file - or passing the flags above and adding
nothing at all. That is the whole point of the design: a customer's tool
never needs us to ship a release.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import secrets
import sys

from data import scope_store
from data.models import ConnectorConfig, VerificationConfig, new_id

_PRESET_DIR = pathlib.Path(__file__).resolve().parent.parent / "connectors" / "presets"


def _load_preset(name: str) -> dict:
    path = _PRESET_DIR / f"{name}.json"
    if not path.exists():
        available = sorted(p.stem for p in _PRESET_DIR.glob("*.json"))
        raise SystemExit(f"no preset {name!r}. Available: {', '.join(available)}")
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description="Register an inbound webhook connector.")
    parser.add_argument("--org", required=True)
    parser.add_argument("--preset", help=f"one of: {', '.join(sorted(p.stem for p in _PRESET_DIR.glob('*.json')))}")
    parser.add_argument("--name")
    parser.add_argument("--source")
    parser.add_argument("--kind", default="alert", choices=["alert", "log", "screenshot", "slack"])
    parser.add_argument("--change-source", action="store_true",
                        help="payloads become change events (deploys) instead of incident evidence")
    parser.add_argument("--strategy", choices=["hmac", "bearer", "ip_allowlist", "none"])
    parser.add_argument("--header")
    parser.add_argument("--prefix")
    parser.add_argument("--allowed-ip", action="append", default=[])
    parser.add_argument("--base-url", default="<ingest-url>",
                        help="deployed ingest URL, used only to print a copy-pasteable webhook URL")
    args = parser.parse_args()

    preset = _load_preset(args.preset) if args.preset else {}
    preset.pop("_setup", None)

    name = args.name or preset.get("name")
    source = args.source or preset.get("source")
    if not name or not source:
        parser.error("--name and --source are required unless --preset supplies them")

    verification = dict(preset.get("verification", {}))
    if args.strategy:
        verification["strategy"] = args.strategy
    if args.header:
        verification["header"] = args.header
    if args.prefix:
        verification["prefix"] = args.prefix
    if args.allowed_ip:
        verification["allowed_ips"] = args.allowed_ip
    verification.setdefault("strategy", "hmac")

    connector_id = new_id("conn")
    secret = None
    if verification["strategy"] in ("hmac", "bearer"):
        verification["secret_ref"] = connector_id
        secret = secrets.token_urlsafe(32)

    config = ConnectorConfig(
        connector_id=connector_id,
        org_id=args.org,
        name=name,
        source=source,
        kind=args.kind or preset.get("kind", "alert"),
        is_change_source=args.change_source or bool(preset.get("is_change_source")),
        verification=VerificationConfig(**verification),
    )

    scope_store.bootstrap_connector_write(connector_id, config.model_dump(mode="json"))

    print(f"\nRegistered connector {connector_id} for tenant {args.org}")
    print(f"  name         : {config.name}")
    print(f"  source       : {config.source}")
    print(f"  routes to    : {'change_events (deploy history)' if config.is_change_source else 'incident evidence pipeline'}")
    print(f"  verification : {config.verification.strategy}")
    print(f"\nWebhook URL (give this to the tool):\n  {args.base_url}/webhook/{connector_id}\n")

    if secret:
        digest_note = "signs the raw body" if config.verification.strategy == "hmac" else "sent as a token header"
        print(f"Signing secret ({digest_note}) - shown once:\n  {secret}\n")
        print("Add it to MORTEMTRACE_CONNECTOR_SECRETS:")
        print(json.dumps({connector_id: secret}, indent=2))
        print(f"\n  (sha256 for reference: {hashlib.sha256(secret.encode()).hexdigest()[:16]}...)")
    else:
        print("!! strategy='none': this webhook is UNSIGNED.")
        print("!! The URL above is the only credential - anyone who learns it can")
        print("!! inject events for this tenant. Use only for tools that cannot sign,")
        print("!! and prefer 'bearer' or 'ip_allowlist' where the tool supports either.")

    if args.preset:
        setup = _load_preset(args.preset).get("_setup", [])
        if setup:
            print("\nSetup steps:")
            for step in setup:
                print(f"  {step.replace('<ingest-url>', args.base_url).replace('<connector_id>', connector_id)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
