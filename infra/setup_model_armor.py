"""One-time setup: creates the Model Armor template gateway/model_armor.py
sanitizes against. Run once per environment:

    python -m infra.setup_model_armor

Idempotent - safe to re-run; skips creation if the template already exists.
"""
from __future__ import annotations

import os
import sys

from google.api_core.exceptions import AlreadyExists
from google.cloud import modelarmor_v1beta as ma

TEMPLATE_ID = os.environ.get("MODEL_ARMOR_TEMPLATE_ID", "mortemtrace-guardian")
LOCATION = os.environ.get("MODEL_ARMOR_LOCATION", "us-central1")


def main() -> None:
    project = os.environ.get("GOOGLE_CLOUD_PROJECT")
    if not project:
        print("GOOGLE_CLOUD_PROJECT is not set", file=sys.stderr)
        sys.exit(1)

    client = ma.ModelArmorClient(
        client_options={"api_endpoint": f"modelarmor.{LOCATION}.rep.googleapis.com"}
    )
    parent = f"projects/{project}/locations/{LOCATION}"

    template = ma.Template(
        filter_config=ma.FilterConfig(
            pi_and_jailbreak_filter_settings=ma.PiAndJailbreakFilterSettings(
                filter_enforcement=ma.PiAndJailbreakFilterSettings.PiAndJailbreakFilterEnforcement.ENABLED,
                confidence_level=ma.DetectionConfidenceLevel.LOW_AND_ABOVE,
            ),
            malicious_uri_filter_settings=ma.MaliciousUriFilterSettings(
                filter_enforcement=ma.MaliciousUriFilterSettings.MaliciousUriFilterEnforcement.ENABLED,
            ),
            sdp_settings=ma.SdpFilterSettings(
                basic_config=ma.SdpBasicConfig(
                    filter_enforcement=ma.SdpBasicConfig.SdpBasicConfigEnforcement.ENABLED,
                ),
            ),
        ),
    )

    try:
        result = client.create_template(
            parent=parent, template_id=TEMPLATE_ID, template=template,
        )
        print(f"created template: {result.name}")
    except AlreadyExists:
        print(f"template already exists: {parent}/templates/{TEMPLATE_ID} (no-op)")


if __name__ == "__main__":
    main()
