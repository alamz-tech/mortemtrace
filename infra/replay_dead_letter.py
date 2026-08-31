"""Replays dead-lettered Pub/Sub messages back into the pipeline.

The subscriptions declare `--dead-letter-topic=dead-letter` and the
DeadLetter model exists, but nothing ever consumed that topic: failed
messages accumulated with no path back in, and recovery meant writing a
one-off script by hand. That happened for real after a Vertex AI quota
exhaustion dead-lettered a batch of runs.

Usage:

    # See what is waiting, without consuming anything
    python infra/replay_dead_letter.py --dry-run

    # Replay everything back onto its original topic
    python infra/replay_dead_letter.py --limit 50

    # Replay only one topic's messages
    python infra/replay_dead_letter.py --topic evidence.received

Safety properties, in order of how much they matter:

  * Dry-run is the default posture for inspection; replaying requires no
    extra flag but --dry-run costs nothing and is worth doing first.
  * Messages are acked on the dead-letter subscription only *after* the
    republish succeeds. A crash mid-run therefore redelivers rather than
    dropping - at-least-once, which the pipeline's idempotency keys
    already tolerate.
  * A replay counter is added as a message attribute, and messages that
    have already been replayed --max-replays times are left in place
    rather than looped forever. Without this, a message that fails for a
    deterministic reason (bad schema, an injection that is correctly
    blocked) would cycle between the pipeline and the dead-letter queue
    indefinitely, burning a Gemini call each time.

Requires a pull subscription on the dead-letter topic; create it with:

    gcloud pubsub subscriptions create dead-letter-replay --topic=dead-letter
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys

from google.cloud import pubsub_v1

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("mortemtrace.replay")

_REPLAY_COUNT_ATTR = "mortemtrace_replay_count"
_ORIGINAL_TOPIC_ATTR = "mortemtrace_original_topic"


def _original_topic(message) -> str | None:
    """Recovers which topic a dead-lettered message came from.

    Pub/Sub stamps CloudEvents-style delivery attributes onto
    dead-lettered messages; the source subscription name is the reliable
    one, and our subscriptions are named "<topic-with-dashes>-push".
    Falls back to an explicit attribute if we set one on a prior replay.
    """
    attrs = dict(message.attributes or {})
    if _ORIGINAL_TOPIC_ATTR in attrs:
        return attrs[_ORIGINAL_TOPIC_ATTR]

    source_sub = attrs.get("CloudPubSubDeadLetterSourceSubscription")
    if source_sub and source_sub.endswith("-push"):
        return source_sub[: -len("-push")].replace("-", ".")
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay dead-lettered messages.")
    parser.add_argument("--project", default=os.environ.get("GOOGLE_CLOUD_PROJECT"))
    parser.add_argument("--subscription", default="dead-letter-replay")
    parser.add_argument("--topic", help="only replay messages whose original topic matches this")
    parser.add_argument("--limit", type=int, default=25)
    parser.add_argument("--max-replays", type=int, default=2,
                        help="leave a message in place once it has been replayed this many times")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.project:
        parser.error("set --project or GOOGLE_CLOUD_PROJECT")

    subscriber = pubsub_v1.SubscriberClient()
    publisher = pubsub_v1.PublisherClient()
    sub_path = subscriber.subscription_path(args.project, args.subscription)

    response = subscriber.pull(
        request={"subscription": sub_path, "max_messages": args.limit},
        timeout=30,
    )
    if not response.received_messages:
        logger.info("dead-letter queue is empty")
        return 0

    replayed = skipped = exhausted = 0
    for received in response.received_messages:
        message = received.message
        topic = args.topic or _original_topic(message)

        if topic is None:
            logger.warning(
                "cannot determine original topic for message %s; leaving it in place "
                "(replay it explicitly with --topic)", message.message_id,
            )
            skipped += 1
            continue
        if args.topic and _original_topic(message) not in (None, args.topic):
            skipped += 1
            continue

        attrs = dict(message.attributes or {})
        replay_count = int(attrs.get(_REPLAY_COUNT_ATTR, "0"))
        if replay_count >= args.max_replays:
            logger.warning(
                "message %s has already been replayed %d times; leaving it in place. "
                "A message failing this consistently is failing deterministically - "
                "investigate rather than replaying again.",
                message.message_id, replay_count,
            )
            exhausted += 1
            continue

        try:
            payload = json.loads(message.data.decode("utf-8"))
            descriptor = f"run={payload.get('run_id')} org={payload.get('org_id')}"
        except Exception:
            descriptor = f"<{len(message.data)} bytes, undecodable>"

        if args.dry_run:
            logger.info("[dry-run] would replay to %s: %s (replays so far: %d)",
                        topic, descriptor, replay_count)
            replayed += 1
            continue

        attrs[_REPLAY_COUNT_ATTR] = str(replay_count + 1)
        attrs[_ORIGINAL_TOPIC_ATTR] = topic
        future = publisher.publish(
            publisher.topic_path(args.project, topic), message.data, **attrs,
        )
        future.result(timeout=30)  # block: we must not ack before the republish lands

        subscriber.acknowledge(
            request={"subscription": sub_path, "ack_ids": [received.ack_id]},
        )
        logger.info("replayed to %s: %s", topic, descriptor)
        replayed += 1

    verb = "would replay" if args.dry_run else "replayed"
    logger.info("%s %d message(s); skipped %d; %d past the replay limit",
                verb, replayed, skipped, exhausted)
    return 0


if __name__ == "__main__":
    sys.exit(main())
