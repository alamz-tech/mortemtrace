# LinkedIn post draft

For the bonus checklist item: post publicly with the hashtag `#AllThingsAgenticHackathon`
(+0.2). Edit freely.

---

Built MortemTrace for Google's All Things Agentic Hackathon (Fortified Enterprise Fleet
category): an on-call incident agent fleet where one committed timeline fans out to four
departments — Engineering, Support, Legal, Finance — each reading it at a different
scope, enforced at the data layer, not in a prompt.

The part I'm most glad I did: deployed it early and hit it with real, adversarial
requests instead of trusting a green test suite. Found and fixed four real bugs that
would've been invisible until demo day — including one where Model Armor's own API was
correctly blocking a prompt injection and my code was silently ignoring the verdict,
because I'd compared a protobuf enum with str() instead of .name. Every one of these was
a bug that read as correct code and only broke against the live system.

Nine agents, a registry that lets a new department start consuming the timeline with no
redeploy, full OpenTelemetry tracing down to individual scope denials — built with Gemini
3.5 Flash on Vertex AI, Google's Agent Development Kit, Firestore, Pub/Sub, Cloud Run,
and Model Armor.

Repo: github.com/alamz-tech/mortemtrace

#AllThingsAgenticHackathon
