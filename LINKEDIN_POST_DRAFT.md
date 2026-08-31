# LinkedIn post draft

For the bonus checklist item: post publicly with the hashtag `#AllThingsAgenticHackathon`
(+0.2). Edit freely. Same sequencing note as BLOG_POST_DRAFT.md — the self-review line
below is written to stay accurate whether the P0 fixes have shipped yet or not ("found and
are closing" vs "found and closed"); pick whichever is true when you actually post.

Two versions below — pick one, or post both a few days apart.

---

## Version 1 — built-it framing

Built MortemTrace for Google's All Things Agentic Hackathon (Fortified Enterprise Fleet
category): an on-call incident agent fleet where one committed, source-traced timeline
fans out to four departments — Engineering, Support, Legal, Finance — each reading it at a
different scope, enforced at the data layer, not in a prompt. Support's agent isn't told
to skip raw logs; it's structurally unable to read them, because the database itself
denies the query regardless of what any prompt says.

The part I'm most glad I did: deployed early and kept hitting the live system with real,
adversarial input instead of trusting a green test suite — then ran a full staff-level
self-review against the finished system and treated my own code like a stranger's pull
request. Between the two, I found and am closing real issues that would've been invisible
until someone else found them first: a protobuf enum compared with str() instead of .name
that silently defeated the one governance control the whole "Fortified Enterprise" category
is about, a PKCE wiring bug that broke real Google sign-in at the token-exchange step, and
gaps in the newest authentication surface that a quick self-check would have missed.

Eleven agents, a registry that lets a new department start consuming the timeline with no
redeploy, full OpenTelemetry tracing down to individual scope denials, real human sign-in
via Google/org SSO, and a webhook receiver so any existing tool — PagerDuty, GitHub
Actions, Jenkins, Terraform — connects without a bespoke integration. Built with Gemini 3.5
Flash on Vertex AI, Google's Agent Development Kit, Model Armor, Firestore, Pub/Sub, and
Cloud Run.

Repo: github.com/alamz-tech/mortemtrace
Full writeup: [link to the blog post]

#AllThingsAgenticHackathon

---

## Version 2 — shorter, lesson-forward

Every real bug in my Google hackathon project this month shared the same shape: code that
read correctly, passed every test against a mock, and was wrong in a way only the live
system would ever show me.

The one I'm gladdest I caught: Model Armor — the governance layer my "Fortified Enterprise
Fleet" entry is built around — was correctly flagging a live prompt injection, and my own
code was silently ignoring the verdict, because I'd compared a protobuf enum with str()
instead of .name. It typechecked. It ran. It just always said "allow."

Built MortemTrace: eleven agents, one committed incident timeline, four departmental read
scopes enforced at the database layer instead of in a prompt — on Gemini 3.5 Flash, Google
ADK, Model Armor, Firestore, Pub/Sub, and Cloud Run.

github.com/alamz-tech/mortemtrace

#AllThingsAgenticHackathon
