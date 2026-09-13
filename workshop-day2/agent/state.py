"""State design.  (Day 2, Block 5)

    "Separate trusted from untrusted. The most important structural move - and it
     starts at the schema."

    TRUSTED                        UNTRUSTED
    operator's system prompt       user messages
    verified user IDs              retrieved documents
    execution metadata             tool outputs
                                   sub-agent summaries

    Different fields. Different rules. NEVER merged.

When they share a field, the agent cannot tell instruction from data - which is
exactly how the breach worked. The three principles are applied here at schema
time, because that is where they are containment rather than hygiene:

    1 MINIMIZE        don't carry what you don't need
    2 TYPE IT         no arbitrary keys - a fixed schema means an attacker
                      cannot smuggle in a field your code doesn't expect
    3 MARK PROVENANCE every field knows its origin, so a downstream node can ask
                      "is this trusted?" and get a real answer
"""
from __future__ import annotations

from config import settings
from agent.models import TRUSTED_ORIGINS, Content
from agent.telemetry import board

#: principle 2 - the only keys that may exist in the trusted zone.
TRUSTED_KEYS = {"system_prompt", "principal_id", "thread_id", "step"}


def to_dict(c: Content) -> dict:
    return {"text": c.text, "origin": c.origin, "label": c.label, "meta": c.meta}


def from_dict(d: dict) -> Content:
    return Content(text=d["text"], origin=d["origin"], label=d.get("label", ""),
                   meta=d.get("meta") or {})


def place(state: dict, items: list[Content]) -> dict:
    """Route new content into the right zone.

    VULNERABLE (split off): everything lands in one flat `context` list, in
    arrival order, indistinguishable.

    SECURE (split on): STUDENT EXERCISE - not implemented yet. (See
    tutorials/v08-state-poisoning.md.) Sort `items` into `trusted` and
    `untrusted` lists by `c.origin in TRUSTED_ORIGINS`, converting each with
    `to_dict(c)`, then return `{"context": trusted + untrusted, "untrusted":
    untrusted}` - different fields, never merged.
    """
    if not settings.on("SECURE_STATE_SPLIT"):
        return {"context": [to_dict(c) for c in items]}

    raise NotImplementedError(
        "state.place: TODO - split items into trusted/untrusted by origin "
        "(see tutorials/v08-state-poisoning.md)"
    )


def assert_containment(state: dict, session) -> None:
    """The proof that the split is real.

    Walk the trusted zone and check that nothing in it came from an untrusted
    origin. With the split off, retrieved articles and sub-agent summaries are
    written into context claiming origin="operator" - and this check fails,
    which is the whole point.
    """
    if not settings.on("SECURE_STATE_SPLIT"):
        leaked = [c for c in state.get("context", [])
                  if c["origin"] == "operator" and c.get("label") not in ("system", "")]
        if leaked:
            board.light("state_containment", "red",
                        f"{len(leaked)} untrusted item(s) sitting in the trusted zone: "
                        + ", ".join(sorted({c['label'] for c in leaked})))
            board.record(session=session.id, principal=session.principal.id, node="state",
                         verdict="contamination", severity="alert",
                         detail="content from retrieval/sub-agents is labelled operator")
        return

    for c in state.get("context", []):
        if c["origin"] in TRUSTED_ORIGINS and c.get("label") not in ("system", ""):
            board.light("state_containment", "red",
                        f"{c['label']} reached a trusted field")
            return


def revalidate(state: dict, session) -> dict:
    """The gate BETWEEN nodes.  (slide 11) STUDENT EXERCISE - not implemented yet.

    Without this, a payload that lands at node 1 is carried forward to nodes 2, 3
    and 4 by the agent itself - free of charge, on the attacker's behalf.
    Containment means breaking the free ride: the payload gets in, but it cannot
    spread.
    """
    if not settings.on("SECURE_STATE_SPLIT"):
        return {}

    raise NotImplementedError(
        "state.revalidate: TODO - re-check every untrusted context item on the way "
        "past (agent.directives.find/strip), logging how many were changed "
        "(see tutorials/v08-state-poisoning.md)"
    )


def for_model(state: dict) -> list[Content]:
    """Assemble what the model actually sees.

    With the split on, untrusted content is fenced and labelled every single time
    it is rendered - not once, when it arrived. STUDENT EXERCISE - not implemented
    yet. (See tutorials/v08-state-poisoning.md.)
    """
    items = [from_dict(d) for d in state.get("context", [])]
    if not settings.on("SECURE_STATE_SPLIT"):
        return items

    raise NotImplementedError(
        "state.for_model: TODO - re-wrap every untrusted item with an "
        "<untrusted origin=... source=...> fence each time context is assembled "
        "(see tutorials/v08-state-poisoning.md)"
    )
