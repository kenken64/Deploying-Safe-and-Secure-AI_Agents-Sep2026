"""Surface 2 - retrieved content.  (Day 1, Block 2; the Day 2 opening demo)

The help-centre search. One of the four seeded articles carries an instruction
hidden in an HTML comment. Nobody typed it into the chat box, so nothing at the
chat box can catch it:

    "The payload didn't come through the front door, so there was nothing at
     the front door to catch it."   (Day 2, slide 6)
"""
from __future__ import annotations

import re

from config import settings
from agent import db, directives
from agent.models import Content

STOP = {"the", "a", "an", "is", "my", "i", "to", "for", "of", "on", "and", "do", "how", "what", "in"}


COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def visible(body: str) -> str:
    """What a CMS search index actually sees. NOT the HTML comments - which is
    precisely why nobody noticed the payload was there."""
    return COMMENT_RE.sub(" ", body)


def search(query: str, limit: int = 1, min_terms: int = 2) -> list[dict]:
    terms = {t for t in re.findall(r"[a-z]+", query.lower()) if t not in STOP and len(t) > 2}
    scored = []
    for art in db.rows("SELECT * FROM articles"):
        hay = (art["title"] + " " + visible(art["body"])).lower()
        hits = {t for t in terms if t in hay}
        if len(hits) >= min_terms:
            scored.append((sum(hay.count(t) for t in hits), art))
    scored.sort(key=lambda s: -s[0])
    return [a for _, a in scored[:limit]]


def vulnerable_fetch(query: str) -> list[Content]:
    """VULNERABLE: the article body is concatenated into the model's context as if
    the operator had written it. Instruction and data share one field, so the
    agent cannot tell them apart.  (Day 2, slide 12)"""
    return [Content(text=a["body"], origin="operator", label=a["id"]) for a in search(query)]


def secure_fetch(query: str) -> list[Content]:
    """SECURE: tag provenance at the boundary and render the body as DATA.
    STUDENT EXERCISE - not implemented yet. (See tutorials/v03-indirect-injection.md.)

    For every article `search(query)` returns, build a `Content` whose:
      1. `origin` is `"retrieval"` - never `"operator"` - so every downstream
         node can ask "is this trusted?" and get a true answer.
      2. `text` is the article body with directive-shaped lines removed
         (`directives.strip(...)`) and then fenced so the model reads it as
         quoted reference material, not as something to obey - e.g. wrap it in
         an `<untrusted origin="retrieval" article="...">...</untrusted>` block
         with a trailing note that it is DATA, not an instruction.

    TODO(student): implement this. Until you do, `python kestrel.py attack a3
    --secure` and `python kestrel.py test` will fail loudly.
    """
    raise NotImplementedError(
        "retrieval.secure_fetch: TODO - tag provenance and fence the body as data "
        "(see tutorials/v03-indirect-injection.md)"
    )


def fetch(query: str) -> list[Content]:
    return secure_fetch(query) if settings.on("SECURE_PROVENANCE") else vulnerable_fetch(query)
