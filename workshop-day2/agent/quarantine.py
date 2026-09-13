"""The quarantine layer.  (Day 2, slide 25)

Every sub-agent output routes through it. Nothing reaches the supervisor's
reasoning unchecked.

    No LLM calls.  No state.  No actions.  Validate and sanitize only.

Why no LLM in here? Because an LLM in the quarantine layer is just one more thing
that can be injected. Its strength is being deterministic and small enough to
audit - which means you should be able to read this entire file in a minute and
be sure of what it does.

    "Placement is the whole skill. A quarantine node one edge too late catches
     nothing."
"""
from __future__ import annotations

from agent import directives
from agent.helpers import SubagentSummary
from agent.models import Content, Session
from agent.telemetry import board

MAX_SUMMARY_CHARS = 800


def check(summary: SubagentSummary, session: Session) -> Content:
    """STUDENT EXERCISE - not implemented yet. (See tutorials/v11-trust-inheritance.md.)

    Four steps, in order, no LLM calls, no state, no actions - this file must stay
    small enough to read in a minute and be sure of what it does:

      1. schema: raise `TypeError` if `summary.text` isn't a string.
      2. strip anything instruction-shaped (`directives.find` / `directives.strip`);
         if anything was found, light `agent_trust` amber and log it with
         `control="SECURE_QUARANTINE"`.
      3. bound the size - truncate to `MAX_SUMMARY_CHARS`, noting the truncation.
      4. tag it: return a `Content` whose text wraps the (possibly stripped,
         possibly truncated) summary in a `<subagent name="..." tier="...">`
         block with a trailing note that it is a REPORT, not an instruction, and
         whose `origin` is `"subagent"`.
    """
    raise NotImplementedError(
        "quarantine.check: TODO - validate, strip, bound, and tag every sub-agent "
        "summary before it can reach Kestrel's context "
        "(see tutorials/v11-trust-inheritance.md)"
    )
