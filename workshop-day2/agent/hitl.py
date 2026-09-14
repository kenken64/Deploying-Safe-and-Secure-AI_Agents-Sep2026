"""Human-in-the-loop.  (Day 2, Block 9)

    HITL isn't a fallback for when automation fails - it's a distinct control
    providing what automation structurally can't.

A rule detects a known pattern: fast, consistent, scalable, and unable to assess
whether a NOVEL action is wise or catastrophic. A human looks at an action that
matches no pattern and asks "is this wise, or is this a disaster?"

THE THREE-FACTOR TEST (slide 43), and it cuts both ways:

    irreversible?    ALWAYS gets a gate
    high impact?     weigh it
    low confidence?  weigh it

    too few interrupts  -> dangerous actions run unreviewed
    too many interrupts -> approval fatigue; reviewers approve without reading.
                           WORSE than no review.

INTERRUPT BEFORE, NEVER AFTER. And while a review is pending the state must be
IMMUTABLE - you approve the thing you reviewed, not one that changed underneath you.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Any

from config import settings
from agent import tools
from agent.models import NeedsApproval, Session, ToolCall
from agent.telemetry import board


@dataclass
class Pending:
    id: str
    session_id: str
    principal_id: str
    tool: str
    args: dict[str, Any]
    reason: str
    frozen: str                 # the immutable snapshot a human actually approves
    status: str = "pending"     # pending | approved | rejected
    decided_by: str = ""


PENDING: dict[str, Pending] = {}


def gate_reason(call: ToolCall, session: Session) -> str | None:
    """Apply the three-factor test. Returns why a human is needed, or None."""
    spec = tools.registry().get(call.name)
    if spec is None:
        return None

    if spec.irreversible:
        if call.name == "refund":
            cents = int(call.args.get("amount_cents") or 0)
            # Small refund autonomous; large refund interrupted. This is the
            # "refund splits by amount" from Day 1's action-sort, made concrete.
            if cents > settings.refund_autonomous_ceiling_cents:
                return (f"irreversible + high impact: refund of ${cents/100:,.2f} exceeds "
                        f"the ${settings.refund_autonomous_ceiling_cents/100:,.2f} "
                        f"autonomous ceiling")
            return None
        return f"irreversible: {call.name} cannot be undone"
    return None


def vulnerable_gate(call: ToolCall, session: Session) -> None:
    """VULNERABLE: nothing pauses. Every action is autonomous.

    Every autonomous action is a standing decision to trust the model. Most
    organisations have never made that decision on purpose - it just accreted.
    """
    reason = gate_reason(call, session)
    if reason:
        board.light("human_gate", "red", f"{call.name} fired with no human: {reason}")
        board.record(session=session.id, principal=session.principal.id, node="hitl",
                     tool=call.name, verdict="ungated", severity="alert", detail=reason)


def secure_gate(call: ToolCall, session: Session) -> None:
    """SECURE: raise BEFORE the side effect, with the call frozen.
    (See tutorials/v14-irreversible-action.md.)

    The call is frozen into `Pending` - args copied, never referenced - because
    you approve the thing you reviewed, not one that changed underneath you.
    `NeedsApproval` then unwinds the caller before the side effect happens.
    """
    reason = gate_reason(call, session)
    if reason is None:
        return                      # nothing to gate; approval fatigue is a risk too

    approval_id = f"apr_{secrets.token_urlsafe(8)}"
    frozen = f"{call.name}({', '.join(f'{k}={v}' for k, v in sorted(call.args.items()))})"
    PENDING[approval_id] = Pending(
        id=approval_id,
        session_id=session.id,
        principal_id=session.principal.id,
        tool=call.name,
        args=dict(call.args),       # a COPY - the reviewer's copy cannot be mutated
        reason=reason,
        frozen=frozen,
    )
    board.light("human_gate", "amber", f"{call.name} paused for a human: {reason}")
    board.record(session=session.id, principal=session.principal.id, node="hitl",
                 tool=call.name, verdict="awaiting_approval", severity="warn",
                 control="SECURE_HITL", detail=f"{reason} :: {frozen}")
    # BEFORE, never after. The caller stops here; the side effect has not happened.
    raise NeedsApproval(call, reason, approval_id)


def gate(call: ToolCall, session: Session) -> None:
    if settings.on("SECURE_HITL"):
        secure_gate(call, session)
    else:
        vulnerable_gate(call, session)


def decide(approval_id: str, approve: bool, who: str) -> Pending | None:
    """A named person approved it. That is different from a system allowing it."""
    p = PENDING.get(approval_id)
    if p is None or p.status != "pending":
        return p
    p.status = "approved" if approve else "rejected"
    p.decided_by = who
    board.record(session=p.session_id, principal=who, node="hitl", tool=p.tool,
                 verdict=p.status, control="SECURE_HITL",
                 detail=f"{who} {p.status} {p.frozen}")
    return p


def queue() -> list[Pending]:
    return [p for p in PENDING.values() if p.status == "pending"]
