"""Authorization at action time.  (Day 1, Block 4)

Two rules that the opening breach violated:

    The agent RECEIVES an identity. It never establishes one, and it never
    trusts the model's claim about who is asking.            (slide 47)

    Check at the ACTION, every action, against the SESSION. A check at the top
    of the conversation is stale by the time the refund fires.  (slide 49)

RBAC is not one check, it is three (slide 48):
    1. invoke    - may this person talk to the agent at all?
    2. tool      - which tools does their role unlock?
    3. resource  - which rows may THIS call touch?   <- miss this and you get slide 9
"""
from __future__ import annotations

from config import settings
from agent import db
from agent.models import Denied, Principal, Session, ToolCall

# level 2: which tools each role unlocks
ROLE_TOOLS: dict[str, set[str]] = {
    "anonymous": {"search_help"},
    "customer":  {"search_help", "list_my_orders", "get_order", "lookup_orders",
                  "refund", "cancel_order", "track_shipment"},
    "staff":     {"search_help", "list_my_orders", "get_order", "lookup_orders",
                  "refund", "cancel_order", "change_email", "apply_discount",
                  "track_shipment", "send_summary"},
}


def resource_owner(call: ToolCall) -> str | None:
    """Whose row is this call about? Returns None when the call is not row-scoped."""
    order_id = call.args.get("order_id")
    if isinstance(order_id, str) and order_id:
        return db.order_owner(order_id)
    cust = call.args.get("customer_id")
    return cust if isinstance(cust, str) else None


def vulnerable_check(session: Session, call: ToolCall) -> None:
    """VULNERABLE: nothing is checked.

    Kestrel runs under ONE service account that can do everything, so any
    successful steering inherits all of it.  (slide 46)
    """
    return None


def secure_check(session: Session, call: ToolCall) -> None:
    """SECURE: all three levels, at the action, against the session.
    STUDENT EXERCISE - not implemented yet. (See tutorials/v04-authz-at-action-time.md.)

    Implement, in order, raising `Denied(level, reason)` the moment one fails:

      level 1 - INVOKE: may this person talk to the agent at all?
                `session.principal.may_invoke_agent` must be true.
      level 2 - TOOL: which tools does their role unlock?
                `call.name` must be in `ROLE_TOOLS[session.principal.role]`.
      level 3 - RESOURCE: which rows may THIS call touch?
                use `resource_owner(call)`; if it names an owner, the caller is
                not staff, and that owner isn't the caller's own customer_id,
                deny. Miss this level and you get the opening breach back.

    One more rule, after all three levels pass: a customer may refund their OWN
    order, but only staff may issue a refund above
    `settings.refund_autonomous_ceiling_cents` - anything larger from a
    "customer"-role caller must also be denied.

    TODO(student): implement this. Until you do, every secure-profile tool call
    will raise instead of being checked - `python kestrel.py test` will fail
    loudly across most attacks, not just a1/a2. That is expected: this check
    runs on every single call, so it is genuinely shared infrastructure.
    """
    raise NotImplementedError(
        "authz.secure_check: TODO - implement the three RBAC levels "
        "(see tutorials/v04-authz-at-action-time.md)"
    )


def check(session: Session, call: ToolCall) -> None:
    if settings.on("SECURE_AUTHZ"):
        secure_check(session, call)
    else:
        vulnerable_check(session, call)
