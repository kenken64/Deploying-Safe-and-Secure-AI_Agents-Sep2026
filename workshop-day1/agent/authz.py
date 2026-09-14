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
    (See tutorials/v04-authz-at-action-time.md.)

    Checked against `session`, never against anything the model asserted. Most
    teams build level 1, often build level 2, and almost never build level 3 -
    and level 3 is the one that produces cross-tenant incidents.
    """
    principal = session.principal

    # level 1 - INVOKE: may this person talk to the agent at all?
    if not principal.may_invoke_agent:
        raise Denied("invoke", f"{principal.id} may not invoke the agent")

    # level 2 - TOOL: which tools does their role unlock?
    if call.name not in ROLE_TOOLS.get(principal.role, set()):
        raise Denied("tool", f"role {principal.role!r} does not unlock {call.name!r}")

    # level 3 - RESOURCE: which rows may THIS call touch?
    owner = resource_owner(call)
    if owner and principal.role != "staff" and owner != principal.customer_id:
        raise Denied("resource", f"{call.name} touches data owned by {owner}, "
                                 f"not {principal.customer_id}")

    # A customer may refund their OWN order - level 3 just established that it is
    # theirs. An arbitrary credit is a different action, and only staff issue it.
    if call.name == "refund" and principal.role != "staff":
        amount = call.args.get("amount_cents")
        ceiling = settings.refund_autonomous_ceiling_cents
        if isinstance(amount, (int, float)) and amount > ceiling:
            raise Denied("resource", f"refund of {amount}c exceeds the {ceiling}c "
                                     f"autonomous ceiling for role {principal.role!r}")


def check(session: Session, call: ToolCall) -> None:
    if settings.on("SECURE_AUTHZ"):
        secure_check(session, call)
    else:
        vulnerable_check(session, call)
