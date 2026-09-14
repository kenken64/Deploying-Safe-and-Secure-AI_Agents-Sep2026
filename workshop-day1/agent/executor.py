"""ONE CHOKEPOINT: the secure tool executor.  (Day 1, slide 41)

    get_order()     ->  1 validate args
    refund()            2 check authz
    cancel()            3 execute
    change_email()      4 validate result
                        5 log

    "One chokepoint you can audit - instead of per-tool discipline you have to trust."

Every tool call goes through here. No exceptions. Day 2 plugs straight into this
file: the output guardrail IS step 4, behavioural telemetry IS step 5.
"""
from __future__ import annotations

import re

from config import settings
from agent import authz, db, directives, tools
from agent.models import (Blocked, Content, Denied, Session, ToolCall, ToolResult)
from agent.telemetry import board


def vulnerable_execute(call: ToolCall, session: Session) -> ToolResult:
    """VULNERABLE: the model names a tool, the tool runs. That is the entire path.

    No argument validation, no authorization, no result validation, and the only
    log line is whatever the tool felt like returning.
    """
    spec = tools.registry().get(call.name)
    if spec is None:
        return ToolResult(ok=False, error=f"no such tool: {call.name}")
    result = spec.fn(call.args, session)
    board.record(session=session.id, principal=session.principal.id, node="tool",
                 tool=call.name, args_fingerprint=call.fingerprint(),
                 records_touched=result.records_touched, egress_host=result.egress_host,
                 detail=result.text[:200])
    _watch_data_boundary(session, call, result)
    _watch_egress(session, call, result)
    return result


def secure_execute(call: ToolCall, session: Session) -> ToolResult:
    """SECURE: the five steps, in order, for every call."""
    registry = tools.registry()

    # step 0 - allowlist the tool NAME itself. Fails safe on anything invented.
    spec = registry.get(call.name)
    if spec is None:
        board.light("tool_boundary", "amber", f"unknown tool {call.name}")
        raise Blocked("SECURE_EXECUTOR", f"tool {call.name!r} is not on the registry")

    # step 1 - validate args against the declared schema
    _validate_args(call, spec)

    # step 2 - check authz, HERE, at the action, against the session
    authz.check(session, call)

    # step 3 - execute
    result = spec.fn(call.args, session)

    # step 4 - validate what comes back (surface 4, the side door - slide 40)
    if settings.on("SECURE_TOOL_RESULTS"):
        result = _validate_result(result, call, session)

    # step 5 - log
    board.record(session=session.id, principal=session.principal.id, node="tool",
                 tool=call.name, args_fingerprint=call.fingerprint(),
                 records_touched=result.records_touched, egress_host=result.egress_host,
                 detail=result.text[:200], control="SECURE_EXECUTOR")
    _watch_data_boundary(session, call, result)
    _watch_egress(session, call, result)
    return result


def _validate_args(call: ToolCall, spec: tools.ToolSpec) -> None:
    """Step 1. Enforce `spec.parameters` (a JSON schema) against `call.args`,
    raising `Blocked("SECURE_EXECUTOR", reason)` on the first violation.
    (See tutorials/v05-tool-argument-injection.md.)

      - any key in `call.args` not present in `schema["properties"]` is an
        UNDECLARED argument - refuse the whole call. This is an allowlist: a
        model that invents `{"sql": ...}` on `get_order` is stopped here,
        before anything runs.
      - every key in `schema["required"]` must be present.
      - each declared value is checked against its rule: `type`
        (string/integer), `enum`, `pattern` (regex, via `re.match`),
        `minimum`, `maximum`.
    """
    schema = spec.parameters or {}
    properties = schema.get("properties", {})

    def refuse(reason: str) -> None:
        board.light("schema_check", "amber", reason)
        raise Blocked("SECURE_EXECUTOR", reason)

    # undeclared arguments - an allowlist, not a denylist
    for key in call.args:
        if key not in properties:
            refuse(f"{call.name}: undeclared argument {key!r}")

    # required arguments
    for key in schema.get("required", []):
        if key not in call.args:
            refuse(f"{call.name}: missing required argument {key!r}")

    # per-argument rules
    type_checks = {
        "string": lambda v: isinstance(v, str),
        "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    }
    for key, value in call.args.items():
        rule = properties[key]
        expected = rule.get("type")
        if expected in type_checks and not type_checks[expected](value):
            refuse(f"{call.name}: argument {key!r} must be {expected}, got {value!r}")
        if "enum" in rule and value not in rule["enum"]:
            refuse(f"{call.name}: argument {key!r}={value!r} not in {rule['enum']}")
        if "pattern" in rule and not (isinstance(value, str)
                                      and re.match(rule["pattern"], value)):
            refuse(f"{call.name}: argument {key!r}={value!r} fails pattern "
                   f"{rule['pattern']!r}")
        if "minimum" in rule and not (isinstance(value, (int, float))
                                      and value >= rule["minimum"]):
            refuse(f"{call.name}: argument {key!r}={value!r} below minimum "
                   f"{rule['minimum']}")
        if "maximum" in rule and not (isinstance(value, (int, float))
                                      and value <= rule["maximum"]):
            refuse(f"{call.name}: argument {key!r}={value!r} above maximum "
                   f"{rule['maximum']}")


def _validate_result(result: ToolResult, call: ToolCall, session: Session) -> ToolResult:
    """Step 4. A compromised API is an injection channel (slide 40).

    Whatever comes back is about to become context, and the model will read it as
    if you wrote it - so it gets the same treatment as any other untrusted text.

    Two outputs, and you want both: the instruction never reaches the model, and
    a light plus a log line say a third party tried to steer your agent. The
    detection is worth as much as the block.
    """
    found = directives.find(result.text)
    if found:
        board.light("tool_boundary", "amber",
                    f"instruction-shaped tool result from {call.name}")
        board.record(session=session.id, principal=session.principal.id, node="tool",
                     tool=call.name, args_fingerprint=call.fingerprint(),
                     verdict="sanitised", severity="warn",
                     control="SECURE_TOOL_RESULTS",
                     detail=f"{call.name} returned {', '.join(found)} - neutralised "
                            f"before it reached the model")
        result.text = directives.strip(result.text)
    return result


def _watch_egress(session: Session, call: ToolCall, result: ToolResult) -> None:
    """Surface 5. Where did this call actually reach?

    With SECURE_EGRESS off the fetch simply succeeds, and nothing anywhere says
    that your agent just read the cloud metadata endpoint on an attacker's behalf.
    """
    host = result.egress_host
    if not host or host in tools.ALLOWED_HOSTS:
        return
    board.light("tool_boundary", "red", f"egress to unapproved host: {host}")
    board.record(session=session.id, principal=session.principal.id, node="tool",
                 tool=call.name, egress_host=host, verdict="egress", severity="alert",
                 detail=f"{call.name} reached {host}, which is not on the allowlist")


#: Tools that read the orders table. The text fallback below is scoped to these,
#: so a help-centre article that merely mentions an order id cannot trip the light.
ORDER_READS = {"lookup_orders", "get_order", "list_my_orders"}


def _watch_data_boundary(session: Session, call: ToolCall, result: ToolResult) -> None:
    """The light that matters most on Day 1.

    It goes RED the moment data belonging to someone other than the signed-in
    customer is returned - whatever route got it there.

    Two ways to see it, because one is not enough. The rows usually carry a
    customer_id, so the check is exact. But lookup_orders is a blank cheque: a
    real model writes `SELECT ship_to FROM orders WHERE id='ORD-100003'` and the
    row that comes back no longer says whose it is. Same leak, thinner evidence -
    so ownership is resolved against the store as well.
    """
    me = session.principal.customer_id
    if session.principal.role == "staff":
        return

    foreign = [r for r in result.rows if r.get("customer_id") and r["customer_id"] != me]
    owners = {r["customer_id"] for r in foreign}
    count = len(foreign)

    if call.name in ORDER_READS:
        disclosed = {oid: owner for oid, owner in db.owners_in(result.text).items()
                     if owner != me}
        if disclosed:
            owners |= set(disclosed.values())
            count = max(count, len(disclosed))

    if owners:
        ids = ", ".join(sorted(owners))
        what = (f"{count} row(s)" if foreign else "order data")
        board.light("data_boundary", "red", f"{what} belonging to {ids} returned to {me}")
        board.record(session=session.id, principal=session.principal.id, node="tool",
                     tool=call.name, records_touched=count, verdict="cross-tenant",
                     severity="alert", detail=f"data owned by {ids} reached {me}")


def execute(call: ToolCall, session: Session) -> ToolResult:
    return (secure_execute(call, session) if settings.on("SECURE_EXECUTOR")
            else vulnerable_execute(call, session))
