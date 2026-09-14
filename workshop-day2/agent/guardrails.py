"""Output guardrails.  (Day 2, Block 7)

The last thing standing between the agent's output and the world.

The honest argument for spending effort at the very end:

    a 95%-accurate guard model         misses 1 in 20
    sophisticated indirect injection   survives sanitization
    a novel exfiltration technique     matches no existing pattern

Defence in depth means assuming each layer leaks - and adding one more.

Two kinds of output, two kinds of danger. Inspect what the agent SAYS *and* what
it is about to DO. The morning's breach exfiltrated through a tool call that
looked completely normal.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter

from config import settings
from agent import db
from agent.models import Session, ToolCall, Verdict
from agent.telemetry import board

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9_\-]{8,}|Bearer\s+[A-Za-z0-9._\-]{12,}|"
                       r"AKIA[0-9A-Z]{12,}|api[_-]?key\s*[=:]\s*\S+)", re.I)
SQL_RE = re.compile(r"\b(select|insert|update|delete|drop|union)\b.{0,40}\b(from|into|table)\b", re.I)
SHELL_RE = re.compile(r"(;\s*(rm|curl|wget|nc|bash|sh)\b|\$\(|`|\|\s*sh\b)")
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\\\")
SYSTEM_PROMPT_FINGERPRINT = "You are Kestrel, the support agent"
#: Where a summary may legitimately be sent. Anywhere else is exfiltration,
#: however valid the call looks.
APPROVED_RECIPIENT_DOMAINS = {"kestrel.example"}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def foreign_customer_ids(text: str, session: Session) -> list[str]:
    """Another customer's identifiers, in something we are about to send out."""
    me = session.principal.customer_id
    found = set(re.findall(r"CUST-\d{4}", text))
    return sorted(c for c in found if c != me)


# ======================================================================================
# what it SAYS
# ======================================================================================

def vulnerable_check_reply(text: str, session: Session) -> Verdict:
    return Verdict.allow("no output guardrail", layer="none")


def secure_check_reply(text: str, session: Session) -> Verdict:
    """Inspect what the agent is about to SAY.
    (See tutorials/v12-silent-exfiltration.md.)

    The operator's own prompt, a credential-shaped string, and another customer's
    id are all things that must never leave, however the model came to say them.
    """
    if SYSTEM_PROMPT_FINGERPRINT in text:
        return Verdict.block("the reply contains the operator's system prompt",
                             layer="output")
    if SECRET_RE.search(text):
        return Verdict.block("the reply contains a credential-shaped string",
                             layer="output")
    foreign = foreign_customer_ids(text, session)
    if foreign:
        return Verdict.block(f"the reply names another customer: {', '.join(foreign)}",
                             layer="output")
    return Verdict.allow("nothing to block in the reply", layer="output")


def check_reply(text: str, session: Session) -> Verdict:
    verdict = (secure_check_reply(text, session) if settings.on("SECURE_OUTPUT_GUARD")
               else vulnerable_check_reply(text, session))
    if not verdict.allowed:
        board.light("output_guard", "amber", verdict.reason)
        board.record(session=session.id, principal=session.principal.id, node="output",
                     verdict="blocked", severity="warn", control="SECURE_OUTPUT_GUARD",
                     detail=verdict.reason)
    return verdict


# ======================================================================================
# what it DOES
# ======================================================================================

def vulnerable_check_tool_args(call: ToolCall, session: Session) -> Verdict:
    return Verdict.allow("no output guardrail on tool arguments", layer="none")


def secure_check_tool_args(call: ToolCall, session: Session) -> Verdict:
    """A payload hidden inside an innocent-looking parameter.
    (See tutorials/v12-silent-exfiltration.md.)

    This is the half people forget. The call is schema-valid, the authorization
    passes, the API returns 200 - and data walks out inside an argument.
    """
    blob = json.dumps(call.args, default=str)

    if SQL_RE.search(blob):
        return Verdict.block(f"SQL in an argument to {call.name}", layer="tool-args")
    if SHELL_RE.search(blob):
        return Verdict.block(f"shell metacharacters in an argument to {call.name}",
                             layer="tool-args")
    if TRAVERSAL_RE.search(blob):
        return Verdict.block(f"path traversal in an argument to {call.name}",
                             layer="tool-args")
    foreign = foreign_customer_ids(blob, session)
    if foreign:
        return Verdict.block(f"{call.name} carries another customer's id: "
                             f"{', '.join(foreign)}", layer="tool-args")
    for key, value in call.args.items():
        # A long, high-entropy argument is what an encoded blob looks like on the
        # way out. The call is schema-valid; that is exactly the problem.
        if isinstance(value, str) and len(value) > 200 and _entropy(value) > 4.2:
            return Verdict.block(f"{call.name}.{key} looks like an encoded blob "
                                 f"({len(value)} chars, entropy "
                                 f"{_entropy(value):.1f})", layer="tool-args")
    if call.name == "send_summary":
        recipient = str(call.args.get("recipient") or "")
        domain = recipient.rpartition("@")[2].lower()
        if domain not in APPROVED_RECIPIENT_DOMAINS:
            return Verdict.block(f"send_summary to an unapproved domain: "
                                 f"{domain or '(none)'}", layer="tool-args")
    return Verdict.allow("nothing to block in the arguments", layer="tool-args")


def check_tool_args(call: ToolCall, session: Session) -> Verdict:
    verdict = (secure_check_tool_args(call, session) if settings.on("SECURE_OUTPUT_GUARD")
               else vulnerable_check_tool_args(call, session))
    if not verdict.allowed:
        board.light("output_guard", "amber", verdict.reason)
        board.record(session=session.id, principal=session.principal.id, node="output",
                     tool=call.name, verdict="blocked", severity="alert",
                     control="SECURE_OUTPUT_GUARD", detail=verdict.reason)
    return verdict
