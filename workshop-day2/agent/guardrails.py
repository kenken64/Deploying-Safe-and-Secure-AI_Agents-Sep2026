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
    """STUDENT EXERCISE - not implemented yet. (See tutorials/v12-silent-exfiltration.md.)

    Inspect what the agent is about to SAY. In order, return `Verdict.block(reason,
    layer="output")` for the first match:

      - `SYSTEM_PROMPT_FINGERPRINT` appears in `text`.
      - `SECRET_RE` matches (an API-key/credential-shaped string).
      - `foreign_customer_ids(text, session)` is non-empty (another customer's id).

    Otherwise `Verdict.allow(layer="output")`.
    """
    raise NotImplementedError(
        "guardrails.secure_check_reply: TODO - block system-prompt leakage, "
        "credential-shaped strings, and foreign customer ids "
        "(see tutorials/v12-silent-exfiltration.md)"
    )


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
    STUDENT EXERCISE - not implemented yet. (See tutorials/v12-silent-exfiltration.md.)

    This is the half people forget. The call is schema-valid, the authorization
    passes, the API returns 200 - and data walks out inside an argument. Inspect
    `blob = json.dumps(call.args, default=str)` and, in order, return
    `Verdict.block(reason, layer="tool-args")` for the first match:

      - `SQL_RE` matches (SQL in an argument).
      - `SHELL_RE` matches (shell metacharacters).
      - `TRAVERSAL_RE` matches (path traversal).
      - `foreign_customer_ids(blob, session)` is non-empty.
      - any string argument longer than 200 chars has `_entropy(value) > 4.2`
        (a possible encoded blob).
      - `call.name == "send_summary"` and the recipient's domain isn't in the
        approved set (`{"kestrel.example"}`).

    Otherwise `Verdict.allow(layer="tool-args")`.
    """
    raise NotImplementedError(
        "guardrails.secure_check_tool_args: TODO - inspect tool arguments for SQL, "
        "shell metacharacters, path traversal, foreign customer ids, high-entropy "
        "blobs, and unapproved outbound domains "
        "(see tutorials/v12-silent-exfiltration.md)"
    )


def check_tool_args(call: ToolCall, session: Session) -> Verdict:
    verdict = (secure_check_tool_args(call, session) if settings.on("SECURE_OUTPUT_GUARD")
               else vulnerable_check_tool_args(call, session))
    if not verdict.allowed:
        board.light("output_guard", "amber", verdict.reason)
        board.record(session=session.id, principal=session.principal.id, node="output",
                     tool=call.name, verdict="blocked", severity="alert",
                     control="SECURE_OUTPUT_GUARD", detail=verdict.reason)
    return verdict
