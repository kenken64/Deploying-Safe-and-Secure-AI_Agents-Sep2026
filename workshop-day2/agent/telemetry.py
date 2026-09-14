"""Observability.  (Day 2, Block 8)

    Security controls PREVENT attacks. Observability DETECTS them. You need both.
    An agent with perfect controls and no observability is an agent that gets
    breached silently.

Four layers, built bottom-up, each depending on the one beneath it:

    4  security intelligence  threat hunting, baselines, forensics   (humans)
    3  behavioural            baselines of normal, flag anomalies    <- catches the
                                                                       legitimate-looking
                                                                       attack
    2  detection              rules & signatures on known-bad        (cheap, reliable)
    1  telemetry              structured log of every node, tool,    (the raw record
                              decision                                everything needs)

Layer 1 is always on - it is the record. Layers 2 and 3 are SECURE_TELEMETRY,
because that is what most teams have never built.
"""
from __future__ import annotations

import time
from collections import Counter, deque
from dataclasses import dataclass, field, asdict
from typing import Any, Literal

Level = Literal["green", "amber", "red"]

LIGHTS: dict[str, str] = {
    # carried over from Day 1 - the edge
    "input_validation": "Input validation",
    "content_filter":   "Content filter",
    "schema_check":     "Schema check",
    "tool_boundary":    "Tool boundary",
    "authorization":    "Authorization",
    "data_boundary":    "DATA BOUNDARY",
    # Day 2 - the interior
    "state_containment": "State containment",
    "agent_trust":       "Sub-agent trust",
    "output_guard":      "Output guardrail",
    "detection":         "Detection",
    "human_gate":        "Human gate",
    "cost_cap":          "Rate & cost",
}


@dataclass
class Event:
    t: float
    session: str
    principal: str
    node: str
    detail: str
    tool: str = ""
    args_fingerprint: str = ""
    records_touched: int = 0
    egress_host: str | None = None
    verdict: str = "ok"
    control: str = ""
    severity: Literal["info", "warn", "alert"] = "info"


# --------------------------------------------------------------------------------------
# LAYER 3 - behavioural baselines.
# The exfiltration on slide 36 produces status=ok and errors=0. Watching for
# FAILURES will never see it. You have to watch the SHAPE of behaviour.
# --------------------------------------------------------------------------------------
BASELINE = {
    "max_records_per_call":   6,     # a customer has a handful of orders, not fifty
    "max_egress_per_session": 2,
    "max_tool_calls":         5,
    "outbound_tools":         {"send_summary", "change_email"},
}


@dataclass
class Board:
    lights: dict[str, Level] = field(default_factory=lambda: {k: "green" for k in LIGHTS})
    events: deque = field(default_factory=lambda: deque(maxlen=500))
    breaches: list[str] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    tool_counts: Counter = field(default_factory=Counter)
    egress_count: int = 0

    def reset(self) -> None:
        self.lights = {k: "green" for k in LIGHTS}
        self.events.clear()
        self.breaches.clear()
        self.findings.clear()
        self.tool_counts.clear()
        self.egress_count = 0

    def light(self, name: str, level: Level, why: str = "") -> None:
        if name not in LIGHTS:
            raise KeyError(name)
        order = {"green": 0, "amber": 1, "red": 2}
        if order[level] >= order[self.lights[name]]:
            self.lights[name] = level
        if level == "red" and why:
            self.breaches.append(f"{LIGHTS[name]}: {why}")

    def record(self, **kw: Any) -> Event:
        """LAYER 1 - telemetry. The raw record everything else needs."""
        ev = Event(t=time.time(), **kw)
        self.events.append(ev)
        self._behavioural(ev)
        return ev

    # -- LAYER 3 ---------------------------------------------------------------------
    def _behavioural(self, ev: Event) -> None:
        """LAYER 3 - behavioural baselines. (See tutorials/v12 and v13.)

        The layer that catches the legitimate-looking attack, because it asks
        "is this NORMAL?" rather than "is this known-bad?". Compared against
        BASELINE's four numbers: records touched per call, outbound calls per
        session, an outbound tool used at all, and tool calls in the turn.
        """
        from config import settings
        if not settings.on("SECURE_TELEMETRY"):
            return
        # Count what the agent DECIDED to do, at the plan node - not what survived
        # to execution. Prevention and detection are separate controls: an
        # outbound call the guardrail blocked is still one the board must show.
        if ev.tool and ev.node == "plan":
            self.tool_counts[ev.tool] += 1
            if ev.tool in BASELINE["outbound_tools"]:
                self.egress_count += 1

        # Four questions, none of them "is this known-bad?". Each asks "is this
        # NORMAL?" - which is the only question that catches b6.
        if ev.records_touched > BASELINE["max_records_per_call"]:
            self._flag(ev, f"{ev.tool or ev.node} touched {ev.records_touched} records "
                           f"in one call (baseline {BASELINE['max_records_per_call']})")

        if self.egress_count > BASELINE["max_egress_per_session"]:
            self._flag(ev, f"{self.egress_count} outbound call(s) this session "
                           f"(baseline {BASELINE['max_egress_per_session']})")

        if ev.tool in BASELINE["outbound_tools"] and ev.node in ("plan", "tool"):
            self._flag(ev, f"{ev.tool} used at all - an outbound tool on a support "
                           f"turn is worth a look even when it returns 200")

        total = sum(self.tool_counts.values())
        if total > BASELINE["max_tool_calls"]:
            self._flag(ev, f"{total} tool calls in one turn "
                           f"(baseline {BASELINE['max_tool_calls']})")

    def _flag(self, ev: Event, why: str) -> None:
        if why in self.findings:
            return
        self.findings.append(why)
        self.light("detection", "amber", why)
        self.events.append(Event(t=time.time(), session=ev.session, principal=ev.principal,
                                 node="behavioural", detail=why, verdict="anomaly",
                                 severity="warn", control="SECURE_TELEMETRY"))

    def tail(self, n: int = 60) -> list[dict]:
        return [asdict(e) for e in list(self.events)[-n:]]

    def worst(self) -> Level:
        if "red" in self.lights.values():
            return "red"
        return "amber" if "amber" in self.lights.values() else "green"


board = Board()
