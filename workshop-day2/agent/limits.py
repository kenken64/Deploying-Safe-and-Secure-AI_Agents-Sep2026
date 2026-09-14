"""Rate limiting and abuse prevention.  (Day 2, Block 10)

A different kind of harm: not a breach, a bill.

    "Amplification is the point of agents - and the danger of them. An agent
     isn't just vulnerable to service degradation; it's vulnerable to economic
     exhaustion. Nothing was stolen. No action was taken. You just got a bill."

ONE RATE LIMIT ISN'T ENOUGH. A gateway cap of 1 request/minute is SATISFIED while
that single request burns 200 steps, 500K tokens and an infinite loop. The attack
picks the level you didn't guard. So: five independent levels.
"""
from __future__ import annotations

import os
import time
from collections import Counter, deque

from config import settings
from agent.models import LimitExceeded, Session, ToolCall
from agent.telemetry import board

#: Rough blended price, only so the circuit breaker has something to trip on.
#: This is a SIMULATED cost - it is not read back from the provider. Set it to
#: your real blended rate if you want the meter to mean something.
USD_PER_1K_TOKENS = float(os.getenv("KESTREL_USD_PER_1K_TOKENS", "0.002"))

_session_starts: deque[float] = deque(maxlen=500)
_daily_tokens = {"n": 0, "day": time.strftime("%Y-%m-%d")}
_cycles: dict[str, Counter] = {}


def reset() -> None:
    _session_starts.clear()
    _daily_tokens.update(n=0, day=time.strftime("%Y-%m-%d"))
    _cycles.clear()


# ---- 1. request rate ---------------------------------------------------------------
def check_session_start() -> None:
    """Level 1 of 5 - the request rate, on a sliding 60-second window.
    (See tutorials/v15-cost-exhaustion.md.)

    This is the one most teams already have, and the one the attack is happy to
    satisfy: a single permitted request can still burn everything below.
    """
    if not settings.on("SECURE_LIMITS"):
        return

    now = time.time()
    while _session_starts and now - _session_starts[0] > 60:
        _session_starts.popleft()
    if len(_session_starts) >= settings.limit_sessions_per_min:
        _trip("1 request rate",
              f"{len(_session_starts)} sessions in the last 60s, cap is "
              f"{settings.limit_sessions_per_min}")
    _session_starts.append(now)


# ---- 2. session execution & 3. loop detection & 4. token budget & 5. cost ----------
def check_step(session: Session, call: ToolCall | None = None) -> None:
    """Levels 2-5 of 5, checked on every step.
    (See tutorials/v15-cost-exhaustion.md.)

    Four independent caps, because one cap is a cap on one thing only and the
    attack picks the level you didn't guard: session execution, loop detection,
    token budget (per-session AND cumulative daily - either alone leaves a gap),
    and the circuit breaker denominated in money.
    """
    if not settings.on("SECURE_LIMITS"):
        # With limits off the only thing standing between you and an unbounded
        # run is the graph's recursion limit - which is a framework safety net,
        # not a control you chose.
        if session.steps > settings.limit_steps_per_session * 2:
            board.light("cost_cap", "red",
                        f"{session.steps} steps in one session, nothing capped it")
        return

    # 2. session execution - one request must not buy unbounded steps.
    if session.steps > settings.limit_steps_per_session:
        _trip("2 session execution",
              f"{session.steps} steps, cap is {settings.limit_steps_per_session}")

    # 3. loop detection - the same call, over and over, is not progress.
    if call is not None:
        seen = _cycles.setdefault(session.id, Counter())
        seen[call.fingerprint()] += 1
        if seen[call.fingerprint()] > settings.limit_repeat_cycle:
            _trip("3 loop detection",
                  f"{call.name} repeated {seen[call.fingerprint()]} times with the "
                  f"same arguments, cap is {settings.limit_repeat_cycle}")

    # 4. token budget - per session AND cumulative daily. Either alone leaves a gap.
    if session.tokens > settings.limit_tokens_per_session:
        _trip("4 token budget",
              f"{session.tokens} tokens this session, cap is "
              f"{settings.limit_tokens_per_session}")
    today = time.strftime("%Y-%m-%d")
    if _daily_tokens["day"] != today:
        _daily_tokens.update(n=0, day=today)
    if _daily_tokens["n"] > settings.limit_tokens_per_day:
        _trip("4 token budget (daily)",
              f"{_daily_tokens['n']} tokens today, cap is "
              f"{settings.limit_tokens_per_day}")

    # 5. cost circuit breaker - the one denominated in money.
    session.cost_usd = session.tokens / 1000 * USD_PER_1K_TOKENS
    if session.cost_usd > settings.limit_cost_ceiling_usd:
        _trip("5 cost ceiling",
              f"${session.cost_usd:.4f} this session, ceiling is "
              f"${settings.limit_cost_ceiling_usd:.2f}")


def account_tokens(n: int) -> None:
    _daily_tokens["n"] += n


def _trip(level: str, detail: str) -> None:
    board.light("cost_cap", "amber", f"{level}: {detail}")
    board.record(session="-", principal="-", node="limits", verdict="capped",
                 severity="warn", control="SECURE_LIMITS", detail=f"{level}: {detail}")
    raise LimitExceeded(level, detail)


def snapshot() -> dict:
    """The budget meter, for the console and the tutorial pages.

    The same four numbers the CLI prints after every attack, but reachable
    without a session in hand: it reads the most recent one, because that is the
    run the student just watched. The daily figure is cumulative across all of
    them, which is the point of having it.

    A meter that only appears once a cap has already fired teaches nothing. The
    number climbing toward the ceiling is the demo.
    """
    from agent import graph
    session = next(reversed(list(graph.SESSIONS.values())), None)
    steps = session.steps if session else 0
    tokens = session.tokens if session else 0
    return {
        "enabled": settings.on("SECURE_LIMITS"),
        "rows": [
            {"key": "steps",  "label": "steps this session",
             "used": steps, "cap": settings.limit_steps_per_session, "fmt": "int"},
            {"key": "tokens", "label": "tokens this session",
             "used": tokens, "cap": settings.limit_tokens_per_session, "fmt": "int"},
            {"key": "daily",  "label": "tokens today",
             "used": _daily_tokens["n"], "cap": settings.limit_tokens_per_day, "fmt": "int"},
            {"key": "cost",   "label": "spend this session",
             "used": round(tokens / 1000 * USD_PER_1K_TOKENS, 4),
             "cap": settings.limit_cost_ceiling_usd, "fmt": "usd"},
        ],
    }


def status(session: Session) -> dict:
    return {
        "steps": f"{session.steps}/{settings.limit_steps_per_session}",
        "tokens": f"{session.tokens}/{settings.limit_tokens_per_session}",
        "daily": f"{_daily_tokens['n']}/{settings.limit_tokens_per_day}",
        "cost": f"${session.tokens / 1000 * USD_PER_1K_TOKENS:.4f}"
                f"/${settings.limit_cost_ceiling_usd:.2f}",
    }
