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

import time
from collections import Counter, deque

from config import settings
from agent.models import LimitExceeded, Session, ToolCall
from agent.telemetry import board

#: rough blended price, only so the circuit breaker has something to trip on
USD_PER_1K_TOKENS = 0.002

_session_starts: deque[float] = deque(maxlen=500)
_daily_tokens = {"n": 0, "day": time.strftime("%Y-%m-%d")}
_cycles: dict[str, Counter] = {}


def reset() -> None:
    _session_starts.clear()
    _daily_tokens.update(n=0, day=time.strftime("%Y-%m-%d"))
    _cycles.clear()


# ---- 1. request rate ---------------------------------------------------------------
def check_session_start() -> None:
    """STUDENT EXERCISE - not implemented yet. (See tutorials/v15-cost-exhaustion.md.)

    A sliding 60-second window: drop entries from `_session_starts` older than 60s,
    call `_trip("1 request rate", ...)` if what remains is already at
    `settings.limit_sessions_per_min`, then record this start.
    """
    if not settings.on("SECURE_LIMITS"):
        return
    raise NotImplementedError(
        "limits.check_session_start: TODO - enforce the sliding-window request-rate cap "
        "(see tutorials/v15-cost-exhaustion.md)"
    )


# ---- 2. session execution & 3. loop detection & 4. token budget & 5. cost ----------
def check_step(session: Session, call: ToolCall | None = None) -> None:
    """STUDENT EXERCISE - not implemented yet. (See tutorials/v15-cost-exhaustion.md.)

    Four independent levels, each calling `_trip(level, detail)` when tripped -
    one cap is a cap on one thing only:

      2. session execution - `_trip` if `session.steps > settings.limit_steps_per_session`.
      3. loop detection - fingerprint `call` (tool + arguments) in a per-session
         `Counter` (`_cycles`); `_trip` if the same fingerprint recurs more than
         `settings.limit_repeat_cycle` times. Skip if `call is None`.
      4. token budget, BOTH per-session (`session.tokens` vs
         `limit_tokens_per_session`) AND cumulative daily (`_daily_tokens`, reset
         when the date rolls over, vs `limit_tokens_per_day`) - you need both,
         since either alone leaves a gap.
      5. cost circuit breaker - set `session.cost_usd` from `session.tokens` and
         `USD_PER_1K_TOKENS`, `_trip` if it exceeds `settings.limit_cost_ceiling_usd`.
    """
    if not settings.on("SECURE_LIMITS"):
        # With limits off the only thing standing between you and an unbounded
        # run is the graph's recursion limit - which is a framework safety net,
        # not a control you chose.
        if session.steps > settings.limit_steps_per_session * 2:
            board.light("cost_cap", "red",
                        f"{session.steps} steps in one session, nothing capped it")
        return

    raise NotImplementedError(
        "limits.check_step: TODO - enforce the four remaining levels (session "
        "steps, loop detection, token budget, cost ceiling) "
        "(see tutorials/v15-cost-exhaustion.md)"
    )


def account_tokens(n: int) -> None:
    _daily_tokens["n"] += n


def _trip(level: str, detail: str) -> None:
    board.light("cost_cap", "amber", f"{level}: {detail}")
    board.record(session="-", principal="-", node="limits", verdict="capped",
                 severity="warn", control="SECURE_LIMITS", detail=f"{level}: {detail}")
    raise LimitExceeded(level, detail)


def status(session: Session) -> dict:
    return {
        "steps": f"{session.steps}/{settings.limit_steps_per_session}",
        "tokens": f"{session.tokens}/{settings.limit_tokens_per_session}",
        "daily": f"{_daily_tokens['n']}/{settings.limit_tokens_per_day}",
        "cost": f"${session.tokens / 1000 * USD_PER_1K_TOKENS:.4f}"
                f"/${settings.limit_cost_ceiling_usd:.2f}",
    }
