"""Attack runner - Day 2.

    python kestrel.py attack b1             run one attack
    python kestrel.py attack all            the whole interior catalogue
    python kestrel.py attack b1 --secure    against the fully hardened build

Every Day 1 control is on for all of these, always. If something lands, it landed
past the entire edge.
"""
from __future__ import annotations

import argparse
import sys
import time

from config import CONTROLS, DAY2, settings
from agent import db, graph, hitl, limits, memory
from agent.models import Principal
from agent.telemetry import board
from attacks.catalogue import ATTACKS, ORDER, Attack

BAR = "=" * 78
DASH = "-" * 78


def _line(kind: str, text: str) -> dict:
    """One transcript line, in the same shape graph._line produces.

    The two special runners below tell their story across more than one session,
    so they cannot simply forward a single graph transcript. They build one, and
    every runner returns the same keys - otherwise the console has a trace and
    the tutorial page prints "(no trace)".
    """
    return {"kind": kind, "text": text, "t": time.time()}


def principal_for(customer_id: str) -> Principal:
    row = db.customer(customer_id)
    return Principal(id=customer_id, display_name=row["name"] if row else customer_id,
                     role="customer", customer_id=customer_id)


def _fresh() -> None:
    # Each attack starts from the seeded database. A planted memory or an issued
    # refund from the previous run would otherwise make the next result a lie.
    db.reset()
    board.reset()
    graph.SESSIONS.clear()
    limits.reset()
    hitl.PENDING.clear()
    memory.CHECKPOINTS.clear()


def _why_stopped(attack: Attack) -> str:
    """Say WHY it did not land - and do not take credit that is not owed.

    With the mock, "it did not land" means a control stopped it: the model is
    deterministic, so nothing else could have changed. With a real model it can
    also mean the model simply did not manage the attack this run - a small local
    model often cannot chain "look the order up, then use the URL from the row".
    Reporting that as a control working is how a lab teaches a false lesson.
    """
    on = [c for c in attack.closed_by if settings.on(c)]
    if on:
        return f"stopped by: {', '.join(on)}"
    if settings.llm_provider == "mock":
        return "stopped by: the controls above"
    return (f"NOT stopped by a control - none of {attack.id}'s controls are on. "
            f"{settings.active_model} did not take the bait this run. Real models "
            f"are not deterministic: re-run it, or try a larger one.")


def run_one(attack: Attack, verbose: bool = True) -> dict:
    _fresh()
    runner = {"thread_guess": _run_thread_guess,
              "memory_landmine": _run_memory_landmine}.get(attack.runner, _run_chat)
    return runner(attack, verbose)


def _header(attack: Attack) -> None:
    print(BAR)
    print(f"{attack.id.upper()}  {attack.name}")
    print(f"{attack.theme} | surface {attack.surface}: "
          f"{attack.entry_point} -> {attack.stage} -> {attack.impact}")
    print(DASH)


def _panel(result: dict, extra: list[str] | None = None) -> None:
    print(DASH)
    for name, level in result["lights"].items():
        mark = {"green": "[ ok ]", "amber": "[warn]", "red": "[BREACH]"}[level]
        print(f"  {mark:<9} {name}")
    for b in dict.fromkeys(result.get("breaches", [])):
        print(f"  !! {b}")
    for f in result.get("findings", []):
        print(f"  ?? detection: {f}")
    for line in extra or []:
        print(f"  {line}")


def _verdict(attack: Attack, landed: bool) -> None:
    print(DASH)
    print("  ATTACK LANDED" if landed else "  attack stopped")
    if landed:
        off = [c for c in attack.closed_by if not settings.on(c)]
        print(f"  fix it with: {', '.join(off) if off else '(see the tutorial)'}")
    else:
        print(f"  {_why_stopped(attack)}")
    print(f"  step by step: tutorials/{attack.tutorial}.md")
    print(BAR)
    print()


def _run_chat(attack: Attack, verbose: bool) -> dict:
    before_refunds = len(db.refunds())
    result = graph.chat(principal_for(attack.who), attack.message)
    landed = (board.worst() == "red") or (len(db.refunds()) > before_refunds)

    if verbose:
        _header(attack)
        print(f'customer says: "{attack.message}"')
        print(DASH)
        for line in result["transcript"]:
            print(f"  {line['kind']:<10} {line['text'][:150]}")
        extra = []
        if result.get("awaiting"):
            extra.append(f"awaiting human approval: {result['awaiting']['id']}")
        if result.get("limits"):
            extra.append("budget  " + "  ".join(f"{k}={v}" for k, v in result["limits"].items()))
        _panel(result, extra)
        _verdict(attack, landed)
    return {"attack": attack.id, "landed": landed, "lights": result["lights"],
            "transcript": result["transcript"], "awaiting": result.get("awaiting")}


def _run_thread_guess(attack: Attack, verbose: bool) -> dict:
    """b3. Ben has a conversation. Alice guesses the thread id and reads it."""
    from agent.models import Denied
    ben = principal_for("CUST-1002")
    alice = principal_for(attack.who)

    ben_session = graph.new_session(ben)
    graph.chat(ben, "Where is my espresso machine, ORD-100003?", session=ben_session)
    ben_thread = ben_session.thread_id

    guesses = [ben_thread]
    if ben_thread.startswith("thread-"):
        n = int(ben_thread.split("-")[1])
        guesses = [f"thread-{n}", f"thread-{n - 1}", f"thread-{n + 1}"]

    read, refused = [], []
    for g in guesses:
        try:
            history = memory.read_thread(g, alice)
            if history:
                read.append((g, history))
        except Denied as exc:
            refused.append((g, str(exc)))

    landed = bool(read)
    result = {"lights": dict(board.lights), "breaches": list(dict.fromkeys(board.breaches)),
              "findings": list(board.findings)}

    trace = [_line("user", 'Ben asks: "Where is my espresso machine, ORD-100003?"'),
             _line("memory", f"Ben's session was stored under thread id: {ben_thread}"),
             _line("why", f"Alice ({alice.id}) tries: {', '.join(guesses)}")]
    for g, history in read:
        trace.append(_line("tool", f"READ {g}: {len(history)} checkpoint(s) of "
                                   f"Ben's conversation"))
        for snap in history[:1]:
            for c in snap["context"][:4]:
                trace.append(_line("memory", f"    {c[:120]}"))
    for g, why in refused:
        trace.append(_line("blocked", f"refused {g}: {why}"))

    if verbose:
        _header(attack)
        print(f"  Ben's session was stored under thread id: {ben_thread}")
        print(f"  Alice ({alice.id}) tries: {', '.join(guesses)}")
        print(DASH)
        for g, history in read:
            print(f"  READ {g}: {len(history)} checkpoint(s) of Ben's conversation")
            for snap in history[:1]:
                for c in snap["context"][:4]:
                    print(f"        {c[:120]}")
        for g, why in refused:
            print(f"  refused {g}: {why}")
        _panel(result)
        _verdict(attack, landed)
    return {"attack": attack.id, "landed": landed, "lights": result["lights"],
            "transcript": trace, "awaiting": None}


def _run_memory_landmine(attack: Attack, verbose: bool) -> dict:
    """b4. Session 1 plants it. Session 2 - a brand new conversation - reads it."""
    alice = principal_for(attack.who)
    first = graph.chat(alice, attack.message)
    planted = [m for m in memory.memories() if m["approved"] == 1
               and "always approved" in m["text"].lower()]
    graph.SESSIONS.clear()
    second = graph.chat(alice, attack.follow_up[0])

    landed = bool(planted)
    result = {"lights": dict(board.lights), "breaches": list(dict.fromkeys(board.breaches)),
              "findings": list(board.findings)}

    trace = [_line("why", f'session 1 - the customer says: "{attack.message}"')]
    trace += first["transcript"]
    trace.append(_line("memory", "stored memories now:"))
    for m in memory.memories()[:4]:
        flag = "APPROVED" if m["approved"] else "pending approval"
        trace.append(_line("blocked" if m["approved"] else "memory",
                           f"    [{flag}] kind={m['kind']} {m['text'][:80]}"))
    trace.append(_line("why", f'session 2 - a NEW conversation: "{attack.follow_up[0]}"'))
    trace += second["transcript"]

    if verbose:
        _header(attack)
        print(f'session 1 - the customer says: "{attack.message}"')
        for line in first["transcript"]:
            print(f"  {line['kind']:<10} {line['text'][:140]}")
        print(DASH)
        print("  stored memories now:")
        for m in memory.memories()[:4]:
            flag = "APPROVED" if m["approved"] else "pending approval"
            print(f"    [{flag:^16}] kind={m['kind']:<10} {m['text'][:80]}")
        print(DASH)
        print(f'session 2 - a NEW conversation: "{attack.follow_up[0]}"')
        for line in second["transcript"]:
            print(f"  {line['kind']:<10} {line['text'][:140]}")
        _panel(result, ["the memory is read by every future session, for as long as it exists"])
        _verdict(attack, landed)
    return {"attack": attack.id, "landed": landed, "lights": result["lights"],
            "transcript": trace, "awaiting": None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kestrel attack", description=__doc__)
    ap.add_argument("target", nargs="?", default="all", help="attack id (b1..b8) or 'all'")
    ap.add_argument("--secure", action="store_true", help="every control on")
    ap.add_argument("--day1-only", action="store_true",
                    help="how today starts: the edge secured, the interior dark")
    ap.add_argument("--control", action="append", default=[])
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.secure:
        settings.apply_profile("secure")
    elif args.day1_only:
        settings.apply_profile("day1-only")
    for c in args.control:
        if c not in CONTROLS:
            print(f"unknown control {c!r}. Day 2 controls: {', '.join(DAY2)}")
            return 2
        settings.set(c, True)

    on = [c for c in DAY2 if settings.on(c)]
    print(f"model={settings.active_model}  |  Day 1 edge: LOCKED ON")
    print(f"Day 2 interior controls ON: {', '.join(on) if on else 'NONE - the interior is dark'}\n")

    targets = ORDER if args.target == "all" else [args.target.lower()]
    unknown = [t for t in targets if t not in ATTACKS]
    if unknown:
        print(f"unknown attack {unknown[0]!r}. known: {', '.join(ORDER)}")
        return 2

    results = [run_one(ATTACKS[t], verbose=not args.quiet) for t in targets]
    landed = [r["attack"] for r in results if r["landed"]]
    print(DASH)
    print(f"  {len(results) - len(landed)}/{len(results)} attacks stopped.")
    if landed:
        print(f"  still landing: {', '.join(landed)}")
    else:
        print("  Contained, detected, and gated. That is Workshop 2 complete.")
    print(DASH)
    return 1 if landed else 0


if __name__ == "__main__":
    sys.exit(main())
