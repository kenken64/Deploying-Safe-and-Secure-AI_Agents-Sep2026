"""Attack runner.

    python kestrel.py attack a1            run one attack against the current build
    python kestrel.py attack all           run the whole catalogue
    python kestrel.py attack a1 --secure   run it against the hardened build

Output is deliberately plain ASCII so it renders the same on macOS Terminal,
Windows PowerShell and a Linux console.
"""
from __future__ import annotations

import argparse
import sys
import textwrap

from config import CONTROLS, settings
from agent import db, graph, intake
from agent.models import Principal
from agent.telemetry import board
from attacks.catalogue import ATTACKS, ORDER, Attack

BAR = "=" * 78
DASH = "-" * 78


def principal_for(customer_id: str) -> Principal:
    row = db.customer(customer_id)
    return Principal(id=customer_id, display_name=row["name"] if row else customer_id,
                     role="customer", customer_id=customer_id)


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
    # Each attack starts from the seeded database, so a refund issued by the
    # previous run cannot make the next result a lie.
    db.reset()
    board.reset()
    graph.SESSIONS.clear()
    before = len(db.refunds())

    if attack.id == "a4":
        return _run_payload_set(attack, verbose)

    result = graph.chat(principal_for(attack.who), attack.message)
    after = len(db.refunds())
    landed = (board.worst() == "red") or (after > before)

    if verbose:
        print(BAR)
        print(f"{attack.id.upper()}  {attack.name}")
        print(f"surface {attack.surface}: {attack.entry_point} -> {attack.stage} -> {attack.impact}")
        print(DASH)
        print(f'customer says: "{attack.message}"')
        print(DASH)
        for line in result["transcript"]:
            print(f"  {line['kind']:<10} {line['text'][:150]}")
        print(DASH)
        for name, level in result["lights"].items():
            mark = {"green": "[ ok ]", "amber": "[warn]", "red": "[BREACH]"}[level]
            print(f"  {mark:<9} {name}")
        if result["breaches"]:
            for b in dict.fromkeys(result["breaches"]):
                print(f"  !! {b}")
        if after > before:
            print(f"  !! {after - before} refund(s) were actually issued")
        print(DASH)
        verdict = "ATTACK LANDED" if landed else "attack stopped"
        print(f"  {verdict}")
        if not landed:
            print(f"  {_why_stopped(attack)}")
        else:
            off = [c for c in attack.closed_by if not settings.on(c)]
            print(f"  fix it with: {', '.join(off)}")
            print(f"  step by step: tutorials/{attack.tutorial}.md")
        print(BAR)
        print()

    return {"attack": attack.id, "landed": landed, "lights": result["lights"],
            "refunds_issued": after - before, "transcript": result["transcript"]}


def _run_payload_set(attack: Attack, verbose: bool) -> dict:
    """a4 - the five payloads. Predict first. (Day 1, slide 32, exercise 3)"""
    if verbose:
        print(BAR)
        print("A4  Beat the validator - five payloads")
        print(DASH)
        print("  Write your prediction DOWN before reading the results below.")
        print("  Which of the five does layered intake validation catch?")
        print(DASH)
    # The console renders whatever is in `transcript`, so a4 has to fill it in
    # itself: the five verdicts ARE the output here, and without them the web UI
    # showed a bare "attack stopped/landed" and nothing else.
    transcript: list[dict] = []
    results = {}
    for name, payload in intake.PAYLOADS.items():
        verdict = intake.check(payload)
        results[name] = verdict.allowed
        mark = ("passed the validator" if verdict.allowed
                else f"BLOCKED at the {verdict.layer} layer - {verdict.reason}")
        transcript.append({"kind": "payload", "text": f"{name:<18} {mark}"})
        if verbose:
            mark = "passed the validator" if verdict.allowed else f"BLOCKED at the {verdict.layer} layer"
            print(f"  {name:<18} {mark}")
            if not verdict.allowed:
                print(f"  {'':<18} reason: {verdict.reason}")
    # Now take the one that got through and run it all the way in. Validation is
    # not the last line - so the honest question is what happens NEXT.
    board.reset()
    graph.SESSIONS.clear()
    before = len(db.refunds())
    end_to_end = graph.chat(principal_for(attack.who), intake.PAYLOADS["P5-natural"])
    leaked = board.worst() == "red" or len(db.refunds()) > before

    got_through = [k for k, allowed in results.items() if allowed]
    if not settings.on("SECURE_INTAKE"):
        headline = "Intake validation is OFF - all five went straight through. Turn it on."
    elif got_through == ["P5-natural"]:
        headline = ("Four of five blocked. The one that got through is structurally "
                    "IDENTICAL to a real customer request - there is nothing malformed "
                    "to catch. Validation cannot read intent it cannot see.")
    else:
        headline = f"{len(results) - len(got_through)} of five blocked."
    transcript.append({"kind": "note", "text": headline})
    transcript.append({"kind": "note",
                       "text": "Running P5-natural end to end, to see what catches it instead:"})
    transcript.extend(end_to_end["transcript"])
    # Name the control that ACTUALLY fired. Under the full secure profile authz
    # refuses at the action; with tenancy but no authz the row simply never comes
    # back. Saying "the tenancy filter" either way credits a control that did not run.
    refused = any(t["kind"] == "blocked" for t in end_to_end["transcript"])
    outcome = (
        "NOTHING DID. It reached another customer's order - which is why the next two "
        "blocks are tools and authorization." if leaked else
        "Stopped BELOW the model, where the model cannot reach or override it - "
        + ("action-time authorization refused the call."
           if refused else "the tenancy filter never returned the row.")
        + " Validation let it through and the layer beneath it caught the request. "
          "That is defence in depth.")
    transcript.append({"kind": "note", "text": outcome})

    if verbose:
        print(DASH)
        if not settings.on("SECURE_INTAKE"):
            print("  Intake validation is OFF - all five went straight through.")
            print("  Turn it on (--control SECURE_INTAKE) and run this again.")
        elif got_through == ["P5-natural"]:
            print("  Four of five blocked. The one that got through is structurally")
            print("  IDENTICAL to a real customer request - there is nothing malformed")
            print("  to catch. Validation cannot read intent it cannot see.")
        print(DASH)
        print("  Running P5-natural end to end, to see what catches it instead:")
        for line in end_to_end["transcript"]:
            print(f"    {line['kind']:<10} {line['text'][:130]}")
        print(textwrap.fill(outcome, width=78, initial_indent="  -> ",
                            subsequent_indent="     "))
        print(f"  step by step: tutorials/{attack.tutorial}.md")
        print(BAR)
        print()
    return {"attack": attack.id, "landed": leaked, "payloads": results,
            "transcript": transcript}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="kestrel attack", description=__doc__)
    ap.add_argument("target", nargs="?", default="all", help="attack id (a1..a7) or 'all'")
    ap.add_argument("--secure", action="store_true", help="run against the hardened build")
    ap.add_argument("--vulnerable", action="store_true", help="run against the shipped build")
    ap.add_argument("--control", action="append", default=[],
                    help="turn one control on, e.g. --control SECURE_TENANCY")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args(argv)

    if args.secure:
        settings.apply_profile("secure")
    elif args.vulnerable:
        settings.apply_profile("vulnerable")
    for c in args.control:
        if c not in CONTROLS:
            print(f"unknown control {c!r}. known: {', '.join(CONTROLS)}")
            return 2
        settings.set(c, True)

    on = [c for c in CONTROLS if settings.on(c)]
    print(f"model={settings.llm_provider}  controls ON: {', '.join(on) if on else 'NONE (shipped build)'}\n")

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
        print("  Every attack in the catalogue is stopped. That is Workshop 1 complete.")
    print(DASH)
    return 1 if landed else 0


if __name__ == "__main__":
    sys.exit(main())
