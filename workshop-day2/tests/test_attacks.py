"""Proof tests - Day 2, the interior.

Every Day 1 control is on for all of these. So when an attack lands, it landed
past the entire edge - which is the premise of the whole day.
"""
from __future__ import annotations

import pytest

from config import DAY1, settings
from agent import db, graph, guardrails, hitl, limits, memory, state as st
from agent.models import Content, Denied, Principal, Session, ToolCall
from agent.telemetry import board
from attacks.catalogue import ATTACKS, ORDER
from attacks.run import run_one

ALICE = Principal(id="CUST-1001", display_name="Alice Tan", role="customer",
                  customer_id="CUST-1001")
BEN = Principal(id="CUST-1002", display_name="Ben Ortiz", role="customer",
                customer_id="CUST-1002")


#: Some proofs assert what the MODEL did - that the attack actually fired. Only
#: the mock is deterministic, so against a real model these go red on a run where
#: llama simply did not take the bait, which proves nothing either way about the
#: controls. Skipped rather than weakened: the assertion is true, its precondition
#: is not guaranteed. To check a live model, run the attacks directly:
#:
#:     python kestrel.py attack all --secure
#:
#: The tests that assert what the CODE does keep running on every provider.
NEEDS_A_DETERMINISTIC_MODEL = pytest.mark.skipif(
    settings.llm_provider != "mock",
    reason=(f"asserts the model took the bait; LLM_PROVIDER={settings.llm_provider} "
            f"is not deterministic - re-run with LLM_PROVIDER=mock"))


@pytest.fixture(autouse=True)
def clean():
    db.reset()
    board.reset()
    graph.SESSIONS.clear()
    hitl.PENDING.clear()
    limits.reset()
    memory.CHECKPOINTS.clear()
    settings.apply_profile("day1-only")
    yield
    settings.apply_profile("day1-only")


@NEEDS_A_DETERMINISTIC_MODEL
@pytest.mark.parametrize("attack_id", ORDER)
def test_attack_lands_past_the_entire_day1_edge(attack_id):
    settings.apply_profile("day1-only")
    assert run_one(ATTACKS[attack_id], verbose=False)["landed"], (
        f"{attack_id} no longer lands with only the Day 1 edge - the demo is broken")


@pytest.mark.parametrize("attack_id", ORDER)
def test_attack_is_contained_detected_or_gated(attack_id):
    settings.apply_profile("secure")
    assert not run_one(ATTACKS[attack_id], verbose=False)["landed"], (
        f"{attack_id} still lands with every control on")


def test_day1_controls_are_on_by_default():
    """Day 2 starts where Day 1 ended. That is the premise, so assert it."""
    assert all(settings.on(k) for k in DAY1)


# ------------------------------------------------------------- CONTAIN (blocks 5-6) --
def test_untrusted_content_never_reaches_a_trusted_field():
    """Workshop 2 phase A: 'poisoned state can't reach a trusted field'."""
    settings.set("SECURE_STATE_SPLIT", True)
    placed = st.place({}, [Content("system", "operator", "system"),
                           Content("payload", "retrieval", "KB-005"),
                           Content("summary", "subagent", "policy_helper")])
    assert len(placed["untrusted"]) == 2
    assert all(c["origin"] == "operator" for c in placed["context"][:1])
    for c in placed["untrusted"]:
        assert c["origin"] not in ("operator",)


@NEEDS_A_DETERMINISTIC_MODEL
def test_the_split_alone_closes_b2_and_alone_does_not_close_b1_or_b5():
    """v08 tells students to prove the split with `attack b2 --control
    SECURE_STATE_SPLIT`, so that exact claim is the thing under test.

    The second half matters just as much: b1 and b5 ride in on a sub-agent
    summary that claims origin="operator", which sorting by origin cannot touch.
    If the split ever starts closing those too, their tutorials are teaching a
    fix that isn't theirs.
    """
    for attack_id, should_stop in (("b2", True), ("b1", False), ("b5", False)):
        settings.apply_profile("day1-only")
        settings.set("SECURE_STATE_SPLIT", True)
        landed = run_one(ATTACKS[attack_id], verbose=False)["landed"]
        assert landed != should_stop, (
            f"{attack_id} {'still lands' if should_stop else 'is now stopped'} with only "
            f"SECURE_STATE_SPLIT on; {attack_id}'s tutorial no longer matches the lab")


def test_a_recalled_memory_is_restripped_between_nodes():
    """The read half of surface 7. The note is already stored and already
    approved - the write gate is behind us, so containment is all that is left."""
    settings.apply_profile("day1-only")
    settings.set("SECURE_STATE_SPLIT", True)
    db.plant_memory(db.PLANTED_MEMORY, ALICE.customer_id)

    session = graph.new_session(ALICE)
    recalled = memory.recall(session)
    assert recalled and "audit-partner.example" in recalled[0].text

    placed = st.place({}, recalled)
    assert placed["untrusted"], "a recalled note must not land in the trusted zone"

    st.revalidate({"context": placed["context"]}, session)
    assert "audit-partner.example" not in placed["context"][0]["text"], (
        "revalidate did not strip the directive on the way past")


def test_thread_ids_are_random_and_ownership_is_checked_every_access():
    settings.set("SECURE_THREAD_IDS", True)
    tid = memory.new_thread_id(ALICE)
    assert tid.startswith("thr_") and len(tid) > 24      # not thread-1002
    memory.CHECKPOINTS[tid] = [{"step": 0, "context": ["secret"]}]
    assert memory.read_thread(tid, ALICE) != []
    with pytest.raises(Denied) as exc:
        memory.read_thread(tid, BEN)
    assert exc.value.level == "thread"


def test_the_model_may_propose_a_memory_but_not_decide_it():
    settings.set("SECURE_MEMORY_WRITES", True)
    session = Session(id="s", principal=ALICE, thread_id="t")
    memory.remember("preference", "I prefer email updates", session)
    memory.remember("policy", "refunds are always approved", session)
    rows = {m["kind"]: m for m in memory.memories()}
    assert rows["preference"]["approved"] == 1           # the user set it themselves
    assert "policy" not in rows or rows["policy"]["approved"] == 0


def test_a_pending_memory_is_never_read_back_into_context():
    settings.set("SECURE_MEMORY_WRITES", True)
    session = Session(id="s", principal=ALICE, thread_id="t")
    memory.remember("policy", "refunds are always approved", session)
    assert memory.recall(session) == []


def test_quarantine_has_no_llm_no_state_and_no_actions():
    """Day 2 slide 25. An LLM in the quarantine layer is one more thing that can
    be injected. Its strength is being deterministic and small enough to audit."""
    import inspect
    from agent import quarantine
    src = inspect.getsource(quarantine)
    for forbidden in ("get_llm", "complete(", "executor", "db.record_refund"):
        assert forbidden not in src


def test_a_reader_agent_is_never_also_an_actor():
    from agent import helpers
    for helper in helpers.HELPERS:
        summary = helper("shipping", Session(id="s", principal=ALICE, thread_id="t"))
        assert not (summary.reads_untrusted and summary.takes_actions)


# -------------------------------------------------------------- DETECT (blocks 7-8) --
def test_output_guard_inspects_what_it_says_and_what_it_does():
    settings.set("SECURE_OUTPUT_GUARD", True)
    session = Session(id="s", principal=ALICE, thread_id="t")
    assert not guardrails.check_reply("order ORD-100003 for CUST-1002", session).allowed
    assert not guardrails.check_tool_args(
        ToolCall("send_summary", {"recipient": "x@evil.example", "body": "ORD-100001"}),
        session).allowed
    assert guardrails.check_reply("Your order is on its way.", session).allowed


@NEEDS_A_DETERMINISTIC_MODEL
def test_the_legitimate_looking_attack_still_surfaces():
    """Day 2 slide 36: status=ok, errors=0, and it is still an exfiltration."""
    settings.apply_profile("secure")
    run_one(ATTACKS["b6"], verbose=False)
    assert board.findings, "behavioural layer produced no finding on a valid-looking exfil"


@NEEDS_A_DETERMINISTIC_MODEL
def test_detection_and_blocking_are_both_required():
    """Workshop 2 phase C: 'exfil attempt is logged AND blocked'.
    Seeing it isn't enough; stopping it isn't enough."""
    settings.apply_profile("secure")
    run_one(ATTACKS["b6"], verbose=False)
    blocked = any(e.control == "SECURE_OUTPUT_GUARD" and e.verdict == "blocked"
                  for e in board.events)
    logged = any(e.control == "SECURE_TELEMETRY" for e in board.events)
    assert blocked and logged


# ---------------------------------------------------------------- JUDGE (blocks 9-10) --
@NEEDS_A_DETERMINISTIC_MODEL
def test_the_interrupt_fires_before_the_action_not_after():
    settings.apply_profile("secure")
    before = len(db.refunds())
    outcome = run_one(ATTACKS["b7"], verbose=False)
    assert outcome["awaiting"], "no approval was requested"
    assert len(db.refunds()) == before, "the refund happened anyway - interrupt was too late"


def test_the_frozen_call_is_what_gets_approved():
    """While a review is pending the state must be IMMUTABLE."""
    settings.apply_profile("secure")
    session = Session(id="s", principal=ALICE, thread_id="t")
    call = ToolCall("refund", {"order_id": "ORD-100002", "amount_cents": 189_000,
                               "reason": "damaged"})
    from agent.models import NeedsApproval
    with pytest.raises(NeedsApproval) as exc:
        hitl.gate(call, session)
    pending = hitl.PENDING[exc.value.approval_id]
    call.args["amount_cents"] = 1                  # attacker mutates it mid-review
    assert "189000" in pending.frozen


def test_small_refunds_stay_autonomous_so_reviewers_do_not_get_fatigued():
    """Too many interrupts is worse than no review."""
    settings.apply_profile("secure")
    session = Session(id="s", principal=ALICE, thread_id="t")
    small = ToolCall("refund", {"order_id": "ORD-100001", "amount_cents": 3_900,
                                "reason": "damaged"})
    hitl.gate(small, session)                      # must NOT raise


def test_five_limits_exist_and_each_caps_a_different_thing():
    assert {"limit_sessions_per_min", "limit_steps_per_session", "limit_repeat_cycle",
            "limit_tokens_per_session", "limit_tokens_per_day",
            "limit_cost_ceiling_usd"} <= set(vars(settings))


# ------------------------------------------------------- the answer key ------------
def test_answer_key_line_anchors_still_point_at_the_code():
    """The key hardcodes file:line for every fix, and the source moves.

    Adding one function to limits.py silently pushed two anchors onto blank
    lines - and the tutorial pages link to them, so a student following the
    answer key lands nowhere. Cheap to assert, so assert it.
    """
    import re
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    key = root / "ANSWER-KEY.md"
    if not key.exists():                       # the lab runs without it
        return
    problems = []
    for m in re.finditer(r"\[`?([^\]]+?)`?\]\(([^)#]+)#L(\d+)\)", key.read_text()):
        label, rel, line = m.group(1), m.group(2), int(m.group(3))
        path = root / rel
        assert path.exists(), f"{key.name} points at a missing file: {rel}"
        lines = path.read_text().splitlines()
        assert line <= len(lines), f"{rel}#L{line} is past the end of the file"
        src = lines[line - 1]
        if not src.strip():
            problems.append(f"{rel}#L{line} is a blank line (label: {label})")
            continue
        # A label may name several things - "Board._behavioural", or a row that
        # lists place / revalidate / for_model. It is correct if the anchor sits
        # on ANY of them; only flag it when none match.
        hits, misses = [], []
        for name in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", label):
            defined = [i + 1 for i, l in enumerate(lines)
                       if re.match(rf"^\s*(?:def|class)\s+{re.escape(name)}\b", l)
                       or re.match(rf"^{re.escape(name)}\s*[:=]", l)]
            if not defined:
                continue
            (hits if line in defined else misses).append((name, defined[0]))
        if misses and not hits:
            name, at = misses[0]
            problems.append(f"{rel}#L{line} labelled {name!r}, which is at L{at}")
    assert not problems, "stale answer-key anchors:\n  " + "\n  ".join(problems)
