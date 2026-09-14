"""Proof tests.

Each attack is asserted TWICE:

    against the shipped build   it must LAND     (otherwise the lesson is fake)
    against the hardened build  it must be STOPPED

The second assertion is your workshop grade. The first one is what stops an
instructor from demoing a vulnerability that quietly stopped working.
"""
from __future__ import annotations

import pytest

from config import settings
from agent import db, graph, intake
from agent.models import Principal
from agent.telemetry import board
from attacks.catalogue import ATTACKS, ORDER
from attacks.run import run_one

ALICE = Principal(id="CUST-1001", display_name="Alice Tan", role="customer",
                  customer_id="CUST-1001")


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
    yield
    settings.apply_profile("vulnerable")


@NEEDS_A_DETERMINISTIC_MODEL
@pytest.mark.parametrize("attack_id", ORDER)
def test_attack_lands_against_the_shipped_build(attack_id):
    settings.apply_profile("vulnerable")
    assert run_one(ATTACKS[attack_id], verbose=False)["landed"], (
        f"{attack_id} no longer lands against the vulnerable build - the demo is broken")


@pytest.mark.parametrize("attack_id", ORDER)
def test_attack_is_stopped_by_the_hardened_build(attack_id):
    settings.apply_profile("secure")
    assert not run_one(ATTACKS[attack_id], verbose=False)["landed"], (
        f"{attack_id} still lands with every control on")


# --------------------------------------------------------------- the specific claims --
def test_tenancy_filter_is_the_control_that_closes_the_opening_breach():
    """Day 1 slide 56: 'Data-boundary light stays GREEN on the cross-tenant attack.'"""
    settings.apply_profile("vulnerable")
    settings.set("SECURE_TENANCY", True)
    settings.set("SECURE_TOOLS", True)
    settings.set("SECURE_EXECUTOR", True)
    settings.set("SECURE_AUTHZ", True)
    run_one(ATTACKS["a1"], verbose=False)
    assert board.lights["data_boundary"] == "green"


def test_narrow_tools_make_the_attack_unrepresentable():
    """Day 1 slide 38. Not 'filtered' - unrepresentable. There is no sql argument."""
    from agent import tools
    settings.set("SECURE_TOOLS", True)
    assert "lookup_orders" not in tools.registry()
    assert "sql" not in tools.registry()["get_order"].parameters["properties"]


def test_validation_blocks_four_of_five_payloads_and_misses_the_natural_one():
    """Day 1 slide 33. The wrong prediction IS the lesson."""
    settings.set("SECURE_INTAKE", True)
    outcome = {name: intake.check(p).allowed for name, p in intake.PAYLOADS.items()}
    assert outcome == {"P1-length-bomb": False, "P2-delimiter": False, "P3-base64": False,
                       "P4-override": False, "P5-natural": True}


def test_the_data_layer_has_no_path_that_returns_another_customers_rows():
    """Day 1 slide 50, rule 2. The filter is not optional and not a keyword argument."""
    rows = db.secure_orders_for(ALICE)
    assert rows and all(r["customer_id"] == "CUST-1001" for r in rows)
    assert db.secure_orders_for(ALICE, "ORD-100003") == []      # Ben's order


def test_credentials_never_reach_the_context_window():
    """Day 1 slide 50, rule 1. If it is in state, it is in a checkpoint."""
    settings.apply_profile("secure")
    graph.chat(ALICE, "Where is my order ORD-100001?")
    from agent.telemetry import board as b
    blob = " ".join(e.detail for e in b.events)
    for secret in ("OPENROUTER_API_KEY", "sk-", "password", "Bearer "):
        assert secret not in blob


def test_authorization_is_checked_at_the_action_not_at_the_start():
    """Day 1 slide 49. A check at the top is stale by the time the refund fires."""
    from agent import authz
    from agent.models import Denied, Session, ToolCall
    settings.set("SECURE_AUTHZ", True)
    session = Session(id="s", principal=ALICE, thread_id="t")
    authz.check(session, ToolCall("get_order", {"order_id": "ORD-100001"}))    # own order: fine
    with pytest.raises(Denied) as exc:
        authz.check(session, ToolCall("get_order", {"order_id": "ORD-100003"}))
    assert exc.value.level == "resource"
