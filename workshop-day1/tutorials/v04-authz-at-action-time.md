# v04 - Authorization at action time

**The action layer** | **Day 1, Block 4** | **Attacks** `a1`, `a2` | **Closed by** `SECURE_AUTHZ`, `SECURE_NO_CREDS_IN_STATE`

The question nobody asks until the incident review: whose authority is the agent acting under?

---

## What you are about to see

This page re-runs attacks you have already met - `a1`, `a2` and `a4` - and asks a different
question of them: **when** was permission checked?

A check at the start of a conversation is stale by the time a refund fires, because
everything in between is text the model can be talked into. The identity the agent
*received* and the identity it *believes* have had several turns to drift apart.

| The attacks | `a1`, `a2`, `a4` - revisited |
|---|---|
| Who runs it | Alice (`CUST-1001`), then a claim to be a supervisor |
| The question | Not "was this user allowed?" but "is this **action**, with **these arguments**, allowed **right now**?" |
| Closed by | `SECURE_AUTHZ` - three levels, checked at the action |
| Also here | `SECURE_NO_CREDS_IN_STATE` - if it is in state, it is in a checkpoint |

**Watch where the refusal happens.** With action-time RBAC on, the model may still be
perfectly steered - it asks for the refund anyway. The difference is that code, below the
model, says no at the point of action rather than trusting a decision made turns earlier.

---

## 1. Run the attack

```
python kestrel.py reset
python kestrel.py attack a1 --control SECURE_TENANCY --control SECURE_TOOLS --control SECURE_EXECUTOR
```

Tenancy is on. Tools are narrow. The executor is in place. And yet:

```
  model      [mock] chose tool get_order(order_id='ORD-100003')
  tool       get_order -> No matching orders.
```

Better - no data leaked. But notice what did **not** happen: nobody refused. No log line
says *"Alice tried to read Ben's order."* You silently returned an empty result, which
means your detection surface is zero and Alice can enumerate all day.

Now add authorization:

```
python kestrel.py attack a1 --secure
```

```
  blocked    get_order refused by authz at level=resource
  [warn]     authorization
```

## 2. The rule that was broken

> **The agent RECEIVES an identity. It never establishes one.**

| Your infrastructure | The agent |
|---|---|
| Authentication happens here. A session identity is **passed in**. | Receives it. Never invents one. |
| | Never trusts the model's claim about who the user is |
| | The model may **request**. Only code decides. |

The opening breach was exactly that failure: *the agent trusted the model's belief about
who was asking.*

## 3. RBAC is three checks, not one

`agent/authz.py`, `secure_check`, is a stub that raises `NotImplementedError` - that is your
exercise. Implement, in order, raising `Denied(level, reason)` at the first failure:

- **level 1 - INVOKE:** may this person talk to the agent at all? Check
  `session.principal.may_invoke_agent`.
- **level 2 - TOOL:** which tools does their role unlock? Check `call.name` against
  `ROLE_TOOLS[session.principal.role]`.
- **level 3 - RESOURCE:** which rows may THIS call touch? Use `resource_owner(call)`; if it
  names an owner, the caller isn't staff, and that owner isn't the caller's own
  `customer_id`, deny. Miss this one and you get slide 9.

Most teams build level 1, often build level 2, and almost never build level 3. Level 3 is
the one that produces cross-tenant incidents.

One more rule, after all three levels pass: a customer may refund their **own** order, but
only staff may issue a refund above `settings.refund_autonomous_ceiling_cents` ($50) -
anything larger from a customer-role caller must also be denied.

**A customer may refund their own order. Only staff issue an arbitrary credit.** Hold on
to the fact that refund splits by amount - it becomes the human-in-the-loop gate on Day 2.

## 4. Timing: check at the action, not at the start

```
conversation starts ---- steering happens ---- model requests the refund ---- ACTION
    check here = STALE                                                   check HERE
```

A conversation can be steered *after* it starts. A check at the top of the session is
stale by the time the refund fires. That is why `authz.check(...)` is **step 2 inside the
executor** (`agent/executor.py`), which runs on every single call - not a decorator on the
entry point, not a middleware at the front door.

Look at the order in `secure_execute` and notice that step 2 comes **before** step 3:

```python
_validate_args(call, spec)     # 1
authz.check(session, call)     # 2   <- before anything happens
result = spec.fn(call.args, session)  # 3
```

## 5. Two rules that bite people

### Rule 1 - credentials never in the context window

Not in the system prompt. Not in state. Not in a tool result.

> If it's in state, it's in a checkpoint - and checkpoints get read.

That is Day 2's subject, and it is the reason this rule exists today. `config.Settings`
drops `openrouter_api_key` from `snapshot()` for exactly this reason, and
`test_credentials_never_reach_the_context_window` asserts it.

### Rule 2 - the tenancy filter is enforced below the model

```
  Model
  Tool layer
  DATA LAYER  <- the filter lives here
```

Covered in `v01`. The point of restating it here: the resource check in `authz` and the
filter in `db` are **not redundant**. The authz check gives you a refusal you can log and
alert on. The data-layer filter is what still holds if someone adds a new tool next month
and forgets to wire the check in.

## 6. Prove it

`authz.secure_check` runs on **every** tool call once `SECURE_AUTHZ` is on - it is genuinely
shared infrastructure, not a1/a2-specific code. The narrowest, most immediate check calls it
directly, with nothing else in the pipeline involved:

```
python kestrel.py test  # or: pytest tests/test_attacks.py -k checked_at_the_action
```

`test_authorization_is_checked_at_the_action_not_at_the_start` asserts that the same
session is allowed `ORD-100001` and refused `ORD-100003` with `level == "resource"`.

```
python kestrel.py attack a1 --secure
python kestrel.py attack a2 --secure
python kestrel.py test
```

These use the full secure profile. Because `secure_check` gates every call, leaving it
unimplemented will make *every* attack's hardened-build test fail, not just `a1`/`a2` - and
because `SECURE_INTAKE` is checked even earlier in the pipeline (`v02`), expect a traceback
from there first if you haven't done that one yet. Work through the tutorials in order and
this settles once every stub is filled in.

## 7. Activity: who may say yes

Before Day 2, sort Kestrel's actions into four buckets. Argue the disagreements out loud -
**the argument is the learning**, and this sort is the input to tomorrow's human-in-the-loop
design.

| Autonomous | Verified identity | Human approver | Never for an agent |
|---|---|---|---|
| *just do it* | *needs the requesting customer* | *a person signs off* | *not available at all* |

Actions: `refund` · `cancel` · `discount` · `change-email` · `escalate` · `lookup-own` ·
`lookup-any`

Then the uncomfortable question: **every autonomous action is a standing decision to trust
the model.** Which of those decisions has your organisation ever made on purpose?
