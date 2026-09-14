# Answer key — Day 2, the interior (`b1` – `b8`)

**Instructor material.** Hand this out *after* the room has fought each attack.

> Day 1's edge attacks have their own key: [`ANSWER-KEY-DAY1.md`](ANSWER-KEY-DAY1.md).

---

## How to read this key

Same shape as Day 1: every control is a runtime switch between two functions that both
ship in the same file, so "Before" and "After" are two functions a few lines apart rather
than two branches.

**Day 2 starts where Day 1 ended.** All nine Day 1 controls are locked on for every attack
below — see [`config.py`](workshop-day2/config.py). So when a `b`-attack lands, it landed
**past the entire edge**. That is the premise of the day, and it is asserted by a test
(`test_day1_controls_are_on_by_default`).

The three themes, and the question each answers:

| | Blocks | The question |
|---|---|---|
| **CONTAIN** | 5 – 6 | Given they are in, how much can they reach? |
| **DETECT** | 7 – 8 | Will we notice? |
| **JUDGE** | 9 – 10 | What did we refuse to automate? |

```
python kestrel.py attack all            # 0/8 stopped
python kestrel.py attack all --secure   # 8/8 stopped
```

---

## CONTAIN — blocks 5 and 6

### b1 — The attack that didn't arrive as input · `SECURE_QUARANTINE` · `SECURE_STATE_SPLIT` · `SECURE_OUTPUT_GUARD` · `SECURE_HITL`

**The Day 2 opening demo.** The customer's question is innocuous. Every Day 1 input control is on and stays green. The payload was read by a tier-1 sub-agent and handed to Kestrel as if one of your own components wrote it.

| Before | After | What changed |
|---|---|---|
| [`helpers.vulnerable_consult`](workshop-day2/agent/helpers.py#L81) — splices each sub-agent's text into context as `origin="operator"`. One line, and it is the whole attack: *"you wrote this." You did not.* | [`helpers.secure_consult`](workshop-day2/agent/helpers.py#L99) → [`quarantine.check`](workshop-day2/agent/quarantine.py#L26) — schema, strip, bound, then tag as `origin="subagent"`. | Four steps, deterministic, **no LLM in the quarantine layer** — an LLM there is one more thing that can be injected. A test asserts the file contains no `get_llm`, no executor, no writes. Its strength is being small enough to read in a minute and be sure of. |

**The essence:** you can verify a message came from the policy helper. You cannot verify the policy helper wasn't manipulated into sending it. That is structural, not a bug — so the defence is containment, not authentication.

### b2 — Poison once, spread everywhere · `SECURE_STATE_SPLIT`

The payload lands at one node, and the agent carries it to every node after, on the attacker's behalf, free of charge.

| Before | After | What changed |
|---|---|---|
| One flat `context` list — system prompt, user message, retrieved article and sub-agent summary, in arrival order, indistinguishable. | [`state.place`](workshop-day2/agent/state.py#L43) sorts by origin into `context` **and** `untrusted`; [`state.revalidate`](workshop-day2/agent/state.py#L89) re-checks carried content between nodes; [`state.for_model`](workshop-day2/agent/state.py#L131) re-fences on every assembly. | Three moves. **Split** so trust is a schema property, not a convention. **Revalidate** so the payload cannot ride free from node 1 to node 4. **Re-fence on render**, because a tag applied once at the boundary is a tag the attacker only has to survive once. [`assert_containment`](workshop-day2/agent/state.py#L62) is the proof. |

**The essence:** when instruction and data share a field, the agent cannot tell them apart. Containment starts at the schema.

> **Note on scope.** `revalidate` deliberately skips the live user turn — that is gated once at intake (Day 1, surface 1). Stripping the customer's own message on every step neutralises `b6` before it starts, and the output guard then has nothing to catch.

### b3 — Thread-ID guessing · `SECURE_THREAD_IDS`

Change one digit and read another user's entire conversation history out of the checkpoint store.

| Before | After | What changed |
|---|---|---|
| [`memory.vulnerable_thread_id`](workshop-day2/agent/memory.py#L33) — `thread-1001`, `thread-1002`, a counter. And [`read_thread`](workshop-day2/agent/memory.py#L65) checks nothing at all. | [`memory.secure_thread_id`](workshop-day2/agent/memory.py#L44) — `secrets.token_urlsafe(24)`, bound to `principal.id` in the `threads` table at creation; `read_thread` looks up the owner and raises `Denied` on **every** access. | Two halves, and one without the other is theatre. An unguessable id is the lock; the ownership check is whether the key fits. Same wall as Day 1's tenancy filter, different room: live queries then, **stored state** now. |

**The essence:** most teams have never threat-modelled the checkpoint store. Every checkpoint is a full copy of state — if a credential was ever in state, it is in a checkpoint now.

### b4 — The memory landmine · `SECURE_MEMORY_WRITES`

Session 1 plants it. Session 2 — a brand-new conversation — detonates it. And every session after that.

| Before | After | What changed |
|---|---|---|
| [`memory.vulnerable_remember`](workshop-day2/agent/memory.py#L111) — the model decides what to memorise, and hardcodes `approved=1`. | [`memory.secure_remember`](workshop-day2/agent/memory.py#L132) — unknown `kind` falls back to `policy` (fail safe), instruction-shaped text is refused outright, and `approved` comes from [`MEMORY_GATES`](workshop-day2/agent/memory.py#L104), never a literal. | Yesterday's rule applied to the one store that outlives the session: **the model may propose, only code decides.** A preference the user set themselves is fine. A *policy* about what the agent may do needs a human. [`recall`](workshop-day2/agent/memory.py#L176) never reads back a pending row. |

**The essence:** a poisoned memory is not a one-shot. It re-detonates on every future session that reads it.

### b5 — Trust inheritance · `SECURE_QUARANTINE` · `SECURE_PRIV_SEP`

The attack enters through the **least**-privileged agent and executes with the **most**-privileged agent's authority.

| Before | After | What changed |
|---|---|---|
| `policy_helper` is tier 1 and can take no action — so it looks harmless. The danger is not what it can *do*, it is what it can *say* to something that can. | [`quarantine.check`](workshop-day2/agent/quarantine.py#L26) for the content, plus the privilege-separation assertion at [`helpers.py#L109`](workshop-day2/agent/helpers.py#L109): a helper that reads untrusted content may never also be an actor. | Conventional mesh: signature valid → content trusted. LLM agents: signature valid → content **unknown**. `SECURE_PRIV_SEP` lives inside `secure_consult`, so it only runs once `SECURE_QUARANTINE` is on — the two are a pair. |

**The essence:** the moment your agent believes another agent's output without checking, a compromise anywhere in the mesh is a compromise everywhere.

---

## DETECT — blocks 7 and 8

### b6 — Silent exfiltration through a perfectly valid tool call · `SECURE_OUTPUT_GUARD` · `SECURE_TELEMETRY`

The call is schema-valid, authorization passes, the API returns 200 — and the data is gone. `status=ok`. `errors=0`.

| Before | After | What changed |
|---|---|---|
| [`guardrails.vulnerable_check_reply`](workshop-day2/agent/guardrails.py#L59) and [`vulnerable_check_tool_args`](workshop-day2/agent/guardrails.py#L98) — both return `allow`, unconditionally. | [`secure_check_reply`](workshop-day2/agent/guardrails.py#L63) inspects what it **says**; [`secure_check_tool_args`](workshop-day2/agent/guardrails.py#L102) inspects what it **does** — SQL, shell metacharacters, traversal, foreign customer ids, high-entropy blobs, and unapproved recipient domains. | Two kinds of output, two kinds of danger. The second half is the one teams forget: everything about the call is valid, and data walks out **inside an argument**. |

**The essence:** guard what it says *and* what it does. The morning's breach left through a tool call that looked completely normal.

### v13 — The attack that looks like normal traffic · `SECURE_TELEMETRY`

**This block has no attack id of its own.** That is the lesson: `v13` re-reads the board from the attacks you already ran, because an attack that looks like normal traffic is not something you can fire on demand.

| Before | After | What changed |
|---|---|---|
| Telemetry records events. Nothing asks whether the pattern is *normal*. | [`Board._behavioural`](workshop-day2/agent/telemetry.py#L110) compares each event against [`BASELINE`](workshop-day2/agent/telemetry.py#L68)'s four numbers: records per call, outbound calls per session, an outbound tool used at all, tool calls per turn. | Security controls **prevent**. Observability **detects**. You need both, and a test asserts it: `test_detection_and_blocking_are_both_required`. |

> **Design note.** `_behavioural` counts what the agent *decided* to do, at the `plan` node — not what survived to execution. The output guard blocks `send_summary` before the executor records anything, so keying detection on execution would go blind exactly when prevention works.

**The essence:** it asks "is this normal?", not "is this known-bad?" — which is the only question that catches an attack nobody has seen before.

---

## JUDGE — blocks 9 and 10

### b7 — An irreversible action with nobody on it · `SECURE_HITL`

$1,890 refunded, approved by nobody.

| Before | After | What changed |
|---|---|---|
| [`hitl.vulnerable_gate`](workshop-day2/agent/hitl.py#L71) — lights a warning and lets it through. Every action autonomous. | [`hitl.secure_gate`](workshop-day2/agent/hitl.py#L84) — freezes a **copy** of the call into `Pending` and raises `NeedsApproval` **before** the side effect. | Interrupt before, never after. And the frozen snapshot is what a human approves — `test_the_frozen_call_is_what_gets_approved` mutates the args mid-review to prove it. Small refunds stay autonomous: **too many interrupts is worse than no review**, because reviewers start approving without reading. |

**The essence:** every autonomous action is a standing decision to trust the model. Most organisations have never made that decision on purpose — it just accreted.

### b8 — Economic exhaustion · `SECURE_LIMITS`

Not a breach. A bill. Nothing stolen, no action taken.

| Before | After | What changed |
|---|---|---|
| Nothing capped. The only backstop is the graph's recursion limit — a framework safety net, not a control you chose. | [`limits.check_session_start`](workshop-day2/agent/limits.py#L37) (request rate) and [`limits.check_step`](workshop-day2/agent/limits.py#L58) (session steps, loop detection, token budget per-session **and** daily, cost ceiling). | **One rate limit isn't enough.** A gateway cap of 1 request/minute is perfectly satisfied while that single request burns 200 steps and 500K tokens. Five independent levels, because the attack picks the one you didn't guard. |

**The essence:** amplification is the point of agents, and the danger of them.

---

## Master table

| # | Attack | Theme | Surface | Closed by | Tutorial |
|---|---|---|---|---|---|
| b1 | Didn't arrive as input | CONTAIN | 6 → 7 → output | `SECURE_QUARANTINE` `SECURE_STATE_SPLIT` `SECURE_OUTPUT_GUARD` `SECURE_HITL` | [v11](workshop-day2/tutorials/v11-trust-inheritance.md) |
| b2 | Poison once, spread everywhere | CONTAIN | 7 state | `SECURE_STATE_SPLIT` | [v08](workshop-day2/tutorials/v08-state-poisoning.md) |
| b3 | Thread-ID guessing | CONTAIN | 7 checkpoints | `SECURE_THREAD_IDS` | [v09](workshop-day2/tutorials/v09-thread-id-guessing.md) |
| b4 | The memory landmine | CONTAIN | 7 long-term memory | `SECURE_MEMORY_WRITES` | [v10](workshop-day2/tutorials/v10-memory-landmine.md) |
| b5 | Trust inheritance | CONTAIN | 6 other agents | `SECURE_QUARANTINE` `SECURE_PRIV_SEP` | [v11](workshop-day2/tutorials/v11-trust-inheritance.md) |
| b6 | Silent exfiltration | DETECT | output | `SECURE_OUTPUT_GUARD` `SECURE_TELEMETRY` | [v12](workshop-day2/tutorials/v12-silent-exfiltration.md) |
| b7 | Irreversible, nobody on it | JUDGE | action | `SECURE_HITL` | [v14](workshop-day2/tutorials/v14-irreversible-action.md) |
| b8 | Economic exhaustion | JUDGE | amplification | `SECURE_LIMITS` | [v15](workshop-day2/tutorials/v15-cost-exhaustion.md) |

## The nine Day 2 controls

| Control | Block | Where it lives |
|---|---|---|
| `SECURE_STATE_SPLIT` | 5 | [`state.place` / `revalidate` / `for_model`](workshop-day2/agent/state.py#L43) |
| `SECURE_THREAD_IDS` | 5 | [`memory.secure_thread_id`](workshop-day2/agent/memory.py#L44) + [`read_thread`](workshop-day2/agent/memory.py#L65) |
| `SECURE_MEMORY_WRITES` | 5 | [`memory.secure_remember`](workshop-day2/agent/memory.py#L132) |
| `SECURE_QUARANTINE` | 6 | [`quarantine.check`](workshop-day2/agent/quarantine.py#L26) |
| `SECURE_PRIV_SEP` | 6 | [`helpers.py#L109`](workshop-day2/agent/helpers.py#L109) |
| `SECURE_OUTPUT_GUARD` | 7 | [`guardrails.secure_check_reply`](workshop-day2/agent/guardrails.py#L63) + [`secure_check_tool_args`](workshop-day2/agent/guardrails.py#L102) |
| `SECURE_TELEMETRY` | 8 | [`Board._behavioural`](workshop-day2/agent/telemetry.py#L110) |
| `SECURE_HITL` | 9 | [`hitl.secure_gate`](workshop-day2/agent/hitl.py#L84) |
| `SECURE_LIMITS` | 10 | [`limits.check_session_start`](workshop-day2/agent/limits.py#L37) + [`check_step`](workshop-day2/agent/limits.py#L58) |

## Verify it yourself

```
cd workshop-day2
python kestrel.py attack all              # 0/8 stopped - Day 1's edge on, interior dark
python kestrel.py attack all --secure     # 8/8 stopped
python kestrel.py attack b4 --control SECURE_MEMORY_WRITES
python kestrel.py test                    # 30 proof tests
python kestrel.py controls                # Day 1 locked on, Day 2 yours to switch
```

### One thing to know before the room asks

Several tutorials' single-control "Prove it" steps show the taught light going green while
the run still prints `ATTACK LANDED`. That is not a broken fix. `landed` is **any** red
light, and the helper-contamination light stays red for as long as `SECURE_QUARANTINE` is
off — so `b7 --control SECURE_HITL` moves `human_gate` from BREACH to warn, and
`state_containment` keeps the verdict red. `b3`, `b4` and `b5` do print `attack stopped` on
their own single control. Read the **light**, not the verdict, when running one control at
a time; the verdict is honest only for `--secure`.
