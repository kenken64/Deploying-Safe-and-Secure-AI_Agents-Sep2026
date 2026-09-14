# v13 - The attack that looks like normal traffic

**All surfaces** | **Block 8** | **Closed by** `SECURE_TELEMETRY`

> Security controls PREVENT attacks. Observability DETECTS them. You need both.

---

## What you are about to see

**This page has no attack of its own, and that is the lesson.** An attack that looks like
normal traffic is not something you can fire on demand and point at - so instead you re-read
the board from the attacks you have already run, and ask a different question of it.

Not *"did something fail?"* - nothing failed. But *"is this shape normal?"*

| The block | Block 8 - behavioural observability |
|---|---|
| Closed by | `SECURE_TELEMETRY` |
| The attack it catches | `b6` - the one that returned 200 and leaked anyway |
| The distinction | Controls **prevent**. Observability **detects**. You need both. |

**Re-run `b6` with `SECURE_TELEMETRY` on and watch the `detection` light**, then read the
trace. Prevention blocked the call; detection is what tells you somebody tried.

---

## 1. The distinction the block hangs on

| PREVENT - security controls | DETECT - observability |
|---|---|
| input validation | telemetry |
| tool design | detection rules |
| authorization | behavioural baselines |
| containment | threat hunting |

Some attacks will succeed. The only question left is whether you see them in time to
contain.

> **An agent with perfect controls and no observability is an agent that gets breached
> silently.**

## 2. See it for yourself

```
python kestrel.py attack b6 --day1-only
```

Read the trace in `/console`. Every line says `status=ok`. The session closes with
`errors=0`. And a customer's entire order history has left the building.

Now turn on the layer that sees it, **without** the layer that stops it:

```
python kestrel.py attack b6 --control SECURE_TELEMETRY
```

```
  ?? detection: outbound tool send_summary used inside a support conversation -
     valid call, unusual shape
```

The attack still lands. But you **know**. That is the difference between an incident you
respond to and an incident you read about from someone else.

## 3. The four layers, built bottom-up

```
  4  security intelligence   threat hunting, behavioural baselines, incident forensics
  3  behavioural             baselines of normal; flag the anomalous
  2  detection               rules & signatures on known-bad patterns
  1  telemetry               structured logs of every node, tool call, decision
```

Each layer depends on the one beneath it.

### Layer 1 - telemetry

`agent/telemetry.py`, `Board.record`. Always on, because it is the record everything else
needs. Note the fields, because they are chosen, not incidental:

```python
board.record(session=..., principal=..., node=..., tool=...,
             args_fingerprint=call.fingerprint(),   # correlate repeats without storing args
             records_touched=len(result.rows),      # volume
             egress_host=result.host,               # where it went
             verdict=..., control=..., severity=...)
```

`args_fingerprint` is a hash, not the arguments. You want to correlate repeated calls
without writing customer data into your log store - which is itself a data store somebody
can read.

### Layer 2 - detection rules

Signatures on known-bad. In this lab those live in `agent/directives.py` and the
guardrail regexes. Cheap, reliable, and blind to anything new.

### Layer 3 - behavioural

`Board._behavioural` in `agent/telemetry.py`, is a stub that raises `NotImplementedError`
once `SECURE_TELEMETRY` is on - that is your exercise. This is the layer that catches the
legitimate-looking attack, because it asks a different question: not *"is this
known-bad?"* but *"is this normal for this agent?"* Update `self.tool_counts` and
`self.egress_count` from the event, then call `self._flag(ev, why)` for each of
`BASELINE`'s four numbers that gets exceeded: records touched in one call, outbound calls
in the session, an outbound tool used at all
(`ev.tool in BASELINE["outbound_tools"] and ev.node == "tool"`), and total tool calls in
the turn.

Four numbers. That is all a first behavioural layer needs to be, and almost nobody has
one.

Because `Board.record` is called from everywhere in the app, and `_behavioural` runs on
every one of those calls once the control is on, expect this stub's `NotImplementedError`
to surface immediately and broadly the moment you turn `SECURE_TELEMETRY` on - that is
expected, not a sign something else is broken.

### Layer 4 - security intelligence

Humans hunting through the record. You cannot buy this one; you staff it. But you can make
it possible, and that is what layers 1-3 are for.

## 4. Fix it - step by step

1. **Log every node, tool call and decision** with a fixed schema. Not print statements -
   structured fields you can query.
2. **Never log the payload itself.** Fingerprint it. Your log store is a data store.
3. **Write down four numbers** that describe normal for your agent: records per call,
   outbound calls per session, tool calls per turn, and which tools are outbound.
4. **Alert on the shape, not the error.** Your existing monitoring already alerts on 500s.
   This is the part it cannot see.
5. **Keep the record long enough to hunt in.** Layer 4 needs history.

## 5. Prove it

```
python kestrel.py attack b6 --control SECURE_TELEMETRY
```

There is no isolated pytest test for `_behavioural` alone -
`test_the_legitimate_looking_attack_still_surfaces` and `python kestrel.py attack all
--secure` both use the full secure profile, so they will keep raising
`NotImplementedError` until every Day 2 stub is filled in, not just this one. The
`--control SECURE_TELEMETRY` run above is your narrow feedback loop while working on this
tutorial.

```
python kestrel.py attack all --secure
```

and `test_the_legitimate_looking_attack_still_surfaces` asserts that `board.findings` is
non-empty after `b6` - that the behavioural layer produced a finding on a call where every
signature-based check was clean.

## 6. On your own agent

- Pull one hour of your agent's logs. Could you answer: how many records did each tool
  call touch? Where did outbound calls go? How many steps did the median session take?
- If the answer is no, you do not have layer 1, and layers 2-4 are not available to you
  yet.
- What is the most abnormal thing your agent could do while returning `status=ok`?
