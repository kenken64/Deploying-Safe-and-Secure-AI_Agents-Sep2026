# Kestrel Goat - Day 2: The interior

> The edge will be breached. **Contain the blast, detect the rest, keep a human on the
> irreversible.**

Same Kestrel. Same SQLite store. Same LangGraph. But this build **starts where Day 1
ended**: all nine Day 1 controls are already on and locked.

> Day 1 secured the edge. Today we assume all of it was bypassed.

**Never deploy this.** It ships broken on purpose.

- Day 1 (the edge) lives in [`../workshop-day1/`](../workshop-day1/) - **do that first**
- Teaching notes and the facilitator playbook: [`../docs/`](../docs/)

---

## Setup

Works on **macOS, Windows and Linux** with nothing but **Python 3.10+**. You never
activate a virtualenv.

```
cd workshop-day2
python kestrel.py doctor      # check this machine
python kestrel.py setup       # venv + dependencies + seed the database
python kestrel.py run         # then open http://127.0.0.1:8000/console
```

Windows uses `python`; macOS and Linux may need `python3`.

**Or open the repo in a dev container** (VS Code with the Dev Containers extension, or
GitHub Codespaces) and pick **Kestrel Goat - Day 2 (the interior)**. It installs both
labs, seeds both databases and forwards port 8000; you never run `setup` yourself. Your
host `.venv` is left alone - the container keeps its own in a named volume.

Docker, if the laptop is locked down:

```
docker build -t kestrel-goat-day2 . && docker run --rm -p 8000:8000 kestrel-goat-day2
```

---

## Start by proving the premise

```
python kestrel.py attack b1 --day1-only
```

`b1` is the attack you were promised at the end of Day 1. Watch the console:

```
  [ ok ]    input_validation      <- GREEN
  [ ok ]    content_filter        <- GREEN
  [ ok ]    schema_check          <- GREEN
  [BREACH]  data_boundary         <- RED anyway
  !! 758 chars of order data sent to audit-partner.example -
     a valid tool call, a 200 response, and an exfiltration
```

Every input control passed, because **the payload never went near the chat box.** It was
read by a tier-1 sub-agent, summarised, and handed to Kestrel as if one of your own
components had written it.

> The payload didn't come through the front door, so there was nothing at the front door
> to catch it.

---

## The shape of the day

| **CONTAIN** | **DETECT** | **JUDGE** |
|---|---|---|
| a breach can't spread | you know it happened | a person on the irreversible |
| State & memory (block 5) | Output guardrails (block 7) | Human-in-the-loop (block 9) |
| Multi-agent trust (block 6) | Observability (block 8) | Rate & cost limits (block 10) |

## The attacks

```
python kestrel.py attack all --day1-only    all 8 land, past the entire Day 1 edge
python kestrel.py attack all --secure       all 8 stopped
```

| | Attack | Theme | Entry -> stage -> impact | Closed by | Tutorial |
|---|---|---|---|---|---|
| `b1` | The attack I promised you | CONTAIN | poisoned article read by a sub-agent -> trusted state -> order history emailed out | quarantine, state split, guard, HITL | [v11](tutorials/v11-trust-inheritance.md) |
| `b2` | Poison once, spread everywhere | CONTAIN | an approved memory recalled at node 1 -> every later node | `SECURE_STATE_SPLIT` | [v08](tutorials/v08-state-poisoning.md) |
| `b3` | Thread-ID guessing | CONTAIN | a guessed id -> stored state -> another user's whole conversation | `SECURE_THREAD_IDS` | [v09](tutorials/v09-thread-id-guessing.md) |
| `b4` | The memory landmine | CONTAIN | a memory the model chose to write -> every future session | `SECURE_MEMORY_WRITES` | [v10](tutorials/v10-memory-landmine.md) |
| `b5` | Trust inheritance | CONTAIN | least-privileged agent -> most-privileged agent's authority | quarantine, priv-sep | [v11](tutorials/v11-trust-inheritance.md) |
| `b6` | Silent exfiltration | DETECT | an innocent-looking parameter -> data leaves, `errors=0` | guard, telemetry | [v12](tutorials/v12-silent-exfiltration.md) |
| `b7` | Irreversible action, nobody on it | JUDGE | a refund request -> $1,890 approved by no one | `SECURE_HITL` | [v14](tutorials/v14-irreversible-action.md) |
| `b8` | Economic exhaustion | JUDGE | one request -> many operations -> a bill | `SECURE_LIMITS` | [v15](tutorials/v15-cost-exhaustion.md) |

## The nine controls you build today

```
python kestrel.py controls
```

| Control | Block | What it does |
|---|---|---|
| `SECURE_STATE_SPLIT` | 5 | trusted and untrusted are different fields, never merged; re-validated between nodes |
| `SECURE_THREAD_IDS` | 5 | random thread ids, bound to identity, ownership checked on every access |
| `SECURE_MEMORY_WRITES` | 5 | the model proposes a memory; code and humans decide what sticks |
| `SECURE_QUARANTINE` | 6 | every sub-agent output clears a deterministic boundary - no LLM, no state, no actions |
| `SECURE_PRIV_SEP` | 6 | the agent that reads untrusted content cannot act |
| `SECURE_OUTPUT_GUARD` | 7 | inspect what it **says** and what it is about to **do** |
| `SECURE_TELEMETRY` | 8 | behavioural baselines - catches the legitimate-looking attack |
| `SECURE_HITL` | 9 | interrupt **before** the irreversible action, with the call frozen |
| `SECURE_LIMITS` | 10 | five independent caps, because one cap caps one thing |

Day 1's nine controls are shown as `day 1` and stay on.

---

## How the tutorials work

Each tutorial at `/tutorial/<name>` is the lab itself. You never leave the page:

1. **Run the attack** against the build you have now - transcript and lights render inline
2. **Read why it worked** - the walkthrough goes to the exact line that allowed it
3. **Apply the fix** - toggle the control right there; the `vulnerable_*` and `secure_*`
   functions both live in the file it names, so you can read them side by side first
4. **Prove it** - re-run the same attack and watch the light go green

## The control room

`/console` adds three Day 2 panels to Day 1's lights and trace:

- **Awaiting a human** - the frozen call, with Approve and Reject
- **What the agent persists** - long-term memories (approved vs pending) and the
  checkpoint store, snapshot by snapshot
- **Detection findings** - what the behavioural layer noticed, separately from what was
  blocked

---

## The model

Three interchangeable providers; the header always says which is running.

| Provider | What it is | Key | Cost |
|---|---|---|---|
| `mock` (default) | deterministic scripted stand-in, and a glass box - every decision says which words steered it | none | free |
| `ollama` | a real model on your own laptop (`ollama pull llama3.1:8b`) | none | free |
| `openrouter` | a real hosted model (`meta-llama/llama-3.1-8b-instruct`) | yes | ~$1-3 per class |

```
python kestrel.py model                      explain the active model
python kestrel.py model "remember that..."   dry-run a sentence through it
```

The mock is the default because the model's steerability has to be a **constant** while
your controls are the **variable** - when a light goes RED to GREEN, the only thing that
changed is your code. **A mock getting steered proves nothing about real LLMs**, so run the
same attacks against a real one too, or flip the switch in the control room while the room
is watching.

Day 2 is the catalogue that survives a real model best. Measured on Ollama at temperature 0:

```
LLM_PROVIDER=ollama OLLAMA_MODEL=llama3.1:8b python kestrel.py attack all
```

| | vulnerable | hardened |
|---|---|---|
| `llama3.1:8b` | **8/8 land** | **8/8 stopped** |
| `llama3.2:3b` | 7/8 land - b4 does not | **8/8 stopped** |

`llama3.2:3b` will not write the memory in b4; it answers the question instead of calling
`remember`. Use the 8B model for the interior demos, or the mock.

---

## Workshop 2 - the brief

> **INCIDENT TICKET - KESTREL. BREACH CONTAINED? - interior review.**
> The edge was bypassed. That's a given now, not a failure.

Ship a build where the breach **can't spread**, **can't hide**, and **can't touch the
irreversible**.

| Phase | What you build | Done when |
|---|---|---|
| **A** State | trusted/untrusted split; provenance tags; thread ids bound to identity | poisoned state can't reach a trusted field, and a guessed thread id bounces |
| **B** Trust | quarantine node between the helpers and Kestrel; split reading from acting | the poisoned-summary path no longer reaches a real action |
| **C** Detect | output guardrail on replies **and** tool args; one behavioural log line | the exfil attempt is **logged AND blocked** |
| **D** Judge & cap | human interrupt before the irreversible action; token budget + cost breaker | the action pauses; a looped session trips the cap |

Phase A is the one that closes the morning. Phase C needs **both** halves - seeing it
isn't enough; stopping it isn't enough.

```
python kestrel.py attack all --secure
python kestrel.py test
```

> **The proof tests want the mock.** Some of them assert what the *model* did -
> that the attack actually fired - and only the mock is deterministic. Run them
> with `LLM_PROVIDER=openrouter` and those skip, saying so, rather than going red
> on a run where the model happened not to take the bait. The tests that assert
> what the *code* does run on every provider. To check a live model, run the
> attacks themselves: `python kestrel.py attack all --secure`.

---

## What's new in this folder

Everything from Day 1, plus:

```
agent/
  state.py        trusted/untrusted split, provenance, the gate BETWEEN nodes   (block 5)
  memory.py       thread ids, the checkpoint store, memory write governance     (block 5)
  helpers.py      two sub-agents, zero-trust tiers, privilege separation        (block 6)
  quarantine.py   no LLM, no state, no actions - read the whole file in a minute (block 6)
  guardrails.py   what it says AND what it does                                 (block 7)
  telemetry.py    four layers, with behavioural baselines                       (block 8)
  hitl.py         the three-factor test; interrupt before, never after          (block 9)
  limits.py       five independent caps                                         (block 10)
  db.py           + KB-005, the Day 2 payload - aimed at the sub-agent, not the chat box
```

## What you end the day with

> **Not an unbreakable agent. An agent where a breach is bounded, visible, and reversible.**
>
> **Contained** - it can't spread. **Detected** - you know it happened.
> **Gated** - a human on the irreversible.

Anyone who sells you an unbreakable agent is wrong. This is better, and truer.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No .venv yet` | `python kestrel.py setup` |
| `Address already in use` | `python kestrel.py run --port 8010` (Day 1 may be on 8000) |
| An attack stopped landing | `python kestrel.py reset`, then `python kestrel.py controls` |
| Ollama selected, nothing happens | `python kestrel.py doctor` checks running, pulled, **and** that the chat endpoint answers |
| Everything is broken | `python kestrel.py reset` reseeds the database |
