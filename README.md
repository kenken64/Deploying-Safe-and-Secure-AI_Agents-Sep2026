# Developing Secure AI Agents

A two-day workshop for engineers who are shipping agentic systems, built around **Kestrel
Goat** - a deliberately vulnerable e-commerce support agent in the tradition of
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat), but targeting the vulnerabilities that
only exist once a language model can **act**.

> **Assume the model is already compromised. Make sure that assumption isn't catastrophic.**

NUS-ISS · Institute of Systems Science, National University of Singapore

---

## Start here

> **Teaching this course?** Start at **[`INSTRUCTORS.md`](INSTRUCTORS.md)** - what to read
> in what order, how to set a machine up, which model to run, and the words for both live
> demos.

| | |
|---|---|
| **[Day 1 - The edge](workshop-day1/)** | *The agent will be steered.* Constrain what it can reach and do. |
| **[Day 2 - The interior](workshop-day2/)** | *Assume the edge already failed.* Contain the blast, detect the rest, keep a human on the irreversible. |
| **[Teaching notes](docs/)** | Slide-by-slide understanding, facilitator playbook, security reference, workshop guide. |
| **[Slides](slides/)** | The two decks the course is taught from. |

Each day is a **self-contained, runnable lab** with its own README, its own attacks, its
own step-by-step tutorials, and its own proof tests. Day 2 ships with Day 1's fixes
already applied and locked on - which is exactly its premise.

```
python kestrel.py doctor      # check this machine (macOS, Windows, Linux)
python kestrel.py setup       # venv + dependencies + seeded SQLite store
python kestrel.py run         # storefront, chat widget, control room, tutorials
```

Nothing to install beyond **Python 3.10+**. No API key. No network. No `make`, no shell
scripts, no virtualenv activation.

---

## What the two days cover

| | **Day 1 - the edge** | **Day 2 - the interior** |
|---|---|---|
| Premise | The agent will be steered | The edge already failed |
| Surfaces | 1 user messages · 2 retrieved content · 3 tool arguments | 4 tool results · 5 external APIs · 6 other agents · 7 state & memory |
| Question | *How do we keep them out?* | *Given they're in: how much damage, will we notice, what did we refuse to automate?* |
| Controls | intake validation · provenance · narrow typed tools · secure executor · RBAC at three levels · the tenancy filter | state split · thread ids · memory governance · quarantine · privilege separation · output guardrails · behavioural observability · human-in-the-loop · rate & cost limits |
| Attacks | 7, `a1`-`a7` | 8, `b1`-`b8` |
| Tutorials | 8 | 9 |
| Proof tests | 20 | 30 |

### The eight surfaces

![The Kestrel agent and the eight places an attacker can write into it](docs/images/kestrel-eight-surfaces.svg)

Every attack in both days is read the same way: **entry point → execution stage → impact.**

| # | Surface | Entry point | Stage | Impact |
|---|---|---|---|---|
| 1 | User messages | chat input | pre-model | direct injection · data disclosure |
| 2 | Retrieved content | help-centre article | retrieval | indirect injection |
| 3 | Tool args (in) | model-built arguments | tool execution | unscoped query · unintended action |
| 4 | Tool results (out) | API / DB response | post-tool, into state | injection via side door |
| 5 | External APIs | payment, shipping | tool execution | SSRF · downstream abuse |
| 6 | Other agents | helper summaries | sub-agent return | trusted-channel injection |
| 7 | State & memory | saved notes | across turns | persistence · credential exposure |
| 8 | The model itself | weights / behaviour | everywhere | why all the others matter |

### One request, eight surfaces, eighteen controls

This is Kestrel handling a single customer message. The dashed red arrows are the
**surfaces** - the places an attacker gets to write text - annotated with the attack ids
that arrive there. Everything inside a node is a **control**, at the exact point in the
graph where it runs.

```mermaid
%%{init: {"flowchart": {"wrappingWidth": 340, "curve": "basis"}}}%%
flowchart TB

  %% ---------------- what an attacker gets to write ----------------
  S1["<b>1 · user message</b><br/>chat input"]
  S2["<b>2 · retrieved content</b><br/>help-centre article"]
  S3["<b>3 · tool arguments</b><br/>written by the model"]
  S4["<b>4 · tool results</b><br/>DB / API response"]
  S5["<b>5 · external APIs</b><br/>payment · shipping"]
  S6["<b>6 · other agents</b><br/>helper summaries"]
  S7["<b>7 · state / memory</b><br/>saved notes · checkpoints"]
  S8["<b>8 · the model itself</b><br/>steerable by design"]

  %% ---------------- the graph, and the control at each node ----------------
  IN(["the customer asks"])
  READ["<b>read_message</b><br/>D1 SECURE_INTAKE · structural, then content"]
  RECALL["<b>recall</b> · long-term notes <i>· Day 2 node</i><br/>D2 SECURE_THREAD_IDS · random, bound to identity<br/>D2 SECURE_MEMORY_WRITES · who may leave a note"]
  RETR["<b>retrieve</b> · the help centre<br/>D1 SECURE_PROVENANCE · every scrap carries its origin<br/>D2 SECURE_STATE_SPLIT · untrusted text stays untrusted"]
  CONS["<b>consult</b> · sub-agents <i>· Day 2 node</i><br/>D2 SECURE_QUARANTINE · a summary is data, not instruction<br/>D2 SECURE_PRIV_SEP · the reader may not act"]
  PLAN{{"<b>plan</b> · the model picks the next edge<br/>D1 SECURE_NO_CREDS_IN_STATE · nothing secret in context<br/>D2 SECURE_LIMITS · steps · tokens · sessions · spend"}}
  ACT["<b>act</b> · gates before the side effect<br/>D2 SECURE_OUTPUT_GUARD · guard what it will <b>DO</b><br/>D2 SECURE_HITL · a human, before, never after"]
  EXEC["<b>the secure executor</b> · one chokepoint · D1 SECURE_EXECUTOR<br/>1 validate args · D1 SECURE_TOOLS<br/>2 authorize · D1 SECURE_AUTHZ, three levels<br/>3 execute · D1 SECURE_TENANCY · D1 SECURE_EGRESS<br/>4 validate the result · D1 SECURE_TOOL_RESULTS<br/>5 log · the raw record, always on<br/>D2 SECURE_TELEMETRY · detection rules and behavioural baselines, over every node"]
  REPLY["<b>reply</b> · the last gate before the world<br/>D2 SECURE_OUTPUT_GUARD · guard what it <b>SAYS</b>"]
  OUT(["the customer reads"])
  WORLD[("the world<br/>store DB · payment · shipping · memory store")]

  %% ---------------- where the attacks come in ----------------
  S1 -.->|"a2 · a4"| READ
  S7 -.->|"b2 · b3 · b4"| RECALL
  S2 -.->|"a3"| RETR
  S6 -.->|"b1 · b5"| CONS
  S8 -.-> PLAN
  S3 -.->|"a1 · a5"| ACT
  S4 -.->|"a6"| EXEC
  S5 -.->|"a7"| EXEC

  %% ---------------- the path ----------------
  IN --> READ
  READ --> RECALL --> RETR --> CONS --> PLAN
  READ -->|"blocked at intake"| REPLY
  PLAN -->|"a tool call"| ACT
  PLAN -->|"no tool · b8 stops here"| REPLY
  ACT -->|"held for a human · b7 stops here"| REPLY
  ACT --> EXEC
  EXEC -->|"the irreversible bit"| WORLD
  EXEC -->|"result into state, then loop"| PLAN
  REPLY -->|"b6 tries to leave here"| OUT

  %% ---------------- styling ----------------
  classDef surface fill:#fdecea,stroke:#c0392b,stroke-width:1px,color:#7b241c
  classDef stage   fill:#eaf1f8,stroke:#2c3e50,stroke-width:1px,color:#17202a
  classDef model   fill:#fff5e0,stroke:#b9770e,stroke-width:1px,color:#6e4b02
  classDef sink    fill:#ececec,stroke:#555555,stroke-width:1px,color:#1c1c1c

  class S1,S2,S3,S4,S5,S6,S7,S8 surface
  class READ,RECALL,RETR,CONS,ACT,EXEC,REPLY stage
  class PLAN model
  class IN,OUT,WORLD sink
```

**D1** controls are Day 1's - they ship locked on in Day 2, because Day 2's premise is that
the edge already failed. **D2** controls are the ones you switch on yourself. `recall` and
`consult` do not exist on Day 1: the interior grows the nodes the interior attacks need.

Read it the way the attacks read: an arrow **in** is an entry point, the node it lands on
is the execution stage, and the impact is whatever is left after the controls in that node
- and the ones downstream of it - have run. Every named control is a runtime switch:
`vulnerable_*` and `secure_*` both live in the file, and the toggle picks one.

---

## How the lab works

**Every control is a runtime switch between two functions that both live in the source:**

```python
def vulnerable_check(text): ...    # what most teams actually shipped
def secure_check(text):     ...    # what the course teaches

def check(text):
    return secure_check(text) if settings.on("SECURE_INTAKE") else vulnerable_check(text)
```

There is no "fixed branch" to diff against. You read both, flip the switch, re-run the
attack, and watch the light.

**Each tutorial is the lab itself.** At `/tutorial/<name>` you never leave the page:

1. **Run the attack** against the build you have now - transcript and lights render inline
2. **Read why it worked** - the walkthrough goes to the exact file and line
3. **Apply the fix** - toggle it right there, after reading the two implementations
4. **Prove it** - re-run the same attack and watch the light go green

**The control room** (`/console`) is the two-pane view the course demos from: customer chat
on the left, lights and trace on the right.

---

## The model

Three interchangeable providers behind one interface. **The page header always says which
one is running** - students never have to discover that the model is a stand-in.

| Provider | What it is | Key | Cost | Deterministic |
|---|---|---|---|---|
| `mock` (default) | a scripted stand-in that follows instructions found anywhere in its context | none | free | **yes** |
| `ollama` | a real model on the student's own laptop | none | free | no |
| `openrouter` | a real hosted model (`meta-llama/llama-3.1-8b-instruct`) | yes | ~$1-3 per class | no |

The mock is the default because the vulnerability being taught is not *"the LLM is
gullible"* - it is *"the system has no control that survives a gullible model."* So the
model's steerability is held **constant** and the controls are the **variable**: when a
light goes RED to GREEN, the only thing that changed is your code. That is what makes
*"prove it in the console"* a grade rather than a coin flip, and it is why both live demos
use it.

It is also a **glass box**, which a real LLM is not:

```
  model   [mock] chose tool refund(order_id='ORD-100003', amount_cents=189000)
  why     rule 2 authority-claim + refund; matched authority_claim="supervisor access";
          do_refund="issue a refund"
```

**A mock getting steered proves nothing about real LLMs.** Say so out loud, then flip the
switch in the control room and run the same attack against a real one.

### What a real local model actually does

Measured on Ollama, temperature 0, both catalogues, vulnerable then hardened:

| | `llama3.2:3b` (2GB) | `llama3.1:8b` (4.9GB) |
|---|---|---|
| Day 1 vulnerable | a1 a2 a4 a5 a7 land; **a3, a6 do not** | a1 a2 a3 a4 a5 land; **a6, a7 do not** |
| Day 1 hardened | **7/7 stopped** | **7/7 stopped** |
| Day 2 vulnerable | 7/8 land; **b4 does not** | **8/8 land** |
| Day 2 hardened | **8/8 stopped** | **8/8 stopped** |

Read the disagreement, because it is the lesson:

- **`llama3.1:8b` obeys the poisoned help-centre article (a3) and refuses the naked SSRF
  (a7).** `llama3.2:3b` does the exact opposite. The bigger model is *better* at spotting
  the blatant attack and *more* useful to the subtle one. Neither is a control, and the
  hardened build stops all seven either way - which is the entire point of the course.
- **a6 lands on neither.** It needs the model to look an order up and then fetch the
  tracking URL from the row it got back; both local models stop after the lookup and just
  read the URL out to the customer. Demo a6 on the mock.
- **Use `llama3.1:8b` for Day 2** - it lands the whole interior catalogue.

The hardened build stops everything on both models. Only the *vulnerable* side is
model-dependent, and the runner says so rather than crediting a control that is switched
off:

```
attack stopped
NOT stopped by a control - none of a6's controls are on. llama3.1:8b did not take
the bait this run. Real models are not deterministic: re-run it, or try a larger one.
```

---

## The docs

| | |
|---|---|
| [`docs/00-course-overview.md`](docs/00-course-overview.md) | The spine: thesis, Kestrel, eight surfaces, attack board, teaching rituals, agendas |
| [`docs/01-day1-the-edge.md`](docs/01-day1-the-edge.md) | Day 1 block by block, with facilitator notes |
| [`docs/02-day2-the-interior.md`](docs/02-day2-the-interior.md) | Day 2 block by block, with facilitator notes |
| [`docs/03-security-reference.md`](docs/03-security-reference.md) | Every control, with illustrative code |
| [`docs/04-facilitator-playbook.md`](docs/04-facilitator-playbook.md) | Run-of-show, demo prep, timing risks, objections, MCQ seed bank |
| [`docs/05-workshop-guide.md`](docs/05-workshop-guide.md) | Both workshops: briefs, phases, proof criteria, attack swap, rubric |
| [`docs/06-gaps-and-build-list.md`](docs/06-gaps-and-build-list.md) | What is built, what is left, and deck defects worth fixing |

---

## Safety

Both labs are **deliberately vulnerable software**. They contain unscoped SQL, a
blank-cheque tool, seeded prompt-injection payloads, an SSRF gadget and an unguarded
checkpoint store, all on purpose.

- Run them on `127.0.0.1` only. The Docker images bind `0.0.0.0` **because a container
  requires it** - do not publish the port beyond your own machine.
- Never deploy either folder anywhere.
- No real credentials, no real customer data, no real payment or shipping endpoints. The
  seeded customers, orders and API hosts are all fictional `*.example` names.
