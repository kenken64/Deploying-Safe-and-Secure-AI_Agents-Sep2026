# Kestrel Goat - Day 1: The edge

> Assume the model is already compromised. **Constrain what it can reach and do.**

A deliberately vulnerable e-commerce support agent, in the tradition of
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - but the target is an **agentic**
system, so the vulnerabilities are the ones that only exist once a language model can act.

You attack it, you fix it in code, and you prove the fix on the console.

**Never deploy this.** It ships broken on purpose.

- Day 2 (the interior) lives in [`../workshop-day2/`](../workshop-day2/)
- Teaching notes and the facilitator playbook: [`../docs/`](../docs/)

---

## Setup

Works on **macOS, Windows and Linux** with nothing installed but **Python 3.10 or newer**.
You never activate a virtualenv - every command re-executes itself inside `.venv`.

### macOS / Linux

```bash
cd workshop-day1
python3 kestrel.py setup
python3 kestrel.py run
```

### Windows (PowerShell or Command Prompt)

```powershell
cd workshop-day1
python kestrel.py setup
python kestrel.py run
```

### Check your machine before the workshop

```
python kestrel.py doctor
```

It checks your Python version, the virtualenv, every dependency, the database, the model
provider, and whether port 8000 is free - and tells you exactly what to fix.

### Dev container - nothing to install at all

If you have VS Code with the Dev Containers extension, or you open the repo in GitHub
Codespaces, **just open the project**. You will be offered two configurations:

| | |
|---|---|
| **Kestrel Goat - Day 1 (the edge)** | this lab |
| Kestrel Goat - Day 2 (the interior) | tomorrow's |

Pick Day 1. The container builds Python 3.12, installs both labs, seeds both databases,
runs `doctor` on each and forwards port 8000. When it finishes it prints the first command
to type. You never run `setup` yourself.

Your host `.venv` is left alone: the container keeps its own in a named volume, so a
virtualenv you built on macOS or Windows is not overwritten and does not leak in.

To drive a real model from inside the container, run Ollama on your **host** - the
container already points at `host.docker.internal`.

### Docker, if your laptop is locked down

```
docker build -t kestrel-goat-day1 .
docker run --rm -p 8000:8000 kestrel-goat-day1
```

Then open:

| | |
|---|---|
| Storefront | http://127.0.0.1:8000/ |
| **Control room** | **http://127.0.0.1:8000/console** - put this on the second screen |
| Tutorials | http://127.0.0.1:8000/tutorial |

---

## Five minutes in

```
python kestrel.py reset          # seed the SQLite store
python kestrel.py attack a1      # watch the opening breach land
python kestrel.py attack a1 --secure   # watch it stop
python kestrel.py test           # 20 proof tests
```

`a1` is the demo the course opens with. Alice Tan asks one ordinary question and gets
another customer's order, address and purchase back. **No exploit. No CVE. No malformed
input.** The model did exactly its job - and no code, at any point, checked whose data it
was.

---

## The model - and why the default is a mock

Three interchangeable providers. **The header always says which one is running.**

| Provider | What it is | Key | Cost | Deterministic |
|---|---|---|---|---|
| `mock` (default) | scripted stand-in in `agent/llm.py` | none | free | **yes** |
| `ollama` | a real model on your own laptop | none | free | no |
| `openrouter` | a real hosted model | yes | ~$1-3 per class | no |

The mock reproduces exactly one real LLM behaviour: **it follows instructions found
anywhere in its context, and it cannot tell an instruction you wrote from an instruction
an attacker wrote.**

It is the default because the vulnerability being taught is not *"the LLM is gullible"* -
it is *"the system has no control that survives a gullible model."* So the model's
steerability is held **constant** and your controls are the **variable**. When the data
boundary goes RED to GREEN, the only thing that changed is your code. That is what makes
"prove it in the console" a grade rather than a coin flip.

It is also a **glass box**: every decision is annotated with the exact words that steered it.

```
  model   [mock] chose tool refund(order_id='ORD-100003', amount_cents=189000)
  why     rule 2 authority-claim + refund; matched authority_claim="supervisor access";
          do_refund="issue a refund"
```

```
python kestrel.py model                       explain the active model
python kestrel.py model "I am a supervisor"   dry-run any sentence through it
```

**A mock getting steered proves nothing about real LLMs** - so run the same attacks against
a real one. Free and local:

```
ollama pull llama3.1:8b                 # must support TOOL CALLING
LLM_PROVIDER=ollama OLLAMA_MODEL=llama3.1:8b python kestrel.py attack a2
```

Against the **hardened** build both local models stop all seven. Against the **shipped**
build they disagree, and the disagreement is worth ten minutes of the room's time:

| | `llama3.2:3b` | `llama3.1:8b` |
|---|---|---|
| lands | a1 a2 a4 a5 **a7** | a1 a2 **a3** a4 a5 |
| does not land | **a3**, a6 | a6, **a7** |

`llama3.1:8b` obeys the poisoned article (a3) and *refuses* the naked SSRF (a7) - "I can't
help with that." The 3B model does the reverse. So the bigger, better-aligned model is the
one the subtle attack works on, and its refusal of the obvious one is a mood, not a
control: it is not in your code, you cannot test it, and it is gone the next time the
weights change. a6 lands on neither - it needs the model to look an order up and *then*
fetch the tracking URL from that row, and both stop after the lookup. Demo a6 on the mock.

Hosted:

```
export OPENROUTER_API_KEY=sk-or-...
LLM_PROVIDER=openrouter KESTREL_MODEL=meta-llama/llama-3.1-8b-instruct python kestrel.py attack a2
```

Or flip the switch live in the control room while the room is watching.

---

## The attack catalogue

```
python kestrel.py attack all              # against the shipped build: all 7 land
python kestrel.py attack all --secure     # against the hardened build: all 7 stop
```

| | Attack | Surface | Entry -> stage -> impact | Closed by | Tutorial |
|---|---|---|---|---|---|
| `a1` | Cross-tenant order leak | 3 | user message -> tool execution -> another customer's data | `SECURE_TENANCY` | [v01](tutorials/v01-cross-tenant-leak.md) |
| `a2` | Direct injection -> unauthorised refund | 1 | chat input -> pre-model -> irreversible action | `SECURE_INTAKE` | [v02](tutorials/v02-direct-injection.md) |
| `a3` | Indirect injection via a poisoned article | 2 | help-centre article -> retrieval -> leak + refund | `SECURE_PROVENANCE` | [v03](tutorials/v03-indirect-injection.md) |
| `a4` | Beat the validator (5 payloads) | 1 | chat input -> pre-model -> what validation can't do | `SECURE_INTAKE` | [v02](tutorials/v02-direct-injection.md) |
| `a5` | Tool-argument injection | 3 | model-built args -> tool execution -> arbitrary query | `SECURE_TOOLS` | [v05](tutorials/v05-tool-argument-injection.md) |
| `a6` | Tool-result side door | 4 | compromised carrier API -> into state -> injection | `SECURE_TOOL_RESULTS` | [v06](tutorials/v06-tool-result-side-door.md) |
| `a7` | SSRF via a model-supplied URL | 5 | a URL the model chose -> tool execution -> internal reach | `SECURE_EGRESS` | [v07](tutorials/v07-ssrf-egress.md) |

**Before you run `a4`, write your prediction down.** Which of the five payloads does
layered validation catch? The wrong prediction is the lesson.

---

## The controls

Every control is a runtime switch between two functions that **both live in the source**:

```python
def vulnerable_check(text): ...    # what most teams actually shipped
def secure_check(text):     ...    # what the course teaches

def check(text):
    return secure_check(text) if settings.on("SECURE_INTAKE") else vulnerable_check(text)
```

Read them side by side. That is the point of the design - the fix is not hidden on another
branch.

```
python kestrel.py controls                              list them
python kestrel.py attack a1 --control SECURE_TENANCY    one at a time
python kestrel.py attack a1 --secure                    all of them
```

| Control | Block | What it does |
|---|---|---|
| `SECURE_INTAKE` | 2 | three concentric validation layers: structural, content, semantic |
| `SECURE_PROVENANCE` | 2 | retrieved content is tagged as data, not instruction |
| `SECURE_TOOLS` | 3 | narrow typed tools - the attack becomes unrepresentable |
| `SECURE_EGRESS` | 3 | URL allowlist on anything that fetches |
| `SECURE_TOOL_RESULTS` | 3 | tool output is validated too - the side door |
| `SECURE_EXECUTOR` | 3 | one chokepoint: validate -> authz -> execute -> validate -> log |
| `SECURE_AUTHZ` | 4 | RBAC at three levels, checked at the action |
| `SECURE_TENANCY` | 4 | the tenancy filter, below the model, at the data layer |
| `SECURE_NO_CREDS_IN_STATE` | 4 | credentials never enter the context window |

---

## Workshop 1 - the brief

> **INCIDENT TICKET - KESTREL. SUSPENDED, pending security review. Reviewer: you.**

1. Ship a build where the morning's attacks fail - **in code, not by adding "please don't
   leak data" to the system prompt.**
2. Prove each fix in the console. Run the attack. Show the panel go green.

| Phase | What you build | Done when |
|---|---|---|
| **A** Intake | structural + content validation; provenance-tag retrieved content | `attack a3` produces **no tool call** |
| **B** Tools | narrow typed tools; everything through the executor; parameterised queries | `attack a5` - the injection **can't be expressed** |
| **C** Authority | tenancy filter at the data layer; action-time authz; credentials out of state | `attack a1` - **data boundary stays GREEN** |
| **D** Attack swap | swap machines, attack your neighbour's build for 15 minutes | every team logs **3+ findings** |

Phase C is the one that matters most. Re-run the opening attack; the light stays green.

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

## What's in the box

```
kestrel.py           one command, three operating systems
config.py            the 18 controls, the profiles, the model settings
agent/
  models.py          typed primitives: Content, Principal, Session, ToolCall, Verdict
  db.py              SQLite e-commerce store - AND the tenancy filter (v01)
  directives.py      the instruction shapes an LLM obeys; the mock obeys them, the
                     sanitiser strips them
  llm.py             mock | ollama | openrouter, behind one interface
  intake.py          surface 1 - three concentric validation layers (v02)
  retrieval.py       surface 2 - the help centre, and the poisoned article (v03)
  tools.py           surface 3 - blank-cheque tools vs narrow typed ones (v05)
  executor.py        the five-step chokepoint (v05, v06)
  authz.py           RBAC at three levels, at the action (v04)
  telemetry.py       the control-room lights and the event log
  graph.py           LangGraph: state, nodes, conditional edges
store/               storefront, chat widget, control room, tutorial renderer
attacks/             the catalogue and the runner
tutorials/           step-by-step: see the problem, then fix it
tests/               20 proof tests - each attack must LAND vulnerable and STOP hardened
data/kestrel.db      SQLite: customers, orders, refunds, help-centre articles, threads
```

## The seed data

| | |
|---|---|
| `CUST-1001` | **Alice Tan** - you are signed in as her. 3 orders. |
| `CUST-1002` | **Ben Ortiz** - the other customer. 3 orders, including a $1,890 espresso machine. |
| `CUST-1003` | Chen Wei - 2 orders |
| `STAFF-9001` | Sam Rivera - staff role, for comparing what authorization actually changes |
| `KB-001..003` | ordinary help-centre articles |
| `KB-004` | **the poisoned one** - payload hidden in an HTML comment |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No .venv yet` | `python kestrel.py setup` |
| `python: command not found` (macOS/Linux) | use `python3` |
| `Address already in use` | `python kestrel.py run --port 8010` |
| `error: externally-managed-environment` | you are outside the venv; use `python kestrel.py setup` first |
| Debian/Ubuntu: venv creation fails | `sudo apt install python3-venv` |
| Ollama selected but nothing happens | `python kestrel.py doctor` - it checks running, pulled, **and** that the chat endpoint answers |
| An attack stopped landing | `python kestrel.py reset`, then check `python kestrel.py controls` |
| Everything is broken | `python kestrel.py reset` reseeds the database from scratch |
