# Deploying the labs

Two services, deployed separately: `workshop-day1/` and `workshop-day2/`. Each is a
self-contained app with its own Dockerfile, its own database and its own environment,
so a student breaking Day 2 cannot touch Day 1.

> **Read this first.** Kestrel is a **deliberately vulnerable** agent. On your laptop
> that is the entire point. On a public URL it is a different proposition: the agent
> holds a real API key, and `b8` — economic exhaustion — is an attack in the
> curriculum, not a hypothetical. The lab's own rate limits (`SECURE_LIMITS`) start
> **off**, because switching them on is Block 10's exercise.
>
> So **set `KESTREL_ACCESS_PASSWORD`**. It is one shared password on a login page —
> a door, not a security model — and it is the difference between a workshop URL and
> an open agent with your billing attached.

---

## Railway

Each day is its own Railway **service**, pointed at the same repo with a different
root directory.

### Day 1

1. **New Project → Deploy from GitHub repo**, pick this repo.
2. **Settings → Root Directory**: `workshop-day1`
3. Railway reads [`workshop-day1/railway.json`](workshop-day1/railway.json) and builds
   the Dockerfile. Nothing else to configure — `$PORT` is injected and the container
   binds it.
4. **Variables** (below), then **Settings → Networking → Generate Domain**.

### Day 2

The same, with **Root Directory** `workshop-day2`. Add it as a second service in the
same project, or a separate project — either works, and they share nothing.

### Variables

| Variable | Day 1 | Day 2 | Notes |
|---|---|---|---|
| `LLM_PROVIDER` | `openrouter` | `openrouter` | `mock` needs no key and costs nothing |
| `OPENROUTER_API_KEY` | required | required | from openrouter.ai/keys |
| `KESTREL_MODEL` | `meta-llama/llama-3.1-8b-instruct` | same | the hosted twin of the ollama model |
| `OPENROUTER_BASE` | *(optional)* | *(optional)* | defaults to `https://openrouter.ai/api/v1`; set it to point at a proxy or gateway |
| `KESTREL_ACCESS_PASSWORD` | **set it** | **set it** | see the warning above |
| `PORT` | — | — | Railway sets this. Do not. |

`ollama` is not an option on Railway — there is no Ollama in the container. Use
`openrouter`, or `mock` if you only want the deterministic walkthrough.

### Cost, and how to bound it

Set a **credit limit on the OpenRouter key itself** — that is the only cap the lab
cannot talk its way past. `llama-3.1-8b-instruct` is cheap (the full 8-attack Day 2
run costs roughly $0.09), but `b8` exists specifically to burn tokens, and a room of
twenty students running it is twenty times that.

Two more things worth knowing:

- Use a **separate key per deployment**, so you can revoke one without touching the other.
- `SECURE_LIMITS` starts off. Once a student switches it on, five caps apply — steps,
  loop detection, per-session tokens, daily tokens, and a dollar ceiling. Before that,
  nothing in the app stops a loop.

---

## What the deployment does and does not keep

The database is SQLite inside the container, seeded at build time from
`agent/db.py`. That means:

- **State resets on every redeploy and restart.** For a lab that is usually what you
  want: a clean store, the same seeded customers, both poisoned articles back in place.
- **A student's planted memory or issued refund survives until the next restart**, and
  is visible to *everyone else on that URL* — there is one database, not one per
  visitor. If you want isolation per student, give each of them their own service, or
  have them run locally.
- Adding a Railway volume at `/app/data` would make state survive restarts. Most of
  the time you do not want that for this lab.

`python kestrel.py reset` reseeds without redeploying, if you have a shell.

---

## Demoing b8: making the cost ceiling actually fire

Day 2's five limits are environment variables, so a live demo can be tuned from
Railway without redeploying code. Day 1 has no limits - `SECURE_LIMITS` is a Day 2
control.

| Variable | Default | |
|---|---|---|
| `KESTREL_LIMIT_SESSIONS_PER_MIN` | `5` | level 1 - request rate |
| `KESTREL_LIMIT_STEPS_PER_SESSION` | `6` | level 2 - session execution |
| `KESTREL_LIMIT_REPEAT_CYCLE` | `3` | level 3 - loop detection |
| `KESTREL_LIMIT_TOKENS_PER_SESSION` | `3000` | level 4 - token budget |
| `KESTREL_LIMIT_TOKENS_PER_DAY` | `30000` | level 4 - daily budget |
| `KESTREL_LIMIT_COST_CEILING_USD` | `0.25` | level 5 - the circuit breaker |
| `KESTREL_USD_PER_1K_TOKENS` | `0.002` | the simulated price the meter uses |

**The levels are checked in order** - steps, loop, tokens, then cost - so to show a
particular cap firing, every level above it must be loose enough for the run to
reach it. On the shipped defaults the cost ceiling is **unreachable**: $0.25 needs
125,000 tokens and the session cap stops at 3,000.

Whichever cap fires first leaves the others below their caps - so you cannot have
every bar full. That is not a tuning problem, it is the block's thesis: five
independent levels, and the attack picks the one you did not guard.

### A. Token budget - RECOMMENDED

```
KESTREL_LIMIT_STEPS_PER_SESSION=20
KESTREL_LIMIT_REPEAT_CYCLE=20
KESTREL_LIMIT_TOKENS_PER_SESSION=2500
KESTREL_LIMIT_TOKENS_PER_DAY=4000
KESTREL_LIMIT_COST_CEILING_USD=0.25       # left unreachable on purpose
```

`b8` on OpenRouter reaches ~3,000 tokens, so the token bar fills past 100% and goes
red, and the trace names the level: `4 token budget: 3032 tokens this session, cap
is 2500`. Measured 2 runs out of 2, identical both times.

Preferred because tokens are the honest unit. The dollar figure is simulated at
`$0.002` per 1K, which is about **31x** the real price of llama-3.1-8b
(`$0.000065` per 1K) - a demo built on it puts a fabricated number in front of the
room. Burning tokens IS the economic exhaustion.

### B. Cost ceiling

```
KESTREL_LIMIT_TOKENS_PER_SESSION=100000
KESTREL_LIMIT_TOKENS_PER_DAY=100000
KESTREL_LIMIT_COST_CEILING_USD=0.005      # NOT 0.01 - see below
```

Gives `5 cost ceiling`, but with two caveats. The token bars sit near zero, because
they have to be loose enough for the run to reach level 5 at all. And `check_step`
runs at the START of a step, so a run that ends before the next check can finish
OVER the cap without ever tripping - at `0.01` that happened on 1 run in 2
(`cost=$0.0101/$0.01`, light still green). `0.005` is crossed early enough that a
later check catches it: 2 out of 2.

With the mock, `b8` burns only ~320 tokens and ~$0.0006, so scale to
`KESTREL_LIMIT_TOKENS_PER_SESSION=300` or `KESTREL_LIMIT_COST_CEILING_USD=0.0005`.

Running both, one after the other, is the strongest version of the block: the same
attack, caught by a different level each time.

> **The cost is simulated** - tokens multiplied by `KESTREL_USD_PER_1K_TOKENS`, never
> read back from OpenRouter. Do not demo by draining a real key: when OpenRouter
> refuses the adapter raises `RuntimeError` and you get a 500, not a lesson. Keep a
> credit limit on the key as the safety net and demo the drain with this meter.

---

## Anywhere else

Nothing here is Railway-specific. Any platform that runs a Dockerfile works:

```
docker build -t kestrel-day2 workshop-day2
docker run -p 8000:8000 \
  -e LLM_PROVIDER=openrouter \
  -e OPENROUTER_API_KEY=sk-or-... \
  -e KESTREL_ACCESS_PASSWORD=choose-one \
  kestrel-day2
```

Without Docker, the same variables plus a host:

```
HOST=0.0.0.0 PORT=8000 KESTREL_ACCESS_PASSWORD=choose-one python kestrel.py run
```

`kestrel.py run` binds `127.0.0.1` unless you say otherwise, and prints a warning
naming the host when you do — including whether a password is set.

### If you are running it behind plain HTTP

The session cookie is marked `Secure`, so it will not be sent over HTTP and the login
will loop. Railway gives you HTTPS, so this does not come up there. On a bare VM
without TLS, set `KESTREL_COOKIE_SECURE=0` — and understand you are sending a shared
password in the clear.
