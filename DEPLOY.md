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
