"""Kestrel storefront, support chat, and the control room.

The layout is deliberately the same two panes the course uses for both live demos:

    LEFT   the customer chat - ordinary, familiar, unthreatening
    RIGHT  the control room  - where you watch the data boundary go red

Nothing here is the lesson. The lesson is in agent/. This is the window onto it.
"""
from __future__ import annotations

import re
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from config import CONTROLS, PROFILES, settings
from agent import db, graph, llm
from agent.models import Principal
from agent.telemetry import LIGHTS, board
from attacks.catalogue import ATTACKS, ORDER, TUTORIAL_LABS
from attacks.run import run_one

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

app = FastAPI(title="Kestrel Goat - Day 1")
app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
templates = Jinja2Templates(directory=str(HERE / "templates"))
# Jinja's template cache keys on a dict under some Python 3.14 builds and raises
# TypeError. Students turn up with every Python from 3.10 to 3.14, so the lab
# simply does not use the cache. Templates are tiny; nobody will notice.
templates.env.cache = None
templates.env.auto_reload = True

SIGNED_IN = {"customer_id": "CUST-1001"}


def principal() -> Principal:
    cid = SIGNED_IN["customer_id"]
    if cid == "STAFF-9001":
        return Principal(id=cid, display_name="Sam Rivera (staff)", role="staff", customer_id=None)
    row = db.customer(cid)
    return Principal(id=cid, display_name=row["name"] if row else cid,
                     role="customer", customer_id=cid)


def board_state() -> dict:
    return {
        "lights": [{"key": k, "label": LIGHTS[k], "level": board.lights[k]} for k in LIGHTS],
        "worst": board.worst(),
        "events": board.tail(40),
        "breaches": list(dict.fromkeys(board.breaches)),
        "refunds": db.refunds()[:6],
    }


def controls_state() -> list[dict]:
    return [{"key": k, "on": settings.on(k), **meta} for k, meta in CONTROLS.items()]


@app.middleware("http")
async def _model_badge(request: Request, call_next):
    """Every page says which model is driving the agent. Students should never
    have to discover that the model is a stand-in - it is on screen the whole time."""
    return await call_next(request)


def model_badge() -> dict:
    if settings.llm_provider == "mock":
        return {"kind": "mock", "text": "MODEL: MOCK",
                "hint": "deterministic stand-in - no key, no network, identical every run"}
    where = "on this laptop via Ollama" if settings.llm_provider == "ollama" else "via OpenRouter"
    return {"kind": "live", "text": f"MODEL: {settings.active_model}",
            "hint": f"a real LLM {where} - non-deterministic"}


@app.on_event("startup")
def _startup() -> None:
    db.ensure()


# ------------------------------------------------------------------ pages ------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    p = principal()
    orders = db.rows("SELECT * FROM orders WHERE customer_id = ?", (p.customer_id,)) if p.customer_id else []
    return templates.TemplateResponse(request, "store.html", {
        "p": p, "orders": orders,
        "customers": db.rows("SELECT * FROM customers"),
        # Every order, with the customer it belongs to. The storefront shows this ONLY
        # behind a collapsed "instructor view" - the shop itself must keep showing just
        # what the signed-in customer is entitled to, or a1 has nothing left to reveal.
        "all_orders": db.rows(
            "SELECT o.*, c.name AS customer_name FROM orders o "
            "LEFT JOIN customers c ON c.id = o.customer_id ORDER BY o.id"),
        "articles": db.rows("SELECT id, title FROM articles"),
        "badge": model_badge(),
    })


@app.get("/console", response_class=HTMLResponse)
def console(request: Request):
    return templates.TemplateResponse(request, "console.html", {
        "p": principal(), "controls": controls_state(),
        "profiles": list(PROFILES), "attacks": [ATTACKS[a] for a in ORDER],
        "provider": settings.llm_provider, "model": settings.model,
        "ollama_model": settings.ollama_model,
        "customers": db.rows("SELECT * FROM customers"),
        "badge": model_badge(), "directives": [n for n, _ in __import__(
            "agent.directives", fromlist=["DIRECTIVES"]).DIRECTIVES],
    })


@app.get("/tutorial", response_class=HTMLResponse)
def tutorial_index(request: Request):
    items = []
    for path in sorted((ROOT / "tutorials").glob("*.md")):
        title = _first_heading(path)
        items.append({"slug": path.stem, "title": title})
    return templates.TemplateResponse(request, "tutorials.html", {
        "items": items, "body": None, "title": "Tutorials", "badge": model_badge()})


def lab_for(slug: str) -> dict | None:
    """Wire each tutorial to the attack it explains and the controls that close it,
    so the whole loop - run it, read it, fix it, prove it - happens on one page.

    Most pages are derived: an attack names its tutorial, so the page owns it.
    TUTORIAL_LABS overrides that for the page the derivation cannot reach (v04 -
    see the note in attacks/catalogue.py).
    """
    if override := TUTORIAL_LABS.get(slug):
        related = [ATTACKS[a] for a in override["attacks"]]
        controls = [k for k in override["controls"] if k in CONTROLS]
        return {
            "attacks": [{"id": a.id, "name": a.name, "message": a.message,
                         "note": a.note} for a in related],
            "controls": [{"key": k, "on": settings.on(k), **CONTROLS[k]} for k in controls],
        }

    related = [a for a in ATTACKS.values() if a.tutorial == slug]
    if not related:
        return None
    controls: list[str] = []
    for a in related:
        for key in a.closed_by:
            if key not in controls:
                controls.append(key)
    return {
        "attacks": [{"id": a.id, "name": a.name, "message": a.message,
                     "note": a.note} for a in related],
        "controls": [{"key": k, "on": settings.on(k), **CONTROLS[k]} for k in controls],
    }


@app.get("/tutorial/{slug}", response_class=HTMLResponse)
def tutorial(request: Request, slug: str):
    path = ROOT / "tutorials" / f"{slug}.md"
    if not path.exists():
        return RedirectResponse("/tutorial")
    items = [{"slug": p.stem, "title": _first_heading(p)}
             for p in sorted((ROOT / "tutorials").glob("*.md"))]
    return templates.TemplateResponse(request, "tutorials.html", {
        "items": items,
        "body": _markdown(path.read_text(encoding="utf-8")),
        "title": _first_heading(path), "slug": slug, "badge": model_badge(),
        "lab": lab_for(slug)})


# ------------------------------------------------------------------- api -------------
@app.post("/api/chat")
async def api_chat(request: Request):
    payload = await request.json()
    text = str(payload.get("text", ""))[:20_000]
    result = graph.chat(principal(), text)
    return JSONResponse({**result, "board": board_state()})


@app.get("/api/board")
def api_board():
    return JSONResponse(board_state())


@app.post("/api/controls")
async def api_controls(request: Request):
    payload = await request.json()
    if profile := payload.get("profile"):
        settings.apply_profile(profile)
    if (key := payload.get("key")) in CONTROLS:
        settings.set(key, bool(payload.get("on")))
    return JSONResponse({"controls": controls_state()})


@app.post("/api/model")
async def api_model(request: Request):
    payload = await request.json()
    provider = payload.get("provider", "mock")
    if provider not in ("mock", "ollama", "openrouter"):
        provider = "mock"
    previous = settings.llm_provider
    settings.llm_provider = provider
    llm.reset_llm()
    try:
        llm.get_llm()
        return JSONResponse({"provider": provider, "model": settings.active_model, "ok": True})
    except Exception as exc:          # no key, no ollama, no network - say exactly which
        settings.llm_provider = previous if previous != provider else "mock"
        llm.reset_llm()
        return JSONResponse({"provider": settings.llm_provider, "ok": False, "error": str(exc)})


@app.post("/api/signin")
async def api_signin(request: Request):
    payload = await request.json()
    SIGNED_IN["customer_id"] = str(payload.get("customer_id", "CUST-1001"))
    return JSONResponse({"signed_in": SIGNED_IN["customer_id"]})


@app.post("/api/attack/{attack_id}")
def api_attack(attack_id: str):
    if attack_id not in ATTACKS:
        return JSONResponse({"error": "unknown attack"}, status_code=404)
    outcome = run_one(ATTACKS[attack_id], verbose=False)
    return JSONResponse({**outcome, "board": board_state()})


@app.post("/api/reset")
def api_reset():
    db.reset()
    board.reset()
    graph.SESSIONS.clear()
    return JSONResponse({"ok": True, "board": board_state()})


# ------------------------------------------------------------ tiny markdown ----------
def _first_heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return path.stem


def _markdown(text: str) -> str:
    """A deliberately small markdown renderer - one less dependency for students
    to install, on any of the three operating systems."""
    out: list[str] = []
    in_code = in_list = in_table = False
    for raw in text.splitlines():
        if raw.startswith("```"):
            out.append("</code></pre>" if in_code else '<pre><code>')
            in_code = not in_code
            continue
        if in_code:
            out.append(_esc(raw))
            continue
        line = _inline(_esc(raw))
        if raw.startswith("|") and "|" in raw[1:]:
            cells = [c.strip() for c in raw.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            if not in_table:
                out.append("<table>")
                in_table = True
                out.append("<tr>" + "".join(f"<th>{_inline(_esc(c))}</th>" for c in cells) + "</tr>")
                continue
            out.append("<tr>" + "".join(f"<td>{_inline(_esc(c))}</td>" for c in cells) + "</tr>")
            continue
        if in_table:
            out.append("</table>")
            in_table = False
        if m := re.match(r"^(#{1,4})\s+(.*)$", raw):
            level, text = len(m.group(1)), m.group(2)
            out.append(f'<h{level} id="{_slug(text)}">{_inline(_esc(text))}</h{level}>')
            continue
        if re.match(r"^\s*[-*]\s+", raw) or re.match(r"^\s*\d+\.\s+", raw):
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{_inline(_esc(re.sub(r'^\s*(?:[-*]|\d+\.)\s+', '', raw)))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if raw.startswith(">"):
            out.append(f"<blockquote>{line.lstrip('&gt;').strip()}</blockquote>")
            continue
        if not raw.strip():
            out.append("")
            continue
        out.append(f"<p>{line}</p>")
    for closer, flag in (("</ul>", in_list), ("</table>", in_table), ("</code></pre>", in_code)):
        if flag:
            out.append(closer)
    return "\n".join(out)


def _slug(s: str) -> str:
    """Heading -> anchor id. `Attack.tutorial_anchor` is written against this."""
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _inline(s: str) -> str:
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', s)
    return s
