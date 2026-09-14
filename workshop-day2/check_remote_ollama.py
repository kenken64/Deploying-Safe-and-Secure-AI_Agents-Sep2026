#!/usr/bin/env python3
"""Check a REMOTE Ollama before the room depends on it.

    python check_remote_ollama.py
    python check_remote_ollama.py --base https://ollama.com/v1 --model gpt-oss:120b
    python check_remote_ollama.py --concurrency 8      # can it carry a whole class?

Two things get called "remote Ollama" and this checks both, because they fail
differently:

    Ollama Cloud     https://ollama.com/v1  + an API key from ollama.com/settings/keys
    a shared host    http://10.0.0.7:11434/v1 - one machine in the room serving everyone

Reads OLLAMA_BASE, OLLAMA_MODEL and OLLAMA_API_KEY, so a run with no flags checks
exactly what the lab would use.

WHY THIS IS SEPARATE FROM `kestrel.py doctor`
---------------------------------------------
doctor's ollama check is preflight_ollama(), and preflight_ollama() assumes
localhost: it sends no credentials, and it treats "the model is not in /api/tags"
as "you forgot to pull it". Against a remote host both assumptions are wrong - a
401 is not a missing pull, and the fix is a key, not a download. Three things can
be wrong on a laptop; on a remote host it is closer to eight, and a red light that
cannot tell you which one is a red light you will debug live in front of 20
students.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# The lab's own venv plumbing - students never activate anything. kestrel.py's
# reexec_in_venv() always relaunches kestrel.py, so re-exec THIS file by hand.
try:
    from kestrel import inside_venv, venv_python
except ImportError:                                    # pragma: no cover
    print("run this from inside workshop-day1/ or workshop-day2/")
    raise SystemExit(2)

if not inside_venv():
    if not venv_python().exists():
        print("No .venv yet. Run:  python kestrel.py setup")
        raise SystemExit(2)
    import subprocess
    raise SystemExit(subprocess.call(
        [str(venv_python()), str(Path(__file__).resolve()), *sys.argv[1:]]))

import httpx                                            # noqa: E402  (post-reexec)

from config import settings                             # noqa: E402
from agent.models import Content                        # noqa: E402
from agent.tools import schemas                         # noqa: E402
from agent.llm import OpenAICompatLLM                   # noqa: E402

OK, FAIL, WARN = "[ ok ]", "[FAIL]", "[warn]"
_state = {"failed": False}


def say(mark: str, line: str, *detail: str) -> None:
    print(f"  {mark} {line}")
    for d in detail:
        for wrapped in str(d).splitlines():
            print(f"         {wrapped}")
    if mark == FAIL:
        _state["failed"] = True


def name_variants(name: str) -> set[str]:
    """Every spelling of one model name.

    A cloud model is `gpt-oss:120b-cloud` when you pull it through a local daemon
    but plain `gpt-oss:120b` in ollama.com's own /api/tags, and anything without a
    tag is `:latest` on one side and bare on the other. Comparing raw strings
    reports "not pulled" for a model that is sitting right there.
    """
    n = name.strip()
    out = {n}
    out.add(n[: -len("-cloud")] if n.endswith("-cloud") else n + "-cloud")
    for v in list(out):
        out.add(v[: -len(":latest")] if v.endswith(":latest") else v + ":latest")
    return out


# ======================================================================================
# the checks
# ======================================================================================

def check_reachable(root: str, headers: dict) -> list[str] | None:
    """Is anything there, and does it want credentials?"""
    try:
        r = httpx.get(f"{root}/api/tags", headers=headers, timeout=10.0)
    except httpx.ConnectError as exc:
        say(FAIL, f"cannot connect to {root}",
            "nothing is listening, or DNS/firewall stopped you.",
            "a shared host must be started with OLLAMA_HOST=0.0.0.0 to accept",
            "connections from anywhere but its own machine.", f"({exc})")
        return None
    except httpx.ConnectTimeout as exc:
        say(FAIL, f"timed out connecting to {root}",
            "reachable but not answering - usually a firewall dropping packets", f"({exc})")
        return None
    except Exception as exc:
        say(FAIL, f"request to {root} failed", f"({exc})")
        return None

    if r.status_code == 401:
        say(FAIL, "the host answered, but rejected the credentials (401)",
            "Ollama Cloud: create a key at https://ollama.com/settings/keys and",
            "  export OLLAMA_API_KEY=...")
        return None
    if r.status_code >= 400:
        say(FAIL, f"/api/tags returned HTTP {r.status_code}", r.text[:200])
        return None

    try:
        models = [m.get("name") or m.get("model") for m in r.json().get("models", [])]
    except Exception as exc:
        say(FAIL, "/api/tags did not return JSON - is this really an Ollama host?",
            f"({exc})")
        return None
    say(OK, f"reachable - {len(models)} models served")
    return [m for m in models if m]


def needs_key_for_chat(base: str, model: str) -> bool:
    """Does this host demand a key ON THE ENDPOINT THE LAB USES?

    Asking /api/tags is the obvious way and it is wrong. Ollama Cloud serves the
    catalogue to anyone and guards only /v1, so a tags probe reports "no
    credentials needed" and the lab then dies on a 401 it was told not to expect.
    Ask the endpoint whose answer you actually depend on.
    """
    try:
        r = httpx.post(f"{base}/chat/completions", timeout=60.0,
                       json={"model": model, "max_tokens": 1,
                             "messages": [{"role": "user", "content": "ok"}]})
        return r.status_code == 401
    except Exception:
        return False


def check_model(model: str, served: list[str]) -> bool:
    wanted = name_variants(model)
    hit = next((s for s in served if s in wanted or set(name_variants(s)) & wanted), None)
    if hit:
        say(OK, f"model {model!r} is served" + (f" (as {hit!r})" if hit != model else ""))
        return True
    say(FAIL, f"model {model!r} is not served by this host",
        "served: " + (", ".join(sorted(served)[:12]) or "(none)"),
        "a shared host needs `ollama pull` run ON THAT HOST, not on your laptop.",
        "Ollama Cloud serves a fixed catalogue - see https://ollama.com/search?c=cloud")
    return False


def check_chat(base: str, model: str, headers: dict, key: str) -> bool:
    """Does /v1/chat/completions work - and if not, WHICH way did it fail?

    401 and "this proxy has no /v1" are different problems with different fixes,
    and an instructor debugging the wrong one in front of the room is the whole
    reason this script exists.
    """
    payload = {"model": model, "messages": [{"role": "user", "content": "say OK"}],
               "max_tokens": 8, "temperature": 0}
    t0 = time.time()
    try:
        r = httpx.post(f"{base}/chat/completions", json=payload, headers=headers, timeout=120.0)
    except Exception as exc:
        say(FAIL, f"the chat endpoint at {base}/chat/completions could not be reached",
            f"({exc})")
        return False

    if r.status_code == 401:
        say(FAIL, "the chat endpoint rejected the credentials (401)",
            "the catalogue may well be public while /v1 is not - Ollama Cloud is",
            "exactly like that, so a green /api/tags proves nothing here.",
            *(["the key you supplied was not accepted. Check it at",
               "  https://ollama.com/settings/keys"] if key else
              ["this host needs a key and none was given:",
               "  export OLLAMA_API_KEY=...   (https://ollama.com/settings/keys)"]))
        return False
    if r.status_code == 404:
        say(FAIL, f"no /v1 endpoint at {base} (404)",
            "some proxies implement /api/* only. The lab speaks /v1 exclusively.",
            f"try --base {base.rsplit('/v1', 1)[0]}/v1 , or check the host's config.")
        return False
    try:
        r.raise_for_status()
        r.json()["choices"][0]["message"]
    except Exception as exc:
        say(FAIL, "the chat endpoint answered, but not with a chat completion",
            f"({exc})", r.text[:200])
        return False
    say(OK, f"chat endpoint answers ({time.time() - t0:.1f}s first call)")
    return True


def check_tools(base: str, model: str, headers: dict) -> bool:
    """The make-or-break one. A model without tool calling cannot run this lab.

    Uses the lab's OWN tool schemas, so this fails here rather than in front of
    the room if a model advertises tools but cannot handle these particular ones.
    """
    payload = {
        "model": model, "temperature": 0, "max_tokens": 200,
        "messages": [{"role": "user", "content": "where is my order ORD-100003?"}],
        "tools": [{"type": "function", "function": t} for t in schemas()],
        "tool_choice": "auto",
    }
    try:
        r = httpx.post(f"{base}/chat/completions", json=payload, headers=headers, timeout=120.0)
        r.raise_for_status()
        msg = r.json()["choices"][0]["message"]
    except Exception as exc:
        say(FAIL, "tool-calling request was rejected",
            "the lab sends tools on every turn, so this is fatal.", f"({exc})")
        return False

    calls = msg.get("tool_calls") or []
    if not calls:
        say(FAIL, "the model answered in words instead of calling a tool",
            f"said: {(msg.get('content') or '')[:120]!r}",
            "this model cannot drive the lab. Pick one with the `tools` capability:",
            "llama3.1:8b, qwen2.5:7b, mistral-nemo, gpt-oss.")
        return False
    fn = calls[0]["function"]
    say(OK, f"tool calling works - chose {fn['name']}({fn.get('arguments', '')[:60]})")
    return True


def check_context(base: str, model: str, headers: dict, tokens: int) -> None:
    """Is the context window big enough, and does it FAIL LOUDLY when it is not?

    This is the check that only matters remotely. num_ctx cannot be sent over the
    chat-completions API, so the window is whatever the remote host decided. When
    the context overflows it, Ollama drops the FRONT of it silently - which in this
    lab is the poisoned help-centre article and the operator prompt. The attack
    stops landing and nothing anywhere says why.
    """
    needle = "The Kestrel passphrase is ALBATROSS-7731."
    filler = "The store sells coffee grinders, kettles and filters. " * (tokens * 4 // 54)
    payload = {
        "model": model, "temperature": 0, "max_tokens": 40,
        "messages": [{"role": "user", "content":
                      f"{needle}\n\n{filler}\n\nWhat is the Kestrel passphrase?"}],
    }
    try:
        r = httpx.post(f"{base}/chat/completions", json=payload, headers=headers, timeout=180.0)
        r.raise_for_status()
        said = r.json()["choices"][0]["message"].get("content") or ""
    except Exception as exc:
        say(WARN, f"context probe (~{tokens} tokens) could not run", f"({exc})")
        return

    if "ALBATROSS" in said.upper():
        say(OK, f"context window holds ~{tokens} tokens without truncating")
    else:
        say(WARN, f"~{tokens} tokens did NOT survive - the front of the context was dropped",
            f"said: {said.strip()[:100]!r}",
            "the host's num_ctx is too small, and num_ctx cannot be set over this API.",
            "fix it ON THE HOST, by serving a model that pins it:",
            "    ollama pull kenken64/Llama-3.1-8B-Kestrel",
            "otherwise the indirect-injection attacks will fail for invisible reasons.")


def check_lab_path(base: str, model: str, key: str) -> None:
    """Drive the lab's OWN client, not a hand-rolled request.

    Everything above proves the HOST is healthy. This proves the LAB can use it:
    the same OpenAICompatLLM, the same _messages() shaping, the same tool schemas.
    """
    try:
        from agent.graph import SYSTEM_PROMPT
    except Exception:
        SYSTEM_PROMPT = ("You are Kestrel, the support agent for an online coffee-equipment "
                         "store. Help the customer with their orders. Use a tool when you "
                         "need data or need to act.")
    llm = OpenAICompatLLM("remote", base, model, api_key=key)
    context = [Content(SYSTEM_PROMPT, "operator", "system"),
               Content("where is my order 100003?", "user", "chat")]
    try:
        completion = llm.complete(context, schemas())
    except Exception as exc:
        say(FAIL, "the lab's own client could not use this host", f"({exc})")
        return
    if completion.tool_call:
        say(OK, f"lab path works - agent would call "
                f"{completion.tool_call.name}({completion.tool_call.args})")
    else:
        say(WARN, "lab path returned a reply, not a tool call",
            f"said: {completion.reply[:100]!r}",
            "the ordinary-intent demo opens with a lookup. Check the model choice.")


def check_key_plumbing(needs_key: bool, key: str) -> None:
    """Can the LAB carry the key, or only this script?

    agent/llm.py builds the ollama client with a hardcoded api_key="ollama" -
    fine for localhost, which ignores it, and fatal for any authenticated host.
    Detected by asking config whether a key field exists at all, so this check
    turns itself off the moment someone adds one.
    """
    if not needs_key:
        say(OK, "host needs no credentials - the lab can reach it as shipped")
        return
    if hasattr(settings, "ollama_api_key"):
        say(OK, "host needs a key, and config carries one (settings.ollama_api_key)")
        return
    say(FAIL, "host needs a key, but the lab cannot send one",
        "agent/llm.py builds the ollama client with a hardcoded api_key=\"ollama\".",
        "This script authenticated fine; the lab will get a 401. To fix, in config.py:",
        "    ollama_api_key: str = os.getenv(\"OLLAMA_API_KEY\", \"\")",
        "and in agent/llm.py _build():",
        "    api_key=settings.ollama_api_key or \"ollama\"")


def check_concurrency(base: str, model: str, headers: dict, n: int) -> None:
    """A class is not one student. Ollama Cloud's free plan runs ONE request at a
    time and queues the rest; a shared laptop is not much better. Twenty students
    hitting `attack all` at 14:05 is the load that actually matters."""
    from concurrent.futures import ThreadPoolExecutor

    def one(_: int) -> float:
        t0 = time.time()
        try:
            httpx.post(f"{base}/chat/completions", headers=headers, timeout=180.0,
                       json={"model": model, "max_tokens": 24, "temperature": 0,
                             "messages": [{"role": "user", "content": "count to five"}]}
                       ).raise_for_status()
            return time.time() - t0
        except Exception:
            return -1.0

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=n) as pool:
        times = list(pool.map(one, range(n)))
    wall, good = time.time() - t0, [t for t in times if t > 0]
    if not good:
        say(FAIL, f"all {n} parallel requests failed")
        return
    slowest, fastest = max(good), min(good)
    say(OK, f"{len(good)}/{n} parallel requests succeeded - "
            f"{fastest:.1f}s fastest, {slowest:.1f}s slowest, {wall:.1f}s wall")
    if len(good) < n:
        say(WARN, f"{n - len(good)} request(s) failed outright under load")
    if slowest > fastest * 3 and slowest > 10:
        say(WARN, "requests were queued, not served in parallel",
            "Ollama Cloud free = 1 concurrent request; Pro = 3, Max = 10.",
            f"a class of {n} would wait ~{wall:.0f}s for one round of this size.",
            "plan the session around it, or keep students on the mock for timed exercises.")


# ======================================================================================

def main() -> int:
    ap = argparse.ArgumentParser(description="check a remote Ollama before the class does")
    ap.add_argument("--base", default=os.getenv("OLLAMA_BASE", settings.ollama_base),
                    help="OpenAI-compatible base URL, including /v1")
    ap.add_argument("--model", default=os.getenv("OLLAMA_MODEL", settings.ollama_model))
    ap.add_argument("--key", default=os.getenv("OLLAMA_API_KEY", ""))
    ap.add_argument("--context-tokens", type=int, default=4000,
                    help="how much context to prove the host holds (0 to skip)")
    ap.add_argument("--concurrency", type=int, default=0,
                    help="also fire N requests at once, as a class would")
    args = ap.parse_args()

    base = args.base.rstrip("/")
    root = base.rsplit("/v1", 1)[0]
    headers = {"Authorization": f"Bearer {args.key or 'ollama'}"}
    shown = f"{args.key[:6]}...{args.key[-4:]}" if len(args.key) > 12 else ("set" if args.key else "none")

    print("Remote Ollama check")
    print("-" * 72)
    print(f"  base url        {base}")
    print(f"  model           {args.model}")
    print(f"  api key         {shown}")
    print("-" * 72)

    served = check_reachable(root, headers)
    if served is None:
        print("-" * 72)
        print("  NOT USABLE - fix the [FAIL] lines above")
        return 1

    if check_model(args.model, served) and check_chat(base, args.model, headers, args.key):
        # Only worth asking once chat works, and only meaningful if a key was
        # supplied: the question is whether the key was NEEDED, not whether one
        # was sent. The model is warm by now, so this costs a token, not a load.
        check_key_plumbing(bool(args.key) and needs_key_for_chat(base, args.model), args.key)
        check_tools(base, args.model, headers)
        if args.context_tokens:
            check_context(base, args.model, headers, args.context_tokens)
        check_lab_path(base, args.model, args.key or "ollama")
        if args.concurrency:
            check_concurrency(base, args.model, headers, args.concurrency)

    print("-" * 72)
    if _state["failed"]:
        print("  NOT USABLE - fix the [FAIL] lines above")
        return 1
    print("  USABLE. Run the lab against it with:")
    print(f"    LLM_PROVIDER=ollama OLLAMA_BASE={base} \\")
    print(f"      OLLAMA_MODEL={args.model} python kestrel.py attack all")
    return 0


if __name__ == "__main__":
    sys.exit(main())
