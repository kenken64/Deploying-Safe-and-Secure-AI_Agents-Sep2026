"""An optional password gate, for when the lab is not on your own laptop.

Kestrel is deliberately vulnerable. Run locally that is the whole point and
nothing here applies - leave `KESTREL_ACCESS_PASSWORD` unset and this module
does nothing at all.

Deployed to a URL it is a different proposition:

    the agent holds a real API key, and b8 is economic exhaustion. An open
    URL means anyone who finds it can spend your OpenRouter balance, and the
    lab's own rate limits are OFF until a student switches them on.

So when the variable IS set, every request needs the password first. This is a
door, not a security model: one shared password, no accounts, no lockout. It
stops a crawler and a passer-by, which is what a workshop URL needs. It is not
what you would put in front of anything real.
"""
from __future__ import annotations

import os
import secrets

from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse

COOKIE = "kestrel_access"
#: Paths that must work before sign-in, or nobody can sign in.
OPEN_PATHS = {"/login", "/healthz", "/favicon.ico"}


def password() -> str:
    return os.getenv("KESTREL_ACCESS_PASSWORD", "")


def enabled() -> bool:
    return bool(password())


def authorised(request: Request) -> bool:
    if not enabled():
        return True
    return secrets.compare_digest(request.cookies.get(COOKIE, ""), password())


LOGIN_PAGE = """<!doctype html><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kestrel Goat</title>
<style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0f1216;
   color:#e6edf3;font:15px/1.55 ui-sans-serif,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
 form{background:#161b22;border:1px solid #252c36;border-radius:10px;padding:26px;
   width:min(370px,92vw)}
 h1{margin:0 0 4px;font-size:17px}
 p{margin:0 0 18px;color:#8b949e;font-size:13px}
 input{width:100%;box-sizing:border-box;background:#0d1117;color:#e6edf3;
   border:1px solid #252c36;border-radius:7px;padding:10px 12px;font:inherit}
 button{margin-top:11px;width:100%;background:#e0a458;color:#1b1205;font-weight:600;
   border:0;border-radius:7px;padding:10px;font:inherit;cursor:pointer}
 .err{color:#f85149;font-size:12.5px;margin:9px 0 0}
</style>
<form method="post" action="/login">
  <h1>Kestrel Goat</h1>
  <p>A deliberately vulnerable support agent, used for a workshop.
     Your instructor has the password.</p>
  <input type="password" name="password" placeholder="Workshop password" autofocus>
  <button type="submit">Enter</button>
  __ERROR__
</form>"""


def login_page(error: str = "") -> HTMLResponse:
    html = LOGIN_PAGE.replace(
        "__ERROR__", f'<p class="err">{error}</p>' if error else "")
    return HTMLResponse(html, status_code=401 if error else 200)


def sign_in(value: str) -> HTMLResponse | RedirectResponse:
    if not (enabled() and secrets.compare_digest(value, password())):
        return login_page("That is not the password.")
    response = RedirectResponse("/", status_code=303)
    # session cookie: closing the browser ends it. httponly so a successful
    # injection in the lab cannot read it back out through the page.
    response.set_cookie(COOKIE, value, httponly=True, samesite="lax",
                        secure=os.getenv("KESTREL_COOKIE_SECURE", "1") == "1")
    return response


def submitted_password(body: bytes) -> str:
    """Read the password out of a urlencoded form body.

    By hand, because `await request.form()` pulls in python-multipart and this
    lab is deliberately thin on dependencies - one less thing for a student to
    install on one of three operating systems. A login form is urlencoded, and
    urlencoded is in the standard library.
    """
    fields = parse_qs(body.decode("utf-8", "replace"))
    return (fields.get("password") or [""])[0]
