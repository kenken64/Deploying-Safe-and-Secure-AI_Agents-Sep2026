"""Serving the lab's own source, so the answer key can point at a line.

The answer key names a file and a line for every fix. On GitHub those are
links; in the lab they were flattened to plain text, because there was nothing
to link to. This is that something.

Two things worth being careful about, in a file that exists to serve files:

  PATH TRAVERSAL. This module resolves a request against the app root and
  refuses anything that escapes it, anything that is not a .py file, and
  anything under .venv or a dotted directory. The rest of Kestrel is
  deliberately vulnerable; a real traversal bug here would be neither
  deliberate nor instructive.

  It is READ ONLY and serves only Python. There is no path by which this
  returns .env, the database, or anything a student has not already got
  checked out in front of them.
"""
from __future__ import annotations

import io
import keyword
import tokenize
from html import escape
from pathlib import Path

#: Only these directories, and only .py inside them.
ALLOWED_DIRS = ("agent", "store", "attacks", "tests")
ALLOWED_FILES = ("config.py", "kestrel.py")


def resolve(root: Path, rel: str) -> Path | None:
    """The app-root-relative path `rel`, or None if it is not ours to serve."""
    if not rel or rel.startswith("/") or "\x00" in rel:
        return None
    candidate = (root / rel).resolve()
    try:
        inside = candidate.relative_to(root.resolve())
    except ValueError:
        return None                                   # escaped the root
    parts = inside.parts
    if any(p.startswith(".") for p in parts):         # .venv, .git, .env
        return None
    if candidate.suffix != ".py" or not candidate.is_file():
        return None
    if len(parts) == 1:
        return candidate if parts[0] in ALLOWED_FILES else None
    return candidate if parts[0] in ALLOWED_DIRS else None


def block_at(path: Path, line: int) -> tuple[int, int]:
    """The def/class block containing `line`, so a link highlights the whole fix.

    Falls back to the single line when the anchor is not inside one - a module
    constant like SECURE_TOOLS, say.
    """
    import ast
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        return line, line
    # defs and classes, plus module-level assignments - several of the fixes are
    # a dict literal (SECURE_TOOLS, MEMORY_GATES, BASELINE) rather than a def,
    # and highlighting one line of a 40-line dict shows nothing.
    kinds = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
             ast.Assign, ast.AnnAssign)
    best = None
    for node in ast.walk(tree):
        if not isinstance(node, kinds):
            continue
        start, end = node.lineno, getattr(node, "end_lineno", node.lineno) or node.lineno
        if start <= line <= end and (best is None or start >= best[0]):
            best = (start, end)
    return best or (line, line)


def _spans(source: str) -> dict[int, list[tuple[int, int, str]]]:
    """(col_start, col_end, css_class) per 1-based line, from the tokenizer."""
    out: dict[int, list[tuple[int, int, str]]] = {}
    try:
        toks = list(tokenize.generate_tokens(io.StringIO(source).readline))
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return out
    for tok in toks:
        if tok.type == tokenize.COMMENT:
            cls = "c"
        elif tok.type == tokenize.STRING:
            cls = "s"
        elif tok.type == tokenize.NAME and keyword.iskeyword(tok.string):
            cls = "k"
        elif tok.type == tokenize.NUMBER:
            cls = "n"
        else:
            continue
        (r1, c1), (r2, c2) = tok.start, tok.end
        for row in range(r1, r2 + 1):
            a = c1 if row == r1 else 0
            b = c2 if row == r2 else len(source.splitlines()[row - 1])
            out.setdefault(row, []).append((a, b, cls))
    return out


def render(path: Path, rel: str, hi: tuple[int, int] | None) -> str:
    source = path.read_text(encoding="utf-8")
    spans = _spans(source)
    lo, hi_end = hi or (0, -1)
    rows = []
    for n, raw in enumerate(source.splitlines(), 1):
        marked, last = [], 0
        for a, b, cls in sorted(spans.get(n, [])):
            if a < last:
                continue
            marked.append(escape(raw[last:a]))
            marked.append(f'<span class="{cls}">{escape(raw[a:b])}</span>')
            last = b
        marked.append(escape(raw[last:]))
        on = " hi" if lo <= n <= hi_end else ""
        rows.append(f'<tr class="sl{on}" id="L{n}">'
                    f'<td class="ln">{n}</td><td class="sc">{"".join(marked) or "&nbsp;"}</td></tr>')
    return f'<table class="src">{"".join(rows)}</table>'
