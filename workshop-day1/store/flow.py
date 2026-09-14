"""Per-attack data-flow diagrams.  (a sequence diagram, drawn as inline SVG)

Rendered on the server, into the page. The lab has no network and no CDN, so a
diagramming library is not an option - and would be a poor trade anyway: the
actors here are fixed and few, and the only thing that varies between attacks is
who hands what to whom.

Read one the way you read the attacks: follow the numbered arrows down. A dashed
red arrow is the hop where the trust boundary is crossed.
"""
from __future__ import annotations

from html import escape

#: Every actor the lab has, in the left-to-right order they are drawn.
#: The key is what a flow refers to; the label is what a student reads.
ACTORS: dict[str, str] = {
    "attacker": "Attacker",
    "human":    "Customer",
    "agent":    "Kestrel · the LLM",
    "sub":      "Sub-agent",
    "state":    "State · memory",
    "exec":     "Executor · tools",
    "store":    "Store · DB",
    "world":    "Outside world",
    "staff":    "Human reviewer",
}

#: hop kinds -> (stroke, dashed, label colour)
KINDS = {
    "normal":  ("#8b949e", False, "#8b949e"),   # ordinary traffic
    "payload": ("#d29922", False, "#d29922"),   # the attacker's text, moving
    "breach":  ("#da3633", True,  "#f85149"),   # the boundary being crossed
    "control": ("#2ea043", False, "#7ee787"),   # where the fix would sit
}

LANE_W = 152
TOP = 54
ROW_H = 46
PAD_X = 14
LABEL_PX = 11             # font-size of a hop label
CHAR_W = LABEL_PX * 0.62  # monospace, so width is just a character count


def render(flow: list[tuple[str, str, str, str]], caption: str = "") -> str:
    """flow is a list of (from_actor, to_actor, label, kind)."""
    if not flow:
        return ""

    used = [k for k in ACTORS if any(k in (f, t) for f, t, _, _ in flow)]

    def lane(i: int) -> float:
        return PAD_X + LANE_W / 2 + i * LANE_W

    def label_span(i: int, hop) -> tuple[float, float]:
        """Where hop i's label starts and ends, so none of it is drawn off-canvas.

        A self-hop's label sits beside its lifeline, and a long one - "the session
        ends; the memory does not" - runs well past the last lane. Measuring it is
        what keeps it on the diagram.
        """
        src, dst, text, _ = hop
        w = len(f"{i + 1}. {text}") * CHAR_W
        si, di = used.index(src), used.index(dst)
        if src == dst:
            out_dir = -1 if si == len(used) - 1 else 1
            tx = lane(si) + 54 * out_dir
            return (tx, tx + w) if out_dir == 1 else (tx - w, tx)
        mid = (lane(si) + lane(di)) / 2
        return mid - w / 2, mid + w / 2

    spans = [label_span(i, hop) for i, hop in enumerate(flow)]
    base_w = PAD_X * 2 + LANE_W * len(used)
    # Grow the canvas to hold whichever label sticks out furthest, on either side.
    shift = max(0.0, max(-lo for lo, _ in spans) + PAD_X)
    right = max(0.0, max(hi for _, hi in spans) - base_w + PAD_X)

    x = {key: shift + lane(i) for i, key in enumerate(used)}
    width = round(shift + base_w + right)
    height = TOP + ROW_H * len(flow) + 26

    out = [
        # Intrinsic size, never stretched: a squashed sequence diagram is an
        # unreadable one. The container scrolls instead.
        f'<svg class="flow" viewBox="0 0 {width} {height}" width="{width}" '
        f'height="{height}" role="img" xmlns="http://www.w3.org/2000/svg" '
        f'aria-label="{escape(caption or "attack data flow")}">',
        '<defs>',
    ]
    for kind, (stroke, _, _) in KINDS.items():
        out.append(
            f'<marker id="ah-{kind}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{stroke}"/></marker>')
    out.append('</defs>')

    # lifelines and actor heads
    for key in used:
        cx = x[key]
        out.append(
            f'<rect x="{cx - LANE_W / 2 + 8}" y="10" width="{LANE_W - 16}" height="30" '
            f'rx="7" fill="#0d1117" stroke="#252c36"/>')
        out.append(
            f'<text x="{cx}" y="29" text-anchor="middle" font-size="11.5" '
            f'font-family="ui-monospace,Menlo,Consolas,monospace" fill="#e6edf3">'
            f'{escape(ACTORS[key])}</text>')
        out.append(
            f'<line x1="{cx}" y1="42" x2="{cx}" y2="{TOP + ROW_H * len(flow)}" '
            f'stroke="#252c36" stroke-dasharray="3 4"/>')

    # the hops
    for i, (src, dst, label, kind) in enumerate(flow):
        stroke, dashed, ink = KINDS.get(kind, KINDS["normal"])
        y = TOP + ROW_H * i + 18
        x1, x2 = x[src], x[dst]
        dash = ' stroke-dasharray="6 4"' if dashed else ""

        if src == dst:                      # a self-hop: something written in place
            # Loop away from the nearer edge, or the label runs off the diagram -
            # which is exactly what "nobody was asked" did on the last lane.
            out_dir = -1 if used.index(src) == len(used) - 1 else 1
            d = 46 * out_dir
            out.append(
                f'<path d="M{x1},{y} q{d},0 {d},13 q0,13 {-d},13" fill="none" '
                f'stroke="{stroke}" stroke-width="1.6"{dash} '
                f'marker-end="url(#ah-{kind})"/>')
            tx = x1 + 54 * out_dir
            anchor = "start" if out_dir == 1 else "end"
        else:
            out.append(
                f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="{stroke}" '
                f'stroke-width="1.6"{dash} marker-end="url(#ah-{kind})"/>')
            tx, anchor = (x1 + x2) / 2, "middle"

        out.append(
            f'<text x="{tx}" y="{y - 7}" text-anchor="{anchor}" font-size="11" '
            f'font-family="ui-monospace,Menlo,Consolas,monospace" fill="{ink}">'
            f'{i + 1}. {escape(label)}</text>')

    out.append('</svg>')
    return "".join(out)
