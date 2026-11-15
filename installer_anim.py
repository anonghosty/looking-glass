#!/usr/bin/env python3
"""The installer's animated Looking Glass logo, drawn in the terminal like the platform's loading screen
(static/img/logo-mark.svg: the lens, the globe lines, the blue-to-red arc, the red ring pinging, the handle).

    installer_anim.py splash                    about 1.6 s: the arc draws itself, the ring pings, the name appears
    installer_anim.py progress STATUS [LOG]     the installation's progress screen until STATUS says STOP: the logo
                                                animating, the current step and a bar. STATUS holds two lines,
                                                "<percent>" and "<message>", rewritten by install.sh.

Each character cell shows two pixels (half blocks). True colour when the terminal says so (COLORTERM), else the
nearest of the 256 colours. Standard library only: it runs before anything else is installed. install.sh only calls it
in a real terminal; LG_NO_ANIMATION=1 (or --no-animation) draws the logo once, still.
"""
import math
import os
import shutil
import signal
import sys
import textwrap
import time

TRUE = os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")
STILL = os.environ.get("LG_NO_ANIMATION") == "1"
SIZE = 40                                   # logo pixels across (and down) on a tall terminal: 40 columns, 20 rows
SIZES = (40, 30, 20)                        # smaller on smaller terminals (80 x 24 gets 30: 15 rows)

LENS, GLOBE, WHITE = (20, 20, 23), (58, 58, 63), (237, 237, 239)
BLUE, RED, VIOLET, DIM = (91, 141, 239), (229, 72, 77), (180, 140, 255), (110, 110, 120)
P0, P1, P2 = (8.4, 18.2), (12.4, 6.6), (19.4, 11.6)        # the arc: a quadratic curve, source to sinkhole


def mix(a, b, t):
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def code(rgb, fg=True):
    if TRUE:
        return f"\x1b[{38 if fg else 48};2;{rgb[0]};{rgb[1]};{rgb[2]}m"
    q = [0 if v < 48 else 1 if v < 115 else (v - 35) // 40 for v in rgb]
    return f"\x1b[{38 if fg else 48};5;{16 + 36 * q[0] + 6 * q[1] + q[2]}m"


# ---- the geometry, worked out once per pixel (in the logo's own 32-unit space)
def _bez(t):
    u = 1 - t
    return (u * u * P0[0] + 2 * u * t * P1[0] + t * t * P2[0], u * u * P0[1] + 2 * u * t * P1[1] + t * t * P2[1])


ARC = [_bez(i / 60) for i in range(61)]
SS = 1                                      # one sample per pixel: crisp, like pixel art (averaging smeared the thin lines)


_GEO = {}


def _geometry(size):
    if size in _GEO:
        return _GEO[size]
    px = []
    scale = 32 / size
    for y in range(size):
        row = []
        for x in range(size):
            samples = []
            for sy in range(SS):
                for sx in range(SS):
                    X, Y = (x + (sx + .5) / SS) * scale, (y + (sy + .5) / SS) * scale
                    r = math.hypot(X - 14, Y - 14)
                    d, t = min((math.hypot(X - ax, Y - ay), i / 60) for i, (ax, ay) in enumerate(ARC))
                    samples.append({"r": r, "arc_d": d, "arc_t": t, "ring_r": math.hypot(X - P2[0], Y - P2[1]),
                                    "src_r": math.hypot(X - P0[0], Y - P0[1]),
                                    "handle": _seg(X, Y, (21.4, 21.4), (27.6, 27.6)),
                                    "glob": min(abs(((X - 14) / 9) ** 2 + ((Y - 14) / 3.4) ** 2 - 1) * 2.6,
                                                abs(((X - 14) / 3.6) ** 2 + ((Y - 14) / 9) ** 2 - 1) * 2.6)})
            row.append(samples)
        px.append(row)
    _GEO[size] = px
    return px


def _seg(x, y, a, b):
    ax, ay = a; bx, by = b
    t = max(0, min(1, ((x - ax) * (bx - ax) + (y - ay) * (by - ay)) / ((bx - ax) ** 2 + (by - ay) ** 2)))
    return math.hypot(x - (ax + t * (bx - ax)), y - (ay + t * (by - ay)))




def pixel(s, arc_upto, phase, ring_scale, ring_alpha, src_alpha):
    """The colour of one sample, or None (the terminal's own background)."""
    c = None
    if s["r"] <= 8.9:
        c = LENS
        if s["glob"] < 0.75:
            c = GLOBE
        if s["arc_d"] < 1.05 and s["arc_t"] <= arc_upto:
            # the arc flows: dashes of 5, gaps of 2 (longer than the SVG's 4 and 3: easier to see in a terminal), moving along it (as the SVG's stroke-dasharray)
            along = s["arc_t"] * 17.5 + phase
            if STILL or along % 7 < 5:
                c = mix(BLUE, RED, s["arc_t"])
        if ring_alpha > 0 and abs(s["ring_r"] - 2.7 * ring_scale) < 0.55:
            c = mix(c, RED, ring_alpha)
    if s["src_r"] <= 1.6:
        c = mix(c or LENS, BLUE, src_alpha)
    if s["ring_r"] <= 1.6 and arc_upto >= 1:
        c = RED
    if abs(s["r"] - 10) <= 1.1 or s["handle"] <= 1.6:
        c = WHITE
    return c


def logo(arc_upto=1.0, t=0.0, size=SIZE):
    """Rows of (top, bottom) colours for the logo at time t (seconds) with the arc drawn up to arc_upto (0..1)."""
    ping = (t % 2.4) / 2.4
    ring_scale = .6 + 1.1 * min(1, ping / .7)
    ring_alpha = 0 if STILL else max(0, .9 * (1 - ping / .7)) if arc_upto >= 1 else 0
    src_alpha = 1 if STILL else .45 + .55 * (1 + math.cos(2 * math.pi * t / 2.4)) / 2
    phase = 0 if STILL else -t * 10
    grid = []
    for row in _geometry(size):
        line = []
        for samples in row:
            cols = [pixel(s, arc_upto, phase, ring_scale, ring_alpha, src_alpha) for s in samples]
            line.append(cols[0])
        grid.append(line)
    return [(grid[y], grid[y + 1]) for y in range(0, size, 2)]


def draw_logo(out, top, left, rows):
    for i, (up, down) in enumerate(rows):
        s = [f"\x1b[{top + i};{left}H"]
        for a, b in zip(up, down):
            if a is None and b is None:
                s.append("\x1b[0m ")
            elif b is None:
                s.append("\x1b[0m" + code(a) + "▀")
            elif a is None:
                s.append("\x1b[0m" + code(b) + "▄")
            else:
                s.append(code(a) + code(b, False) + "▀")
        s.append("\x1b[0m")
        out.append("".join(s))


def text_at(out, row, col, text, rgb=None, bold=False):
    out.append(f"\x1b[{row};{max(1, col)}H\x1b[0m" + ("\x1b[1m" if bold else "") + (code(rgb) if rgb else "") + text + "\x1b[0m")


def screen_on():
    sys.stdout.write("\x1b[?1049h\x1b[?25l\x1b[2J"); sys.stdout.flush()


def screen_off():
    sys.stdout.write("\x1b[0m\x1b[?25h\x1b[?1049l"); sys.stdout.flush()


def fit(cols, lines, spare):
    """The largest logo that fits with `spare` rows left for the text; None when none does."""
    return next((s for s in SIZES if cols >= s + 4 and lines >= s // 2 + spare), None)


def splash():
    cols, lines = shutil.get_terminal_size((80, 24))
    size = fit(cols, lines, 6)
    if size is None:
        return
    screen_on()
    try:
        top, left = max(1, (lines - size // 2 - 4) // 2), (cols - size) // 2 + 1
        name, sub = "L O O K I N G   G L A S S", "Shadowserver threat replay for African CSIRTs"
        t0 = time.time()
        while True:
            t = time.time() - t0
            if t > 1.7 or STILL and t > .6:
                break
            out = []
            draw_logo(out, top, left, logo(arc_upto=1.0 if STILL else min(1, t / .9), t=t, size=size))
            fade = 1.0 if STILL else max(0.0, min(1.0, (t - .8) / .5))
            if fade > 0:
                text_at(out, top + size // 2 + 1, (cols - len(name)) // 2 + 1, name, mix((0, 0, 0), VIOLET, fade), True)
                text_at(out, top + size // 2 + 3, (cols - len(sub)) // 2 + 1, sub, mix((0, 0, 0), DIM, fade))
            sys.stdout.write("".join(out)); sys.stdout.flush()
            time.sleep(1 / 15)
    finally:
        screen_off()


def read_status(path):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return None, ""
    if lines and lines[0].strip() == "STOP":
        return "STOP", ""
    try:
        return max(0, min(100, int(lines[0]))), " ".join(lines[1:]).strip()
    except (IndexError, ValueError):
        return 0, ""


def progress(path, logpath=""):
    parent = os.getppid()
    screen_on()
    signal.signal(signal.SIGINT, signal.SIG_IGN)          # Ctrl+C goes to the installer, which stops cleanly
    try:
        t0, size, last = time.time(), None, None
        while True:
            pct, msg = read_status(path)
            if pct == "STOP" or os.getppid() != parent:
                break
            cols, lines = shutil.get_terminal_size((80, 24))
            if (cols, lines) != size:
                size = (cols, lines)
                sys.stdout.write("\x1b[0m\x1b[2J")
            t = time.time() - t0
            out = []
            title = "Installing Looking Glass"
            text_at(out, 2, (cols - len(title)) // 2 + 1, title, VIOLET, True)
            size = fit(cols, lines, 14)
            if size:
                draw_logo(out, 4, (cols - size) // 2 + 1, logo(1.0, t, size))
            row = 4 if not size else size // 2 + 6
            width = max(20, min(cols - 8, 76))
            wrapped = textwrap.wrap(msg or "Working...", width)[:3]
            for i in range(3):
                line = wrapped[i] if i < len(wrapped) else ""
                text_at(out, row + i, 1, " " * cols)
                text_at(out, row + i, (cols - len(line)) // 2 + 1, line, WHITE)
            bar_w = width - 6
            filled = round(bar_w * (pct or 0) / 100)
            bar = code(VIOLET) + "█" * filled + code((50, 44, 66)) + "░" * (bar_w - filled)
            text_at(out, row + 4, (cols - bar_w - 6) // 2 + 1, bar + f"\x1b[0m {pct or 0:3d}%")
            if logpath:
                note = f"The full log: {logpath}"[:cols - 2]
                text_at(out, min(lines - 1, row + 7), (cols - len(note)) // 2 + 1, note, DIM)
            if (pct, msg, size) != last or not STILL:
                sys.stdout.write("".join(out)); sys.stdout.flush()
                last = (pct, msg, size)
            time.sleep(1 / 12)
    finally:
        screen_off()


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "splash":
            splash()
        elif len(sys.argv) > 2 and sys.argv[1] == "progress":
            progress(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
    except Exception:                       # noqa: BLE001  (the animation never stops an installation)
        try:
            screen_off()
        except Exception:                   # noqa: BLE001
            pass
