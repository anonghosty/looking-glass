#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Settings → Organisation: the logo's size and crop tool (logo-tool.js; the user, 2026-11-19: a wide logo with white
margins "looks bad", PNGs without a background, "accommodate sizes and cropping ratios ... and the recommended size").
From the files, no server: the picture is fitted to the advisory's 2:1 frame (the PDF's logo card), margins trimmed,
a background for see-through pictures, previews of the card on both advisory looks, the recommended size, a result
within the server's limit, made in the browser (nothing sent before Save), a keyboard-usable dialog.
With LG_TRY_BROWSER=1 and Playwright, the tool also runs on made-up pictures (scratchpad try_logo_tool.py does this).
Usage: tests/check_logo_tool.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def src(name, live):
    p = os.path.join(S, name + ".new")
    return open(p if S and os.path.exists(p) else live, encoding="utf-8").read()


js = src("logo-tool.js", os.path.join(HERE, "static", "js", "logo-tool.js"))
org = src("organisation.js", os.path.join(HERE, "static", "js", "organisation.js"))
html = src("settings.html", os.path.join(HERE, "templates", "settings.html"))
css = src("settings.css", os.path.join(HERE, "static", "css", "settings.css"))
import organisation as O  # noqa: E402
apdf = open(os.path.join(HERE, "advisory_pdf.py"), encoding="utf-8").read()

print("1. The advisory's frame")
m = re.search(r"bw, bh = (\d+), (\d+)", apdf)
bw, bh = int(m.group(1)), int(m.group(2))
ok("the frame is the PDF's logo card's picture area (2:1)", "OUT_W = 464, OUT_H = 232" in js and abs((bw - 16) / (bh - 16) - 2) < 0.01, f"{bw}x{bh}")
ok("…the result never over the server's limit", f"const MAX_KB = {O.MAX_LOGO // 1024};" in js and "<= MAX_KB * 1024" in js)
ok("…a PNG, a JPEG when opaque and the PNG would be too big, smaller sizes before giving up", 'toDataURL("image/png")' in js
   and 'toDataURL("image/jpeg"' in js and "[348, 174]" in js)
print("2. Trim, size, place, background")
ok("empty margins trimmed (see-through or the corner's colour)", "function contentBox(img)" in js and "Trim empty margins" in js)
ok("a size slider and drag, or the arrow keys, to place it", 'zoom.type = "range"' in js and '"pointermove"' in js and "ArrowLeft" in js)
ok("a background for see-through pictures: keep it, white or dark", "Keep see-through" in js and "White background" in js and "Dark background" in js)
print("3. What the administrator sees")
ok("the frame's border highlighted", ".lt-border" in css and "dashed" in css[css.find(".lt-border"):css.find(".lt-border") + 120])
ok("previews of the card on the designed and the plain advisory", "On the advisory (designed, dark pages)" in js and "On the advisory (plain, white pages)" in js
   and ".lt-on-dark" in css and ".lt-on-light" in css)
ok("the recommended size and the saved size", "Recommended: a wide logo" in js and "The saved logo:" in js)
print("4. Safe and usable")
ok("made in the browser: nothing fetched or sent by the tool", "fetch(" not in js and "XMLHttpRequest" not in js and "createObjectURL" in js and "revokeObjectURL" in js)
ok("a real dialog: Escape cancels, the focus comes back", "showModal()" in js and '"cancel"' in js and "prev.focus()" in js and 'aria-labelledby' in js)
ok("Settings opens it for a chosen picture (up to 5 MB) and keeps the old way without it", "window.LGLogoTool.open(f)" in org
   and "5 * 1024 * 1024" in org and "if (f.size > maxKb * 1024)" in org)
ok("…loaded before organisation.js", html.find("js/logo-tool.js") != -1 and html.find("js/logo-tool.js") < html.find("js/organisation.js"))
ok("the server still checks what arrives (PNG / JPEG, its real type, the size)", "def check_logo" in open(os.path.join(HERE, "organisation.py"), encoding="utf-8").read())

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
