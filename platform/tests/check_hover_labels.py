#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Hover labels on the header and portal buttons (header-tips.js; the user, 2026-11-19: "when you hover in a portal it
should say what the button is"), from the files, no server: every page with a header loads it, it names a button by
its aria-label, title or text, on hover and on keyboard focus, never fetches anything, and the bell is named from the
start. The browser checks (tests/browser_checks.py) hover a header button on every page of every role.
Usage: tests/check_hover_labels.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


js = src("header-tips.js", os.path.join(HERE, "static", "js", "header-tips.js"))
for page in ("_page_nav.html", "index.html", "services.html"):
    ok(f"{page} loads the hover labels", "js/header-tips.js" in src(page, os.path.join(HERE, "templates", page)))
ok("a button is named by its aria-label, else its title, else its text", 'getAttribute("aria-label")' in js
   and 'getAttribute("title")' in js and "textContent" in js)
ok("…on hover and on keyboard focus, gone on Escape, scrolling or leaving", all(k in js for k in ('"mouseover"', '"focusin"', '"focusout"', '"Escape"', '"scroll"')))
ok("…only for the header and portal buttons", ".hud-right" in js and ".nav-ic" in js and ".mg-top-actions" in js)
ok("…plain text, nothing fetched", "textContent = name" in js and "fetch(" not in js and "innerHTML" not in js)
ok("…the browser's own tooltip kept aside while it shows, and put back", 'removeAttribute("title")' in js and 'setAttribute("title", cur.dataset.lgTitle)' in js)
css = src("app.css", os.path.join(HERE, "static", "css", "app.css"))
ok("styled above everything, never in the way of a click", ".lg-htip" in css and "pointer-events: none" in css[css.find(".lg-htip"):css.find(".lg-htip") + 200])
bell = src("notifications.js", os.path.join(HERE, "static", "js", "notifications.js"))
ok("the bell has a name before its first count arrives", 'b.title = "Notifications"; b.setAttribute("aria-label", "Notifications")' in bell)
bc = open(os.path.join(HERE, "tests", "browser_checks.py"), encoding="utf-8").read()
ok("the browser checks hover a header button on every page", "a header button shows no hover label" in bc)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
