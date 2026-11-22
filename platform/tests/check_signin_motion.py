#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The sign-in's motion and the dive after it (the user, 2026-11-19), no database:
1. /welcome (signin_welcome.py): signed out -> the sign-in page, never the product's logo; signed in -> the page with
   the next page, which is a path on this site only (//elsewhere, http://..., a loop to /welcome -> the Overview);
2. a successful sign-in goes to /welcome?next=... (auth.start_session), the session cookie set as before;
3. the pages: the old look (no soft-card classes), the card turns (auth-turn.js before sign-in, in PUBLIC_STATIC),
   the welcome page clears an earlier "arriving" mark before loader.js, motion off for people who turn it off,
   and no logo or tab icon before sign-in.
Usage: tests/check_signin_motion.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


S = os.environ.get("LG_HELD_DIR", "")


def src(name, live):
    p = os.path.join(S, name + ".new")
    return open(p if S and os.path.exists(p) else live, encoding="utf-8").read()


print("1. /welcome")
from flask import Flask, g  # noqa: E402
import signin_welcome as SW  # noqa: E402
import auth  # noqa: E402
app = Flask(__name__, template_folder=os.path.join(HERE, "templates"))
who = {"u": None}


@app.before_request
def _u():
    g.user = who["u"]


if S and os.path.exists(os.path.join(S, "welcome.html.new")):    # the held template, before it is copied in
    import jinja2
    app.jinja_loader = jinja2.ChoiceLoader([jinja2.DictLoader({"welcome.html": src("welcome.html", "")}), app.jinja_loader])
SW.install(app, {"safe_next": auth._safe_next})
c = app.test_client()
r = c.get("/welcome?next=/findings")
ok("signed out: sent to the sign-in page, nothing else", r.status_code in (302, 303) and r.headers["Location"].endswith("/login")
   and b"Looking Glass" not in r.data)
who["u"] = {"user": "analyst1"}
r = c.get("/welcome?next=/findings")
body = r.get_data(as_text=True)
ok("signed in: the page, with the page asked for next", r.status_code == 200 and 'data-next="/findings"' in body, r.status_code)
ok("…never kept by a browser or proxy", "no-store" in r.headers.get("Cache-Control", ""))
for bad in ("//example.org/x", "https://example.org/", "/welcome", "/welcome?next=/welcome", "javascript:alert(1)", ""):
    b = c.get("/welcome", query_string={"next": bad}).get_data(as_text=True)
    ok(f"next {bad!r}: the Overview instead", 'data-next="/overview"' in b, bad)
who["u"] = {"user": "automation", "automation": True}
ok("the automation key gets no welcome page", c.get("/welcome").status_code in (302, 303))
asrc = open(os.path.join(HERE, "auth.py"), encoding="utf-8").read()
ok("2. a successful sign-in goes to /welcome?next=..., the cookie set as before",
   'resp = redirect("/welcome?next=" + quote(nxt, safe="/"))' in asrc and "resp.set_cookie(cookie_name(), token" in asrc)
ok("…/welcome is not a public page (signed out it is the sign-in)", not any("/welcome".startswith(p) for p in auth.PUBLIC_PATHS))
ok("…the turn script loads before sign-in", "/static/js/auth-turn.js" in auth.PUBLIC_STATIC)

print("3. The pages")
login = src("login.html", os.path.join(HERE, "templates", "login.html"))
base = src("auth_base.html", os.path.join(HERE, "templates", "auth_base.html"))
welcome = src("welcome.html", os.path.join(HERE, "templates", "welcome.html"))
turn = src("auth-turn.js", os.path.join(HERE, "static", "js", "auth-turn.js"))
card = src("auth-card.js", os.path.join(HERE, "static", "js", "auth-card.js"))
wjs = src("welcome.js", os.path.join(HERE, "static", "js", "welcome.js"))
css = src("auth.css", os.path.join(HERE, "static", "css", "auth.css"))
ok("the old look: no soft-card parts", not any(k in login + css for k in ("auth-round", "auth-orbs", "auth-badge", "auth-swap")))
ok("the card turns over (a real 3D turn) for Create an account, Sign in and Back", "window.LGTurn.turn(card" in card
   and "rotateY(90deg)" in css and ".auth-wrap { perspective" in css and "js/auth-turn.js" in base)
ok("…the entrance never replays and the inside never fades during a turn (the fade the user saw)",
   ".auth-card.lg-settled { animation: none; }" in css and 'v.classList.remove("auth-in")' in turn)
ok("…the next step turns in when it changed; the last step's button and the card leave", 'sessionStorage.setItem("lg.turn"' in turn
   and "lg-going" in turn and "lg-leaving" in turn and "body.lg-leaving .auth-card" in css)
ok("the dive: the globe to black, then the logo, then the page asked for", "transform: scale(14)" in css
   and 'LGLoader.busy("Opening Looking Glass")' in wjs and "LGLoader.go(safe" in wjs)
ok("…an earlier page's 'arriving' mark is cleared before loader.js reads it (no double logo)",
   'sessionStorage.removeItem("lg.arrive")' in wjs and welcome.index("js/welcome.js") < welcome.index("js/loader.js"))
ok("…next is a path on this site in the page too", "/^\\/(?!\\/)" in wjs)
ok("motion off (the person's setting): no turn, no dive", "prefers-reduced-motion" in turn and "prefers-reduced-motion" in wjs
   and "location.replace(safe)" in wjs)
ok("no logo or tab icon before sign-in", "<img" not in login + base and 'href="data:,"' in base and "signin_logo" not in login + base)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
