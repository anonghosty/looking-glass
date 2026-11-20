#!/usr/bin/env python3
"""The guided tour on every platform and portal (tour.js, tour_prefs.py; the user, 2026-11-20: "add the tour to every
platform too ... also add a test to check these").

1. Every signed-in page with a header loads tour.js; the sign-in pages never do (nothing of the product before sign-in).
2. Every page has its own steps, each with a title and words; every part a step points at exists in the pages' templates
   or scripts (a renamed part would leave a step pointing at nothing: caught here, not by a user).
3. tour.js fetches nothing but /api/tour, writes words with textContent only, keeps the focus in its card, and waits for
   the page's loading before it offers itself.
4. /api/tour: signed in only, CSRF on changes, a page key is checked, per person, nothing else kept, owner-only file.
Made-up users only. Run from the platform's folder: .venv/bin/python tests/check_tour.py (LG_HELD_DIR: held .new files).
"""
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:300]}")


def held(path):
    """A held .new copy of a page file when there is one (the release ships it), else the live file."""
    n = os.path.basename(path)
    return os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else path


def read(path):
    p = held(path)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


TDIR = os.path.join(HERE, "templates")
JDIR = os.path.join(HERE, "static", "js")
tour = read(os.path.join(JDIR, "tour.js"))

print("1. Loaded on every signed-in page with a header, never before sign-in")
ok("tour.js exists", bool(tour))
nav = read(os.path.join(TDIR, "_page_nav.html"))
ok("the shared header (_page_nav.html) loads it", "js/tour.js" in nav)
SIGNED_OUT = {"login.html", "auth_base.html", "forgot.html", "enrol.html", "enrol_done.html", "welcome.html", "denied.html"}
pages = sorted(f for f in os.listdir(TDIR) if f.endswith(".html") and not f.startswith("_"))
with_header = []
for f in pages:
    src = read(os.path.join(TDIR, f))
    if f in SIGNED_OUT:
        ok(f"{f}: no tour (signed out)", "tour.js" not in src)
        continue
    if "hud-right" in src or "mg-top-actions" in src or "_page_nav.html" in src:
        with_header.append(f)
        ok(f"{f}: loads the tour (itself or through the shared header)", "js/tour.js" in src or "_page_nav.html" in src)
ok("…the map, the services platform and the portals are among them",
   {"index.html", "services.html", "overview.html", "management.html", "findings.html", "advisory.html", "audit.html", "admin.html",
    "settings.html", "definitions.html", "combinations.html", "intelligence.html", "review.html", "acode.html",
    "advisory_portal.html"} <= set(with_header), sorted(with_header))

print("2. Every page's own steps")
m = re.search(r"const STEPS = \{(.*?)\n  \};", tour, re.S)
body = m.group(1) if m else ""
keys = re.findall(r'^    "([^"]+)": \[', body, re.M)
WANT = ["/overview", "/#intro", "/", "/services", "/management", "/findings", "/advisory", "/advisory/", "/definitions",
        "/combinations", "/intelligence", "/audit", "/admin", "/settings", "/review/", "/intel/"]
ok("steps for every platform and portal", set(WANT) <= set(keys), sorted(set(WANT) - set(keys)))
steps = re.findall(r'^      \["((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)", "((?:[^"\\]|\\.)*)"\],$', body, re.M)
n_lines = len(re.findall(r'^      \[', body, re.M))
ok("every step is [part, title, words], all three given", steps and len(steps) == n_lines and all(a and b and c for a, b, c in steps),
   f"{len(steps)} of {n_lines}")
for k in keys:
    blk = re.search(r'^    "' + re.escape(k) + r'": \[(.*?)^    \],', body, re.S | re.M)
    titles = re.findall(r'^      \["(?:[^"\\]|\\.)*", "((?:[^"\\]|\\.)*)"', blk.group(1), re.M) if blk else []
    ok(f"{k}: at least 3 steps, no title twice", len(titles) >= 3 and len(titles) == len(set(titles)), titles)
# every part a step points at: its ids and classes are in the templates or the page scripts (held copies first)
corpus = ""
for d in (TDIR, JDIR):
    for f in os.listdir(d):
        if f.endswith((".html", ".js")) and f != "tour.js":
            corpus += read(os.path.join(d, f))
missing = []
for sel, _t, _x in steps:
    for alt in sel.split(","):
        toks = re.findall(r"([#.])([A-Za-z][\w-]*)", re.sub(r":not\([^)]*\)", "", alt))
        for kind, name in toks:
            if re.search(r"(?<![\w-])" + re.escape(name) + r"(?![\w-])", corpus):
                continue
            # a class a script builds from a key (`ax-sec-${key}` with section("inf", …)): the prefix and the key
            pre, _, key = name.rpartition("-")
            if pre and re.search(re.escape(pre) + r"-\$\{", corpus) and re.search(r'\("' + re.escape(key) + r'", ', corpus):
                continue
            missing.append(f"{kind}{name} ({sel})")
ok("every part a step points at exists in the pages' templates or scripts", not missing, missing)
ok("a step whose part is not on the page is left out (never pointing at nothing)",
   "const n = [...document.querySelectorAll(sel)].find(vis);" in tour and "if (n) out.push" in tour)
ok("the header buttons explained from their own descriptions (a new button is covered)", 'getAttribute("title")' in tour and ".hud-right .nav-ic" in tour)
ok("/advisory/12, /review/…, /intel/… use their page's steps", r"/^\/(advisory|review|intel)\/./" in tour)

print("3. What the script does")
ok("fetches only /api/tour", set(re.findall(r'fetch\("([^"]+)"', tour)) == {"/api/tour"} and "XMLHttpRequest" not in tour
   and "sendBeacon" not in tour, re.findall(r'fetch\("([^"]+)"', tour))
ok("…changes carry the page's CSRF token", '"X-CSRF-Token": csrf' in tour)
inner = re.findall(r"innerHTML\s*=\s*(.{0,30})", tour)
ok("words written with textContent; innerHTML only for the fixed icon", len(inner) == 1 and inner[0].startswith("'<svg"), inner)
ok("a dialog with a label, the focus kept in its card (Tab), Escape and arrow keys",
   'setAttribute("aria-modal", "true")' in tour and 'e.key === "Tab"' in tour and 'e.key === "Escape"' in tour and 'e.key === "ArrowRight"' in tour)
ok("…the focus goes back where it was when the tour ends", "ui.back.focus()" in tour)
ok("the first-visit offer: Take the tour, Skip, Don't show again", all(w in tour for w in ('"Take the tour"', '"Skip"', '"Don\'t show again"')))
ok("…offered only after the page's loading (never over a page still being drawn)", "#lgTransition.on, .st-loading:not([hidden])" in tour)
ok("…once per page, per person (the server's memory), and this browser's", 'store.get("seen:" + pageKey())' in tour and "server.pages" in tour)
ok("the Tutorial button before Log out", 'host.insertBefore(b, logout' in tour and 'aria-label", "Tutorial"' in tour)
css = read(os.path.join(HERE, "static", "css", "app.css"))
ok("its styles are in app.css", all(c in css for c in (".lg-tour-card", ".lg-tour-spot", ".lg-tour-offer")))
fsrc = open(os.path.join(HERE, "features.py"), encoding="utf-8").read()
ok("registered in features.py (not app.py)", "import tour_prefs" in fsrc and "tour_prefs.install(app" in fsrc)

print("4. /api/tour")
from flask import Flask, g  # noqa: E402
import tour_prefs as TP  # noqa: E402
tmp = tempfile.mkdtemp()
app = Flask(__name__)
who = {"user": None, "csrf": True, "automation": False}


@app.before_request
def _u():
    g.user = {"user": who["user"], "automation": who["automation"]} if who["user"] else None


prefs = TP.install(app, {"base_dir": tmp, "csrf_ok": lambda: who["csrf"]})
c = app.test_client()
ok("signed out: refused", c.get("/api/tour").status_code == 401 and c.post("/api/tour", json={"page": "/"}).status_code == 401)
who["user"] = "grace"
ok("a new person: nothing seen", c.get("/api/tour").get_json() == {"pages": [], "never": False})
who["csrf"] = False
ok("a change without the page's CSRF token: refused", c.post("/api/tour", json={"page": "/overview"}).status_code == 403)
who["csrf"] = True
for bad in ("javascript:alert(1)", "/" + "a" * 60, "https://example.org/", 5, "/x y", "/<b>"):
    ok(f"not a page key ({str(bad)[:20]}): 400", c.post("/api/tour", json={"page": bad}).status_code == 400)
ok("a page seen: remembered", c.post("/api/tour", json={"page": "/overview"}).status_code == 200
   and c.get("/api/tour").get_json()["pages"] == ["/overview"])
c.post("/api/tour", json={"page": "/overview"})
ok("…once", c.get("/api/tour").get_json()["pages"] == ["/overview"])
ok("the map's Overview and a portal with an id part are page keys", c.post("/api/tour", json={"page": "/#intro"}).status_code == 200
   and c.post("/api/tour", json={"page": "/advisory/"}).status_code == 200)
ok("Don't show again: remembered", c.post("/api/tour", json={"never": True}).get_json()["never"] is True)
ok("…only true counts", c.post("/api/tour", json={"never": "false"}).status_code == 200 and c.get("/api/tour").get_json()["never"] is True)
who["user"] = "daniel"
ok("another person has their own", c.get("/api/tour").get_json() == {"pages": [], "never": False})
for i in range(TP.MAX_PAGES + 10):
    c.post("/api/tour", json={"page": f"/p{i}"})
ok(f"at most {TP.MAX_PAGES} pages kept per person", len(c.get("/api/tour").get_json()["pages"]) == TP.MAX_PAGES)
who["automation"] = True
ok("an automation account has no tour memory", c.get("/api/tour").status_code == 401)
path = os.path.join(tmp, "data", "tour_seen.json")
d = json.load(open(path))
ok("the file holds only page keys and the never flag, per person", set(d) == {"grace", "daniel"}
   and all(set(v) == {"pages", "never"} for v in d.values()), d.get("grace"))
ok("…owner-only (0600)", (os.stat(path).st_mode & 0o777) == 0o600)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
