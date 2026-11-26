#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""RULE (the user, 2026-11-20: "this has to be a check ... make sure everywhere that needs a loading screen is well
done"): every page opens with the loading animation (loader.js: the logo, "Opening …").

1. loader.js takes over every link to another page of the platform (not only the header's), and leaves downloads,
   files, the API, the sign-in pages and a place on the same page to the browser.
2. No page script switches pages by itself without LGLoader.go (location.href / assign / replace to a page), except a
   fallback for when the loader is missing, the sign-in redirect and the address's own query.
3. Every signed-in page loads loader.js and says when it is ready (LGLoader.ready / wait / pane), so the logo never
   hangs and never vanishes before the page is drawn.
The browser side (every link on every page, per role, clicked: the logo shows) is in browser_checks.py (loader_links).
Run from the platform's folder: python3 tests/check_loader_everywhere.py (LG_HELD_DIR: held .new files).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(HERE, "static", "js")):        # run from a draft folder: the platform is the current one
    HERE = os.getcwd()
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:400]}")


def read(path):
    n = os.path.basename(path)
    p = os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else path
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


JDIR, TDIR = os.path.join(HERE, "static", "js"), os.path.join(HERE, "templates")
loader = read(os.path.join(JDIR, "loader.js"))

print("1. loader.js takes over every link to another page")
ok("any link (a[href]), not only the header's page buttons", 'e.target.closest?.("a[href]")' in loader)
ok("…same origin only; new tabs, modified clicks and download links left alone",
   "u.origin !== location.origin" in loader and 'a.target === "_blank"' in loader and 'a.hasAttribute("download")' in loader
   and "e.metaKey || e.ctrlKey || e.shiftKey || e.altKey" in loader)
ok("…the API, files, the sign-in pages and downloads (PDF, CSV, ZIP, reports) left to the browser",
   all(w in loader for w in ("api|static|login|logout|forgot|enrol|welcome", "pdf|csv|zip", "report|preview|export")))
ok("…a place on the same page is not a page change", "u.pathname === location.pathname && u.search === location.search" in loader)
ok("…a link a page handles itself first is left to it (defaultPrevented)", "e.defaultPrevented" in loader)
# 2026-11-25: the bell's /settings#monitor while on Settings showed "Opening settings" for good (the browser only
# scrolled, nothing arrived to take the logo down); Back to a page kept by the browser showed its leaving logo
go = loader[loader.find("    go(url, label) {"):loader.find("    /** on arrival")]
ok("LGLoader.go to a place on this page opens the page again there, never showing the logo",
   "u.pathname === location.pathname && u.search === location.search" in go and "location.reload()" in go
   and go.find("location.reload()") < go.find("show(text)"))
ok("…Back to a page the browser kept: the leaving logo is taken down (pageshow, persisted)",
   'addEventListener("pageshow"' in loader and "e.persisted" in loader and 'classList.remove("on", "leaving")' in loader)

print("2. No page script switches pages without the loader")
FALLBACK = re.compile(r"if \(window\.LGLoader\)")
bad = []
for f in sorted(os.listdir(JDIR)):
    if not f.endswith(".js") or f in ("loader.js",):
        continue
    src = read(os.path.join(JDIR, f))
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        if not re.search(r"location\.(href|assign|replace)\s*(=|\()", ln) or "location.href =" not in ln and "location.assign(" not in ln \
                and "location.replace(" not in ln:
            continue
        near = "\n".join(lines[max(0, i - 6):i + 1])
        if "LGLoader" in near:                         # LGLoader.go(…) with the plain switch only as its fallback
            continue
        if "u.toString()" in ln or "/audit" in ln:   # the address's own query (display.js); a moved tab's redirect
            continue
        bad.append(f"{f}:{i + 1}: {ln.strip()[:120]}")
ok("every page switch in a script goes through LGLoader.go (a plain switch only as its fallback)", not bad, bad)
ok("the Executive portal's Settings goes through the loader", 'window.LGLoader.go("/settings")' in read(os.path.join(JDIR, "management.js")))

print("3. Every signed-in page loads the loader")
SIGNED_OUT = {"login.html", "auth_base.html", "forgot.html", "enrol.html", "enrol_done.html", "welcome.html", "denied.html"}
nav = read(os.path.join(TDIR, "_page_nav.html"))
missing = []
for f in sorted(os.listdir(TDIR)):
    if not f.endswith(".html") or f.startswith("_") or f in SIGNED_OUT:
        continue
    src = read(os.path.join(TDIR, f))
    if "js/loader.js" not in src and not ("_page_nav.html" in src and "js/loader.js" in nav):
        missing.append(f)
ok("every signed-in page loads loader.js (itself or through the shared header)", not missing, missing)
quiet = []
for f in sorted(os.listdir(JDIR)):
    if f.endswith(".js") and f not in ("loader.js",):
        src = read(os.path.join(JDIR, f))
        if re.search(r"getJSON\(|fetch\(", src) and re.search(r"replaceChildren|innerHTML|textContent", src) \
                and not re.search(r"LGLoader\??\.(ready|wait|pane|busy)", src) and f.split(".")[0] in {
                    "app", "services", "management", "findings", "advisory", "advisory-portal", "audit", "admin", "settings",
                    "definitions", "combinations", "intelligence", "review", "acode", "overview"}:
            quiet.append(f)
ok("each page's own script says when it is ready (the logo neither hangs nor leaves early)", not quiet, quiet)

print("4. Even controls (the user, 2026-11-25)")
# the welcome page's big button (intro-cta) stays out of every page and form: one height per size (app.css)
big = []
for d, ext in ((JDIR, ".js"), (TDIR, ".html")):
    for f in sorted(os.listdir(d)):
        if f.endswith(ext) and "intro-cta" in read(os.path.join(d, f)):
            big.append(f)
ok("no page or script uses the big welcome-page button (intro-cta): saving and confirming use the standard button", not big, big)
app_css = read(os.path.join(HERE, "static", "css", "app.css"))
ok("one height per size in app.css: 34 px standard, 28 px small, a small button beside a field takes its height",
   "--ctl-h: 34px" in app_css and "--ctl-h-sm: 28px" in app_css and "tr:has(> td >" in app_css)

print("5. Every form field has a name and a label (the user, 2026-11-25: Chrome's Issues panel)")
forms = loader[loader.find("// every form field has a name and a label"):loader.find("// a scrolling table or list")]
ok("loader.js (on every signed-in page) names and labels every field as it appears", bool(forms)
   and "new MutationObserver" in forms and "window.LGForms" in forms)
ok("…a field with neither id nor name gets a name from what it is about", "if (!e.id && !e.name) e.name = `lg-${slug(what)}`" in forms)
ok("…a field with no label gets a real <label for> with the words beside it (aria-label, placeholder, title, column)",
   "l.htmlFor = e.id" in forms and 'getAttribute("placeholder")' in forms and 'querySelector("thead tr")' in forms)
ok("…the labels sit in one hidden holder at the end of the page: nothing is put beside a field",
   "box().append(l)" in forms and "e.before(" not in forms and "document.body.append(holder)" in forms)
ok("…a label whose field a page redrew away is removed (no label for nothing)", "const prune" in forms and "l.remove()" in forms)
ok("…fields of a form the browser posts itself are left alone (their names are the server's)", 'e.closest("form[action]")' in forms)
ok("…built with the DOM and the CSSOM only (no HTML strings)", "innerHTML" not in forms and "insertAdjacentHTML" not in forms)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
