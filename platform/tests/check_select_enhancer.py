#!/usr/bin/env python3
"""Every page whose drop-downs ask for the Looking Glass look (class "lg-enhance") loads the script that draws it
(static/js/lg-select.js). 2026-11-20: the advisory page's two new drop-downs (the PDF's look, the name on its pages)
showed as plain white browser menus, because advisory.html never loaded lg-select.js (spotted by the user).

A page asks for it when its template, a template it extends or includes, or a page script it loads has "lg-enhance".
It is drawn when the same page (itself, through what it extends or includes) loads js/lg-select.js.
Run from the platform's folder: python3 tests/check_select_enhancer.py (LG_HELD_DIR: held .new files).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = os.environ.get("LG_HELD_DIR", "")
TDIR, JDIR = os.path.join(HERE, "templates"), os.path.join(HERE, "static", "js")
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:300]}")


def read(path):
    n = os.path.basename(path)
    p = os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else path
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


def page_sources(name, seen=None):
    """The template and everything it extends or includes, recursively."""
    seen = seen if seen is not None else set()
    if name in seen:
        return []
    seen.add(name)
    src = read(os.path.join(TDIR, name))
    out = [src]
    for ref in re.findall(r"""\{%-?\s*(?:extends|include)\s+["']([^"']+)["']""", src):
        out += page_sources(ref, seen)
    return out


def scripts_of(srcs):
    return {m for s in srcs for m in re.findall(r"""filename=['"]js/([\w.-]+\.js)['"]""", s)}


print("Every page that asks for the Looking Glass drop-downs loads lg-select.js")
pages = sorted(f for f in os.listdir(TDIR) if f.endswith(".html") and not f.startswith("_"))
asking = []
for p in pages:
    srcs = page_sources(p)
    js = scripts_of(srcs)
    asks = any("lg-enhance" in s for s in srcs) or any("lg-enhance" in read(os.path.join(JDIR, j)) for j in js if j != "lg-select.js")
    if not asks:
        continue
    asking.append(p)
    ok(f"{p}: loads lg-select.js", "lg-select.js" in js, sorted(js))
ok("the pages that ask for it were found (the check reads the templates and their scripts)", len(asking) >= 6, asking)
ok("the advisory page is among them (its look and name drop-downs, 2026-11-20)", "advisory.html" in asking, asking)
css = read(os.path.join(HERE, "static", "css", "app.css"))
ok("the drop-downs' styles (.lgs) are in app.css, which every page loads", ".lgs {" in css and ".lgs-btn" in css)

print("No drop-down stays the browser's own list (the user, 2026-11-20: \"Yes, all 14\")")
# a select written in a template, or made by a page script with el("select", …) / createElement("select"), asks for
# lg-enhance; NATIVE lists any that must stay the browser's (none today)
NATIVE = set()
plain = []
for f in sorted(os.listdir(TDIR)):
    if f.endswith(".html"):
        for m in re.finditer(r"<select\b[^>]*>", read(os.path.join(TDIR, f))):
            if "lg-enhance" not in m.group(0) and f not in NATIVE:
                plain.append(f"{f}: {m.group(0)[:70]}")
for f in sorted(os.listdir(JDIR)):
    if not f.endswith(".js") or f == "lg-select.js":
        continue
    src = read(os.path.join(JDIR, f))
    # the rest of the line too: a class given in the next statement on that line (advisory.js: s.className = …)
    for m in re.finditer(r"""(?:el\(\s*["']select["'][^)]*\)|createElement\(\s*["']select["']\s*\))[^\n]*""", src):
        if "lg-enhance" not in m.group(0) and f"{f}" not in NATIVE:
            plain.append(f"{f}: {m.group(0)[:80]}")
ok("every select in the templates and page scripts asks for the Looking Glass dropdown", not plain, plain)
ls = read(os.path.join(JDIR, "lg-select.js"))
ok("…an option's explanation (title) stays, and so does the select's own tooltip",
   "if (o.title) b.title = o.title;" in ls and "ui.btn.title = sel.title ||" in ls)
ok("…code that focuses a select (a picker asking for a choice) reaches the visible button",
   'sel.addEventListener("focus", () => btn.focus());' in ls)
ok("…value and selectedIndex set by code are both followed", 'for (const prop of ["value", "selectedIndex"])' in ls)
ok("…long names wrap, never cut with \"…\" (the full-text rule covers .lgs-value and .lgs-opt span)",
   re.search(r"\.lgs-value,\s*\.lgs-opt span[^{]*\{\s*white-space: normal", css.replace("\n", " ")) is not None
   or (".lgs-value" in css and "white-space: normal; overflow: visible; text-overflow: clip" in css))
ok("…the people picker's red \"needs a person\" border reaches the new button",
   ".pp-pick.need .lgs-pp-sel .lgs-btn" in css)
ok("…the sizes the plain lists had carry over (organisation picker, report filter, region match, severity)",
   all(r in css for r in (".lgs-av-netsel { max-width: 640px; }", ".lgs-cb-filter-sel", ".st-matchcell .lgs-st-pick", "#sevTable .lgs-sev-pick")))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
