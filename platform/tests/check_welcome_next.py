#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Right after signing in (/welcome, static/js/welcome.js; the held copy $LG_HELD_DIR/welcome.js.new when there is one):
node runs the page on a stand-in browser. It opens the page the sign-in was for, and only a path on this site: a next
of //host, a full URL, javascript:, a backslash or a space in it opens the Overview instead. With motion it dives in
(the loading screen opens the page after the intro); with "reduce motion" (or no loading screen) it goes straight
there, without the dive. The arriving mark of an earlier page is cleared first.
Run: .venv/bin/python tests/check_welcome_next.py"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import page_harness as H  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


if not H.NODE:
    print("SKIPPED: no node to run the page with"); sys.exit(77)

SRC = H.page_src("welcome.js")
JS = r"""
const C = JSON.parse(process.argv[1]); const R = { replaced: [], went: [], busy: [], timers: [], removed: [] };
globalThis.sessionStorage = { removeItem: (k) => R.removed.push(k) };
window.matchMedia = (q) => ({ matches: C.reduce && /prefers-reduced-motion: reduce/.test(q), addEventListener() {} });
globalThis.requestAnimationFrame = (f) => f();
globalThis.setTimeout = (f, ms) => { R.timers.push(ms); f(); return 0; };
location.replace = (u) => R.replaced.push(u);
if (C.loader) window.LGLoader = { busy: (t) => R.busy.push(t), go: (u, t) => R.went.push([u, t]), ready() {} }; else delete window.LGLoader;
if (C.next !== null) document.body.dataset.next = C.next;
document.readyState = "complete";
""" + SRC + r"""
R.diving = document.body.classList.contains("diving");
console.log(JSON.stringify(R));
"""


def run(next_, reduce=False, loader=True):
    out, raw = H.run(JS, {"next": next_, "reduce": reduce, "loader": loader})
    return out or {"error": raw[-300:]}


print("Only a path on this site")
SAFE = ["/findings?state=open#f12", "/overview", "/combinations/LG-C-0000ABCD", "/%2F%2Fevil.example"]
UNSAFE = ["//evil.example/x", "https://evil.example/", "javascript:alert(1)", "JavaScript:alert(1)", "/\\evil.example", "\\\\evil.example",
          "/ok path", "/\t/evil.example", "/\n/evil.example", " /overview", "evil.example", "", "data:text/html,x", "///evil.example"]
for n in SAFE:
    r = run(n)
    ok(f"{n!r}: opened after the intro", r.get("went") == [[n, "Opening Looking Glass"]] and r.get("replaced") == [], str(r))
for n in UNSAFE:
    r = run(n)
    ok(f"{n!r}: the Overview instead", r.get("went") == [["/overview", "Opening Looking Glass"]] and r.get("replaced") == [], str(r))
r = run(None)
ok("no next at all: the Overview", r.get("went") == [["/overview", "Opening Looking Glass"]], str(r))

print("The intro, and without motion")
r = run("/findings")
ok("with motion: it dives in, the logo on the black, then the page opens (about 2 s and 3.3 s)",
   r.get("diving") is True and r.get("busy") == ["Opening Looking Glass"] and 2000 <= min(t for t in r.get("timers", [0]) if t > 1000) < 3300
   and max(r.get("timers") or [0]) <= 4000, str(r))
ok("...an earlier page's arriving mark is cleared first", r.get("removed") == ["lg.arrive"], str(r.get("removed")))
r = run("/findings", reduce=True)
ok("reduce motion: straight there, no dive, no wait", r.get("replaced") == ["/findings"] and r.get("went") == [] and not r.get("diving")
   and r.get("timers") == [], str(r))
r = run("//evil.example", reduce=True)
ok("...and still only a path on this site", r.get("replaced") == ["/overview"], str(r))
r = run("/findings", loader=False)
ok("no loading screen on the page: straight there", r.get("replaced") == ["/findings"] and not r.get("diving"), str(r))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
