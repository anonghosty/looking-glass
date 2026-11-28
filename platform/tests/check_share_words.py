#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shares in words never mislead, the same on every page, PDF and CSV (the user, 2026-11-26: "check every chart,
everything, every grain of sand: nothing gets missing on the whole platform"; a sector with 4 of 43,281 events read
"0%"). Bend law f proves the rule; this runs the real code on the edges:
  1. shares.pct / shares.of: a part with records is never "0%", a part of the whole never "100%", rounded half up
  2. the browser's LGShare (static/js/loader.js) gives the same words as shares.py for the same share (node)
  3. no module or page works out a share's words by itself any more (the old ways that read "0%" or "100%"):
     `:.0%}`, `:.1%}`, `round(100 * x)` + "%", `Math.round(100 * x)` + "%", `(100 * x).toFixed(d)` + "%"
LG_HELD_DIR: the held page files of the next release (default: static/js)."""
import glob
import json
import os
import re
import shutil
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import shares  # noqa: E402

ok = bad = 0


def check(cond, what):
    global ok, bad
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    ok, bad = ok + bool(cond), bad + (not cond)


CASES = [(4, 43281, 0, "<1%"), (4, 43281, 1, "<0.1%"), (43277, 43281, 0, ">99%"), (43277, 43281, 1, ">99.9%"),
         (0, 10, 0, "0%"), (10, 10, 0, "100%"), (10, 10, 1, "100.0%"), (1, 200, 0, "1%"), (1, 8, 0, "13%"),
         (1, 8, 1, "12.5%"), (1, 3, 1, "33.3%"), (2, 3, 0, "67%"), (199, 200, 0, ">99%"), (1, 2000, 1, "0.1%"),
         (0, 0, 0, "0%")]
print("== 1. shares.py")
for p, t, d, want in CASES:
    check(shares.of(p, t, d) == want, f"of({p}, {t}, {d}) = {want!r} (got {shares.of(p, t, d)!r})")
for x, d, want in [(0.0001, 0, "<1%"), (0.9999, 0, ">99%"), (0.005, 0, "1%"), (0.0004, 1, "<0.1%"), (1, 0, "100%"), (0, 1, "0.0%")]:
    check(shares.pct(x, d) == want, f"pct({x}, {d}) = {want!r} (got {shares.pct(x, d)!r})")
rows = [{"count": 5}, {"count": 3}]
check(shares.other(rows, 10) == 2 and shares.other(rows, 7) == 0, "other(): the total less the rows shown, never below 0")
check(shares.cut(8, 23, "networks") == "Top 8 of 23 networks" and shares.cut(8, 8) == "", "cut(): 'Top 8 of 23 networks'; '' when all are shown")

held = os.environ.get("LG_HELD_DIR")
loader = os.path.join(held, "loader.js.new") if held and os.path.exists(os.path.join(held, "loader.js.new")) else os.path.join(ROOT, "static/js/loader.js")
print("== 2. the browser's LGShare agrees (" + os.path.basename(loader) + ")")
# found as every page check finds it (tests/page_harness.py): LG_NODE, then PATH, then the project's own ~/lg-node copy
# (2026-11-26: the local suite has no LG_NODE, and this check alone did not look in ~/lg-node)
node = next((c for c in (os.environ.get("LG_NODE"), shutil.which("node"),
                         *sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))) if c and os.path.exists(c)), None)
src = open(loader).read()
if "window.LGShare" not in src:
    check(False, "loader.js defines window.LGShare")
elif not node:
    # the browser's half runs under Node: a maintainer's part (tests/page_harness.py); it fails in LG_SUITE=all
    if os.environ.get("LG_SUITE") == "all":
        check(False, "node is there to run loader.js's LGShare (LG_NODE)")
    else:
        print("  (its page-script part runs under Node: a maintainer's check, run by LG_SUITE=all; not part of an installation's checks)")
else:
    a = src.index("  // rounded half up, the same text as shares.py")
    b = src.index("\n  };", src.index("window.LGShare = {")) + 5
    prog = ("const window = {};\n" + src[a:b] + "\nconst q = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
            "process.stdout.write(JSON.stringify(q.map(([k, x, y, d]) => k === 'of' ? window.LGShare.of(x, y, d) : window.LGShare.pct(x, d))));")
    import random
    rng = random.Random(26)
    qs = [["of", p, t, d] for p, t, d, _ in CASES] + [["of", p, t, d] for t in (rng.randint(1, 90000) for _ in range(400))
                                                      for p, d in [(rng.randint(0, t), rng.choice([0, 1]))]]
    qs += [["pct", rng.random() ** 3, 0, rng.choice([0, 1])] for _ in range(400)]
    js = json.loads(subprocess.run([node, "-e", prog], input=json.dumps(qs), capture_output=True, text=True, check=True).stdout)
    py = [shares.of(x, y, d) if k == "of" else shares.pct(x, d) for k, x, y, d in qs]
    diff = [(q, p, j) for q, p, j in zip(qs, py, js) if p != j]
    check(not diff, f"{len(qs)} shares: the page's words = the PDF's words" + (f"; e.g. {diff[:3]}" if diff else ""))

print("== 3. no share worked out on its own")
PY_BAD = [re.compile(r"\{[^{}]*:\.\d?%\}"), re.compile(r"round\(\s*100\s*\*[^)]*\)\s*\}?\s*%")]
JS_BAD = [re.compile(r"Math\.round\(\s*(?:100\s*\*|[^()]*\*\s*100\b)[^;]*?[`'\"]?\s*%"),
          re.compile(r"\(\s*100\s*\*[^()]*\)\.toFixed\(\d\)\s*\}?\s*[`'\"]?\s*%"),
          re.compile(r"\*\s*100\)\.toFixed\(\d\)\s*\}?\s*[`'\"]?\s*%")]
found = []
for f in sorted(glob.glob(os.path.join(ROOT, "*.py"))):
    if os.path.basename(f) == "shares.py":
        continue
    for n, line in enumerate(open(f, encoding="utf-8"), 1):
        if any(r.search(line) for r in PY_BAD) and "noqa: share" not in line:
            found.append(f"{os.path.basename(f)}:{n}: {line.strip()[:100]}")
js_dir = held if held else os.path.join(ROOT, "static/js")
js_files = sorted(glob.glob(os.path.join(js_dir, "*.js.new"))) if held else sorted(glob.glob(os.path.join(js_dir, "*.js")))
if held:   # a page file without a held copy ships as it is
    have = {os.path.basename(f)[:-4] for f in js_files}
    js_files += [f for f in sorted(glob.glob(os.path.join(ROOT, "static/js/*.js"))) if os.path.basename(f) not in have]
for f in js_files:
    for n, line in enumerate(open(f, encoding="utf-8"), 1):
        if any(r.search(line) for r in JS_BAD) and "noqa: share" not in line:
            found.append(f"{os.path.basename(f)}:{n}: {line.strip()[:100]}")
check(not found, f"every share through shares.py / LGShare ({len(found)} places work it out themselves)")
for x in found[:40]:
    print(f"         {x}")
print(f"\n{ok}/{ok + bad} checks passed")
sys.exit(1 if bad else 0)
