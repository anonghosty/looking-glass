# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The two suites stay apart (2026-11-26): an installation runs its own checks, the maintainer runs everything.

1. tests/maintainer_rows.txt names only test files that exist and are rows of tests/run_all_checks.sh, each once.
2. No installation check needs what an installation does not have without saying so: a test that runs a page's script
   under Node (page_harness, LG_NODE) or reads PDFs with pypdfium2 is either a maintainer row, or its Node / pypdfium2
   part is the maintainer's (page_harness.no_node, or LG_SUITE=all: a failure there, one plain line on an installation).
3. A test never prints SKIPPED and then passes: a skipped part either exits 77 (counted) or is a maintainer's part.
4. tests/run_all_checks.sh refuses an unknown LG_SUITE; tests/maintainer_checks.sh runs LG_SUITE=all.
No database, no network. Run: .venv/bin/python tests/check_suite_split.py"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


suite = open(os.path.join(HERE, "run_all_checks.sh"), encoding="utf-8").read()
rows = re.findall(r"tests/([\w.]+\.(?:py|sh))", suite)
listed = [ln.split("#", 1)[0].strip() for ln in open(os.path.join(HERE, "maintainer_rows.txt"), encoding="utf-8")]
listed = [x for x in listed if x]
print("1. the maintainer's list")
ok("every listed file exists", all(os.path.isfile(os.path.join(HERE, f)) for f in listed),
   [f for f in listed if not os.path.isfile(os.path.join(HERE, f))])
ok("every listed file is a row of the suite", all(f in rows for f in listed), [f for f in listed if f not in rows])
ok("each is listed once", len(listed) == len(set(listed)), sorted({f for f in listed if listed.count(f) > 1}))
ok(f"the list is not empty, and not the whole suite ({len(listed)} of {len(set(rows))} test files)", 0 < len(listed) < len(set(rows)))

print("2. installation checks say when a part needs Node or pypdfium2")
loose = []
for f in sorted(set(rows) - set(listed)):
    p = os.path.join(HERE, f)
    if not f.endswith(".py") or not os.path.isfile(p):
        continue
    s = open(p, encoding="utf-8", errors="replace").read()
    needs_node = "page_harness" in s or "LG_NODE" in s
    needs_pdf = "pypdfium2" in s
    guarded = "no_node(" in s or "LG_SUITE" in s
    # a file that only finds Node to run nothing with it (page_harness for its file paths) passes this too, when it
    # never calls PH.run / node itself
    runs_node = re.search(r"\bPH\.run\(|\bH\.run\(|subprocess\.run\(\s*\[\s*node\b|\[node,", s)
    if (needs_node and runs_node or needs_pdf and re.search(r"import pypdfium2|pypdfium2\.", s)) and not guarded:
        loose.append(f)
ok("every installation check that runs Node or pypdfium2 keeps that part for the maintainer", not loose, loose)

print("3. no part is skipped in silence")
silent = []
for f in sorted(set(rows)):
    p = os.path.join(HERE, f)
    if not f.endswith(".py") or not os.path.isfile(p):
        continue
    L = open(p, encoding="utf-8", errors="replace").read().splitlines()
    for i, ln in enumerate(L):
        if re.search(r"print\([^)]*\bSKIP", ln):
            after = " ".join(L[i:i + 4])
            if not re.search(r"exit\(77\)|return 77|SystemExit\(77\)|_exit\(77\)|done\(77\)", after):
                silent.append(f"{f}:{i + 1}")
ok("every printed SKIPPED is followed by exit 77 (so the suite counts it)", not silent, silent)

print("4. the runner")
r = subprocess.run(["bash", os.path.join(HERE, "run_all_checks.sh")], cwd=PF, capture_output=True, text=True, timeout=120,
                   env={**os.environ, "LG_SUITE": "everything-please"})
ok("an unknown LG_SUITE is refused before any check runs", r.returncode == 2 and "LG_SUITE must be" in r.stdout, r.stdout[-200:])
m = open(os.path.join(HERE, "maintainer_checks.sh"), encoding="utf-8").read()
ok("tests/maintainer_checks.sh runs the whole suite (LG_SUITE=all)", "LG_SUITE=all" in m and "run_all_checks.sh" in m)
ok("the suite's default is the installation's checks", 'LG_SUITE="${LG_SUITE:-installation}"' in suite)

print(f"\n{checks - len(fails)} of {checks} passed")
sys.exit(1 if fails else 0)
