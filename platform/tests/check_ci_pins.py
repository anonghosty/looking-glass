#!/usr/bin/env python3
"""The GitHub checks (.github/workflows) stay hardened (review follow-up item 7, 2026-11-15): every action pinned to a
full commit, the MongoDB image pinned by digest with a password made in the run (none stored), a database job whose
skips count as failures, and pip-audit pinned. Reads the workflow files beside platform/ (a release) or in
tools/release_root/ (the development tree). Run: .venv/bin/python tests/check_ci_pins.py"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


wf_dir = next((d for d in (os.path.join(HERE, "..", ".github", "workflows"), os.path.join(HERE, "tools", "release_root", ".github", "workflows"))
               if os.path.isdir(d)), None)
if not wf_dir:
    print("no .github/workflows here: skipped"); sys.exit(77)
files = sorted(glob.glob(os.path.join(wf_dir, "*.yml")))
src = {os.path.basename(f): open(f, encoding="utf-8").read() for f in files}
ok("the checks workflow is there", "checks.yml" in src)
uses = [(f, u) for f, s in src.items() for u in re.findall(r"uses:\s*([^\s#]+)", s)]
loose = [f"{f}: {u}" for f, u in uses if not re.fullmatch(r"[\w.-]+/[\w.-]+(/[\w./-]+)?@[0-9a-f]{40}", u)]
ok("every action is pinned to a full commit (a moved tag cannot run new code)", uses and not loose, "; ".join(loose))
s = src.get("checks.yml", "")
ok("MongoDB runs pinned by its image digest", re.search(r"mongo@sha256:[0-9a-f]{64}", s) is not None)
ok("its administrator password is made in the run and masked (none stored)", "openssl rand" in s and "::add-mask::" in s
   and not re.search(r"MONGO_INITDB_ROOT_PASSWORD=(?!\"\$PW\")\S+", s))
ok("the database checks treat a skip as a failure", "if ! python tests/$t.py" in s and "test_new_collections" in s)
ok("libraries are checked for known vulnerabilities, with a pinned pip-audit", re.search(r"pip-audit==\d+\.\d+\.\d+", s) is not None
   and "pip-audit -r platform/requirements.txt -r database/requirements.txt" in s)
ok("the workflow token stays read-only", re.search(r"^permissions:\s*\n\s+contents:\s*read\s*$", s, re.M) is not None)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
