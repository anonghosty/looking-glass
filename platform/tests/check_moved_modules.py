#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The parts moved out of app.py (2026-11-24) still fit together. No database writes, no network.
- every name a moved module reads from app.py (_A.name) exists on app.py once it has started: a typo or a name removed
  from app.py would only show when that code runs
- every name a moved module defines is still on app.py, the same object (other modules and checks use app.name)
- a moved module never reads its own file's namespace (globals(), __name__, __file__) where app.py's was meant, and
  never rebinds a global ('global'): its code behaves as it did inside app.py
- no risky call (subprocess, os.system, eval, pickle...) is reached through app.py (_A.x), where Bandit cannot see it
- each module is installed: its routes are on the Flask app with the endpoint names they had
Run: .venv/bin/python tests/check_moved_modules.py"""
import ast
import inspect
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ.setdefault("LG_QUIET", "1")
MOVED = ["analytics_api", "report_downloads", "infection_kb", "lookup_jobs", "card_notes", "name_definitions", "intel_match_api"]
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + (f"  [{str(info)[:300]}]" if info != "" and not cond else ""))
    if not cond:
        fails.append(label)


import app as A  # noqa: E402

for m in MOVED:
    path = os.path.join(HERE, f"{m}.py")
    ok(f"{m}.py is there", os.path.isfile(path))
    if not os.path.isfile(path):
        continue
    tree = ast.parse(open(path, encoding="utf-8").read())
    used = sorted({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "_A"})
    missing = [n for n in used if not hasattr(A, n)]
    ok(f"{m}: every name it reads from app.py exists there ({len(used)})", not missing, missing)
    mod = sys.modules.get(m)
    ok(f"{m}: imported and installed by app.py", mod is not None and getattr(mod, "_A", None) is A)
    defs = [n.name for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and n.name not in ("install", "_Recorder")]
    # a name app.py defines again further down keeps the later one, as it always did (the researchers' notes wrap
    # mp_resolve, issue_resolve and issues_resolve): then app.py holds a function of that name from a later module
    later = {d for d in defs if getattr(A, d, None) is not getattr(mod, d, object())
             and getattr(getattr(A, d, None), "__name__", "") == d and getattr(getattr(A, d, None), "__module__", "") in MOVED + ["app"]}
    not_kept = [d for d in defs if getattr(A, d, None) is not getattr(mod, d, object()) and d not in later]
    ok(f"{m}: app.py keeps every name it defines, the same object ({len(defs)}; defined again further down: {sorted(later) or 'none'})",
       not not_kept, not_kept)
    self_ref = [f"line {n.lineno}: {ast.unparse(n)[:40]}" for n in ast.walk(tree)
                if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("globals", "locals"))
                or (isinstance(n, ast.Name) and n.id in ("__name__", "__file__") and isinstance(n.ctx, ast.Load))]
    ok(f"{m}: never reads its own namespace where app.py's was meant", not self_ref, self_ref)
    rebinds = [f"line {n.lineno}: global {', '.join(n.names)}" for n in ast.walk(tree) if isinstance(n, ast.Global)
               and n.names != ["_A"]]
    ok(f"{m}: rebinds no global", not rebinds, rebinds)
    # Bandit (GitHub's static analysis) does not recognise a call reached through app.py (_A.subprocess.run, _A.os.system):
    # such calls are not allowed here, so nothing risky can hide from it in the moved code
    risky = [f"line {n.lineno}: {ast.unparse(n)[:50]}" for n in ast.walk(tree) if isinstance(n, ast.Attribute)
             and re.match(r"^_A\.(subprocess|pickle|marshal|shelve|eval|exec|compile|__import__|os\.(system|popen|exec\w*|spawn\w*)|"
                          r"tempfile\.mktemp|yaml\.load|random\.)", ast.unparse(n))]
    ok(f"{m}: reaches no risky call through app.py, where Bandit cannot see it", not risky, risky)
    views = {getattr(f, "__module__", "") for f in A.app.view_functions.values()}
    routes = [n.name for n in tree.body if isinstance(n, ast.FunctionDef)
              and any(ast.unparse(d).startswith("_R.") for d in n.decorator_list)]
    if routes:
        # a route the response cache wraps (response_cache.install) is that wrapper around the module's own function
        here = [r for r in routes if inspect.unwrap(A.app.view_functions.get(r) or (lambda: None)) is getattr(mod, r, None)]
        ok(f"{m}: its {len(routes)} route(s) are on the app under their own endpoint names", len(here) == len(routes) and m in views,
           sorted(set(routes) - set(here)))

print(f"\n{checks - len(fails)} of {checks} moved-module checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
