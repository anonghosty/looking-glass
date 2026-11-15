#!/usr/bin/env python3
"""Looking Glass runs in exactly one gunicorn worker (review 2026-11-15): sessions, sign-in limits and the days in memory
live in that process, so more workers would sign people out at random. gunicorn.conf.py refuses to start otherwise, and
the service runs --workers 1. Touches no file or service.
Run: .venv/bin/python tests/check_single_worker.py"""
import os, runpy, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class _Log:
    def __init__(self): self.lines = []
    def error(self, m, *a): self.lines.append(m % a if a else m)


class _Server:
    def __init__(self, workers):
        self.cfg = type("C", (), {"workers": workers})(); self.log = _Log()


conf = runpy.run_path(os.path.join(ROOT, "gunicorn.conf.py"))
hook = conf.get("on_starting")
print("One worker process")
ok("gunicorn.conf.py has an on_starting check", callable(hook))
if callable(hook):
    for n in (2, 4):
        s = _Server(n)
        try:
            hook(s); stopped = False
        except SystemExit:
            stopped = True
        ok(f"--workers {n}: refuses to start, and says why", stopped and any("exactly one worker" in l for l in s.log.lines))
    s = _Server(1)
    try:
        hook(s); started = True
    except SystemExit:
        started = False
    ok("--workers 1: starts", started and not s.log.lines)
for unit in ("deploy/looking-glass.service.template",):
    text = open(os.path.join(ROOT, unit), encoding="utf-8").read()
    ok(f"{unit} runs --workers 1", "--workers 1 " in text)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
