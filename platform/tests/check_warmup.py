#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Warm-up (warmup.py): the Definitions page's heavy summaries and the first views are worked out in the background
whenever the copies of the days in memory change, and only then; a job that fails is logged, the others still run,
and it is tried again at the next change. No database needed.  Run: .venv/bin/python tests/check_warmup.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import warmup as W  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


class Day:
    def __init__(self, serial, n):
        self.serial, self.events = serial, [0] * n


class Store:
    def __init__(self):
        self.days = {}


class Log:
    def __init__(self):
        self.lines = []

    def warning(self, *a):
        self.lines.append(a[0] % a[1:] if len(a) > 1 else a[0])

    def exception(self, *a):
        self.lines.append(a[0])


a, b, ran = Store(), Store(), []
log = Log()


def boom():
    ran.append("boom")
    raise RuntimeError("no data")


ctx = {"stores": lambda: [a, b], "logger": log, "start": False,
       "jobs": [("first", lambda: ran.append("first")), ("broken", boom), ("last", lambda: ran.append("last"))]}
state = W.install(ctx)
ok("not started when asked not to (scripts, checks)", state["runs"] == 0)
ok("nothing in memory: nothing to warm", W.run_once(ctx, state) is False and not ran)
a.days["2026-11-14"] = Day(1, 10)
ok("a day appears: every job runs, in order", W.run_once(ctx, state) is True and ran == ["first", "boom", "last"], str(ran))
ok("…a failing job is logged and the others still run", state["failed"] == [("broken", "RuntimeError")] and any("broken failed" in x for x in log.lines))
ran.clear()
ok("the same copies of the days: nothing runs again", W.run_once(ctx, state) is False and not ran)
a.days["2026-11-14"] = Day(2, 10)
ok("a day reloaded (new copy): the jobs run again", W.run_once(ctx, state) is True and ran[0] == "first")
ran.clear()
b.days["2026-11-14"] = Day(3, 5)
ok("the other platform's day changes: the jobs run again", W.run_once(ctx, state) is True and ran)
ok("the key names every loaded day of both platforms", len(W.days_key([a, b])) == 2)
ok("the time it took is kept (Task monitor)", "took" in state and state["runs"] == 3)
# a day waiting for its reports is reloaded every minute, empty each time (2026-11-26: a warm-up every minute)
a.days["2026-11-15"] = Day(10, 0)
W.run_once(ctx, state); ran.clear(); runs0 = state["runs"]
for s_ in (11, 12, 13):
    a.days["2026-11-15"] = Day(s_, 0)
    W.run_once(ctx, state)
ok("an EMPTY day loaded again and again: no warm-up for it (nothing changed)", state["runs"] == runs0 and not ran, str(ran))
a.days["2026-11-15"] = Day(14, 7)
ok("…its reports arrive (rows): the jobs run", W.run_once(ctx, state) is True and ran)
ran.clear()
a.days["2026-11-15"] = Day(15, 7)
ok("…a day WITH rows reloaded (the hourly refresh) still warms, as before", W.run_once(ctx, state) is True and ran)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
