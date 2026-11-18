#!/usr/bin/env python3
"""Drill-down counts worked out behind the page (index_refresh.py; the user, 2026-11-17: the Definitions page and the
combination filters made people wait 22 s after a start and 3-6 s after each change or hourly expiry, all of it
Python). Made-up data only, no database:
1. counts that are current are served without counting
2. with no counts yet, two requests at once count ONCE and both get the answer
3. in the service (background mode), out-of-date counts are served at once while one recount runs behind the page
4. in the checks (background off), out-of-date counts are counted at once, as before
5. the Executive portal's report day shares the report day's counts (no second 2.4 s count of the same day)
Run: .venv/bin/python tests/check_index_refresh.py"""
import os
import sys
import threading
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import index_refresh as R  # noqa: E402
import services_intel as SI  # noqa: E402

checks, fails = 0, []


def settle(gate, most=10.0):
    """Wait until the gate's background counts have finished (a slow or paused machine: not a fixed sleep)."""
    end = time.time() + most
    while time.time() < end:
        with gate.lock:
            if not gate.busy:
                return
        time.sleep(0.05)


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class Counter:
    """A stand-in index: counting takes `secs`; the stored answer is kept like the real ones."""
    def __init__(self, secs):
        self.secs, self.calls, self.stored = secs, 0, None

    def build(self, cached_only=False):
        if cached_only:
            return self.stored
        self.calls += 1
        time.sleep(self.secs)
        self.stored = f"count #{self.calls}"
        return self.stored


print("1. Current counts")
g, c = R.Gate("t1"), Counter(0.3)
ok("served as they are, nothing counted", g.serve("report", "current", "old", c.build) == "current" and c.calls == 0)

print("2. No counts yet: two requests at once")
g, c = R.Gate("t2"), Counter(0.5)
got = []
ts = [threading.Thread(target=lambda: got.append(g.serve("report", None, None, c.build))) for _ in range(2)]
for t in ts:
    t.start()
for t in ts:
    t.join()
ok("counted once, both get the answer", c.calls == 1 and got == ["count #1", "count #1"], f"{c.calls} counts, {got}")

print("3. In the service: out of date")
g, c = R.Gate("t3"), Counter(0.8)
g.background = True
t = time.perf_counter(); first = g.serve("report", None, "earlier counts", c.build); dt = time.perf_counter() - t
ok("the earlier counts at once (no wait for the recount)", first == "earlier counts" and dt < 0.1, f"{dt * 1000:.0f} ms")
second = g.serve("report", None, "earlier counts", c.build)
ok("... a second request meanwhile does not start another recount", second == "earlier counts")
settle(g)
ok("... one recount ran behind the page and its answer is kept", c.calls == 1 and c.stored == "count #1", f"{c.calls} recounts")

print("4. In the checks: out of date")
g, c = R.Gate("t4"), Counter(0.2)
ok("counted at once, as before", g.serve("report", None, "earlier counts", c.build) == "count #1" and c.calls == 1)

print("5. The Executive portal's day shares the report day's counts")
D = datetime(2026, 11, 16, tzinfo=timezone.utc)


class Day:
    def __init__(self, start):
        self.start, self.events, self.serial = start, [{"ip": "192.0.2.1", "report": "scan_http", "issues": [], "_t": (start + timedelta(hours=2)).timestamp()}], 1


class Store:
    def __init__(self, days):
        self.days = {d.start: d for d in days}

    def get(self, _t):
        return None


class Patterns:
    def fields_for(self, base):
        return []

    def items(self, base, e, fields):
        return []


sv = SI.ServicesIntel({"svc_store": Store([Day(D - timedelta(days=1)), Day(D)]), "comms_store": Store([Day(D - timedelta(days=1)), Day(D)]),
                       "patterns": Patterns(), "replay_now": lambda: D + timedelta(hours=8), "labels": lambda: {}})
rep = sv.index()
ok("the report day's own date gives the very same counts (counted once)", sv.index("2026-11-16") is rep and sv.gate.runs == 1, f"{sv.gate.runs} counts")
ok("... another day still has its own", sv.index("2026-11-15") is not rep and sv.gate.runs == 2)
ok("... and every day in memory its own", sv.index("memory") is not rep and sv.gate.runs == 3)

print("6. A count that fails never takes the page down")


class Broken(Counter):
    def __init__(self):
        super().__init__(0.05)
        self.broken = True

    def build(self, cached_only=False):
        if cached_only:
            return self.stored
        self.calls += 1
        if self.broken:
            raise ValueError("a record no rule expected")
        self.stored = f"count #{self.calls}"
        return self.stored


import logging  # noqa: E402
logging.getLogger("looking-glass").disabled = True      # the expected tracebacks, not printed here
g, b = R.Gate("t6"), Broken()
g.background = True
got = g.serve("report", None, "earlier counts", b.build)
settle(g)
ok("in the service: the earlier counts at once, the failure kept for the task monitor",
   got == "earlier counts" and g.failures == 1 and g.last_error and "no rule expected" in g.last_error[2], str(g.last_error))
ok("... and not tried again straight away (no failing loop)", g.serve("report", None, "earlier counts", b.build) == "earlier counts"
   and (settle(g) or b.calls == 1), f"{b.calls} tries")
import system_alerts as SA  # noqa: E402
ok("... an alert for the administrators' bell and the task monitor", any("could not be updated" in a["title"] and a["problem"]
                                                                      for a in SA.count_alerts()))
g.failed_at["report"] -= R.RETRY_SECONDS + 1
b.broken = False
g.serve("report", None, "earlier counts", b.build)
settle(g)
ok("... tried again after the pause, the new counts kept and the alert gone",
   b.stored == "count #2" and g.last_error is None and not [a for a in SA.count_alerts() if a["key"].startswith("counts-failed:t6:")],
   f"{b.calls} tries")
g, b = R.Gate("t7"), Broken()
ok("in the checks, with earlier counts: those, no error", g.serve("report", None, "earlier counts", b.build) == "earlier counts")
g, b = R.Gate("t8"), Broken()
try:
    g.serve("report", None, None, b.build)
    raised = False
except ValueError:
    raised = True
ok("with no counts at all: the error reaches the request that counted (as before)", raised)
logging.getLogger("looking-glass").disabled = False
for gate in list(R.GATES):                       # the made-up gates are not the platform's
    if gate.name.startswith("t"):
        R.GATES.remove(gate)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
