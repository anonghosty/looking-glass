#!/usr/bin/env python3
"""Older days kept a few minutes for analyst codes (recent_days.py; 2026-11-18: the same older day was loaded three times
in 13 s for one analyst code's page and counts). Made-up days, no database:
1. a day asked again while kept is not loaded again
2. two requests for the same day at once load it once
3. a new constituency or new stored data (another version): loaded again, never the old copy
4. after its time: loaded again
5. at most ANALYST_DAY_KEEP days kept, the oldest dropped; 0 keeps none (as before)
6. a day that could not be loaded is not kept (asked again later)
Run: .venv/bin/python tests/check_recent_days.py"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from recent_days import RecentDays  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class Loader:
    def __init__(self, secs=0.0):
        self.n, self.secs = 0, secs

    def __call__(self):
        self.n += 1
        time.sleep(self.secs)
        return {"day": "2026-11-13", "load": self.n}


print("1. Kept: not loaded again")
r, ld = RecentDays(keep=1, ttl=60), Loader()
a = r.get(("services", "2026-11-13"), (1, 0), ld)
b = r.get(("services", "2026-11-13"), (1, 0), ld)
ok("the page, its records and its counts share one load", a is b and ld.n == 1, f"{ld.n} loads")

print("2. Two requests at once")
r, ld, got = RecentDays(keep=1, ttl=60), Loader(.4), []
ts = [threading.Thread(target=lambda: got.append(r.get(("services", "2026-11-13"), (1, 0), ld))) for _ in range(3)]
for t in ts:
    t.start()
for t in ts:
    t.join()
ok("three requests at once: one load, the same day for all", ld.n == 1 and all(x is got[0] for x in got), f"{ld.n} loads")

print("3. Another version: loaded again")
r, ld = RecentDays(keep=1, ttl=60), Loader()
r.get(("services", "2026-11-13"), (1, 0), ld)
c = r.get(("services", "2026-11-13"), (2, 0), ld)
ok("a new constituency: a fresh load, never the old copy", ld.n == 2 and c["load"] == 2)
d = r.get(("services", "2026-11-13"), (2, 1), ld)
ok("new stored data: a fresh load", ld.n == 3 and d["load"] == 3)

print("4. After its time: loaded again")
r, ld = RecentDays(keep=1, ttl=.3), Loader()
r.get(("comms", "2026-11-13"), (1, 0), ld)
time.sleep(.4)
r.get(("comms", "2026-11-13"), (1, 0), ld)
ok("past ANALYST_DAY_KEEP_S: loaded again", ld.n == 2)

print("5. How many are kept")
r, ld = RecentDays(keep=1, ttl=60), Loader()
r.get(("services", "2026-11-12"), (1, 0), ld)
r.get(("services", "2026-11-13"), (1, 0), ld)
ok("keep 1: only the newest day held (memory stays one day)", list(r.days) == [("services", "2026-11-13")], str(list(r.days)))
r, ld = RecentDays(keep=0, ttl=60), Loader()
r.get(("services", "2026-11-13"), (1, 0), ld)
r.get(("services", "2026-11-13"), (1, 0), ld)
ok("keep 0: nothing kept, every request loads (as before)", ld.n == 2 and not r.days)

print("6. A day that could not be loaded")
r = RecentDays(keep=1, ttl=60)
ok("not kept, asked again later", r.get(("services", "2026-11-13"), (1, 0), lambda: None) is None and not r.days)

print("7. Never two days in memory together (a code spanning many days)")
held, peak = [0], [0]


class Held:
    def __init__(self):
        held[0] += 1; peak[0] = max(peak[0], held[0])

    def __del__(self):
        held[0] -= 1


r = RecentDays(keep=1, ttl=60)
for i in range(5):
    r.get(("services", f"2026-11-0{i + 1}"), (1, 0), Held)
ok("keep 1, five days read in turn: at most one day held at any moment", peak[0] == 1, f"at most {peak[0]} held")

print("8. The counts after a start (acode_warm.py) start only in the running service")
import acode_warm  # noqa: E402
import index_refresh  # noqa: E402
calls = []
api = type("Api", (), {"warm": lambda self, stop=None: calls.append(1) or 3})()
s = acode_warm.install(None, {"acodes": api})
ok("in a check or a tool (not the service): never started", not s["started"])
was, index_refresh.SERVING = index_refresh.SERVING, True
os.environ["ANALYST_WARM_DELAY_S"] = "0"
try:
    ok("ANALYST_WARM_DELAY_S 0: never started, even in the service", not acode_warm.install(None, {"acodes": api})["started"])
    os.environ["ANALYST_WARM_DELAY_S"] = "1"
    s = acode_warm.install(None, {"acodes": api})
    time.sleep(1.6)
    ok("in the service: started after its delay, once", s["started"] and calls == [1] and s["made"] == 3, f"{len(calls)} runs")
finally:
    index_refresh.SERVING = was
    os.environ.pop("ANALYST_WARM_DELAY_S", None)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
