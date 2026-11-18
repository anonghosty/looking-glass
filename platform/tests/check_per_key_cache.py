#!/usr/bin/env python3
"""The analyst codes' device counts on the Findings page (acodes.PerKeyCache; 2026-11-18 browser check: one lock for
every code made a 16 s count hold every other code's count, and their placeholders spun for over 30 s). Made-up
computations, no database:
1. a slow key never makes another key wait
2. the same key asked twice at once is worked out once, and both get the answer
3. an answer is kept for its time, then worked out again
4. at most `size` answers kept, the oldest dropped
Run: .venv/bin/python tests/check_per_key_cache.py"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from acodes import PerKeyCache  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. A slow key never makes another key wait")
c = PerKeyCache(ttl=60, size=8)
done = {}


def slow():
    time.sleep(1.5)
    return "slow answer"


t = threading.Thread(target=lambda: done.setdefault("slow", c.get("LG-A-SLOW", slow)))
t.start()
time.sleep(.2)                                             # the slow one holds its own lock now
t0 = time.perf_counter()
fast = c.get("LG-A-FAST", lambda: "fast answer")
dt = time.perf_counter() - t0
ok("the fast key answers at once while the slow one is still counting", fast == "fast answer" and dt < .3, f"{dt * 1000:.0f} ms")
t.join()
ok("... and the slow one gets its own answer", done.get("slow") == "slow answer")

print("2. The same key asked twice at once is worked out once")
c, calls, got = PerKeyCache(ttl=60, size=8), [], []


def counted():
    calls.append(1)
    time.sleep(.5)
    return "once"


ts = [threading.Thread(target=lambda: got.append(c.get("LG-A-SAME", counted))) for _ in range(3)]
for x in ts:
    x.start()
for x in ts:
    x.join()
ok("three requests at once: one count, three answers", len(calls) == 1 and got == ["once"] * 3, f"{len(calls)} counts")

print("3. Kept for its time, then worked out again")
c, n = PerKeyCache(ttl=.3, size=8), []
c.get("K", lambda: n.append(1) or len(n))
c.get("K", lambda: n.append(1) or len(n))
ok("within its time: not worked out again", len(n) == 1)
time.sleep(.4)
ok("after it: worked out again", c.get("K", lambda: n.append(1) or len(n)) == 2)

print("4. At most `size` answers kept")
c = PerKeyCache(ttl=60, size=3)
for i in range(5):
    c.get(f"K{i}", lambda i=i: i)
    time.sleep(.01)
ok("the oldest dropped, the newest kept", sorted(c.cache) == ["K2", "K3", "K4"], str(sorted(c.cache)))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
