#!/usr/bin/env python3
"""A constituency change is never overtaken by a day load already running (external review, 2026-11-12): the load that
began before the change is not stored; it loads again, so the day kept is the new constituency's. Both platforms'
stores. No database: the loads are stand-ins.  Run: .venv/bin/python tests/check_scope_reload.py"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


def race(store, label, day_cls):
    calls = []

    def fake_load(start):
        n = len(calls)
        calls.append(n)
        if n == 0:
            time.sleep(0.6)                      # the old constituency's load, still running when Settings change
        d = day_cls(start, [])
        d.marker = n
        d.per_source, d.arrived, d.sig = {}, {}, None
        return d
    saved = (store.days, store.loading, store.changes, store.__dict__.get("_load"))
    store.days, store.loading, store.changes = {}, {}, {}
    store._load = fake_load
    try:
        now = A.utcnow()
        t = threading.Thread(target=lambda: store.get(now))
        t.start()
        time.sleep(0.15)
        store.reset()                            # Settings saved: a new constituency
        t.join(10)
        kept = [d for d in store.days.values()]
        ok(f"{label}: the day kept is the one loaded after the change, not the load that was running",
           len(calls) == 2 and kept and kept[0].marker == 1, f"loads {calls}, kept {[d.marker for d in kept]}")
    finally:
        store.days, store.loading, store.changes = saved[0], saved[1], saved[2]
        if saved[3] is None:
            del store._load
        else:
            store._load = saved[3]


race(A.store, "map platform", A.Day)
import services  # noqa: E402
race(A.svc["store"], "services platform", services.Day if hasattr(services, "Day") else A.Day)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
