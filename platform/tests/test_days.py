"""Check which day the replay uses, and how each collection behaves for several days (read-only).

For each test day it loads every registered collection the same way the server does and prints the
row counts, so you can see that collections without rows for that day are simply absent.
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import needs_db  # noqa: E402
needs_db.require()   # no reachable MongoDB (a fresh clone, CI): skipped, not crashed
import app as tm  # noqa: E402

now = tm.utcnow()
rn = tm.replay_now()
print(f"real now (UTC):   {now:%Y-%m-%d %H:%M:%S}")
print(f"replay clock:     {rn:%Y-%m-%d %H:%M:%S}  -> replay day {tm.day_start(rn).date()} (offset {tm.OFFSET_HOURS:g} h)")
print(f"after midnight the replay day becomes {tm.day_start(rn + timedelta(days=1)).date()}\n")

srcs = tm.registry.get()
for back in (2, 1, 0):
    day = tm.day_start(now) - timedelta(days=back)
    d = tm.store._load(day)
    label = {2: "day before yesterday", 1: "yesterday (what plays today)", 0: "today (plays tomorrow)"}[back]
    print(f"{day.date()}  {label}: {len(d.events):,} events from {len(d.per_source)} of {len(srcs)} collections")
    for name, n in sorted(d.per_source.items(), key=lambda kv: -kv[1]):
        print(f"    {name:34s} {n:>7,}")
    empty = [s["name"] for s in srcs if s["name"] not in d.per_source]
    print(f"    no rows for this day ({len(empty)}): {', '.join(empty)}\n")
