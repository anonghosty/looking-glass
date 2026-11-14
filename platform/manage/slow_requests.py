#!/usr/bin/env python3
"""Which pages and data requests were slow in real use (slow_log.py): per route, how often, median and slowest time,
and how many requests were running at once. Run on the server: ./manage/slow_requests.py [--days N]"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import slow_log  # noqa: E402

days = 7
if "--days" in sys.argv:
    try:
        days = max(1, int(sys.argv[sys.argv.index("--days") + 1]))
    except (IndexError, ValueError):
        sys.exit("--days takes a number")
path = os.path.join(os.environ.get("LG_DATA_DIR") or os.path.join(os.path.dirname(HERE), "data"), "slow_requests.jsonl")
rows = slow_log.summary(path, days)
if not rows:
    print(f"No request took longer than {slow_log.threshold():g} s in the last {days} day(s) (or the log is empty).")
    sys.exit(0)
print(f"Requests slower than {slow_log.threshold():g} s, last {days} day(s), slowest first:")
print(f"{'times':>6} {'median':>8} {'slowest':>8} {'at once':>8}  route (roles)")
for r in rows[:40]:
    print(f"{r['count']:6d} {r['median']:7.1f}s {r['slowest']:7.1f}s {r['running_max']:8d}  {r['route']}  ({', '.join(r['roles']) or '-'})")
