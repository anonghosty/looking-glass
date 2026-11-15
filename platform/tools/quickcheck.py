"""Fast checks: the MongoDB connection, every report collection's size and filename index, and how long the
replay day's rows take to count (the same indexed query the platform uses).

Usage: .venv/bin/python tools/quickcheck.py   Read-only.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

print("ping:", tm.client.admin.command("ping"), flush=True)
t = time.time()
srcs = tm.registry.get()
print(f"report collections on the map: {len(srcs)}  [{time.time() - t:.1f}s]", flush=True)
no_index = [s["name"] for s in srcs if not s["filename_index"]]
for s in srcs:
    c = tm.db[s["name"]]
    print(f"  {s['name']:40s} ~{c.estimated_document_count():>10,} docs  filename index: {'yes' if s['filename_index'] else 'NO'}")
if no_index:
    print(f"\n{len(no_index)} collection(s) without a filename index are not loaded (unless FALLBACK_SCAN=1): {', '.join(no_index)}")

day = tm.day_start(tm.replay_now())
t = time.time()
sig = tm.store.signature(day)
print(f"\nreplay day {day.date()}: {sum(sig.values()):,} rows in {len(sig)} reports, counted in {time.time() - t:.2f}s", flush=True)
