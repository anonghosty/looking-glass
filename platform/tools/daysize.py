"""How big is one day? Rows and files per report for a day, counted with the filename index (no collection scan),
plus the day's time range, top tags and countries.

Usage: .venv/bin/python tools/daysize.py [YYYY-MM-DD]   (default: yesterday UTC). Read-only.
"""
import os
import re
import sys
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
try:
    datetime.strptime(day, "%Y-%m-%d")
except ValueError:
    sys.exit("usage: tools/daysize.py [YYYY-MM-DD]")
q = {"filename": {"$regex": "^" + re.escape(day)}}

total, files, docs = 0, 0, []
print(f"Reports with files for {day}:")
for s in tm.registry.get():
    c = tm.db[s["name"]]
    if not s["filename_index"]:
        print(f"  {s['name']:40s} skipped: no filename index")
        continue
    t = time.time()
    n = c.count_documents(q)
    if not n:
        continue
    f = c.distinct("filename", q)
    total, files = total + n, files + len(f)
    print(f"  {s['name']:40s} {n:8,} rows  {len(f):3} files  [{time.time() - t:.1f}s]", flush=True)
    docs += list(c.find(q, {"extracted_date": 1, "tag": 1, "dst_geo": 1, "src_geo": 1, "geo": 1, "_id": 0}))

print(f"\nTotal: {total:,} rows in {files} files")
ds = sorted(d["extracted_date"] for d in docs if d.get("extracted_date"))
print("range:", ds[0] if ds else None, "->", ds[-1] if ds else None)
print("empty dst_geo:", sum(1 for d in docs if not d.get("dst_geo")))
print("top tags:", Counter(d.get("tag") for d in docs).most_common(8))
print("top src:", Counter(d.get("src_geo") or d.get("geo") for d in docs).most_common(6))
print("top dst:", Counter(d.get("dst_geo") for d in docs).most_common(6))
