"""How many docs does one day's set of files hold? Uses the filename index (no collection scan)."""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

day = sys.argv[1] if len(sys.argv) > 1 else "2026-11-05"
t = time.time()
q = {"filename": {"$regex": "^" + re.escape(day)}}
print("docs:", tm.coll.count_documents(q), f"[{time.time() - t:.1f}s]", flush=True)
t = time.time()
files = tm.coll.distinct("filename", q)
print("files:", len(files), files[:5], f"[{time.time() - t:.1f}s]", flush=True)
t = time.time()
docs = list(tm.coll.find(q, {"extracted_date": 1, "tag": 1, "dst_geo": 1, "src_geo": 1}))
ds = sorted(d["extracted_date"] for d in docs if d.get("extracted_date"))
print("loaded", len(docs), f"[{time.time() - t:.1f}s]", "range:", ds[0] if ds else None, "->", ds[-1] if ds else None, flush=True)
print("empty dst_geo:", sum(1 for d in docs if not d.get("dst_geo")), flush=True)
from collections import Counter
print("top tags:", Counter(d.get("tag") for d in docs).most_common(8), flush=True)
print("top src:", Counter(d.get("src_geo") for d in docs).most_common(6), flush=True)
print("top dst:", Counter(d.get("dst_geo") for d in docs).most_common(6), flush=True)
