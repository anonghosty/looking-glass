"""Analyse the single-host ("publicly accessible / vulnerable services") collections: no src_/dst_ fields, just an ip.

For each one: rows for a day (filename prefix), whether it has a filename index, and its field names
(from the newest documents). Then which fields are common across them.

Usage: .venv/bin/python tools/analyze_services.py [YYYY-MM-DD]   (default: yesterday UTC). Read-only.
"""
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]

rows, field_cols, examples, total = [], Counter(), {}, 0
for name in sorted(db.list_collection_names()):
    if name.startswith(("files_", "discovered_fields_")):
        continue
    c = db[name]
    docs = list(c.find().sort("_id", -1).limit(20))
    if not docs:
        continue
    fields = set().union(*(d.keys() for d in docs))
    if any(re.search(r"src|dst", k, re.I) for k in fields) or "http_referer_ip" in fields:
        continue                                    # communications report: already on the map
    if "ip" not in fields:
        rows.append((name, "-", "no ip field", 0, sorted(fields)[:12]))
        continue
    idx = any(list(ix["key"].keys())[0] == "filename" for ix in c.list_indexes())
    n = c.count_documents({"filename": {"$regex": "^" + re.escape(day)}}) if idx else -1
    total += max(n, 0)
    for f in fields:
        field_cols[f] += 1
        v = next((d[f] for d in docs if d.get(f) not in (None, "")), None)
        if v is not None and f not in examples:
            examples[f] = str(v)[:40]
    rows.append((name, "yes" if idx else "NO", n, len(fields), None))

cand = [r for r in rows if r[2] != "no ip field"]
print(f"Single-host collections with an ip field: {len(cand)}; rows for {day}: {total:,}")
for name, idx, n, nf, _ in sorted(cand, key=lambda r: -(r[2] if isinstance(r[2], int) else 0)):
    print(f"  {name:32s} index {idx:3s} rows {n:>8}  fields {nf}")
skipped = [r for r in rows if r[2] == "no ip field"]
if skipped:
    print("\nWithout an ip field (skipped):", ", ".join(r[0] for r in skipped))
print(f"\nField frequency across {len(cand)} collections (fields in at least 20%):")
for f, k in field_cols.most_common():
    if k >= 0.2 * len(cand):
        print(f"  {f:28s} {k:3d}  ({k / len(cand):.0%})  e.g. {examples.get(f, '')!r}")
json.dump({"day": day, "collections": [r[0] for r in cand], "fields": dict(field_cols)},
          open(os.path.join(os.path.dirname(__file__), "services_fields.json"), "w"), indent=1)
