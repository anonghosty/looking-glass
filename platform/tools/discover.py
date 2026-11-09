"""Survey every collection in the Shadowserver DB: which ones carry source/destination fields?

Read-only. For each collection: estimated size, indexes, field names (union of the latest 3 docs),
fields whose name contains 'src' or 'dst', the latest document's date/filename, and how many rows the
previous day's report file(s) hold (using the filename index when present).
Writes tools/discovery.json and prints a summary.
"""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dotenv import load_dotenv  # noqa: E402
from pymongo import MongoClient  # noqa: E402

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE, ".env"))
client = MongoClient(
    host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", "27017")),
    username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
    authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=5000, tz_aware=True,
)
db = client[os.environ.get("MONGO_DB", "shadowserver")]
yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def short(v):
    if isinstance(v, datetime):
        return v.isoformat()
    s = str(v)
    return s if len(s) <= 80 else s[:77] + "..."


report = []
for name in sorted(db.list_collection_names()):
    c = db[name]
    entry = {"name": name}
    try:
        entry["estimated"] = c.estimated_document_count()
        idx = [list(ix["key"].keys()) for ix in c.list_indexes()]
        entry["indexes"] = idx
        docs = list(c.find().sort("_id", -1).limit(3))
        fields = []
        for d in docs:
            for k in d:
                if k not in fields:
                    fields.append(k)
        entry["fields"] = fields
        entry["srcdst"] = [f for f in fields if re.search(r"src|dst", f, re.I)]
        latest = docs[0] if docs else {}
        entry["latest"] = {k: short(v) for k, v in latest.items() if k != "_id"}
        entry["has_extracted_date"] = "extracted_date" in fields
        entry["has_filename"] = "filename" in fields
        if idx and any(i and i[0] == "filename" for i in idx) and "filename" in fields:
            q = {"filename": {"$regex": "^" + re.escape(yesterday)}}
            entry["yesterday_rows"] = c.count_documents(q)
            entry["yesterday_files"] = c.distinct("filename", q)[:5]
        else:
            entry["yesterday_rows"] = None
    except Exception as exc:  # keep going
        entry["error"] = str(exc)
    report.append(entry)
    flag = "SRC/DST" if entry.get("srcdst") else "       "
    print(f"{flag} {name:42s} est={entry.get('estimated', '?'):>10}  yday={entry.get('yesterday_rows')!s:>7}  {','.join(entry.get('srcdst', []))}", flush=True)

with open(os.path.join(BASE, "tools", "discovery.json"), "w", encoding="utf-8") as f:
    json.dump({"yesterday": yesterday, "collections": report}, f, indent=1, default=str)
print("\nwith src/dst fields:", sum(1 for e in report if e.get("srcdst")), "of", len(report))
