"""Run the compatibility diagnostic on every collection in MongoDB (read-only) and print the result:
which reports the platform loads onto the map, and which match discovery but lack required fields.

Usage: .venv/bin/python tools/diagnose_reports.py [collection ...]   (no names = all)
"""
import os
import sys

from dotenv import load_dotenv
from pymongo import MongoClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from sources import Registry  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]
csv = lambda v: [x.strip() for x in (v or "").split(",") if x.strip()]
reg = Registry(db, exclude=csv(os.environ.get("EXCLUDE_COLLECTIONS", "outdated_dnssec_key")),
               include=sys.argv[1:] or csv(os.environ.get("MONGO_COLLECTIONS")) or None,
               fallback_scan=os.environ.get("FALLBACK_SCAN") == "1")
items = reg.get()


def show(i):
    d = i["diagnostic"]
    print(f"  {i['name']:38s} layout {d['layout']:12s} required {d['required_ok']}/{d['required_total']}")
    for c in d["checks"]:
        if not c["ok"]:
            kind = "MISSING (required)" if c["required"] else "missing (recommended)"
            print(f"      {kind:22s} {c['need']}: {' or '.join(c['fields'])} {c['note']}")


print(f"Compatible, loaded onto the map: {len(items)}")
for i in items:
    show(i)
print(f"\nMatch discovery but cannot be processed yet: {len(reg.unsupported)}")
for i in reg.unsupported:
    show(i)
print(f"\nCollections without source/destination fields (not candidates): "
      f"{len(reg.names) - len(items) - len(reg.unsupported)} (including files_* and discovered_fields_*)")
