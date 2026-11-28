# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Run the compatibility diagnostic on every collection in MongoDB (read-only) and print the result:
which reports the platform loads onto the map, and which match discovery but lack required fields.

Usage: .venv/bin/python tools/diagnose_reports.py [collection ...]   (no names = all)
"""
import os
import sys

# the platform folder first: db_connect and sources live there, not in tools/ (audit 2026-11-27, 8-6: it was added
# after `import db_connect`, so the tool stopped with ModuleNotFoundError as documented)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from dotenv import load_dotenv  # noqa: E402
from pymongo import MongoClient  # noqa: E402
import db_connect  # noqa: E402  (where the database is; TLS for one on another computer)
from sources import Registry  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
client = MongoClient(**db_connect.kwargs(os.environ.get),
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
