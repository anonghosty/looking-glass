#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The decoder against this installation's own latest report day (the user, 2026-11-16: "recheck the decoded, add a
check for that"). Counts only, never a value: how many CLogin check-ins decode and how many do not, and that every one
that decodes passes the recheck (its field names are the format's and its fixed-shape values have their shape). Also
that no decoded value is flagged as instruction-like without the note. Skipped (77) when there are none on the day.
Run: tests/verify_beacon_decode.py [YYYY-MM-DD]   (default: the newest day with CLogin requests in MongoDB)"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from dotenv import load_dotenv  # noqa: E402
from pymongo import MongoClient  # noqa: E402

import beacon_decode as B  # noqa: E402

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env"))
try:
    c = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                    password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"),
                    serverSelectionTimeoutMS=8000)
    db = c[os.environ["MONGO_DB"]]
    cols = [x for x in db.list_collection_names() if x.startswith(("event4_", "event6_")) and "http" in x]
except Exception as e:                                    # noqa: BLE001  (no database here: CI)
    print(f"SKIPPED: no reports database ({type(e).__name__})"); sys.exit(77)
CL = {"http_url": {"$regex": "/CLogin", "$options": "i"}}
if len(sys.argv) > 1:
    day = datetime.fromisoformat(sys.argv[1]).replace(tzinfo=timezone.utc)
else:
    newest = None
    for col in cols:
        d = db[col].find_one(CL, {"extracted_date": 1}, sort=[("extracted_date", -1)])
        v = (d or {}).get("extracted_date")
        if isinstance(v, str):
            v = datetime.fromisoformat(v[:19]).replace(tzinfo=timezone.utc)
        elif isinstance(v, datetime) and v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        if v and (newest is None or v > newest):
            newest = v
    if newest is None:
        print("SKIPPED: no CLogin requests in the reports"); sys.exit(77)
    day = newest.replace(hour=0, minute=0, second=0, microsecond=0)
end = day + timedelta(days=1)
q = {"$or": [{"extracted_date": {"$gte": day, "$lt": end}}, {"extracted_date": {"$gte": day.strftime("%Y-%m-%dT"), "$lt": end.strftime("%Y-%m-%dT")}}], **CL}
n = ok_n = bad = noted = 0
for col in cols:
    for e in db[col].find(q, {"http_url": 1}):
        n += 1
        r = B.first(e["http_url"])
        if not r or r.get("generic"):
            continue
        ok_n += 1
        obj = {str(k).lower(): v for k, v in (r.get("json") or {}).items()}
        fmt = next((f for f in B.FORMATS if f.name == r.get("format")), None)
        if B.recheck(obj) or (fmt and not set(obj) <= fmt.vocab):
            bad += 1
        if B.instruction_like(obj) and B.INJECTION_NOTE not in r.get("notes", []):
            noted += 1
if not n:
    print(f"SKIPPED: no CLogin requests on {day.date()}"); sys.exit(77)
print(f"CLogin requests on {day.date()}: {n}; decoded {ok_n} ({ok_n / n:.1%}); not decoded {n - ok_n}")
print(f"  {'ok  ' if not bad else 'FAIL'} every decoded check-in passes the recheck  [{bad} do not]")
print(f"  {'ok  ' if not noted else 'FAIL'} every instruction-like value carries its note  [{noted} without]")
sys.exit(1 if bad or noted else 0)
