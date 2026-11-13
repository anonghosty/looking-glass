"""Check "Replayed so far" against MongoDB: count records with extracted_date from 00:00 up to a moment of the
replayed day directly in every reported collection, and compare with /api/replayed at the same moment.

Usage: .venv/bin/python tests/verify_replayed.py [ISO time]   (default: now minus 24 hours)
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
lgauth.require_server()   # no running service (a fresh clone, CI): skipped, not crashed
import os, sys  # noqa: E401
# These totals are for the whole country. With a constituency set in Settings the platform shows only that part, which
# tests/verify_constituency.py checks against MongoDB: skip (exit 77) instead of reporting a false difference.
try:
    import json as _json
    _st = _json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "settings.json")))
    if _st.get("networks") or _st.get("cidrs"):
        print(f"SKIPPED: a constituency is set in Settings ({len(_st.get('networks') or [])} AS numbers, "
              f"{len(_st.get('cidrs') or [])} address ranges); the constituency check compares it with MongoDB.")
        sys.exit(77)
except (OSError, ValueError):
    pass

import json
import os
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
get = lambda p: json.load(urllib.request.urlopen(f"http://127.0.0.1:5000{p}", timeout=180))
# default: the platform's own replay position (it waits on the previous day until the new reports arrive)
_rn = None if len(sys.argv) > 1 else get("/api/clock").get("replay_now")
at = (datetime.fromisoformat((sys.argv[1] if len(sys.argv) > 1 else _rn).replace("Z", "+00:00")) if (len(sys.argv) > 1 or _rn)
      else datetime.now(timezone.utc) - timedelta(hours=24)).replace(microsecond=0)
start = at.replace(hour=0, minute=0, second=0)
at_s = at.isoformat().replace("+00:00", "Z")

client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]

app = get(f"/api/replayed?at={at_s}")
sources = get(f"/api/sources?at={at_s}")["sources"]
mongo = 0
for s in sources:
    c = db[s["name"]]
    mongo += c.count_documents({"extracted_date": {"$gte": start, "$lte": at}})
    mongo += c.count_documents({"extracted_date": {"$gte": start.strftime("%Y-%m-%dT"), "$lte": at_s}})
print(f"Replay position {at_s}")
print(f"MongoDB records 00:00 to then: {mongo:,}")
print(f"Platform 'Replayed so far':    {app['replayed']:,} of {app['total']:,}")
print("MATCH" if mongo == app["replayed"] else "DIFFERENT")
sys.exit(0 if mongo == app["replayed"] else 1)
