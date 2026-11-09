"""Check that the platform's totals match MongoDB exactly for the replayed day.

For every report (collection) it counts records with extracted_date on the day directly in MongoDB and
compares them with what the running app reports (/api/sources and /api/stats).

Usage: .venv/bin/python tests/verify_totals.py [YYYY-MM-DD]   (default: yesterday UTC)
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
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
# default: the day the platform is replaying (after midnight it keeps the previous day until the new reports arrive)
day = sys.argv[1] if len(sys.argv) > 1 else (get("/api/clock").get("replay_day")
                                             or (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d"))[:10]
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
end = start + timedelta(days=1)
at = (start + timedelta(hours=12)).isoformat().replace("+00:00", "Z")

client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]

app_sources = get(f"/api/sources?at={at}")
stats = get(f"/api/stats?at={at}")

print(f"Day {day} (app day {app_sources['day']})\n")
print(f"{'report':38} {'mongo':>8} {'app':>8}  ok")
total_mongo = total_app = 0
bad = 0
for s in app_sources["sources"]:
    name = s["name"]
    c = db[name]
    # extracted_date may be stored as a date or as an ISO string; count both forms
    n = c.count_documents({"extracted_date": {"$gte": start, "$lt": end}})
    n += c.count_documents({"extracted_date": {"$gte": start.strftime("%Y-%m-%dT"), "$lt": end.strftime("%Y-%m-%dT")}})
    a = s["rows_today"]
    total_mongo += n; total_app += a
    ok = n == a
    bad += not ok
    print(f"{s['label'][:38]:38} {n:8,} {a:8,}  {'yes' if ok else 'NO'}")
print(f"{'TOTAL':38} {total_mongo:8,} {total_app:8,}  {'yes' if total_mongo == total_app else 'NO'}")
print(f"\n/api/stats total (shown as 'Events yesterday'): {stats['total']:,}  "
      f"{'matches' if stats['total'] == total_mongo else 'DIFFERS from'} MongoDB")
print(f"critical {stats['critical']:,} · source hosts {stats['unique_src_ip']:,} · reports {stats['unique_sources']} · "
      f"cross-report hosts {stats['multi_source_hosts']:,}")
sys.exit(1 if bad or stats["total"] != total_mongo else 0)
