"""Check the publicly accessible / vulnerable services platform against MongoDB for one day:
records per report (extracted_date on the day), total, hosts, and that demo mode hides IP addresses.

Usage: .venv/bin/python tests/verify_services.py [YYYY-MM-DD]   (default: yesterday UTC). Read-only.
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import json
import os
import re
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))
day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
end = start + timedelta(days=1)
at = (start + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]
get = lambda p: json.load(urllib.request.urlopen(f"http://127.0.0.1:5000{p}", timeout=180))

facets = get(f"/api/svc/facets?at={at}")
app_rows = {r["name"]: r["rows"] for r in facets["reports"]}
nxt = end.strftime("%Y-%m-%d")
total_db, ips, bad = 0, set(), 0
for name in sorted(app_rows):
    n = 0
    for d in db[name].find({"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in (day, nxt)]}, {"extracted_date": 1, "ip": 1}):
        ed = d.get("extracted_date")
        if isinstance(ed, str):
            try:
                ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
            except ValueError:
                continue
        if not isinstance(ed, datetime):
            continue
        if ed.tzinfo is None:
            ed = ed.replace(tzinfo=timezone.utc)
        if start <= ed < end:
            n += 1
            ips.add(str(d.get("ip") or ""))
    total_db += n
    if n != app_rows[name]:
        bad += 1
        print(f"  MISMATCH {name}: MongoDB {n}, platform {app_rows[name]}")
stats = get(f"/api/svc/stats?at={at}")
print(f"{day}: {len(app_rows)} reports, {sum(1 for v in app_rows.values() if v)} with data, mismatching reports: {bad}")
print(f"records: MongoDB {total_db:,} · platform {stats['total']:,} · {'match' if total_db == stats['total'] else 'DIFFERENT'}")
print(f"hosts:   MongoDB {len(ips - {''}):,} · platform {stats['hosts']:,} · {'match' if len(ips - {''}) == stats['hosts'] else 'DIFFERENT'}")
demo = get(f"/api/svc/events?from={start.isoformat().replace('+00:00', 'Z')}&to={(start + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')}&demo=1")
import re as _re
leak = [e["ip"] for e in demo["events"] if not _re.fullmatch(r"x\.\d{1,3}\.x\.\d{1,3}|x:[0-9a-f]{4}:x:x:x:x:x:[0-9a-f]{4}", e["ip"])]
print(f"demo mode: {len(demo['events'])} records checked, unmasked IPs: {len(leak)}")
