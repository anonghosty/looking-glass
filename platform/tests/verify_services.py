"""Check the publicly accessible / vulnerable services platform against MongoDB for one day:
records per report (extracted_date on the day), total, hosts, and that demo mode hides IP addresses.

Usage: .venv/bin/python tests/verify_services.py [YYYY-MM-DD]   (default: yesterday UTC). Read-only.
Exit code: 0 everything matches, 1 any mismatch or an address shown in demo mode (so tests/run_all_checks.sh reports
it), 77 skipped (no services data for the day yet). Before 2026-11-11 it always exited 0, and its demo check still
expected the old x.161.x.34 masking; masked views now show "Host <reference>" (host_label.py).
"""
import ipaddress
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
if not total_db and not stats["total"]:
    print(f"SKIPPED: no services records for {day} yet")
    sys.exit(77)
print(f"{day}: {len(app_rows)} reports, {sum(1 for v in app_rows.values() if v)} with data, mismatching reports: {bad}")
rec_ok, host_ok = total_db == stats["total"], len(ips - {""}) == stats["hosts"]
print(f"records: MongoDB {total_db:,} · platform {stats['total']:,} · {'match' if rec_ok else 'DIFFERENT'}")
print(f"hosts:   MongoDB {len(ips - {''}):,} · platform {stats['hosts']:,} · {'match' if host_ok else 'DIFFERENT'}")
demo = get(f"/api/svc/events?from={start.isoformat().replace('+00:00', 'Z')}&to={(start + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')}&demo=1")


def shows_address(v):
    """A real address, whole or in part, where demo mode must show only an opaque label."""
    v = str(v or "")
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\bx\.\d{1,3}\.x\.\d{1,3}\b", v))


leak = [e for e in demo["events"] if shows_address(e.get("ip"))]
labels = sum(1 for e in demo["events"] if str(e.get("ip") or "").startswith("Host "))
print(f"demo mode: {len(demo['events'])} records checked, shown as host labels: {labels}, addresses shown: {len(leak)}")
problems = bad + (not rec_ok) + (not host_ok) + bool(leak) + (labels != len(demo["events"]))
print("ALL MATCH" if not problems else f"{problems} PROBLEM(S)")
sys.exit(1 if problems else 0)
