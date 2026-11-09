"""Check that both platforms show exactly the constituency set in Settings (AS numbers only; address ranges are
not counted here): every count is compared with MongoDB directly. Read-only.

Usage: .venv/bin/python tests/verify_constituency.py [YYYY-MM-DD]   (default: yesterday UTC)
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
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc); end = start + timedelta(days=1)
at = (start + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
get = lambda p: json.load(urllib.request.urlopen("http://127.0.0.1:5000" + p, timeout=300))
client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                     password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]
st = json.load(open(os.path.join(os.path.dirname(__file__), "..", "data", "settings.json")))
asns = {str(a) for a in st["networks"]}
print(f"constituency: {sorted(asns)} ranges {st['cidrs']}")


def in_day(d):
    ed = d.get("extracted_date")
    if isinstance(ed, str):
        try:
            ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
        except ValueError:
            return False
    if not isinstance(ed, datetime):
        return False
    if ed.tzinfo is None:
        ed = ed.replace(tzinfo=timezone.utc)
    return start <= ed < end


q = lambda: {"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in (day, end.strftime("%Y-%m-%d"))]}
# communications: source or destination network in the constituency
comms_expected = 0
for s in get(f"/api/sources?at={at}")["sources"]:
    for d in db[s["name"]].find(q(), {"extracted_date": 1, "src_asn": 1, "dst_asn": 1}):
        if in_day(d) and (str(d.get("src_asn") or "") in asns or str(d.get("dst_asn") or "") in asns):
            comms_expected += 1
comms = get(f"/api/stats?at={at}")["total"]
print(f"communications: MongoDB {comms_expected:,} · platform {comms:,} · {'match' if comms == comms_expected else 'DIFFERENT'}")
# services: the host's network in the constituency
svc_expected = 0
for r in get(f"/api/svc/facets?at={at}")["reports"]:
    for d in db[r["name"]].find(q(), {"extracted_date": 1, "asn": 1}):
        if in_day(d) and str(d.get("asn") or "") in asns:
            svc_expected += 1
svc = get(f"/api/svc/stats?at={at}&n=200")
print(f"services: MongoDB {svc_expected:,} · platform {svc['total']:,} · {'match' if svc['total'] == svc_expected else 'DIFFERENT'}")
print("services networks shown:", [r["label"] for r in svc["breakdowns"]["network"]])
