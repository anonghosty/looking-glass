"""Check the new-report detection: MongoDB row counts per report for a day, how long the check takes, and
whether the running service has the same reports loaded (via /api/clock).

Usage: .venv/bin/python tools/check_reports.py [YYYY-MM-DD]   (default: yesterday UTC)
Importing app.py here does not start the replay schedule (only the server runs it).
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))), "tests"))
import lgauth  # noqa: E402,F401  local API login (automation key)
import json
import os
import sys
import time
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import app  # noqa: E402

day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
t0 = time.time()
sig = app.store.signature(start)
print(f"MongoDB check for {day}: {len(sig)} reports, {sum(sig.values())} rows (files of {day} and the next day), {time.time() - t0:.2f}s")
for k, v in sorted(sig.items(), key=lambda x: -x[1]):
    print(f"  {k:40s} {v:7d}")
clock = json.load(urllib.request.urlopen("http://127.0.0.1:5000/api/clock", timeout=30))
if clock["replay_day"] == day:
    served = {r["source"]: r["rows"] for r in clock["reports"]}
    missing = [k for k in sig if k not in served]
    print(f"Service: {clock['state']}, {len(served)} reports, {clock['day_total']} events, version {clock['data_version']}")
    print("Reports in MongoDB but not in the service:", missing or "none")
    print("Recent report changes announced:", clock["report_changes"] or "none")
else:
    print(f"Service is on {clock['replay_day']}, not {day}")
