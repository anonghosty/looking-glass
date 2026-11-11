"""Consistency check of the publicly accessible / vulnerable services platform: for many filter combinations every
endpoint must agree (stats, analysis, regions, replayed, stream over the whole day, drill-down lists), in normal and
demo mode. Read-only; runs against the live service.

Usage: .venv/bin/python tests/check_services_consistency.py [YYYY-MM-DD]   (default: yesterday UTC)
Exit code: 0 all consistent, 1 any mismatch (so tests/run_all_checks.sh reports it), 77 skipped (no services data
for the day yet, e.g. a fresh install). Before 2026-11-11 it printed FAIL lines but always exited 0.
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

day = sys.argv[1] if len(sys.argv) > 1 else (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
start = datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
end_at = (start + timedelta(hours=23, minutes=59, seconds=59)).isoformat().replace("+00:00", "Z")
at = (start + timedelta(hours=12)).isoformat().replace("+00:00", "Z")


def get(path, pairs):
    q = urllib.parse.urlencode(pairs)
    return json.load(urllib.request.urlopen(f"http://127.0.0.1:5000{path}?{q}", timeout=300))


# the day's busiest region and network, so the check works for any country and constituency
_fac = get("/api/svc/facets", [("at", at)])["facets"]
_top = lambda k, i=0: ([r["value"] for r in _fac.get(k, []) if r["value"]] + ["", ""])[i]
REGION, NETWORK = _top("region", 1) or _top("region"), _top("network")
COMBOS = [
    [],
    [("service", "DNS Open Resolvers")],
    [("service", "DNS Open Resolvers"), ("cross", "1")],
    [("service", "Device Identification"), ("cross", "1")],
    [("multi", "1")],
    [("vulnerable", "1")],
    [("vulnerable", "1"), ("multi", "1")],
    [("region", REGION)],
    [("region", REGION), ("cross", "1")],
    [("issue", "CVE-2023-48795")],
    [("family", "Compromised"), ("cross", "1")],
    [("asn", NETWORK)],
    [("severity", "critical"), ("service", "Accessible SSH")],
    [("port", "22")],
]
fails = 0
for demo in (False, True):
    for combo in COMBOS:
        pairs = combo + ([("demo", "1")] if demo else [])
        s = get("/api/svc/stats", pairs + [("at", at)])
        i = get("/api/svc/insight", pairs + [("at", at)])
        r = get("/api/svc/regions", pairs + [("at", at)])
        rep = get("/api/svc/replayed", pairs + [("at", end_at)])
        stream = 0
        for k in range(48):   # the stream, in 30-minute windows over the whole day (no sampling: high limit)
            f = (start + timedelta(minutes=30 * k)).isoformat().replace("+00:00", "Z")
            t = (start + timedelta(minutes=30 * (k + 1))).isoformat().replace("+00:00", "Z")
            stream += get("/api/svc/events", pairs + [("from", f), ("to", t), ("limit", "2000")])["total"]
        hosts_drill = get("/api/svc/drill", pairs + [("at", at), ("metric", "hosts")])["total"] if s["total"] else 0
        regions_sum = sum(v["events"] for v in r["regions"].values())
        checks = {"insight": i["total"], "regions": regions_sum, "replayed(total)": rep["total"], "stream": stream}
        bad = {k: v for k, v in checks.items() if v != s["total"]}
        if hosts_drill != s["hosts"]:
            bad["hosts drill"] = (hosts_drill, s["hosts"])
        if i["hosts"] != s["hosts"]:
            bad["insight hosts"] = (i["hosts"], s["hosts"])
        label = " + ".join(f"{k}={v}" for k, v in combo) or "(whole day)"
        status = "ok  " if not bad else "FAIL"
        fails += bool(bad)
        print(f"{status} {'demo ' if demo else '     '}{label:55s} records {s['total']:>6} hosts {s['hosts']:>6} reports {s['services']:>3}"
              + ("" if not bad else f"   mismatch: {bad}"))
        if not demo and not combo and not s["total"]:
            print(f"SKIPPED: no services records for {day} yet")
            sys.exit(77)
print("\nALL CONSISTENT" if not fails else f"\n{fails} INCONSISTENT")
sys.exit(1 if fails else 0)
