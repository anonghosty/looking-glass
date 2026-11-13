#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Accuracy of "Hosts in several reports" (cross) combined with other filters, and of the filtered stream backfill,
on the publicly accessible / vulnerable services platform. Read-only: queries the running service's API.

For every report family F (and the busiest service reports S), with "several reports" switched on after F:
  1. the widened view (F, then several reports) breaks its records down by service report; each bubble's count
  2. must equal the records shown after clicking that bubble (F, several reports, then that service)
  3. and must equal an independent count from the raw records (hosts with an F record that are in 2+ reports,
     their records in that service).
Also: legacy cross=1 still widens to all reports; a filtered stream finds the latest records however long ago.

Usage: .venv/bin/python tests/check_cross_filters.py [base_url]   (default http://127.0.0.1:5000)
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
lgauth.require_server()   # no running service (a fresh clone, CI): skipped, not crashed
import json
import sys
import urllib.parse
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
fails = 0


def get(path, pairs=()):
    q = urllib.parse.urlencode(list(pairs))
    with urllib.request.urlopen(f"{BASE}{path}{'?' + q if q else ''}", timeout=300) as r:
        return json.load(r)


def ok(label, cond, info=""):
    global fails
    fails += not cond
    print(("  ok  " if cond else "  FAIL") + " " + label + (f"  [{info}]" if info else ""), flush=True)


def seed(pairs):
    return ("cross", "seed:" + urllib.parse.urlencode(pairs))


# the day's records straight from MongoDB, independent of the platform's filter code: each services collection's
# documents with their own ip and extracted_date (same day rule as the platform: filename prefix, then the
# extracted_date inside the day); the report label and family per collection come from the facets list.
import os                                                    # noqa: E402
from datetime import datetime, timedelta, timezone          # noqa: E402
from dotenv import dotenv_values                            # noqa: E402
from pymongo import MongoClient                             # noqa: E402

ENV = dotenv_values(os.path.join(os.path.dirname(__file__), "..", ".env"))
db = MongoClient(host=ENV.get("MONGO_HOST", "localhost"), port=int(ENV.get("MONGO_PORT") or 27017), username=ENV.get("MONGO_USER") or None,
                 password=ENV.get("MONGO_PASSWORD") or None, authSource=ENV.get("MONGO_AUTH_SOURCE") or "admin")[ENV.get("MONGO_DB") or "shadowserver"]
clock = get("/api/svc/clock")
day = clock["replay_day"]
print(f"day {day}, replay at {clock['replay_now']}")
start = datetime.fromisoformat(day + "T00:00:00+00:00"); end = start + timedelta(days=1)
facets = get("/api/svc/facets")
settings_public = get("/api/settings/public")
if settings_public.get("restricted"):
    print("SKIPPED: a constituency is set in Settings; this check needs the whole country (the constituency check covers the rest).")
    sys.exit(77)
raw, mismatch = [], []
for r in facets["reports"]:
    if not r["rows"]:
        continue
    n = 0
    for d in db[r["name"]].find({"filename": {"$regex": f"^({day}|{end.date().isoformat()})"}}, {"ip": 1, "extracted_date": 1}):
        ed = d.get("extracted_date")
        if isinstance(ed, str):
            ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
        if isinstance(ed, datetime) and ed.tzinfo is None:
            ed = ed.replace(tzinfo=timezone.utc)
        if isinstance(ed, datetime) and start <= ed < end:
            raw.append({"ip": d.get("ip"), "service": r["label"], "family": r["family"]}); n += 1
    if n != r["rows"]:
        mismatch.append((r["label"], n, r["rows"]))
ok(f"{len(raw):,} records read from MongoDB; every report's count equals the platform's", not mismatch, str(mismatch[:5]))
per_host = {}
for e in raw:
    per_host.setdefault(e["ip"], set()).add(e["service"])
fam_of = {}
for e in raw:
    fam_of.setdefault(e["family"], set()).add(e["ip"])
for e in raw:
    e["ip_ref"] = None

families = sorted({e["family"] for e in raw})
print("\n1-3. family + several reports + each service bubble")
for fam in families:
    sp = [("family", fam)]
    base = sp + [seed(sp)]
    st = get("/api/svc/stats", base + [("n", "200")])
    bubbles = {r["value"]: r["count"] for r in st["breakdowns"]["service"]}
    hosts = {h for h in fam_of.get(fam, ()) if len(per_host[h]) > 1}
    expect_total = sum(1 for e in raw if (e["ip_ref"] or e["ip"]) in hosts)
    ok(f"{fam} + several reports: {st['total']:,} records (independent count {expect_total:,})", st["total"] == expect_total)
    for svc, n in sorted(bubbles.items(), key=lambda kv: -kv[1])[:6]:
        clicked = get("/api/svc/stats", base + [("service", svc)])
        indep = sum(1 for e in raw if (e["ip_ref"] or e["ip"]) in hosts and e["service"] == svc)
        ok(f"   bubble {svc}: {n:,} = after clicking {clicked['total']:,} = independent {indep:,}", n == clicked["total"] == indep)

print("\n4. Hosts with multiple issues: issues across ALL the host's reports of the day (table = view = independent)")
# each host's issues over the whole day, from the whole-day host table (no filter or scope code involved)
whole = get("/api/svc/drill", [("metric", "hosts"), ("all", "1")])
day_issues = {r["ip"]: set(r["issues"]) for r in whole["rows"]}
for sel in [[("service", "Block List")], [("family", "Blocklisted")], [("service", "DNS Open Resolvers")], [("family", "Compromised")]]:
    name = sel[0][1]
    sel_hosts = {e["ip"] for e in raw if (e["service"] if sel[0][0] == "service" else e["family"]) == name}
    multi_hosts = {h for h in sel_hosts if len(day_issues.get(h, ())) > 1}
    table = get("/api/svc/drill", sel + [("metric", "multi"), ("all", "1")])
    view = sel + [("multi", "seed:" + urllib.parse.urlencode(sel))]
    st = get("/api/svc/stats", view + [("n", "200")])
    rg = get("/api/svc/regions", view)
    expect = sum(1 for e in raw if e["ip"] in multi_hosts)
    ins = get("/api/svc/insight", sel)
    ok(f"{name} + multiple issues: card {ins['multi_issue_hosts']:,} = table {table['total']:,} = view {st['hosts']:,} hosts = independent {len(multi_hosts):,}",
       ins["multi_issue_hosts"] == table["total"] == st["hosts"] == len(multi_hosts))
    ok(f"   view records {st['total']:,} = independent {expect:,} = heatmap {sum(v['events'] for v in rg['regions'].values()):,}",
       st["total"] == expect == sum(v["events"] for v in rg["regions"].values()))
    for b in st["breakdowns"]["service"][:5]:
        indep = sum(1 for e in raw if e["ip"] in multi_hosts and e["service"] == b["value"])
        clicked = get("/api/svc/stats", view + [("service", b["value"])])
        ok(f"   bubble {b['value']}: {b['count']:,} = after clicking {clicked['total']:,} = independent {indep:,}", b["count"] == clicked["total"] == indep)

print("\n5. Several reports: the analysis table = the filtered view (hosts, records, heatmap)")
for sel in [[("service", "Block List")], [("service", "DNS Open Resolvers")]]:
    table = get("/api/svc/drill", sel + [("metric", "cross"), ("all", "1")])
    view = sel + [seed(sel)]
    st = get("/api/svc/stats", view)
    rg = get("/api/svc/regions", view)
    ok(f"{sel[0][1]}: table {table['total']:,} hosts = view {st['hosts']:,}; records {st['total']:,} = heatmap {sum(v['events'] for v in rg['regions'].values()):,}",
       table["total"] == st["hosts"] and st["total"] == sum(v["events"] for v in rg["regions"].values()))

print("\nThe case reported: Blocklisted + several reports + Accessible HTTP (insight dialog)")
sp = [("family", "Blocklisted")]
ins = get("/api/svc/insight", sp + [seed(sp), ("service", "Accessible HTTP")])
st = get("/api/svc/stats", sp + [seed(sp), ("n", "200")])
http = next((r["count"] for r in st["breakdowns"]["service"] if r["value"] == "Accessible HTTP"), 0)
ok(f"analysis shows {ins.get('total', 0):,} records, the bubble counted {http:,}", ins.get("total", 0) == http and http > 0)

print("\nService seed: DNS Open Resolvers + several reports, then another report")
sp = [("service", "DNS Open Resolvers")]
st = get("/api/svc/stats", sp + [seed(sp), ("n", "200")])
others = [r for r in st["breakdowns"]["service"] if r["value"] != "DNS Open Resolvers"]
ok("the widened view includes the resolvers' other reports", len(others) > 0, f"{len(others)} other reports")
if others:
    o = others[0]
    c = get("/api/svc/stats", sp + [seed(sp), ("service", o["value"])])
    ok(f"then {o['value']}: {c['total']:,} = bubble {o['count']:,}", c["total"] == o["count"])

print("\nLegacy links (cross=1) keep their meaning: every filter chooses the hosts, all their reports shown")
a = get("/api/svc/stats", [("family", "Blocklisted"), ("cross", "1")])
b = get("/api/svc/stats", [("family", "Blocklisted"), seed([("family", "Blocklisted")])])
ok(f"cross=1 {a['total']:,} = seed form {b['total']:,}", a["total"] == b["total"])

print("\nFiltered stream: the latest records however long ago (Block List)")
e = get("/api/svc/events", [("service", "Block List"), ("to", clock["replay_now"]), ("limit", "60"), ("latest", "1")])
done = get("/api/svc/replayed", [("service", "Block List")])
ok(f"Block List: {e['returned']} latest records returned ({done['replayed']:,} replayed so far)",
   e["returned"] == min(60, done["replayed"]) and all(x["service"] == "Block List" for x in e["events"]))
sel = [("family", "Blocklisted"), seed([("family", "Blocklisted")]), ("service", "Accessible HTTP")]
e2 = get("/api/svc/events", sel + [("to", clock["replay_now"]), ("limit", "60"), ("latest", "1")])
done2 = get("/api/svc/replayed", sel)
# early in the replayed day nothing of this selection may have been replayed yet: then none is the right answer
ok(f"cross selection in the stream: {e2['returned']} records ({done2['replayed']:,} replayed so far), all Accessible HTTP",
   e2["returned"] == min(60, done2["replayed"]) and all(x["service"] == "Accessible HTTP" for x in e2["events"]))

print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
