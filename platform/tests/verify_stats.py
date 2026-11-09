#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Statistics and filters of the communications platform against MongoDB, for the replay day. Read-only.

Every figure is worked out a second time straight in MongoDB with aggregation pipelines that derive the fields on
their own (not with the platform's code), then compared with the running service:
  1. headline figures of /api/stats and /api/overview (events, critical, source hosts, hosts in several reports, ...)
  2. every top list, the 96 quarter-hour timeline, the hourly chart per attack type, the top networks per company
  3. every filter on its own (the 3 most common values and the rarest), checked on /api/stats, /api/geo, /api/replayed
  4. combinations: AND across filters, OR inside one filter
  5. the "unknown" / "untagged" / "unrated" labels (records without a value)
  6. edges: unknown filter names, values that do not exist, at= outside the allowed days, the 30-minute cap and the
     limits of /api/events. The longest filter request the server accepts and the speed under load are reported only.

Skipped (exit 77) when a constituency is set in Settings (tests/verify_constituency.py covers that) or when the replay
day has no records yet. With demo masking forced for the automation login, the host-level filters are left out.

Usage: tests/verify_stats.py [YYYY-MM-DD] [-v]   (default: the day being replayed; -v prints every comparison)
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import concurrent.futures as cf
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv
from pymongo import MongoClient

HERE = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(HERE, "..", ".env"))
BASE = "http://127.0.0.1:5000"
ARGS = [a for a in sys.argv[1:] if not a.startswith("-")]
VERBOSE = "-v" in sys.argv[1:]
EMPTY = {"infection": "unknown", "tag": "untagged", "severity": "unrated"}

try:
    _st = json.load(open(os.path.join(HERE, "..", "data", "settings.json")))
    if _st.get("networks") or _st.get("cidrs"):
        print(f"SKIPPED: a constituency is set in Settings; tests/verify_constituency.py compares it with MongoDB.")
        sys.exit(77)
except (OSError, ValueError):
    pass


def api(path, params=None, timeout=300):
    q = urllib.parse.urlencode(params or [], doseq=True)
    t = time.time()
    with urllib.request.urlopen(f"{BASE}{path}" + (f"?{q}" if q else ""), timeout=timeout) as r:
        return json.load(r), time.time() - t


client = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                     username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                     authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)
db = client[os.environ["MONGO_DB"]]

clock, _ = api("/api/clock")
DAY = ARGS[0] if ARGS else clock["replay_day"]
START = datetime.fromisoformat(DAY).replace(tzinfo=timezone.utc)
END = START + timedelta(days=1)
AT = (START + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
DEMO = bool(clock.get("demo_forced"))
diag, _ = api("/api/diagnostics")
LAYOUT = {s["name"]: s["layout"] for s in diag["supported"]}
src_list, _ = api("/api/sources", {"at": AT})
if src_list["day"] != DAY:
    print(f"SKIPPED: the platform answers for {src_list['day']}, not {DAY} (only the replay day and the day before are served).")
    sys.exit(77)
NAMES = [s["name"] for s in src_list["sources"] if s["rows_today"]]
if not NAMES:
    print(f"SKIPPED: no records for {DAY} yet.")
    sys.exit(77)

# ---------------------------------------------------------------- independent field derivation, inside MongoDB
CLASS_RULES = [(r"ddos", "DDoS"), (r"brute_force", "Brute force"), (r"initial_access", "Initial access"),
               (r"spoof", "IP spoofing"), (r"spam", "Spam"), (r"sinkhole|drone", "Botnet C2"), (r"scan|darknet", "Scanning")]
klass = lambda n: next((label for p, label in CLASS_RULES if re.search(p, n)), "Other")
S = lambda f: {"$toString": {"$ifNull": [f"${f}", ""]}}


def first(*exprs):
    """The first non-empty string of the expressions."""
    out = exprs[-1]
    for e in reversed(exprs[:-1]):
        out = {"$cond": [{"$gt": [{"$strLenCP": e}, 0]}, e, out]}
    return out


def stage(name):
    lay = LAYOUT.get(name, "standard")
    if lay == "legacy":        # local host in ip / geo / city ...
        src = lambda p: S(p.replace("src_", ""))
    elif lay == "referer":
        src = lambda p: S(p.replace("src_", "http_referer_"))
    else:
        src = S
    dst = (lambda p: first(S(p), S(p.replace("dst_", "")))) if lay == "inbound" else S
    infection = [S("infection")] + ([S("type")] if lay == "legacy" else []) + [S("family"), S("tag"), S("application"), {"$literal": name}]
    f = {
        "source": {"$literal": name}, "attack_class": {"$literal": klass(name)},
        "src_ip": src("src_ip"), "src_asn": src("src_asn"), "src_geo": src("src_geo"), "src_city": src("src_city"),
        "dst_ip": first(dst("dst_ip"), {"$arrayElemAt": [{"$split": [S("dst_network"), "/"]}, 0]}),
        "dst_asn": dst("dst_asn"), "dst_geo": dst("dst_geo"), "dst_city": dst("dst_city"), "dst_port": dst("dst_port"),
        "severity": S("severity"), "tag": S("tag"), "protocol": S("protocol"), "http_host": S("http_host"),
        "http_agent": first(S("http_agent"), S("agent")) if lay == "legacy" else S("http_agent"),
        "infection": first(*infection), "t": "$_ed",
    }
    prefixes = (START.strftime("%Y-%m-%d"), END.strftime("%Y-%m-%d"))
    return [{"$match": {"$or": [{"filename": {"$regex": "^" + p}} for p in prefixes]}},
            {"$addFields": {"_ed": {"$convert": {"input": "$extracted_date", "to": "date", "onError": None, "onNull": None}}}},
            {"$match": {"_ed": {"$gte": START, "$lt": END}}},
            {"$project": {"_id": 0, **f}}]


def mongo(tail):
    p = stage(NAMES[0]) + [{"$unionWith": {"coll": n, "pipeline": stage(n)}} for n in NAMES[1:]] + tail
    return list(db[NAMES[0]].aggregate(p, allowDiskUse=True))


def mmatch(flt):
    return [{"$match": {k: {"$in": [("" if v == EMPTY.get(k) else v) for v in vals]} for k, vals in flt.items()}}] if flt else []


SUMMARY = [{"$facet": {
    "total": [{"$count": "n"}],
    "critical": [{"$match": {"severity": "critical"}}, {"$count": "n"}],
    "src": [{"$match": {"src_ip": {"$ne": ""}}}, {"$group": {"_id": "$src_ip", "s": {"$addToSet": "$source"}}},
            {"$group": {"_id": None, "n": {"$sum": 1}, "multi": {"$sum": {"$cond": [{"$gt": [{"$size": "$s"}, 1]}, 1, 0]}}}}],
    "dst": [{"$match": {"dst_ip": {"$ne": ""}}}, {"$group": {"_id": "$dst_ip"}}, {"$count": "n"}],
    "inf": [{"$group": {"_id": "$infection"}}, {"$count": "n"}],
    "srcs": [{"$group": {"_id": "$source"}}, {"$count": "n"}],
}}]
KEYS = ["total", "critical", "unique_src_ip", "multi_source_hosts", "unique_dst_ip", "unique_infection", "unique_sources"]


def msum(flt):
    r = mongo(mmatch(flt) + SUMMARY)[0]
    g = lambda k, f="n": (r[k][0][f] if r[k] else 0)
    return {"total": g("total"), "critical": g("critical"), "unique_src_ip": g("src"), "multi_source_hosts": g("src", "multi"),
            "unique_dst_ip": g("dst"), "unique_infection": g("inf"), "unique_sources": g("srcs")}


fails, checks = [], 0


def ok(label, cond, info="", show=False):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    if not cond or show or VERBOSE:
        print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)
    return cond


def compare(label, flt):
    params = [("at", AT)] + [(k, v) for k, vs in flt.items() for v in vs]
    st, dt = api("/api/stats", params)
    m = msum(flt)
    diff = {k: f"platform {st[k]:,} / mongo {m[k]:,}" for k in KEYS if st[k] != m[k]}
    geo, _ = api("/api/geo", params)
    rep, _ = api("/api/replayed", params)
    if geo["total"] != m["total"]:
        diff["map"] = f"{geo['total']:,}"
    if rep["total"] != m["total"]:
        diff["replayed"] = f"{rep['total']:,}"
    ok(f"{label}: {st['total']:,} events, {st['unique_src_ip']:,} source hosts, {st['critical']:,} critical", not diff,
       "; ".join(f"{k} {v}" for k, v in diff.items()) or f"{dt * 1000:.0f} ms")
    return st, m


print(f"Day {DAY}: {len(NAMES)} reports, replay {clock['state']} at {clock['replay_now'][11:19]}" + (" (demo masking forced)" if DEMO else ""))

# 1 -------------------------------------------------------------------------------------------------------------
print("1. Headline figures")
st, m = compare("no filter", {})
ov, _ = api("/api/overview")
if ov["day"] == DAY:
    for k_ov, k_m in (("total", "total"), ("critical", "critical"), ("source_hosts", "unique_src_ip"),
                      ("cross_report_hosts", "multi_source_hosts"), ("infections", "unique_infection")):
        ok(f"overview {k_ov} {ov[k_ov]:,}", ov[k_ov] == m[k_m], f"mongo {m[k_m]:,}")

# 2 -------------------------------------------------------------------------------------------------------------
print("2. Top lists and charts")
fields = [("source", 12), ("attack_class", 8), ("infection", 8), ("tag", 8), ("src_city", 8), ("src_geo", 8),
          ("dst_geo", 8), ("dst_port", 6), ("severity", 5)] + ([] if DEMO else [("http_host", 8)])
for field, n in fields:
    rows = mongo([{"$group": {"_id": f"${field}", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}])
    mc = {(r["_id"] or EMPTY.get(field, "unknown")): r["n"] for r in rows}
    bad = [f"{r['value']}: {r['count']:,} vs {mc.get(r['value'])}" for r in st[field] if mc.get(r["value"]) != r["count"]]
    ranks = [r["count"] for r in st[field]] == [r["n"] for r in rows[:n]]
    ok(f"top {field} ({len(st[field])} of {len(rows):,} values)", not bad and ranks, "; ".join(bad[:3]) or ("" if ranks else "ranking counts differ"))
day_ms = int(START.timestamp() * 1000)
tl = [0] * 96
for r in mongo([{"$group": {"_id": {"$floor": {"$divide": [{"$subtract": [{"$toLong": "$t"}, day_ms]}, 900000]}}, "n": {"$sum": 1}}}]):
    tl[min(95, int(r["_id"]))] += r["n"]
ok("timeline, 96 quarter hours (stats)", tl == st["timeline"])
if ov["day"] == DAY:
    ok("timeline, 96 quarter hours (overview)", tl == ov["timeline"])
hours = {}
for r in mongo([{"$group": {"_id": {"c": "$attack_class", "h": {"$hour": "$t"}}, "n": {"$sum": 1}}}]):
    hours.setdefault(r["_id"]["c"], [0] * 24)[r["_id"]["h"]] += r["n"]
ok(f"hourly chart, {len(st['hours_by_class'])} attack types x 24 hours", all(hours.get(c) == v for c, v in st["hours_by_class"].items()))
if not DEMO:
    for side in ("src", "dst"):
        by_asn = {r["_id"]: r["n"] for r in mongo([{"$match": {f"{side}_asn": {"$ne": ""}}}, {"$group": {"_id": f"${side}_asn", "n": {"$sum": 1}}}])}
        bad = [f"{r['value']}: {r['count']:,} vs {sum(by_asn.get(str(a), 0) for a in r['asns']):,}" for r in st[f"{side}_network"]
               if sum(by_asn.get(str(a), 0) for a in r["asns"]) != r["count"]]
        ok(f"top {side} networks per company ({len(st[f'{side}_network'])})", not bad, "; ".join(bad[:3]))

# 3 -------------------------------------------------------------------------------------------------------------
print("3. Every filter on its own (stats, map and replayed count)")
fac, _ = api("/api/facets", {"at": AT})
for field in ("source", "attack_class", "infection", "severity", "tag", "src_city", "dst_geo", "dst_port", "protocol", "src_geo"):
    vals = [r["value"] for r in fac.get(field, [])]
    for v in (vals[:3] + vals[-1:]) if len(vals) > 3 else vals:
        compare(f"{field} = {v}", {field: [v]})
if not DEMO:
    for field in ("http_host", "dst_ip", "src_ip", "dst_city", "http_agent"):
        for r in mongo([{"$match": {field: {"$ne": ""}}}, {"$group": {"_id": f"${field}", "n": {"$sum": 1}}}, {"$sort": {"n": -1}}, {"$limit": 2}]):
            compare(f"{field} = (one with {r['n']:,} records)", {field: [r["_id"]]})
    for side in ("src", "dst"):
        for r in st[f"{side}_network"][:2]:
            p, _ = api("/api/stats", [("at", AT), (f"{side}_asn", r["value"])])
            mm = msum({f"{side}_asn": [str(a) for a in r["asns"]]})
            ok(f"{side}_asn = company '{r['value']}' ({len(r['asns'])} AS numbers): {p['total']:,}", p["total"] == mm["total"], f"mongo {mm['total']:,}")
            for form in (str(r["asns"][0]), f"AS{r['asns'][0]}"):
                p2, _ = api("/api/stats", [("at", AT), (f"{side}_asn", form)])
                one = msum({f"{side}_asn": [str(r["asns"][0])]})["total"]
                ok(f"{side}_asn written as '{form}': {p2['total']:,}", p2["total"] == one, f"mongo {one:,}")

# 4 -------------------------------------------------------------------------------------------------------------
print("4. Combinations (AND across filters, OR inside one)")


def top(f, i=0):
    rows = fac.get(f, [])
    return [rows[min(i, len(rows) - 1)]["value"]] if rows else []


combos = [
    {"attack_class": top("attack_class"), "src_city": top("src_city")},
    {"source": top("source"), "severity": top("severity")},
    {"infection": top("infection") + top("infection", 1)},
    {"infection": top("infection") + top("infection", 1), "src_city": top("src_city") + top("src_city", 1)},
    {"attack_class": top("attack_class"), "dst_geo": top("dst_geo"), "dst_port": top("dst_port"), "severity": top("severity")},
    {"src_city": top("src_city"), "src_geo": top("src_geo"), "tag": top("tag"), "protocol": top("protocol")},
]
for c in combos:
    c = {k: sorted(set(v)) for k, v in c.items() if v}
    if c:
        compare(" & ".join(f"{k}={'|'.join(v)}" for k, v in c.items()), c)
every, _ = compare("every attack type selected", {"attack_class": [r["value"] for r in fac["attack_class"]]})
ok("every attack type selected = the whole day", every["total"] == st["total"])

# 5 -------------------------------------------------------------------------------------------------------------
print("5. Records without a value")
for f, label in EMPTY.items():
    compare(f"{f} = {label}", {f: [label]})

# 6 -------------------------------------------------------------------------------------------------------------
print("6. Edges")
whole = st["total"]


def total(params):
    return api("/api/stats", [("at", AT)] + params, timeout=120)[0]["total"]


ok("a value that does not exist gives 0", total([("infection", "no-such-value-xyz")]) == 0)
ok("an unknown filter name is ignored (whole day)", total([("colour", "red")]) == whole)
ok("an empty filter value is ignored (whole day)", total([("src_city", "")]) == whole)
ips = [r["_id"] for r in mongo([{"$match": {"src_ip": {"$ne": ""}}}, {"$group": {"_id": "$src_ip"}}, {"$sort": {"_id": 1}}, {"$limit": 150}])]
if ips:
    ok(f"{len(ips)} source hosts in one request (OR)", total([("src_ip", i) for i in ips]) == msum({"src_ip": ips})["total"])
prev = (START - timedelta(days=1)).date().isoformat()
if DAY == clock["replay_day"]:
    r, _ = api("/api/stats", {"at": "2001-01-01T12:00:00Z"})
    ok(f"at= long ago is held to the day before ({prev})", r["day"] == prev, r["day"])
    for label, at in (("tomorrow", (END + timedelta(hours=12)).isoformat()), ("not a date", "yesterday")):
        r, _ = api("/api/stats", {"at": at})
        ok(f"at= {label} answers for the replay day", r["day"] == DAY, r["day"])
ev, _ = api("/api/events", {"from": DAY + "T08:00:00Z", "to": DAY + "T12:00:00Z", "limit": "50"})
ok("/api/events keeps at most 30 minutes", ev["from"].startswith(DAY + "T11:30:00"), ev["from"])
mw = mongo([{"$match": {"t": {"$gte": START + timedelta(hours=11, minutes=30), "$lt": START + timedelta(hours=12)}}}, {"$count": "n"}])
mw = mw[0]["n"] if mw else 0
ok(f"/api/events total for 11:30-12:00 ({ev['total']:,}) = MongoDB", ev["total"] == mw, f"mongo {mw:,}")
ok("/api/events sampled flag", ev["sampled"] == (ev["total"] > 50) and ev["returned"] == min(50, ev["total"]))
for lim, want in (("0", 1), ("-5", 1), ("99999", 2000)):
    e, _ = api("/api/events", {"from": DAY + "T11:30:00Z", "to": DAY + "T12:00:00Z", "limit": lim})
    ok(f"/api/events limit={lim} is held to {want}", e["returned"] == min(want, e["total"]), f"returned {e['returned']}")

# reported only: depend on the machine and the web server settings
print("   (information only)")
longest = None
for n in (100, 200, 300, 400, 600):
    many = [f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}" for i in range(n)]
    try:
        api("/api/stats", [("at", AT)] + [("src_ip", i) for i in many], timeout=60)
        longest = (n, len(urllib.parse.urlencode([("src_ip", i) for i in many])))
    except urllib.error.HTTPError as e:
        print(f"   filter values in one request: {longest[0] if longest else 0} accepted"
              f" (~{(longest[1] if longest else 0) // 1000} KB), {n} refused with HTTP {e.code}")
        break
else:
    print(f"   filter values in one request: {longest[0]} accepted")
t = time.time()
cities = [r["value"] for r in fac.get("src_city", [])[:5]] or [""]
with cf.ThreadPoolExecutor(12) as ex:
    times = list(ex.map(lambda i: api("/api/stats", [("at", AT), ("src_city", cities[i % len(cities)])])[1], range(24)))
print(f"   24 filtered statistics requests, 12 at a time: {time.time() - t:.1f}s in all, slowest {max(times):.1f}s; "
      f"unfiltered statistics {api('/api/stats', {'at': AT})[1]:.2f}s for {whole:,} events")

print(f"\n{checks - len(fails)} of {checks} checks agree with MongoDB" + (f"; {len(fails)} FAILED" if fails else ""))
sys.exit(1 if fails else 0)
