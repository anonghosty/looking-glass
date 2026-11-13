#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Statistics and filters of the services platform (publicly accessible / vulnerable services) against MongoDB. Read-only.
Usage: tests/verify_svc_stats.py
Every record is re-derived from the raw documents with this script's own code (not services.py), then the platform's
/api/svc/stats, /api/svc/facets and /api/svc/replayed are compared with it."""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
lgauth.require_server()   # no running service (a fresh clone, CI): skipped, not crashed
import os, sys, re, time, json, urllib.request, urllib.parse, urllib.error
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(BASE_DIR, ".env"))
BASE = "http://127.0.0.1:5000"


def api(path, params=None, timeout=300):
    q = urllib.parse.urlencode(params or [], doseq=True)
    t = time.time()
    with urllib.request.urlopen(f"{BASE}{path}" + (f"?{q}" if q else ""), timeout=timeout) as r:
        return json.load(r), time.time() - t


db = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)),
                 username=os.environ.get("MONGO_USER"), password=os.environ.get("MONGO_PASSWORD"),
                 authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"), serverSelectionTimeoutMS=8000)[os.environ["MONGO_DB"]]

clock, _ = api("/api/svc/clock")
DAY = clock["replay_day"]
START = datetime.fromisoformat(DAY).replace(tzinfo=timezone.utc)
END = START + timedelta(days=1)
AT = (START + timedelta(hours=12)).isoformat().replace("+00:00", "Z")
fac, _ = api("/api/svc/facets", {"at": AT})
LABEL = {r["name"]: r["label"] for r in fac["reports"]}
NAMES = [r["name"] for r in fac["reports"] if r["rows"]]
if not NAMES:
    print(f"SKIPPED: no services records for {DAY} yet."); sys.exit(77)
try:
    st_ = json.load(open(os.path.join(BASE_DIR, "data", "settings.json")))
    if st_.get("networks") or st_.get("cidrs"):
        print("SKIPPED: a constituency is set in Settings (tests/verify_constituency.py covers it)."); sys.exit(77)
except (OSError, ValueError):
    pass

# ---------------------------------------------------------------- own derivation
FAM = [(r"^compromised_", "Compromised"), (r"^blocklist", "Blocklisted"), (r"^device_id", "Identified device"),
       (r"^scan6?_", "Exposed service"), (r"^population6?_", "Service population")]
fam = lambda n: next((f for p, f in FAM if re.match(p, n)), "Other")
S = lambda v: "" if v is None else (v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(v, datetime) else str(v))
MARK = {"exposed-admin-panel": "Exposed admin panel", "device-implant": "Device implant", "badcandy": "Badcandy",
        "cpanel-compromised": "Cpanel compromised", "open-dir": "Open dir", "vulnerable": "Vulnerable"}


def derive(d, name):
    tags = [t.strip() for t in S(d.get("tag")).replace(",", ";").split(";") if t.strip()]
    issues = [t.upper() for t in tags if t.lower().startswith("cve-")]
    if S(d.get("ssl_poodle")).upper() == "Y": issues.append("POODLE (SSLv3)")
    if S(d.get("freak_vulnerable")).upper() == "Y": issues.append("FREAK")
    if S(d.get("cert_expired")).upper() == "Y": issues.append("Expired certificate")
    issues += [MARK[t] for t in tags if t in MARK]
    if fam(name) == "Compromised" and not issues:
        issues.append("Compromised")
    product = next((S(d.get(k)) for k in ("device_model", "server", "server_type", "serverid_software", "application") if d.get(k) not in (None, "")), "")
    ed = d["extracted_date"]
    return {"ip": S(d.get("ip")), "port": S(d.get("port")), "protocol": S(d.get("protocol")), "asn": S(d.get("asn")),
            "geo": S(d.get("geo")), "region": S(d.get("region")), "city": S(d.get("city")), "hostname": S(d.get("hostname")),
            "sector": S(d.get("sector")), "severity": S(d.get("severity")).strip().lower(), "tags": tags, "issues": issues,
            "vulnerable": bool(issues), "vendor": S(d.get("device_vendor")), "device_type": S(d.get("device_type")),
            "product": product[:80], "version": S(d.get("version") or d.get("device_version") or d.get("serverid_version"))[:60],
            "report": name, "family": fam(name), "service": LABEL.get(name, name),
            "_t": (ed if ed.tzinfo else ed.replace(tzinfo=timezone.utc)).timestamp()}


t0 = time.time()
EV = []
for n in NAMES:
    q = {"$or": [{"filename": {"$regex": "^" + p}} for p in (START.strftime("%Y-%m-%d"), END.strftime("%Y-%m-%d"))]}
    for d in db[n].find(q):
        ed = d.get("extracted_date")
        if isinstance(ed, str):
            try: ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
            except ValueError: continue
        if not isinstance(ed, datetime): continue
        if ed.tzinfo is None: ed = ed.replace(tzinfo=timezone.utc)
        if START <= ed < END:
            d["extracted_date"] = ed
            EV.append(derive(d, n))
print(f"Services day {DAY}: {len(EV):,} records from {len(NAMES)} reports read from MongoDB in {time.time()-t0:.1f}s")

day_reports = defaultdict(set); day_issues = defaultdict(set)
for e in EV:
    day_reports[e["ip"]].add(e["service"])
    if e["issues"]: day_issues[e["ip"]].update(e["issues"])

EMPTY = {"vendor": "unknown vendor", "device_type": "unknown type", "product": "unknown product", "severity": "unrated",
         "city": "unknown city", "sector": "unknown sector"}


def match(e, flt):
    for k, vals in flt.items():
        if k == "tag":
            if not vals & set(e["tags"]): return False
        elif k == "issue":
            if not vals & set(e["issues"]): return False
        elif k == "vulnerable":
            if not e["vulnerable"]: return False
        elif e[k] not in vals: return False
    return True


def expect(flt):
    vs = [e for e in EV if match(e, flt)]
    hosts = {e["ip"] for e in vs}
    k = {"total": len(vs), "hosts": len(hosts), "critical": sum(e["severity"] == "critical" for e in vs),
         "high": sum(e["severity"] == "high" for e in vs), "vulnerable": sum(e["vulnerable"] for e in vs),
         "vulnerable_hosts": len({e["ip"] for e in vs if e["vulnerable"]}), "services": len({e["report"] for e in vs}),
         "networks": len({e["asn"] for e in vs if e["asn"]}), "cities": len({e["city"] for e in vs if e["city"]}),
         "cross_report_hosts": sum(1 for ip in hosts if len(day_reports[ip]) > 1),
         "multi_issue_hosts": sum(1 for ip in hosts if len(day_issues[ip]) > 1)}
    q = [0] * 96; hf = {}
    for e in vs:
        i = int((e["_t"] - START.timestamp()) // 900); q[min(95, max(0, i))] += 1
        hf.setdefault(e["family"], [0] * 24)[min(23, max(0, i // 4))] += 1
    sev = Counter(e["severity"] or "unrated" for e in vs)
    return vs, k, q, hf, sev


KEYS = ["total", "hosts", "critical", "high", "vulnerable", "vulnerable_hosts", "services", "networks", "cities",
        "cross_report_hosts", "multi_issue_hosts"]
fails, checks = [], 0


def ok(label, cond, info="", show=False):
    global checks
    checks += 1
    if not cond: fails.append(label)
    if not cond or show:
        print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def compare(label, flt, show=False):
    params = [("at", AT)]
    for k, vs in flt.items():
        params += [("vulnerable", "1")] if k == "vulnerable" else [(k, EMPTY.get(k, v) if v == "" else v) for v in vs]
    st, dt = api("/api/svc/stats", params)
    _, k, q, hf, sev = expect(flt)
    diff = [f"{x} {st[x]:,}/{k[x]:,}" for x in KEYS if st[x] != k[x]]
    if st["quarters"] != q: diff.append("quarters")
    if st["hours_by_family"] != hf: diff.append("hours_by_family")
    if {r["value"]: r["count"] for r in st["severity"]} != dict(sev): diff.append("severity")
    rp, _ = api("/api/svc/replayed", params)
    if rp["total"] != k["total"]: diff.append(f"replayed {rp['total']:,}")
    ok(f"{label}: {k['total']:,} records, {k['hosts']:,} hosts, {k['vulnerable_hosts']:,} vulnerable hosts", not diff,
       "; ".join(diff) or f"{dt*1000:.0f} ms", show)
    return st


print("1. Headline figures, charts and every breakdown (no filter)")
st = compare("no filter", {}, show=True)
whole = st["total"]
facets = fac["facets"]
LISTKEY = {"issue": "issues", "tag": "tags"}
for b, field in (("service", "service"), ("family", "family"), ("severity", "severity"), ("issue", "issue"), ("tag", "tag"),
                 ("port", "port"), ("city", "city"), ("vendor", "vendor"), ("device_type", "device_type"),
                 ("product", "product"), ("sector", "sector"), ("protocol", "protocol"), ("region", "region")):
    cnt = Counter(); hs = defaultdict(set)
    for e in EV:
        vals = e[LISTKEY[field]] if field in LISTKEY else [e[field]]
        for v in vals:
            cnt[v] += 1; hs[v].add(e["ip"])
    rows = facets[b]
    bad = [f"{r['value']}: {r['count']}/{cnt.get(r['value'])} hosts {r['hosts']}/{len(hs.get(r['value'], ()))}"
           for r in rows if cnt.get(r["value"]) != r["count"] or len(hs.get(r["value"], ())) != r["hosts"]]
    ok(f"breakdown {b}: {len(rows)} values (whole day)", not bad, "; ".join(bad[:3]), show=True)
    top8 = st["breakdowns"][b]
    ok(f"breakdown {b}: top list on the statistics", all(cnt.get(r["value"]) == r["count"] for r in top8))

print("2. Every filter on its own (3 most common values + the rarest)")
for field in ("family", "report", "service", "severity", "port", "protocol", "city", "region", "sector", "vendor",
              "device_type", "product", "tag", "issue", "asn", "geo"):
    if field in ("report", "asn", "geo"):
        c = Counter(e[field] for e in EV)
        vals = [v for v, _ in c.most_common()]
    else:
        vals = [r["value"] for r in facets.get(field, [])]
    vals = [v for v in vals if v != ""]
    for v in (vals[:3] + vals[-1:]) if len(vals) > 3 else vals:
        compare(f"{field} = {v}", {field: {v}})
compare("vulnerable only", {"vulnerable": {True}}, show=True)
ips = Counter(e["ip"] for e in EV).most_common(2)
for ip, _ in ips:
    compare(f"ip = (host with {_} records)", {"ip": {ip}})

print("3. Combinations (AND across, OR inside)")
fv = lambda f, i=0: facets[f][min(i, len(facets[f]) - 1)]["value"] if facets.get(f) else None
combos = [
    {"family": {fv("family")}, "severity": {fv("severity")}},
    {"service": {fv("service"), fv("service", 1)}, "city": {fv("city")}},
    {"issue": {fv("issue"), fv("issue", 1)}, "vulnerable": {True}},
    {"tag": {fv("tag")}, "port": {fv("port")}, "protocol": {fv("protocol")}},
    {"family": {r["value"] for r in facets["family"]}},
]
for c in combos:
    c = {k: {x for x in v if x is not None} for k, v in c.items()}
    c = {k: v for k, v in c.items() if v}
    s = compare(" & ".join(f"{k}={'|'.join(map(str, v))}" for k, v in c.items()), c, show=True)
print("4. 'unknown ...' labels (records without a value)")
for k in EMPTY:
    compare(f"{k} = {EMPTY[k]}", {k: {""}}, show=True)
print("5. Edges")
r, _ = api("/api/svc/stats", [("at", AT), ("colour", "red")]); ok("unknown filter name ignored", r["total"] == whole)
r, _ = api("/api/svc/stats", [("at", AT), ("service", "no-such-service")]); ok("value that does not exist gives 0", r["total"] == 0)
r, _ = api("/api/svc/stats", [("at", AT), ("n", "abc")]); ok("n=abc falls back to 8 per list", len(r["breakdowns"]["service"]) <= 8)
t = time.time(); api("/api/svc/stats", {"at": AT}); print(f"   unfiltered services statistics: {time.time()-t:.2f}s for {whole:,} records")
print(f"\n{checks - len(fails)} of {checks} checks agree with MongoDB" + (f"; {len(fails)} FAILED: {fails[:6]}" if fails else ""))
sys.exit(1 if fails else 0)
