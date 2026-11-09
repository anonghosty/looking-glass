#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Executive portal against MongoDB: figures, filters, every day of the 7-day baseline, every grade, and the clickable
"Top findings" combinations. Read-only (no report downloads). Usage: tests/verify_management.py"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import os, sys, json, time, urllib.request, urllib.parse
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import mongo_derive as L  # noqa: E402
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(BASE_DIR, ".env"))
db = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                 password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"))[os.environ["MONGO_DB"]]


def api(path, params=None):
    q = urllib.parse.urlencode(params or [], doseq=True)
    with urllib.request.urlopen(f"http://127.0.0.1:5000{path}" + (f"?{q}" if q else ""), timeout=600) as r:
        return json.load(r)


try:
    st_ = json.load(open(os.path.join(BASE_DIR, "data", "settings.json")))
    if st_.get("networks") or st_.get("cidrs"):
        print("SKIPPED: a constituency is set in Settings (tests/verify_constituency.py covers it)."); sys.exit(77)
except (OSError, ValueError):
    pass

fails, checks = [], 0


def ok(label, cond, info="", show=False):
    global checks
    checks += 1
    if not cond: fails.append(label)
    if not cond or show:
        print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


diag = api("/api/diagnostics")
LAYOUT = {s["name"]: s["layout"] for s in diag["supported"]}
C_NAMES = [s["name"] for s in diag["supported"]]
svf = api("/api/svc/facets")
S_LABEL = {r["name"]: r["label"] for r in svf["reports"]}
S_NAMES = list(S_LABEL)


# ---------------------------------------------------------------- expected figures, own code
def exp_comms(ev):
    hosts = defaultdict(lambda: {"inf": set(), "rep": set(), "cls": set()})
    inf, reg, att, rep = Counter(), Counter(), Counter(), Counter()
    inf_h, reg_h, rep_h = defaultdict(set), defaultdict(set), defaultdict(set)
    hours = [0] * 24
    for e in ev:
        i = e["infection"] or "unknown"; r = L.title(e["src_region"]) or "Unknown region"
        inf[i] += 1; reg[r] += 1; att[e["attack_class"]] += 1; rep[e["source"]] += 1
        hours[int((e["_t"] - T0) // 3600) % 24] += 1
        if e["src_ip"]:
            h = hosts[e["src_ip"]]; h["inf"].add(i); h["rep"].add(e["source"]); h["cls"].add(e["attack_class"])
            inf_h[i].add(e["src_ip"]); reg_h[r].add(e["src_ip"]); rep_h[e["source"]].add(e["src_ip"])
    k = {"events": len(ev), "devices": len(hosts), "infections": len(inf), "reports": len(rep),
         "regions": len([r for r in reg if r != "Unknown region"]), "multi_infected": sum(len(h["inf"]) > 1 for h in hosts.values()),
         "cross_report": sum(len(h["rep"]) > 1 for h in hosts.values()),
         "critical": sum(e["severity"] == "critical" for e in ev)}
    return k, hours, {"infections": (inf, inf_h), "regions": (reg, reg_h), "reports": (rep, rep_h), "attack": (att, None)}, \
        {"domains": len({e["http_host"] for e in ev if e["http_host"]}), "destinations": len({e["dst_ip"] for e in ev if e["dst_ip"]})}


def exp_svc(ev):
    hosts = defaultdict(lambda: {"iss": set(), "svc": set()})
    iss, svc, reg = Counter(), Counter(), Counter()
    iss_h, svc_h, reg_h = defaultdict(set), defaultdict(set), defaultdict(set)
    hours = [0] * 24
    for e in ev:
        r = L.title(e["region"]) or "Unknown region"
        svc[e["service"]] += 1; reg[r] += 1; svc_h[e["service"]].add(e["ip"]); reg_h[r].add(e["ip"])
        hours[int((e["_t"] - T0) // 3600) % 24] += 1
        h = hosts[e["ip"]]; h["svc"].add(e["service"])
        for i in e["issues"]:
            iss[i] += 1; iss_h[i].add(e["ip"]); h["iss"].add(i)
    k = {"records": len(ev), "hosts": len(hosts), "vulnerable_hosts": sum(bool(h["iss"]) for h in hosts.values()),
         "multi_issue": sum(len(h["iss"]) > 1 for h in hosts.values()), "cross_report": sum(len(h["svc"]) > 1 for h in hosts.values()),
         "issues": len(iss), "services": len(svc), "regions": len([r for r in reg if r != "Unknown region"]),
         "critical": sum(e["severity"] == "critical" for e in ev)}
    return k, hours, {"issues": (iss, iss_h), "services": (svc, svc_h), "regions": (reg, reg_h)}, {}


def assess(today, vals):
    seen = [v for v in vals if v is not None]
    if len(seen) < 3: return None
    a = sum(seen) / len(seen)
    if a == 0: return "normal" if not today else ("high" if today >= 20 else "watch")
    ch = (today - a) / a
    if today == 0 and a >= 10: return "watch"
    if abs(ch) >= .10 and (max(today, a) < 20 or abs(today - a) < 10): return "normal"
    if abs(ch) < .10: return "normal"
    if ch > 0: return "high" if ch >= .5 else "watch" if ch >= .25 else "info"
    return "watch" if ch <= -.5 else "good" if ch <= -.25 else "info"


def check_platform(platform):
    global T0
    d = api(f"/api/mgmt/{platform}")
    start = datetime.fromisoformat(d["day"]).replace(tzinfo=timezone.utc); T0 = start.timestamp()
    load = (lambda s: L.comms(db, C_NAMES, LAYOUT, s)) if platform == "comms" else (lambda s: L.services(db, S_NAMES, S_LABEL, s))
    exp = exp_comms if platform == "comms" else exp_svc
    t = time.time(); EV = load(start)
    print(f"\n== Executive, {platform}: day {d['day']}, {len(EV):,} records from MongoDB ({time.time()-t:.1f}s)")

    def keep(e, f):
        if platform == "comms":
            return all(not v or got == v for v, got in (
                (f.get("attack"), e["attack_class"]), (f.get("infection"), e["infection"] or "unknown"), (f.get("report"), e["source"]),
                (f.get("region"), L.title(e["src_region"])), (f.get("severity"), e["severity"])))
        return all(not v or got for v, got in (
            (f.get("family"), e["family"] == f.get("family")), (f.get("service"), e["service"] == f.get("service")),
            (f.get("issue"), f.get("issue") in e["issues"]), (f.get("region"), (L.title(e["region"]) or "Unknown region") == f.get("region")),
            (f.get("severity"), e["severity"] == f.get("severity"))))

    def one(label, f, dd=None, show=False):
        dd = dd or api(f"/api/mgmt/{platform}", f)
        ev = [e for e in EV if keep(e, f)]
        k, hours, lists, extra = exp(ev)
        diff = [f"{x} {dd['kpis'][x]:,}/{k[x]:,}" for x in k if dd["kpis"].get(x) != k[x]]
        if dd["hours"] != hours: diff.append("hours")
        for name, (cnt, hs) in lists.items():
            key = {"attack": "attack"}.get(name, name)
            for r in dd.get(key) or []:
                if cnt.get(r["value"]) != r["count"] or (hs is not None and "hosts" in r and len(hs.get(r["value"], ())) != r["hosts"]):
                    diff.append(f"{name} '{r['value']}' {r['count']}/{cnt.get(r['value'])}"); break
        if platform == "comms":
            for x in ("domains", "destinations"):
                if dd["c2"][x] != extra[x]: diff.append(f"c2 {x}")
        ok(label + f": {k.get('events', k.get('records')):,} " + ("events" if platform == "comms" else "records"), not diff, "; ".join(diff[:4]), show)
        return dd

    one("no filter", {}, d, show=True)
    facet_keys = ("attack", "infection", "report", "region", "severity") if platform == "comms" else ("family", "service", "issue", "region", "severity")
    for fk in facet_keys:
        vals = [v["value"] if isinstance(v, dict) else v for v in d["facets"].get(fk, [])]
        for v in (vals[:2] + vals[-1:]) if len(vals) > 2 else vals:
            one(f"{fk} = {v}", {fk: v})
    a, b_ = facet_keys[0], facet_keys[3]
    if d["facets"].get(a) and d["facets"].get(b_):
        va = d["facets"][a][0]; va = va["value"] if isinstance(va, dict) else va
        one(f"{a} = {va} & {b_} = {d['facets'][b_][0]}", {a: va, b_: d["facets"][b_][0]}, show=True)

    # 7-day baseline: every past day's figures against MongoDB, and the grade of every figure
    b = d.get("baseline") or {}
    if b.get("building"):
        print("   baseline still being built: waiting up to 5 minutes")
        for _ in range(30):
            time.sleep(10); d = api(f"/api/mgmt/{platform}"); b = d["baseline"]
            if not b.get("building"): break
    keys = list(b.get("kpis", {}))
    for i, day_s in enumerate(b.get("days", [])):
        got = {k: b["kpis"][k][i] for k in keys}
        s = datetime.fromisoformat(day_s).replace(tzinfo=timezone.utc)
        T0_save = T0
        globals()["T0"] = s.timestamp()
        k = exp(load(s))[0]
        globals()["T0"] = T0_save
        if all(v is None for v in got.values()):
            ok(f"baseline {day_s}: no reports", sum(k.values()) == 0 or k.get("events", k.get("records")) == 0, f"mongo has {k}")
            continue
        diff = [f"{x} {got[x]}/{k[x]}" for x in keys if x in k and got[x] != k[x]]
        ok(f"baseline {day_s}: " + ", ".join(f"{x} {got[x]:,}" for x in keys[:2]), not diff, "; ".join(diff[:4]), show=True)
    grades = b.get("assess", {}).get("kpis", {})
    bad = [k for k, g in grades.items() if (g or {}).get("level") != assess(d["kpis"].get(k, 0), b["kpis"][k])]
    ok(f"grades of {len(grades)} figures (Normal / Slight / Caution / Danger ...) recomputed", not bad, ", ".join(bad), show=True)
    ibad = [n for n, g in b.get("assess", {}).get("items", {}).items()
            if (g or {}).get("level") != assess(next(r["hosts"] for r in (d.get("infections") or d.get("issues")) if r["value"] == n), b["items"][n])]
    ok(f"grades of {len(b.get('assess', {}).get('items', {}))} top {'infections' if platform == 'comms' else 'issues'} recomputed", not ibad, ", ".join(ibad[:3]), show=True)


T0 = 0
for p in ("comms", "services"):
    check_platform(p)

# clickable "Top findings" combinations: the portal narrowed to one must count exactly its devices / hosts
print("\n== Clickable combinations")
LABEL = {s["name"]: s["label"] for s in diag["supported"]}
d0 = api("/api/mgmt/comms"); s0 = api("/api/mgmt/services")
start = datetime.fromisoformat(d0["day"]).replace(tzinfo=timezone.utc)
EV = L.comms(db, C_NAMES, LAYOUT, start); SV = L.services(db, S_NAMES, S_LABEL, start)
def exact(ev, ipk, items_of, want, skip_empty=True):
    sets = defaultdict(set)
    for e in ev:
        if e[ipk] or not skip_empty:
            sets[e[ipk]].update(items_of(e))
    ips = {ip for ip, s in sets.items() if " + ".join(sorted(s)) == want}
    return ips, [e for e in ev if (e[ipk] or not skip_empty) and e[ipk] in ips]


print(f"Executive, {d0['day']}: {len(EV):,} events and {len(SV):,} services records in MongoDB")
cases = [("comms", "icombo", d0["multi"]["combos"], "src_ip", lambda e: {e["infection"] or "unknown"}, EV, True, "devices", "multi"),
         ("comms", "rcombo", d0["cross"]["combos"], "src_ip", lambda e: {LABEL.get(e["source"], e["source"])}, EV, True, "devices", "cross"),
         ("services", "icombo", s0["multi"]["combos"], "ip", lambda e: set(e["issues"]), SV, False, "hosts", "multi"),
         ("services", "scombo", s0["cross"]["combos"], "ip", lambda e: {e["service"]}, SV, False, "hosts", "cross")]
for plat, key, rows, ipk, items_of, ev, skip, unit, part in cases:
    for r in rows[:3] + rows[-1:]:
        want = r["label"]
        ips, sel = exact(ev, ipk, items_of, want, skip)
        d = api(f"/api/mgmt/{plat}", [(key, want)])
        k = d["kpis"]
        n = k["devices"] if plat == "comms" else k["hosts"]
        recs = k["events"] if plat == "comms" else k["records"]
        rows_after = d[part]["combos"]
        ok(f"{plat} {key} '{want[:50]}': {n:,} {unit}, {recs:,} records",
           n == r["count"] == len(ips) and recs == len(sel) and len(rows_after) == 1 and rows_after[0]["label"] == want,
           f"row said {r['count']:,}, MongoDB {len(ips):,} {unit} / {len(sel):,} records, list now {[x['label'][:30] for x in rows_after][:3]}")
# with another filter on top: the combination inside one region
reg = d0["facets"]["region"][0]
top = d0["multi"]["combos"][0]["label"]
d = api("/api/mgmt/comms", [("region", reg)])
r_in = next((x for x in d["multi"]["combos"] if x["label"] == top), None)
ips, sel = exact([e for e in EV if L.title(e["src_region"]) == reg], "src_ip", lambda e: {e["infection"] or "unknown"}, top)
d2 = api("/api/mgmt/comms", [("region", reg), ("icombo", top)])
ok(f"region {reg} + icombo '{top}': {d2['kpis']['devices']:,} devices", r_in and d2["kpis"]["devices"] == r_in["count"] == len(ips), f"MongoDB {len(ips):,}")
d3 = api("/api/mgmt/comms", [("icombo", "no-such + combination")])
ok("a combination that does not exist gives an empty page", d3["kpis"]["devices"] == 0 and d3["kpis"]["events"] == 0)

print(f"\n{checks - len(fails)} of {checks} checks agree with MongoDB" + (f"; {len(fails)} FAILED: {fails[:6]}" if fails else ""))
sys.exit(1 if fails else 0)
