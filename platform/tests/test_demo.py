"""Smoke test: company names in normal mode, and that demo mode leaks no IPs, ASNs or company names."""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402

tm.store.get(tm.replay_now())
c = tm.app.test_client()
# every API needs a login now: use the local automation key (auth.py), as the other check scripts do
c.environ_base["HTTP_X_LG_AUTOMATION"] = open(os.path.join(tm.BASE_DIR, "data", "automation.key")).read().strip()
to = tm.iso(tm.replay_now())
real = c.get(f"/api/events?latest=1&limit=200&to={to}").get_json()["events"]
if not real:
    # the replay is still at 00:00 (a new day's report is settling): sample the whole loaded day instead
    to = tm.iso(tm.day_start(tm.replay_now()) + tm.timedelta(days=1) - tm.timedelta(seconds=1))
    real = c.get(f"/api/events?latest=1&limit=200&to={to}").get_json()["events"]
if not real:
    print("SKIPPED: no events loaded for the replay day yet (run it again once the day's reports are in)")
    sys.exit(77)
demo = c.get(f"/api/events?latest=1&limit=200&to={to}&demo=1").get_json()["events"]
e = real[-1]
print("normal:", e["src_ip"], "|", e["src_asn_name"], "->", e["dst_asn_name"])
d = demo[-1]
print("demo:  ", d["src_ip"], "|", d["src_asn"], "->", d["dst_asn"], "| hostname:", d["src_hostname"] or "-")

names = {v["name"] for v in tm.asn_registry.all().values()}
blob = json.dumps(demo) + json.dumps(c.get("/api/stats?demo=1").get_json())
leaks = []
ipv4_full = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", blob)
leaks += [f"ip {x}" for x in ipv4_full[:5]]
leaks += [f"name {n}" for n in names if len(n) > 4 and f'"{n}' in blob]
leaks += [f"asn {m}" for m in re.findall(r'"(?:src|dst)_asn": "(\d+)"', blob)[:5]]
print("demo leaks:", leaks or "none")

st = c.get("/api/stats").get_json()
print("src networks:", [(r["label"], r["count"], r["asns"]) for r in st["src_network"][:5]])
print("dst networks:", [(r["label"], r["count"]) for r in st["dst_network"][:4]])
std = c.get("/api/stats?demo=1").get_json()
print("src networks (demo):", [(r["label"], r["count"]) for r in std["src_network"][:5]])
print("hours_by_class keys:", list(st["hours_by_class"]), "current hour", st["current_hour"])
net_name = st["src_network"][min(1, len(st["src_network"]) - 1)]["value"] if st["src_network"] else ""   # a real network of the day
net_alias = std["src_network"][min(1, len(std["src_network"]) - 1)]["value"] if std["src_network"] else ""   # and an alias
for q in (f"kind=src_asn&value={net_name}", f"kind=src_asn&value={net_alias}&demo=1", f"kind=src_ip&value={e['src_ref']}&demo=1"):
    r = c.get("/api/insight?" + q).get_json()
    print(f"insight {q[:40]:40s} -> {r.get('value_label')} total={r.get('total')} asns={r.get('asns_covered')}")
    if "demo=1" in q:
        b = json.dumps(r)
        print("   leaks:", re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", b)[:3] or "none",
              [n for n in names if len(n) > 4 and n in b][:3] or "none")
