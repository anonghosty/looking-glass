"""Smoke test: build the source registry, load the replay day from all collections, hit the APIs."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["TRUST_PROXY"] = "0"     # the app is called in-process, not through a reverse proxy (proxy_guard.py)
import app as tm  # noqa: E402

t = time.time()
srcs = tm.registry.get()
print(f"registry: {len(srcs)} collections in {time.time() - t:.1f}s")
for s in srcs:
    print(f"  {s['name']:34s} {s['layout']:9s} {s['class']:15s} fn_idx={s['filename_index']}  {s['label']}")
t = time.time()
day = tm.store.get(tm.replay_now())
print(f"day {day.start.date()}: {len(day.events)} events in {time.time() - t:.1f}s; per source {day.per_source}")
# every API needs a login: use the local automation key (data/automation.key), as the other check scripts do
try:
    with open(os.path.join(tm.BASE_DIR, "data", "automation.key")) as f:
        KEY = f.read().strip()
except OSError:
    sys.exit("data/automation.key not found: start the service once so it is created")
c = tm.app.test_client()
c.environ_base.update({"REMOTE_ADDR": "127.0.0.1", "HTTP_X_LG_AUTOMATION": KEY})
r = c.get("/api/stats")
if r.status_code != 200:
    sys.exit(f"/api/stats answered {r.status_code}: {r.get_data(as_text=True)[:200]}")
st = r.get_json()
print("stats total", st["total"], "sources", st["unique_sources"], "multi-source hosts", st["multi_source_hosts"])
print("  attack_class", st["attack_class"])
top_city = next((e["src_city"] for e in day.events if e.get("src_city")), "")   # any city of the day, not one country's
for kind, value in (("source", "event4_honeypot_brute_force"), ("attack_class", "Brute force"), ("src_city", top_city)):
    r = c.get(f"/api/insight?kind={kind}&value={value}").get_json()
    print(f"\ninsight {kind}={value}: total {r['total']} reports {r['reports']} cross {r['cross_report_hosts']}")
    for s in r["insights"]:
        print("  -", s)
    print("  breakdown keys:", list(r["breakdowns"]))
bf = next((e for e in day.events if e["source"] == "event4_honeypot_brute_force"), None)
if bf:
    print("\nbrute force sample:", json.dumps({k: bf[k] for k in ("src_ip", "src_city", "dst_geo", "dst_port", "infection", "severity", "attack_class", "dst_coords")}))
    print("  extras:", json.dumps(bf["extras"])[:500])
dns = next((e for e in day.events if e["source"] == "event4_sinkhole_dns"), None)
if dns:
    print("dns sample extras:", json.dumps(dns["extras"])[:300], "dst_coords", dns["dst_coords"])
