"""Build / update data/asns.json: one entry per network (AS number) seen in the data, with its company and type.

Usage:  .venv/bin/python manage/asn_registry.py [days]       (default: the last 7 days)

The same look-up as Settings > Identify networks (asn_lookup.py): PeeringDB for the network's brand name and type,
RIPEstat for the registered holder of every AS number (free public sources; only AS numbers are sent).
* Collects every AS number in the last N days of both platforms (read-only against MongoDB).
* Networks already in data/asns.json are skipped; entries you edit by hand (reviewed=true) are never overwritten.
  Set "name" to the brand you want shown, e.g. "Example Telecom", and "reviewed": true.
* "demo_alias" (Telco N, Institution N, Provider N...) is assigned once and kept stable (--reset-aliases renumbers).
* Prints the networks ranked by events so you can review the important ones first.
"""
import os
import sys
from collections import Counter
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as tm  # noqa: E402
import asn_lookup  # noqa: E402

PATH = os.path.join(tm.BASE_DIR, "data", "asns.json")
args = [a for a in sys.argv[1:] if not a.startswith("--")]
days = int(args[0]) if args else 7

today = tm.day_start(tm.utcnow())
count, meta = Counter(), {}
for back in range(days, 0, -1):
    d = tm.store._load(today - timedelta(days=back))
    for e in d.events:
        for s, role in (("src", "source"), ("dst", "destination")):
            a = (e[f"{s}_asn"] or "").strip()
            if a.isdigit():
                count[a] += 1
                meta.setdefault(a, {"country": e[f"{s}_geo"], "roles": set()})["roles"].add(role)
    d = tm.svc["store"]._load(today - timedelta(days=back))
    for e in d.events:
        a = (e["asn"] or "").strip()
        if a.isdigit():
            count[a] += 1
            meta.setdefault(a, {"country": e["geo"], "roles": set()})["roles"].add("service")
for m in meta.values():
    r = m.pop("roles")
    m["role"] = "both" if {"source", "destination"} <= r else (next(iter(r)) if len(r) == 1 else "both")

if "--reset-aliases" in sys.argv:
    reg = asn_lookup.load(PATH)
    for v in reg["asns"].values():
        v.pop("demo_alias", None)
    asn_lookup.save(PATH, reg)

last = {}


def progress(st):
    if st["log"] and st["log"][-1] != last.get("line"):
        print("  " + st["log"][-1], flush=True)
        last["line"] = st["log"][-1]


st = asn_lookup.identify(PATH, count, meta, progress=progress)
reg = asn_lookup.load(PATH)
asns = reg["asns"]
print(f"\n{len(count)} networks seen in {days} days. {st['message']} Registry: {len(asns)} entries -> {PATH}\n")
for a, n in count.most_common():
    v = asns.get(a, {})
    print(f"AS{a:<7} {n:>7,}  {v.get('country', ''):2s} {v.get('role', ''):11s} {'*' if v.get('reviewed') else ' '} "
          f"{v.get('name', '')[:38]:38s} {v.get('type', ''):11s} | {v.get('holder', '')[:50]}  [{v.get('demo_alias', '')}]")
