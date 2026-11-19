#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Drop-down counts that follow the other filters (facets.py; the user, 2026-11-19), on made-up records, no database:
each filter's choices are counted over the records matching every OTHER filter, checked against a plain count of the
same records for many random filter sets; the map page asks again when a filter changes and keeps chosen values.
Usage: tests/check_facet_counts.py"""
import os
import random
import sys
from collections import Counter

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import facets  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


FIELDS = {"source": ["r1", "r2", "r3"], "src_city": ["Alpha", "Beta", "Gamma", ""], "tag": ["a", "b"],
          "dst_port": [23, 80, 443], "beacon": ["x", "y"]}
rnd = random.Random(7)
events = [{f: rnd.choice(v) for f, v in FIELDS.items()} for _ in range(3000)]


def value(e, f):
    return e.get(f)


def brute(flt, field):
    """The records matching every filter except `field`'s own."""
    return [e for e in events if all(value(e, f) in vals for f, vals in flt.items() if f != field)]


print("1. Each field counted over the records matching every OTHER filter")
p0 = facets.pools(events, {}, value)
ok("no filter: every field counts the whole day", p0.of("tag") is events and p0.total == len(events))
bad = 0
for trial in range(200):
    flt = {}
    for f, v in FIELDS.items():
        if rnd.random() < .45:
            flt[f] = set(rnd.sample(v, rnd.randint(1, len(v))))
    p = facets.pools(events, flt, value)
    if p.total != len(brute(flt, None)):
        bad += 1
    for field in FIELDS:
        if Counter(e[field] for e in p.of(field)) != Counter(e[field] for e in brute(flt, field)):
            bad += 1
ok("200 random filter sets: every field's counts equal a plain count of the same records", bad == 0, f"{bad} differ")
flt = {"src_city": {"Alpha"}, "tag": {"a"}}
p = facets.pools(events, flt, value)
cities = Counter(e["src_city"] for e in p.of("src_city"))
ok("a filter's own choice does not hide its alternatives (other cities still counted)", len(cities) > 1)
ok("…while the other filters narrow them (only tag a)", all(e["tag"] == "a" for e in p.of("src_city")))
ok("…and every other field is counted over the records matching both",
   all(e["src_city"] == "Alpha" and e["tag"] == "a" for e in p.of("source")))

print("2. The service and the map page")
src = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
ok("/api/facets reads the filters and caches per filter set",
   "flt = parse_filters(request.args)" in src and 'beacons, filters_key(flt))' in src and "_facets_core(day, demo, beacons, flt)" in src)
ok("…every field, the networks and the beacons use the other filters' records",
   "for e in pool.of(field)" in src and 'pool.of(f"{side}_asn")' in src and 'facet_rows(pool.of("beacon"))' in src)
ok("…the beacon filter is matched on its label, as the records are", 'beacon_stats.label(e) if f == "beacon" else e.get(f)' in src)
S = os.environ.get("LG_HELD_DIR", "")
js_path = os.path.join(S, "app.js.new") if S and os.path.exists(os.path.join(S, "app.js.new")) else os.path.join(HERE, "static", "js", "app.js")
js = open(js_path, encoding="utf-8").read()
ok("the map page asks with the filters, again whenever one changes, dropping slower older answers",
   "p = filterParams()" in js and "loadGeo(true); loadFacets(); }, 250)" in js and "if (my !== loadFacets.seq) return;" in js)
ok("…a chosen value with nothing left is still listed (0), so it can be taken off", "function withChosen(rows, key)" in js
   and js.count("withChosen(") >= 12)
ok("…the focused box or button keeps the keyboard focus when the lists are rebuilt", "keepFocus(buildFilters)" in js
   and "cb.dataset.fk" in js and "b.dataset.fk = key" in js)

print("3. The services platform: list filters (tags, issues) and its page")
import services as SV  # noqa: E402
TAGS, ISS = ["t1", "t2", "t3"], ["CVE-2099-0001", "weak-tls", "old-ssh"]
sevs = [{"service": rnd.choice(["Accessible HTTP", "Open DNS"]), "city": rnd.choice(["Alpha", "Beta"]),
         "tags": rnd.sample(TAGS, rnd.randint(0, 2)), "issues": rnd.sample(ISS, rnd.randint(0, 2)), "ip": f"192.0.2.{i % 50}"}
        for i in range(2000)]
bad = 0
for trial in range(150):
    flt = {}
    for f, v in (("service", ["Accessible HTTP", "Open DNS"]), ("city", ["Alpha", "Beta"]), ("tag", TAGS), ("issue", ISS)):
        if rnd.random() < .5:
            flt[f] = set(rnd.sample(v, rnd.randint(1, len(v))))
    p = facets.pools(sevs, flt, test=lambda e, f, vals: SV.matches(e, {f: vals}))
    for field in ("service", "city", "tag", "issue"):
        want = [e for e in sevs if SV.matches(e, {f: v for f, v in flt.items() if f != field})]
        if sorted(map(id, p.of(field))) != sorted(map(id, want)):
            bad += 1
ok("150 random filter sets with list filters: each list counted over the records matching the other filters", bad == 0, f"{bad} differ")
ssrc = open(os.path.join(HERE, "services_api.py"), encoding="utf-8").read()
ok("/api/svc/facets counts per choice of filters (cached per set)", "facet_counts(day, request.args, demo)" in ssrc
   and "region_version(), cache_args(request.args))" in ssrc)
ok("…several reports / multiple issues: the chosen hosts' records, following the filters added after",
   "def facet_scope(day, args)" in ssrc and "seed_flt, flt = split_cross(args)" in ssrc and "ips = seed_hosts(day, cross, multi, seed_flt)" in ssrc)
ok("…each list the filter it sets (Network is asn)", '"network": "asn"' in ssrc and "breakdowns(pool.of(f), demo, 400)[name] if f in flt" in ssrc)
sjs_path = os.path.join(S, "services.js.new") if S and os.path.exists(os.path.join(S, "services.js.new")) else os.path.join(HERE, "static", "js", "services.js")
sjs = open(sjs_path, encoding="utf-8").read()
ok("the services page asks with the filters when one changes, keeps chosen values and the focus",
   "/api/svc/facets?${p}" in sjs and "setTimeout(loadFacets, 250)" in sjs and "function withChosen(rows, key)" in sjs
   and "keepFocus(buildFilters)" in sjs)
ok("…the report list shows each report's records in the selection", "inSel.get(r.label)" in sjs)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
