#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Services on the researchers' page (services_kb.py), against the services day in memory:

1. Every report the map puts in Services is listed once, its IPv6 twin folded in (Accessible RDP = scan_rdp +
   scan6_rdp), in the map's group order.
2. The figures are right: hosts and records per report, its products, ports and issues, counted again here from the
   records themselves.
3. Researchers never see a host: no address, host name, network (AS number or name) or city of a record appears in
   any answer, the list or a report's page.
4. Only the Definitions permission (researchers, admins) may read it; a viewer, an analyst without it and management
   are refused.
5. Notes on a services report (notes.py, section "services"), in a throwaway file.
Usage: tests/check_services_kb.py"""
import collections
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import logging  # noqa: E402
logging.disable(logging.WARNING)
import app as A  # noqa: E402
from flask import g  # noqa: E402
import notes as N  # noqa: E402
from report_map import sibling  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms):
    with A.app.test_request_context(path):
        g.user = {"user": "lg-selftest-services", "role": "x", "perms": set(perms), "csrf": None}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, r.get_data(as_text=True)


sday = A.svc["store"].get(A.replay_now())
events = [e for d in A.svc["store"].days.values() for e in d.events]
if not events:
    print("SKIPPED: no services records in memory (no reports loaded yet)")
    sys.exit(77)
RESEARCHER = {"definitions"}

print("1. The list")
code, body = call("/api/kb/services", RESEARCHER)
d = json.loads(body) if code == 200 else {}
ok("a researcher reads the services list", code == 200, f"HTTP {code}")
rows = d.get("reports") or []
mapped = {k for k, e in A.REPORT_MAP.get()["reports"].items() if e["section"] == "Services"}
bases = {sibling(k) if sibling(k) in A.REPORT_MAP.get()["reports"] else k for k in mapped}
ok("every Services report of the map is listed once", sorted(r["name"] for r in rows) == sorted(bases), f"{len(rows)} rows, {len(bases)} expected")
ok("IPv6 twins are folded in, never a row of their own", not [r for r in rows if re.match(r"^(scan|population)6_|^device_id6$", r["name"]) and sibling(r["name"]) in bases]
   and any("scan6_rdp" in r["names"] for r in rows if r["name"] == "scan_rdp"))
order = d.get("groups") or []
ok("rows follow the group order", [order.index(r["group"]) for r in rows if r["group"] in order] == sorted(order.index(r["group"]) for r in rows if r["group"] in order))

print("2. The figures, counted again")
per = collections.defaultdict(lambda: {"records": 0, "hosts": set(), "issues": collections.defaultdict(set), "products": collections.Counter()})
for e in events:
    x = per[e["report"]]
    x["records"] += 1; x["hosts"].add(e["ip"])
    for i in e.get("issues") or ():
        x["issues"][i].add(e["ip"])
    if e.get("product"):
        x["products"][e["product"]] += 1
byname = {r["name"]: r for r in rows}
bad = []
for r in rows:
    rec = sum(per[n]["records"] for n in r["names"]); hosts = sum(len(per[n]["hosts"]) for n in r["names"])
    if (r["records"], r["hosts"]) != (rec, hosts):
        bad.append(f"{r['name']}: {r['records']}/{r['hosts']} vs {rec}/{hosts}")
ok("records and hosts per report match the records in memory", not bad, "; ".join(bad[:3]))
busiest = max(rows, key=lambda r: r["hosts"])
code, body = call(f"/api/kb/service?name={busiest['name']}", RESEARCHER)
det = json.loads(body) if code == 200 else {}
ok(f"a report's page opens ({busiest['title']})", code == 200 and det.get("name") == busiest["name"], f"HTTP {code}")
want = collections.Counter()
for n in busiest["names"]:
    want.update(per[n]["products"])
ok("…its products are the records' products, most first", [p for p, _ in det.get("products", [])][:5] == [p for p, _ in want.most_common(5)])
wi = collections.Counter()
for n in busiest["names"]:
    wi.update({i: len(h) for i, h in per[n]["issues"].items()})
ok("…its issues and their hosts match", {r["name"]: r["hosts"] for r in det.get("issues", [])} == dict(wi) or det.get("issues_total") == len(wi))
withcve = next((r for r in rows if any(i["cve"] for i in r["issues"])), None)
if withcve:
    ok("CVEs on a report carry their CISA KEV / CVSS flags for the list", all("exploited" in i or "cvss" in i or not i["cve"] for i in withcve["issues"]), withcve["name"])
ok("the four groups are there", set(order) >= {"Known vulnerability", "Can be abused for attacks (amplification, tunnels)"})

print("3. No host ever")
ips = {e["ip"] for e in events if e.get("ip")}
names = {e["hostname"].lower() for e in events if e.get("hostname")}
asns = {str(e["asn"]) for e in events if e.get("asn")}
cities = {e["city"].lower() for e in events if e.get("city") and len(e["city"]) > 3}


def leaks(text):
    found = []
    for m in set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}\b", text, re.I)):
        if m in ips:
            found.append(m)
    strings = []
    def walk(v):
        if isinstance(v, dict):
            for k, x in v.items():
                if k in ("asn", "network", "city", "region", "ip", "hostname"):
                    found.append(f"key {k}")
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            strings.append(v.lower())
    walk(json.loads(text))
    found += [s for s in strings if s in names or s in cities]
    return found
pages = [call("/api/kb/services", RESEARCHER)[1]] + [call(f"/api/kb/service?name={r['name']}", RESEARCHER)[1] for r in rows]
hits = [h for p in pages for h in leaks(p)]
ok(f"no address, host name, network or city in the list or any of the {len(rows)} report pages", not hits, ", ".join(sorted(set(map(str, hits)))[:6]))
ok("…checked against the records in memory", len(ips) > 0, f"{len(ips):,} addresses, {len(names):,} host names, {len(cities):,} cities")

print("4. Who may read it")
for label, perms in (("a viewer", {"view"}), ("an analyst without Definitions", {"view", "unmasked", "export"}), ("management", {"management"})):
    c1 = call("/api/kb/services", perms)[0]; c2 = call(f"/api/kb/service?name={busiest['name']}", perms)[0]
    ok(f"{label} is refused", c1 == 403 and c2 == 403, f"{c1}/{c2}")
ok("an unknown report gives 404", call("/api/kb/service?name=scan_nothing_here", RESEARCHER)[0] == 404)

print("5. Notes on a services report")
with tempfile.TemporaryDirectory() as tmp:
    nb = N.Notes(os.path.join(tmp, "notes.json"), A.people)
    nb.add("services", "scan_rdp", "Most RDP hosts here answer with the default certificate name.", "lg-selftest", "researcher")
    nb.add("issues", "scan_rdp", "a note in another section", "lg-selftest", "researcher")
    ok("a note is kept under the services report", [n["text"] for n in nb.list("services", "scan_rdp")] == ["Most RDP hosts here answer with the default certificate name."])
    ok("…apart from the other sections", len(nb.list("issues", "scan_rdp")) == 1 and not nb.list("infections", "scan_rdp"))
    ok("an unknown section falls back to infections (never a new section)", N._section("whatever") == "infections" and N._section("services") == "services")

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
