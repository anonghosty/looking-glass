#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Settings → Constituency: pick address blocks from the reports (address_blocks.py; the user, 2026-11-19), on made-up
records (documentation addresses), no database: blocks counted before the constituency, the country's side only, the
network most records belong to, blocks already in the constituency marked, administrators only, and the page's list.
Usage: tests/check_address_blocks.py"""
import ipaddress
import os
import sys
from types import SimpleNamespace

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
import address_blocks as AB  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. Blocks")
ok("an IPv4 address: its /24", AB.block_of("192.0.2.77") == "192.0.2.0/24")
ok("an IPv6 address: its /48", AB.block_of("2001:db8:1:2::5") == "2001:db8:1::/48")
ok("not an address: nothing", AB.block_of("example.org") == "" and AB.block_of("") == "" and AB.block_of("300.1.1.1") == "")

print("2. Counted per loaded day, the country's side only")
rows = [{"src_ip": "192.0.2.10", "src_asn": "64500", "src_geo": "GH", "dst_ip": "198.51.100.1", "dst_asn": "64999", "dst_geo": "NL"},
        {"src_ip": "192.0.2.11", "src_asn": "64500", "src_geo": "GH", "dst_ip": "", "dst_asn": "", "dst_geo": ""},
        {"src_ip": "203.0.113.5", "src_asn": "64501", "src_geo": "GH", "dst_ip": "", "dst_asn": "", "dst_geo": ""}]
t = AB.tally(rows, (("src_ip", "src_asn", "src_geo"), ("dst_ip", "dst_asn", "dst_geo")), "GH")
ok("the country's hosts counted per block and network", t[("192.0.2.0/24", "64500")] == 2 and t[("203.0.113.0/24", "64501")] == 1)
ok("…a foreign side (a sinkhole abroad) is not offered", not any(b == "198.51.100.0/24" for b, _ in t))
svc = AB.tally([{"ip": "192.0.2.12", "asn": "64502", "geo": "GH"}], (("ip", "asn", "geo"),), "GH")
ok("the services platform: its host", svc[("192.0.2.0/24", "64502")] == 1)
src = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
ssrc = open(os.path.join(HERE, "services.py"), encoding="utf-8").read()
ok("both day loaders count them before the constituency applies",
   src.index("_address_blocks.tally(rows") < src.index("if settings.restricted:\n                rows = [e for e in rows")
   and ssrc.index("address_blocks.tally(rows") < ssrc.index("if st is not None and st.restricted:\n                rows = ")
   and "day.block_raw" in src and "day.block_raw" in ssrc)

print("3. The list")
d1 = SimpleNamespace(block_raw=t)
d2 = SimpleNamespace(block_raw=svc)
st = SimpleNamespace(restricted=True, asns={"64501"}, nets=[ipaddress.ip_network("192.0.2.0/23")])
covered = lambda blk, asn: (asn in st.asns) or any(ipaddress.ip_network(blk).subnet_of(n) for n in st.nets)  # noqa: E731
out, total = AB.listing([d1, d2], lambda a: {"64500": "Example Telecom", "64501": "Example University"}.get(a, f"AS{a}"), covered)
by = {r["block"]: r for r in out}
ok("both platforms added up, busiest first", by["192.0.2.0/24"]["records"] == 3 and out[0]["block"] == "192.0.2.0/24" and total == 2)
ok("…with the network most of its records belong to", by["192.0.2.0/24"]["asn"] == "64500" and by["192.0.2.0/24"]["network"] == "Example Telecom")
ok("…a block already in the constituency is marked (by its network or a range)",
   by["203.0.113.0/24"]["covered"] is True and by["192.0.2.0/24"]["covered"] is True)

print("4. Administrators only")
from flask import Flask  # noqa: E402
app = Flask(__name__)
perm = {"v": False}
api = AB.install(app, {"has_perm": lambda p: perm["v"] and p == "settings", "settings": st, "days": lambda: [d1, d2],
                       "company": lambda a: f"AS{a}", "day": lambda: "2099-01-01"})
c = app.test_client()
ok("no settings permission: refused", c.get("/api/settings/address-blocks").status_code == 403)
perm["v"] = True
j = c.get("/api/settings/address-blocks").get_json()
ok("an administrator gets the blocks", j and j["shown"] == 2 and j["blocks"][0]["block"] == "192.0.2.0/24")
st2 = SimpleNamespace(restricted=False, asns=set(), nets=[])
api2 = AB.install(Flask("b"), {"has_perm": lambda p: True, "settings": st2, "days": lambda: [], "company": str, "day": lambda: ""})
ok("whole country (no constituency): nothing marked as already in", api2["covered"]("192.0.2.0/24", "64500") is False)
fsrc = open(os.path.join(HERE, "features.py"), encoding="utf-8").read()
ok("installed from features.py, with the network names (asns) from app.py", "address_blocks.install(app" in fsrc and '"asns": asn_registry' in src)

print("5. The Settings page")
S = os.environ.get("LG_HELD_DIR", "")
pick = lambda name, live: os.path.join(S, name + ".new") if S and os.path.exists(os.path.join(S, name + ".new")) else live  # noqa: E731
html = open(pick("settings.html", os.path.join(HERE, "templates", "settings.html")), encoding="utf-8").read()
jsp = pick("address-blocks.js", os.path.join(HERE, "static", "js", "address-blocks.js"))
js = open(jsp, encoding="utf-8").read() if os.path.exists(jsp) else ""
ok("a 'Pick address blocks from the reports' list under the extra address ranges, with a search",
   'id="blockPick"' in html and 'id="blockSearch"' in html and "js/address-blocks.js" in html)
ok("ticking adds the block to the extra address ranges and unticking takes it off (saved with Apply settings)",
   "setLines(cb.checked ? [...cur, r.block] : cur)" in js and 'new Event("input"' in js)
ok("…each box says what it adds (for screen readers)", 'cb.setAttribute("aria-label", `Add ${r.block}' in js)
ok("…no outside look-up: only this server's list", js.count("fetch(") == 1 and '"/api/settings/address-blocks"' in js)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
