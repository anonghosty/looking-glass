#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Settings: address blocks for the constituency (address_blocks.py), on made-up records (documentation addresses), no
database: blocks counted before the constituency, the country's side only, the network most records belong to, blocks
already in the constituency marked, one network's blocks and the saved ranges that are blocks, administrators only, and
the page's one picker (the Constituent column of Network names & types; the user's design, 2026-11-21).
Usage: tests/check_address_blocks.py   (LG_HELD_DIR=<folder>: check the held .new page files)"""
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

print("5. One network's blocks, and the saved ranges that are blocks (the Constituent column's Some address blocks)")
rows_n, total_n = AB.of_network([d1, d2], "64500")
ok("a network's blocks: those most of whose records are in it, with all their records",
   [r["block"] for r in rows_n] == ["192.0.2.0/24"] and rows_n[0]["records"] == 3 and total_n == 1)
ok("…a network that is never the main one of a block has none", AB.of_network([d1, d2], "64502") == ([], 0))
busy = SimpleNamespace(block_raw={("192.0.2.0/24", "64500"): 5, ("192.0.3.0/24", "64500"): 9, ("192.0.4.0/24", "64500"): 1})
ok("…busiest first", [r["block"] for r in AB.of_network([busy], "64500")[0]] == ["192.0.3.0/24", "192.0.2.0/24", "192.0.4.0/24"])
cnt, own = AB.summary([d1, d2], [ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/22"),
                                 ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("192.0.2.7/32")])
ok("blocks per network", cnt == {"64500": 1, "64501": 1}, cnt)
ok("a saved range that is exactly a block belongs to that block's network; a wider or narrower range does not (Other address ranges)",
   own == {"192.0.2.0/24": "64500", "203.0.113.0/24": "64501"}, own)
perm["v"] = False
ok("one network's blocks and the summary: administrators only",
   c.get("/api/settings/address-blocks?asn=64500").status_code == 403 and c.get("/api/settings/address-blocks?summary=1").status_code == 403)
perm["v"] = True
j = c.get("/api/settings/address-blocks?asn=64500").get_json()
ok("API: one network's blocks", j and j["asn"] == "64500" and j["total"] == 1 and j["blocks"] == [{"block": "192.0.2.0/24", "records": 3}], j)
ok("API: an AS number is digits only", c.get("/api/settings/address-blocks?asn=AS64500").status_code == 400
   and c.get("/api/settings/address-blocks?asn=1;drop").status_code == 400)
j = c.get("/api/settings/address-blocks?summary=1").get_json()
ok("API: the summary (the saved /23 is wider than a block: no network)", j and j["counts"] == {"64500": 1, "64501": 1} and j["owners"] == {}, j)

print("6. The Settings page: one picker in Network names & types (held .new files when LG_HELD_DIR is set)")
S = os.environ.get("LG_HELD_DIR", "")
pick = lambda name, live: os.path.join(S, name + ".new") if S and os.path.exists(os.path.join(S, name + ".new")) else live  # noqa: E731
rd = lambda p: open(p, encoding="utf-8").read() if os.path.exists(p) else ""  # noqa: E731
html = rd(pick("settings.html", os.path.join(HERE, "templates", "settings.html")))
card = rd(pick("_net_card.html", os.path.join(HERE, "templates", "_net_card.html")))
js = rd(pick("address-blocks.js", os.path.join(HERE, "static", "js", "address-blocks.js")))
nj = rd(pick("net-editor.js", os.path.join(HERE, "static", "js", "net-editor.js")))
sj = rd(pick("settings.js", os.path.join(HERE, "static", "js", "settings.js")))
scope = html.split('id="cardScope"', 1)[1].split("</section>", 1)[0] if 'id="cardScope"' in html else ""
ok("the Constituency card keeps the mode choice and a live summary line",
   'data-mode="all"' in scope and 'data-mode="some"' in scope and 'id="scopeSummary"' in scope)
ok("…and its wording on where it applies (only the quarterly purge works on the whole database)",
   "Only the quarterly purge works on the whole database" in scope)
ok("…without its own network list, search, extra ranges box or pick-blocks list",
   all(x not in html for x in ('id="netTable"', 'id="netSearch"', 'id="blockPick"', 'id="blockSearch"', "Pick address blocks",
                                "Extra address ranges", 'id="someBox"')))
ok("address-blocks.js loads before settings.js (settings.js asks it which saved ranges are blocks)",
   0 <= html.find("js/address-blocks.js") < html.find("js/settings.js"))
ok("the Constituent column is a drop-down with the three choices",
   '["out", "Not in"]' in nj and '["whole", "The whole network"]' in nj and '["some", "Some address blocks"]' in nj
   and 'el("select", "nb-pick lg-enhance")' in nj and '"Constituent"' in nj)   # lg-enhance: the Looking Glass drop-down
ok("…Some address blocks opens the row in place (an expansion row under it, across the table)",
   'el("tr", "nb-row")' in nj and "tr.after(prow)" in nj and "c.colSpan = 8" in nj and "window.LGBlocks.panel(" in nj)
ok("…the row's toggle says what is chosen and has aria-expanded; the table's scroll area grows while a row is open",
   'tog.setAttribute("aria-expanded"' in nj and "chosenText(" in nj and '"nb-grow"' in nj
   and "of ${plural(total, \"block\")} chosen" in js)
ok("…the focus stays on the network's choice, or goes back to its toggle when the blocks are closed",
   "?.focus(); return; }" in nj and "sync(); tog.focus();" in nj)
ok("…read only (no Settings permission): the choice in words, without controls", "if (!C.writable())" in nj
   and '"The whole network" : s === "some" ? `Some address blocks: ' in nj and "readOnly = !data.writable" in sj)
ok("the blocks: busiest first with their records, a search, the full list on demand, a labelled tick box each",
   "Show all ${plural(hits.length, \"block\")}" in js and 'plural(r.records, "record")' in js
   and 'q.setAttribute("aria-label", `Search the address blocks of' in js and 'lab.append(cb,' in js)
ok("…the loading animation while a network's list is asked for the first time", 'L?.busy?.("Loading the address blocks")' in js
   and "L?.ready?.()" in js)
ok("…no outside look-up: only this server's list", js.count("fetch(") == 1 and 'const API = "/api/settings/address-blocks"' in js
   and "?asn=" in js and "?summary=1" in js)
ok("Other address ranges: a box under the table, in the read-only (Settings) card only",
   "{% if readonly %}" in card.split('id="netEdTable"', 1)[-1] and 'id="cidrs"' in card and "Other address ranges" in card)
ok("Identify networks moved to the network list", 'id="btnIdentify"' in card and 'id="unknownCount"' in card)
ok("the live summary: N networks, M address blocks, K other ranges (singular and plural)",
   '${plural(k.nets, "network")}, ${plural(k.blocks, "address block")}, ${plural(k.other, "other range")}' in sj
   and "n === 1 ? one : (many || `${one}s`)" in sj)
ok("saved as before: whole networks as AS numbers, chosen blocks and other ranges as address ranges, with Apply settings",
   'networks: mode === "some" ? [...chosen].sort() : []' in sj and 'uniqSorted([...blockList(), ...cidrList()])' in sj
   and 'fetch("/api/settings", { method: "POST"' in sj and "body: JSON.stringify(w)" in sj)
ok("loading: a saved range that is a network's block shows as that network's chosen block, the rest as other ranges",
   "const a = blockInfo.owners[c];" in sj and "pickSet(String(a)).add(c)" in sj and '$("cidrs").value = other.join("\\n")' in sj)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
