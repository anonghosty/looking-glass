#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
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

print("2. Counted per loaded day, both sides of a record (like the Records column)")
rows = [{"src_ip": "192.0.2.10", "src_asn": "64500", "src_geo": "GH", "dst_ip": "198.51.100.1", "dst_asn": "64999", "dst_geo": "NL"},
        {"src_ip": "192.0.2.11", "src_asn": "64500", "src_geo": "GH", "dst_ip": "", "dst_asn": "", "dst_geo": ""},
        {"src_ip": "203.0.113.5", "src_asn": "64501", "src_geo": "GH", "dst_ip": "", "dst_asn": "", "dst_geo": ""}]
t = AB.tally(rows, (("src_ip", "src_asn"), ("dst_ip", "dst_asn")))
ok("hosts counted per block and network", t[("192.0.2.0/24", "64500")] == 2 and t[("203.0.113.0/24", "64501")] == 1)
ok("…the other side of a communication too, whatever its country (r90: a network with records has blocks to choose)",
   t[("198.51.100.0/24", "64999")] == 1)
svc = AB.tally([{"ip": "192.0.2.12", "asn": "64502", "geo": "GH"}], (("ip", "asn"),))
ok("the services platform: its host", svc[("192.0.2.0/24", "64502")] == 1)
src = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
ssrc = open(os.path.join(HERE, "services.py"), encoding="utf-8").read()
ok("both day loaders count them before the constituency applies, both sides on network communications",
   src.index("_address_blocks.tally(rows") < src.index("if settings.restricted:\n                rows = [e for e in rows")
   and ssrc.index("address_blocks.tally(rows") < ssrc.index("if st is not None and st.restricted:\n                rows = ")
   and '(("src_ip", "src_asn"), ("dst_ip", "dst_asn"))' in src and "day.block_raw" in src and "day.block_raw" in ssrc)

print("3. The list")
d1 = SimpleNamespace(block_raw=t)
d2 = SimpleNamespace(block_raw=svc)
st = SimpleNamespace(restricted=True, asns={"64501"}, nets=[ipaddress.ip_network("192.0.2.0/23")])
covered = lambda blk, asn: (asn in st.asns) or any(ipaddress.ip_network(blk).subnet_of(n) for n in st.nets)  # noqa: E731
out, total = AB.listing([d1, d2], lambda a: {"64500": "Example Telecom", "64501": "Example University"}.get(a, f"AS{a}"), covered)
by = {r["block"]: r for r in out}
ok("both platforms added up, busiest first", by["192.0.2.0/24"]["records"] == 3 and out[0]["block"] == "192.0.2.0/24" and total == 3)
ok("…with the network most of its records belong to", by["192.0.2.0/24"]["asn"] == "64500" and by["192.0.2.0/24"]["network"] == "Example Telecom")
ok("…a block already in the constituency is marked (by its network or a range)",
   by["203.0.113.0/24"]["covered"] is True and by["192.0.2.0/24"]["covered"] is True)

print("4. Administrators only")
from flask import Flask  # noqa: E402
app = Flask(__name__)
perm = {"v": False}
old = SimpleNamespace(block_raw={("198.18.5.0/24", "64500"): 4})          # an earlier day still in memory
api = AB.install(app, {"has_perm": lambda p: perm["v"] and p == "settings", "settings": st, "days": lambda: [d1, d2],
                       "all_days": lambda: [old, d1, d2], "company": lambda a: {"64999": "Example Cloud"}.get(a, f"AS{a}"),
                       "day": lambda: "2099-01-01"})
c = app.test_client()
ok("no settings permission: refused", c.get("/api/settings/address-blocks").status_code == 403)
perm["v"] = True
j = c.get("/api/settings/address-blocks").get_json()
ok("an administrator gets the blocks", j and j["shown"] == 3 and j["blocks"][0]["block"] == "192.0.2.0/24")
st2 = SimpleNamespace(restricted=False, asns=set(), nets=[])
api2 = AB.install(Flask("b"), {"has_perm": lambda p: True, "settings": st2, "days": lambda: [], "company": str, "day": lambda: ""})
ok("whole country (no constituency): nothing marked as already in", api2["covered"]("192.0.2.0/24", "64500") is False)
fsrc = open(os.path.join(HERE, "features.py"), encoding="utf-8").read()
ok("installed from features.py, with the network names (asns) from app.py, and every day in memory (all_days)",
   "address_blocks.install(app" in fsrc and '"asns": asn_registry' in src and '"all_days": blocks_all_days' in fsrc
   and "for s in (store, svc_store) for d in list(s.days.values())" in fsrc)

print("5. One network's blocks: every block it has records in, its own count; shared blocks under both")
rows_n, total_n = AB.of_network([d1, d2], "64500")
ok("a network's blocks with its own records there (not the block's total)",
   rows_n == [{"block": "192.0.2.0/24", "records": 2}] and total_n == 1, rows_n)
ok("…a block shared by two networks is listed under both, each with its own count",
   AB.of_network([d1, d2], "64502") == ([{"block": "192.0.2.0/24", "records": 1}], 1))
ok("…a network seen only on the destination side of a communication has its block (r90: records but no blocks before)",
   AB.of_network([d1, d2], "64999") == ([{"block": "198.51.100.0/24", "records": 1}], 1))
few = SimpleNamespace(block_raw={("192.0.2.0/24", "64500"): 50, ("192.0.2.0/24", "396982"): 2})
ok("…a network with 2 records in someone else's busy block still has that block to choose",
   AB.of_network([few], "396982") == ([{"block": "192.0.2.0/24", "records": 2}], 1))
ok("…a network with no records has none", AB.of_network([d1, d2], "64777") == ([], 0))
busy = SimpleNamespace(block_raw={("192.0.2.0/24", "64500"): 5, ("192.0.3.0/24", "64500"): 9, ("192.0.4.0/24", "64500"): 1})
ok("…busiest first", [r["block"] for r in AB.of_network([busy], "64500")[0]] == ["192.0.3.0/24", "192.0.2.0/24", "192.0.4.0/24"])

print("6. Each saved range's network: yesterday, else any day in memory, else Other address ranges")
saved = [ipaddress.ip_network(x) for x in ("192.0.2.0/24", "203.0.113.0/24", "192.0.2.7/32", "198.18.5.0/24", "100.64.9.0/24",
                                           "10.0.0.0/8")]
cnt, own, info = AB.summary([d1, d2], saved, [old, d1, d2])
ok("blocks per network: every network with records in a block (a shared block counts for both)",
   cnt == {"64500": 1, "64501": 1, "64502": 1, "64999": 1}, cnt)
ok("a saved block with records yesterday: its main network", own.get("192.0.2.0/24") == "64500" and info["192.0.2.0/24"]["seen"] == "yesterday"
   and info["192.0.2.0/24"]["exact"] and info["192.0.2.0/24"]["nets"] == {"64500": 2, "64502": 1}, info["192.0.2.0/24"])
ok("a single address saved: the network of the block it is in (part of a block)", own.get("192.0.2.7/32") == "64500"
   and info["192.0.2.7/32"]["part"] is True and not info["192.0.2.7/32"]["exact"])
ok("a saved block with NO records yesterday but records on an earlier day in memory: still that network's (shown in its row)",
   own.get("198.18.5.0/24") == "64500" and info["198.18.5.0/24"]["seen"] == "earlier" and info["198.18.5.0/24"]["nets"] == {},
   info.get("198.18.5.0/24"))
ok("a saved block never seen in the reports: no network (Other address ranges, not seen in the reports yet)",
   "100.64.9.0/24" not in own and info["100.64.9.0/24"]["seen"] == "" and info["100.64.9.0/24"]["asn"] == "")
ok("a range far wider than a block (a /8): no single network", "10.0.0.0/8" not in own)
cnt2, own2, _ = AB.summary([d1, d2], saved)
ok("without the days in memory, the earlier block is not known (so all_days is what keeps it in its row)",
   "198.18.5.0/24" not in own2)


def folded(asn, picked):
    """the page's "N of M blocks chosen" (settings.js blockCount): M = blocks with records yesterday + chosen not among them"""
    listed = lambda r: info.get(r, {}).get("exact") and info.get(r, {}).get("nets", {}).get(asn)  # noqa: E731
    return f"{len(picked)} of {cnt.get(asn, 0) + sum(1 for r in picked if not listed(r))} blocks chosen"


ok("the folded count includes chosen blocks without records: 2 of 2 (1 listed + 1 without records yesterday)",
   folded("64500", ["192.0.2.0/24", "198.18.5.0/24"]) == "2 of 2 blocks chosen", folded("64500", ["192.0.2.0/24", "198.18.5.0/24"]))
perm["v"] = False
ok("one network's blocks, the summary, Add a block and the range check: administrators only",
   all(c.get(f"/api/settings/address-blocks?{q}").status_code == 403
       for q in ("asn=64500", "summary=1", "add=192.0.2.0/24&for=64500", "check=192.0.2.0/24")))
perm["v"] = True
j = c.get("/api/settings/address-blocks?asn=64500").get_json()
ok("API: one network's blocks", j and j["asn"] == "64500" and j["total"] == 1 and j["blocks"] == [{"block": "192.0.2.0/24", "records": 2}], j)
ok("API: an AS number is digits only", c.get("/api/settings/address-blocks?asn=AS64500").status_code == 400
   and c.get("/api/settings/address-blocks?asn=1;drop").status_code == 400)
j = c.get("/api/settings/address-blocks?summary=1").get_json()
ok("API: the summary, with each saved range's network (the saved /23 holds only 64500's block)",
   j and j["counts"] == {"64500": 1, "64501": 1, "64502": 1, "64999": 1} and j["owners"] == {"192.0.2.0/23": "64500"}
   and j["info"]["192.0.2.0/23"]["seen"] == "yesterday", j)

print("7. Add a block (a network's row) and Other address ranges' Add: checked on the server like Apply settings")
add = lambda q: c.get(f"/api/settings/address-blocks?{q}")  # noqa: E731
r = add("add=198.18.9.0/24&for=64500")
ok("a block with no records: added to this network, no records yesterday", r.status_code == 200
   and r.get_json()["range"] == "198.18.9.0/24" and r.get_json()["info"]["asn"] == "64500" and r.get_json()["info"]["nets"] == {}, r.get_json())
r = add("add=198.18.9.77&for=64500")
ok("a single address: the /24 it is in", r.status_code == 200 and r.get_json()["range"] == "198.18.9.0/24")
r = add("add=198.18.9.77/24&for=64500")
ok("a range written loosely: written the standard way (as Apply settings keeps it)", r.get_json()["range"] == "198.18.9.0/24")
r = add("add=192.0.2.0/24&for=64502")
ok("a block this network shares with another: accepted", r.status_code == 200 and r.get_json()["range"] == "192.0.2.0/24")
r = add("add=198.51.100.0/24&for=64500")
ok("a block the reports put in another network (and none of this one's records): refused with the reason",
   r.status_code == 400 and "part of Example Cloud (AS64999), not of AS64500" in r.get_json()["error"], r.get_json())
r = add("add=192.0.2.300&for=64500")
ok("not an address: refused with the same words as Apply settings", r.status_code == 400
   and r.get_json()["error"] == "not an address range: 192.0.2.300", r.get_json())
ok("…and an empty box, or a missing or wrong network, refused", add("add=&for=64500").status_code == 400
   and add("add=192.0.2.0/24").status_code == 400 and add("add=192.0.2.0/24&for=AS1").status_code == 400)
r = add("check=198.51.100.7/22")
ok("Other address ranges' Add: the range written the standard way", r.status_code == 200 and r.get_json() == {"range": "198.51.100.0/22"})
ok("…a single address stays a single address there (as before)", add("check=198.51.100.7").get_json() == {"range": "198.51.100.7/32"})
ok("…not an address range: refused", add("check=nonsense").status_code == 400 and add("check=" + "1" * 80).status_code == 400)
import settings as lg_settings  # noqa: E402
for raw in ("198.51.100.7/22", "198.51.100.7", "2001:db8::1/48"):
    clean, errs = lg_settings.Settings.validate({"country": "GH", "networks": [], "cidrs": [raw]})
    ok(f"…the same result as Apply settings for {raw}", AB.clean_range(raw)[0] == clean["cidrs"][0] and not errs)

print("8. The Settings page: one picker in Network names & types (held .new files when LG_HELD_DIR is set)")
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
   and '"The whole network" : s === "some" ? `Some address blocks: ' in nj and '$("cidrsAdd").hidden = !data.writable' in sj
   and "if (can) {" in sj)
ok("the blocks: busiest first with their records yesterday, a search, the full list on demand, a labelled tick box each",
   "Show all ${plural(hits.length, \"block\")}" in js and '`${plural(n, "record")} yesterday`' in js
   and 'q.setAttribute("aria-label", `Search the address blocks of' in js and 'lab.append(cb,' in js)
ok("…the loading animation while a network's list is asked for the first time", 'L?.busy?.("Loading the address blocks")' in js
   and "L?.ready?.()" in js)
ok("…no outside look-up: only this server's list", js.count("fetch(") == 1 and 'const API = "/api/settings/address-blocks"' in js
   and "?asn=" in js and "?summary=1" in js and "?add=" in js and "&for=" in js and "?check=" in js)
print("   r90: chosen blocks stay in their row; Add a block; Other address ranges one row each")
ok("the row says the choice is kept until unticked (row and card hint)",
   "Your choice is kept until you untick it; blocks without records stay chosen." in js
   and "Your choice is kept until you untick it; blocks without records stay chosen." in " ".join(card.split()))
ok("…the chosen blocks come first, ticked, with or without records (a chosen block not in yesterday's list is still drawn)",
   "after the blocks you chose" in js and "[...first, ...rows.filter((r) => !mine.has(r.block))]" in js
   and "by.get(b) || { block: b, records: null }" in js and "cb.checked = o.isChosen(r.block)" in js)
ok("…a chosen block without records says so; a single address says its block's records",
   '"no records yesterday"' in js and "in a block with ${plural(n, \"record\")} yesterday" in js)
ok("…the open row's count includes chosen blocks without records (listed + chosen not listed)",
   "chosenText(k.chosen, rows.length + k.extra)" in js)
ok("…and so does the folded text (settings.js blockCount, the same rule as section 6)",
   "(blockInfo.counts[a] || 0) + [...pickedOf(a)].filter((r) => !listed(r)).length" in sj and "C.blockCount(asn)" in nj)
ok("Add a block: a labelled box with a hint, checked on the page first, then on the server, then added to this network",
   'el("label", "nb-add-label", "Add a block")' in js and "addLab.htmlFor = addId" in js and 'setAttribute("aria-describedby"' in js
   and js.index("if (!looksLikeRange(text))") < js.index("await addTo(o.asn, text)") < js.index("o.toggle(d.range, true, d.info)")
   and 'addIn.addEventListener("keydown"' in js and 'role", "status"' in js)
ok("…the page's check: IPv4 with /0-32, IPv6 with /0-128, at most 64 characters",
   "function looksLikeRange(s)" in js and "Number(len) <= 32" in js and "Number(len) <= 128" in js and "s.length > 64" in js)
ok("unticking removes the range wherever it was chosen (a shared block is one range); ticking it in either row ticks the same range",
   "for (const s of picks.values()) s.delete(blk)" in sj and "if (!allPicked().has(blk)) { pickSet(a).add(blk); blockInfo.owners[blk] = a; }" in sj
   and "i && i.exact && i.nets && i.nets[a]" in sj)
ok("loading: a saved range whose network is known (yesterday or any day in memory) goes to that network's row, the rest to Other",
   "const a = blockInfo.owners[c];" in sj and "pickSet(String(a)).add(c)" in sj and "others = other; drawOthers();" in sj
   and "info: b.info || {}" in sj)
ok("Other address ranges: under the table, Settings card only, one row each with a labelled remove button, and a box to add one",
   "{% if readonly %}" in card.split('id="netEdTable"', 1)[-1] and 'id="cidrs"' in card and 'id="cidrsList"' in card
   and 'for="cidrsNew"' in card and 'id="cidrsAddBtn"' in card and 'id="cidrsMsg" role="status"' in card
   and "<textarea" not in card and 'x.setAttribute("aria-label", `Remove ${r}`)' in sj)
ok("…a range not seen in the reports yet says so, and the note counts them",
   'const NOT_SEEN = "not seen in the reports yet"' in sj and 'id="cidrsNote"' in card and "Ranges not seen in the reports yet" in card)
ok("…removing marks unsaved changes and keeps the keyboard focus (the next remove button, else the box)",
   "others.splice(k, 1); drawOthers(k);" in sj and '(xs[Math.min(focusAt, xs.length - 1)] || $("cidrsNew"))?.focus()' in sj
   and sj.index("others.splice(k, 1)") < sj.index("refresh();", sj.index("others.splice(k, 1)")))
ok("…adding is checked on the page and on the server, like Add a block", "window.LGBlocks.looksLikeRange(text)" in sj
   and "await window.LGBlocks.check(text)" in sj)
ok("Identify networks moved to the network list", 'id="btnIdentify"' in card and 'id="unknownCount"' in card)
ok("the live summary: N networks, M address blocks, K other ranges (singular and plural)",
   '${plural(k.nets, "network")}, ${plural(k.blocks, "address block")}, ${plural(k.other, "other range")}' in sj
   and "n === 1 ? one : (many || `${one}s`)" in sj)
ok("the settings saved as before: country, time zone, whole networks as AS numbers, chosen blocks and other ranges as address ranges",
   'return { country: $("country").value, timezone: $("tzone").value, networks: mode === "some" ? [...chosen].sort() : [],' in sj
   and 'cidrs: mode === "some" ? uniqSorted([...blockList(), ...cidrList()]) : [] };' in sj
   and "const cidrList = () => others.slice();" in sj and "const blockList = () => [...allPicked()];" in sj
   and 'fetch("/api/settings", { method: "POST"' in sj)
ok("…and beside them, with the same Apply settings, the row each chosen block was ticked or added in (block_networks)",
   "body: JSON.stringify({ ...w, block_networks: blockNetworks() })" in sj
   and "const blockNetworks = () => Object.fromEntries([...someNets].flatMap((a) => [...(picks.get(a) || [])].map((r) => [r, a])));" in sj)

print("9. Remembered: the network each block was chosen under (data/constituency_blocks.json, beside the settings)")
import json  # noqa: E402
import stat  # noqa: E402
import tempfile  # noqa: E402
tmpd = tempfile.mkdtemp(prefix="lg-blocks-")
fake_st = SimpleNamespace(path=os.path.join(tmpd, "settings.json"))
P = AB.chosen_path(fake_st)
ok("the file sits beside settings.json", P == os.path.join(tmpd, "constituency_blocks.json"))
ok("no file yet: no records (the page falls back to the reports), never an error", AB.load_chosen(P) == {})
n = AB.remember(P, ["198.18.9.0/24", "192.0.2.0/24", "100.64.9.0/24"],
                {"198.18.9.0/24": "64500", "192.0.2.0/24": "64502", "203.0.113.0/24": "64501"})
ok("Apply settings records the row of each saved block; a block not saved is not recorded",
   n == 2 and AB.load_chosen(P) == {"198.18.9.0/24": "64500", "192.0.2.0/24": "64502"}, AB.load_chosen(P))
ok("…readable by the service only (0600), written in one step (no .tmp left)",
   stat.S_IMODE(os.stat(P).st_mode) == 0o600 and not os.path.exists(P + ".tmp"))
cnt9, own9, info9 = AB.summary([d1, d2], [ipaddress.ip_network(x) for x in ("198.18.9.0/24", "192.0.2.0/24", "100.64.9.0/24")],
                               [old, d1, d2], AB.load_chosen(P))
ok("after a reload: a block added with no records anywhere stays in the row it was added in",
   own9.get("198.18.9.0/24") == "64500" and info9["198.18.9.0/24"]["remembered"] is True and info9["198.18.9.0/24"]["seen"] == "")
ok("…the recorded row comes first, before what the reports say (a shared block ticked under AS64502)",
   own9.get("192.0.2.0/24") == "64502")
ok("…a range with no record and never seen still falls back (Other address ranges)", "100.64.9.0/24" not in own9)
AB.remember(P, ["192.0.2.0/24"], {"192.0.2.0/24": "64502"})
ok("removing a block from its row (unticked, then Apply settings) removes its record", AB.load_chosen(P) == {"192.0.2.0/24": "64502"})
AB.remember(P, ["192.0.2.0/24", "198.51.100.0/22"], None)
ok("a save without the rows (an older page or a script) keeps the records of ranges still saved", AB.load_chosen(P) == {"192.0.2.0/24": "64502"})
AB.remember(P, [], None)
ok("…and drops the ones no longer saved", AB.load_chosen(P) == {})
for bad in ("not json at all", "[1, 2, 3]", '{"192.0.2.0/24": "AS1;drop", "nonsense": "64500", "198.18.9.0/24": ["64500"]}'):
    with open(P, "w", encoding="utf-8") as fh:
        fh.write(bad)
    ok(f"a tampered file falls back cleanly ({bad[:20]})", AB.load_chosen(P) == {})
with open(P, "w", encoding="utf-8") as fh:
    json.dump({"192.0.2.0/24": "64500", "bad": "1", "198.18.9.0/24": "x"}, fh)
ok("…only its sound records are used", AB.load_chosen(P) == {"192.0.2.0/24": "64500"})
os.chmod(P, 0)
unreadable = AB.load_chosen(P) if os.geteuid() != 0 else {}
os.chmod(P, 0o600)
ok("an unreadable file means no records", unreadable == {})
app9 = Flask("c9")
st9 = SimpleNamespace(restricted=True, asns=set(), nets=[ipaddress.ip_network("198.18.9.0/24")], path=fake_st.path)
AB.remember(P, ["198.18.9.0/24"], {"198.18.9.0/24": "64500"})
AB.install(app9, {"has_perm": lambda p: True, "settings": st9, "days": lambda: [d1, d2], "company": str, "day": lambda: ""})
j9 = app9.test_client().get("/api/settings/address-blocks?summary=1").get_json()
ok("API: the summary reads the file (the page places the range in its row)", j9["owners"] == {"198.18.9.0/24": "64500"}
   and j9["info"]["198.18.9.0/24"]["remembered"] is True, j9)
os.remove(P)
ok("…and without it, no record and no error", app9.test_client().get("/api/settings/address-blocks?summary=1").get_json()["owners"] == {})
asrc = open(os.path.join(HERE, "app.py"), encoding="utf-8").read()
save_fn = asrc.split('@app.route("/api/settings", methods=["POST"])', 1)[1].split("\n@app.route", 1)[0]
ok("written only by Apply settings (administrators, CSRF, a fresh sign-in), after the settings, and audited with it",
   save_fn.index("_settings_change_allowed()") < save_fn.index("settings.save(clean)")
   < save_fn.index("_address_blocks.remember(_address_blocks.chosen_path(settings), clean[\"cidrs\"], body.get(\"block_networks\"))")
   < save_fn.index('"settings_changed"') and "kept with their network" in save_fn
   and asrc.count("_address_blocks.remember(") == 1)
bsh = open(os.path.join(HERE, "manage", "backup.sh"), encoding="utf-8").read()
sfp = open(os.path.join(HERE, "deploy", "stale_files.py"), encoding="utf-8").read()
ok("backed up with data/ (the backup takes the whole project folder) and never moved aside as an old code file (data/ skipped)",
   '-czf "$out" "$name"' in bsh and '"data"' in sfp.split("SKIP_DIRS = ", 1)[1].split("\n", 1)[0])

print("10. The platforms' empty stream: a loaded day with nothing says so (not 'waiting')")
apj = rd(pick("app.js", os.path.join(HERE, "static", "js", "app.js")))
svj = rd(pick("services.js", os.path.join(HERE, "static", "js", "services.js")))
ok("network communications: no records for your constituency on the day, or none reported, when the day is loaded",
   "} else if (!filtered && r.total === 0) {" in apj
   and 'msg = !$("scopePill").hidden ? `No records for your constituency on ${r.day}.` : `No records reported on ${r.day}.`;' in apj
   and 'if (!state.waiting) $("streamEmpty").textContent = msg ||' in apj)
ok("services: the same, never while the day is still waiting for its report",
   "} else if (!filtered && r.total === 0 && !state.waiting) {" in svj
   and "msg = COUNTRY.restricted ? `No records for your constituency on ${r.day}.` : `No records reported on ${r.day}.`;" in svj)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
