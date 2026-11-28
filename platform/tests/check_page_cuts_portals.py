#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The portal pages say when a list is cut and never mislead with a share (2026-11-26, "nothing goes missing"): each
page's own code (the held copies when there are some) RUNS under node on made-up figures:

  intel.js        a part of a report reads ">99%", never "100%"; each services report says "and 2 more sets" and shows
                  them on a click; decoded-beacon operators past 6 are counted; a code that will not load says why
                  (never a row that silently vanishes)
  intelligence.js a value of 1 in 43,281 records reads "<1%", never "0%", in the breakdown and the key findings
  combos.js       "Top 8 of 23 networks", "Top 8 of 40 cities", "Top 6 of 9 kinds", "Top 6 of 14 ports"; a region's
                  "and 3 more cities"; all researchers' notes on a click; "<1%" repeating, never "0%"
  findings.js     "Devices per region" says "Top 8 of 14 regions" (and networks theirs)
  advisory-portal.js  "Top 20 of 57 recipients", "Top 10 of 31 impacts", "Top 10 of 26 reports"
  advisory.js     "again" counts all 900 devices, not the 500 listed; a 300-byte file reads "300 bytes", never "0 KB"

Skips (77) where node is not installed. Run: .venv/bin/python tests/check_page_cuts_portals.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import page_harness as H  # noqa: E402

passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f": {str(detail)[:700]}" if detail else ""))


def ran(what, out, raw):
    if out is None:
        ok(f"{what} runs", False, raw)
    return out


if not H.NODE:
    print("SKIPPED: node is not installed here (CI runs this check)")
    sys.exit(77)

# ---------------------------------------------------------------- intel.js
SRC = H.page_src("intel.js")
print(f"== intel.js ({os.path.basename(H.page_path('intel.js'))})")
defs = H.extract(SRC, ["$", "el", "fmt", "svg", "ICON", "GROUP", "ORDER", "SHOW", "pct", "beaconCode", "plural", "rn", "OS_NAME", "shownValue",
                       "iconBtn", "codeChip", "noteBtn", "beaconChip", "noteBtnFor", "copySeg", "figures", "valueRow", "kindCard", "seenIn",
                       "everyCard", "paint"], optional=("beaconCode",))
ops = [{"value": f"op{i}", "count": 100 - i, "share": (100 - i) / 1000, "hosts": 6, "repeat_hosts": 0} for i in range(8)]
data = {
    "report": {"report": "event4_sinkhole", "name": "m0yv", "records": 1000,
               "indicators": [{"kind": "Beacon operator", "distinct": 8, "values": ops},
                              {"kind": "C2 domain", "distinct": 1, "values": [{"value": "a.example", "count": 999, "share": 0.9996, "hosts": 9, "repeat_hosts": 0}]}],
               "combinations": []},
    "every": {"name": "m0yv", "section": "infections", "days": ["2026-11-25"],
              "cross": {"sources": [], "infections": [], "issues": [], "issues_total": 0,
                        "services": [{"report": "scan_x", "title": "Accessible X", "kind": "Services reports", "hosts": 12,
                                      "combinations": [{"items": [f"v{i}"], "hosts": 6, "code": f"LG-C-0000000{i}"} for i in range(5)]}]}},
}
JS = defs + r"""
let st = null; const copy = () => {}, open = () => {}, keepPlace = () => {}, toast = () => {};
const acrossView = () => {}, compareView = () => {}, servicePane = () => {}, comboCard = () => el("div");
ROUTES.push(["operator=op3", 404, { error: "No selection of 5 or more devices carries these beacons in the days in memory: an analyst can hand them over." }],
            ["/api/beacon/code", 200, { code: "LG-B-12345678", text: "decoded beacons" }]);
const D = JSON.parse(process.argv[1]);
(async () => {
  const out = {};
  st = { i: 0, q: "", focus: null, open: {}, rail: el("div"), pane: el("div"), d: { name: "m0yv", section: "infections", reports: [D.report] } };
  paint();
  await new Promise((r) => setTimeout(r, 20));
  out.pane = lines(st.pane);
  out.ops_rows = st.pane.querySelectorAll(".ig-beacon-code").length;
  out.op3 = (st.pane.querySelectorAll(".ig-beacon-code").find((r) => r.textContent.includes("Operator op3")) || { textContent: "" }).textContent;
  const card = everyCard(D.every); out.every = lines(card);
  const b = card.querySelectorAll("button").find((x) => /^Show all 5$/.test(x.textContent)); out.every_btn = !!b;
  if (b) b.click();
  out.every_sets_after = everyCard(D.every).querySelectorAll(".ig-every-k").length;
  console.log(JSON.stringify(out));
})();
"""
o = ran("Intel gathered", *H.run(JS, data))
if o:
    ok("a value on 999 of 1,000 records reads '>99%', never '100%'", ">99%" in o["pane"] and "100%" not in o["pane"], [x for x in o["pane"] if "%" in x])
    ok("decoded-beacon operators: 6 rows with a code and a line counting the other 2",
       o["ops_rows"] == 6 and any("2 more operators are listed in the Beacon operator card" in x for x in o["pane"]), (o["ops_rows"], o["pane"][-6:]))
    ok("an operator whose code is refused keeps its row and says why", "Operator op3" in o["op3"] and "No code for this one: No selection of 5 or more devices" in o["op3"], o["op3"])
    ok("each services report: 3 sets shown, 'and 2 more sets', a 'Show all 5' button", "and 2 more sets" in o["every"] and o["every_btn"], o["every"])
    ok("...which shows all 5 sets", o["every_sets_after"] == 5, o["every_sets_after"])

# ---------------------------------------------------------------- intelligence.js
SRC = H.page_src("intelligence.js")
print(f"== intelligence.js ({os.path.basename(H.page_path('intelligence.js'))})")
defs = H.extract(SRC, ["el", "fmt", "pl", "dayLabel", "drawView"])
d = {"title": "Compromised website", "meaning": "m", "days": ["2026-11-25"], "day": "2026-11-25", "total": 43281, "hosts": 10, "q": "",
     "stats": {"records": 43281, "hosts": 10, "networks": 2, "regions": 1, "fields": []},
     "facets": [{"key": "tag", "label": "Tag", "values": [{"value": "big", "label": "big", "rows": 43280}, {"value": "tiny", "label": "tiny", "rows": 1}], "more": 0}]}
JS = r"""const $ = (id) => document.getElementById(id);
const view = { name: "", day: "", filters: {}, q: "", reveal: false }; const fetchView = () => {}, table = () => el("div"), codeBox = () => el("div"), hostView = () => {};
""" + defs + r"""
const d = JSON.parse(process.argv[1]); const pane = el("div");
try { drawView(pane, d); } catch (e) { console.error(e); }
const brk = pane.querySelectorAll("ul.brk li").map((li) => li.textContent);
const find = pane.querySelectorAll("ul.i-findings li").map((li) => li.textContent);
console.log(JSON.stringify({ brk, find }));
"""
o = ran("Abused or Compromised view", *H.run(JS, d))
if o:
    ok("breakdown: 1 of 43,281 records reads '<1%', the rest '>99%' (never '0%' / '100%')", o["brk"] == ["big>99%", "tiny<1%"], o["brk"])
    ok("key findings: 'big (43,280 records, >99%)'", any("(43,280 records, >99%)" in x for x in o["find"]), o["find"])

# ---------------------------------------------------------------- combos.js
SRC = H.page_src("combos.js")
print(f"== combos.js ({os.path.basename(H.page_path('combos.js'))})")
defs = H.extract(SRC, ["el", "fmt", "chips", "drawEntry", "figures", "drawGrid", "drawGeo"])
nets = [{"label": f"Net {i}", "asn": 64500 + i, "devices": 50 - i, "records": 60 - i, "share": 0.01} for i in range(8)]
s = {"devices": 300, "records": 900, "repeat": 1, "multi_day": 0, "networks": 23, "cities": 40, "peak_hour": None, "hours": [],
     "regions": [{"value": "R1", "label": "R1", "devices": 200, "share": 0.6667}], "country": "",
     "region_details": {"R1": {"devices": 200, "records": 500, "cities": [[f"C{i}", 10 - i] for i in range(5)], "networks": [["Net 0", 9]], "ips": [], "totals": {"cities": 7}}},
     "networks_all": nets, "top_networks": nets, "top_cities": [{"label": f"C{i}", "region": "R1", "devices": 9 - i} for i in range(8)],
     "kinds": [{"label": f"k{i}", "records": 9 - i} for i in range(6)], "ports": [{"label": f"p{i}", "records": 9 - i} for i in range(6)],
     "top_devices": [], "across": {}, "per_day": [], "totals": {"networks": 23, "cities": 40, "kinds": 9, "ports": 14}}
entry = {"kind": "r", "code": "LG-C-00000001", "name": "m0yv", "section": "infections", "report": "r", "items": ["a"],
         "notes": [{"role": "Researcher", "by": f"R {i}", "date": "", "text": f"note {i}", "codes": []} for i in range(9)]}
JS = r"""const $ = (id) => document.getElementById(id); let entry = null, drawSeq = 0; const SVG = "x"; let shapesP = null, shapesFor = null;
window.LGRegions = null; window.lgDeviceNote = () => el("p");
""" + defs + r"""
const [s, en] = JSON.parse(process.argv[1]); entry = en;
(async () => {
  try { figures(s); } catch (e) { console.error(e); }
  await new Promise((r) => setTimeout(r, 10));
  const grid = $("cbGrid").querySelectorAll("article").map((a) => lines(a));
  const tiles = lines($("cbTiles")), tree = lines($("cbTree"));
  drawEntry(en);
  const box = $("cbEntry"); const notes0 = box.querySelectorAll(".cb-note").length, ntext = lines(box);
  const btn = box.querySelectorAll("button").find((b) => /^Show the other/.test(b.textContent)); if (btn) btn.click();
  console.log(JSON.stringify({ grid, tiles, tree, notes0, ntext, notes1: box.querySelectorAll(".cb-note").length }));
})();
"""
o = ran("the Combinations results", *H.run(JS, [s, entry]))
if o:
    head = {g[0]: g for g in o["grid"] if g}
    ok("Networks card: 'Top 8 of 23 networks.'", "Top 8 of 23 networks." in head.get("Networks", []), head.get("Networks"))
    ok("Cities card: 'Top 8 of 40 cities.'", "Top 8 of 40 cities." in head.get("Cities", []), head.get("Cities"))
    ok("What the devices are: 'Top 6 of 9 kinds.'", "Top 6 of 9 kinds." in head.get("What the devices are", []), head.get("What the devices are"))
    ok("Ports: 'Top 6 of 14 ports.'", "Top 6 of 14 ports." in head.get("Ports", []), head.get("Ports"))
    ok("a region's cities: 4 shown and 'and 3 more cities' (7 in all)", "and 3 more cities" in o["tree"], o["tree"])
    ok("'repeating it': 1 of 300 devices reads '<1% of the devices', never '0%'", "<1% of the devices" in o["tiles"], o["tiles"])
    ok("researchers' notes: 6 of 9 shown, 'The first 6 of 9 notes are shown.'", o["notes0"] == 6 and "The first 6 of 9 notes are shown." in o["ntext"], o["ntext"])
    ok("...and a click shows all 9", o["notes1"] == 9, o["notes1"])

# ---------------------------------------------------------------- findings.js
SRC = H.page_src("findings.js")
print(f"== findings.js ({os.path.basename(H.page_path('findings.js'))})")
defs = H.extract(SRC, ["el", "bars", "reviewPanel"])
reg = [{"label": f"Region {i}", "devices": 20 - i} for i in range(8)]
f = {"review": {"source": "LG-C-00000001", "drill": {"devices": 120, "records": 300, "networks": 23, "top_networks": [{"label": f"N{i}", "devices": 9 - i} for i in range(8)],
                                                  "regions": reg, "per_day": [], "totals": {"regions": 14}},
                "researcher": {"code": "LG-C-00000001", "devices": 150, "records": 400, "networks": 25, "top_networks": [{"label": f"N{i}", "devices": 9 - i} for i in range(8)],
                               "regions": reg, "per_day": [], "totals": {"regions": 15, "networks": 25}},
                "analyst": {}}}
JS = r"""let data = { findings: [], statuses: [] }, byId = {};
""" + defs + r"""
const f = JSON.parse(process.argv[1]); let p = null;
try { p = reviewPanel(f, {}); } catch (e) { keep(e); }
const art = (p || el("div")).querySelectorAll("article").map((a) => lines(a));
console.log(JSON.stringify({ art, errs: ERRS }));
"""
o = ran("the finding's review panel", *H.run(JS, f))
if o and len(o["art"]) >= 2:
    ok("drill-down view: 'Top 8 of 14 regions.' under Devices per region", "Top 8 of 14 regions." in o["art"][0], o["art"][0])
    ok("...and 'Top 8 of 23 networks.' under Devices per network", "Top 8 of 23 networks." in o["art"][0], o["art"][0])
    ok("researcher's view: 'Top 8 of 15 regions.' and 'Top 8 of 25 networks.'", "Top 8 of 15 regions." in o["art"][1] and "Top 8 of 25 networks." in o["art"][1], o["art"][1])
elif o:
    ok("the review panel draws its views", False, o)

# ---------------------------------------------------------------- advisory-portal.js (the whole page)
SRC = H.page_src("advisory-portal.js")
print(f"== advisory-portal.js ({os.path.basename(H.page_path('advisory-portal.js'))})")
dash = {"kpis": {"waiting": 0, "drafts": 0, "drafted": 0, "sent": 80, "sends": 90, "recipients": 57, "reports": 1, "generations": 1, "open_findings": 0,
                 "closed_findings": 0, "closed_cases": 0, "open_cases": 0, "days_to_send": None},
        "waiting": [], "recipients": [{"name": f"Org {i}", "advisories": 30 - i, "last": "2026-11-20"} for i in range(20)],
        "per_month": [], "impacts": [{"label": f"Impact {i}", "advisories": 20 - i, "level": "high"} for i in range(10)],
        "reports": [{"title": f"Report {i}", "advisories": 20 - i} for i in range(10)], "advisories": [], "open_findings": [], "totals": {"recipients": 57, "impacts": 31, "reports": 26}}
JS = r"""
const D0 = JSON.parse(process.argv[1]); ROUTES.push(["/api/advisory/dashboard", 200, D0]);
""" + SRC + r"""
setTimeout(() => {
  const cards = document.getElementById("apMain").querySelectorAll("section").map((s) => lines(s));
  console.log(JSON.stringify({ cards }));
}, 30);
"""
o = ran("the advisory portal", *H.run(JS, dash))
if o:
    head = {c[0]: c for c in o["cards"] if c}
    ok("Sent to: 'Top 20 of 57 recipients, the most first.'", "Top 20 of 57 recipients, the most first." in head.get("Sent to", []), head.get("Sent to"))
    ok("Impacts: 'Top 10 of 31 impacts, the most first.'", "Top 10 of 31 impacts, the most first." in head.get("Impacts in the advisories sent", []),
       head.get("Impacts in the advisories sent"))
    ok("Reports: 'Top 10 of 26 reports, the most first.'", "Top 10 of 26 reports, the most first." in head.get("Reports in the advisories sent", []),
       head.get("Reports in the advisories sent"))

# ---------------------------------------------------------------- advisory.js (the whole page)
SRC = H.page_src("advisory.js")
print(f"== advisory.js ({os.path.basename(H.page_path('advisory.js'))})")
devs = [{"ip": f"192.0.2.{i % 250}.{i}", "hostname": "", "ports": [], "reports": [], "cves": [], "issues": [], "infections": [], "labels": [], "records": 1, "last": ""} for i in range(500)]
idx = {"finding": {"number": 7, "title": "A finding"}, "organisation": "CSIRT", "org_set": True, "has_logo": False, "can_edit": False,
       "limits": {}, "tlp_levels": ["TLP:AMBER"], "tlp_url": "",
       "networks": [{"network": "Net A", "devices": 900, "records": 1000, "asns": [], "status": "sent", "status_label": "Sent"}]}
net = {"devices_total": 900, "file_base": "adv", "has_report": True, "saved": False,
       "advisory": {"network": "Net A", "locked": True, "data_title": "the report", "reports": [], "impact": [],
                    "affected": {"devices": 900, "records": 1000, "cves": [], "issues": [], "categories": [], "labels": []},
                    "devices": devs, "attack": None, "brand": "", "description": "", "heading": "", "heading_default": "", "history": [],
                    "insights": [], "kinds_line": "", "look": {}, "organisation": "Net A", "recipients": [], "recommended_actions": "",
                    "ref": "ADV-1", "report_stale": False, "sends": [], "status": "sent", "subject": "S", "tlp": "TLP:AMBER",
                    "generated": [{"name": "small.txt", "size": 300, "at": "2026-11-25", "by": "A", "n": 1}]}}
again = {"state": "ready", "again": True, "latest": "2026-11-25", "again_ips": [devs[0]["ip"], devs[1]["ip"], devs[2]["ip"], "198.51.100.1", "198.51.100.2"]}
JS = r"""
const [IDX0, NET0, AG] = JSON.parse(process.argv[1]);
document.body.dataset.fid = "7";
ROUTES.push(["/again", 200, AG], ["/net?", 200, NET0], ["/api/advisory/7", 200, IDX0]);
window.LGFindingsLive = null;
""" + SRC + r"""
setTimeout(() => {
  const main = document.getElementById("avMain");
  const ag = (main.querySelector(".av-again") || { textContent: "" }).textContent;
  const kb = main.all().map((n) => n.textContent).filter((t) => /\d+ (bytes|KB)$/.test(t.trim()));
  console.log(JSON.stringify({ again: ag, files: kb.slice(-3), errs: ERRS }));
}, 60);
"""
o = ran("the advisory page", *H.run(JS, [idx, net, again]))
if o:
    ok("'again' counts all 900 devices (5 of them), and says 3 of the 500 listed are marked",
       o["again"].startswith("5 of these 900 devices were reported again") and "3 of them are among the 500 listed below" in o["again"], o["again"])
    ok("a 300-byte file reads '300 bytes', never '0 KB'", any(t.endswith("300 bytes") for t in o["files"]) and not any(t.endswith(" 0 KB") for t in o["files"]),
       (o["files"], o["errs"]))

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
