#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The pages show the count audit's new fields (count audit round 2, 2026-11-26; the server side: counting_keys.py and
tests/check_count_keys.py): each page's own code (the held copies when there are some) RUNS under node on made-up
figures, and every line below must be drawn:

  services.js   the analysis lists "Sectors (network type)" and "Industry (Shadowserver)"; "N records without a network
                (not counted as a network)" and the same for regions, under the Intel lists and in the analysis; the
                records without an address and the loader's sentence (load_notes.text) with the load figures; an
                "Industry (Shadowserver)" filter menu from the facets (else the figures) that sets the industry filter;
                a record's own sector is offered as the industry filter, never as the network type's
  app.js        the overview says what the day's loader kept once or left out (load_notes.text, /api/overview)
  management.js "Sectors (network type)", "Industry (Shadowserver)"; "N events from devices without a region" beside
                the Regions map and "... without a network" beside the networks; "A device seen in two regions (or
                networks of two types) counts in each." under Regions and Sectors (hosts on the services platform)
  intelligence.js  which days the report's records are dated (dated.text)

Skips (77) where node is not installed. Run: .venv/bin/python tests/check_page_count_notes.py"""
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


def defs_of(src, names, **kw):
    """The page's definitions, or None (and a failure) when the page lacks one: the old page fails, never crashes."""
    try:
        return H.extract(src, names, **kw)
    except KeyError as e:
        ok(f"the page defines {e.args[0]}", False)
        return None


if not H.NODE:
    print("SKIPPED: node is not installed here (CI runs this check)")
    sys.exit(77)

LOAD_TEXT = ("2 rows also in another file that day (counted once); 1 row of this day's report files is dated outside "
             "2026-11-25 (not shown on any day).")


def rows(n, prefix, first=900):
    return [{"value": f"{prefix}{i}", "label": f"{prefix} {i}", "count": first - i, "hosts": 3, "share": 0.01} for i in range(n)]


# ---------------------------------------------------------------- services.js
SVC = H.page_src("services.js")
print(f"== services.js ({os.path.basename(H.page_path('services.js'))})")
STUBS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n || 0).toLocaleString("en-US"), titleCase = (s) => String(s || "");
const SEV_ORDER = ["critical", "high", "medium", "low", "info"], ACCENT = "#5b8def", PAL = ["#111", "#222", "#333"];
const sevColor = () => "#f00", famColor = () => "#0f0", flagImg = () => el("img", "flag"), defOf = () => null;
const attachTip = (node, fn) => { node._tip = fn; }, showTip = () => {}, hideTip = () => {}, keyable = () => {};
const opened = []; const openInsight = (p) => opened.push(p), narrow = (p, k, v) => [...p, [k, v]], filterPairs = () => [];
const quarterHours = () => {}, stackedHours = () => {}, keepFocus = (f) => f();
const state = { dayStart: null, svcFamily: new Map(), glossary: null, facets: null, stats: null,
  filters: { family: new Set(), severity: new Set(), service: new Set(), issue: new Set(), region: "", city: "", asn: "", port: "", vendor: "", device_type: "", industry: "" } };
const replayNow = () => Date.now(), valueLabel = (k, v) => String(v), regionLabel = (v) => v;
const COUNTRY = { code: "KE" }; const kindLabel = () => "Selection", selTitle = () => "All", renderParts = () => {}, defBox = () => {};
const toggleDrill = () => {}, explainAll = () => {}, refLabels = new Map();
let changed = 0; const filtersChanged = () => { changed++; };
const intel = $("intel"); document.body.append(intel);
for (const id of ["topIssue", "topService", "topNet", "topRegion", "topCity", "topVendor", "topProduct", "topPort", "topFamily", "donut", "sevBar", "sevLegend"]) {
  const box = el("section"); box.append($(id)); intel.append(box); }
const kTile = el("div", "kpi"); kTile.append($("kTotal")); document.body.append(kTile);
// the filter drawer's grid: Device type, then the menu the page adds
const grid = el("section", "fg grid2"); document.body.append(grid);
const devLab = el("label"); devLab.append(el("span", null, "Device type"), $("fDevice")); grid.append(devLab);
for (const id of ["fFamily", "fSeverity", "fService", "fIssue", "fRegion", "fCity", "fAsn", "fPort", "fVendor", "srcCount", "issCount", "svcSearch", "issSearch", "fVuln", "fMulti", "fCross"]) $(id);
"""
names = ["pct", "tipLine", "OTHER", "donutChart", "severityMix", "TOP_SHOWN", "topList", "swatchLabel", "renderIntel", "card", "BREAK_TITLES",
         "KEY_OF", "unknownNote", "loadNotes", "noteUnder", "renderInsight", "withChosen", "chips", "checklist", "select", "industryMenu", "buildFilters"]
svc_defs = defs_of(SVC, names, optional=("TOP_SHOWN", "OTHER"))
B = {"issue": rows(3, "iss"), "service": rows(3, "svc"), "network": rows(4, "N") + [{"value": "Unknown network", "label": "Unknown network", "count": 7, "hosts": 2, "share": 0.001}],
     "region": rows(3, "R") + [{"value": "Unknown region", "label": "Unknown region", "count": 5, "hosts": 1, "share": 0.001}],
     "city": [], "vendor": [], "product": [], "port": [], "family": [{"value": "Exposed service", "label": "Exposed service", "count": 3000, "hosts": 9, "share": 1}],
     "sector": [{"value": "Telco / ISP", "label": "Telco / ISP", "count": 2000, "hosts": 4, "share": 0.66}],
     "industry": [{"value": "Communications", "label": "Communications", "count": 2500, "hosts": 4, "share": 0.83}]}
S = {"total": 3000, "hosts": 40, "no_address": 3, "breakdowns": B, "severity": [], "quarters": [], "hours_by_family": {},
     "totals": {"network": 4, "region": 3}, "unknowns": {"network": {"records": 7, "hosts": 2}, "region": {"records": 1, "hosts": 1}},
     "load_notes": {"dups": 2, "outside": 1, "undated": 0, "text": LOAD_TEXT}}
FACETS = {"filtered": False, "reports": [], "unsupported": [],
          "facets": {"family": [], "severity": [], "service": [], "issue": [], "region": [], "city": [], "network": [], "port": [], "vendor": [], "device_type": [],
                     "industry": [{"value": "Communications", "label": "Communications", "count": 2500}, {"value": "Education", "label": "Education", "count": 9}]}}
if svc_defs is not None:
    JS = STUBS + svc_defs + r"""
const [s, F] = JSON.parse(process.argv[1]); const out = {};
renderIntel(s);
out.intel = lines($("intel"));
out.ktitle = kTile.title || "";
const d = { ...s, day: "2026-11-25", day_total: 9000, vulnerable_hosts: 0, issues: 3, multi_issue_hosts: 0, services: 3, cross_report_hosts: 0, networks: 4, regions: 3,
  findings: [], peak_hour: null, host_rows: [], hosts_total: 0 };
renderInsight([], d);
setTimeout(() => {
  out.secs = $("iBody").querySelectorAll("section").map((x) => lines(x));
  state.facets = F; buildFilters();
  const menu = () => { const lab = devLab.nextElementSibling; return lab ? lab.querySelector("select") : null; };
  const sel = menu();
  out.menu_label = sel && sel.parentElement ? lines(sel.parentElement)[0] : "";
  out.menu_opts = sel ? sel.children.map((o) => o.textContent) : [];
  out.menu_after_device = !!(sel && sel.parentElement && devLab.nextElementSibling === sel.parentElement);
  if (sel) { sel.value = "Communications"; sel.fire("change"); }
  out.filter = state.filters.industry; out.changed = changed;
  // no facets list for it: the figures' own breakdown
  state.facets = { ...F, facets: { ...F.facets, industry: undefined } }; state.stats = s; buildFilters();
  out.menu_opts2 = (menu() || { children: [] }).children.map((o) => o.textContent);
  out.menus = grid.querySelectorAll("select").length;
  console.log(JSON.stringify(out));
}, 5);
"""
    o, raw = H.run(JS, [S, FACETS])
    if o is None:
        ok("the services page runs", False, raw)
    else:
        ok("Intel Networks: '7 records without a network (not counted as a network).'",
           "7 records without a network (not counted as a network)." in o["intel"], o["intel"])
        ok("Intel Regions: '1 record without a region (not counted as a region).'",
           "1 record without a region (not counted as a region)." in o["intel"], o["intel"])
        load = "3 records without an address (not counted as hosts). " + LOAD_TEXT
        ok("load figures: the records without an address and the loader's own sentence, in the Intel panel",
           load in o["intel"], o["intel"])
        ok("...and on the Records tile's hover", o["ktitle"] == load, o["ktitle"])
        heads = {x[0]: x for x in o["secs"] if x}
        ok("analysis: the Sectors list reads 'Sectors (network type)'", "Sectors (network type)" in heads and "Sectors" not in heads, list(heads))
        ok("analysis: an 'Industry (Shadowserver)' list from breakdowns.industry", "Communications" in heads.get("Industry (Shadowserver)", []),
           heads.get("Industry (Shadowserver)"))
        ok("analysis Networks / Regions: the records without one, said under the list",
           "7 records without a network (not counted as a network)." in heads.get("Networks", [])
           and "1 record without a region (not counted as a region)." in heads.get("Regions", []), (heads.get("Networks"), heads.get("Regions")))
        ok("filters: an 'Industry (Shadowserver)' menu right after Device type", o["menu_label"] == "Industry (Shadowserver)" and o["menu_after_device"],
           (o["menu_label"], o["menu_after_device"]))
        ok("...listing the facets' industries with their counts", o["menu_opts"] == ["All industries", "Communications (2,500)", "Education (9)"], o["menu_opts"])
        ok("...choosing one sets the industry filter", o["filter"] == "Communications" and o["changed"] >= 1, (o["filter"], o["changed"]))
        ok("...from the figures' breakdown when the facets do not send it", o["menu_opts2"] == ["All industries", "Communications (2,500)"]
           and o["menus"] == 1, (o["menu_opts2"], o["menus"]))

# a record's own sector is Shadowserver's column: offered as the industry filter (openModal, the record window)
rec_defs = defs_of(SVC, ["section", "openModal"])
if rec_defs is not None:
    JS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n || 0).toLocaleString("en-US"), titleCase = (s) => String(s || ""), regionLabel = (v) => v, regionUnknown = () => false;
const famColor = () => "#0f0", sevColor = () => "#f00", flagImg = () => el("img"), defBox = () => {}, hideTip = () => {}, toast = () => {};
const LT = () => ({ also: () => "" }), COUNTRY = { code: "KE", name: "Kenya" }, state = { demo: false }, refLabels = new Map();
const opened = []; const openInsight = (p) => opened.push(p);
const E = JSON.parse(process.argv[1]); const getJSON = async () => E;
""" + rec_defs + r"""
openModal.seq = 0; openModal.loading = null;
(async () => {
  try { await openModal({ id: "x", extracted_date: "2026-11-25T01:00:00Z" }); } catch (e) { keep(e); }
  const dts = $("mBody").querySelectorAll("dt"), dds = $("mBody").querySelectorAll("dd");
  const i = dds.findIndex((x) => x.textContent === "Communications");
  if (i >= 0) dds[i].click();
  console.log(JSON.stringify({ label: i >= 0 ? dts[i].textContent : "", opened, errs: ERRS }));
})();
"""
    ev = {"event": {"id": "x", "ip": "192.0.2.7", "ip_ref": "r1", "port": 80, "protocol": "tcp", "hostname": "", "network": "Example Telecom (AS64500)",
                    "sector": "Communications", "city": "", "region": "", "geo": "KE", "service": "Accessible HTTP", "report": "scan_http",
                    "family": "Exposed service", "severity": "medium", "vendor": "", "device_type": "", "product": "", "version": "", "tags": [],
                    "issues": [], "tag": "", "extracted_date": "2026-11-25T01:00:00Z", "extras": {}},
          "host_records": 1, "host_services": ["Accessible HTTP"]}
    o, raw = H.run(JS, ev)
    if o is None:
        ok("the record window runs", False, raw)
    else:
        ok("record window: the record's sector reads 'Industry (Shadowserver)' and opens the industry filter (the network type's before)",
           o["label"] == "Industry (Shadowserver)" and o["opened"] == [[["industry", "Communications"]]], o)

# ---------------------------------------------------------------- app.js (the overview)
APP = H.page_src("app.js")
print(f"== app.js ({os.path.basename(H.page_path('app.js'))})")
app_defs = defs_of(APP, ["showLoadNote", "loadIntro"], optional=("showLoadNote",))
if app_defs is not None:
    JS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n || 0).toLocaleString("en-US"), countUp = (node, v) => { node.textContent = fmt(v); };
const quarterHours = () => {}, hhmm = () => "", LT = () => ({ also: () => "" }), classColor = () => "#0f0", CLASS_INFO = {};
const attachTip = () => {}, tipLine = (a, b) => el("div", null, `${a || ""}${b || ""}`), pct = (a, b) => `${a}/${b}`;
const O = JSON.parse(process.argv[1]);
const getJSON = async (u) => (u.includes("/api/overview") ? O : { total: 0, reports: [], unsupported: [], day: O.day });
const wrap = el("section"); wrap.append($("introStats")); document.body.append(wrap);
""" + app_defs + r"""
(async () => {
  try { await loadIntro(true); } catch (e) { keep(e); }
  await new Promise((r) => setTimeout(r, 10));
  console.log(JSON.stringify({ intro: lines(wrap) }));
})();
"""
    ov = {"day": "2026-11-25", "total": 1200, "reports_active": 3, "reports_total": 9, "source_hosts": 40, "infections": 2, "cities": 3,
          "cross_report_hosts": 1, "timeline": [], "peak_quarter": None, "classes": [], "schedule": {"state": "playing"},
          "load_notes": {"dups": 2, "outside": 1, "undated": 0, "text": LOAD_TEXT}}
    o, raw = H.run(JS, ov)
    if o is None:
        ok("the map overview runs", False, raw)
    else:
        ok("overview: the loader's sentence under the figures of what was loaded", LOAD_TEXT in o["intro"], o["intro"])

# ---------------------------------------------------------------- management.js
MG = H.page_src("management.js")
print(f"== management.js ({os.path.basename(H.page_path('management.js'))})")
mg_defs = defs_of(MG, ["SECTOR_LABEL", "countNotes"])
if mg_defs is not None:
    JS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n || 0).toLocaleString("en-US");
for (const [id, h] of [["cMap", "Regions"], ["cSectors", "Sectors"], ["cNets", "Most affected networks"]]) { const c = $(id); c.append(el("h2", null, h)); document.body.append(c); }
""" + mg_defs + r"""
const [dc, ds] = JSON.parse(process.argv[1]); const out = {};
countNotes(dc); out.comms = ["cMap", "cSectors", "cNets"].map((id) => lines($(id)));
out.x2_comms = $("tX2Title").textContent;
countNotes(ds); out.svc = ["cMap", "cSectors", "cNets"].map((id) => lines($(id))); out.x2 = $("tX2Title").textContent;
countNotes({ platform: "comms", unknowns: { regions: { events: 0, devices: 0 }, networks: { events: 0, devices: 0 } } });
out.none = lines($("cNets"));
console.log(JSON.stringify(out));
"""
    dc = {"platform": "comms", "unknowns": {"regions": {"events": 12, "devices": 3}, "networks": {"events": 1, "devices": 1}}}
    ds = {"platform": "services", "unknowns": {"regions": {"events": 4, "devices": 2}, "networks": {"events": 9, "devices": 2}}}
    o, raw = H.run(JS, [dc, ds])
    if o is None:
        ok("the Executive cards run", False, raw)
    else:
        m, s_, n = o["comms"]
        both = "A device seen in two regions (or networks of two types) counts in each."
        ok("Executive: the Sectors card reads 'Sectors (network type)'", s_[:1] == ["Sectors (network type)"], s_)
        ok("Regions: '12 events from devices without a region.' and the counting rule", m[1:] == ["12 events from devices without a region. " + both], m)
        ok("Sectors: the counting rule under it", both in s_, s_)
        ok("networks: '1 event from devices without a network.'", "1 event from devices without a network." in n, n)
        ok("services platform: records and hosts ('4 records from hosts without a region.')",
           o["svc"][0][1:] == ["4 records from hosts without a region. A host seen in two regions (or networks of two types) counts in each."]
           and "9 records from hosts without a network." in o["svc"][2], o["svc"])
        ok("nothing without a network: no line (never '0 events ...')", o["none"] == ["Most affected networks"], o["none"])
        ok("Executive services: Shadowserver's own column is titled 'Industry (Shadowserver)' (comms keeps its own card)",
           o["x2"] == "Industry (Shadowserver)" and o["x2_comms"] == "", (o["x2"], o["x2_comms"]))

# ---------------------------------------------------------------- intelligence.js
IT = H.page_src("intelligence.js")
print(f"== intelligence.js ({os.path.basename(H.page_path('intelligence.js'))})")
it_defs = defs_of(IT, ["el", "fmt", "pl", "dayLabel", "drawView"])
if it_defs is not None:
    DATED = "The report sent on 2026-11-25 (its file date); its records are dated 2026-11-24 to 2026-11-25; 3 records have no time."
    d = {"title": "Compromised website", "meaning": "m", "days": ["2026-11-25"], "day": "2026-11-25", "total": 10, "hosts": 4, "q": "",
         "stats": {"records": 10, "hosts": 4, "networks": 1, "regions": 1, "fields": []}, "facets": [],
         "dated": {"basis": "file", "first": "2026-11-24", "last": "2026-11-25", "undated": 3, "text": DATED}}
    JS = r"""const $ = (id) => document.getElementById(id);
const view = { name: "", day: "", filters: {}, q: "", reveal: false }; const fetchView = () => {}, table = () => el("div"), codeBox = () => el("div"), hostView = () => {};
""" + it_defs + r"""
const d = JSON.parse(process.argv[1]); const pane = el("div");
try { drawView(pane, d); } catch (e) { keep(e); }
console.log(JSON.stringify({ text: lines(pane) }));
"""
    o, raw = H.run(JS, d)
    if o is None:
        ok("the Abused or Compromised view runs", False, raw)
    else:
        ok("Abused or Compromised: the days the records are dated (dated.text)", DATED in o["text"], o["text"])

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
