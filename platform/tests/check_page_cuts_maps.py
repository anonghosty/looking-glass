#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The two map pages draw every list, share and ring truthfully (2026-11-26, "nothing goes missing"): the page's own
functions (static/js/app.js and services.js, the held copies when there are some) RUN under node on made-up figures:

  Map page Intel panel (app.js renderIntel): a cut list says "Top 6 of 23 networks" and shows every row the page has on
  a click; each hover share is of all events (s.total), 1 of 43,281 reads "<0.1%"; the attack-type ring centres on all
  events and lists "Other"; the severity bar shows a severity the rows leave out, so its parts add up.
  Map page analysis (app.js renderInsight): "Top 8 of 19" over a cut breakdown, "Top 10 of 340 hosts", both rings
  centred on the selection with an "Other" part that makes the parts add up, the share fallback never "0.0%".
  Services Intel (services.js renderIntel): the 80 rows in the browser, 6 drawn, "Top 6 of 23 networks", "Show all".
  Services analysis (services.js renderInsight): "Top 10 of 45", "Top 15 of 230 hosts", rings of the whole selection.
  Services map hover (tipFor): "Reports: ... and 5 more" with the server's per-region totals.

Skips (77) where node is not installed. Run: .venv/bin/python tests/check_page_cuts_maps.py"""
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
        print(f"  FAIL {name}" + (f": {str(detail)[:600]}" if detail else ""))


if not H.NODE:
    print("SKIPPED: node is not installed here (CI runs this check)")
    sys.exit(77)

TOTAL = 43281


def rows(n, first, step, prefix, last=None):
    out = [{"value": f"{prefix}{i}", "label": f"{prefix} {i}", "count": first - i * step, "hosts": 3} for i in range(n)]
    if last is not None:
        out[-1]["count"] = last
    return out


# ---------------------------------------------------------------- app.js
APP = H.page_src("app.js")
print(f"== app.js ({os.path.basename(H.page_path('app.js'))})")
app_defs = H.extract(APP, ["pct", "tipLine", "TOP_SHOWN", "top", "OTHER", "donutChart", "severityMix", "drawDonut", "drawSeverity",
                           "renderIntel", "BREAK_TITLES", "PIVOT_KEYS", "PIVOTS", "card", "renderInsight"], optional=("TOP_SHOWN", "OTHER"))
APP_STUBS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n).toLocaleString("en-US");
const titleCase = (s) => String(s || "");
const countryName = (c) => c, srcLabel = (v) => v, flagImg = () => el("img", "flag");
const SEV_ORDER = ["critical", "high", "medium", "low", "info", "unrated"], ACCENT = "#5b8def", CLASS_INFO = {};
const sevColor = () => "#f00", classColor = () => "#0f0", infColor = () => "#00f", kbEntry = () => null;
const attachTip = (node, fn) => { node._tip = fn; }, showTip = () => {}, hideTip = () => {}, keyable = () => {};
const tipText = (node) => (node._tip ? node._tip().map((x) => x.textContent).join(" | ") : "");
const opened = []; const openScoped = (k, v) => opened.push([k, v]); const drillTo = (d, k, v) => opened.push([k, v]);
const drawHourClass = () => {}, drawTimeline = () => {}, stackedHours = () => {}, quarterHours = () => {};
const state = { facets: {}, demo: false }; const renderParts = () => {}, renderKb = () => {}, renderHostMalpedia = () => {};
const cacheLabel = () => {}, entityLabel = (k, v) => String(v), dayWord = (d) => d, replayNow = () => Date.now(), toggleDrill = () => {}, autoExplain = () => {};
const LT = () => ({ also: () => "", slot: () => "" });
for (const id of ["topSrcNet", "topDstNet", "topSource", "topInfection", "topCity", "topHost", "topDst", "topClass", "donut", "sevBar", "sevLegend"]) {
  const box = el("section"); box.append($(id)); }
const legendOf = (ol) => ol.children.map((li) => ({ text: li.textContent, name: (li.querySelector("span:not(.swatch)") || {}).textContent }));
const centreOf = (svg) => svg.children.filter((c) => c.tag === "text").map((c) => c.textContent);
"""
s = {"total": TOTAL, "totals": {"src_network": 23, "dst_network": 9, "source": 30, "infection": 19, "src_city": 40, "http_host": 77, "dst_geo": 12},
     "src_network": rows(8, 9000, 500, "Net"), "dst_network": rows(8, 3000, 100, "Dst"),
     "source": rows(12, 9000, 600, "rep", last=1), "infection": rows(8, 5000, 300, "inf"), "src_city": rows(8, 4000, 200, "city"),
     "src_geo": [{"value": "GH", "count": TOTAL}], "http_host": rows(8, 900, 50, "dom"), "dst_geo": rows(8, 2000, 100, "C"),
     "attack_class": [{"value": "Scanning", "count": 30000}, {"value": "Botnet C2", "count": 12281}],
     "severity": [{"value": v, "count": c} for v, c in (("critical", 1000), ("high", 20000), ("medium", 15000), ("low", 7000), ("info", 277))],
     "timeline": [], "hours_by_class": {}}
JS = APP_STUBS + app_defs + r"""
const s = JSON.parse(process.argv[1]);
renderIntel(s);
const out = {};
const net = $("topSrcNet"), more = net._more;
out.net_rows = net.children.length; out.net_more = more ? more.textContent : ""; out.net_more_hidden = more ? more.hidden : true;
const btn = more && more.querySelector("button"); out.net_btn = btn ? btn.textContent : "";
if (btn) btn.click();
out.net_rows_after = $("topSrcNet").children.length;
const src = $("topSource"); out.src_more = src._more ? src._more.textContent : "";
out.src_tip0 = tipText(src.children[0]);
const sb = src._more && src._more.querySelector("button"); if (sb) sb.click();
out.src_rows_after = $("topSource").children.length;
out.src_tip_last = tipText($("topSource").children[$("topSource").children.length - 1]);
out.city_tip0 = tipText($("topCity").children[0]);
out.donut = legendOf($("topClass")); out.donut_centre = centreOf($("donut"));
out.sev = $("sevLegend").children.map((x) => x.textContent);
console.log(JSON.stringify(out));
"""
out, raw = H.run(JS, s)
if out is None:
    ok("the Intel panel runs", False, raw)
if out:
    ok("Source networks: 6 of the 8 rows drawn, and the line says 'Top 6 of 23 networks.'",
       out["net_rows"] == 6 and out["net_more"].startswith("Top 6 of 23 networks."), out["net_more"])
    ok("...with a button that shows every row the page has (8), named for what it shows", out["net_btn"] == "Show the top 8" and out["net_rows_after"] == 8,
       (out["net_btn"], out["net_rows_after"]))
    ok("Source reports: 'Top 6 of 30 reports.' and all 12 rows on a click", out["src_more"].startswith("Top 6 of 30 reports.") and out["src_rows_after"] == 12,
       (out["src_more"], out["src_rows_after"]))
    ok("a report's hover share is of ALL events (9,000 of 43,281 = 21%), not of the rows shown", "9,000 events · 21% of all events" in out["src_tip0"], out["src_tip0"])
    ok("...and a report with 1 of 43,281 events reads '<0.1%', never '0%'", "1 events · <0.1% of all events" in out["src_tip_last"], out["src_tip_last"])
    ok("a city's hover share is of all events too (4,000 of 43,281 = 9.2%)", "9.2% of all events" in out["city_tip0"], out["city_tip0"])
    names = [x["name"] for x in out["donut"]]
    ok("attack-type ring: centred on all 43,281 events", out["donut_centre"][:1] == ["43,281"], out["donut_centre"])
    ok("...with an 'Other' part for the 1,000 events the rows leave out, so the parts add up", names[-1:] == ["Other"]
       and out["donut"][-1]["text"] == "Other2.3%", out["donut"])
    ok("severity mix: every severity, plus 'other' for the 4 the server left out ('<0.1%')",
       len(out["sev"]) == 6 and out["sev"][-1] == "other<0.1%", out["sev"])

# the analysis window
d = {"kind": "attack_class", "value": "Scanning", "kind_label": "Attack type", "value_label": "Scanning", "total": 5000, "all_total": TOTAL,
     "share": 0.1155, "hosts": 340, "c2_hosts": 3, "dst_ips": 4, "beacon_median_label": None, "multi_infected": 0, "reports": 3, "cross_report_hosts": 0,
     "insights": [], "hours_by_class": {}, "timeline": [], "current_hour": 3, "as_of": "2026-11-25T12:00:00Z", "peak_hour": None,
     "severity": [{"value": "critical", "count": 3000}, {"value": "high", "count": 1999}],
     "breakdowns": {"infection": rows(8, 600, 20, "inf", last=1), "src_asn": rows(8, 500, 25, "AS")},
     "totals": {"infection": 19, "src_asn": 31},
     "top_hosts": [{"ip": f"192.0.2.{i}", "ref": f"h{i}", "count": 50 - i, "infections": ["x"], "city": "Accra", "asn": "AS1",
                    "first": "2026-11-25T01:00:00Z", "last": "2026-11-25T02:00:00Z"} for i in range(10)]}
for b in d["breakdowns"].values():
    for x in b:
        x["share"] = round(x["count"] / 5000, 4)
JS2 = APP_STUBS + app_defs + r"""
const d = JSON.parse(process.argv[1]);
renderInsight(d);
setTimeout(() => {
  const body = $("iBody"), out = {};
  out.secs = body.querySelectorAll("section").map((s) => ({ h: (s.querySelector("h3") || {}).textContent, hint: (s.querySelector("p.brk-cut") || {}).textContent || "",
    legend: s.querySelector("ol") ? legendOf(s.querySelector("ol")) : null, centre: s.querySelector("svg") ? centreOf(s.querySelector("svg")) : null,
    sev: s.querySelector(".sevlegend") ? s.querySelector(".sevlegend").children.map((x) => x.textContent) : null }));
  out.kpis = body.querySelectorAll(".i-kpi").map((k) => k.textContent);
  const d2 = { ...d, all_total: 0, share: 0.00001 }; renderInsight(d2);
  out.kpis2 = $("iBody").querySelectorAll(".i-kpi").map((k) => k.textContent);
  console.log(JSON.stringify(out));
}, 5);
"""
o2, raw = H.run(JS2, d)
if o2 is None:
    ok("the analysis window runs", False, raw)
if o2:
    by = {x.get("h"): x for x in o2["secs"]}
    ok("breakdown 'Infections / categories': 'Top 8 of 19, by events.'", by.get("Infections / categories", {}).get("hint") == "Top 8 of 19, by events.",
       by.get("Infections / categories"))
    ok("'Most active source hosts': 'Top 10 of 340 hosts, by events.'", by.get("Most active source hosts", {}).get("hint") == "Top 10 of 340 hosts, by events.",
       by.get("Most active source hosts"))
    mix = by.get("Share by infection / category", {})
    inf_rest = 5000 - sum(x["count"] for x in d["breakdowns"]["infection"])
    ok(f"the composition ring is of the whole selection (5,000) with 'Other' ({inf_rest:,})",
       (mix.get("centre") or [""])[0] == "5,000" and (mix.get("legend") or [{}])[-1].get("name") == "Other", mix)
    net = next((x for x in o2["secs"] if x.get("h") == "Source networks" and x.get("legend")), {})
    ok("the networks ring is of the whole selection too, with 'Other'", (net.get("centre") or [""])[0] == "5,000"
       and (net.get("legend") or [{}])[-1].get("name") == "Other", net)
    sev = by.get("Severity mix", {}).get("sev") or []
    ok("the analysis severity mix: the 1 unlisted event as 'other' ('<0.1%')", sev[-1:] == ["other<0.1%"], sev)
    share_kpi = next((k for k in o2["kpis2"] if "Share of all events" in k), "")
    ok("'Share of all events' from the share alone: 1 in 100,000 reads '<0.1%', never '0.0%'", share_kpi.startswith("<0.1%"), share_kpi)

# ---------------------------------------------------------------- services.js
SVC = H.page_src("services.js")
print(f"== services.js ({os.path.basename(H.page_path('services.js'))})")
svc_defs = H.extract(SVC, ["pct", "tipLine", "OTHER", "donutChart", "severityMix", "TOP_SHOWN", "topList", "swatchLabel", "renderIntel",
                           "card", "BREAK_TITLES", "KEY_OF", "unknownNote", "loadNotes", "noteUnder", "renderInsight"],
                      optional=("TOP_SHOWN", "OTHER", "unknownNote", "loadNotes", "noteUnder"))
svc_map = H.extract(SVC, ["LISTS", "countOf", "mergeRegion", "tipList", "tipFor"], optional=("LISTS", "countOf", "tipList"), indent=4)
SVC_STUBS = r"""
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const fmt = (n) => Math.round(n || 0).toLocaleString("en-US"), titleCase = (s) => String(s || "");
const SEV_ORDER = ["critical", "high", "medium", "low", "info"], ACCENT = "#5b8def", PAL = ["#111", "#222", "#333"];
const sevColor = () => "#f00", famColor = () => "#0f0", flagImg = () => el("img", "flag"), defOf = () => null;
const attachTip = (node, fn) => { node._tip = fn; }, showTip = () => {}, hideTip = () => {}, keyable = () => {};
const tipText = (node) => (node._tip ? node._tip().map((x) => x.textContent).join(" | ") : "");
const openInsight = () => {}, narrow = (p) => p, filterPairs = () => [], quarterHours = () => {}, stackedHours = () => {};
const state = { dayStart: null, svcFamily: new Map(), glossary: null }; const replayNow = () => Date.now();
const COUNTRY = { code: "GH" }; const kindLabel = () => "Selection", selTitle = () => "All", renderParts = () => {}, defBox = () => {};
const toggleDrill = () => {}, explainAll = () => {}, refLabels = new Map();
for (const id of ["topIssue", "topService", "topNet", "topRegion", "topCity", "topVendor", "topProduct", "topPort", "topFamily", "donut", "sevBar", "sevLegend"]) {
  const box = el("section"); box.append($(id)); }
const legendOf = (ol) => ol.children.map((li) => ({ text: li.textContent, name: (li.querySelector("span:not(.swatch)") || {}).textContent }));
const centreOf = (svg) => svg.children.filter((c) => c.tag === "text").map((c) => c.textContent);
let file = null; const nameOf = (k) => k;
"""
b = {"issue": rows(10, 900, 30, "iss"), "service": rows(10, 9000, 300, "svc"), "network": rows(80, 2000, 20, "N"), "region": rows(5, 9000, 1000, "R"),
     "city": rows(12, 3000, 100, "c"), "vendor": rows(3, 100, 10, "v"), "product": rows(3, 100, 10, "p"), "port": rows(7, 900, 10, "p"),
     "family": [{"value": "Exposed service", "label": "Exposed service", "count": 30000, "hosts": 9}, {"value": "Identified device", "label": "Identified device", "count": 13000, "hosts": 9}]}
sv = {"total": TOTAL, "breakdowns": b, "severity": [], "quarters": [], "hours_by_family": {}, "totals": {"network": 230, "issue": 10, "city": 12}}
JS3 = SVC_STUBS + svc_defs + svc_map + r"""
const s = JSON.parse(process.argv[1]); const out = {};
renderIntel(s);
const net = $("topNet"); out.net_rows = net.children.length; out.net_more = net._more ? net._more.textContent : "";
const nb = net._more && net._more.querySelector("button"); out.net_btn = nb ? nb.textContent : ""; if (nb) nb.click();
out.net_rows_after = $("topNet").children.length;
const city = $("topCity"); out.city_more = city._more ? city._more.textContent : "";
const iss = $("topIssue"); out.iss_more = iss._more ? iss._more.textContent : "";
out.fam = legendOf($("topFamily")); out.fam_centre = centreOf($("donut"));
// the map hover: the server's per-region totals
const r1 = { events: 10, hosts: 4, vulnerable_hosts: 1, critical: 0, raw: "A", services: [["svc A", 5], ["svc B", 3], ["svc C", 1], ["svc D", 1]],
  issues: [], cities: [["Accra", 6], ["Tema", 2], ["Ho", 1], ["Keta", 1]], networks: [], totals: { services: 9, cities: 4 } };
out.tip = tipFor("A", r1).map((x) => x.textContent);
console.log(JSON.stringify(out));
"""
o3, raw = H.run(JS3, sv)
if o3 is None:
    ok("the services Intel panel runs", False, raw)
if o3:
    ok("Networks: 6 of the 80 rows drawn, 'Top 6 of 230 networks.'", o3["net_rows"] == 6 and o3["net_more"].startswith("Top 6 of 230 networks."), o3["net_more"])
    ok("...a click shows the 80 rows the page has (named 'Show the top 80', as 230 exist)", o3["net_btn"] == "Show the top 80" and o3["net_rows_after"] == 80,
       (o3["net_btn"], o3["net_rows_after"]))
    ok("Cities: 'Top 6 of 12 cities.' and a 'Show all 12' button", o3["city_more"].startswith("Top 6 of 12 cities.") and "Show all 12" in o3["city_more"], o3["city_more"])
    ok("Issues: 'Top 6 of 10 issues.'", o3["iss_more"].startswith("Top 6 of 10 issues."), o3["iss_more"])
    ok("report-family ring: centred on all 43,281 records, 'Other' for the 281 the rows leave out",
       o3["fam_centre"][:1] == ["43,281"] and o3["fam"][-1]["name"] == "Other" and o3["fam"][-1]["text"].endswith("0.6%"), (o3["fam_centre"], o3["fam"]))
    rep = next((t for t in o3["tip"] if t.startswith("Reports:")), "")
    cit = next((t for t in o3["tip"] if t.startswith("Cities:")), "")
    ok("map hover: 'Reports: ... and 5 more' when the region has 9 reports and 4 are listed", rep.endswith("svc D 1 and 5 more"), rep)
    ok("...and nothing added when all 4 cities are listed", cit == "Cities: Accra 6, Tema 2, Ho 1, Keta 1", cit)

d = {"total": 5000, "day_total": TOTAL, "day": "2026-11-25", "hosts": 230, "vulnerable_hosts": 3, "issues": 45, "multi_issue_hosts": 0, "services": 10,
     "cross_report_hosts": 0, "networks": 40, "regions": 3, "findings": [], "peak_hour": None, "hours_by_family": {}, "quarters": [], "severity": [],
     "breakdowns": {"family": [{"value": "Exposed service", "label": "Exposed service", "count": 4000, "hosts": 9}, {"value": "Identified device", "label": "Identified device", "count": 900, "hosts": 9}],
                    "service": rows(10, 400, 10, "svc"), "issue": rows(10, 300, 10, "iss"), "network": rows(10, 400, 10, "N")},
     "totals": {"issue": 45, "network": 40, "service": 10}, "others": {"issue": 1200},
     "host_rows": [{"ref": f"h{i}", "ip": f"192.0.2.{i}", "issues": [], "services": ["x"], "events": 3, "city": "", "network": "", "vendor": "", "product": "", "last": ""} for i in range(15)],
     "hosts_total": 230}
for k, v in d["breakdowns"].items():
    for x in v:
        x["share"] = round(x["count"] / 5000, 4)
JS4 = SVC_STUBS + svc_defs + r"""
const d = JSON.parse(process.argv[1]);
renderInsight([], d);
setTimeout(() => {
  const body = $("iBody");
  const secs = body.querySelectorAll("section").map((s) => ({ h: (s.querySelector("h3") || {}).textContent, hint: (s.querySelector("p.brk-cut") || {}).textContent || "",
    legend: s.querySelector("ol") ? legendOf(s.querySelector("ol")) : null, centre: s.querySelector("svg") ? centreOf(s.querySelector("svg")) : null }));
  console.log(JSON.stringify({ secs }));
}, 5);
"""
o4, raw = H.run(JS4, d)
if o4 is None:
    ok("the services analysis runs", False, raw)
if o4:
    secs = o4["secs"]
    hint = lambda h: next((x["hint"] for x in secs if x.get("h") == h and x["hint"]), "")  # noqa: E731
    ok("breakdown 'Issues': 'Top 10 of 45, by records.'", hint("Issues") == "Top 10 of 45, by records.", [x for x in secs if x.get("h") == "Issues"])
    ok("'Services (reports)': all 10 shown, no cut line", hint("Services (reports)") == "", hint("Services (reports)"))
    ok("'Hosts to follow up first': 'Top 15 of 230 hosts, by follow-up priority.'", hint("Hosts to follow up first") == "Top 15 of 230 hosts, by follow-up priority.",
       hint("Hosts to follow up first"))
    fam = next((x for x in secs if x.get("h") == "Share by report family"), {})
    ok("the family ring is of the selection (5,000 records) with 'Other' (100)", (fam.get("centre") or [""])[0] == "5,000"
       and (fam.get("legend") or [{}])[-1].get("name") == "Other" and (fam.get("legend") or [{}])[-1].get("text", "").endswith("2.0%"), fam)
    iss = next((x for x in secs if x.get("h") == "Issues" and x["legend"]), {})
    ok("the issues ring: 'Other issues' is the server's own count (1,200 records = 24%), shares of the 5,000",
       (iss.get("centre") or [""])[0] == "5,000" and (iss.get("legend") or [{}])[-1].get("text") == "Other issues24%", iss)

print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
