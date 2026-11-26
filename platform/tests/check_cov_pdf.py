#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The three report PDFs built from rich made-up inputs, every section and every kind of explanation: the analysts'
report of a figure (reports_pdf.py), the Executive report (executive_pdf.py) and the analyst's combination report with
and without an advisory in front (combo_pdf.py). Documentation addresses, private AS numbers and made-up names only.
Each PDF must render (%PDF), and what it prints (every text drawn, read as it is drawn) must hold the sections, the
explanations' facts and warnings, and never a cut-off "…" in place of text:
- every kind of explanation: an actively exploited CVE (CISA's action, ransomware use), a CVE not in KEV, one not looked
  up yet, a threat actor, a Malpedia family, a Looking Glass definition, an offline reference, an unknown name
- long lists continue on their own pages (key findings, every report, the explanations, Across reports patterns)
- the region map: matched regions, a region too small to see (a dot), zoomed to the records, the whole country as one
- an advisory: its TLP label, the preview's watermark and who/when, the plain look, IP addresses in place of codes
With pypdfium2 installed the PDF's own text is checked for "…" too. No database needed.
Run: .venv/bin/python tests/check_cov_pdf.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import combo_pdf as CP  # noqa: E402
import executive_pdf as EXP  # noqa: E402
import reports_pdf as RP  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None


def pdf_cut(data):
    """True when the PDF's own text has a "…" (only checked where pypdfium2 is installed)."""
    if pdfium is None:
        return False
    d = pdfium.PdfDocument(data)
    return any("…" in d[i].get_textpage().get_text_range() for i in range(len(d)))


DRAWN = []
_text, _P = EXP.Doc.text, RP.P


def rec_text(self, x, y, t, *a, **k):
    DRAWN.append(str(t) + (" " + " ".join(t.lines) if getattr(t, "lines", None) else ""))
    return _text(self, x, y, t, *a, **k)


def rec_P(text, st, **kw):
    DRAWN.append(str(text))
    return _P(text, st, **kw)


EXP.Doc.text = rec_text
RP.P = rec_P


def drawn(fn):
    DRAWN.clear()
    data = fn()
    return data, " ".join(DRAWN)


ATTACK = {"version": "18.1", "techniques": [
    {"id": "T1071.001", "name": "Web Protocols", "tactics": ["Command and Control"], "certainty": "observed", "certainty_label": "Observed",
     "status": "reviewed", "url": "https://attack.mitre.org/techniques/T1071/001/"},
    {"id": "T1190", "name": "Exploit Public-Facing Application", "tactics": ["Initial Access"], "certainty": "possible",
     "certainty_label": "Possible", "status": "reviewed", "url": "https://attack.mitre.org/techniques/T1190/"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactics": ["Execution"], "certainty": "known",
     "certainty_label": "Known", "status": "reviewed", "url": "https://attack.mitre.org/techniques/T1059/"}]}
LONG = "What this family does, in words long enough to wrap over several lines of a card. " * 6
ENR = {
    "CVE-2099-0001": {"kind": "cve", "exploited": True, "found": True, "kev": {"name": "Example Gateway Command Injection", "date_added": "2026-01-05",
                      "vendor": "Example Corp", "product": "Gateway", "ransomware": "Known", "action": "Apply the vendor's update.", "due": "2026-01-26"},
                      "cvss": {"score": 9.8, "version": "3.1", "severity": "critical", "source": "NVD"}, "sources": ["CVE Program"], "nvd": False,
                      "epss": 0.9712, "epss_percentile": 0.999, "published": "2026-01-02", "description": "A command injection in Example Gateway.",
                      "cwes": "CWE-78", "note": "Seen on many routers.", "note_by": "Grace"},
    "CVE-2099-0002": {"kind": "cve", "found": True, "cvss": {"score": 7.5, "severity": "high"}, "epss": 0.02, "description": "A leak.", "nvd": True,
                      "sources": ["NVD"]},
    "CVE-2099-0003": {"kind": "cve", "pending": True, "cvss": {"score": 5.0, "severity": "medium"}},
    "CVE-2099-0004": {"kind": "cve"},
    "exampleactor": {"found": True, "kind": "actor", "name": "Example Actor", "matched_by": "alias", "description": LONG, "families": "examplebot",
                     "attribution": "Unknown group", "country": "Nowhere", "sponsor": "none known", "targets": "routers", "sectors": "telecoms",
                     "licence_short": "CC BY-SA 4.0", "also": [{"source_label": "MISP Galaxy"}]},
    "examplebot": {"found": True, "name": "ExampleBot", "family": "win.examplebot", "matched_by": "name", "type": "Botnet", "description": LONG,
                   "alt_names": "EBot", "seen_in": "Sinkhole Events", "near": "examplebot2", "updated": "2026-11-01", "by": "Malpedia",
                   "attack": ATTACK, "notes": [{"role": "Researcher/TI", "by": "Grace", "date": "2026-11-16", "text": "Calls home hourly.",
                                                "codes": [{"code": "LG-C-0001", "text": "the hourly pattern"}]}]},
    "samplerat": {"curated": True, "title": "Sample RAT", "description": "A remote access tool.", "updated": "2026-11-02", "by": "Daniel",
                  "type": "Remote access"},
    "demoloader": {"reference": True, "source_label": "MISP Galaxy", "id": "misp-1", "matched_by": "synonym", "name": "Demo Loader",
                   "description": "A loader."},
    "testworm": {"pending": True},
    "mockminer": {"reason": "No source knows this name yet."}}

print("1. The analysts' report of a figure (reports_pdf.py)")
print("   the building blocks")
S = RP.styles()
ok("a value of any kind as safe text: lists joined, markup escaped, nothing for None", RP.t(["a", "b<c>"]) == "a, b&lt;c&gt;" and RP.t(None) == "")
uni = RP._FONT.get("unicode")
RP._FONT["unicode"] = False
ok("…without a Unicode font: arrows and quotes in plain letters", RP.t("a → b “c” …") == "a -&gt; b \"c\" ...")
RP._FONT["unicode"] = uni
ok("a link that is no web address is printed as text, not linked", "href" not in RP.link("ftp://x", S["link"]).text and "href" in RP.link("https://www.example.org/", S["link"]).text)
ok("a cell longer than the limit ends with 'more in the CSV'", RP._cell("word " * 400).endswith("… (more in the CSV)") and RP._cell(["a", "b"]) == "a, b" and RP._cell(None) == "")
ok("key-figure tiles: nothing to show is a spacer; 7 figures make two rows", isinstance(RP.kpi_grid([(None, "x")], S, 500), RP.Spacer)
   and len(RP.kpi_grid([(i, f"f{i}") for i in range(7)], S, 500)._cellvalues) == 2)
ok("hour bars: none without hours; drawn with the peak", RP.bar_hours([0] * 24, S, 500, "t") is None and RP.bar_hours(list(range(24)), S, 500, "t", peak=23) is not None)
ok("top bars: none under two rows; drawn with names", RP.bar_top([{"label": "a", "count": 1}], 500, "t") is None
   and RP.bar_top([{"label": "a → b", "count": 3}, {"value": "c", "count": 2}], 500, "t") is not None)
ok("explanation badges, one per kind", [RP._kind(ENR[k])[0] for k in ("CVE-2099-0001", "CVE-2099-0002", "CVE-2099-0004", "exampleactor", "examplebot",
                                                                     "samplerat", "demoloader", "testworm", "mockminer")]
   == ["kev", "cve", "none", "actor", "found", "curated", "reference", "none", "none"])
ok("…a CVE not looked up yet says so", RP._kind(ENR["CVE-2099-0003"])[1] == "CVE · not looked up yet")
RP.MAX_ROWS, real_max = 3, RP.MAX_ROWS
SPEC = {"platform": "comms", "platform_label": "Network communications", "title": "Devices calling sinkholes", "selection": "Example Net",
        "day": "2026-11-17", "generated_by": "Grace Mensah", "scope": "Ghana · whole country", "intro": "What this figure shows.",
        "summary_points": ["300 devices", "5 infections"], "kpis": [("300", "Devices"), ("5", "Infections"), ("", "skipped"), ("12", "Networks"), ("4", "Regions")],
        "hours": list(range(24)), "peak_hour": 23,
        "geo": {"title": "Where the devices are", "note": "Regions by devices.", "regions": [{"value": "GREATER ACCRA", "label": "Greater Accra", "count": 30, "hosts": 20},
                                                                                        {"value": "ASHANTI", "label": "Ashanti", "count": 10, "hosts": 5}],
                "details": {"GREATER ACCRA": {"city_devices": [["Accra", 15], ["Tema", 5]]}}},
        "priorities": (["Device", "Why"], [["192.0.2.1", "Several infections"]], [.3, .7]), "priorities_intro": "",
        "enrichment": ENR, "enrichment_stats": {"examplebot": "120 devices"}, "enrichment_note": "Explained by these sources.",
        "charts": [("Ports", [{"label": "80", "count": 5}, {"label": "443", "count": 3}]), ("Countries", [{"label": "US", "count": 4}, {"label": "NL", "count": 2}]),
                   ("One only", [{"label": "x", "count": 1}])],
        "breakdowns": [("Networks", ["Network", "Devices"], [["Example Net", 20]], [.6, .4]), ("Cities", ["City", "Devices", "Events"], [["Accra", 15, 30]]),
                       ("Empty", ["X"], []), ("Single column", ["Only"], [["one"]])],
        "columns": [["ip", "IP address"], ["infection", "Infection"], ["_explained", "What it is"], ["_source", "Source"]],
        "rows": [{"ip": f"192.0.2.{i}", "infection": "examplebot", "_explained": "A botnet.", "_source": "Malpedia"} for i in range(6)],
        "total": 6, "glossary": [("Sinkhole Events", "Devices calling sinkholes.", "https://www.shadowserver.org/what-we-do/network-reporting/sinkhole-events-report/"),
                                 ("No link", "x", "")],
        "sources": ["Shadowserver Foundation daily reports", "Malpedia"], "demo": True}
pdf, txt = drawn(lambda: RP.build(SPEC))
ok("renders", pdf[:4] == b"%PDF")
for part in ("Executive summary", "Where the devices are", "Priorities", "Infections and categories explained", "Breakdowns",
             "The complete list", "References", "About this report"):
    ok(f"…has '{part}'", part in txt)
ok("…the actively exploited CVE: CISA's catalog, the ransomware use, the required action and its due date",
   "Known Exploited Vulnerabilities catalog on 2026-01-05" in txt and "used in ransomware campaigns" in txt and "(due 2026-01-26" in txt)
ok("…a CVE not in KEV says it is no proof of safety", "this does not mean it is safe" in txt)
ok("…CVSS with its source, EPSS with its percentile, NVD's analysis to come", "base score 9.8 (Critical, from NVD)" in txt
   and "more likely than 99.9% of all CVEs" in txt and "NVD's own analysis is added within minutes" in txt)
ok("…a threat actor is no malware program", "is a threat actor (a group of attackers), not a malware program; matched by alias" in txt)
ok("…Malpedia family, the reference, aliases, origin, targets, sectors, weakness, update", all(s in txt for s in (
    "Malpedia family win.examplebot, matched by name", "Answered by MISP Galaxy (misp-1), matched by synonym", "Also known as", "Suspected origin",
    "Targets", "Sectors", "Malware it uses", "Weakness", "Updated", "Similar names in Malpedia", "Seen in reports")))
ok("…the researchers' notes with their combinations", "Notes shared by Researcher/TI: Grace" in txt and "LG-C-0001" in txt)
ok("…MITRE ATT&CK with the certainty in colour", "Observed" in txt and "T1071.001" in txt)
ok("…only the first rows printed, the CSV has the rest", "the first 3 are printed here" in txt and "which sources know it" in txt)
ok("…demo mode marked", "Demo mode (masked)" in txt)
ok("…no '…' in place of text", "…" not in txt and not pdf_cut(pdf))
spec2 = dict(SPEC, columns=[["ip", "IP address"], ["_explained", "What it is"]], csv_name="figure.csv", total=1, rows=SPEC["rows"][:1],
             demo=False, executive=True, geo={"regions": SPEC["geo"]["regions"], "shapes": {"bbox": [0, 0, 1, 1], "regions": {}}},
             platform_label="Publicly accessible services", hours=None)
pdf2, txt2 = drawn(lambda: RP.build(spec2))
ok("with a CSV: the complete list is in the CSV, named, with what each infection is", pdf2[:4] == b"%PDF"
   and "is in the CSV file delivered with this report, figure.csv" in txt2 and "plus what each infection / issue is" in txt2 and "1 entry" in txt2)
spec3 = dict(SPEC, columns=[["ip", "IP address"], ["_explained", "What it is"]], total=1, rows=SPEC["rows"][:1], enrichment={}, geo=None)
pdf3, txt3 = drawn(lambda: RP.build(spec3))
ok("…without one: the last column gives what each is", "The last column gives what each infection / category is" in txt3)
spec4 = dict(SPEC, columns=[["ip", "IP address"]], total=2, rows=SPEC["rows"][:2], enrichment={}, charts=[], breakdowns=[], geo=None, glossary=[])
pdf4, txt4 = drawn(lambda: RP.build(spec4))
ok("…a plain list: no word about explanations; no breakdowns section", "2 entries." in txt4 and "Breakdowns" not in txt4)
RP.MAX_ROWS = real_max

print("2. The Executive report (executive_pdf.py)")
REG = [{"value": "GREATER ACCRA", "label": "Greater Accra", "count": 60, "hosts": 40}, {"value": "Ashanti Region", "label": "Ashanti", "count": 20, "hosts": 10},
       {"value": "TINY ISLAND", "label": "Tiny Island", "count": 3, "hosts": 2}, {"value": "Unknown region", "label": "Unknown", "count": 1, "hosts": 1},
       {"value": "NOWHERE", "label": "Nowhere", "count": 1}]
SHAPES = {"bbox": [0, 0, 10, 10], "regions": {
    "GA": {"name": "Greater Accra Region", "polys": [[[[0, 0], [5, 0], [5, 5], [0, 5]]]], "label": [2.5, 2.5]},
    "AS": {"name": "Ashanti", "polys": [[[[5, 5], [10, 5], [10, 10], [5, 10]]]], "aliases": ["Ashanti Region"]},
    "TI": {"name": "Tiny Island", "polys": [[[[9.9, 0.1], [9.91, 0.1], [9.91, 0.11]]]]}}}
DETAILS = {"GREATER ACCRA": {"city_devices": [["Accra", 30], ["Tema", 8], ["Greater Accra", 2], ["Madina", 0]]}}


def base_d(comms):
    rows = [{"label": f"Row {i}", "value": f"v{i}", "count": 50 - i, "hosts": 30 - i} for i in range(9)]
    findings = [f"Finding {i}: " + "a long observation about the week's devices and networks, " * 4 for i in range(16)]
    d = {"platform": "comms" if comms else "services", "day": "2026-11-17", "cities_map": [], "tz": {"zone": "Africa/Nairobi", "same_as_utc": False,
         "offset_minutes": 180, "city": "Nairobi"}, "findings": findings, "hours": [i % 7 for i in range(24)], "peak_hour": 6,
         "regions": REG, "region_details": DETAILS, "sectors": rows[:3] + [{"label": f"S{i}", "count": 1} for i in range(8)], "attack": rows[:3],
         "families": rows[:3], "networks": [{"label": "Example Net", "value": "Example Net", "hosts": 9}, {"label": "Unknown", "value": "Unknown network", "hosts": 1}],
         "destinations": [{"label": "US", "count": 5}, {"label": "ZZ", "count": 2}, {"label": "KZ", "count": 1}], "services": rows[:4],
         "multi": {"devices": 10, "hosts": 10, "share": .1, "by_count": [{"label": "2", "count": 8}, {"label": "3", "count": 2}],
                   "combos": [{"label": "examplebot + samplerat", "count": 4}], "combinations": 3},
         "cross": {"devices": 7, "hosts": 7, "share": .07, "by_count": [{"label": "2", "count": 7}], "combinations": 2, "combos": [],
                   "pairs": [{"label": "A + B", "count": 3}]}, "report_pairs": [{"label": "Sinkhole + Honeypot", "count": 3}],
         "beacon": {"repeating": 5, "regular": 2, "typical": "1 h"}, "issue_kinds": [{"label": "CVE", "count": 4}, {"label": "Other", "count": 2}],
         "severity": [{"value": "critical", "label": "Critical", "count": 3}, {"value": "low", "label": "Low", "count": 1}],
         "reports": [{"label": f"Example report number {i} with a fairly long name that wraps", "value": f"rep_{i}", "hosts": 300 - i, "count": 900 - i}
                     for i in range(150)],
         "baseline": {"days": [f"2026-11-{d:02d}" for d in range(10, 18)], "available": 5, "kpis": {"devices": [10, 12, None, 11, 9, 10, 13], "hosts": [1] * 7},
                      "items": {"examplebot": [3, 4, 5, None, 6, 7, 8], "CVE-2099-0001": [1, 1]},
                      "assess": {"kpis": {"devices": {"label": "Normal", "level": "normal"}, "hosts": {"label": "Rising", "level": "watch"}},
                                 "items": {"examplebot": {"label": "Rising", "level": "watch", "note": "Check the new devices."},
                                           "CVE-2099-0001": {"label": "New", "level": "high", "note": "Patch first."}}},
                      "scale": [{"name": "Normal", "level": "normal", "range": "-10% to +10%", "meaning": "Nothing unusual."}]}}
    if comms:
        d["kpis"] = {"devices": 300, "infections": 5, "multi_infected": 10, "cross_report": 7, "regions": 4, "networks": 12, "events": 900,
                     "share_of_day": .4, "critical": 3}
        d["infections"] = [{"value": "examplebot", "title": "ExampleBot", "hosts": 40, "count": 90, "family": "win.examplebot"},
                           {"value": "exampleactor", "title": "Example Actor", "hosts": 20, "count": 30, "family": "actor:example"},
                           {"value": "samplerat", "title": "Sample RAT", "hosts": 10, "count": 12},
                           {"value": "mockminer", "hosts": 3, "count": 3}]
    else:
        d["kpis"] = {"hosts": 500, "services": 800, "vulnerable_hosts": 120, "kev_hosts": 30, "kev_cves": 2, "critical_cves": 3, "multi_issue": 15,
                     "records": 2000, "share_of_day": .5, "cves": 4, "issues": 6, "cross_report": 7}
        d["issues"] = [{"value": "CVE-2099-0001", "title": "Example Gateway Command Injection", "hosts": 30, "count": 40, "exploited": True,
                        "cvss": 9.8, "epss": .97, "cve": True},
                       {"value": "CVE-2099-0002", "hosts": 20, "count": 20, "exploited": False, "cvss": 7.5, "epss": .01, "cve": True},
                       {"value": "CVE-2099-0003", "hosts": 10, "count": 10, "exploited": False, "cvss": 5.0, "cve": True},
                       {"value": "open-telnet", "title": "Telnet open", "hosts": 9, "count": 9, "exploited": False, "cvss": None}]
        d["infections_on"] = [{"value": "examplebot", "hosts": 5, "count": 5, "exploited": False, "cvss": None, "infection": True}]
    return d


META = {"platform_label": "Network communications", "scope": "Ghana · whole country", "selection": "Whole country", "generated_by": "Grace Mensah",
        "shapes": SHAPES, "stats": {"examplebot": "40 devices"}, "demo": True}
ENR_BIG = dict(ENR, **{f"extra{i}": {"curated": True, "title": f"Extra {i}", "description": LONG} for i in range(8)})
pdf, txt = drawn(lambda: EXP.build(base_d(True), ENR_BIG, META))
ok("communications: renders", pdf[:4] == b"%PDF")
for part in ("Key findings (continued)", "7-day baseline", "Regions and cities", "Top infections", "Where infected devices connect to",
             "Deeper insight", "Repeat behaviour", "EVERY REPORT OF THIS SELECTION (150)", "WHAT THE TOP INFECTIONS ARE"):
    ok(f"…has '{part}'", part in txt)
ok("…the findings that do not fit the card continue on their own page, none dropped", "Finding 15:" in txt and "more on the next page" in txt)
ok("…the peak hour in the installation's own time beside UTC", "(09:00 Nairobi time)" in txt)
ok("…the regions: a region named differently on the map (Ashanti Region) found by its alias, cities under it",
   "Ashanti" in txt and "Accra" in txt and "Tema" in txt)
ok("…countries by name: the short table, then the world list, else the code", "United States" in txt and "Kazakhstan" in txt and "ZZ" in txt)
ok("…pills: a threat actor, a Malpedia family, a Looking Glass definition", "Threat actor" in txt and "Malpedia" in txt and "Looking Glass definition" in txt)
ok("…the actively exploited CVE's alert box with CISA's action", "Actively exploited since 2026-01-05; used in ransomware" in txt and "Required action" in txt)
ok("…ATT&CK on the card: techniques by tactic, the known ones counted", "ATT&CK v18.1" in txt and "1 techniques known for this malware" in txt)
ok("…what changed in 7 days, with the advice under a rising item", "Check the new devices." in txt and "How changes are graded" in txt)
ok("…no '…' in place of text", "…" not in txt and not pdf_cut(pdf))
m2 = dict(META, platform_label="Publicly accessible services", nomap=True, demo=False)
d2 = base_d(False)
d2["baseline"]["available"] = 1
pdf, txt = drawn(lambda: EXP.build(d2, {k: ENR[k] for k in ("CVE-2099-0001", "CVE-2099-0002", "samplerat")}, m2))
ok("services: renders, the map left out when its regions are not on it", pdf[:4] == b"%PDF" and "Map left out" in txt)
ok("…pills: actively exploited, CVSS, EPSS, an infection on the hosts, a configuration issue", all(s in txt for s in (
    "Actively exploited", "CVSS 9.8", "EPSS 97%", "Infection / category · calling botnet sinkholes", "Configuration / exposure")))
ok("…fewer than 3 days: 'not enough days yet' in place of a grade", "not enough days yet" in txt)
ok("…kinds of issue and exposed services", "Kinds of issue" in txt and "Exposed services" in txt)
doc = EXP.Doc(dict(META, day="2026-11-17"))
doc.new_page("Map tests")
DRAWN.clear()
doc.region_map(30, 500, 300, 300, {"bbox": [0, 0, 10, 10], "regions": SHAPES["regions"]}, [REG[2]], {}, True)
ok("a map whose records are all in a tiny region: zoomed to it, said so", any("Zoomed to the regions with records" in s for s in DRAWN))
DRAWN.clear()
doc.region_map(30, 500, 300, 300, {"bbox": [0, 0, 10, 10], "whole": True, "regions": {"GA": SHAPES["regions"]["GA"]}}, REG[:2], {}, True)
ok("the whole country as one area: every row adds to it (40 + 10 hosts)", any(s == "Greater Accra" for s in DRAWN) and "50" in DRAWN, str(DRAWN[-6:]))
DRAWN.clear()
doc.region_map(30, 500, 300, 300, None, REG, {}, True)
ok("no map for the country: said so", "No region map for this country." in DRAWN)
DRAWN.clear()
doc.spark(10, 10, 100, 20, [None, None], None)
ok("a trend with fewer than two days: said so", "not enough days yet" in DRAWN)
EXP._ISO_NAMES = None
real_open = open


def no_iso(path, *a, **k):
    if "iso_3166" in str(path):
        raise OSError("not installed")
    return real_open(path, *a, **k)


import builtins  # noqa: E402
builtins.open = no_iso
try:
    ok("without the system's country list: Kosovo still named, an unknown code kept", EXP._country("XK") == "Kosovo" and EXP._country("QQ") == "QQ")
finally:
    builtins.open = real_open
EXP._ISO_NAMES = None

print("3. The analyst's combination report (combo_pdf.py)")


def devs(n, earlier=True):
    return [{"ip": f"192.0.2.{i}", "network": "Example Net", "asn": 64500 + i % 3, "region": "Greater Accra", "city": "Accra", "records": 50 - i % 50,
             "days": 3, "last": "2026-11-17 10:00", "flags": {"infections": ["examplebot"], "issues": ["open-telnet"], "cves": ["CVE-2099-0001"]},
             "also": "Honeypot Events" if i % 2 else "", "earlier": ("2026-11-15: carried this same combination; " * 3) if earlier and i % 3 == 0 else ""}
            for i in range(n)]


PATTERNS = [{"code": f"LG-C-{i:04d}", "devices": 9 - i % 9, "ips": [f"198.51.100.{j}" for j in range(45)],
             "parts": [{"report": "event4_sinkhole", "title": "Sinkhole Events with a long title that wraps", "items": [f"Tag: tag-{k}" for k in range(12)]},
                       {"report": "scan_http", "items": ["Port: 80", "Server: ExampleServer/1.0"]}]} for i in range(14)]


def combo_d(**over):
    d = {"section": "infections", "code": "LG-C-0001", "name": "examplebot", "headline": "Devices calling sinkholes as ExampleBot from Example Net",
         "parts": [("Sinkhole Events", ["Port: 80", "Tag: botnet"] + [f"Tag: extra-label-number-{i}" for i in range(14)]), ("Honeypot Events", [])],
         "kpis": {"devices": 60, "records": 400, "repeat": 0, "also": 5, "regions": 2, "cities": 1, "networks": 3},
         "hours": [i % 5 for i in range(24)], "peak_hour": 4, "findings": [f"Finding {i}." for i in range(5)], "devices": devs(60),
         "csv_devices": "LG-C-0001_devices.csv", "csv_records": "LG-C-0001_records.csv", "shapes": SHAPES, "regions": REG[:3], "region_details": DETAILS,
         "networks": [{"label": "Example Net", "hosts": 30}], "cities": [{"label": "Accra", "hosts": 30}],
         "across": {"multi": 12, "patterns_total": 14, "patterns": PATTERNS}, "report_sets": [{"label": "Sinkhole + Honeypot", "hosts": 4}],
         "kinds": [{"label": "MikroTik router", "count": 6}, {"label": CP.NOT_GIVEN, "count": 1}], "ports": [{"label": "80/tcp", "count": 9}],
         "explained": [(k, ENR[k]) for k in ("examplebot", "exampleactor", "demoloader", "mockminer", "CVE-2099-0001", "CVE-2099-0002")]
                      + [(f"extra{i}", ENR_BIG[f"extra{i}"]) for i in range(6)],
         "notes": [{"name": "examplebot", "role": "Researcher/TI", "by": "Grace", "date": "2026-11-16", "text": LONG, "codes": [{"code": "LG-C-0001"}]},
                   {"role": "", "by": "", "text": "Another note.", "codes": [{"code": "LG-C-0999"}]}] * 3,
         "stats": {"examplebot": "60 devices"}, "ref_levels": {}, "ref_reports": ["event4_sinkhole", "scan_http"]}
    d.update(over)
    return d


CMETA = {"platform_label": "Network communications", "scope": "Ghana · whole country", "selection": "Example Net", "day": "2026-11-17",
         "generated_by": "Grace Mensah", "header": "LG-C-0001 · examplebot"}
pdf, txt = drawn(lambda: CP.build(combo_d(), CMETA))
ok("the analyst's report renders", pdf[:4] == b"%PDF")
for part in ("COMBINATION LG-C-0001", "Geographic Location", "The IP addresses with the most records", "The IP addresses (continued)",
             "Across reports, continued", "What the devices are", "WHAT THE NAME AND ITS VULNERABILITIES ARE", "Researcher/TI note on examplebot",
             "On this combination", "ANALYST · COMBINATION"):
    ok(f"…has '{part}'", part in txt)
ok("…the cross-report patterns by their codes", "LG-C-0013" in txt and "LG-C-0000" in txt)
ok("…what the card says about where it comes from (read as Malpedia's family, defined by)", "examplebot is read as Malpedia's win.examplebot (name)" in txt
   and "Defined by Malpedia, updated 2026-11-01" in txt)
ok("…the CVE's alert box and the 'used in ransomware' words", "Actively exploited since 2026-01-05; used in ransomware" in txt)
ok("…'0%' when none repeat it", "0% of the devices" in txt)
ok("…no '…' in place of text", "…" not in txt and not pdf_cut(pdf))
d_svc = combo_d(section="services", code="LG-A-0007", hours=None, devices=devs(30, earlier=False), shapes=None, report_sets=[], ports=[],
                kinds=[{"label": CP.NOT_GIVEN, "count": 3}], across={"multi": 3, "patterns_total": 0, "patterns": []}, notes=[],
                explained=[("CVE-2099-0001", ENR["CVE-2099-0001"])], impact=[{"flag": "rce", "label": "Remote code execution", "level": "critical",
                                                                             "text": "An attacker may run code.", "reports": ["Accessible HTTP"]}],
                kpis={"devices": 2000, "records": 5, "repeat": 1, "also": 0, "regions": 1, "cities": 1, "networks": 1})
pdf, txt = drawn(lambda: CP.build(d_svc, dict(CMETA, platform_label="Publicly accessible services", header="LG-A-0007")))
ok("an analyst code on services: renders; the busiest IP addresses under the findings", pdf[:4] == b"%PDF" and "The busiest IP addresses" in txt)
ok("…an analyst code's Across reports points to the researchers' view", "An analyst code covers the whole selection" in txt)
ok("…'<0.1%' for one device in 2,000", "<0.1% of the devices" in txt)
ok("…no notes yet: said so", "No researcher notes on this name yet" in txt)
ok("…the Impact section, the explanations under it", "Remote code execution" in txt and "ANALYST · SELECTION" in txt)
d_side = combo_d(across={"multi": 0, "patterns_total": 0, "patterns": []}, devices=devs(3), explained=[("samplerat", ENR["samplerat"])], notes=[])
pdf, txt = drawn(lambda: CP.build(d_side, CMETA))
ok("charts alone with room under them: the explanations carry on there, the page named for both",
   pdf[:4] == b"%PDF" and "Reports these devices were seen in · What the devices are · Destination ports · Explained" in txt)
d_none = combo_d(devices=[], across={"multi": 0, "patterns_total": 0, "patterns": []}, report_sets=[], kinds=[], ports=[], explained=[], notes=[])
pdf, txt = drawn(lambda: CP.build(d_none, CMETA))
ok("nothing to list: one empty table page, no Across reports, no Explained", pdf[:4] == b"%PDF" and "Across reports" not in txt and "WHAT THE NAME" not in txt)

print("4. An advisory in front (combo_pdf with advisory_pdf)")
ADV = {"logo": None, "title": "Example CSIRT Security Advisory", "subject": "ExampleBot on Example Net", "ref": "ADV-2026-001", "tlp": "TLP:AMBER",
       "tlp_colour": "#FFC000", "network": "Example Net", "reports": [{"title": "Sinkhole Events", "url": "https://www.example.org/sinkhole/"}],
       "devices": devs(4), "description": "What was found.", "actions": "What to do.", "header": "Advisory header", "labels": [], "impact": [],
       "kinds_line": "", "recipients": [], "look": "plain", "brand": "Example CSIRT", "insights": True,
       "preview": {"who": "Rachel Advisor", "at": "2026-11-17 10:00", "ref": ""}}
pdf, txt = drawn(lambda: CP.build(combo_d(notes=[]), dict(CMETA, advisory=ADV)))     # combos.py hands an advisory no notes
ok("renders with the advisory's pages first", pdf[:4] == b"%PDF" and "ADVISORY" in txt and "Example CSIRT" in txt)
ok("…a preview: who and when on every page, never a saved reference", "PREVIEW · NOT FOR DISTRIBUTION · Rachel Advisor · 2026-11-17 10:00 · not saved yet" in txt)
ok("…the TLP label", "TLP:AMBER" in txt)
ok("…patterns named by their devices' IP addresses, not codes; more than 40 point to the CSV",
   "198.51.100.44" not in txt and "198.51.100.39" in txt and "and 5 more (every one in the devices CSV)" in txt and "LG-C-0013" not in txt)
ok("…the Technical Details part titled Definitions", "TECHNICAL DETAILS" in txt and "Definitions" in txt)
ok("…an advisory's definitions never name the team member who wrote them", "Defined by Malpedia" not in txt and "Notes shared by" not in txt)
ok("…no '…' in place of text", "…" not in txt and not pdf_cut(pdf))
adv2 = dict(ADV, insights=False, look="designed", brand="", preview=None, tlp="")
pdf, txt = drawn(lambda: CP.build(combo_d(), dict(CMETA, advisory=adv2)))
ok("without insights, no name, no TLP: the advisory, its definitions and references only", pdf[:4] == b"%PDF" and "Geographic Location" not in txt
   and "TLP:" not in txt and "Contains the addresses of affected devices" in txt)
ok("the plain look keeps a value that is no colour as it is", CP._light("not a colour") == "not a colour")
ok("labels: references, insights", CP.AnalystDoc.label_of("References") == "REFERENCES" and CP.AnalystDoc.label_of("Overview") == "INSIGHTS")
d0 = CP.AnalystDoc(dict(CMETA))
d0.new_page("x")
ok("no TLP: no label drawn", d0.tlp_mark(10) == 0)
ok("a pattern of the name only: said so", d0.chips(10, 400, 300, []) == 400 - 18)
ok("context: an update without an author is still dated", CP.AnalystDoc.context_of("x", {"updated": "2026-11-01"}) == "Updated 2026-11-01")

EXP.Doc.text, RP.P = _text, _P
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
