#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Nothing goes missing or misleads in the Executive report (the user, 2026-11-26: "every nook and cranny has to be
accurate, no misses"). Made-up data only, no database, no server:

PDF (executive_pdf.build on a made-up dashboard answer; what it draws, and with pypdfium2 what the PDF says):
  1. the donuts (Sectors, Attack types, Severity): the centre is the selection's real total (43,281 events), a sector
     with 1 event reads "<1%", what the rows leave out is an "Other" part;
  2. a capped card says "Top N of M ... shown" (networks, countries, top infections / issues, combinations), M from
     the server's totals;
  3. the 7-day trend table: every infection sent, continued on the next page, and "Top N of M" with M the totals;
  4. a region's cities: "+ N more cities" when it has more than are listed;
  5. no MITRE ATT&CK technique and no definition printed twice (one grouped ATT&CK block; a CISA required action
     several CVEs share printed once; a CVE whose title is its description's first sentence described once);
     tests/pdf_pages_check.content_problems() and attack_duplicates() find nothing.
ZIP (management.py's /api/mgmt/report on a throwaway Flask app with stand-in stores):
  6. the seven-day-trend CSV has EVERY infection of the day (40), not the top 15;
  7. the combinations CSV: 1 device of 2,601 reads "<0.1%", never "0.0%";
  8. the page's answer: each region's lists carry their full counts (cities_total, city_devices_total, ...), and
     totals.networks does not count "Unknown network".
Run: PYTHONPATH=$(ls -d .venv/lib/python3*/site-packages) ~/lg-shots/venv/bin/python tests/check_exec_complete.py
(or .venv/bin/python: the pypdfium2 checks are then skipped, the rest runs)."""
import csv
import io
import logging
import os
import shutil
import sys
import tempfile
import types
import zipfile
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import executive_pdf as EXP  # noqa: E402

sys.path.insert(0, HERE)
import test_tools  # noqa: E402

try:
    pdfium = test_tools.find_pypdfium2()
    if pdfium is None:
        raise ImportError
    # the checks of tests/pdf_pages_check.py (that file runs its own made-up PDFs when imported: only its functions)
    _src = open(os.path.join(HERE, "pdf_pages_check.py"), encoding="utf-8").read().split("\ndef made_up(")[0]
    PPC = types.ModuleType("pdf_pages_check_functions")
    PPC.__file__ = os.path.join(HERE, "pdf_pages_check.py")
    exec(compile(_src, "pdf_pages_check.py", "exec"), PPC.__dict__)  # noqa: S102  (the project's own test file)
except ImportError:
    pdfium = PPC = None

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


DRAWN = []
_text = EXP.Doc.text


def rec_text(self, x, y, t, *a, **k):
    DRAWN.append(str(t) + (" " + " ".join(t.lines) if getattr(t, "lines", None) else ""))
    return _text(self, x, y, t, *a, **k)


EXP.Doc.text = rec_text


def build(d, enr, meta):
    DRAWN.clear()
    pdf = EXP.build(d, enr, meta)
    if os.environ.get("LG_EXEC_PDF_OUT"):          # to look at the pages (the rule: render and look at every page)
        with open(os.path.join(os.environ["LG_EXEC_PDF_OUT"], f"executive_{d['platform']}.pdf"), "wb") as fh:
            fh.write(pdf)
    return pdf, list(DRAWN)


def pdf_text(pdf):
    doc = pdfium.PdfDocument(pdf)
    return [doc[i].get_textpage().get_text_range() for i in range(len(doc))], doc


SECTORS = [("Telco / ISP", 31323), ("University / research", 2760), ("Cloud / CDN", 1133), ("Government", 654), ("Hosting", 538),
           ("Bank", 277), ("Enterprise", 154), ("Exchange (IXP)", 37), ("Finance / insurance", 19), ("Unknown", 2), ("Data centre", 1)]
SENT = sum(c for _, c in SECTORS)              # 36,898: the rows sent; the selection has 43,281 events
TOTAL = 43281
ATT = lambda *ids: {"version": "18.1", "techniques": [
    {"id": i, "name": {"T1071.001": "Web Protocols", "T1071.004": "DNS", "T1059": "Command and Scripting Interpreter"}[i],
     "tactics": ["Command and Control" if i.startswith("T1071") else "Execution"], "certainty": "observed", "certainty_label": "Observed",
     "url": f"https://attack.mitre.org/techniques/{i.replace('.', '/')}/"} for i in ids]}


def base(comms):
    rows = lambda n, k="v": [{"label": f"Network number {i}", "value": f"{k}{i}", "count": 500 - i, "hosts": 300 - i} for i in range(n)]
    infs = [{"value": f"examplebot{i}", "title": f"ExampleBot {i}", "hosts": 400 - i, "count": 900 - i, "share": .01} for i in range(15)]
    d = {"platform": "comms" if comms else "services", "day": "2026-11-17", "cities_map": [], "tz": None,
         "findings": ["Headline finding.", "A second finding."], "hours": [i % 5 + 1 for i in range(24)], "peak_hour": 4,
         "regions": [{"value": "GREATER ACCRA", "label": "Greater Accra", "count": 60, "hosts": 40}],
         "region_details": {"GREATER ACCRA": {"city_devices": [["Accra", 30], ["Tema", 8], ["Madina", 5], ["Kasoa", 4], ["Ashaiman", 3], ["Dodowa", 2]],
                                              "city_devices_total": 9}},
         "sectors": [{"label": n, "value": n.lower(), "count": c, "hosts": c} for n, c in SECTORS],
         "attack": [{"label": "Botnet", "value": "botnet", "count": 30000}, {"label": "Brute force", "value": "bf", "count": 3}],
         "families": [{"label": "Exposed service", "value": "x", "count": 30000}, {"label": "Compromised", "value": "c", "count": 2}],
         "networks": rows(12), "destinations": [{"label": c, "count": 100 - i} for i, c in enumerate(("US", "NL", "DE", "GB", "FR", "IE", "DK", "IL", "CA", "SG"))],
         "services": rows(12, "s"),
         "multi": {"devices": 10, "hosts": 10, "share": .1, "by_count": [{"label": "2", "count": 8}, {"label": "3", "count": 2}],
                   "combos": [{"label": f"examplebot{i} + examplebot{i + 1}", "count": 9 - i} for i in range(8)], "combinations": 23},
         "cross": {"devices": 7, "hosts": 7, "share": .07, "by_count": [{"label": "2", "count": 7}], "combinations": 2, "combos": [],
                   "pairs": [{"label": "A + B", "count": 3}]}, "report_pairs": [{"label": "Sinkhole + Honeypot", "count": 3}],
         "beacon": {"repeating": 5, "regular": 2, "typical": "1 h"}, "issue_kinds": [{"label": "CVE", "count": 4}, {"label": "Other", "count": 2}],
         "severity": [{"value": "critical", "label": "Critical", "count": 30000}, {"value": "high", "label": "high", "count": 2}],
         "reports": [{"label": "Sinkhole Events", "value": "event4_sinkhole", "hosts": 300, "count": 900}],
         "totals": {"infections": 40, "networks": 23, "destinations": 31, "services": 19, "issues": 33, "infections_on": 1, "report_pairs": 1},
         "infections": infs}
    items = {r["value"]: [100, 101, 99, 100, 102, 98, 100] for r in infs}
    d["baseline"] = {"days": [f"2026-11-{x:02d}" for x in range(10, 17)], "available": 7, "kpis": {"devices": [10] * 7, "hosts": [10] * 7},
                     "items": items, "assess": {"kpis": {}, "items": {}}, "scale": []}
    if comms:
        d["kpis"] = {"devices": 300, "infections": 40, "multi_infected": 10, "cross_report": 7, "regions": 4, "networks": 23, "events": TOTAL,
                     "share_of_day": .4, "critical": 3}
    else:
        d["kpis"] = {"hosts": 500, "services": 19, "vulnerable_hosts": 120, "kev_hosts": 30, "kev_cves": 2, "critical_cves": 3, "multi_issue": 15,
                     "records": TOTAL, "share_of_day": .5, "cves": 4, "issues": 33, "cross_report": 7}
        d["issues"] = [{"value": f"CVE-2099-000{i}", "title": "An integer overflow in the example parser lets an attacker run code on the device",
                        "hosts": 30 - i, "count": 40, "exploited": i < 2, "cvss": 9.8, "epss": .5, "cve": True} for i in range(3)]
        d["infections_on"] = [{"value": "examplebot", "hosts": 5, "count": 5, "exploited": False, "cvss": None, "infection": True}]
        d["baseline"]["items"] = {r["value"]: [3] * 7 for r in d["issues"]}
    return d


META = {"platform_label": "Network communications", "scope": "Example country", "selection": "Whole country", "generated_by": "Grace Mensah",
        "shapes": None, "nomap": True, "stats": {}, "demo": False}
DESC = ("An integer overflow in the example parser lets an attacker run code on the device. It affects every version "
        "before 2.0 and needs no login, so a device that is reachable from the internet can be taken over.")
ENR_C = {"examplebot0": {"curated": True, "title": "ExampleBot 0", "description": "A botnet that calls home every hour.", "attack": ATT("T1071.001", "T1071.004")},
         "examplebot1": {"curated": True, "title": "ExampleBot 1", "description": "Another botnet that calls home.", "attack": ATT("T1071.001", "T1059")},
         "examplebot2": {"curated": True, "title": "ExampleBot 2", "description": "A third one.", "attack": ATT("T1071.001", "T1071.004")}}
ACTION = "Apply updates per vendor instructions or discontinue use of the product if updates are unavailable."
ENR_S = {f"CVE-2099-000{i}": {"kind": "cve", "found": True, "exploited": i < 2, "description": DESC.replace("every version before 2.0", f"version 1.{i} of build {i}"), "cvss": {"score": 9.8, "severity": "critical"},
                              "kev": {"name": f"Example Parser {i} Integer Overflow", "date_added": "2026-01-05", "action": ACTION} if i < 2 else None}
         for i in range(3)}

print("1-5. The Executive PDF (communications)")
pdf, drawn = build(base(True), ENR_C, META)
txt = " ".join(drawn)
ok("renders", pdf[:4] == b"%PDF")
ok("1. the donut's centre is the selection's real total (43,281 events), not the sum of the rows sent (36,898)",
   "43,281" in drawn and f"{SENT:,}" not in drawn, [s for s in drawn if s.replace(",", "").isdigit()][:12])
ok("…a sector with 1 event of 43,281 reads '<1%', never '0%'", "Data centre" in drawn and "0%" not in drawn)
other_ = [s for s in drawn if s.startswith("Other")]
ok("…what the rows leave out (6,383 events) is an 'Other' part, so the parts add up", bool(other_) and __import__("shares").other(
   [{"count": c} for _, c in SECTORS], TOTAL) == TOTAL - SENT, other_)
ok("2. Most affected networks: 'Top N of 23 networks shown'", any(s.startswith("Top ") and s.endswith("of 23 networks shown") for s in drawn),
   [s for s in drawn if s.startswith("Top ")])
ok("…Where devices connect to: 'Top N of 31 countries shown'", any("of 31 countries shown" in s for s in drawn))
ok("…the top infections: 'Top N of 40 infections shown', every one in the CSV", any("of 40 infections shown" in s and "seven-day-trend CSV" in s for s in drawn))
ok("…the combinations: 'Top 5 of 23 combinations shown'", "Top 5 of 23 combinations shown" in drawn)
ok("3. the 7-day trend table: all 15 infections sent are in it", all(f"ExampleBot {i}" in drawn for i in range(15)))
ok("…and it says 15 of the 40", any(s.startswith("Top 15 of 40 infections shown") for s in drawn))
ok("4. a region with 9 cities, 4 listed: '+ 5 more cities'", "+ 5 more cities" in drawn, [s for s in drawn if "more" in s])
ok("5. one grouped MITRE ATT&CK block, each technique once with every name it covers",
   "MITRE ATT&CK v18.1 techniques" in drawn and sum(s.startswith("T1071.001 ") for s in drawn) == 1
   and any("examplebot0, examplebot1, examplebot2" in s for s in drawn))
ok("…no '…' in place of text", "…" not in txt)
if pdfium:
    pages, doc = pdf_text(pdf)
    ok("…the PDF's own text: T1071.001 printed once", sum(p.count("T1071.001") for p in pages) == 1, [p.count("T1071.001") for p in pages])
    probs = PPC.content_problems(doc) + PPC.attack_duplicates(doc)
    ok("…content_problems() and attack_duplicates() find nothing", probs == [], probs[:5])
    lay = [f"page {i + 1}: {p}" for i in range(len(doc)) for p in PPC.page_problems(doc[i])]
    ok("…no text over other text, no '…', nothing off the page", lay == [], lay[:5])
elif os.environ.get("LG_SUITE") == "all":
    ok("pypdfium2 is there to read the PDF's own text", False)
else:
    print("  (reading the PDF's own text needs pypdfium2: a maintainer's part, run by LG_SUITE=all; not part of an installation's checks)")

print("1-5. The Executive PDF (services)")
pdf, drawn = build(base(False), ENR_S, dict(META, platform_label="Publicly accessible services"))
ok("renders", pdf[:4] == b"%PDF")
ok("2. the top issues: 'Top N of 34 issues and infections shown' (33 issues + 1 infection)",
   any("of 34 issues and infections shown" in s for s in drawn), [s for s in drawn if "shown" in s])
ok("…Exposed services: 'of 19 services shown'", any("of 19 services shown" in s for s in drawn))
ok("…a Report family with 2 of 43,281 records reads '<1%'", "0%" not in drawn)
flat = " ".join(" ".join(drawn).split())
ok("5. the CISA required action two CVEs share: printed once, naming both", flat.count("Apply updates per vendor instructions") == 1
   and "For CVE-2099-0000, CVE-2099-0001" in flat, flat.count("Apply updates per vendor instructions"))
ok("…a CVE's description: once (Explained), the Top issues card says where", "Described under Explained." in drawn)
if pdfium:
    pages, doc = pdf_text(pdf)
    probs = PPC.content_problems(doc) + PPC.attack_duplicates(doc)
    ok("…content_problems() and attack_duplicates() find nothing", probs == [], probs[:5])
    lay = [f"page {i + 1}: {p}" for i in range(len(doc)) for p in PPC.page_problems(doc[i])]
    ok("…no text over other text, no '…', nothing off the page", lay == [], lay[:5])
EXP.Doc.text = _text

print("6-8. The ZIP of the Executive report (management.py)")
from flask import Flask, g  # noqa: E402
import management as M  # noqa: E402

tmp = tempfile.mkdtemp(prefix="lg-exec-complete-")
DAY = datetime(2026, 11, 17, tzinfo=timezone.utc)
T0 = DAY.timestamp()


def ev(i, inf, region="GREATER ACCRA", city=None, asn=64500):
    return {"src_ip": f"10.{i // 65536}.{i // 256 % 256}.{i % 256}", "infection": inf, "attack_class": "Botnet", "source": "event4_sinkhole",
            "severity": "medium", "src_region": region, "src_city": city, "src_coords": None, "src_asn": asn, "dst_geo": "US",
            "http_host": "", "dst_ip": "", "_t": T0 + 3600}


events = []
for k in range(40):                                  # 40 infections, infection k on 41 - k devices
    events += [ev(100000 + k * 100 + j, f"inf{k:02d}", city=f"City {j % 9}") for j in range(41 - k)]
for i in range(2600):                                # 2,600 devices with "comboa + combob", one with "comboa + comboc"
    events += [ev(i, "comboa"), ev(i, "combob")]
events += [ev(5000, "comboa"), ev(5000, "comboc"), ev(6000, "lonely", asn=0)]
day = types.SimpleNamespace(start=DAY, events=events)


class Store:
    days = {DAY: day}

    def get(self, now):
        return day

    def signature(self, start):
        return None                                  # nothing in the past week: the baseline days are empty

    def _load(self, start):
        return types.SimpleNamespace(start=start, events=[])


try:
    app = Flask(__name__)
    app.logger.setLevel(logging.CRITICAL)

    @app.before_request
    def _me():
        g.user = {"user": "mgr"}
    reg_ = types.SimpleNamespace(company=lambda asn, d: f"Example Net {asn}", all=lambda: {"64500": {"type": "isp"}})
    ctx = {"AUTH": {"has_perm": lambda p: p == "management", "audit": types.SimpleNamespace(add=lambda *a, **k: None)},
           "public_demo": lambda: False, "data_dir": tmp, "store": Store(), "svc_store": Store(), "asn_registry": reg_,
           "type_labels": lambda: {"isp": "Telco / ISP", "unknown": "Unknown"}, "registry": types.SimpleNamespace(get=lambda: []),
           "read_names": lambda: {}, "knowledge_base": lambda: {}, "replay_now": lambda: DAY, "mp_resolve": lambda n: [{"name": n}],
           "issues_resolve": lambda names: {}, "scope_text": lambda: "Made-up constituency", "country": lambda: "ZZ",
           "user": lambda: {"user": "mgr"}, "sources_text": [], "build_pdf": lambda spec: b"%PDF-fallback"}
    M.register(app, ctx)
    c = app.test_client()
    r = c.get("/api/mgmt/comms")
    d = r.get_json()
    det = d["region_details"]["Greater Accra"]
    ok("8. a region's lists carry their full counts: 9 cities by events and by devices, every infection, every network",
       det.get("cities_total") == 9 and det.get("city_devices_total") == 9 and det.get("top_total") == 44 and det.get("networks_total") == 2, det)
    ok("…totals.networks does not count 'Unknown network' (1 network, not 2)", d["totals"]["networks"] == 1, d["totals"])
    r = c.get("/api/mgmt/report?platform=comms")
    z = zipfile.ZipFile(io.BytesIO(r.data))
    files = {n.rsplit("_", 1)[-1]: z.read(n).decode("utf-8-sig") for n in z.namelist() if n.endswith(".csv")}
    trend = list(csv.reader(io.StringIO(files.get("seven-day-trend.csv", ""))))
    blank = trend.index([]) if [] in trend else len(trend)
    names = [row[0] for row in trend[blank + 2:]]
    want = {f"inf{k:02d}" for k in range(40)} | {"comboa", "combob", "comboc", "lonely"}
    ok("6. the seven-day-trend CSV: EVERY infection of the day (44), not the top 15", set(names) == want and len(names) == 44,
       f"{len(names)} rows: {names[:5]}")
    ok("…each with today's devices (inf00 on 41)", any(row and row[0] == "inf00" and row[-1] == "41" for row in trend))
    combo = list(csv.reader(io.StringIO(files.get("infection-combinations.csv", ""))))
    rare = next((row for row in combo if row and row[0] == "comboa + comboc"), None)
    ok("7. the combinations CSV: 1 device of 2,601 reads '<0.1%', never '0.0%'", rare is not None and rare[3] == "<0.1%", rare)
    common = next((row for row in combo if row and row[0] == "comboa + combob"), None)
    ok("…the biggest part of the whole reads '>99.9%', never '100.0%'", common is not None and common[3] == ">99.9%", common)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
