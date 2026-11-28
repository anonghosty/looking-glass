#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Nothing goes missing (the user, 2026-11-26: "every sector, every organisation, everything"): the lists a file or a
PDF cut, the shares that read 0% or 100% for a part, and the totals beside every capped list, on made-up data only:
- quarterly: the management_summary CSV holds every region, sector, recurring network, KEV CVE and infection; the
  advisor_network_issues CSV every issue of every network; the PDFs' cards say "7 of M; all in the ... CSV"
- combos: a share of 1 in 43,281 reads "<0.1%", 99.5% reads ">99%"; "and N more" infections; every cross-report pattern
  recorded and in the ZIP's patterns CSV; every set of reports (their shares add up); the PDF says "8 of N patterns"
- combo_pdf: made-up combination PDFs pass tests/pdf_pages_check.content_problems (no "0%", no "N of M" with N > M, no
  paragraph printed twice)
- services_intel: every infection name and every services report of it, with infections_total; infections_of(n=None)
- combo_review: the drill-down's figures carry every region and the regions' total
- audit_portal: the failure rate "<0.1" for one failure in thousands; totals beside the top 8 failure sources/exporters
- sender_audit: "<1%" / ">99%" for a part; intel: totals beside leads, report sets and cross combinations
- intelligence: the constituency first, then the cap; capped: said in the JSON and in the CSV file's last row
- beacon_stats: every operator, version and C2 domain; unusual: the week card's total beside its top 5
No database, no live file: temporary folders and stand-ins only. Run: .venv/bin/python tests/check_cut_lists_data.py
(the PDF text checks need pypdfium2: without it in .venv the file runs itself again with ~/lg-shots/venv's Python)."""
import collections
import csv
import io
import json
import os
import re
import sys
import tempfile
import types
import zipfile
from datetime import date, datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
try:
    import pypdfium2 as pdfium
except ImportError:
    pdfium = None
    shots = os.path.expanduser("~/lg-shots/venv/bin/python")
    if os.path.exists(shots) and not os.environ.get("LG_CUT_REEXEC"):
        import glob
        site = glob.glob(os.path.join(ROOT, ".venv", "lib", "python3*", "site-packages"))
        env = dict(os.environ, LG_CUT_REEXEC="1", PYTHONPATH=os.pathsep.join(site + [os.environ.get("PYTHONPATH", "")]))
        os.execve(shots, [shots, os.path.abspath(__file__)] + sys.argv[1:], env)
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask, g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


if pdfium is None:          # the PDF text checks are the maintainer's part (a failure in LG_SUITE=all)
    if os.environ.get("LG_SUITE") == "all":
        ok("pypdfium2 is there to read the PDFs' own text", False)
    else:
        print("  (its PDF-text part needs pypdfium2: a maintainer's check, run by LG_SUITE=all; not part of an installation's checks)")


def content_problems(data):
    """tests/pdf_pages_check.content_problems on PDF bytes ([] without pypdfium2). That file runs its own check when it
    is imported, so only its functions are taken from it."""
    if pdfium is None:
        return []
    src = open(os.path.join(HERE, "pdf_pages_check.py"), encoding="utf-8").read().split("\ndef made_up")[0]
    ns = {"__name__": "pdf_pages_check_functions", "__file__": os.path.join(HERE, "pdf_pages_check.py")}
    exec(compile(src, "pdf_pages_check.py", "exec"), ns)       # noqa: S102  (the project's own test file)
    return ns["content_problems"](pdfium.PdfDocument(data))


def pdf_text(data):
    if pdfium is None:
        return ""
    d = pdfium.PdfDocument(data)
    return "\n".join(d[i].get_textpage().get_text_range() for i in range(len(d)))


tmp = tempfile.mkdtemp(prefix="lg-cut-")
os.makedirs(os.path.join(tmp, "data"))

# ------------------------------------------------------------------ 1. quarterly
print("1. Quarterly: every row in the CSVs, '7 of M' on the PDFs' cards")
import quarterly as QY  # noqa: E402
import quarterly_pdf  # noqa: E402

json.dump({"asns": {str(64500 + i): {"name": f"Example Net {i}"} for i in range(30)}}, open(os.path.join(tmp, "data", "asns.json"), "w"))
MONTHS = ["2026-07", "2026-08", "2026-09"]
R = {"quarter": "2026Q3", "lo": date(2026, 7, 1), "hi": date(2026, 10, 1), "months": MONTHS, "today": date(2026, 10, 5),
     "reports": {"scan_http": {"kind": "service", "label": "Accessible HTTP", "family": "Made-up"},
                 "event4_sinkhole_http": {"kind": "sinkhole", "label": "Sinkhole HTTP", "family": "Made-up sinkholes"}},
     "other": {}, "failed": {}, "rep_recs": collections.Counter(), "rep_hosts": collections.defaultdict(dict), "rep_total": collections.Counter(),
     "rep_day": collections.defaultdict(collections.Counter), "rep_noaddr": collections.Counter(),
     "net_total": collections.Counter(), "net_month": collections.Counter(), "net_hosts": collections.defaultdict(dict),
     "all_hosts": {}, "last_seen": {}, "region": collections.defaultdict(set), "region_recs": collections.Counter(),
     "sector": collections.defaultdict(set), "sector_recs": collections.Counter(),
     "inf_hosts": collections.defaultdict(set), "inf_recs": collections.Counter(),
     "issue_hosts": collections.defaultdict(set), "issue_recs": collections.Counter(), "kev_hosts": set(), "kev_recs": 0,
     "cve_hosts": collections.defaultdict(set), "kev_cves": set(), "rep_out": collections.Counter(),
     "constituency": QY.constituency(None), "kev_set": set(), "purge_on": False, "purge": QY.purge_dates(2026, 3),
     "purge_all": {}, "oldest_day": None, "oldest_known": False}
mi = {m: i for i, m in enumerate(MONTHS)}
n_host = 0
for net in range(22):                                    # 22 networks with records in every month: all recurring
    for m in MONTHS:
        for j in range(2):
            n_host += 1
            h = f"10.{net}.{mi[m]}.{j}"
            QY._add(R, "scan_http", R["reports"]["scan_http"], {"m": m, "a": str(64500 + net), "h": h}, 1, m + "-05",
                    f"County {n_host % 47}", f"Sector {n_host % 25}", mi, {}, False, False)
for i in range(18):                                      # 18 infections and 15 KEV CVEs on made-up hosts
    R["inf_hosts"][f"inf{i:02d}"].update({f"10.0.0.{i}", f"10.0.1.{i}"}); R["inf_recs"][f"inf{i:02d}"] += 2
for i in range(15):
    c = f"CVE-2099-{1000 + i}"
    R["cve_hosts"][c].add(f"10.1.0.{i}"); R["kev_set"].add(c); R["kev_cves"].add(c); R["kev_hosts"].add(f"10.1.0.{i}")
for i in range(14):                                      # one network with 14 issues
    R["issue_hosts"][("64500", f"issue-{i:02d}")].add(f"10.0.0.{i}"); R["issue_recs"][("64500", f"issue-{i:02d}")] += 1
X = QY.figures(R, None, tmp, date(2026, 10, 5))
W, A = QY.workflow(tmp, 2026, 3, R["last_seen"])
rows = QY.csv_rows(R, X, W, A, None)
sec = collections.Counter(r[0] for r in rows["management"] if r[1] not in ("Networks with records in every month so far",
                                                                             "Addresses with a KEV CVE"))
ok("the management_summary CSV: every region (47, not the first 20)", sec["Regions"] == len(X["regions"]) == 47, sec["Regions"])
# Shadowserver's own sector column is "Industry (Shadowserver)"; Sectors are the network types (the user, 2026-11-26)
ok("…every industry (Shadowserver) (25)", sec["Industry (Shadowserver)"] == len(X["industries"]) == 25, sec["Industry (Shadowserver)"])
ok("…every sector (network type)", sec["Sectors (network type)"] == len(X["sectors"]) >= 1, sec["Sectors (network type)"])
ok("…every recurring network (22, not 15)", sec["Recurring networks"] == len(X["recurring"]) == 22, sec["Recurring networks"])
ok("…every KEV CVE (15, not 10)", sec["Actively exploited (CISA KEV)"] == 15, sec["Actively exploited (CISA KEV)"])
ok("…every infection (18, not 15)", sec["Infections"] == 18, sec["Infections"])
iss = [r for r in rows["issues"] if r[1] == "64500"]
ok("the advisor_network_issues CSV: every issue of the network (14, not 10)", len(iss) == 14, len(iss))
out = os.path.join(tmp, "q")
os.makedirs(out)
st = ("VALID", "made-up")
R["_guards"], R["_purge"] = [("made-up guard", True, "")], rows["purge"]
pm, pa = os.path.join(out, "m.pdf"), os.path.join(out, "a.pdf")
dm = " ".join(quarterly_pdf.write_management(pm, R, X, W, A, st, "made by the check"))
da = " ".join(quarterly_pdf.write_advisor(pa, R, X, W, A, st, "made by the check"))
ok("the management PDF's Regions card: '7 of 47; all in the management_summary CSV'",
   "Unique addresses per region · 7 of 47; all in the management_summary CSV" in dm)
ok("…Industry (Shadowserver) '12 of 25', Infections '7 of 18', KEV '6 of 15', recurring networks '12 of 22'",
   all(t in dm for t in ("12 of 25; all", "7 of 18; all", "6 of 15; all", "12 of 22; all")))
ok("the advisor PDF: '5 of 14 issues' beside the network, every one in the CSV",
   "5 of 14 issues" in da and "every issue of every network" in da)
for nm, p in (("management", pm), ("advisor", pa)):
    probs = content_problems(open(p, "rb").read())
    ok(f"the quarterly {nm} PDF reads right (content_problems)", probs == [], probs[:3])

# ------------------------------------------------------------------ 2. shares
print("2. Shares: never 0% for a part with records, never 100% for a part")
import combos as C  # noqa: E402
import combo_pdf as CP  # noqa: E402
ok("combos: 1 of 43,281 reads '<0.1%'", C._share(1, 43281) == "<0.1%", C._share(1, 43281))
ok("combos: 995 of 1,000 reads '>99%', not '100%'", C._share(995, 1000) == ">99%", C._share(995, 1000))
ok("combos: 0 is '0%', the whole '100%', 5 of 100 '5.0%'", (C._share(0, 9), C._share(9, 9), C._share(5, 100)) == ("0%", "100%", "5.0%"))
ok("combo_pdf: the same rule", (CP._share(1, 43281), CP._share(995, 1000)) == ("<0.1%", ">99%"))

# ------------------------------------------------------------------ 3. combos: "and N more", every pattern
print("3. Combinations: every pattern, every set of reports, 'and N more'")
enr = {"infections": [{"name": f"inf{i}", "hosts": 20 - i} for i in range(12)], "infections_total": 12, "infections_hosts": 30}
pts = " ".join(C.enrich_points(enr))
ok("the infections line says 'and 4 more' (12 names, 8 listed)", "and 4 more" in pts, pts)

LABELS = {"event4_sinkhole_http": "Sinkhole HTTP", "event4_sinkhole_dns": "Sinkhole DNS"}


class Intel:
    on_codes = None

    def index(self, scope):
        return {"by": {}}


ctx = {"base_dir": tmp, "intel": Intel(), "labels": lambda: LABELS, "network": lambda a: f"Example Net {a}" if a else "",
       "has_perm": lambda p: True, "shapes": lambda: None, "notes": types.SimpleNamespace(list=lambda s, n: []),
       "explain": lambda s, n: None, "scope_text": lambda: "made-up", "country": lambda: "Kenya",
       "audit": types.SimpleNamespace(add=lambda *a, **k: None), "build_pdf": lambda spec: b"%PDF-plain",
       "store": types.SimpleNamespace(days={}), "svc_store": types.SimpleNamespace(days={}), "fetch": lambda *a: [],
       "host_flags": lambda hosts, day=None, load=True: {}, "impact_of": lambda reps: []}
capp = Flask("cut-combos")
capp.secret_key = "made-up"
C.install(capp, ctx)


def find_fn(name, roots):
    """A function defined inside install(), found through the routes' closures (no hook of its own)."""
    seen, todo = set(), list(roots)
    while todo:
        f = todo.pop()
        if id(f) in seen or not isinstance(f, types.FunctionType):
            continue
        seen.add(id(f))
        if getattr(f, "__name__", "") == name and getattr(f, "__code__", None):
            return f
        for c in getattr(f, "__closure__", None) or ():
            try:
                v = c.cell_contents
            except ValueError:
                continue
            if isinstance(v, types.FunctionType):          # never a proxy (flask.request) or another object
                todo.append(v)
    return None


package = find_fn("package", capp.view_functions.values())
ok("the package of a search is reachable for the check", package is not None)
T0 = datetime(2026, 11, 20, 8, tzinfo=timezone.utc)
evs = []
for i in range(20):                       # 20 devices, each in both reports with a C2 domain of its own: 20 patterns
    for src in LABELS:
        evs.append({"src_ip": f"192.0.2.{i}", "src_asn": 64500 + i % 3, "source": src, "infection": "examplebot",
                    "http_host": f"c2-{i}.example", "timestamp": T0.isoformat(), "extracted_date": "2026-11-20", "_t": T0.timestamp(),
                    "src_region": f"Region {i % 4}", "src_city": "Town", "src_geo": "KE", "dst_port": 80, "protocol": "tcp"})
entry = {"code": "LG-C-00000001", "section": "infections", "name": "examplebot", "kind": "r", "report": "Sinkhole HTTP",
         "items": [], "label": "x"}
m = C.Matcher(entry, LABELS)
found = [e for e in evs if e["source"] == "event4_sinkhole_http"]
job = {"id": "review1", "user": "made.up", "log": []}
res = None
try:
    res = package(job, entry, found, [("2026-11-20", len(found))], [T0], evs, None)
except Exception as exc:                                  # noqa: BLE001
    ok("the package is made", False, f"{type(exc).__name__}: {exc}")
if res:
    z = zipfile.ZipFile(io.BytesIO(res["bytes"]))
    pat = [n for n in z.namelist() if n.endswith("_patterns.csv")]
    ok("the ZIP has a patterns CSV", len(pat) == 1, z.namelist())
    if pat:
        prow = list(csv.reader(io.StringIO(z.read(pat[0]).decode("utf-8-sig"))))[1:]
        ok("…with every one of the 20 patterns (the page shows 15, the PDF 8)", len(prow) == 20, len(prow))
        ok("…each with its code and its device", all(r[0].startswith("LG-X-") and r[1] == "1" and r[4] for r in prow))
    sm = job.get("summary") or {}
    ok("the page's summary: the patterns' and sets' totals beside the top lists",
       (sm.get("across") or {}).get("totals") == {"patterns": 20, "sets": 1}, (sm.get("across") or {}).get("totals"))
    rec = json.load(open(os.path.join(tmp, "data", "combo_codes.json")))
    ok("every pattern's code is recorded (20, not 15), so each in the CSV resolves",
       sum(1 for v in rec.values() if v.get("kind") == "x") == 20)
    pdfb = z.read([n for n in z.namelist() if n.endswith(".pdf")][0])
    txt = pdf_text(pdfb)
    if pdfium is not None:
        ok("the PDF says '8 of 20 exact patterns are drawn here', and where every one is",
           "8 of 20 exact patterns are drawn here" in " ".join(txt.split()) and "_patterns.csv" in txt)
        probs = content_problems(pdfb)
        ok("the combination PDF reads right (content_problems)", probs == [], probs[:3])

print("4. combo_pdf on its own: a made-up report, every card cut says 'Top n of N'")
d = {"section": "infections", "code": "LG-C-0001", "name": "examplebot", "headline": "Devices calling sinkholes as ExampleBot",
     "parts": [("Sinkhole HTTP", ["Tag: botnet"])],
     "kpis": {"devices": 60, "records": 120, "repeat": 0, "also": 0, "regions": 2, "cities": 1, "networks": 3},
     "hours": None, "peak_hour": None, "findings": ["One finding."],
     "devices": [{"ip": f"192.0.2.{i}", "network": "Example Net", "asn": "64500", "region": "Nairobi", "city": "Town", "records": 2,
                  "days": 1, "last": "2026-11-20 08:00", "also": "", "flags": {"infections": [], "issues": [], "cves": []}, "earlier": ""}
                 for i in range(60)],
     "csv_devices": "x_devices.csv", "csv_records": "x_records.csv", "csv_patterns": "", "shapes": None,
     "regions": [{"value": "Nairobi", "label": "Nairobi", "count": 60, "hosts": 60, "share": 1}], "region_details": {},
     "networks": [{"label": "Example Net", "hosts": 60}], "cities": [{"label": "Town", "hosts": 60}],
     "across": {"multi": 0, "patterns_total": 0, "patterns": []}, "report_sets": [],
     "kinds": [{"label": f"Vendor {i} router", "count": 40 - i} for i in range(30)],
     "ports": [{"label": f"{8000 + i}/tcp", "count": 40 - i} for i in range(30)],
     "explained": [], "stats": {}, "notes": [], "ref_levels": {}, "ref_reports": ["event4_sinkhole_http"], "impact": []}
try:
    pdfb = CP.build(d, {"platform_label": "Network communications", "scope": "made-up", "selection": "x", "day": "2026-11-20",
                        "generated_by": "made.up", "header": "LG-C-0001"})
    txt = " ".join(pdf_text(pdfb).split())
    if pdfium is not None:
        ok("no repeat: 'none of the devices', never '0% of the devices'", "none of the devices" in txt and "0% of the devices" not in txt)
        ok("the kinds and ports cards say 'Top n of 30'", len(re.findall(r"Top \d+ of 30", txt)) >= 2, re.findall(r"Top \d+ of \d+", txt))
        probs = content_problems(pdfb)
        ok("the made-up combination PDF reads right (content_problems)", probs == [], probs[:3])
except Exception as exc:                                  # noqa: BLE001
    ok("the made-up combination PDF is made", False, f"{type(exc).__name__}: {exc}")

# ------------------------------------------------------------------ 5. services_intel
print("5. services_intel: every infection, every report of it")
import services_intel as SI  # noqa: E402
si = SI.ServicesIntel({})
REPS = [f"scan_r{i}" for i in range(7)]
HOSTS = [f"192.0.2.{i}" for i in range(25)]
data = {"hosts": {r: set(HOSTS) for r in REPS}, "showable": {}, "combo_hosts": {r: {} for r in REPS}, "host_issues": {},
        "infected": {h: {f"inf{i:02d}"} for i, h in enumerate(HOSTS)}, "host_items": {}, "host_reports": {h: REPS for h in HOSTS},
        "sink_rep": {}, "days": ["2026-11-20"]}
si.index = lambda scope=None, load=True: data
fh = si.for_hosts(set(HOSTS))
ok("every infection name (25, not 20), with infections_total", len(fh["infections"]) == 25 and fh.get("infections_total") == 25,
   (len(fh["infections"]), fh.get("infections_total")))
ok("…each with every services report it is in (7, not 6)", all(len(x["reports"]) == 7 and x["reports_total"] == 7 for x in fh["infections"]))
ok("…and the totals dict beside the lists", fh.get("totals", {}).get("infections") == 25 and fh["totals"].get("services") == 7)
ok("infections_of(n=None): every one (the default n=10 unchanged)",
   len(si.infections_of(set(HOSTS), n=None)) == 25 and len(si.infections_of(set(HOSTS))) == 10)

# ------------------------------------------------------------------ 6. combo_review
print("6. combo_review: the drill-down's figures carry every region and the totals")
import combo_review as CR  # noqa: E402
rapp = Flask("cut-review")
CR.install(rapp, {"book": types.SimpleNamespace(), "findings": types.SimpleNamespace(), "has_perm": lambda p: True,
                  "network": lambda a: f"Example Net {a}", "acodes": None, "base_dir": tmp})
drill_build = find_fn("drill_build", rapp.view_functions.values())
ok("the drill-down's builder is reachable for the check", drill_build is not None)
if drill_build:
    devs_ = [{"src_ip": f"192.0.2.{i}", "src_asn": 64500 + i, "src_region": f"County {i}", "extracted_date": "2026-11-20"} for i in range(30)]
    figs, _ = drill_build("LG-C-1", True, devs_, "x")
    ok("every region (30, not 8), with regions_total", len(figs["regions"]) == 30 and figs.get("regions_total") == 30)
    ok("the top 8 networks with their total", len(figs["top_networks"]) == 8 and (figs.get("totals") or {}).get("top_networks") == 30)
    ok("…and the regions add up to every device", sum(r["devices"] for r in figs["regions"]) == figs["devices"] == 30)

# ------------------------------------------------------------------ 7. audit_portal
print("7. Audit portal: the failure rate and the totals beside the top 8")
import audit_portal as AP  # noqa: E402
now = datetime.now(timezone.utc).timestamp()
RECS = [{"t": now - 3600, "event": "login", "user": f"user{i % 3}", "ip": "192.0.2.1"} for i in range(4000)]
RECS += [{"t": now - 1800, "event": "login_failed", "user": "x", "ip": f"198.51.100.{i % 12}", "location": "Nowhere"} for i in range(2)]
RECS += [{"t": now - 1800 + i, "event": "login_failed", "user": "x", "ip": f"203.0.113.{i}", "location": "Nowhere"} for i in range(10)]
RECS += [{"t": now - 900, "event": "intelligence_export", "user": f"exporter{i}"} for i in range(11)]
audit = types.SimpleNamespace(records=lambda: RECS, is_selftest=lambda r: False, add=lambda *a, **k: None,
                              chain=types.SimpleNamespace(seal=lambda: None, record_retention_setting=lambda: None))
aapp = Flask("cut-audit")
AP.install(aapp, {"has_perm": lambda p: True, "users": types.SimpleNamespace(all=lambda: {}), "roles": None, "sessions": None,
                  "audit": audit, "people": types.SimpleNamespace(audit=lambda u: u), "auditor_role": "auditor", "perms_catalog": {}})
overview = find_fn("overview", aapp.view_functions.values())
ov = overview(now - 86400, now + 60) if overview else {}
k_ = ov.get("kpis") or {}
ok("12 failures in 4,012 attempts: '0.3' (one decimal, shares.py)", k_.get("failure_rate") == "0.3", k_.get("failure_rate"))
RECS[:] = [r for r in RECS if r["event"] != "login_failed"] + [{"t": now - 60, "event": "login_failed", "user": "x", "ip": "192.0.2.9"}]
ov = overview(now - 86400, now + 60)
ok("1 failure in 4,001 attempts: '<0.1', never '0.0'", ov["kpis"]["failure_rate"] == "<0.1", ov["kpis"]["failure_rate"])
RECS[:] = RECS + [{"t": now - 1800 + i, "event": "login_failed", "user": "x", "ip": f"203.0.113.{i}", "location": "Nowhere"} for i in range(10)]
ov = overview(now - 86400, now + 60)
ok("the top 8 failure sources with their total (11 sources)", len(ov["fail_sources"]) == 8 and ov["totals"]["fail_sources"] == 11,
   ov.get("totals"))
ok("the top 8 exporters with their total (11 people)", len(ov["exports_by"]) == 8 and ov["totals"]["exports_by"] == 11, ov.get("totals"))

# ------------------------------------------------------------------ 8. sender_audit
print("8. Sender check: shares of a part")
import sender_audit as SA  # noqa: E402
srows = [{"alg": "rsa-sha256", "bits": 2048, "result": "pass", "signer": "example.org", "from_domain": "example.org", "action": "kept"}
         for _ in range(999)] + [{"alg": "", "bits": 0, "result": "none", "signer": "", "from_domain": "example.org", "action": "kept"}]
shown = " ".join(s["shows"] for s in SA.standards(srows, "off"))
ok("999 of 1,000 valid: '>99%', not '100%'", "valid signatures by the expected domain (>99%)" in shown, re.findall(r"\([^)]*%\)", shown))

# ------------------------------------------------------------------ 9. intel totals
print("9. Intel gathered: totals beside the top lists")
import intel as IN  # noqa: E402
sets = collections.Counter({tuple(sorted({f"Report {i}", "Report X"})): 1 for i in range(20)})
xc = collections.Counter({((f"Report {i}", ("Tag: a",)), ("Report X", ())): 1 for i in range(20)})
acr = IN.Intel._across({"sets": {("infections", "x"): sets}, "by": {}, "xcombos": {("infections", "x"): xc}, "xhosts": {}},
                       ("infections", "x"), "x")
ok("report sets and cross combinations: the top 12 with their totals (20)",
   len(acr["report_sets"]) == 12 and len(acr["cross_combos"]) == 12 and acr["totals"] == {"cross_combos": 20, "report_sets": 20, "shared": 0},
   acr.get("totals"))

# ------------------------------------------------------------------ 10. intelligence
print("10. Abused or Compromised: the constituency first, then the cap")
import intelligence as INT  # noqa: E402


class Cur(list):
    def limit(self, n):
        return Cur(self[:n])


class Coll:
    def __init__(self, rows):
        self.rows = rows

    def find(self, q=None, proj=None):
        rx = ((q or {}).get("filename") or {}).get("$regex")
        out = [r for r in self.rows if not rx or re.match(rx, r["filename"])]
        if proj and any(v == 1 for v in proj.values()):
            out = [{k: r[k] for k in proj if proj[k] == 1 and k in r} for r in out]
        elif proj:
            out = [{k: v for k, v in r.items() if proj.get(k) != 0} for r in out]
        return Cur(out)

    def count_documents(self, q):
        return len(self.find(q))

    def estimated_document_count(self):
        return len(self.rows)


class FakeDB(dict):
    def list_collection_names(self):
        return list(self)


DAY = (datetime.now(timezone.utc).date() - timedelta(days=1)).isoformat()
web = [{"filename": f"{DAY}-x.csv", "timestamp": f"{DAY} 01:00:{i:02d}", "ip": f"198.51.100.{i}", "asn": "64999", "tag": "out"}
       for i in range(10)]                                 # outside the constituency, first in the collection
web += [{"filename": f"{DAY}-x.csv", "timestamp": f"{DAY} 02:00:{i:02d}", "ip": f"192.0.2.{i}", "asn": "64500", "tag": "defacement"}
        for i in range(7)]


class Settings:
    restricted, version = True, 1

    def in_scope(self, asn, ip):
        return str(asn) == "64500"


INT.ROW_CAP = 5
audited = []
iapp = Flask("cut-intel", template_folder=os.path.join(ROOT, "templates"))
INT.install(iapp, {"db": FakeDB({"compromised_website": Coll(web)}),
                   "report_map": types.SimpleNamespace(get=lambda: {"reports": {"compromised_website": {
                       "section": "Intelligence", "group": "Compromised systems and victims", "title": "Compromised Website", "has_ip": True}}}),
                   "settings": Settings(), "has_perm": lambda p: p in g.user["perms"], "is_demo": lambda: False,
                   "audit": types.SimpleNamespace(add=lambda ev, **k: audited.append((ev, k))), "csrf_ok": lambda: True,
                   "svc_reports": lambda: set(), "network": lambda a: "Example Net", "cross": lambda hosts: {}})


def icall(path, body):
    with iapp.test_request_context(path, method="POST", json=body):
        g.user = {"user": "lg-check", "role": "analyst", "perms": {"view", "unmasked", "export"}}
        ep = iapp.url_map.bind("localhost").match(path, method="POST")
        r = iapp.view_functions[ep[0]](**ep[1])
        r = r[0] if isinstance(r, tuple) else r
        return r.get_data(as_text=True)


j = json.loads(icall("/api/intelligence/report", {"name": "compromised_website", "day": DAY}))
ok("the constituency's rows are read (5 of its 7), not the scoped part of the first 5 rows (none)", j["total"] == 5, j["total"])
ok("…and the page is told: capped, 7 in all", j.get("cap") == {"capped": True, "total": 7, "read": 5, "limit": 5}, j.get("cap"))
with iapp.test_request_context("/api/intelligence"):
    g.user = {"user": "lg-check", "role": "analyst", "perms": {"view", "unmasked", "export"}}
    summ = iapp.view_functions["api_intelligence"]().get_json()
card = summ["groups"][0]["reports"][0]
ok("the day's count: every row in the constituency (7), never the scoped part of the first ROW_CAP", card["today"] == 7, card["today"])
text = icall("/api/intelligence/export.csv", {"name": "compromised_website", "day": DAY})
last = list(csv.reader(io.StringIO(text.lstrip("﻿"))))[-1][0]
ok("the export says it in its file: its last row", last.startswith("Not every row: this file comes from the first 5 of the 7 rows"), last)
ok("…and in the audit entry", any("capped" in k.get("detail", "") for ev, k in audited if ev == "intelligence_export"))

# ------------------------------------------------------------------ 11. beacon_stats
print("11. Decoded beacons: every operator, version and domain")
import beacon_stats as BS  # noqa: E402
import beacon_decode  # noqa: E402
real_read, real_field = BS._read, beacon_decode.field
BS._read = lambda e: ("Beacon A", "decoded")
beacon_decode.field = lambda e, k: e.get("_" + k)
try:
    bev = [{"src_ip": f"192.0.2.{i}", "_operator": f"op{i}", "_version": f"v{i}", "http_host": f"c2-{i}.example", "_t": 1.0 + i,
            "infection": "x"} for i in range(9)]
    row = BS.drill(bev)["rows"][0]
    ok("every operator, version and C2 domain (9 each, not 5)",
       (len(row["operators"]), len(row["versions"]), len(row["domains"])) == (9, 9, 9), (len(row["operators"]), len(row["domains"])))
finally:
    BS._read, beacon_decode.field = real_read, real_field

# ------------------------------------------------------------------ 12. unusual
print("12. Unusual activity: the week card's total beside its top 5")
import unusual  # noqa: E402
import unusual_detect as UD  # noqa: E402
CFG = {"window": 28, "min_devices": 10, "ratio": 2.0, "z": 4.0, "min_history": 7}
d0 = date(2026, 10, 20)
ds = [(d0 + timedelta(days=i)).isoformat() for i in range(29)]
th = {f"{64501 + k}|sinkhole": 10 for k in range(8)}
hist = [{"day": dd, "n_devices": 1000, "reports": {"sinkhole": {"devices": 200, "platform": "comms"}}, "threads": dict(th), "pairs": {}}
        for dd in ds[:28]]
todayx = dict(hist[0], day=ds[28], threads={k: 60 for k in th})
sug = UD.detect(todayx, hist, CFG)
ub = tempfile.mkdtemp(prefix="lg-cut-unusual-")
os.makedirs(os.path.join(ub, "data", "unusual", "days"))
json.dump({"day": ds[28], "made": 1, "config": CFG, "suggestions": sug, "week": {ds[28]: sug}},
          open(os.path.join(ub, "data", "unusual", "suggestions.json"), "w"))
uapp = Flask("cut-unusual")


@uapp.before_request
def _who():
    g.user = {"user": "lgpt-person"}


unusual.install(uapp, {"base_dir": ub, "has_perm": lambda p: p == "management", "csrf_ok": lambda: True,
                       "audit": types.SimpleNamespace(add=lambda *a, **k: None), "db": {}, "settings": None,
                       "network": lambda a: "Lakeside", "svc_label": lambda n: n})
wk = uapp.test_client().get("/api/mgmt/unusual-week").get_json()
n_sug = len(sug)
ok(f"the top 5 of {n_sug} unusual threads, with the total and how many more", n_sug > 5 and len(wk["top"]) == 5
   and wk.get("totals") == {"top": n_sug} and wk.get("more") == n_sug - 5, (n_sug, wk.get("totals"), wk.get("more")))

import shutil  # noqa: E402
shutil.rmtree(tmp, ignore_errors=True)
shutil.rmtree(ub, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else "")
      + ("" if pdfium is not None else " (PDF text not checked: no pypdfium2)"))
sys.exit(1 if fails else 0)
