#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Report downloads (PDF + CSV in a ZIP, or PDF alone) of both platforms and the Executive portal, against the
platform's own lists and against MongoDB. Each download is an audit-log entry of the automation account (filtered as a
self-test on the Admin page). Usage: tests/check_reports.py"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import os, sys, io, csv, json, re, time, zipfile, urllib.request, urllib.parse, urllib.error
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import mongo_derive as L  # noqa: E402
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient

load_dotenv(os.path.join(BASE_DIR, ".env"))
db = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                 password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"))[os.environ["MONGO_DB"]]


def raw(path, params):
    q = urllib.parse.urlencode(params, doseq=True)
    t = time.time()
    with urllib.request.urlopen(f"http://127.0.0.1:5000{path}?{q}", timeout=900) as r:
        return r.read(), r.headers.get("Content-Type", ""), r.headers.get("Content-Disposition", ""), time.time() - t


api = lambda path, params=(): json.loads(raw(path, list(params))[0])
fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def pdf_ok(b):
    pages = len(re.findall(rb"/Type\s*/Page[^s]", b))
    return b.startswith(b"%PDF") and b.rstrip().endswith(b"%%EOF") and pages > 0, pages


def unzip(b):
    z = zipfile.ZipFile(io.BytesIO(b))
    out = {}
    for n in z.namelist():
        data = z.read(n)
        out[n] = data if n.endswith(".pdf") else list(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
    return out


clock = api("/api/clock")
DAY = clock["replay_day"]; START = datetime.fromisoformat(DAY).replace(tzinfo=timezone.utc)
AT = DAY + "T12:00:00Z"
diag = api("/api/diagnostics")
LAYOUT = {s["name"]: s["layout"] for s in diag["supported"]}
EV = L.comms(db, [s["name"] for s in diag["supported"]], LAYOUT, START)
svf = api("/api/svc/facets")
S_LABEL = {r["name"]: r["label"] for r in svf["reports"]}
SEV = L.services(db, list(S_LABEL), S_LABEL, START)
print(f"Day {DAY}: {len(EV):,} communications and {len(SEV):,} services records in MongoDB")

print("\n1. Network communications: analysis reports (ZIP = PDF + complete CSV list)")
stats = api("/api/stats", [("at", AT)])
top_inf = stats["infection"][0]["value"]; top_src = stats["source"][0]["value"]
cases = [("infection", top_inf, "hosts", len({e["src_ip"] for e in EV if e["infection"] == top_inf and e["src_ip"]}), "source hosts"),
         ("source", top_src, "hosts", len({e["src_ip"] for e in EV if e["source"] == top_src and e["src_ip"]}), "source hosts"),
         ("infection", top_inf, "dst_ips", len({e["dst_ip"] for e in EV if e["infection"] == top_inf and e["dst_ip"]}), "destination IPs"),
         ("infection", top_inf, "c2", len({e["http_host"] for e in EV if e["infection"] == top_inf and e["http_host"]}), "C2 domains"),
         ("filters", "attack_class=Botnet C2", "hosts", len({e["src_ip"] for e in EV if e["attack_class"] == "Botnet C2" and e["src_ip"]}), "source hosts")]
for kind, value, metric, mongo_n, what in cases:
    p = [("at", AT), ("kind", kind), ("value", value), ("metric", metric), ("all", "1")]
    drill = api("/api/insight/drill", p)
    b, ctype, disp, dt = raw("/api/insight/report", p)
    files = unzip(b)
    pdfs = [n for n in files if n.endswith(".pdf")]; csvs = [n for n in files if n.endswith(".csv")]
    good, pages = pdf_ok(files[pdfs[0]]) if pdfs else (False, 0)
    rows = len(files[csvs[0]]) - 1 if csvs else -1
    ok(f"{kind}={value[:28]} / {metric}: ZIP with PDF ({pages} pages) + CSV of {rows:,} rows in {dt:.1f}s",
       ctype == "application/zip" and good and rows == drill["total"] == mongo_n, f"list {drill['total']:,}, MongoDB {mongo_n:,} {what}")
b, ctype, _, dt = raw("/api/insight/report", [("at", AT), ("kind", "infection"), ("value", top_inf), ("metric", "hosts"), ("all", "1"), ("format", "pdf")])
good, pages = pdf_ok(b)
ok(f"format=pdf gives the PDF alone ({pages} pages, {len(b)//1024} KB, {dt:.1f}s)", ctype == "application/pdf" and good)
try:
    raw("/api/insight/report", [("at", AT), ("kind", "infection"), ("value", top_inf), ("metric", "hosts")])
    ok("without all=1 the report is refused", False)
except urllib.error.HTTPError as e:
    ok("without all=1 the report is refused", e.code == 400, f"HTTP {e.code}")

print("\n2. Services: analysis reports")
sst = api("/api/svc/stats", [("at", AT)])
fam0 = sst["breakdowns"]["family"][0]["value"]; iss0 = sst["breakdowns"]["issue"][0]["value"] if sst["breakdowns"]["issue"] else None
scases = [([("family", fam0)], "hosts", len({e["ip"] for e in SEV if e["family"] == fam0}), "hosts"),
          ([], "vulnerable", len({e["ip"] for e in SEV if e["issues"]}), "hosts with an issue"),
          ([], "issues", len({i for e in SEV for i in e["issues"]}), "issues")]
if iss0:
    scases.append(([("issue", iss0)], "hosts", len({e["ip"] for e in SEV if iss0 in e["issues"]}), "hosts"))
for flt, metric, mongo_n, what in scases:
    p = [("at", AT), ("metric", metric), ("all", "1")] + flt
    drill = api("/api/svc/drill", p)
    b, ctype, _, dt = raw("/api/svc/report", p)
    files = unzip(b)
    pdfs = [n for n in files if n.endswith(".pdf")]; csvs = [n for n in files if n.endswith(".csv")]
    good, pages = pdf_ok(files[pdfs[0]]) if pdfs else (False, 0)
    rows = len(files[csvs[0]]) - 1 if csvs else -1
    lab = (flt[0][0] + "=" + flt[0][1][:24]) if flt else "everything"
    ok(f"{lab} / {metric}: ZIP with PDF ({pages} pages) + CSV of {rows:,} rows in {dt:.1f}s",
       ctype == "application/zip" and good and rows == drill["total"] == mongo_n, f"list {drill['total']:,}, MongoDB {mongo_n:,} {what}")

print("\n3. Executive reports (PDF + combination CSVs + 7-day trend CSV)")
for plat in ("comms", "services"):
    d = api(f"/api/mgmt/{plat}")
    b, ctype, _, dt = raw("/api/mgmt/report", [("platform", plat)])
    files = unzip(b)
    pdfs = [n for n in files if n.endswith(".pdf")]
    good, pages = pdf_ok(files[pdfs[0]]) if pdfs else (False, 0)
    ok(f"{plat}: ZIP with PDF ({pages} pages) and {len(files) - 1} CSV files in {dt:.1f}s", ctype == "application/zip" and good)
    multi_name, cross_name = ("infection-combinations", "report-combinations") if plat == "comms" else ("issue-combinations", "service-combinations")
    mkey, ckey = ("devices", "devices") if plat == "comms" else ("hosts", "hosts")
    for name, part in ((multi_name, "multi"), (cross_name, "cross")):
        f = next((v for n, v in files.items() if n.endswith(f"_{name}.csv")), None)
        rows = f[1:] if f else []
        total = sum(int(r[2]) for r in rows)
        ok(f"{plat}: {name}.csv lists {len(rows):,} combinations adding up to {total:,} {mkey}",
           f is not None and len(rows) == d[part]["combinations"] and total == d[part][mkey], f"page: {d[part]['combinations']:,} / {d[part][mkey]:,}")
    tr = next((v for n, v in files.items() if n.endswith("_seven-day-trend.csv")), None)
    b_ = d["baseline"]; keys = list(b_["kpis"])
    good_tr = tr is not None
    if tr:
        for i, day_s in enumerate(b_["days"]):
            row = tr[1 + i]
            good_tr &= row[0] == day_s and all((row[1 + j] == "" and b_["kpis"][k][i] is None) or row[1 + j] == str(b_["kpis"][k][i]) for j, k in enumerate(keys))
        last = tr[1 + len(b_["days"])]
        good_tr &= last[0].startswith(d["day"]) and all(last[1 + j] == str(d["kpis"].get(k, "")) for j, k in enumerate(keys))
    ok(f"{plat}: seven-day-trend.csv matches the page's 7-day baseline and today's figures", good_tr)
b, ctype, _, _ = raw("/api/mgmt/report", [("platform", "comms"), ("format", "pdf")])
ok("Executive format=pdf gives the PDF alone", ctype == "application/pdf" and pdf_ok(b)[0])
print(f"\n{checks - len(fails)} of {checks} report checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
