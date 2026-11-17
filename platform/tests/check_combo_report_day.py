#!/usr/bin/env python3
"""The analysts' combination search counts like the researcher (the user, 2026-11-17: the search showed 53 devices where
the researcher and the Executive portal showed 43). Made-up records only (documentation addresses), no database:
1. the report day is the default: exactly the devices that carried the whole combination that day
2. the days in memory: each day matched on its own (a router on 15 Nov and a sinkhole call on 16 Nov is not a device
   carrying the combination)
3. each report-day device says whether it carried the same combination on the other days in memory, or what changed
4. each device names its infections, issues and CVEs that day (page, devices CSV)
Run: .venv/bin/python tests/check_combo_report_day.py"""
import csv
import faulthandler
import io
import os
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, g  # noqa: E402
import combos  # noqa: E402
import intel as I  # noqa: E402
import services_intel as SI  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


D15 = datetime(2026, 11, 15, tzinfo=timezone.utc)
D16 = D15 + timedelta(days=1)
REP = "scan_mikrotik_service"
n_id = [0]


class Day:
    def __init__(self, start, events):
        self.start, self.events, self.serial = start, events, 1


class Store:
    def __init__(self, days):
        self.days = {d.start: d for d in days}

    def get(self, _t):
        return None


class Patterns:
    def fields_for(self, base):
        return []

    def items(self, base, e, fields):
        return []


def svc(ip, day, issues=(), tags=()):
    n_id[0] += 1
    t = day + timedelta(hours=3)
    return {"id": f"s{n_id[0]}", "ip": ip, "report": REP, "report_label": "Accessible MikroTik Service", "asn": "64500",
            "issues": list(issues), "tags": list(tags), "region": "greater accra", "city": "accra", "geo": "GH",
            "extracted_date": t.isoformat(), "_t": t.timestamp(), "port": 8291, "protocol": "tcp"}


def sink(ip, day, name="m0yv"):
    n_id[0] += 1
    t = day + timedelta(hours=4)
    return {"id": f"c{n_id[0]}", "src_ip": ip, "infection": name, "source": "event4_sinkhole_http", "_t": t.timestamp(),
            "timestamp": t.isoformat(), "extracted_date": t.isoformat()}


A, B, C, D = "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"
# A: router + m0yv on both days (the same). B: router on 15 Nov only, m0yv on 16 Nov (never both the same day).
# C: router + m0yv on 16 Nov; on 15 Nov a router without the sinkhole call (changed). D: 16 Nov only, with a CVE.
svc_days = [Day(D15, [svc(A, D15), svc(B, D15), svc(C, D15)]),
            Day(D16, [svc(A, D16), svc(C, D16), svc(D, D16, issues=["CVE-2023-30799"], tags=["router", "cve-2018-14847"])])]
comms_days = [Day(D15, [sink(A, D15)]),
              Day(D16, [sink(A, D16), sink(B, D16), sink(C, D16), sink(D, D16), sink(D, D16, "andromeda")])]
labels = {"event4_sinkhole_http": "Sinkhole HTTP", REP: REP}
now16 = lambda: D16 + timedelta(hours=7)                              # noqa: E731  (replaying 16 Nov)
sv = SI.ServicesIntel({"svc_store": Store(svc_days), "comms_store": Store(comms_days), "patterns": Patterns(),
                       "replay_now": now16, "labels": lambda: labels})


class FakeIntel:
    on_codes = None

    def index(self, scope=None):
        return {"by": {}, "xcombos": {}, "days": []}


class Audit:
    def add(self, *a, **k):
        pass


class Notes:
    def list(self, *a):
        return []


tmp = tempfile.mkdtemp(prefix="lg-combo-rd-")
os.makedirs(os.path.join(tmp, "data"), exist_ok=True)
app = Flask(__name__)
app.secret_key = "test-only"
ctx = {"intel": FakeIntel(), "store": Store(comms_days), "svc_store": Store(svc_days), "labels": lambda: labels,
       "fetch": lambda *a: [], "network": lambda asn: "Example Net" if asn else "", "has_perm": lambda p: True,
       "csrf_ok": lambda: True, "is_demo": lambda: False, "audit": Audit(), "notes": Notes(), "explain": lambda *a: None,
       "build_pdf": lambda spec: b"%PDF-1.4 test", "scope_text": lambda: "test", "base_dir": tmp, "can_note": lambda: False,
       "shapes": lambda: None, "country": lambda: "Ghana", "title_of": lambda n: "Accessible MikroTik Service" if n == REP else n,
       "svc_matcher": lambda entry, scope="memory": sv.matcher(entry, scope), "svc_new_code": lambda r, i: (None, "no"),
       "host_flags": lambda hosts, scope=None: sv.host_flags(hosts, scope), "replay_now": now16, "logger": app.logger}
book = combos.install(app, ctx)


@app.before_request
def _user():
    g.user = {"user": "analyst-test"}


parts = [(REP, []), (SI.SINK, ["Infection: m0yv"])]
book.record("services", REP, None, [parts])
code = I.cross_code("services", REP, parts)
cl = app.test_client()


def search(**body):
    r = cl.post("/api/combos/search", json={"code": code, **body})
    if "id" not in (r.get_json() or {}):
        print("    search refused:", r.status_code, r.get_json())
        return None, {}
    jid = r.get_json()["id"]
    s = {}
    for _ in range(1800):
        s = cl.get(f"/api/combos/search/{jid}").get_json()
        if s.get("state") != "running":
            return jid, s
        time.sleep(0.1)
    print("    still running after 3 minutes:", (s.get("log") or [])[-3:])
    return jid, {}


if os.environ.get("LG_TEST_DEBUG"):
    faulthandler.dump_traceback_later(40, exit=True)
print("1. The report day (the default)")
lk = cl.get(f"/api/combo-codes/{code}").get_json()
ok("the look-up names the report day", lk.get("report_day") == "2026-11-16", str(lk.get("report_day")))
jid, s = search()
sm = s.get("summary") or {}
ok("the search finished", s.get("state") == "done", s.get("error", ""))
ips = sorted(d["ip"] for d in sm.get("top_devices") or [])
ok("exactly the devices with the whole combination on 16 Nov: A, C and D (not B)", ips == [A, C, D], str(ips))
ok("the summary says it is the report day", sm.get("report_day") == "2026-11-16")

print("2. The days in memory: each day on its own")
_, s2 = search(where="memory")
ips2 = sorted(d["ip"] for d in (s2.get("summary") or {}).get("top_devices") or [])
ok("B (router on 15 Nov, sinkhole call on 16 Nov) is never counted", B not in ips2 and ips2 == [A, C, D], str(ips2))
ok("A on both days", next(d for d in s2["summary"]["top_devices"] if d["ip"] == A)["days"] == 2)

print("3. The other days in memory: the same, or changed")
by = {d["ip"]: d for d in sm.get("top_devices") or []}
ea = by.get(A, {}).get("earlier") or []
ok("A: carried this same combination on 15 Nov", len(ea) == 1 and ea[0]["same"] and ea[0]["day"] == "2026-11-15", str(ea))
ec = by.get(C, {}).get("earlier") or []
ok("C: changed on 15 Nov, and says what (in the report, no sinkhole call)",
   len(ec) == 1 and not ec[0]["same"] and "changed" in ec[0]["text"] and "no sinkhole call" in ec[0]["text"]
   and "in Accessible MikroTik Service" in ec[0]["text"], str(ec))
ok("D: nothing on another day", (by.get(D, {}).get("earlier") or []) == [])

print("4. What each device is: infections, issues, CVEs")
dd = by.get(D, {})
ok("D's infections that day: andromeda and m0yv", dd.get("infections") == ["andromeda", "m0yv"], str(dd.get("infections")))
ok("D's CVEs: from its issues and its tags", dd.get("cves") == ["CVE-2018-14847", "CVE-2023-30799"], str(dd.get("cves")))
z = zipfile.ZipFile(io.BytesIO(cl.get(f"/api/combos/search/{jid}/download").data))
dev_csv = next(n for n in z.namelist() if n.endswith("_devices.csv"))
rows = list(csv.DictReader(io.StringIO(z.read(dev_csv).decode("utf-8-sig"))))
ok("the files are named for the report day", "2026-11-16" in dev_csv and "memory" not in dev_csv, dev_csv)
pdf = z.read(next(n for n in z.namelist() if n.endswith(".pdf")))
if os.environ.get("LG_TEST_PDF"):                       # to look at the pages (made-up data)
    open(os.environ["LG_TEST_PDF"], "wb").write(pdf)
ok("the PDF is drawn (combo_pdf.py, with the new device columns), not the plain fallback",
   pdf.startswith(b"%PDF") and pdf != b"%PDF-1.4 test" and len(pdf) > 5000, f"{len(pdf):,} bytes")
rd = {r["ip"]: r for r in rows}
ok("devices CSV: infections, issues, CVEs and other days columns",
   rd.get(D, {}).get("cves") == "CVE-2018-14847, CVE-2023-30799" and "m0yv" in rd.get(D, {}).get("infections", "")
   and "same combination" in rd.get(A, {}).get("other_days", "") and "changed" in rd.get(C, {}).get("other_days", ""))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
