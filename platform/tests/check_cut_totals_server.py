#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The full counts the server sends beside a cut list, and a share sent as a raw fraction (2026-11-26: "nothing goes
missing on the whole platform"). Made-up data in temporary folders, each module's own Flask routes on a small app;
nothing of this installation is read or written. Proved by running:

  1. services_kb.py: a report and its IPv6 twin with 20 distinct products and 250 issues: the window gets the top 12
     products with "totals": {"products": 20, ...} and issues_total 250 (it read 200: the merged list's own cap);
     a product outside one twin's top 12 is counted in full; the list gives each report's product and port totals
     and the full count of the changes beside the newest 30;
  2. request_tracker.py: a user's share of the server time is the raw fraction (1 second of 43,281 is not 0), and the
     shares add up to 1;
  3. connectors.py: the send log gives the newest 200 and "totals": {"log": 1234}; ?n= gives more (Show all), at most
     LOG_MAX; the Audit portal's Data sent out counts every send in the log, not only the newest 5,000 entries;
  4. pipeline_settings.py: the Workers settings give the newest 50 results the pipeline did and "totals": {"results": 60}.

No database needed. Run: .venv/bin/python tests/check_cut_totals_server.py"""
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import date
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask, g  # noqa: E402

passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f": {str(detail)[:500]}" if detail else ""))


TMP = Path(tempfile.mkdtemp(prefix="lg-cut-totals-"))


class Audit:
    def __init__(self):
        self.rows = []

    def add(self, *a, **k):
        self.rows.append((a, k))


# ---------------------------------------------------------------- 1. services_kb.py
print("1. Services reports (services_kb.py)")
import services_kb as SK  # noqa: E402


def rec(i, report, product, issues=()):
    return {"ip": f"192.0.2.{i % 250}" if "6" not in report else f"2001:db8::{i}", "report": report, "product": product,
            "vendor": "Example Corp", "device_type": "router", "version": "1.0", "port": 443, "protocol": "tcp", "severity": "high",
            "issues": list(issues), "tags": []}


# the IPv4 report: 15 products (Product 0 the most common), 250 issues; the IPv6 twin: Products 10..19, Product 19 the
# most common there (its count in the IPv4 report is outside that report's top 12)
evs = []
for p in range(15):
    for k in range(30 - p):
        evs.append(rec(len(evs), "scan_x", f"Product {p}", issues=[f"issue-{(len(evs)) % 250}"]))
for p in range(10, 20):
    for k in range(5 + (p - 10) * 3):
        evs.append(rec(len(evs), "scan6_x", f"Product {p}"))


class Day:
    def __init__(self, e):
        self.events, self.serial = e, 1


class Store:
    days = {date(2026, 11, 20): Day(evs)}


REPORTS = {"scan_x": {"section": "Services", "group": "Known vulnerability", "title": "Accessible X", "severity": "high", "url": ""},
           "scan6_x": {"section": "Services", "group": "Known vulnerability", "title": "IPv6 Accessible X", "url": ""}}
EVENTS = [{"kind": "changed", "report": "scan_x", "text": f"Change {i}", "at": "2026-11-01"} for i in range(35)]


class RMap:
    def get(self):
        return {"reports": REPORTS, "status": {}, "events": EVENTS}

    def description(self, n):
        return None

    def descriptions(self):
        return {"text_included": False}

    def rules(self):
        return {"group_order": {"Services": ["Known vulnerability"]}}


class Notes:
    def list(self, sec, name):
        return []


SK._STATS.update(at=0, data=None)
app = Flask("lg-cut-totals")
SK.install(app, {"report_map": RMap(), "svc_store": Store(), "report_info": lambda n: {}, "notes": Notes(), "allowed": lambda: True,
                 "cve_card": lambda n: {}, "issues_kb": lambda: {}, "collections": lambda: [], "patterns": None, "services_intel": None})
c = app.test_client()
det = c.get("/api/kb/service?name=scan_x").get_json() or {}
tot = det.get("totals") or {}
ok("the window gets the top 12 products and their full count: 20 (15 + the twin's 5 others)",
   len(det.get("products", [])) == 12 and tot.get("products") == 20, (len(det.get("products", [])), tot))
counts = dict(map(tuple, det.get("products", [])))
ok("...a product outside the IPv4 report's top 12 is counted in full with its twin (Product 13: 17 + 14 = 31)",
   counts.get("Product 13") == 31, counts)
ok("...every top list has its total (products, devices, versions, ports, tags, issues)",
   set(tot) >= {"products", "devices", "versions", "ports", "tags", "issues"}, tot)
ok("...250 distinct issues: issues_total 250 (not the merged list's cap of 200), 60 sent", det.get("issues_total") == 250
   and tot.get("issues") == 250 and len(det.get("issues", [])) == 60, (det.get("issues_total"), tot.get("issues"), len(det.get("issues", []))))
lst = c.get("/api/kb/services").get_json() or {}
row = next((r for r in lst.get("reports", []) if r["name"] == "scan_x"), {})
ok("the list: each report's 3 products with their total (20) and ports (1)", row.get("products") and len(row["products"]) == 3
   and (row.get("totals") or {}).get("products") == 20 and (row.get("totals") or {}).get("ports") == 1, row.get("totals"))
ok("...issues_total is the full 250", row.get("issues_total") == 250, row.get("issues_total"))
ok("...the changes: the newest 30 and 'totals': {'events': 35}", len(lst.get("events", [])) == 30
   and (lst.get("totals") or {}).get("events") == 35, (len(lst.get("events", [])), lst.get("totals")))
SK._STATS.update(at=0, data=None)

# the "exploited" count (the user, 2026-11-26: "check every issue"): an actively exploited CVE seen once, on the IPv6
# twin, ranks last of the report's 251 issues, far below the top 40 the count used to look at; it must still count


class Store2:
    days = {date(2026, 11, 20): Day(evs + [rec(len(evs), "scan6_x", "Product 19", issues=["CVE-2024-0001"])])}


app2 = Flask("lg-cut-totals-kev")
SK.install(app2, {"report_map": RMap(), "svc_store": Store2(), "report_info": lambda n: {}, "notes": Notes(), "allowed": lambda: True,
                  "cve_card": lambda n: {"exploited": n == "CVE-2024-0001"}, "issues_kb": lambda: {}, "collections": lambda: [],
                  "patterns": None, "services_intel": None})
row2 = next((r for r in (app2.test_client().get("/api/kb/services").get_json() or {}).get("reports", []) if r["name"] == "scan_x"), {})
ok("the list's 'exploited': a KEV CVE ranked 251st of 251 issues (outside the top 40) counts: 1", row2.get("exploited") == 1,
   (row2.get("exploited"), row2.get("issues_total")))
SK._STATS.update(at=0, data=None)

# ---------------------------------------------------------------- 2. request_tracker.py
print("2. Task monitor, Users (request_tracker.py)")
import request_tracker as RT  # noqa: E402

keep = (dict(RT.DONE), dict(RT.RUNNING), dict(RT.META))
RT.DONE.clear(); RT.RUNNING.clear(); RT.META.clear()
now = time.time()
RT.DONE["heavy"].extend([(now - 5, 43280.0, 1.0, "/a", 200)])
RT.DONE["light"].extend([(now - 5, 0.04, 0.0, "/b", 200), (now - 4, 0.96, 0.0, "/b", 200)])
RT.DONE["tiny"].extend([(now - 5, 0.0004, 0.0, "/c", 200)])
us = {u["user"]: u for u in RT.users(now)}
ok("the share is a fraction: 1 s of 43,281 s is 1/43,281 (not rounded to 0)", abs(us["light"]["share"] - 1 / 43281.0004) < 1e-9, us["light"])
ok("...a request of 0.4 ms still has a share above 0 (its seconds read 0.0, its share does not)", us["tiny"]["seconds"] == 0.0
   and us["tiny"]["share"] > 0, us["tiny"])
ok("...nearly all of it is below 1 (the page says '>99%')", 0.99 < us["heavy"]["share"] < 1, us["heavy"])
ok("...the shares add up to 1", abs(sum(u["share"] for u in us.values()) - 1) < 1e-9, [u["share"] for u in us.values()])
RT.DONE.clear(); RT.RUNNING.clear(); RT.META.clear()
ok("nobody: no share at all, no division by 0", RT.users(now) == [])
RT.DONE.update(keep[0]); RT.RUNNING.update(keep[1]); RT.META.update(keep[2])

# ---------------------------------------------------------------- 3. connectors.py
print("3. Connectors, the send log (connectors.py)")
import connectors as CN  # noqa: E402

cbase = TMP / "connectors"
(cbase / "data").mkdir(parents=True)
with open(cbase / "data" / "connectors_log.jsonl", "w", encoding="utf-8") as f:
    for i in range(1234):
        f.write(json.dumps({"target": "t1", "at": 1764000000 + i, "day": "2026-11-20", "status": "sent", "devices": 2}) + "\n")
    for i in range(7):
        f.write(json.dumps({"target": "t2", "at": 1764000000 + i, "status": "sent"}) + "\n")
    f.write("not json\n")
capp = Flask("lg-cut-connectors")
CN.install(capp, {"base_dir": str(cbase), "audit": Audit(), "has_perm": lambda p: True, "csrf_ok": lambda: True, "fresh": lambda: True})
cc = capp.test_client()
j = cc.get("/api/connectors/t1/log").get_json() or {}
ok("the send log: the newest 200 of target t1 and 'totals': {'log': 1234}", len(j.get("log", [])) == 200
   and (j.get("totals") or {}).get("log") == 1234 and j["log"][0]["at"] == 1764000000 + 1233, (len(j.get("log", [])), j.get("totals")))
j = cc.get("/api/connectors/t1/log?n=1234").get_json() or {}
ok("...?n=1234 (Show all): every one of the 1,234", len(j.get("log", [])) == 1234, len(j.get("log", [])))
LOG_MAX = getattr(CN, "LOG_MAX", 5000)
j = cc.get(f"/api/connectors/t1/log?n={LOG_MAX * 10}").get_json() or {}
ok("...at most LOG_MAX in one answer, a bad n gives the 200", len(j.get("log", [])) == min(1234, LOG_MAX)
   and len((cc.get("/api/connectors/t1/log?n=x").get_json() or {}).get("log", [])) == 200)
ok("...another target's count is its own (7)", (cc.get("/api/connectors/t2/log").get_json() or {}).get("totals", {}).get("log") == 7)
with open(cbase / "data" / "connectors_log.jsonl", "a", encoding="utf-8") as f:
    for i in range(5000):
        f.write(json.dumps({"target": "t1", "at": 1765000000 + i, "day": "2026-11-21", "status": "sent", "devices": 1}) + "\n")
a = cc.get("/api/audit/connectors").get_json() or {}
ok("the Audit portal's Data sent out counts every send of the log (6,241), not only the newest 5,000 entries",
   (a.get("totals") or {}).get("sends") == 6241 and (a.get("totals") or {}).get("devices") == 1234 * 2 + 5000
   and a.get("more") == 6241 - 1000, (a.get("totals"), a.get("more")))

# ---------------------------------------------------------------- 4. pipeline_settings.py
print("4. Workers, done by the pipeline (pipeline_settings.py)")
import pipeline_settings as PS  # noqa: E402

here = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src = next((p for p in ([Path(os.environ["LG_TEST_PIPELINE_SRC"])] if os.environ.get("LG_TEST_PIPELINE_SRC") else [])
            + [here.parent / "database", here.parent / "shadowserver"] if (p / "worker_settings.py").exists()), None)
if not src:
    print("  (skipped: no pipeline's worker_settings.py beside the platform)")
else:
    pipe = TMP / "database"
    pipe.mkdir()
    shutil.copy(src / "worker_settings.py", pipe / "worker_settings.py")
    (pipe / "shadowserver_pipeline.py").write_text("# stand-in\n")
    (pipe / ".env").write_text("MAIL_PROVIDER=imap\nWORKERS=6\n")
    plat = TMP / "platform-data"
    done = plat / "pipeline_requests" / "done"
    done.mkdir(parents=True)
    for i in range(60):
        p = done / f"r{i:03d}.json"
        p.write_text(json.dumps({"id": f"r{i:03d}", "kind": "settings", "by": "admin", "status": "applied", "changed": [f"c{i}"],
                                 "applied_at": "2026-11-20T10:00"}))
        os.utime(p, (1764000000 + i, 1764000000 + i))
    old = os.environ.get("PIPELINE_DIR")
    os.environ["PIPELINE_DIR"] = str(pipe)
    papp = Flask("lg-cut-pipeline")
    PS.install(papp, {"base_dir": str(TMP / "platform"), "data_dir": str(plat), "has_perm": lambda p: True, "csrf_ok": lambda: True,
                      "fresh": lambda: True, "audit": Audit(), "users": None, "throttle": None, "client": lambda: ("", "")})

    @papp.before_request
    def _who():
        g.user = {"user": "admin", "csrf": "x"}

    s = papp.test_client().get("/api/pipeline/settings").get_json() or {}
    ok("60 requests done: the newest 50 sent and 'totals': {'results': 60}", s.get("found") and len(s.get("results", [])) == 50
       and (s.get("totals") or {}).get("results") == 60, (s.get("found"), len(s.get("results", [])), s.get("totals"), s.get("message")))
    ok("...the newest first", (s.get("results") or [{}])[0].get("id") == "r059", (s.get("results") or [{}])[0].get("id"))
    if old is None:
        os.environ.pop("PIPELINE_DIR", None)
    else:
        os.environ["PIPELINE_DIR"] = old

shutil.rmtree(TMP, ignore_errors=True)
print()
print(f"{passed}/{passed + failed} checks passed" + (f"; {failed} FAILED" if failed else ""))
sys.exit(1 if failed else 0)
