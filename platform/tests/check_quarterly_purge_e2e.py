#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The quarterly purge end to end: the platform (quarterly.py) makes the report and writes the permit, the database
pipeline (quarterly_purge.py) deletes, the platform records it (the audit log, the bell). Pretend dates only: no real
waiting; "today" is handed to quarterly.build, quarterly_purge.run and the platform's background check (tick).

  2026Q4 ends Thursday 31 December 2026; its report is made on Sunday 3 January 2027; the 15th working day after the
  quarter is Thursday 21 January; the purge runs on Friday 22 January; the cutoff is 22 December 2026 (rows dated
  before it go, the last 31 days stay).

  Cycle A, the purge on: made VALID on 3 January with a permit; 21 January refused, nothing deleted; 22 January exactly
  the rows dated before the cutoff deleted (the rows from 22 December on, January's rows, other collections, findings,
  cases, advisories and the quarterly reports kept); recorded once (one audit entry, one bell alert); a second run
  that day deletes and records nothing.
  Cycle B, the purge off: no permit, nothing deleted on any day, a permit forged while off refused, nothing recorded.
  Cycle C, the purge on but the report NOT VALID: no permit, nothing deleted, nothing recorded.

Builds its OWN throwaway MongoDB database (lg_purge_e2e_<random>), never the reports database, and drops it at the end,
also on failure; temporary folders for the platform's data and the pipeline's. Only made-up rows and documentation
addresses (192.0.2.x, 198.51.100.x, 203.0.113.x).
The pipeline's code: LG_PIPELINE_DIR (a held copy may hold only the changed files), else ../database (a release) or
../shadowserver (a development copy).
Run: .venv/bin/python tests/check_quarterly_purge_e2e.py   (needs an account that may create a database:
tests/run_admin_db_tests.sh, or LG_MONGO_ADMIN_FILE; without one it is skipped)"""
import csv
import hashlib
import io
import json
import logging
import os
import secrets
import shutil
import sys
import tempfile
import zipfile
from collections import Counter
from datetime import date, datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.dirname(HERE)
sys.path.insert(0, PLATFORM)
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def done(code=None):
    print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
    sys.exit(code if code is not None else (1 if fails else 0))


# ------------------------------------------------------------------ the pipeline's code (appended: platform first)
TOP = os.path.dirname(PLATFORM)
CANDS = [p for p in (os.environ.get("LG_PIPELINE_DIR"), os.path.join(TOP, "database"), os.path.join(TOP, "shadowserver")) if p]
PIPE_CODE = next((p for p in CANDS if os.path.isfile(os.path.join(p, "quarterly_purge.py"))), None)
if not PIPE_CODE:
    print("SKIPPED: the database pipeline's quarterly_purge.py was not found (LG_PIPELINE_DIR, ../database, ../shadowserver)")
    done(77)
for p in [PIPE_CODE] + [c for c in CANDS if c != PIPE_CODE and os.path.isdir(c)]:
    sys.path.append(p)

from flask import Flask  # noqa: E402

import auth  # noqa: E402
import quarterly as qq  # noqa: E402
import quarterly_purge as qp  # noqa: E402
import system_alerts  # noqa: E402

# a run lock of this test's own (r91): never the pipeline folder's real .pipeline.lock, which a scheduled run takes
qp.RUN_LOCK = os.path.join(tempfile.mkdtemp(prefix="lgpe_lock_"), ".pipeline.lock")
print(f"The pipeline's quarterly_purge.py from {os.path.basename(PIPE_CODE)}/")

Q = "2026Q4"
CUT = "2026-12-22"
D = date
plog = logging.getLogger("lg-purge-e2e")
plog.addHandler(logging.NullHandler())
plog.propagate = False


def ts(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


# ------------------------------------------------------------------ the rule's dates, as both sides work them out
print("\nThe dates of 2026Q4 (both sides)")
pd_ = qq.purge_dates(2026, 4)
pp_ = qp.dates(2026, 4)
want = {"last_day": D(2026, 12, 31), "working_day_15": D(2027, 1, 21), "purge_day": D(2027, 1, 22), "cutoff": D(2026, 12, 22)}
ok("the platform: ends Thu 31 Dec 2026, 15th working day Thu 21 Jan, purge Fri 22 Jan, cutoff 22 Dec 2026",
   all(pd_[k] == v for k, v in want.items()), str(pd_))
ok("the pipeline works out the same dates itself", all(pp_[k] == v for k, v in want.items()), str(pp_))
ok("made automatically on the next quarter's 3rd day (3 January 2027), not on the 2nd",
   qq.make_due(D(2027, 1, 3)) == Q and qq.make_due(D(2027, 1, 2)) is None and qq.make_day(2026, 4) == D(2027, 1, 3))
ok("the permit's rule: VALID, made 3 Jan, purge on, before the purge day: a permit",
   qq.permit_rule(True, D(2027, 1, 3), D(2027, 1, 22), True, D(2027, 1, 3)) == (True, ""))
ok("...not when the purge is off, nor when NOT VALID",
   qq.permit_rule(True, D(2027, 1, 3), D(2027, 1, 22), False, D(2027, 1, 3)) == (False, qq.WHY_OFF)
   and qq.permit_rule(False, D(2027, 1, 3), D(2027, 1, 22), True, D(2027, 1, 3)) == (False, qq.WHY_INVALID))

# ------------------------------------------------------------------ the made-up rows
POOL = [f"192.0.2.{i}" for i in range(1, 255)] + [f"198.51.100.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(1, 255)]
REPORTS = ("scan_http", "event4_sinkhole_http", "blocklist")       # report collections with the filename index


def fixture():
    rows = {c: [] for c in REPORTS}

    def svc(coll, ip, asn, day):
        rows[coll].append({"ip": ip, "port": 80, "geo": "KE", "region": "NAIROBI", "sector": "Information", "severity": "medium",
                           "tag": "", "asn": asn, "filename": f"{day}-{coll}-ke.csv", "extracted_date": f"{day} 12:00:00",
                           "logged_date": f"{day} 12:00:00"})

    d, k = D(2026, 10, 1), 0
    while d <= D(2027, 1, 10):                         # every day of the quarter, and ten days of January
        day = d.isoformat()
        for j in range(2):
            svc("scan_http", POOL[(2 * k + j) % 300], 64500 + j, day)
        if k % 3 == 0:
            rows["event4_sinkhole_http"].append({
                "src_ip": POOL[300 + k % 100], "src_asn": 64501, "src_geo": "KE", "src_region": "MOMBASA", "src_sector": "Information",
                "dst_ip": "198.51.100.250", "dst_geo": "US", "dst_port": 80, "infection": "andromeda", "family": "", "tag": "",
                "severity": "high", "filename": f"{day}-event4_sinkhole_http-ke.csv", "extracted_date": f"{day} 08:00:00",
                "logged_date": f"{day} 08:00:00"})
        d += timedelta(days=1)
        k += 1
    for day, n in (("2026-10-01", 1), ("2026-12-21", 3), ("2026-12-22", 2), ("2026-12-31", 1), ("2027-01-05", 1)):
        for i in range(n):                             # the day before the cutoff goes; the cutoff day itself stays
            svc("blocklist", POOL[500 + i], 64502, day)
    return rows


ROWS = fixture()
EXP_DEL = {c: sum(1 for r in ROWS[c] if r["filename"][:10] < CUT) for c in REPORTS}
EXP_KEEP = {c: len(ROWS[c]) - EXP_DEL[c] for c in REPORTS}
OTHERS = {"scan_ftp": 2, "files_scan_http": 3, "lg_e2e_keep": 2}   # never touched (no filename index / not reports)
ok("fixture: rows on both sides of the cutoff in every report collection, and January rows",
   all(EXP_DEL[c] and EXP_KEEP[c] for c in REPORTS) and any(r["filename"].startswith("2027-01") for r in ROWS["scan_http"]),
   f"delete {EXP_DEL}, keep {EXP_KEEP}")


def seed(db):
    for c in db.list_collection_names():
        db.drop_collection(c)
    for c in REPORTS:
        db[c].insert_many([dict(r) for r in ROWS[c]])
        db[c].create_index([("filename", 1), ("category", 1), ("line_hash", 1)])
    db["scan_ftp"].insert_many([{"ip": POOL[600 + i], "asn": 64503, "port": 21, "geo": "KE", "region": "NAIROBI",
                                 "filename": f"2026-11-0{i + 1}-scan_ftp-ke.csv"} for i in range(OTHERS["scan_ftp"])])
    db["files_scan_http"].insert_many([{"filename": f"2026-10-0{i + 1}-scan_http-ke.csv", "rows": 2} for i in range(OTHERS["files_scan_http"])])
    db["files_scan_http"].create_index([("filename", 1)])
    db["lg_e2e_keep"].insert_many([{"filename": f"2026-10-0{i + 1}-x.csv", "note": "made up"} for i in range(OTHERS["lg_e2e_keep"])])
    db["lg_e2e_keep"].create_index([("filename", 1)])


def counts(db):
    return {c: db[c].count_documents({}) for c in list(REPORTS) + list(OTHERS)}


BEFORE = {**{c: len(ROWS[c]) for c in REPORTS}, **OTHERS}


# ------------------------------------------------------------------ a platform and a pipeline, each in a temp folder
def setup(root):
    base = os.path.join(root, "platform")
    data = os.path.join(base, "data")
    os.makedirs(os.path.join(data, "advisories", "files", "ADV-2026-001"))

    def J(name, obj):
        with open(os.path.join(data, name), "w", encoding="utf-8") as fh:
            json.dump(obj, fh)
    J("asns.json", {"asns": {"64500": {"name": "Example Net A"}, "64501": {"name": "Example Net B"},
                             "64502": {"name": "Example Net C"}, "64503": {"name": "Example Net D"}}})
    J("infections.json", {"infections": {"andromeda": {"title": "Andromeda (Gamarue)"}}})
    at = ts("2026-11-02 09:00:00")
    H = [{"status": "management", "user": "an.analyst", "role": "analyst", "at": at, "comment": "", "to": ""}]
    J("findings.json", {"seq": 4, "items": {
        "1": {"id": "1", "title": "Exposed web panels", "network": "Example Net A", "status": "management", "at": at,
              "user": "an.analyst", "history": H},
        "2": {"id": "2", "origin": "analyst", "kind": "case", "title": "A case on two networks", "status": "management",
              "at": at, "user": "an.analyst", "children": ["3", "4"], "history": H},
        "3": {"id": "3", "parent": "2", "kind": "review", "title": "Sub-finding A", "network": "Example Net A",
              "status": "management", "at": at, "user": "an.analyst", "history": H},
        "4": {"id": "4", "parent": "2", "kind": "review", "title": "Sub-finding B", "network": "Example Net B",
              "status": "management", "at": at, "user": "an.analyst", "history": H}}})
    J("advisories/ADV-2026-001.json", {"ref": "ADV-2026-001", "finding": "1", "network": "Example Net A", "status": "sent",
                                       "subject": "Exposed web panels", "sends": [{"at": at + 86400, "by": "adv.example",
                                                                                   "to": ["Example Net A"]}],
                                       "reports": [{"n": 1, "at": at, "name": "x.pdf"}], "updated": at + 86400})
    buf = io.StringIO()
    csv.writer(buf).writerows([["ip", "asn", "network", "reports"], [POOL[0], "64500", "Example Net A", "Accessible HTTP"]])
    with zipfile.ZipFile(os.path.join(data, "advisories", "files", "ADV-2026-001", "1.zip"), "w") as zf:
        zf.writestr("devices.csv", buf.getvalue())
    pipe = os.path.join(root, "pipeline")                # the pipeline's folder and DATA_DIR (its purge record)
    os.makedirs(pipe)
    with open(os.path.join(pipe, "shadowserver_pipeline.py"), "w") as fh:
        fh.write("# made-up stand-in\n")
    with open(os.path.join(pipe, ".env"), "w") as fh:
        fh.write(f"DATA_DIR={pipe}\n")
    os.environ["PIPELINE_DIR"] = pipe
    audit = auth.Audit(os.path.join(data, "audit.log"))
    api = qq.install(Flask(f"purge_e2e_{secrets.token_hex(3)}"),
                     {"base_dir": base, "db": DB, "has_perm": lambda p: False, "csrf_ok": lambda: False, "audit": audit,
                      "logger": None, "serving": False, "findings": None, "settings": None})
    return base, pipe, audit, api


def snapshot(base, quarter_files=True):
    """sha256 of the findings, cases, advisories and (optionally) the quarterly report files."""
    out = {}
    data = os.path.join(base, "data")
    for rel in ("findings.json", "advisories/ADV-2026-001.json", "advisories/files/ADV-2026-001/1.zip"):
        out[rel] = hashlib.sha256(open(os.path.join(data, rel), "rb").read()).hexdigest()
    qd = qq.quarter_dir(base, Q)
    if quarter_files and os.path.isdir(qd):
        for n in sorted(os.listdir(qd)):
            if n.endswith((".csv", ".pdf")) or n == "summary.json":
                out["quarterly/" + n] = hashlib.sha256(open(os.path.join(qd, n), "rb").read()).hexdigest()
    return out


def purge_audits(audit):
    return [r for r in audit.records() if r.get("event") == "quarterly_purge"]


def purged_bell(base, now):
    a = system_alerts.Alerts(base, env={})
    return [x for x in a.for_user("ada.admin", now, has_perm=lambda p: p in ("settings", "management", "advisory"))
            if x["id"].startswith("sys:quarterly-purged")]


def pipeline(base, pipe, day, at):
    return qp.run(DB, os.path.join(base, "data"), pipe, plog, today=day, now=ts(at))


def nothing_recorded(label, base, pipe, audit, api, now):
    api["tick"](now=now)
    st = qp.read_status(pipe)
    ok(f"{label}: nothing recorded as a purge (no audit entry, no bell alert, no purge_result.json, no 'done', "
       "no purged_before)",
       not purge_audits(audit) and not purged_bell(base, now)
       and not os.path.exists(os.path.join(qq.quarter_dir(base, Q), "purge_result.json"))
       and not st.get("done") and not qp.purged_before(pipe), json.dumps(st)[:300])


# ------------------------------------------------------------------ the throwaway database
import _throwaway_mongo  # noqa: E402  (the platform's way to an account that may create a throwaway database)
from dotenv import dotenv_values  # noqa: E402

_env = dotenv_values(os.path.join(PLATFORM, ".env"))
client = _throwaway_mongo.client(_env.get("MONGO_HOST") or "127.0.0.1", _env.get("MONGO_PORT") or 27017)
if client is None:
    print("\nSKIPPED: no account here may create a throwaway database (run tests/run_admin_db_tests.sh, or set LG_MONGO_ADMIN_FILE)")
    done(1 if fails else 77)            # 77: skipped (run_all_checks.sh); the CI database job counts it as a failure
DBN = f"lg_purge_e2e_{secrets.token_hex(4)}"
assert DBN.startswith("lg_purge_e2e_")
DB = client[DBN]
roots = []
keep_pipe_env = os.environ.get("PIPELINE_DIR")
try:
    # ============================================================== cycle A: the purge on
    print("\nCycle A: the purge turned on (Settings → Quarterly)")
    roots.append(tempfile.mkdtemp(prefix="lgpe_a_"))
    base, pipe, audit, api = setup(roots[-1])
    seed(DB)
    ok("1. seeded: made-up rows from October 2026 to 10 January 2027, findings, a case, an advisory", counts(DB) == BEFORE,
       str(counts(DB)))
    qq.set_purge(base, True, "ada.admin", "Ada Admin", {"quarter": ""}, now=ts("2027-01-02 09:00:00"))
    ok("...the switch is on (data/quarterly/purge_confirmed.json says enabled: true)", qq.purge_on(base)
       and json.load(open(qq.confirm_path(base)))["enabled"] is True)
    kept0 = snapshot(base, quarter_files=False)

    print(" 2. Pretend Sunday 3 January 2027: the report is made")
    r0 = pipeline(base, pipe, D(2027, 1, 3), "2027-01-03 00:10:00")
    ok("the pipeline that morning, before the report: nothing deleted", counts(DB) == BEFORE and r0.get("outcome") != "done", str(r0))
    st = qq.build(DB, base, Q, "made automatically after the quarter ended", today=D(2027, 1, 3), now=ts("2027-01-03 00:20:00"))
    qd = qq.quarter_dir(base, Q)
    ok("VALID, every guard passes", st["valid"] and st["status"] == "VALID" and all(g["ok"] for g in st["guards"]),
       "; ".join(f"{g['name']}: {g['detail']}" for g in st["guards"] if not g["ok"]))
    ok("a permit is written (status.json says so, the file is there)", st["permit"] is True and st["no_permit_why"] == ""
       and os.path.isfile(os.path.join(qd, "purge_permit.json")), str(st.get("no_permit_why")))
    permit = json.load(open(os.path.join(qd, "purge_permit.json")))
    ok("the permit: 2026Q4, VALID, made 3 January, purge day 22 January, cutoff 22 December, 15th working day 21 January",
       (permit["quarter"], permit["valid"], permit["status"], permit["generated_at"][:10], permit["purge_day"], permit["cutoff"],
        permit["working_day_15"]) == (Q, True, "VALID", "2027-01-03", "2027-01-22", CUT, "2027-01-21"), str(permit))
    ok("the report's dry count = the rows before the cutoff in the report collections",
       st["rows_purge_deletes"] == sum(EXP_DEL.values()), f"{st['rows_purge_deletes']} vs {sum(EXP_DEL.values())}")
    ok("the pipeline reads the same permit through its own careful reader", qp.read_permit(os.path.join(base, "data"), Q) == permit
       and qp.check_confirmation(qp.read_confirmation(os.path.join(base, "data"))) == "")
    reports0 = snapshot(base)

    print(" 3. Pretend Thursday 21 January 2027 (the 15th working day): too early")
    r1 = pipeline(base, pipe, D(2027, 1, 21), "2027-01-21 06:00:00")
    ok("the pipeline deletes nothing", r1.get("outcome") != "done" and counts(DB) == BEFORE, str(r1))
    print(f"      (its answer that day: {r1.get('quarter')}: {r1.get('why')})")
    # that day the latest quarter whose purge day has passed is 2026Q3 (cutoff 21 September), and the reports start on
    # 1 October: it says there is nothing to purge and names the quarter that is waiting, not a refusal for 2026Q3
    ok("...and says so honestly: nothing to purge for 2026Q3, 2026Q4 is purged on Friday 22 January 2027",
       (r1.get("quarter"), r1.get("outcome"), r1.get("next_quarter"), r1.get("next_purge_day")) == ("2026Q3", "nothing to purge", Q, "2027-01-22")
       and r1.get("why") == ("Nothing to purge now: no report rows are dated before Monday 21 September 2026, the cutoff of 2026Q3; "
                             "2026Q4 is purged on Friday 22 January 2027 if its report is VALID and the purge is on"), str(r1))
    ok("the permit on its own is refused that day too: before the purge day",
       qp.check_permit(qp.read_permit(os.path.join(base, "data"), Q), Q, qp.dates(2026, 4), D(2027, 1, 21))
       == "before the purge day (2027-01-22)")
    nothing_recorded("21 January", base, pipe, audit, api, ts("2027-01-21 06:05:00"))

    print(" 4. Pretend Friday 22 January 2027: the purge day")
    r2 = pipeline(base, pipe, D(2027, 1, 22), "2027-01-22 06:00:00")
    after = counts(DB)
    ok("the pipeline purges 2026Q4 with the cutoff 22 December", (r2.get("outcome"), r2.get("quarter"), r2.get("cutoff"),
                                                                  r2.get("purge_day")) == ("done", Q, CUT, "2027-01-22"), str(r2))
    ok(f"exactly the rows dated before 22 December are deleted: {sum(EXP_DEL.values())} in all",
       r2.get("rows_deleted") == sum(EXP_DEL.values())
       and {c: (r2.get("collections") or {}).get(c, {}).get("deleted") for c in REPORTS} == EXP_DEL, str(r2.get("collections")))
    ok("...the database agrees, collection by collection (kept = seeded - deleted)",
       all(after[c] == EXP_KEEP[c] for c in REPORTS), f"{after} vs keep {EXP_KEEP}")
    ok("...no report row before the cutoff is left", all(DB[c].count_documents({"filename": {"$lt": CUT}}) == 0 for c in REPORTS))
    left = Counter(r["filename"][:10] for c in REPORTS for r in DB[c].find({}, {"filename": 1}))
    ok("the rows from 22 December on are kept (the cutoff day itself: 2 blocklist + 2 scan_http rows)",
       DB["blocklist"].count_documents({"filename": {"$regex": "^2026-12-22"}}) == 2
       and DB["scan_http"].count_documents({"filename": {"$regex": "^2026-12-22"}}) == 2 and min(left) == CUT, str(min(left)))
    ok("January 2027's rows are all kept",
       sum(v for d_, v in left.items() if d_.startswith("2027-01")) == sum(1 for c in REPORTS for r in ROWS[c] if r["filename"].startswith("2027-01")))
    ok("a report collection without the filename index, files_* and lg_* are untouched",
       all(after[c] == n for c, n in OTHERS.items()) and "scan_ftp" in (r2.get("skipped") or {}), str(r2.get("skipped")))
    ok("the report's dry count equals what was deleted", r2.get("rows_deleted") == st["rows_purge_deletes"])
    ok("the pipeline's record: done for 2026Q4, purged before 22 December (files before it are not loaded again)",
       Q in (qp.read_status(pipe).get("done") or {}) and qp.purged_before(pipe) == CUT
       and qp.is_purged("2026-12-21-scan_http-ke.csv", qp.purged_before(pipe))
       and not qp.is_purged("2026-12-22-scan_http-ke.csv", qp.purged_before(pipe)))
    ok("findings, the case and its sub-findings, and the advisory are unchanged", snapshot(base, quarter_files=False) == kept0)
    ok("the quarterly reports themselves (CSVs, PDFs, summary) are unchanged", snapshot(base) == reports0)

    print(" 5. The platform records the purge once")
    api["tick"](now=ts("2027-01-22 06:10:00"))
    au = purge_audits(audit)
    n_del = sum(EXP_DEL.values())
    ok("one audit entry: quarterly_purge, 2026Q4, by looking-glass, the rows and the cutoff",
       len(au) == 1 and au[0]["target"] == Q and au[0]["user"] == qq.SYSTEM_USER
       and f"{n_del:,} rows deleted from {len(REPORTS)} report collections" in au[0]["detail"] and CUT in au[0]["detail"], str(au))
    res = json.load(open(os.path.join(qd, "purge_result.json")))
    ok("the purge's result is kept with its quarter (purge_result.json)", res.get("outcome") == "done" and res.get("rows_deleted") == n_del
       and res.get("cutoff") == CUT, str(res))
    bl = purged_bell(base, ts("2027-01-22 06:11:00"))
    ok("one bell alert for administrators: Quarterly purge done (2026Q4), with the count",
       len(bl) == 1 and bl[0]["title"] == f"Quarterly purge done ({Q})" and f"{n_del:,} raw report rows" in bl[0]["text"], str(bl))
    ok("the card says it was purged", qq.purge_fact(st, True, D(2027, 1, 22), True, res).startswith("Purged on"))
    r3 = pipeline(base, pipe, D(2027, 1, 22), "2027-01-22 18:00:00")
    ok("a second run the same day: already done, nothing deleted", r3.get("outcome") == "already done" and counts(DB) == after, str(r3))
    api["tick"](now=ts("2027-01-22 18:10:00"))
    api["tick"](now=ts("2027-01-22 18:20:00"))
    bl2 = purged_bell(base, ts("2027-01-22 18:21:00"))
    ok("...and nothing new is recorded: still one audit entry, still the one bell alert",
       len(purge_audits(audit)) == 1 and len(bl2) == 1 and bl2[0]["id"] == bl[0]["id"], f"{len(purge_audits(audit))} / {bl2}")
    r4 = pipeline(base, pipe, D(2027, 1, 25), "2027-01-25 06:00:00")
    ok("the next working day too: already done, nothing deleted", r4.get("outcome") == "already done" and counts(DB) == after)

    # ============================================================== cycle B: the purge off
    print("\nCycle B: the purge off (the default)")
    roots.append(tempfile.mkdtemp(prefix="lgpe_b_"))
    base, pipe, audit, api = setup(roots[-1])
    seed(DB)
    ok("seeded again", counts(DB) == BEFORE)
    st = qq.build(DB, base, Q, "made automatically after the quarter ended", today=D(2027, 1, 3), now=ts("2027-01-03 00:20:00"))
    qd = qq.quarter_dir(base, Q)
    ok("3 January: VALID, but no permit, because the purge is off", st["valid"] and not st["permit"]
       and st["no_permit_why"] == qq.WHY_OFF and not os.path.exists(os.path.join(qd, "purge_permit.json")), str(st.get("no_permit_why")))
    qq.set_purge(base, True, "ada.admin", "Ada Admin", {"quarter": Q}, now=ts("2027-01-05 09:00:00"))
    on_permit = os.path.isfile(os.path.join(qd, "purge_permit.json"))
    qq.set_purge(base, False, "ada.admin", "Ada Admin", {"quarter": Q}, now=ts("2027-01-10 09:00:00"))
    ok("turned on (5 January) the permit appears; turned off again (10 January) it is removed",
       on_permit and not os.path.exists(os.path.join(qd, "purge_permit.json")) and not qq.purge_on(base))
    for day, at in ((D(2027, 1, 21), "2027-01-21 06:00:00"), (D(2027, 1, 22), "2027-01-22 06:00:00")):
        r = pipeline(base, pipe, day, at)
        ok(f"{day:%d %B}: refused, nothing deleted", r.get("outcome") == "refused" and counts(DB) == BEFORE, str(r))
    qq._write_json(os.path.join(qd, "purge_permit.json"), qq.permit_doc(st))
    r = pipeline(base, pipe, D(2027, 1, 22), "2027-01-22 07:00:00")
    ok("a permit forged while the switch is off: refused (the purge is not turned on), nothing deleted",
       (r.get("outcome"), r.get("quarter"), r.get("why")) == ("refused", Q, qp.NOT_ON) and counts(DB) == BEFORE, str(r))
    r = pipeline(base, pipe, D(2027, 1, 25), "2027-01-25 06:00:00")
    ok("the next working day: still refused, nothing deleted", r.get("outcome") == "refused" and counts(DB) == BEFORE, str(r))
    nothing_recorded("purge off", base, pipe, audit, api, ts("2027-01-25 06:10:00"))
    ok("...and the platform's background check removed the forged permit (the purge is off)",
       not os.path.exists(os.path.join(qd, "purge_permit.json")))

    # ============================================================== cycle C: a NOT VALID report
    print("\nCycle C: the purge on, the report NOT VALID")
    roots.append(tempfile.mkdtemp(prefix="lgpe_c_"))
    base, pipe, audit, api = setup(roots[-1])
    seed(DB)
    qq.set_purge(base, True, "ada.admin", "Ada Admin", {"quarter": ""}, now=ts("2027-01-02 09:00:00"))
    real_status = qq.status_line
    qq.status_line = lambda G_, R_: ("NOT VALID", "made NOT VALID by the check")
    try:
        st = qq.build(DB, base, Q, "made automatically after the quarter ended", today=D(2027, 1, 3), now=ts("2027-01-03 00:20:00"))
    finally:
        qq.status_line = real_status
    qd = qq.quarter_dir(base, Q)
    ok("3 January: NOT VALID, no permit (the report is NOT VALID)", not st["valid"] and not st["permit"]
       and st["no_permit_why"] == qq.WHY_INVALID and not os.path.exists(os.path.join(qd, "purge_permit.json")))
    r = pipeline(base, pipe, D(2027, 1, 22), "2027-01-22 06:00:00")
    ok("22 January: refused (no purge permit), nothing deleted",
       r.get("outcome") == "refused" and r.get("quarter") == Q and str(r.get("why")).startswith("no purge permit")
       and counts(DB) == BEFORE, str(r))
    ok("...the refusal names the quarter waiting next and its purge day",
       "Next: 2027Q1 is purged on Thursday 22 April 2027 if its report is VALID and the purge is on" in str(r.get("why")), str(r.get("why")))
    nothing_recorded("NOT VALID", base, pipe, audit, api, ts("2027-01-22 06:10:00"))
finally:
    client.drop_database(DBN)
    ok("the throwaway database is dropped", DBN not in client.list_database_names())
    for r_ in roots:
        shutil.rmtree(r_, ignore_errors=True)
    if keep_pipe_env is None:
        os.environ.pop("PIPELINE_DIR", None)
    else:
        os.environ["PIPELINE_DIR"] = keep_pipe_env

done()
