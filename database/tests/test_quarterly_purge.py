#!/usr/bin/env python3
"""The quarterly purge (quarterly_purge.py): its dates, the permit's checks, and a purge of made-up rows in a throwaway
database that is dropped afterwards (the real database is never touched). Only documentation addresses.

  * the working-day calendar for every quarter of 2026 to 2029 (and the platform's quarterly.py agrees, when it is
    beside this pipeline);
  * it deletes exactly the rows dated before the cutoff, from report collections only (never files_*,
    discovered_fields_*, lg_* or a collection without the filename index);
  * it refuses unless the platform's purge_confirmed.json says the purge is turned on (missing, "enabled": false,
    malformed, a symbolic link), logging that once per quarter;
  * it refuses without a permit, with a NOT VALID permit, before the purge day, with a cutoff inside 31 days, with
    dates that are not the rule's, and when run a second time;
  * it writes its result (per collection), and files before the cutoff are not loaded again.
Run: .venv/bin/python tests/test_quarterly_purge.py"""
import datetime as dt
import importlib.util
import json
import logging
import os
import shutil
import sys
import tempfile
import uuid

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
import quarterly_purge as qp  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


log = logging.getLogger("t")
log.addHandler(logging.NullHandler())
D = dt.date

print("The calendar: 15 working days (Mon-Fri) after the quarter, the purge on the next one, the last 31 days kept")
by_hand = {(2026, 4): ("2027-01-21", "2027-01-22", "2026-12-22"), (2026, 1): ("2026-04-21", "2026-04-22", "2026-03-22"),
           (2028, 3): ("2028-10-20", "2028-10-23", "2028-09-22"),        # the quarter ends on a Saturday
           (2029, 3): ("2029-10-19", "2029-10-22", "2029-09-21")}        # ... on a Sunday
for (y, q), want in by_hand.items():
    d = qp.dates(y, q)
    ok(f"{y}Q{q}: 15th working day {want[0]}, purge {want[1]}, cutoff {want[2]} (worked out by hand)",
       (d["working_day_15"].isoformat(), d["purge_day"].isoformat(), d["cutoff"].isoformat()) == want, str(d))
bad = []
for y in range(2026, 2030):
    for q in range(1, 5):
        d = qp.dates(y, q)
        last = d["last_day"]
        weekdays = [last + dt.timedelta(days=i) for i in range(1, 40) if (last + dt.timedelta(days=i)).weekday() < 5]
        if not (d["working_day_15"] == weekdays[14] and d["purge_day"] == weekdays[15] and d["purge_day"].weekday() < 5
                and (d["purge_day"] - d["cutoff"]).days == 31 and (last + dt.timedelta(days=1)).day == 1):
            bad.append(f"{y}Q{q}")
ok("every quarter of 2026 to 2029: the 15th and 16th weekday after its last day, counted independently", not bad, ", ".join(bad))
plat = next((p for p in (os.path.join(os.path.dirname(HERE), n, "quarterly.py") for n in ("platform", "threatmap")) if os.path.exists(p)), None)
if plat:
    spec = importlib.util.spec_from_file_location("lg_platform_quarterly", plat)
    try:
        sys.path.insert(0, os.path.dirname(plat))
        pq = importlib.util.module_from_spec(spec); spec.loader.exec_module(pq)
        diff = [f"{y}Q{q}" for y in range(2026, 2030) for q in range(1, 5)
                if {k: v for k, v in pq.purge_dates(y, q).items() if k in qp.dates(y, q)} != qp.dates(y, q)]
        ok("the platform's quarterly.py works out the same dates for every quarter of 2026 to 2029", not diff, ", ".join(diff))
        ok("...and selects the same rows (the same filter)", pq.purge_filter("2026-12-22") == qp.purge_filter("2026-12-22"))
    except Exception as exc:  # noqa: BLE001  (the platform's own libraries are not in this venv: its own test checks it)
        print(f"  (the platform's quarterly.py could not be loaded here: {exc.__class__.__name__}; its own check compares)")
ok("the quarter due on its purge day is that quarter; the day before, the one before",
   qp.due_quarter(D(2027, 1, 22)) == (2026, 4) and qp.due_quarter(D(2027, 1, 21)) == (2026, 3))
ok("the quarter waiting after the due one, in words: 21 January 2027 (2026Q3 due) names 2026Q4 and Friday 22 January 2027",
   qp.next_purge_text(qp.due_quarter(D(2027, 1, 21))) == "2026Q4 is purged on Friday 22 January 2027 if its report is VALID and the purge is on"
   and qp.next_quarter(2026, 4) == (2027, 1), qp.next_purge_text((2026, 3)))
ok("no database here: whether rows wait before a cutoff is not known (the plain refusal is worded)", qp.has_rows_before(None, "2026-09-21") is None)

print("\nThe permit's checks (no database)")
d4 = qp.dates(2026, 4)
good = {"quarter": "2026Q4", "valid": True, "status": "VALID", "purge_day": "2027-01-22", "cutoff": "2026-12-22",
        "generated_at": "2027-01-01T00:10:00+00:00"}
ok("a VALID permit with the rule's dates, on the purge day: allowed", qp.check_permit(good, "2026Q4", d4, D(2027, 1, 22)) == "")
ok("no permit: refused", "no purge permit" in qp.check_permit(None, "2026Q4", d4, D(2027, 1, 22)))
ok("a NOT VALID permit: refused", "VALID" in qp.check_permit(dict(good, valid=False, status="NOT VALID"), "2026Q4", d4, D(2027, 1, 22)))
ok("a permit for another quarter: refused", "another quarter" in qp.check_permit(dict(good, quarter="2026Q3"), "2026Q4", d4, D(2027, 1, 22)))
ok("before the purge day: refused", "before the purge day" in qp.check_permit(good, "2026Q4", d4, D(2027, 1, 21)))
ok("a cutoff that is not the rule's (an earlier purge, more deleted): refused",
   "not the rule" in qp.check_permit(dict(good, cutoff="2027-01-10"), "2026Q4", d4, D(2027, 1, 22)))
near = dict(d4, cutoff=D(2027, 1, 1))
ok("a cutoff within 31 days of today: refused", "within 31 days" in qp.check_permit(dict(good, cutoff="2027-01-01"), "2026Q4", near, D(2027, 1, 22)))
ok("a report made after its purge day: refused",
   "not made before" in qp.check_permit(dict(good, generated_at="2027-02-01T00:00:00+00:00"), "2026Q4", d4, D(2027, 2, 2)))
ok("a file dated before the cutoff counts as purged (not loaded again); one on the cutoff, or undated, does not",
   qp.is_purged("2026-12-21-scan_http-ke.csv", "2026-12-22") and not qp.is_purged("2026-12-22-scan_http-ke.csv", "2026-12-22")
   and not qp.is_purged("scan_http.csv", "2026-12-22") and not qp.is_purged("2026-01-01-x.csv", ""))

print("\nThe purge's switch (Settings → Quarterly): off unless the platform's purge_confirmed.json says enabled (no database)")
ok("enabled: true is on; false, a string, a list, nothing: off",
   qp.check_confirmation({"enabled": True}) == "" and all(qp.check_confirmation(x) == qp.NOT_ON for x in
                                                         ({"enabled": False}, {"enabled": "true"}, {"enabled": 1}, [], None, {})))
sw = tempfile.mkdtemp(prefix="lg-purge-switch-")
sw_data = os.path.join(sw, "platform", "data")
sw_base = os.path.join(sw, "pipeline")
os.makedirs(os.path.join(sw_data, "quarterly", "2026Q4")); os.makedirs(sw_base)
with open(os.path.join(sw_data, "quarterly", "2026Q4", "purge_permit.json"), "w", encoding="utf-8") as fh:
    json.dump(good, fh)


class Count(logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


slog = logging.getLogger("t-switch")
slog.setLevel(logging.INFO)
slog.propagate = False
counted = Count()
slog.addHandler(counted)


def confirm(text):
    p = os.path.join(sw_data, "quarterly", qp.CONFIRM_FILE)
    if text is None:
        if os.path.lexists(p):
            os.remove(p)
        return
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)


try:
    # db=None: a refusal never reaches the database (a purge that got that far would fail on None)
    for label, text in (("without purge_confirmed.json", None), ("with \"enabled\": false", '{"enabled": false}'),
                        ("with a malformed file", '{"enabled": tru'), ("with \"enabled\": \"true\" (a string)", '{"enabled": "true"}'),
                        ("with a list instead of an object", '[{"enabled": true}]')):
        confirm(text)
        r = qp.run(None, sw_data, sw_base, slog, today=D(2027, 1, 22))
        ok(f"a VALID permit on its purge day, but {label}: refused, the purge is not turned on",
           r.get("outcome") == "refused" and r.get("why") == qp.NOT_ON, str(r))
    target = os.path.join(sw, "elsewhere.json")
    with open(target, "w", encoding="utf-8") as fh:
        fh.write('{"enabled": true}')
    confirm(None)
    os.symlink(target, os.path.join(sw_data, "quarterly", qp.CONFIRM_FILE))
    r = qp.run(None, sw_data, sw_base, slog, today=D(2027, 1, 22))
    ok("a confirmation reached through a symbolic link is not read: refused", r.get("outcome") == "refused" and r["why"] == qp.NOT_ON, str(r))
    os.remove(os.path.join(sw_data, "quarterly", qp.CONFIRM_FILE))
    os.remove(os.path.join(sw_base, qp.STATUS_FILE))          # a fresh pipeline: nothing recorded yet
    counted.lines.clear()
    for _ in range(3):
        qp.run(None, sw_data, sw_base, slog, today=D(2027, 1, 22))
    ok("the refusal is logged once per quarter, not at every run", len([x for x in counted.lines if qp.NOT_ON in x]) == 1, str(counted.lines))
    ok("...and recorded in the pipeline's own status (the platform shows it)",
       qp.read_status(sw_base).get("last", {}).get("why") == qp.NOT_ON)
    confirm('{"enabled": true, "by": "ada.admin", "at": "2027-01-05T09:00:00+00:00"}')
    ok("turned on: the confirmation is read", qp.check_confirmation(qp.read_confirmation(sw_data)) == "")
    os.remove(os.path.join(sw_data, "quarterly", "2026Q4", "purge_permit.json"))
    r = qp.run(None, sw_data, sw_base, slog, today=D(2027, 1, 22))
    ok("turned on but no permit (turning it off removed it, or the report was NOT VALID): still refused",
       r.get("outcome") == "refused" and "no purge permit" in r["why"], str(r))
    ok("...the refusal names the quarter waiting next and its purge day (2027Q1, Thursday 22 April 2027)",
       "Next: 2027Q1 is purged on Thursday 22 April 2027" in r["why"] and r.get("next_quarter") == "2027Q1"
       and r.get("next_purge_day") == "2027-04-22", str(r))
finally:
    shutil.rmtree(sw, ignore_errors=True)

# ------------------------------------------------------------------ the database part
try:
    import test_report_names as trn
    s0, client = trn.throwaway_db()
except Exception:  # noqa: BLE001
    client = None
if not client:
    print("\nSKIPPED the database part: MongoDB not reachable, or no account here may create a throwaway database "
          "(run the platform's tests/run_admin_db_tests.sh, or set LG_MONGO_ADMIN_FILE)")
    print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
    sys.exit(1 if fails else 0)

DBN = f"lg_test_purge_{uuid.uuid4().hex[:8]}"
tmp = tempfile.mkdtemp(prefix="lg-purge-")
plat_data = os.path.join(tmp, "platform", "data")
base = os.path.join(tmp, "pipeline")
os.makedirs(plat_data); os.makedirs(base)
ROW_INDEX = [("filename", 1), ("category", 1), ("line_hash", 1)]
DAYS = ["2026-07-15", "2026-09-30", "2026-10-01", "2026-12-21", "2026-12-22", "2026-12-31", "2027-01-15"]
try:
    db = client[DBN]
    want = {}
    for coll in ("scan_http", "event4_sinkhole_http"):
        docs = [{"ip": f"192.0.2.{i}", "filename": f"{d}-{coll}-ke.csv", "category": coll, "line_hash": f"{d}{i}"}
                for d in DAYS for i in range(3)]
        db[coll].insert_many(docs)
        db[coll].create_index(ROW_INDEX, unique=True)
        want[coll] = sum(1 for x in docs if x["filename"][:10] < "2026-12-22")
    db["scan_http"].insert_one({"ip": "192.0.2.99", "filename": "undated-scan_http.csv", "category": "scan_http", "line_hash": "u"})
    # not report collections, or no filename index: never touched, whatever their rows' dates
    db["files_scan_http"].insert_many([{"filename": f"{d}-scan_http-ke.csv"} for d in DAYS])
    db["discovered_fields_scan_http"].insert_many([{"filename": f"{d}-x.csv", "field_name": "ip"} for d in DAYS])
    db["lg_notes"].insert_many([{"filename": f"{d}-x.csv"} for d in DAYS])
    db["scan_noindex"].insert_many([{"filename": f"{d}-scan_noindex-ke.csv"} for d in DAYS])
    totals = {n: db[n].count_documents({}) for n in db.list_collection_names()}

    def permit(**kw):
        os.makedirs(os.path.join(plat_data, "quarterly", "2026Q4"), exist_ok=True)
        with open(os.path.join(plat_data, "quarterly", "2026Q4", "purge_permit.json"), "w", encoding="utf-8") as fh:
            json.dump(dict(good, **kw), fh)

    def unchanged():
        return all(db[n].count_documents({}) == k for n, k in totals.items())

    def switch(text):
        os.makedirs(os.path.join(plat_data, "quarterly"), exist_ok=True)
        p = os.path.join(plat_data, "quarterly", qp.CONFIRM_FILE)
        if text is None:
            if os.path.lexists(p):
                os.remove(p)
            return
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(text)

    print("\nRefusals: nothing is deleted")
    permit()
    for label, text in (("without purge_confirmed.json", None), ("with \"enabled\": false", '{"enabled": false}'),
                        ("with a malformed purge_confirmed.json", "{not json")):
        switch(text)
        r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
        ok(f"a VALID permit, {label}: refused, nothing deleted", r.get("outcome") == "refused" and r["why"] == qp.NOT_ON
           and unchanged(), str(r))
    os.remove(os.path.join(plat_data, "quarterly", "2026Q4", "purge_permit.json"))
    switch('{"enabled": true, "by": "ada.admin"}')
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
    ok("without a permit: refused, nothing deleted", r.get("outcome") == "refused" and "no purge permit" in r["why"] and unchanged(), str(r))
    ok("...rows wait before its cutoff, so it is a refusal that names the next quarter", r["why"].startswith(qp.NO_PERMIT)
       and "Next: 2027Q1 is purged on Thursday 22 April 2027" in r["why"], r["why"])
    # 23 July 2026: the latest quarter whose purge day has passed is 2026Q2 (cutoff 21 June 2026), and the made-up rows
    # start on 15 July: nothing was ever there to purge for it; the quarter waiting is 2026Q3 (purge Thursday 22 October)
    r = qp.run(db, plat_data, base, log, today=D(2026, 7, 23))
    ok("no report row before the due quarter's cutoff: 'nothing to purge', naming the next quarter and its purge day, nothing deleted",
       r.get("outcome") == "nothing to purge" and r.get("quarter") == "2026Q2" and unchanged()
       and r.get("why") == ("Nothing to purge now: no report rows are dated before Sunday 21 June 2026, the cutoff of 2026Q2; "
                            "2026Q3 is purged on Thursday 22 October 2026 if its report is VALID and the purge is on"), str(r))
    ok("...and the database part says so: no rows before 21 June, rows before 22 December",
       qp.has_rows_before(db, "2026-06-21") is False and qp.has_rows_before(db, "2026-12-22") is True)
    permit(valid=False, status="NOT VALID")
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
    ok("with a NOT VALID permit: refused, nothing deleted", r.get("outcome") == "refused" and unchanged(), str(r))
    permit(cutoff="2027-01-10")
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
    ok("with a permit whose cutoff is inside the last 31 days (not the rule's): refused, nothing deleted",
       r.get("outcome") == "refused" and unchanged(), str(r))
    permit()
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 21))
    ok("the day before the purge day: nothing due for 2026Q4, nothing deleted",
       r.get("quarter") != "2026Q4" and unchanged(), str(r))
    os.symlink(os.path.join(plat_data, "quarterly", "2026Q4"), os.path.join(plat_data, "quarterly", "2026Q9"))
    link = os.path.join(tmp, "elsewhere"); os.makedirs(link)
    shutil.move(os.path.join(plat_data, "quarterly", "2026Q4"), os.path.join(link, "2026Q4"))
    os.symlink(os.path.join(link, "2026Q4"), os.path.join(plat_data, "quarterly", "2026Q4"))
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
    ok("a permit reached through a symbolic link is not read: refused", r.get("outcome") == "refused" and unchanged(), str(r))
    os.remove(os.path.join(plat_data, "quarterly", "2026Q4")); os.remove(os.path.join(plat_data, "quarterly", "2026Q9"))
    shutil.move(os.path.join(link, "2026Q4"), os.path.join(plat_data, "quarterly", "2026Q4"))

    print("\nThe purge on its day, with a VALID permit")
    r = qp.run(db, plat_data, base, log, today=D(2027, 1, 22))
    ok("done", r.get("outcome") == "done", str(r))
    ok("exactly the rows dated before the cutoff (2026-12-22) are deleted from each report collection",
       all(r["collections"][c]["deleted"] == want[c] for c in want)
       and all(db[c].count_documents({"filename": {"$lt": "2026-12-22", "$gte": "0"}}) == 0 for c in want), str(r.get("collections")))
    ok("the rows from the cutoff on are kept (the last 31 days), and an undated row too",
       all(db[c].count_documents({}) == totals[c] - want[c] for c in want)
       and db["scan_http"].count_documents({"filename": "undated-scan_http.csv"}) == 1)
    ok("files_*, discovered_fields_*, lg_* and a collection without the filename index are untouched",
       all(db[n].count_documents({}) == totals[n] for n in ("files_scan_http", "discovered_fields_scan_http", "lg_notes", "scan_noindex")))
    ok("...and the one without the index is said so", "scan_noindex" in r.get("skipped", {}), str(r.get("skipped")))
    st = qp.read_status(base)
    ok("the result is written: per collection, the rows deleted, the dates",
       st.get("done", {}).get("2026Q4", {}).get("rows_deleted") == sum(want.values()) and st.get("purged_before") == "2026-12-22"
       and st["last"]["collections"]["scan_http"]["deleted"] == want["scan_http"] and st["last"]["cutoff"] == "2026-12-22")
    ok("its status file is the pipeline's own, owner-only", oct(os.stat(os.path.join(base, qp.STATUS_FILE)).st_mode & 0o777) == "0o600")
    ok("files dated before the cutoff are not loaded again (purged_before)", qp.purged_before(base) == "2026-12-22")
    db["scan_http"].insert_one({"filename": "2026-11-01-scan_http-ke.csv", "category": "scan_http", "line_hash": "late"})
    r2 = qp.run(db, plat_data, base, log, today=D(2027, 1, 23))
    ok("a second run for the same quarter: refused as already done, nothing deleted",
       r2.get("outcome") == "already done" and db["scan_http"].count_documents({"line_hash": "late"}) == 1, str(r2))
    r3 = qp.run_safely(lambda: (_ for _ in ()).throw(RuntimeError("no database")), plat_data, base, log, today=D(2027, 1, 23))
    ok("a check that cannot run never raises (the pipeline's run goes on) and says so",
       r3 == {} and qp.read_status(base)["last"]["outcome"] == "failed" and qp.read_status(base)["done"].get("2026Q4"))
finally:
    client.drop_database(DBN)
    ok("the throwaway database is dropped", DBN not in client.list_database_names())
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
