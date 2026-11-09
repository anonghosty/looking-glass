#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""End-to-end test of report arrivals and new collections on BOTH platforms and the intro page, against a running
copy of the app. The real service, its data files and the real database are never written: the real database is
only read (to copy the replay day's rows).

  setup     copy the project to ~/lg_e2e_app (own data/ files), copy the replay day's rows into a throwaway
            database (lg_e2e), start the copy on port 5055 and wait until both platforms have loaded
  check     simulate Shadowserver: late rows, new collections (compatible and not), a constituency change, dropped
            collections; after each step check what the platforms and the intro page report (as the browser sees it)
  teardown  stop the copy, drop lg_e2e and delete ~/lg_e2e_app

Usage: .venv/bin/python tests/e2e_test.py setup|check|teardown|all      (all = setup, check, teardown)
"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timedelta

from dotenv import dotenv_values
from pymongo import MongoClient

SRC = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COPY = os.path.expanduser("~/lg_e2e_app")
DBNAME = "lg_e2e"
PORT = 5055
BASE = f"http://127.0.0.1:{PORT}"
ENV = dotenv_values(os.path.join(SRC, ".env"))
client = MongoClient(host=ENV.get("MONGO_HOST", "localhost"), port=int(ENV.get("MONGO_PORT") or 27017),
                     username=ENV.get("MONGO_USER") or None, password=ENV.get("MONGO_PASSWORD") or None,
                     authSource=ENV.get("MONGO_AUTH_SOURCE") or "admin", serverSelectionTimeoutMS=8000)
real = client[ENV.get("MONGO_DB") or "shadowserver"]
test = client[DBNAME]
fails = 0


def ok(label, cond, info=""):
    global fails
    fails += not cond
    print(("  ok  " if cond else "  FAIL") + " " + label + (f"  [{info}]" if info else ""), flush=True)
    return cond


def get(path, method="GET", body=None, headers=None):
    req = urllib.request.Request(BASE + path, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def wait_for(fn, timeout=90, step=2):
    """Poll until fn() is truthy (returns its value) or time out (returns the last value)."""
    end, v = time.time() + timeout, None
    while time.time() < end:
        try:
            v = fn()
            if v:
                return v
        except Exception as e:  # server busy reloading
            v = None
        time.sleep(step)
    return v


# ------------------------------------------------------------------ setup
def replay_day():
    with urllib.request.urlopen("http://127.0.0.1:5000/api/clock", timeout=30) as r:
        return json.load(r)["replay_day"]


def setup():
    day = replay_day()
    nxt = (datetime.fromisoformat(day) + timedelta(days=1)).date().isoformat()
    print(f"setup: replay day {day} (rows with filenames {day}* and {nxt}*, as the app loads them)")
    # 1. project copy (own data files: schedule, settings, caches), using the real virtualenv
    if os.path.exists(COPY):
        shutil.rmtree(COPY)
    shutil.copytree(SRC, COPY, ignore=shutil.ignore_patterns(".venv", "__pycache__", "*.log", "backups"))
    # 2. throwaway database with the day's rows of every collection (one older row where a report has none that day,
    #    so it is still monitored, as in the real database)
    client.drop_database(DBNAME)
    rx = {"$regex": f"^({re.escape(day)}|{re.escape(nxt)})"}
    total = 0
    for name in sorted(real.list_collection_names()):
        c = real[name]
        docs = list(c.find({"filename": rx}, {"_id": 0}))
        if not docs:
            one = c.find_one(sort=[("_id", -1)], projection={"_id": 0})
            docs = [one] if one else []
        if docs:
            test[name].insert_many(docs)
            total += len(docs)
        # the same filename indexes as the real collection (whatever they are called)
        for ix in c.index_information().values():
            if ix["key"] and ix["key"][0][0] == "filename":
                test[name].create_index(ix["key"])
    print(f"setup: {total} rows in {len(test.list_collection_names())} collections copied to {DBNAME}")
    # 3. start the copy (its own data/schedule.json continues the same replay day)
    env = dict(os.environ, MONGO_DB=DBNAME, PORT=str(PORT))
    log = open(os.path.join(COPY, "e2e_server.log"), "w")
    p = subprocess.Popen([os.path.join(SRC, ".venv", "bin", "python"), os.path.join(COPY, "app.py")], cwd=COPY, env=env,
                         stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    open(os.path.join(COPY, "e2e_server.pid"), "w").write(str(p.pid))
    print(f"setup: copy started on port {PORT} (pid {p.pid}); waiting for both platforms to load")
    c1 = wait_for(lambda: get("/api/clock")["day_total"] > 0 and get("/api/clock"), 240, 3)
    c2 = wait_for(lambda: get("/api/svc/clock")["day_total"] > 0 and get("/api/svc/clock"), 240, 3)
    with urllib.request.urlopen("http://127.0.0.1:5000/api/clock", timeout=30) as r:
        rc1 = json.load(r)
    with urllib.request.urlopen("http://127.0.0.1:5000/api/svc/clock", timeout=30) as r:
        rc2 = json.load(r)
    ok("copy loaded the same communications day as the real service", c1 and c1["day_total"] == rc1["day_total"] and c1["sources"] == rc1["sources"],
       f"copy {c1 and c1['day_total']}/{c1 and c1['sources']} reports, real {rc1['day_total']}/{rc1['sources']}")
    ok("copy loaded the same services day as the real service", c2 and c2["day_total"] == rc2["day_total"] and c2["sources"] == rc2["sources"],
       f"copy {c2 and c2['day_total']}/{c2 and c2['sources']} reports, real {rc2['day_total']}/{rc2['sources']}")


# ------------------------------------------------------------------ check
def day_rows(name, n, day):
    """n rows of a collection for the replay day (copied from the day's own rows, or an older row moved to the day)."""
    docs = list(test[name].find({"filename": {"$regex": "^" + re.escape(day)}}, {"_id": 0}).limit(n))
    if not docs:
        docs = list(real[name].find({}, {"_id": 0}).sort([("_id", -1)]).limit(n))
        for d in docs:
            ed = d.get("extracted_date")
            noon = datetime.fromisoformat(day + "T12:00:00+00:00")
            d["extracted_date"] = noon if not isinstance(ed, str) else noon.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
    for i, d in enumerate(docs):
        d["filename"] = f"{day}-e2e-{name}-{i}.csv"
    return docs


def insert(name, docs, index=True):
    test[name].insert_many([dict(d) for d in docs])
    if index:
        test[name].create_index("filename")


def report(clock, source):
    return next((r for r in clock["reports"] if r["source"] == source), None)


def check():
    c0, s0, o0 = get("/api/clock"), get("/api/svc/clock"), get("/api/overview")
    f0 = get("/api/svc/facets")
    day = c0["replay_day"]
    print(f"check: replay day {day}; communications {c0['day_total']} events / {c0['sources']} reports; "
          f"services {s0['day_total']} records / {s0['sources']} reports")

    print("\n1. Late rows for a communications report that is already in (Sinkhole HTTP +5)")
    insert("event4_sinkhole_http", day_rows("event4_sinkhole_http", 5, day))
    c = wait_for(lambda: (lambda x: x["day_total"] == c0["day_total"] + 5 and x)(get("/api/clock")), 60)
    ok("map platform: day total +5 within ~15 s", bool(c), f"{c0['day_total']} -> {get('/api/clock')['day_total']}")
    ok("map platform: data version changed (open pages refresh)", c and c["data_version"] != c0["data_version"])
    ok("map platform: the arrival is announced (report_changes)", c and any(r.get("source") == "event4_sinkhole_http" for r in c["report_changes"]),
       c and json.dumps(c["report_changes"])[:200])
    ok("intro page: total +5", get("/api/overview")["total"] == o0["total"] + 5)
    ok("services platform: not affected", get("/api/svc/clock")["day_total"] == s0["day_total"])

    print("\n2. A communications report with no rows yet that day gets its first rows (first report of the day)")
    # the clock lists reports with rows; the intro page lists every monitored report
    empty = [r.get("name") or r.get("source") for r in o0["reports"] if not r.get("rows") and not r.get("events")]
    late_src = empty[0] if empty else None
    if ok("there is a report without rows to use", late_src is not None, str(empty)):
        before = get("/api/clock")
        insert(late_src, day_rows(late_src, 4, day))
        c = wait_for(lambda: (lambda x: (report(x, late_src) or {}).get("rows") and x)(get("/api/clock")), 60)
        ok(f"map platform: {late_src} now has rows", bool(c), c and str(report(c, late_src)))
        ok("map platform: announced as new report data", c and any(r.get("source") == late_src for r in c["report_changes"]))
        o = get("/api/overview")
        ok("intro page: reports with data +1", o["reports_active"] == o0["reports_active"] + 1, f"{o0['reports_active']} -> {o['reports_active']}")
        c1 = get("/api/clock")
        ok("map platform: total grew by what the report adds", c1["day_total"] > before["day_total"], f"{before['day_total']} -> {c1['day_total']}")

    print("\n3. Late rows for a services report that is already in (scan_http +5)")
    s_before = get("/api/svc/clock")
    insert("scan_http", day_rows("scan_http", 5, day))
    s = wait_for(lambda: (lambda x: x["day_total"] == s_before["day_total"] + 5 and x)(get("/api/svc/clock")), 60)
    ok("services platform: day total +5", bool(s), f"{s_before['day_total']} -> {get('/api/svc/clock')['day_total']}")
    ok("services platform: data version changed", s and s["data_version"] != s_before["data_version"])
    ok("services platform: arrival announced", s and any(r.get("source") == "scan_http" for r in s["report_changes"]), s and json.dumps(s["report_changes"])[:200])
    f = get("/api/svc/facets")
    ok("services facets (filters, intro card) follow", f != f0)

    print("\n4. A services report with no rows that day gets its first rows")
    empty_s = [r.get("name") or r.get("source") for r in get("/api/svc/facets")["reports"] if not r.get("rows")]
    if ok("there is a services report without rows to use", bool(empty_s), str(empty_s[:5])):
        src = empty_s[0]
        insert(src, day_rows(src, 3, day))
        s = wait_for(lambda: (lambda x: (report(x, src) or {}).get("rows") and x)(get("/api/svc/clock")), 60)
        ok(f"services platform: {src} now has rows and is announced", s and any(r.get("source") == src for r in s["report_changes"]), s and str(report(s, src)))

    print("\n5. New communications collection, compatible (event4_e2e_new_report)")
    c_before = get("/api/clock")
    insert("event4_e2e_new_report", day_rows("event4_sinkhole_http", 6, day))
    c = wait_for(lambda: (lambda x: x["sources"] == c_before["sources"] + 1 and x)(get("/api/clock")), 60)
    ok("map platform: report count +1 within ~15 s", bool(c), f"{c_before['sources']} -> {get('/api/clock')['sources']}")
    ns = c and next((n for n in c["new_sources"] if n.get("name") == "event4_e2e_new_report"), None)
    ok("announced as new and compatible", ns and ns.get("compatible") is True, str(ns))
    c = wait_for(lambda: (lambda x: report(x, "event4_e2e_new_report") and report(x, "event4_e2e_new_report")["rows"] == 6 and x)(get("/api/clock")), 60)
    ok("its 6 rows are loaded onto the map", bool(c))
    o = get("/api/overview")
    ok("intro page: monitored reports +1", o["reports_total"] == o0["reports_total"] + 1, f"{o0['reports_total']} -> {o['reports_total']}")
    ok("intro page: listed among the reports", any(r.get("name") == "event4_e2e_new_report" or r.get("source") == "event4_e2e_new_report" for r in o["reports"]))
    ok("services platform: does not pick it up", get("/api/svc/clock")["sources"] == s0["sources"] + 0)

    print("\n6. New communications collection that lacks fields (no source country, no event time)")
    rows = [{k: v for k, v in d.items() if k not in ("src_geo", "extracted_date")} for d in day_rows("event4_sinkhole_http", 3, day)]
    insert("event4_e2e_partial", rows)
    c = wait_for(lambda: (lambda x: x["unsupported"] >= 1 and x)(get("/api/clock")), 60)
    ok("map platform: counted as unsupported", bool(c))
    ns = c and next((n for n in c["new_sources"] if n.get("name") == "event4_e2e_partial"), None)
    ok("announced as not compatible, with what is missing", ns and ns.get("compatible") is False, str(ns)[:200])
    o = get("/api/overview")
    un = next((u for u in o["unsupported"] if u["name"] == "event4_e2e_partial"), None)
    ok("intro page: listed as not supported yet, with missing fields", un and un["missing"], str(un)[:200])
    ok("not loaded onto the map", not report(get("/api/clock"), "event4_e2e_partial"))

    print("\n7. New services collection, compatible (a Shadowserver report type not in the database yet)")
    defs = json.load(open(os.path.join(SRC, "data", "service_reports.json"), encoding="utf-8"))
    known = set(real.list_collection_names())
    cand = [k for k in defs if not k.startswith("_") and k.startswith("scan_") and k not in known]
    new_s = cand[0] if cand else "scan_e2e_new_service"
    s_before = get("/api/svc/clock")
    insert(new_s, day_rows("scan_http", 6, day))
    s = wait_for(lambda: (lambda x: x["sources"] == s_before["sources"] + 1 and x)(get("/api/svc/clock")), 60)
    ok(f"services platform: report count +1 ({new_s})", bool(s), f"{s_before['sources']} -> {get('/api/svc/clock')['sources']}")
    ns = s and next((n for n in s["new_sources"] if n.get("name") == new_s), None)
    ok("announced as new and compatible, with its field score and official name", ns and ns.get("compatible") is True and ns.get("label"), str(ns)[:240])
    s = wait_for(lambda: (lambda x: report(x, new_s) and report(x, new_s)["rows"] == 6 and x)(get("/api/svc/clock")), 60)
    ok("its 6 rows are loaded", bool(s))
    f = get("/api/svc/facets")
    ok("filters / intro card list it", any(r.get("name") == new_s or r.get("source") == new_s for r in f["reports"]), "")
    ok("map platform: does not pick it up", get("/api/clock")["sources"] == c_before["sources"] + 1)

    print("\n8. New services collection that lacks a required field (no country)")
    insert("scan_e2e_nogeo", [{k: v for k, v in d.items() if k != "geo"} for d in day_rows("scan_http", 3, day)])
    s = wait_for(lambda: (lambda x: x["unsupported"] >= 1 and x)(get("/api/svc/clock")), 60)
    ok("services platform: counted as unsupported", bool(s))
    ns = s and next((n for n in s["new_sources"] if n.get("name") == "scan_e2e_nogeo"), None)
    ok("announced as not compatible, missing Country", ns and ns.get("compatible") is False and "Country" in ns.get("missing", []), str(ns)[:200])
    f = get("/api/svc/facets")
    ok("intro card / filters list it as not processed yet", any(u.get("name") == "scan_e2e_nogeo" for u in f.get("unsupported", [])))

    print("\n9. Constituency change (Settings) reaches both platforms; then back to the whole country")
    tok = dotenv_values(os.path.join(COPY, ".env")).get("SETTINGS_TOKEN") or ""
    hdr = {"X-Settings-Token": tok} if tok else {}
    cb, sb = get("/api/clock"), get("/api/svc/clock")
    st = get("/api/settings", headers=hdr)["settings"]
    # the busiest source network of the copied day, so the check works for any country
    net = str(get("/api/stats")["src_network"][0]["asns"][0])
    r = get("/api/settings", "POST", {"country": st["country"], "networks": [net], "cidrs": []}, hdr)
    ok("settings accepted", r.get("settings", {}).get("networks") in ([net], [int(net)]), str(r)[:160])
    c = wait_for(lambda: (lambda x: 0 < x["day_total"] < cb["day_total"] and x)(get("/api/clock")), 90)
    s = wait_for(lambda: (lambda x: 0 < x["day_total"] < sb["day_total"] and x)(get("/api/svc/clock")), 90)
    ok("map platform: only the constituency's events", bool(c), f"{cb['day_total']} -> {c and c['day_total']}")
    ok("services platform: only the constituency's records", bool(s), f"{sb['day_total']} -> {s and s['day_total']}")
    pub = get("/api/settings/public")
    ok("open pages see the change (settings/public restricted)", pub.get("restricted") is True)
    get("/api/settings", "POST", {"country": st["country"], "networks": [], "cidrs": []}, hdr)
    c = wait_for(lambda: (lambda x: x["day_total"] == cb["day_total"] and x)(get("/api/clock")), 90)
    s = wait_for(lambda: (lambda x: x["day_total"] == sb["day_total"] and x)(get("/api/svc/clock")), 90)
    ok("whole country again on both", bool(c) and bool(s))

    print("\n10. Collections removed: both platforms and the intro page drop them")
    for n in ("event4_e2e_new_report", "event4_e2e_partial", new_s, "scan_e2e_nogeo"):
        test.drop_collection(n)
    c = wait_for(lambda: (lambda x: x["sources"] == c0["sources"] and x["unsupported"] == c0["unsupported"] and x)(get("/api/clock")), 90)
    s = wait_for(lambda: (lambda x: x["sources"] == s0["sources"] and x["unsupported"] == s0["unsupported"] and x)(get("/api/svc/clock")), 90)
    ok("map platform: back to its reports", bool(c), str(get("/api/clock")["sources"]))
    ok("services platform: back to its reports", bool(s), str(get("/api/svc/clock")["sources"]))
    o = get("/api/overview")
    ok("intro page: back to its report count, nothing unsupported", o["reports_total"] == o0["reports_total"] and not o["unsupported"])

    print("\n11. Replay schedule unaffected by all of this")
    c = get("/api/clock")
    ok("still playing the same day", c["state"] == "playing" and c["replay_day"] == day, f"{c['state']} {c['replay_day']}")


def teardown():
    pidf = os.path.join(COPY, "e2e_server.pid")
    if os.path.exists(pidf):
        pid = int(open(pidf).read())
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        time.sleep(1)
    client.drop_database(DBNAME)
    print(f"teardown: copy stopped, {DBNAME} dropped:", DBNAME not in client.list_database_names())
    if os.path.exists(COPY):
        shutil.rmtree(COPY)
    print("teardown: ~/lg_e2e_app removed:", not os.path.exists(COPY))


if __name__ == "__main__":
    what = sys.argv[1] if len(sys.argv) > 1 else "all"
    if what in ("setup", "all"):
        setup()
    if what in ("check", "all"):
        check()
    if what in ("teardown", "all"):
        teardown()
    if what != "setup" and what != "teardown":
        print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
    sys.exit(1 if fails else 0)
