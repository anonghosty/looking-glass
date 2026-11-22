#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Abused or Compromised (intelligence.py) against MongoDB: every figure the page and its export show, recounted here
straight from the reports' collections, independently of the page's code (2026-11-18: every other data area had a
"vs MongoDB" check, this one had none). Read-only, counts only; nothing leaves the server.

Checked, for every Intelligence report and each of the 8 report days:
1. rows per report and day = the records MongoDB holds for that report day (the date in the file name);
2. each report's "today" and its 7-day median, each group's per-day totals, "today" and median;
3. "never received" = exactly the reports with no record in the 8 days;
4. "still arriving": how many reports arrived on the latest day, and how many usually do (the median of the 7 days);
5. a report's view (unfiltered): its records and distinct IP addresses = MongoDB's;
6. the CSV export of that view: one row per record, the same count;
7. management's counts (/api/intelligence/totals) = the analysts' figures, with no IP address in them.
The latest report day may still be arriving while this runs: there the page may lag MongoDB by its 2-minute cache,
never lead it. Skipped (exit 77) with no running service, in demo mode, or with a constituency set in Settings
(tests/verify_constituency.py covers the constituency). Usage: tests/verify_intelligence.py"""
import os as _os, sys as _sys; _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
import lgauth  # noqa: E402,F401  local API login (automation key)
lgauth.require_server()   # no running service (a fresh clone, CI): skipped, not crashed
import csv, io, ipaddress, json, os, re, statistics, sys, urllib.parse  # noqa: E402
from dotenv import load_dotenv  # noqa: E402
from pymongo import MongoClient  # noqa: E402

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))
db = MongoClient(host=os.environ["MONGO_HOST"], port=int(os.environ.get("MONGO_PORT", 27017)), username=os.environ.get("MONGO_USER"),
                 password=os.environ.get("MONGO_PASSWORD"), authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"))[os.environ["MONGO_DB"]]
ROW_CAP = 20000                                   # the page reads at most this many rows of a report and day
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

try:
    st_ = json.load(open(os.path.join(BASE_DIR, "data", "settings.json")))
    if st_.get("networks") or st_.get("cidrs"):
        print("SKIPPED: a constituency is set in Settings (tests/verify_constituency.py covers it)."); sys.exit(77)
except (OSError, ValueError):
    pass

fails, checks = [], 0


def ok(label, cond, info="", show=False):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    if not cond or show:
        print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def get(path, params=None, raw=False):
    q = urllib.parse.urlencode(params or [], doseq=True)
    with lgauth.urlopen(f"{lgauth.BASE}{path}" + (f"?{q}" if q else ""), timeout=600) as r:
        body = r.read()
    return body if raw else json.loads(body)


try:
    s = get("/api/intelligence")
except Exception as e:                            # noqa: BLE001
    if "403" in str(e):
        print("SKIPPED: demo mode is on (Abused or Compromised shows real records only with it off)."); sys.exit(77)
    raise
days = s["days"]                                  # oldest first; the last is the latest report day
latest, before = days[-1], days[:-1]
have = set(db.list_collection_names())


def mongo(name, day):
    return db[name].count_documents({"filename": {"$regex": "^" + re.escape(day)}}) if name in have else 0


def ip_ok(v):
    try:
        ipaddress.ip_address(str(v or "").strip()); return True
    except ValueError:
        return False


print(f"Abused or Compromised against MongoDB: {sum(len(g['reports']) for g in s['groups'])} reports, days {days[0]} to {latest}")
cards = [c for g in s["groups"] for c in g["reports"]]
truth = {c["name"]: {d: mongo(c["name"], d) for d in days} for c in cards}

print("1-2. Rows per report and day; today and the 7-day median")
for c in cards:
    page = {p["day"]: p["rows"] for p in c["per_day"]}
    t = truth[c["name"]]
    older = [d for d in before if page.get(d) != t[d]]
    ok(f"{c['title']}: every earlier day = MongoDB", not older, "; ".join(f"{d}: page {page.get(d)} vs MongoDB {t[d]}" for d in older[:3]))
    ok(f"{c['title']}: the latest day never ahead of MongoDB", page.get(latest, 0) <= mongo(c["name"], latest),
       f"page {page.get(latest)} vs MongoDB {t[latest]}")
    ok(f"{c['title']}: its 7-day median", c["median"] == statistics.median([t[d] for d in before]),
       f"page {c['median']} vs {statistics.median([t[d] for d in before])}")
for g in s["groups"]:
    page = {p["day"]: p["rows"] for p in g["per_day"]}
    want = {d: sum(truth[c["name"]][d] for c in g["reports"]) for d in days}
    ok(f"group {g['group']}: per-day totals (earlier days) = MongoDB", all(page.get(d) == want[d] for d in before),
       "; ".join(f"{d}: {page.get(d)} vs {want[d]}" for d in before if page.get(d) != want[d])[:200])
    ok(f"group {g['group']}: its 7-day median", g["median"] == statistics.median([want[d] for d in before]), f"{g['median']} vs {statistics.median([want[d] for d in before])}")
    ok(f"group {g['group']}: reports received", g["received"] == sum(1 for c in g["reports"] if any(truth[c["name"]].values())))

print("3. Never received")
nr_page = {x["name"] for x in s["not_received"]}
nr_true = {c["name"] for c in cards if not any(truth[c["name"]].values())}
ok("the reports listed as never received are exactly those with no record in the 8 days", nr_page == nr_true,
   f"page only: {sorted(nr_page - nr_true)[:4]}, MongoDB only: {sorted(nr_true - nr_page)[:4]}", show=True)

print("4. Still arriving")
usual = int(statistics.median([sum(1 for c in cards if truth[c["name"]][d]) for d in before])) if before else 0
ok("the usual number of reports a day = the median of the 7 days before", s["arriving"]["usual"] == usual,
   f"page {s['arriving']['usual']} vs {usual}", show=True)
ok("reports in on the latest day: never more than MongoDB holds", s["arriving"]["in"] <= sum(1 for c in cards if mongo(c["name"], latest)),
   f"page {s['arriving']['in']}")

print("5-6. Each report's view and its CSV export (the latest day with records)")
viewed = 0
for c in cards:
    t = truth[c["name"]]
    day = next((d for d in reversed(before) if t[d]), None)      # an earlier day: complete, not still arriving
    if not day:
        continue
    v = get("/api/intelligence/report", {"name": c["name"], "day": day})
    rows = list(db[c["name"]].find({"filename": {"$regex": "^" + re.escape(day)}}, {"ip": 1, "_id": 0}).limit(ROW_CAP))
    ok(f"{c['title']} {day}: the view's records = MongoDB's", v["total"] == min(t[day], ROW_CAP), f"view {v['total']} vs {t[day]}")
    hosts = {str(r.get("ip")).strip() for r in rows if ip_ok(r.get("ip"))}
    ok(f"{c['title']} {day}: its IP addresses = MongoDB's distinct addresses", v["hosts"] == len(hosts), f"view {v['hosts']} vs {len(hosts)}")
    body = get("/api/intelligence/export.csv", {"name": c["name"], "day": day}, raw=True).decode("utf-8-sig")
    n_csv = sum(1 for _ in csv.reader(io.StringIO(body))) - 1
    ok(f"{c['title']} {day}: the CSV export has one row per record", n_csv == v["total"], f"CSV {n_csv} vs view {v['total']}")
    viewed += 1
ok("at least one report's view and export were compared", viewed > 0 or not any(any(t.values()) for t in truth.values()),
   f"{viewed} report(s)", show=True)

print("7. Management's counts")
tot = get("/api/intelligence/totals")
by = {g["group"]: g for g in s["groups"]}
same = all(g["group"] in by and g["today"] == by[g["group"]]["today"] and g["median"] == by[g["group"]]["median"]
           and g["received"] == by[g["group"]]["received"] for g in tot["groups"])
ok("management's totals = the analysts' figures, group by group", same and len(tot["groups"]) == len(s["groups"]), show=True)
ok("…and carry no IP address", not IP_RX.search(json.dumps(tot)), show=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
