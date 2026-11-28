#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The quarterly report (quarterly.py, quarterly_pdf.py) against data whose answers are known in advance, its guards
against data made inconsistent on purpose, and what it keeps in data/quarterly/ (status, summary, the purge permit).
Builds its OWN throwaway MongoDB database (lg_quarterly_test_<random>), never the reports database, and drops it at the
end, also on failure. Only documentation addresses (192.0.2.x, 198.51.100.x, 203.0.113.x). The platform's data folder
is a temporary one.
Run: .venv/bin/python tests/check_quarterly.py   (the database part needs an account that may create a database:
tests/run_admin_db_tests.sh, or LG_MONGO_ADMIN_FILE; without one it is skipped)"""
import copy
import csv
import io
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import zipfile
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PLATFORM = os.path.dirname(HERE)
sys.path.insert(0, PLATFORM)
sys.path.insert(0, HERE)
import quarterly as qq  # noqa: E402
import services  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


def ts(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()


# ------------------------------------------------------------------ 1. dates (no database)
print("Purge dates: 15 working days (Mon-Fri) after the quarter, then the next working day; the last 31 days kept")
by_hand = {(2026, 1): ("2026-04-21", "2026-04-22"), (2026, 4): ("2027-01-21", "2027-01-22"),
           (2028, 3): ("2028-10-20", "2028-10-23"),       # ends on a Saturday
           (2029, 3): ("2029-10-19", "2029-10-22")}       # ends on a Sunday
for (y, q), (d15, pday) in by_hand.items():
    p = qq.purge_dates(y, q)
    ok(f"{y}Q{q}: 15th working day {d15}, purge {pday} (worked out by hand)",
       (p["working_day_15"].isoformat(), p["purge_day"].isoformat()) == (d15, pday), f"{p['working_day_15']} / {p['purge_day']}")
for y in range(2026, 2030):
    for q in range(1, 5):
        p = qq.purge_dates(y, q)
        last = p["last_day"]
        weekdays = [d for d in (last + timedelta(days=i) for i in range(1, 40)) if d.weekday() < 5]   # counted independently
        good = (p["working_day_15"] == weekdays[14] and p["purge_day"] == weekdays[15] and p["purge_day"].weekday() < 5
                and p["cutoff"] == p["purge_day"] - timedelta(days=31) and last == qq.quarter_range(y, q)[1] - timedelta(days=1))
        ok(f"{y}Q{q} (ends {last:%a %d %b}): purge {p['purge_day']:%a %d %b %Y}, kept from {p['cutoff']}", good)
ok("the rows the purge deletes: a report day before the cutoff (the pipeline's filter)",
   qq.purge_filter("2026-12-22") == {"filename": {"$gte": "0000-00-00", "$lt": "2026-12-22", "$regex": "^[0-9]{4}-[0-9]{2}-[0-9]{2}"}})
ok("regions in the platform's usual case (Nairobi, not NAIROBI); none given: Region unknown",
   qq.region_label("NAIROBI") == "Nairobi" and qq.region_label(" ") == qq.UNKNOWN_REGION)

# ------------------------------------------------------------------ 2. the fixture
POOL = [f"192.0.2.{i}" for i in range(256)] + [f"198.51.100.{i}" for i in range(256)] + [f"203.0.113.{i}" for i in range(256)]
rows = defaultdict(list)


def svc(coll, ip, asn, day, t="12:00:00", **kw):
    d = {"ip": ip, "port": 80, "geo": "KE", "region": kw.pop("region", "NAIROBI"), "sector": kw.pop("sector", "Information"),
         "severity": "medium", "tag": kw.pop("tag", ""), "filename": f"{day}-{coll}-ke.csv", "extracted_date": f"{day} {t}",
         "logged_date": f"{day} {t}"}
    if asn is not None:
        d["asn"] = asn
    d.update(kw)
    rows[coll].append(d)


def sink(ip, asn, day, t="08:00:00"):
    d = {"src_ip": ip, "src_geo": "KE", "src_region": "MOMBASA", "src_sector": "Information", "dst_ip": "198.51.100.250",
         "dst_geo": "US", "dst_port": 80, "infection": "andromeda", "family": "", "tag": "", "severity": "high",
         "filename": f"{day}-event4_sinkhole_http-ke.csv", "extracted_date": f"{day} {t}", "logged_date": f"{day} {t}"}
    if asn is not None:
        d["src_asn"] = asn
    rows["event4_sinkhole_http"].append(d)


for i, ip in enumerate(POOL[:760]):          # a big network: 760 addresses, four rows each (the two-stage count)
    tag = "cve-2099-0001" if i < 10 else "cve-2099-0002" if i < 15 else "exposed-admin-panel" if i < 40 else ""
    for day in (f"2026-10-{1 + i % 28:02d}", f"2026-11-{1 + i % 28:02d}", f"2026-12-{1 + i % 28:02d}", f"2026-12-{3 + i % 26:02d}"):
        svc("scan_http", ip, 64500, day, tag=tag)
for ip in POOL[:20]:                         # the same addresses in a second report (another network)
    sink(ip, 64501, "2026-11-20")
    sink(ip, 64501, "2026-12-05")
for k, ip in enumerate(POOL[600:605]):       # no network: "unknown network"
    svc("blocklist", ip, None, "2026-12-31", "23:59:59" if k == 0 else "10:00:00",
        sector='=HYPERLINK("http://example.invalid")' if k == 1 else "Information")
svc("blocklist", POOL[605], "", "2026-12-30")
svc("scan_http", POOL[700], 64502, "2026-10-01", "00:00:00")           # the first second: in
svc("scan_http", POOL[701], 64502, "2026-12-31", "23:59:59")           # the last second: in
svc("scan_http", POOL[702], 64502, "2027-01-01", "00:00:00")           # next quarter: out
sink(POOL[1], 64501, "2026-09-30", "23:59:59")                        # previous quarter: out
sink(POOL[709], 64503, "2026-08-15")                                  # a network seen only in the previous quarter
# rows with no infection and no family (r90): named readably, never by their raw tag list. Another destination than
# the sinkhole above (the constituency check counts that one's rows), November and December only (recurring networks)
TAGGED = {"badcandy;device-implant;ssl": POOL[400:403], "": POOL[403:405], "examplebot;iot": POOL[405:406]}
for tg, ips in TAGGED.items():
    for ip in ips:
        sink(ip, 64501, "2026-11-21" if tg.startswith("badcandy") else "2026-12-06")
        rows["event4_sinkhole_http"][-1].update(infection="", tag=tg, dst_ip="203.0.113.250")

HOST = {"scan_http": "ip", "blocklist": "ip", "event4_sinkhole_http": "src_ip"}
ASNF = {"scan_http": "asn", "blocklist": "asn", "event4_sinkhole_http": "src_asn"}
LO, HI = "2026-10-01", "2027-01-01"


def expected():
    """The answers, by brute force over the inserted rows (no MongoDB, no quarterly.py)."""
    E = {"rec": Counter(), "uniq": defaultdict(set), "net": defaultdict(set), "net_rec": Counter(), "all": set(), "day": defaultdict(Counter),
         "before": Counter()}
    for c, docs in rows.items():
        for d in docs:
            day = d["filename"][:10]
            if day < "2026-12-22":
                E["before"][c] += 1
            if not (LO <= day < HI):
                continue
            a = str(d.get(ASNF[c]) or "")
            m = day[:7]
            E["rec"][(c, a, m)] += 1
            E["uniq"][(c, a, m)].add(d[HOST[c]])
            E["uniq"][(c, a, "Q")].add(d[HOST[c]])
            E["net"][a].add(d[HOST[c]])
            E["net_rec"][a] += 1
            E["all"].add(d[HOST[c]])
            E["day"][c][day] += 1
    return E


E = expected()
ok("fixture: the edge rows are where they should be (independent of the report)",
   E["day"]["scan_http"]["2026-10-01"] > 0 and E["day"]["scan_http"]["2026-12-31"] > 0 and "2027-01-01" not in E["day"]["scan_http"])

base = tempfile.mkdtemp(prefix="lgq_")
os.makedirs(os.path.join(base, "data", "advisories", "files", "ADV-2026-001"))


def J(name, obj):
    with open(os.path.join(base, "data", name), "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


J("asns.json", {"asns": {"64500": {"name": "Example Net A"}, "64501": {"name": "Example Net B"}, "64502": {"name": "Example Net C"},
                         "64503": {"name": "Example Net D"}}})
J("infections.json", {"infections": {"andromeda": {"title": "Andromeda (Gamarue)"}, "examplebot": {"title": "Examplebot (Example family)"}}})
LONG = ("The example transport protocol with certain example extensions, found in Example before 9.6 and other products, "
        "allows remote attackers to bypass integrity checks such that some packets are omitted, and a client and server may "
        "consequently end up with a connection for which some security features have been downgraded or disabled, aka a "
        "Mallard attack.")
J("cve_cache.json", {"kev": {"t": 1, "items": {"CVE-2099-0001": {"name": "Example Product Remote Code Execution"}}},
                     "nvd": {"CVE-2099-0002": {"t": 9e9, "data": {"description": LONG}}}, "epss": {}, "cveorg": {}})
MGR = "mgr.wanjiru"


def H(status, at, **kw):
    return dict({"status": status, "user": MGR, "role": "management", "at": ts(at), "comment": "", "to": ""}, **kw)


items = {
    "1": {"id": "1", "kind": "review", "title": "Exposed web panels", "network": "Example Net A", "status": "closed", "at": ts("2026-10-05 09:00:00"),
          "user": "an.analyst", "review": {"decision": "analyst", "by": MGR},
          "history": [H("management", "2026-10-05 09:00:00", user="an.analyst"),
                      H("advisor", "2026-10-07 09:00:00", kind="decision", decision="accepted",
                        comment="Use the analyst's view (drilled down): approved, start with device 192.0.2.5 and the rest of the list"),
                      H("closed", "2026-10-15 09:00:00", kind="advisory_sent", comment="Sent.")]},
    "2": {"id": "2", "kind": "review", "title": "+Duplicate panels", "network": "Example Net B", "status": "closed", "at": ts("2026-11-01 09:00:00"),
          "user": "an.analyst", "review": {"decision": "rejected", "by": MGR},
          "history": [H("management", "2026-11-01 09:00:00"), H("closed", "2026-11-03 09:00:00", kind="decision", decision="rejected",
                                                                 comment="Already reported to this provider last week; no new advisory needed.")]},
    "3": {"id": "3", "title": "Waiting finding", "status": "management", "at": ts("2026-12-01 09:00:00"), "user": "a.researcher",
          "history": [H("management", "2026-12-01 09:00:00")]},
    "4": {"id": "4", "kind": "review", "title": "Decided last quarter", "status": "closed", "at": ts("2026-09-01 09:00:00"), "user": "an.analyst",
          "review": {"decision": "rejected"}, "history": [H("management", "2026-09-01 09:00:00"),
                                                          H("closed", "2026-09-10 09:00:00", kind="decision", decision="rejected", comment="Old.")]},
    "5": {"id": "5", "title": "Nobody answered", "status": "closed", "expired": True, "at": ts("2026-11-10 09:00:00"), "user": "a.researcher",
          "history": [H("management", "2026-11-10 09:00:00"), H("closed", "2026-12-20 09:00:00", kind="expired", user="looking-glass",
                                                                 comment="Time to act expired")]},
    # opened after the quarter ended and still open: not one of the quarter's open cases (a quarter made again later
    # counted it; Q3/Q4 test on lg-test, 2026-11-21)
    "6": {"id": "6", "title": "Opened next quarter", "network": "Example Net A", "status": "management",
          "at": ts("2027-01-02 09:00:00"), "user": "a.researcher", "history": [H("management", "2027-01-02 09:00:00")]},
}
J("findings.json", {"seq": 6, "items": items})
J("advisories/ADV-2026-001.json", {"ref": "ADV-2026-001", "finding": "1", "network": "Example Net A", "status": "sent", "subject": "Exposed web panels",
                                   "sends": [{"at": ts("2026-11-15 10:00:00"), "by": "adv.otieno", "to": ["Example Net A"]}],
                                   "reports": [{"n": 1, "at": ts("2026-11-14 10:00:00"), "name": "x.pdf"}], "updated": ts("2026-11-15 10:00:00")})
named = POOL[:5] + [POOL[765]]          # five seen again in December, one never in the data
buf = io.StringIO()
w = csv.writer(buf)
w.writerow(["ip", "asn", "network", "reports"])
for ip in named:
    w.writerow([ip, "64500", "Example Net A", "Accessible HTTP"])
with zipfile.ZipFile(os.path.join(base, "data", "advisories", "files", "ADV-2026-001", "1.zip"), "w") as zf:
    zf.writestr("devices.csv", buf.getvalue())
# a pipeline beside it (its purge record is read from its DATA_DIR): none yet
pipe = os.path.join(base, "pipeline")
os.makedirs(pipe)
open(os.path.join(pipe, "shadowserver_pipeline.py"), "w").write("# made-up\n")
open(os.path.join(pipe, ".env"), "w").write(f"DATA_DIR={pipe}\n")
os.environ["PIPELINE_DIR"] = pipe

# ------------------------------------------------------------------ 3. the database (throwaway)
import _throwaway_mongo  # noqa: E402  (the platform's way to an account that may create a throwaway database)
from dotenv import dotenv_values  # noqa: E402
_env = dotenv_values(os.path.join(PLATFORM, ".env"))
# the environment first, as load_dotenv gives the other database tests: a throwaway MongoDB on its own port (the CI
# rehearsal, the local suite) is named there, and the .env's database is never tried with its administrator
client = _throwaway_mongo.client(os.environ.get("MONGO_HOST") or _env.get("MONGO_HOST") or "127.0.0.1",
                                 os.environ.get("MONGO_PORT") or _env.get("MONGO_PORT") or 27017)
if client is None:
    shutil.rmtree(base, ignore_errors=True)
    print("\nSKIPPED the database part: no account here may create a throwaway database "
          "(run tests/run_admin_db_tests.sh, or set LG_MONGO_ADMIN_FILE)")
    print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
    sys.exit(1 if fails else 77)            # 77: skipped (run_all_checks.sh); the CI database job counts it as a failure
DBN = f"lg_quarterly_test_{secrets.token_hex(4)}"
assert DBN.startswith("lg_quarterly_test_")
out = tempfile.mkdtemp(prefix="lgq_out_")
try:
    db = client[DBN]
    for c, docs in rows.items():
        db[c].insert_many([dict(d) for d in docs])
        db[c].create_index([("filename", 1), ("category", 1), ("line_hash", 1)])
    TODAY = date(2027, 1, 10)

    print("\nA run on consistent data")
    R, PS, X, W, A, rws, G = qq.make(db, "2026Q4", base, TODAY, [])
    status, files = qq.publish(out, R, X, W, A, rws, G, "made by the check")
    ok("every guard passes on consistent data, and the run is VALID", status[0] == "VALID" and all(g[1] for g in G),
       "; ".join(g[0] for g in G if not g[1]))
    ok("two PDFs: one for management, one for advisors",
       os.path.basename(files["pdf_management"]) == "quarterly_2026Q4_management.pdf"
       and os.path.basename(files["pdf_advisor"]) == "quarterly_2026Q4_advisor.pdf"
       and all(os.path.getsize(files[k]) > 5000 for k in ("pdf_management", "pdf_advisor")))
    ok("the host field comes from the platform's registries (sinkhole: src_ip, scans: ip)",
       R["reports"]["event4_sinkhole_http"]["fields"]["ip"] == "src_ip" and R["reports"]["scan_http"]["fields"]["ip"] == "ip")
    ok("quarter records = rows from 1 Oct 00:00:00 to 31 Dec 23:59:59, and none either side", sum(R["rep_total"].values()) == sum(E["rec"].values()),
       f"{sum(R['rep_total'].values())} vs {sum(E['rec'].values())}")
    ok("unique addresses across every report", len(R["all_hosts"]) == len(E["all"]), f"{len(R['all_hosts'])} vs {len(E['all'])}")
    ok("the big network (760 addresses, 3,040 rows) counted in two stages",
       len(R["net_hosts"]["64500"]) == len(E["net"]["64500"]) == 760 and R["net_total"]["64500"] == E["net_rec"]["64500"])
    ok("rows with no network counted as unknown network", R["net_total"][""] == E["net_rec"][""] == 6, f"{R['net_total']['']}")
    ok("regions in the platform's usual case (Nairobi, Mombasa)", {r["label"] for r in X["regions"]} == {"Nairobi", "Mombasa"},
       str([r["label"] for r in X["regions"]]))

    def table(path):
        lines = open(path, encoding="utf-8").read().splitlines()
        k = next(i for i, ln in enumerate(lines) if ln.startswith("quarter,") or ln.startswith("section,"))
        return lines[:k], list(csv.DictReader(lines[k:]))
    head, adv = table(files["advisor"])
    bad = []
    for r in adv:
        a = r["asn"]
        if r["report"].startswith("All reports"):
            if int(r["unique addresses quarter"]) != len(E["net"][a]) or int(r["records quarter"]) != E["net_rec"][a]:
                bad.append(f"all reports {a}")
            continue
        c = next((k for k, v in R["reports"].items() if v["label"] == r["report"]), None)
        for m in ("2026-10", "2026-11", "2026-12"):
            if int(r[f"records {m}"]) != E["rec"][(c, a, m)] or int(r[f"unique addresses {m}"]) != len(E["uniq"][(c, a, m)]):
                bad.append(f"{c}/{a}/{m}")
        if int(r["unique addresses quarter"]) != len(E["uniq"][(c, a, "Q")]):
            bad.append(f"{c}/{a}/quarter")
    ok("advisor CSV: every report, network and month equals the known answer", not bad and len(adv) > 0, ", ".join(bad[:5]))
    ok("advisor CSV: network names, not only numbers (Example Net A, Unknown network)",
       any(r["network"] == "Example Net A" for r in adv) and any(r["network"] == qq.UNKNOWN_NET for r in adv))
    ok("advisor CSV: the previous quarter's columns filled (it has data)", all(r["records previous quarter"] != "" for r in adv))
    ok("advisor CSV: readable report names, never only the collection name",
       not any(r["report"] in rows for r in adv) and any(r["report"] == services.service_of("scan_http") for r in adv))
    head, adm = table(files["admin"])
    cut = qq.purge_dates(2026, 4)["cutoff"].isoformat()
    bad = []
    for r in adm:
        c = r["collection"]
        if c not in rows:
            continue
        if int(r["rows of this quarter before the cutoff"]) != sum(v for d, v in E["day"][c].items() if d < cut) \
                or int(r["days without data"]) != 92 - len(E["day"][c]) or int(r["rows the purge deletes (all quarters)"]) != E["before"][c]:
            bad.append(c)
        if [int(r[f"rows {m}"]) for m in ("2026-10", "2026-11", "2026-12")] != [sum(v for d, v in E["day"][c].items() if d.startswith(m)) for m in ("2026-10", "2026-11", "2026-12")]:
            bad.append(c + " months")
    ok("admin CSV: rows per month, days without data, this quarter's rows before the cutoff and everything the purge deletes",
       not bad, ", ".join(bad))
    ok("admin CSV: the purge dates are stated (2027-01-21, 2027-01-22, cutoff 2026-12-22)",
       all(s in "\n".join(head) for s in ("2027-01-21", "2027-01-22", "2026-12-22")))
    head, mg = table(files["management"])

    def val(sec, name, metric, period="2026Q4"):
        return next((r["value"] for r in mg if r["section"] == sec and r["name"] == name and r["metric"] == metric and r["period"] == period), None)
    ok("management: quarter totals (records, unique addresses, networks)",
       (val("Totals", "All reports", "records"), val("Totals", "All reports", "unique addresses"), val("Totals", "All reports", "networks"))
       == (str(sum(E["rec"].values())), str(len(E["all"])), str(len([k for k in E["net_rec"] if k not in ("", "0", None)]))))
    D1 = "Decisions (one per organisation of a case)"
    ok("management: decisions approved 1, rejected 1, waiting 1 (a decision of last quarter left out)",
       (val("Management decisions", D1, "approved"), val("Management decisions", D1, "rejected"), val("Management decisions", D1, "waiting")) == ("1", "1", "1"))
    reasons = [r for r in mg if r["section"] == "Management decisions" and r["name"].startswith("#")]
    ok("management: each decision with its date and full reason; an address in a comment becomes [address]",
       len(reasons) == 2 and reasons[0]["period"] == "2026-10-07"
       and reasons[0]["value"] == "Use the analyst's view (drilled down): approved, start with device [address] and the rest of the list")
    ok("management: time to act (1 expired; median 2.0 days to the decision, 10.0 to the advisory)",
       (val("Time to act", "Expired unanswered (time to act passed)", "findings"),
        val("Time to act", "Median days from opening to the decision", "days"),
        val("Time to act", "Median days from opening to the advisory sent", "days")) == ("1", "2.0", "10.0"))
    ok("management: KEV (10 addresses with CVE-2099-0001, by its catalogue name)",
       val("Actively exploited (CISA KEV)", "Addresses with a KEV CVE", "unique addresses") == "10"
       and any(r["name"] == "CVE-2099-0001: Example Product Remote Code Execution" and r["value"] == "10" for r in mg))
    ok("management: infections by their readable name (Andromeda (Gamarue): 20)", val("Infections", "Andromeda (Gamarue)", "unique addresses") == "20")
    infs = {r["name"]: r["value"] for r in mg if r["section"] == "Infections" and r["metric"] == "unique addresses"}
    no_name = qq.readable("event4_sinkhole_http", "communication")
    ok("management: a row with no infection or family is named readably, never by its raw tags (r90): the issues its tags "
       "stand for (Badcandy, Device implant: 3), a tag the knowledge base knows (Examplebot (Example family): 1), else the "
       f"report's name ({no_name}: 2)",
       (infs.get("Badcandy, Device implant"), infs.get("Examplebot (Example family)"), infs.get(no_name)) == ("3", "1", "2")
       and not any(";" in n or n in TAGGED for n in infs) and no_name and ";" not in no_name, str(infs))
    ok("...the same names as one shared function gives them (infection_name), with the knowledge base's titles",
       qq.infection_name(qq.infection_key({"t": "badcandy;device-implant;ssl"}, "event4_sinkhole_http", "communication"), {})
       == "Badcandy, Device implant"
       and qq.infection_name(qq.infection_key({"i": "andromeda", "t": "x;y"}, "n", "communication"), {"andromeda": "Andromeda (Gamarue)"})
       == "Andromeda (Gamarue)"
       and qq.infection_name(qq.infection_key({"f": "Mirai"}, "n", "communication"), {}) == "Mirai")
    ok("management: better or worse (networks gone 1: Example Net D; appeared 2: A and C), counted from the reports",
       val("Better or worse", "networks gone", "count") == "1" and val("Better or worse", "networks appeared", "count") == "2"
       and PS["source"] == "counted from the reports now",
       f"gone {val('Better or worse', 'networks gone', 'count')}, new {val('Better or worse', 'networks appeared', 'count')}")
    ok("management: recurring networks (records in all three months: Example Net A only)",
       val("Recurring networks", "Networks with records in every month so far", "networks") == "1")
    ok("management: advisories sent 1, in November", val("Advisories", "Advisories sent", "sends") == "1" and val("Advisories", "Sent", "sends", "2026-11") == "1")
    head, org = table(files["orgs"])
    ok("advisor follow-up: 6 devices named, 5 still seen after the advisory, 1 not seen since",
       [(r["organisation"], r["devices named in them"], r["still seen after the advisory was sent"], r["not seen since"]) for r in org]
       == [("Example Net A", "6", "5", "1")])
    ok("advisor follow-up: a finding opened after the quarter is not one of its open cases (Example Net A: 0)",
       [r.get("cases still open") for r in org if r["organisation"] == "Example Net A"] == ["0"], str(org))
    head, iss = table(files["issues"])
    ok("advisor: top issues per network, KEV marked",
       any(r["network"] == "Example Net A" and r["issue or CVE"].startswith("CVE-2099-0001") and r["in CISA KEV"] == "yes" and r["unique addresses"] == "10" for r in iss))
    m2 = [r for r in iss if r["issue or CVE"].startswith("CVE-2099-0002")]
    ok("a CVE known only by a long description: its id and short name (\"Mallard attack\"), the full description in the CSV",
       m2 and m2[0]["issue or CVE"] == "CVE-2099-0002: Mallard attack" and m2[0]["CVE description"] == LONG, str(m2[:1]))
    texts = {os.path.basename(p): open(p, encoding="utf-8").read() for k, p in files.items() if not k.startswith("pdf")}
    ok("every CSV says VALID on its first line", all(t.startswith("Report status,VALID") for t in texts.values()))
    ok("no output CSV contains an IP address", not any(qq.ADDR_RE.search(t) for t in texts.values()))
    ok("no output names a manager or any account", not any(u in t for t in texts.values() for u in (MGR, "adv.otieno", "an.analyst", "a.researcher")))
    ok("no output cuts a text short (no \"…\")", not any("…" in t for t in texts.values()))
    ok("a formula-like value from the data (a sector =HYPERLINK(...)) gets a leading apostrophe",
       "'=HYPERLINK" in texts[os.path.basename(files["management"])])
    risky = [cell for t in texts.values() for row in csv.reader(io.StringIO(t)) for cell in row
             if cell[:1] in ("=", "+", "-", "@") and not re.fullmatch(r"[+-]?\d+(?:[.,]\d+)*%?|-+", cell)]
    ok("no CSV cell starts with = + - @ (outside numbers)", not risky, str(risky[:3]))
    try:
        import pypdf  # noqa: F401
        have_pdf = True
    except ImportError:
        have_pdf = False
    if have_pdf:
        import pypdf
        for k in ("pdf_management", "pdf_advisor"):
            text = " ".join(p.extract_text() or "" for p in pypdf.PdfReader(files[k]).pages)
            ok(f"{k}: VALID at the top, no address, nothing cut short", "VALID" in text and not qq.ADDR_RE.search(text) and "…" not in text)
        mt = " ".join(p.extract_text() or "" for p in pypdf.PdfReader(files["pdf_management"]).pages)
        at = " ".join(p.extract_text() or "" for p in pypdf.PdfReader(files["pdf_advisor"]).pages)
        ok("the management PDF has management's decisions; the advisor PDF does not",
           "Management's decisions" in mt and "Management's decisions" not in at and "Issues per network" in at)

    print("\nEach guard trips on inconsistent data")

    def trip(n, mutate):
        R2, W2, A2, r2 = copy.deepcopy(R), copy.deepcopy(W), copy.deepcopy(A), copy.deepcopy(rws)
        mutate(R2, W2, A2, r2)
        res = {g[0].split()[0]: g[1] for g in qq.guards(db, R2, X, W2, A2, r2)}
        return res[str(n)] is False
    ok("guard 1 (months add up) trips", trip(1, lambda R2, W2, A2, r2: R2["rep_total"].update({"scan_http": 1})))
    ok("guard 1 trips for a network too", trip(1, lambda R2, W2, A2, r2: R2["net_month"].update({("64500", "2026-11"): 1})))
    ok("guard 2 (uniques sane) trips", trip(2, lambda R2, W2, A2, r2: R2["rep_hosts"][("blocklist", "")].update({bytes([i]) * 8: 1 for i in range(50)})))
    ok("guard 2 trips when all-reports uniques exceed the sum over reports",
       trip(2, lambda R2, W2, A2, r2: R2["net_hosts"]["64501"].update({bytes([i, 1]) * 4: 2 for i in range(5)})))
    extra = db["scan_http"].insert_one({"ip": POOL[3], "asn": 64500, "filename": "2026-11-11-scan_http-ke.csv"}).inserted_id
    ok("guard 3 (independent recount) trips when MongoDB holds a row the report did not count", trip(3, lambda *a: None))
    db["scan_http"].delete_one({"_id": extra})
    ok("guard 3 passes again once it is gone", not trip(3, lambda *a: None))
    ok("guard 4 (nothing lost) trips", trip(4, lambda R2, W2, A2, r2: R2["net_total"].update({"": 3})))
    ok("guard 5 (purge dry count) trips on a wrong figure", trip(5, lambda R2, W2, A2, r2: r2["purge"].update({"scan_http": r2["purge"]["scan_http"] + 1})))
    ok("guard 5 trips when the cutoff falls inside the last 31 days",
       trip(5, lambda R2, W2, A2, r2: R2["purge"].update({"cutoff": R2["purge"]["purge_day"] - timedelta(days=10)})))
    ok("guard 6 (advisories and cases) trips on a missing decision row", trip(6, lambda R2, W2, A2, r2: r2.update({"decisions_listed": 1})))
    ok("guard 6 trips when approved + rejected + waiting is not the decisions", trip(6, lambda R2, W2, A2, r2: W2.update({"waiting": 2})))
    ok("guard 6 trips on an advisory not listed", trip(6, lambda R2, W2, A2, r2: r2.update({"advisories_listed": 0})))
    ok("guard 7 (dates) trips on an off-by-one end", trip(7, lambda R2, W2, A2, r2: R2.update({"hi": date(2026, 12, 31)})))
    ok("guard 7 trips on an off-by-one start", trip(7, lambda R2, W2, A2, r2: R2.update({"lo": date(2026, 10, 2)})))
    out2 = tempfile.mkdtemp(prefix="lgq_leak_")
    R3, rw3 = copy.deepcopy(R), copy.deepcopy(rws)
    rw3["management"].append(["Leak", "device " + POOL[7], "2026Q4", "x", 1, ""])
    st3, f3 = qq.publish(out2, R3, X, W, A, rw3, list(G[:-1]), "leak test")
    ok("guard 8: an address in an output fails the run and no output is left behind",
       st3[0] == "NOT VALID" and not f3 and not any(n.endswith((".csv", ".pdf")) for n in os.listdir(out2)), st3[1])
    shutil.rmtree(out2, ignore_errors=True)
    out3 = tempfile.mkdtemp(prefix="lgq_bad_")
    G4 = qq.guards(db, copy.deepcopy(R), X, W, A, dict(rws, decisions_listed=0))
    st4, f4 = qq.publish(out3, copy.deepcopy(R), X, W, A, rws, G4, "bad run")
    firsts = [open(p, encoding="utf-8").readline() for k, p in f4.items() if not k.startswith("pdf")]
    ok("a failed guard marks the run NOT VALID on the first line of every CSV", st4[0] == "NOT VALID" and firsts
       and all(ln.startswith("Report status,NOT VALID") for ln in firsts))
    if have_pdf:
        ok("...and at the top of both PDFs", all("NOT VALID" in (pypdf.PdfReader(f4[k]).pages[0].extract_text() or "") for k in ("pdf_management", "pdf_advisor")))
    shutil.rmtree(out3, ignore_errors=True)

    print("\nThe constituency (r89): one network plus one /24, the platforms' own Settings object")
    import ipaddress

    import settings as lg_settings
    S = lg_settings.Settings(os.path.join(base, "data", "settings_check.json"))
    clean, _errs = lg_settings.Settings.validate({"country": "KE", "networks": ["64501"], "cidrs": ["198.51.100.0/24"]})
    S.save(clean)
    RANGE = ipaddress.ip_network("198.51.100.0/24")

    def mine(asn, ip):                       # by hand, independent of settings.py and quarterly.py
        try:
            in_range = ipaddress.ip_address(str(ip)) in RANGE
        except ValueError:
            in_range = False
        return str(asn or "") == "64501" or in_range

    def expected_in(keep):
        recs, hosts, nets = 0, set(), defaultdict(set)
        for c, docs in rows.items():
            for d in docs:
                if not (LO <= d["filename"][:10] < HI):
                    continue
                if c == "event4_sinkhole_http":
                    k = keep(d.get("src_asn"), d["src_ip"]) or keep(d.get("dst_asn"), d.get("dst_ip"))
                else:
                    k = keep(d.get("asn"), d["ip"])
                if k:
                    recs += 1
                    hosts.add(d[HOST[c]])
                    nets[str(d.get(ASNF[c]) or "")].add(d[HOST[c]])
        return recs, hosts, nets
    er, eh, en = expected_in(mine)
    Rs, PSs, Xs, Ws, As, rws_s, Gs = qq.make(db, "2026Q4", base, TODAY, [], scope=S)
    out_s = tempfile.mkdtemp(prefix="lgq_scope_")
    st_s, f_s = qq.publish(out_s, Rs, Xs, Ws, As, rws_s, Gs, "made by the check (constituency)")
    ok("restricted: the counts include only the constituency's hosts (records, unique addresses, per network)",
       sum(Rs["rep_total"].values()) == er and len(Rs["all_hosts"]) == len(eh) and 0 < er < sum(E["rec"].values())
       and {a: len(h) for a, h in Rs["net_hosts"].items()} == {a: len(h) for a, h in en.items()},
       f"{sum(Rs['rep_total'].values())} vs {er}; {len(Rs['all_hosts'])} vs {len(eh)}")
    ok("...every guard still passes (the recount: counted + outside = every stored row), VALID",
       st_s[0] == "VALID" and all(g[1] for g in Gs), "; ".join(f"{g[0]}: {g[2]}" for g in Gs if not g[1]))
    ok("...the rows outside it are counted apart: in + out = the whole quarter",
       sum(Rs["rep_total"].values()) + sum(Rs["rep_out"].values()) == sum(E["rec"].values()))
    ok("...the purge's dry count and the admin CSV's stored rows stay the whole database",
       Rs["purge_all"] == R["purge_all"] and rws_s["purge"] == rws["purge"])
    texts_s = {k: open(p, encoding="utf-8").read() for k, p in f_s.items() if not k.startswith("pdf")}
    ok("...every CSV says what it was counted for",
       all("Counted for,1 network and 1 address range (the constituency set in Settings)" in t for t in texts_s.values()))
    ok("...and the admin CSV says its rows and purge figures are all networks in the database",
       "all networks in the database, not only the constituency" in texts_s["admin"])
    ok("whole country: every CSV says \"Counted for: the whole country\"",
       all("Counted for,the whole country" in open(p, encoding="utf-8").read() for k, p in files.items() if not k.startswith("pdf")))
    if have_pdf:
        ms = " ".join(" ".join((p.extract_text() or "") for p in pypdf.PdfReader(f_s["pdf_management"]).pages).split())
        ok("...the PDFs say it too, and that the purge rows are all networks",
           "Counted for: 1 network and 1 address range" in ms and "not only the constituency" in ms)
    # the map's rule for communications: kept when the other side's host is in the constituency
    S2 = lg_settings.Settings(os.path.join(base, "data", "settings_check2.json"))
    S2.save(lg_settings.Settings.validate({"country": "KE", "networks": [], "cidrs": ["198.51.100.250/32"]})[0])
    er2, eh2, _en2 = expected_in(lambda a, ip: str(ip) == "198.51.100.250")
    R2s = qq.collect_db(db, 2026, 4, TODAY, [], scope=S2)
    ok("a communication whose destination host is in the constituency is kept (source OR destination, as the map)",
       sum(R2s["rep_total"].values()) == er2 and R2s["rep_total"]["event4_sinkhole_http"] == 40 and len(R2s["all_hosts"]) == len(eh2),
       f"{sum(R2s['rep_total'].values())} vs {er2}")
    shutil.rmtree(out_s, ignore_errors=True)
    # a change of constituency between quarters is flagged
    st_k = qq.build(db, base, "2026Q4", "made by the check (constituency)", today=date(2027, 1, 3), now=ts("2027-01-03 00:20:00"), scope=S)
    summ_k = json.load(open(os.path.join(qq.quarter_dir(base, "2026Q4"), "summary.json")))
    ok("status.json and summary.json record the constituency",
       st_k["constituency"].startswith("1 network and 1 address range") and st_k["constituency_key"] == qq.constituency(S)["key"]
       and summ_k["constituency"]["key"] == qq.constituency(S)["key"])
    _R6, PS6, X6, *_ = qq.make(db, "2027Q1", base, date(2027, 4, 2), [])
    ok("a quarter compared against one counted for a different constituency says so",
       PS6.get("other_constituency") is True and PS6["source"].endswith("counted for a different constituency"))
    _R7, PS7, *_ = qq.make(db, "2027Q1", base, date(2027, 4, 2), [], scope=S)
    ok("...and not when it is the same constituency", PS7.get("other_constituency") is False
       and PS7["source"] == "the previous quarter's kept summary")
    shutil.rmtree(qq.quarter_dir(base, "2026Q4"), ignore_errors=True)

    print("\nAn empty quarter says so (r89)")
    out_e = tempfile.mkdtemp(prefix="lgq_empty_")
    Re, PSe, Xe, We, Ae, rws_e, Ge = qq.make(db, "2026Q2", base, TODAY, [])
    st_e, f_e = qq.publish(out_e, Re, Xe, We, Ae, rws_e, Ge, "made by the check (empty)")
    want = f"No report rows were loaded for 2026Q2 (Looking Glass holds report rows from {qq.say_day(Re['oldest_day'], False)} on)."
    ok("the oldest report day comes from the database (the fixture's oldest row, 15 August 2026)",
       Re["oldest_day"] == date(2026, 8, 15), str(Re.get("oldest_day")))
    ok("every CSV says it on its first lines", all(want in "\n".join(open(p, encoding="utf-8").read().splitlines()[:5])
                                                    for k, p in f_e.items() if not k.startswith("pdf")))
    if have_pdf:
        pe = [" ".join((p.extract_text() or "").split()) for p in pypdf.PdfReader(f_e["pdf_management"]).pages]
        ok("...and every page of the PDFs", all(want in t for t in pe), pe[0][:300])
    shutil.rmtree(out_e, ignore_errors=True)

    print("\nWhat is kept in data/quarterly/ (status, summary, the purge permit)")
    now = ts("2027-01-03 00:20:00")
    # the purge is OFF until an administrator turns it on (r88): a VALID report then writes no permit, and says so
    ok("a new installation: the quarterly purge is off", not qq.purge_on(base))
    st0 = qq.build(db, base, "2026Q4", "made automatically after the quarter ended", today=date(2027, 1, 3), now=now)
    qd = qq.quarter_dir(base, "2026Q4")
    ok("purge off: a VALID report writes no permit, and status.json says why",
       st0["valid"] and not st0["permit"] and st0["no_permit_why"] == qq.WHY_OFF and st0["purge_on"] is False
       and not os.path.exists(os.path.join(qd, "purge_permit.json")), str(st0.get("no_permit_why")))
    adm0 = open(os.path.join(qd, qq.file_name("admin", "2026Q4")), encoding="utf-8").read()
    ok("...the admin CSV says the purge is off and nothing will be deleted",
       "Quarterly purge,off," in adm0 and "nothing will be deleted" in adm0 and "Rows the purge would delete if turned on" in adm0)
    if have_pdf:
        ret = " ".join((p.extract_text() or "") for p in pypdf.PdfReader(os.path.join(qd, qq.file_name("pdf_management", "2026Q4"))).pages)
        adv = " ".join((p.extract_text() or "") for p in pypdf.PdfReader(os.path.join(qd, qq.file_name("pdf_advisor", "2026Q4"))).pages)
        ok("...and both PDFs: the retention page and Keep your copy say it is off, no rows will be deleted",
           "Off on this installation" in " ".join(ret.split()) and "nothing will be deleted" in " ".join(ret.split())
           and "no report rows will be deleted" in " ".join(adv.split()))
    rec, changed = qq.set_purge(base, True, "ada.admin", "Ada Admin", {"quarter": "2026Q4"}, now=now + 60)
    ok("turned on (Settings → Quarterly): the permit is written for the quarter whose purge day has not passed",
       qq.purge_on(base) and changed == [("2026Q4", "purge permit written")] and os.path.exists(os.path.join(qd, "purge_permit.json"))
       and oct(os.stat(qq.confirm_path(base)).st_mode & 0o777) == "0o600", str(changed))
    st = qq.build(db, base, "2026Q4", "made automatically after the quarter ended", today=date(2027, 1, 3), now=now)
    qd = qq.quarter_dir(base, "2026Q4")
    ok("made on the next quarter's 3rd day: VALID, every file kept", st["valid"] and sorted(os.listdir(qd)) == sorted(
        [qq.file_name(k, "2026Q4") for k in qq.FILES] + ["status.json", "summary.json", "purge_permit.json"]), str(sorted(os.listdir(qd))))
    permit = json.load(open(os.path.join(qd, "purge_permit.json")))
    ok("the purge permit: VALID, the quarter, the rule's dates", permit["valid"] is True and permit["status"] == "VALID"
       and (permit["quarter"], permit["purge_day"], permit["cutoff"], permit["working_day_15"]) == ("2026Q4", "2027-01-22", "2026-12-22", "2027-01-21"))
    ok("status.json: valid, every guard, made when, the 15th working day, the purge day, the cutoff",
       st["status"] == "VALID" and len(st["guards"]) == 8 and st["generated_at"].startswith("2027-01-03")
       and (st["working_day_15"], st["purge_day"], st["cutoff"]) == ("2027-01-21", "2027-01-22", "2026-12-22"))
    summ = json.load(open(os.path.join(qd, "summary.json")))
    ok("summary.json: counts per network and report, no address",
       summ["per_network"]["64500"]["unique"] == 760 and "scan_http|64500" in summ["per_report_network"]
       and not qq.ADDR_RE.search(json.dumps(summ)))
    ok("the kept files are owner-only", all(oct(os.stat(os.path.join(qd, n)).st_mode & 0o777) == "0o600" for n in os.listdir(qd))
       and oct(os.stat(qd).st_mode & 0o777) == "0o700")
    # a NOT VALID run never leaves a permit: the earlier one goes
    real_status = qq.status_line
    qq.status_line = lambda G_, R_: ("NOT VALID", "made NOT VALID by the check")
    try:
        st7 = qq.build(db, base, "2026Q4", "made again on request", today=date(2027, 1, 5), now=ts("2027-01-05 10:00:00"))
    finally:
        qq.status_line = real_status
    ok("a NOT VALID report writes no purge permit, and the earlier one is gone",
       not st7["valid"] and not st7["permit"] and not os.path.exists(os.path.join(qd, "purge_permit.json")))
    st = qq.build(db, base, "2026Q4", "made again on request", today=date(2027, 1, 6), now=ts("2027-01-06 10:00:00"))
    ok("made again, VALID, before its purge day: the permit is back", st["valid"] and os.path.exists(os.path.join(qd, "purge_permit.json")))
    if have_pdf:
        ret = " ".join(" ".join((p.extract_text() or "") for p in pypdf.PdfReader(os.path.join(qd, qq.file_name("pdf_management", "2026Q4"))).pages).split())
        ok("purge on: the retention page says it runs on the purge day unless turned off", "On when this report was made" in ret)
    # the next quarter compares against the kept summary, not the reports (their rows may be purged by then)
    for c in rows:
        db[c].delete_many({"filename": {"$lt": "2026-12-22"}})
    db["scan_http"].insert_one({"ip": POOL[1], "asn": 64504, "filename": "2027-02-01-scan_http-ke.csv"})
    R5, PS5, X5, *_ = qq.make(db, "2027Q1", base, date(2027, 4, 2), [])
    ok("the next quarter's \"vs previous quarter\" comes from the kept summary.json (after the purge)",
       PS5["source"] == "the previous quarter's kept summary" and X5["better_worse"]["unique addresses previous quarter"] == len(E["all"]))
    open(os.path.join(qd, "purge_result.json"), "w").write(json.dumps({"outcome": "done", "quarter": "2026Q4"}))
    st6 = qq.build(db, base, "2026Q4", "made again on request", today=date(2027, 1, 30), now=ts("2027-01-30 10:00:00"))
    ok("made again after its purge day: no permit (nothing more is deleted for it), the purge's record kept",
       not st6["permit"] and "after its purge day" in st6["no_permit_why"] and not os.path.exists(os.path.join(qd, "purge_permit.json"))
       and os.path.exists(os.path.join(qd, "purge_result.json")))
    try:
        qq.build(db, base, "2027Q1", "x", today=date(2027, 3, 31))
        ok("a quarter that has not ended is refused", False)
    except qq.Refused:
        ok("a quarter that has not ended is refused", True)
    json.dump({"purged_before": "2026-12-22"}, open(os.path.join(pipe, "quarterly_purge_status.json"), "w"))
    try:
        qq.build(db, base, "2026Q4", "x", today=date(2027, 2, 1))
        ok("a quarter whose raw rows were purged cannot be counted again", False)
    except qq.Refused as exc:
        ok("a quarter whose raw rows were purged cannot be counted again", "deleted" in str(exc))
    os.remove(os.path.join(pipe, "quarterly_purge_status.json"))

    print("\nA collection that cannot be read")
    db.command("create", "scan_broken", viewOn="scan_http", pipeline=[{"$project": {"x": {"$divide": [1, 0]}}}])
    out4 = tempfile.mkdtemp(prefix="lgq_fail_")
    R5, PS5, X5, W5, A5, r5, G5 = qq.make(db, "2026Q4", base, TODAY, [])
    st5, f5 = qq.publish(out4, R5, X5, W5, A5, r5, G5, "failing collection")
    adm5 = open(f5["admin"], encoding="utf-8").read()
    ok("an unreadable collection is reported, never skipped silently", "scan_broken" in R5["failed"])
    ok("...it marks the run NOT VALID and is listed in the admin CSV",
       st5[0] == "NOT VALID" and ",FAILED," in adm5 and "scan_broken" in adm5.splitlines()[0])
    shutil.rmtree(out4, ignore_errors=True)
finally:
    client.drop_database(DBN)
    ok("the throwaway database is dropped", DBN not in client.list_database_names())
    shutil.rmtree(base, ignore_errors=True)
    shutil.rmtree(out, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
