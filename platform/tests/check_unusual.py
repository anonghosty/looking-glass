#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Unusual activity (unusual_detect.py, unusual.py; the user, 2026-11-24), with made-up numbers and made-up users:
- the normal is the median: one odd day does not move it; a day is suggested only when well above normal AND big
  enough; a thread with too few earlier days is not judged;
- the day summary holds counts only, never an address; the constituency decides which side of a record is ours;
- report pairs carry how much more often than chance they go together;
- Dismiss keeps a thread quiet for 30 days unless it doubles; Confirm makes it a watched thread; both audited;
- who sees what: analysts everything, researchers no devices, management the week card only, others nothing.
DB-free. Run from the platform's folder: .venv/bin/python tests/check_unusual.py
"""
import json
import os
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import unusual  # noqa: E402
import unusual_detect as pd  # noqa: E402

checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    print(f"  {'ok  ' if cond else 'FAIL'} {name}" + ("" if cond else f"  [{detail}]"))
    if not cond:
        fails.append(name)


CFG = {"window": 28, "min_devices": 10, "ratio": 2.0, "z": 4.0, "min_history": 7}


def days(n, start="2026-10-20"):
    import datetime as dt
    d0 = dt.date.fromisoformat(start)
    return [(d0 + dt.timedelta(days=i)).isoformat() for i in range(n)]


def summary(day, threads=None, reports=None, pairs=None, n=1000):
    return {"day": day, "n_devices": n, "reports": reports or {"sinkhole": {"devices": 200, "platform": "comms"}},
            "threads": threads or {}, "pairs": pairs or {}}


print("== the normal, and when a thread is suggested")
ds = days(29)
hist = [summary(d, {"64514|sinkhole": 10 + (i % 3)}) for i, d in enumerate(ds[:28])]
today = summary(ds[28], {"64514|sinkhole": 48})
s = pd.detect(today, hist, CFG)
net = [x for x in s if x["kind"] == "network"]
ok("a thread at about 4x its normal is suggested", net and net[0]["value"] == 48 and net[0]["normal"] == 11, net)
w = pd.words(net[0], lambda r: "Sinkhole HTTP", lambda a: f"AS{a} Lakeside") if net else ""
ok("…in plain words, with its normal", "AS64514 Lakeside, Sinkhole HTTP: 48 devices, normally about 11 (4.4x)." == w, w)
ok("…with its history for the chart (the day itself last)", net and net[0]["history"][-1] == (ds[28], 48) and len(net[0]["history"]) == 29)
odd = [summary(d, {"64514|sinkhole": 500 if i == 5 else 10}) for i, d in enumerate(ds[:28])]
s2 = [x for x in pd.detect(summary(ds[28], {"64514|sinkhole": 48}), odd, CFG) if x["kind"] == "network"]
ok("one odd day in the weeks before does not move the normal (the median)", s2 and s2[0]["normal"] == 10, s2)
small = [summary(d, {"64514|sinkhole": 1}) for d in ds[:28]]
ok("small: 1 device a day, then 3, is not suggested (below the minimum size)",
   not [x for x in pd.detect(summary(ds[28], {"64514|sinkhole": 3}), small, CFG) if x["kind"] == "network"])
ok("a little above normal (14 against 10) is not suggested",
   not [x for x in pd.detect(summary(ds[28], {"64514|sinkhole": 14}), [summary(d, {"64514|sinkhole": 10}) for d in ds[:28]], CFG)
        if x["kind"] == "network"])
new = [x for x in pd.detect(summary(ds[28], {"64514|sinkhole": 20}), [summary(d) for d in ds[:28]], CFG) if x["kind"] == "network"]
ok("a thread that was always 0 and is now 20 is suggested as new", new and new[0]["new"] is True and "normally none" in
   pd.words(new[0], lambda r: r, lambda a: a), new)
ok("too few earlier days: not judged", not pd.detect(today, hist[-3:], CFG))
ok("days the report did not arrive do not count as 0",
   not [x for x in pd.detect(today, [summary(d, reports={"other": {"devices": 5, "platform": "comms"}}) for d in ds[:28]], CFG)
        if x["kind"] == "network"])
whole = [x for x in pd.detect(summary(ds[28], reports={"sinkhole": {"devices": 900, "platform": "comms"}}),
                              [summary(d) for d in ds[:28]], CFG) if x["kind"] == "report"]
ok("the whole constituency's report total is a thread too", whole and whole[0]["asn"] == "*" and whole[0]["value"] == 900, whole)

print("== learning from the team's decisions (per report)")
ok("no decision: the bar as set", pd.sensitivity({}, "sinkhole") == (1.0, 0, 0))
ok("each Dismiss raises it a step, each Confirm lowers it", pd.sensitivity({"sinkhole": {"dismissed": 2, "confirmed": 0}}, "sinkhole")[0] == 1.5
   and pd.sensitivity({"sinkhole": {"dismissed": 0, "confirmed": 1}}, "sinkhole")[0] == 0.75)
ok("…within bounds (never below 0.75x, never above 2x)", pd.sensitivity({"sinkhole": {"dismissed": 40}}, "sinkhole")[0] == 2.0
   and pd.sensitivity({"sinkhole": {"confirmed": 40}}, "sinkhole")[0] == 0.75)
mid = summary(ds[28], {"64514|sinkhole": 30})
ok("30 against a normal of 11 is suggested as set", [x for x in pd.detect(mid, hist, CFG) if x["kind"] == "network"])
ok("…not after the team dismissed this report's threads twice (it now asks from 3x)",
   not [x for x in pd.detect(mid, hist, CFG, {"sinkhole": {"dismissed": 2}}) if x["kind"] == "network"])
low = summary(ds[28], {"64514|sinkhole": 22})
ok("22 against 11 is not suggested as set", not [x for x in pd.detect(low, hist, CFG) if x["kind"] == "network"])
sens = [x for x in pd.detect(low, hist, CFG, {"sinkhole": {"confirmed": 1}}) if x["kind"] == "network"]
ok("…but is once the team confirmed one of this report's threads (it now asks from 1.5x)", sens and sens[0]["asked_from"] == 1.5, sens)
ok("…and says why, in words", sens and pd.learned_words(sens[0], {"sinkhole": {"confirmed": 1}}, lambda r: "Sinkhole HTTP")
   == "Looking Glass asks from 1.5x its normal for Sinkhole HTTP, after 0 dismissal(s) and 1 confirmation(s) by your team.")

print("== report pairs")
R = {"a": {"devices": 100, "platform": "comms"}, "b": {"devices": 50, "platform": "services"}}
ph = [summary(d, reports=R, pairs={"a|b": 5}) for d in ds[:28]]
pr = [x for x in pd.detect(summary(ds[28], reports=R, pairs={"a|b": 40}), ph, CFG) if x["kind"] == "pair"]
ok("a pair seen together far more often than normal is suggested", pr and pr[0]["value"] == 40 and pr[0]["normal"] == 5, pr)
ok("…with how much more often than chance (lift = 40 x 1000 / (100 x 50) = 8)", pr and pr[0]["lift"] == 8.0, pr)
ok("…in words", pr and "both A and B" in pd.words(pr[0], lambda r: r.upper(), lambda a: a))
BIG = {"a": {"devices": 900, "platform": "comms"}, "b": {"devices": 900, "platform": "services"}}
grew = [x for x in pd.detect(summary(ds[28], reports=BIG, pairs={"a|b": 400}), [summary(d, reports=BIG, pairs={"a|b": 100}) for d in ds[:28]], CFG)
        if x["kind"] == "pair"]
ok("a pair that only grew with its reports (no more often together than chance) is not suggested", not grew, grew)

print("== the day summary: counts only, and the constituency")


class Scope:
    restricted = True

    def in_scope(self, asn, ip):
        return str(asn) == "64514"


d = pd.Day("2026-11-23")
recs = [{"src_ip": "198.18.1.1", "src_asn": 64514, "dst_ip": "203.0.113.9", "dst_asn": 64999, "filename": "2026-11-23-x.csv"},
        {"src_ip": "203.0.113.5", "src_asn": 64999, "dst_ip": "198.18.1.2", "dst_asn": 64514, "filename": "2026-11-23-x.csv"},
        {"src_ip": "203.0.113.6", "src_asn": 64999, "dst_ip": "203.0.113.7", "dst_asn": 64998, "filename": "2026-11-23-x.csv"},
        {"ip": "198.18.1.1", "asn": 64514, "filename": "2026-11-23-scan.csv"},
        {"ip": "198.18.1.3", "asn": 64514, "filename": "2026-11-23-special.csv"}]
got = [pd.device_of(r, Scope()) for r in recs]
ok("the source when it is in the constituency", got[0] == ("198.18.1.1", 64514, "comms"), got[0])
ok("…else the destination", got[1] == ("198.18.1.2", 64514, "comms"), got[1])
ok("…and neither side: left out", got[2] is None)
ok("services: the host", got[3] == ("198.18.1.1", 64514, "services"))
ok("special reports stay out", got[4] is None)
d.add("sinkhole", "comms", "198.18.1.1", 64514)
d.add("sinkhole", "comms", "198.18.1.2", 64514)
d.add("scan_rdp", "services", "198.18.1.1", 64514)
sm = d.summary()
ok("per report, per network and report, per pair", sm["reports"]["sinkhole"]["devices"] == 2 and sm["threads"]["64514|sinkhole"] == 2
   and sm["pairs"] == {"scan_rdp|sinkhole": 1} and sm["n_devices"] == 2, sm)
ok("no address in the summary", "198.18" not in json.dumps(sm))

print("== Dismiss: quiet for 30 days, unless it doubles")
now = time.time()
dis = {"t1": {"until": now + 30 * 86400, "value": 40}}
ok("dismissed: quiet", unusual.quiet({"id": "t1", "value": 60}, dis, now))
ok("…unless it doubled", not unusual.quiet({"id": "t1", "value": 80}, dis, now))
ok("…and back after the 30 days", not unusual.quiet({"id": "t1", "value": 41}, dis, now + 31 * 86400))

print("== who sees what (made-up users)")
from flask import Flask, g  # noqa: E402

base = tempfile.mkdtemp(prefix="lg-unusual-")
os.makedirs(os.path.join(base, "data", "unusual", "days"))
sug = pd.detect(today, hist, CFG) + pr
with open(os.path.join(base, "data", "unusual", "suggestions.json"), "w") as f:
    json.dump({"day": ds[28], "made": int(now), "config": CFG, "suggestions": sug, "week": {ds[28]: sug}}, f)
for s_ in hist + [today]:
    with open(os.path.join(base, "data", "unusual", "days", f"{s_['day']}.json"), "w") as f:
        json.dump(s_, f)
PERMS, AUDIT, CSRF = {"p": set()}, [], {"ok": True}


class Audit:
    def add(self, event, **kw):
        AUDIT.append((event, kw))


class Coll:
    def find(self, q, fields):
        return [{"src_ip": "198.18.1.1", "src_asn": 64514, "filename": f"{ds[28]}-x"},
                {"src_ip": "198.18.1.1", "src_asn": 64514, "filename": f"{ds[28]}-x"},
                {"src_ip": "198.18.9.9", "src_asn": 64515, "filename": f"{ds[28]}-x"}]


app = Flask(__name__)


@app.before_request
def _who():
    g.user = {"user": "lgpt-person"}


unusual.install(app, {"base_dir": base, "has_perm": lambda p: p in PERMS["p"], "csrf_ok": lambda: CSRF["ok"],
                       "audit": Audit(), "db": {"sinkhole": Coll()}, "settings": None,
                       "network": lambda a: "Lakeside", "svc_label": lambda n: n})
c = app.test_client()
tid = [x for x in sug if x["kind"] == "network"][0]["id"]
PERMS["p"] = set()
ok("no permission: the page's data is refused", c.get("/api/unusual").status_code == 403)
ok("…and the week card", c.get("/api/mgmt/unusual-week").status_code == 403)
PERMS["p"] = {"definitions"}
j = c.get("/api/unusual").get_json()
ok("a researcher does not open the analysts' page (they meet it in Looking Glass asks)", c.get("/unusual").status_code == 403)
ok("a researcher sees the cards", j and len(j["suggestions"]) == len(sug) and j["masked"] is True and j["can_decide"] is False, j)
ok("…without links to the platforms", all(not x["links"] for x in j["suggestions"]))
ok("…and never the devices", c.get(f"/api/unusual/{tid}/devices").status_code == 403)
ok("…nor Confirm or Dismiss", c.post(f"/api/unusual/{tid}/confirm", json={"name": "x"}).status_code == 403)
PERMS["p"] = {"management"}
wk = c.get("/api/mgmt/unusual-week").get_json()
ok("management: the week card, in words, no address", wk and wk["ready"] and wk["top"] and "198.18" not in json.dumps(wk), wk)
ok("…and not the Unusual activity page", c.get("/api/unusual").status_code == 403)
PERMS["p"] = {"view", "unmasked", "export"}
j = c.get("/api/unusual").get_json()
card = next(x for x in j["suggestions"] if x["id"] == tid)
ok("an analyst sees the cards with a link to the map, filtered", card["links"] and card["links"][0]["href"] == "/?source=sinkhole&src_asn=64514", card["links"])
dv = c.get(f"/api/unusual/{tid}/devices").get_json()
ok("…and the devices of that network only, with their records", dv and dv["total"] == 1 and dv["devices"][0] == {
    "ip": "198.18.1.1", "asn": 64514, "network": "AS64514 Lakeside", "records": 2}, dv)
CSRF["ok"] = False
ok("Confirm without the form token: refused", c.post(f"/api/unusual/{tid}/confirm", json={"name": "Lakeside sinkhole"}).status_code == 403)
CSRF["ok"] = True
ok("Confirm without a name: refused", c.post(f"/api/unusual/{tid}/confirm", json={"name": " "}).status_code == 400)
r = c.post(f"/api/unusual/{tid}/confirm", json={"name": "Lakeside <b>sinkhole</b>"})
j = c.get("/api/unusual").get_json()
ok("Confirm: it leaves the suggestions and is tracked", r.status_code == 200 and tid not in [x["id"] for x in j["suggestions"]]
   and j["confirmed"] and j["confirmed"][0]["name"] == "Lakeside bsinkhole/b", j.get("confirmed"))
ok("…with its chart from the day summaries", j["confirmed"] and len(j["confirmed"][0]["history"]) == 29)
ok("…in the audit log", AUDIT and AUDIT[-1][0] == "unusual_confirmed")
pid = [x for x in sug if x["kind"] == "pair"][0]["id"]
r = c.post(f"/api/unusual/{pid}/dismiss", json={})
j = c.get("/api/unusual").get_json()
ok("Dismiss: it leaves the suggestions, counted as kept quiet", r.status_code == 200 and pid not in [x["id"] for x in j["suggestions"]]
   and j["quieted"] == 1, j.get("quieted"))
ok("…in the audit log", AUDIT[-1][0] == "unusual_dismissed")
lrn = json.load(open(os.path.join(base, "data", "unusual", "decisions.json")))["learned"]
ok("the decisions are learned per report (the confirmed network thread's report, the dismissed pair's two)",
   lrn.get("sinkhole") == {"dismissed": 0, "confirmed": 1} and lrn.get("a") == {"dismissed": 1, "confirmed": 0}
   and lrn.get("b") == {"dismissed": 1, "confirmed": 0}, lrn)
c.post(f"/api/unusual/{tid}/confirm", json={"name": "renamed"})
ok("renaming a watched thread is not a second confirmation",
   json.load(open(os.path.join(base, "data", "unusual", "decisions.json")))["learned"]["sinkhole"]["confirmed"] == 1)
j = c.get("/api/unusual").get_json()
ok("a watched thread well above its normal again today says so on its card", j["confirmed"] and "48 devices" in j["confirmed"][0]["growing"],
   j["confirmed"][0].get("growing") if j["confirmed"] else None)
ok("Stop tracking: audited", c.post(f"/api/unusual/{tid}/untrack", json={}).status_code == 200 and AUDIT[-1][0] == "unusual_untracked")
ok("a card id that is not one: not found", c.get("/api/unusual/../devices").status_code == 404)
st = os.stat(os.path.join(base, "data", "unusual", "decisions.json")).st_mode & 0o777
ok("the decisions file is owner-only (0600)", st == 0o600, oct(st))

print(f"\n{checks - len(fails)} of {checks} unusual-activity checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
