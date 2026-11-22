#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Findings over time (finding_watch.py), the corners tests/check_finding_watch.py leaves: offline, with made-up
findings, days and devices (documentation addresses only).
- FINDING_ACT_DAYS / FINDING_GRACE_DAYS that are not numbers fall back to 30 / 7; 0 days never closes a finding
- a review's kept search: one organisation's sub-finding counts only its own devices; a search with nothing kept is
  "none"; an analyst code that is not one is skipped
- "seen again" for a combination code matches the latest day with the code's own matcher
- a finding that cannot be worked out is an error, never a crash of the others, and is tried again
- an advisory whose state cannot be read keeps the finding open (never closed by mistake)
- the background loop closes what is due and logs it
- the addresses: only for roles that see them; an advisor only after management approved; nobody signed in: 403
No database needed. Run: .venv/bin/python tests/check_cov_finding_watch.py"""
import os
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask, g  # noqa: E402

import finding_watch as FW  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


print("The number of days from .env")
os.environ["FINDING_ACT_DAYS"] = "thirty"
os.environ["FINDING_GRACE_DAYS"] = "a week"
ok("FINDING_ACT_DAYS not a number: 30", FW.act_days() == 30)
ok("FINDING_GRACE_DAYS not a number: 7", FW.grace_days() == 7)
os.environ["FINDING_ACT_DAYS"], os.environ["FINDING_GRACE_DAYS"] = "-5", "-1"
ok("negative numbers: 0 (never)", FW.act_days() == 0 and FW.grace_days() == 0)
os.environ["FINDING_ACT_DAYS"], os.environ["FINDING_GRACE_DAYS"] = "30", "7"

LATEST = datetime(2026, 11, 17, tzinfo=timezone.utc)


class Day:
    def __init__(self, start, events):
        self.start, self.events = start, events


class Store:
    def __init__(self, events, has_days=True):
        self.day = Day(LATEST, events)
        self.days = {LATEST: self.day} if has_days else {}

    def get(self, now):
        return self.day


COMMS = Store([{"src_ip": "192.0.2.1", "source": "event4_sinkhole"}, {"src_ip": "192.0.2.9", "source": "event4_sinkhole"}])
SVC = Store([{"ip": "198.51.100.1", "report": "scan_rdp"}, {"ip": "198.51.100.2", "report": "scan_rdp"}])


class Matcher:
    def __init__(self, ips):
        self.ips = ips

    def host(self, e):
        return e.get("ip") or e.get("src_ip") or ""

    def match(self, evs):
        return [e for e in evs if self.host(e) in self.ips]


class Book:
    def __init__(self):
        self.kept = {}

    def review_kept(self, fid):
        return fid in self.kept

    def review_records(self, fid):
        return self.kept[fid], None

    def get(self, code):
        return {"LG-A-1": {"kind": "a", "platform": "services", "day": "2026-11-15", "days": ["2026-11-14", "2026-11-15"]},
                "LG-A-2": {"kind": "x"}}.get(code)


OPENED = time.time() - 90 * 86400


class Findings:
    OPEN = {"new", "management", "researcher", "analyst", "advisor"}

    def __init__(self):
        self.items, self.expired, self.reported = {}, [], {}
        self.adv_fail = set()

    def get(self, fid):
        x = self.items.get(str(fid))
        if x and x.get("explode"):
            raise RuntimeError("broken finding")
        return x

    def set_reported(self, fid, first, last, seen):
        self.reported[fid] = (first, last, seen)

    def all_open(self):
        return [x for x in self.items.values() if x["status"] in self.OPEN]

    def advisories_of(self, fid):
        if str(fid) in self.adv_fail:
            raise RuntimeError("advisories not readable")
        return []

    def expire(self, fid, why, user):
        self.expired.append((fid, why, user))
        self.items[str(fid)]["status"] = "closed"
        return True

    def visible(self, user, settings, strict=False):
        return list(self.items.values())

    def sees(self, x, user, settings, strict=False):
        return True


F, BOOK = Findings(), Book()


class Log:
    infos, exc = [], []

    def info(self, *a):
        self.infos.append(a)

    def exception(self, *a):
        self.exc.append(a)


class Audit:
    rows = []

    def add(self, what, **kw):
        self.rows.append((what, kw))


PERMS = set()
app = Flask("cov-fw")
LOG = Log()
real_sleep = time.sleep
ctx = {"findings": F, "book": BOOK, "acodes": type("A", (), {"records": staticmethod(lambda entry: [{"ip": "198.51.100.1", "report": "scan_rdp"},
                                                                                                    {"ip": "198.51.100.7", "report": "scan_rdp"}])})(),
       "stores": {"comms": COMMS, "services": SVC}, "replay_now": lambda: LATEST, "network": lambda asn: "Example Net" if asn == 64500 else "Other Net",
       "svc_matcher": lambda e: Matcher({"198.51.100.2"}), "comms_matcher": lambda e: Matcher({"192.0.2.1"}),
       "has_perm": lambda p: p in PERMS, "logger": LOG, "audit": Audit(), "no_loop": True}
api = FW.install(app, ctx)


def wait_ready(fid, tries=200):
    for _ in range(tries):
        r = api.result(fid)
        if r and r.get("state") not in ("counting",) and not r.get("stale"):
            return r
        real_sleep(0.02)
    return api.result(fid)


hist = [{"at": OPENED, "status": "new"}]
print("What a finding is about")
BOOK.kept["1"] = {"entry": {"kind": "r"}, "m": None, "plat": "comms", "per_day": [("2026-11-10", 3), ("2026-11-11", 0), ("2026-11-12", 2)],
                  "found": [{"src_ip": "192.0.2.1", "src_asn": 64500, "source": "event4_sinkhole"},
                            {"src_ip": "192.0.2.2", "src_asn": 64501, "source": "event4_sinkhole"}]}
F.items["1"] = {"id": 1, "status": "new", "at": OPENED, "review": {"decision": ""}, "network": "Example Net", "history": hist}
c1 = api.compute(F.items["1"])
ok("one organisation's sub-finding: only its own devices (1 of 2)", c1["devices"] == 1, str(c1))
ok("…its reported days: the days of the kept search with records", (c1["reported_first"], c1["reported_last"]) == ("2026-11-10", "2026-11-12"))
ok("…seen again in the latest day by the combination's own matcher (192.0.2.1)", c1["again"] == 1 and c1["again_ips"] == ["192.0.2.1"], str(c1))
BOOK.kept["2"] = {}
F.items["2"] = {"id": 2, "status": "new", "at": OPENED, "review": {"x": 1}, "history": hist}
ok("a review whose search kept nothing: none", api.compute(F.items["2"]) == {"state": "none"})
BOOK.kept["3"] = {"entry": {"kind": "x"}, "m": Matcher(set()), "plat": "services", "per_day": [("2026-11-12", 4)],
                  "found": [{"ip": "198.51.100.2", "asn": 64500, "report": "scan_rdp"}]}
F.items["3"] = {"id": 3, "status": "new", "at": OPENED, "review": {"x": 1}, "history": hist}
c3 = api.compute(F.items["3"])
ok("a services review: its devices seen again by the services matcher", c3["again"] == 1 and c3["again_ips"] == ["198.51.100.2"], str(c3))
F.items["4"] = {"id": 4, "status": "new", "at": OPENED, "codes": ["LG-A-2", "LG-C-9", "LG-A-1"], "history": hist}
c4 = api.compute(F.items["4"])
ok("an analyst code that is not one is skipped, the next one used (its days, its devices)", c4["reported_first"] == "2026-11-14" and c4["devices"] == 2, str(c4))
ok("…devices of the latest day in the same reports: 198.51.100.1 again", c4["again_ips"] == ["198.51.100.1"], str(c4))

print("Worked out in the background")
r = wait_ready("4")
ok("the result arrives, the reported days are written", r.get("state") == "ready" and F.reported.get("4", ("",))[0] == "2026-11-14", str(r))
ok("…last seen: the latest report while it still shows the devices", F.reported["4"][2] == "2026-11-17", str(F.reported.get("4")))
F.items["5"] = {"id": 5, "status": "new", "at": OPENED, "codes": ["LG-A-1"], "history": hist}
real_get = F.get
calls = {"n": 0}


def flaky(fid):
    calls["n"] += 1
    if str(fid) == "5" and calls["n"] == 2:
        raise RuntimeError("broken just now")
    return real_get(fid)


F.get = flaky
first = api.result("5")
ok("asked for the first time: counting", first == {"state": "counting"})
for _ in range(100):
    if LOG.exc:
        break
    real_sleep(0.02)
ok("a finding that fails is logged, the worker keeps going", any("finding %s" in a[0] for a in LOG.exc), str(LOG.exc))
F.get = real_get
r = wait_ready("5")
ok("…and it is tried again (counting, then ready)", r.get("state") == "ready", str(r))
ok("no finding: nothing", api.result("999") is None)
empty = FW.install(Flask("cov-fw2"), dict(ctx, stores={"comms": Store([], False), "services": Store([], False)}))
F.items["6"] = {"id": 6, "status": "new", "at": OPENED, "history": hist}
ok("no day in memory anywhere: still answers (counting, then none for a finding from a name)",
   empty.result("6") == {"state": "counting"} and empty.compute(F.items["6"]) == {"state": "none"})

print("Time to act")
os.environ["FINDING_ACT_DAYS"] = "0"
ok("0 days: no end date, nothing closed", api.act_until(F.items["6"]) == "" and api.expire_due() == [])
os.environ["FINDING_ACT_DAYS"] = "30"
F.adv_fail.add("6")
ok("an advisory that cannot be read: the finding stays open", 6 not in api.expire_due() and F.items["6"]["status"] == "new")
F.adv_fail.discard("6")
F.items["6"]["reported"] = {"last": "2026-09-01"}
closed = api.expire_due()
ok("devices last seen more than 30 days ago: closed, with why, audited", 6 in closed and "last seen in the reports of 2026-09-01" in F.expired[-1][1]
   and ctx["audit"].rows[-1][0] == "finding_status")

print("The background loop")
F.items["7"] = {"id": 7, "status": "new", "at": OPENED, "history": hist}
naps = []


class Clock:
    @staticmethod
    def sleep(s):
        naps.append(s)
        if len(naps) > 1:
            raise SystemExit                               # ends the loop's thread after one round
    time = staticmethod(time.time)


FW.time = Clock
FW.install(Flask("cov-fw3"), dict(ctx, no_loop=False))
for _ in range(200):
    if len(naps) > 1:
        break
    real_sleep(0.02)
FW.time = time
ok("the loop waits for the service, then closes what is due and logs it, then sleeps 30 minutes",
   naps[:2] == [120, 1800] and F.items["7"]["status"] == "closed" and any("time to act expired" in a[0] for a in LOG.infos), str(naps))

print("Who sees what")
c = app.test_client()


@app.before_request
def _who():
    g.user = {"user": WHO["user"], "role": "x"} if WHO["user"] else None


WHO = {"user": ""}
ok("nobody signed in: 403", c.get("/api/findings/watch").status_code == 403)
WHO["user"] = "made-up-external"
ok("an account outside the team: 403", c.get("/api/findings/watch").status_code == 403)
PERMS.update({"definitions"})
j = c.get("/api/findings/watch").get_json()
ok("a researcher: counts for every finding, no address", "findings" in j and "again_ips" not in str(j) and "198.51.100" not in str(j))
ok("…the addresses of a finding: refused (403)", c.get("/api/findings/4/again").status_code == 403)
PERMS.clear()
PERMS.update({"advisory"})
F.items["8"] = {"id": 8, "status": "advisor", "at": OPENED, "codes": ["LG-A-1"], "kind": "case", "history": hist}
ok("an advisor, a case (never an advisory): 404", c.get("/api/findings/8/again").status_code == 404)
F.items["9"] = {"id": 9, "status": "new", "at": OPENED, "codes": ["LG-A-1"], "review": {"decision": "both"}, "history": hist}
ok("an advisor, a decided review: the addresses", c.get("/api/findings/9/again").status_code == 200)
F.items["10"] = {"id": 10, "status": "advisor", "at": OPENED, "codes": ["LG-A-1"],
                 "history": [{"at": OPENED, "status": "advisor", "role": "researcher"}]}
ok("an advisor, handed over without management's approval: 404", c.get("/api/findings/10/again").status_code == 404)
PERMS.clear()
PERMS.update({"settings"})
ok("an administrator: an unknown finding is 404", c.get("/api/findings/nope/again").status_code == 404)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
