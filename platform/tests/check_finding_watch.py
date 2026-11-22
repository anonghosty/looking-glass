#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Findings over time (finding_watch.py, 2026-11-14): the day a finding's records were reported, its devices in the
latest report again, who sees which addresses, and closing a finding whose time to act has passed.
Run: .venv/bin/python tests/check_finding_watch.py"""
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flask import Flask, g  # noqa: E402

import finding_watch  # noqa: E402
import findings as FM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


UTC = timezone.utc
LATEST = datetime(2026, 11, 13, tzinfo=UTC)


class Day:
    def __init__(self, start, events):
        self.start, self.events = start, events


class Store:
    """The day the platform replays (LATEST), and, as in a running service, a later day partly loaded too."""
    def __init__(self, events):
        later = LATEST + timedelta(days=1)
        self.days = {LATEST: Day(LATEST, events), later: Day(later, [])}

    def get(self, dt):
        return self.days[LATEST]


class People:
    def name(self, u, default=""):
        return {"grace": "Grace", "rachel": "Rachel"}.get(u, default)


tmp = tempfile.mkdtemp()
path = os.path.join(tmp, "findings.json")
now = time.time()
old = (datetime.now(UTC) - timedelta(days=45)).date().isoformat()
items = {
    "1": {"id": "1", "section": "issues", "name": "x", "title": "an analyst's selection", "text": "", "codes": ["LG-A-00000001"],
          "user": "grace", "role": "analyst", "at": now, "status": "researcher", "participants": ["grace", "rachel"],
          "history": [{"status": "researcher", "user": "grace", "role": "analyst", "at": now}]},
    "2": {"id": "2", "section": "issues", "name": "y", "title": "an old one", "text": "", "codes": ["LG-A-00000002"],
          "user": "grace", "role": "analyst", "at": now - 50 * 86400, "status": "researcher", "participants": ["grace"],
          "reported": {"first": old, "last": old},
          "history": [{"status": "researcher", "user": "grace", "role": "analyst", "at": now - 50 * 86400}]},
    "3": {"id": "3", "section": "issues", "name": "z", "title": "from a name", "text": "", "codes": [],
          "user": "rachel", "role": "researcher", "at": now, "status": "new", "participants": ["rachel"],
          "history": [{"status": "new", "user": "rachel", "role": "researcher", "at": now}]},
    # made before channels (no participants): visible to every team role (Security Reviewer, 2026-11-14)
    "8": {"id": "8", "section": "issues", "name": "s", "title": "from before channels", "text": "", "codes": ["LG-A-00000001"],
          "user": "grace", "role": "analyst", "at": now, "status": "researcher",
          "history": [{"status": "researcher", "user": "grace", "role": "analyst", "at": now}]},
    # the reviewer's cases (external review, 2026-11-14): all reported 45 days ago
    "4": {"id": "4", "section": "issues", "name": "w", "title": "with the advisor", "text": "", "codes": [],
          "user": "grace", "role": "analyst", "at": now - 50 * 86400, "status": "advisor", "participants": ["grace"],
          "reported": {"first": old, "last": old}, "history": [{"status": "advisor", "user": "grace", "role": "analyst", "at": now - 50 * 86400}]},
    "5": {"id": "5", "section": "issues", "name": "v", "title": "an advisory not sent", "text": "", "codes": [],
          "user": "grace", "role": "analyst", "at": now - 50 * 86400, "status": "analyst", "participants": ["grace"],
          "reported": {"first": old, "last": old}, "history": [{"status": "analyst", "user": "grace", "role": "analyst", "at": now - 50 * 86400}]},
    "6": {"id": "6", "section": "issues", "name": "u", "title": "still being reported", "text": "", "codes": [],
          "user": "grace", "role": "analyst", "at": now - 50 * 86400, "status": "analyst", "participants": ["grace"],
          "reported": {"first": old, "last": old, "seen": datetime.now(UTC).date().isoformat()},
          "history": [{"status": "analyst", "user": "grace", "role": "analyst", "at": now - 50 * 86400}]},
    "7": {"id": "7", "section": "issues", "name": "t", "title": "a review opened today of old records", "text": "", "codes": [],
          "user": "grace", "role": "analyst", "at": now, "status": "management", "participants": ["grace"],
          "reported": {"first": old, "last": old}, "history": [{"status": "management", "user": "grace", "role": "analyst", "at": now}]},
}
with open(path, "w", encoding="utf-8") as fh:
    json.dump({"seq": 8, "items": items}, fh)
F = FM.Findings(path, People())
F.advisories_of = lambda fid: [{"status": "drafted"}] if str(fid) == "5" else []
audited = []

# analyst code 1: three devices reported on 9 Nov in one report; the latest day has two of them in that report again
codes = {"LG-A-00000001": {"kind": "a", "code": "LG-A-00000001", "platform": "services", "day": "2026-11-09", "section": "issues"},
         "LG-A-00000002": {"kind": "a", "code": "LG-A-00000002", "platform": "services", "day": old, "section": "issues"},
         "LG-A-00000003": {"kind": "a", "code": "LG-A-00000003", "platform": "services", "day": "2026-11-13", "section": "issues"}}
recs = {"LG-A-00000001": [{"ip": ip, "report": "compromised_website"} for ip in ("192.0.2.1", "192.0.2.2", "192.0.2.3")],
        "LG-A-00000002": [{"ip": "192.0.2.9", "report": "compromised_website"}],
        "LG-A-00000003": [{"ip": "192.0.2.1", "report": "compromised_website"}]}
latest = [{"ip": "192.0.2.1", "report": "compromised_website"}, {"ip": "192.0.2.2", "report": "compromised_website"},
          {"ip": "192.0.2.3", "report": "blocklist"}]                    # .3 is there, but in another report


class Book:
    def get(self, c):
        return codes.get(c)


class ACodes:
    def records(self, entry):
        return recs[entry["code"]]


perms = {"analyst": {"unmasked", "export"}, "researcher": {"definitions"}, "advisor": {"advisory"}, "admin": {"settings", "users"}}
app = Flask(__name__)
W = finding_watch.install(app, {"findings": F, "book": Book(), "acodes": ACodes(), "replay_now": lambda: LATEST,
                                "stores": {"comms": Store([]), "services": Store(latest)}, "network": lambda a: "",
                                "svc_matcher": None, "comms_matcher": None, "no_loop": True,
                                "audit": type("A", (), {"add": staticmethod(lambda *a, **k: audited.append((a, k)))})(),
                                "has_perm": lambda p: p in perms.get(getattr(g, "user", {}).get("role", ""), set())})

print("When the records were reported, and the devices in the latest report again")
r = W.compute(F.get("1"))
ok("an analyst code: its day is the reported day", r.get("reported_last") == "2026-11-09", str(r))
ok("…2 of its 3 devices are in the same report again on the latest day (a device in another report does not count)",
   r.get("devices") == 3 and r.get("again") == 2 and r.get("again_ips") == ["192.0.2.1", "192.0.2.2"], str(r))
ok("a finding from a name has no records: nothing to compare", W.compute(F.get("3")) == {"state": "none"})
F.data["items"]["9"] = dict(F.get("3"), id="9", codes=["LG-A-00000003"], status="analyst", participants=["grace"])
r9 = W.compute(F.get("9"))
ok("reported on the replay day itself: not 'seen again', even with a later day in memory (sweep 2026-11-14)",
   r9.get("latest") == "2026-11-13" and r9.get("again") is None, str(r9))


def call(path, role, user):
    with app.test_request_context(path):
        g.user = {"user": user, "role": role}
        ep, kw = app.url_map.bind("localhost").match(path)
        rv = app.view_functions[ep](**kw)
        rv, st = (rv if isinstance(rv, tuple) else (rv, 200))
        return st, rv.get_json()


# the worker fills the cache in the background: wait for it
for _ in range(50):
    st, d = call("/api/findings/watch", "researcher", "rachel")
    if d["findings"].get("1", {}).get("state") == "ready":
        break
    time.sleep(.1)
print("Who sees what")
ok("the list gives counts and days, never an address", st == 200 and d["findings"]["1"].get("again") == 2
   and "again_ips" not in json.dumps(d) and "192.0.2" not in json.dumps(d), json.dumps(d)[:300])
ok("…only the findings in the user's channel (and, as for every team role, those from before channels)", set(d["findings"]) == {"1", "3", "8"}, str(sorted(d["findings"])))
ok("…and the reported day is kept with the finding", (F.get("1").get("reported") or {}).get("last") == "2026-11-09")
st, d = call("/api/findings/1/again", "researcher", "rachel")
ok("a researcher is refused the addresses", st == 403)
st, d = call("/api/findings/1/again", "analyst", "grace")
ok("an analyst in the channel gets them", st == 200 and d.get("again_ips") == ["192.0.2.1", "192.0.2.2"], str(d))
st, d = call("/api/findings/3/again", "advisor", "nobody")
ok("…an advisor outside the channel does not", st == 404)
st, d = call("/api/findings/8/again", "advisor", "nobody")
ok("…nor an advisor on a finding from before channels that management has not approved (Security Reviewer)", st == 404, str(st))
st, d = call("/api/findings/8/again", "analyst", "grace")
ok("…while an analyst still gets that finding's addresses", st == 200, str(st))
st, d = call("/api/findings/watch", "external", "eve")
ok("an account outside the findings team (external) is refused the list (r90)", st == 403 and "findings" not in d, str(st))

print("Time to act")
os.environ["FINDING_ACT_DAYS"] = "30"
ok("act by: 30 days after its devices were last seen (still in the latest report: 13 Nov)",
   W.act_until(F.get("1")) == "2026-12-13" and F.get("1")["reported"].get("seen") == "2026-11-13", W.act_until(F.get("1")))
closed = W.expire_due()
x2 = F.get("2")
ok("an open finding reported 45 days ago, nobody acting on it, is closed", closed == ["2"] and x2["status"] == "closed" and x2.get("expired"), str(closed))
ok("…not one with the advisor (organisations wait for their advisory)", F.get("4")["status"] == "advisor")
ok("…not one with an advisory not yet sent", F.get("5")["status"] == "analyst")
ok("…not one whose devices the latest report still shows", F.get("6")["status"] == "analyst")
ok("…not a review opened today of old records (grace period)", F.get("7")["status"] == "management"
   and W.act_until(F.get("7")) >= (datetime.now(UTC) + timedelta(days=6)).date().isoformat(), W.act_until(F.get("7")))
ok("…and the closing is in the audit log: finding_status by looking-glass, with the reason",
   any(a and a[0] == "finding_status" and k.get("user") == "looking-glass" and "#2" in k.get("target", "") and "expired" in k.get("detail", "")
       for a, k in audited), str(audited))
h = x2["history"][-1]
ok("…'Time to act expired' in its history, by Looking Glass", h.get("kind") == "expired" and h["comment"].startswith(finding_watch.EXPIRED)
   and F.shown(x2)["history"][-1]["by"] == "Looking Glass", str(h))
ok("…the others stay open", F.get("1")["status"] == "researcher" and F.get("3")["status"] == "new")
ok("the page shows no 'act by' where it cannot expire (with the advisor, an advisory waiting)",
   call("/api/findings/watch", "admin", "grace")[1]["findings"].get("4", {}).get("act_until") == ""
   and call("/api/findings/watch", "admin", "grace")[1]["findings"].get("5", {}).get("act_until") == "")
ok("…and it is not closed twice", W.expire_due() == [])
os.environ["FINDING_ACT_DAYS"] = "0"
ok("FINDING_ACT_DAYS=0: nothing ever expires", W.act_until(F.get("1")) == "" and W.expire_due() == [])
os.environ.pop("FINDING_ACT_DAYS")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
