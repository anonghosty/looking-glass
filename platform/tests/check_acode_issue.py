#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A CVE ticked on an analyst code's page (acodes.py, 2026-11-14): an analyst code of exactly the selection's devices
that carry it, the same code when ticked again, nothing for a CVE none of them carry, the channel and CSRF rules, and
no address in the answer. Stand-ins for the code book and the days (no database). Run: .venv/bin/python tests/check_acode_issue.py"""
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from flask import Flask, g  # noqa: E402

import acodes  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


class Book:
    def __init__(self):
        self.lock, self.data = threading.RLock(), {}

    def _load(self):
        pass

    def get(self, c):
        e = self.data.get(c)
        return dict(e, code=c) if e else None

    def put(self, c, e):
        self.data[c] = dict(e)

    def record(self, *a, **k):
        pass


class Day:
    def __init__(self, events):
        self.events = events


class Findings:
    asked_of = None

    def of_code(self, c):
        return ({"id": "7", "participants": ["rachel"], "title": "a finding", "text": "", "status": "analyst", "user": "rachel"}
                if c == SRC else None)

    def sees(self, f, user, admin, strict=False):
        return admin or user in (f.get("participants") or [])


SRC = "LG-A-00000AAA"
CROSS_CALLS = []          # how the every-category section was asked for (hold_small or not)
# the selection: three services records on three hosts; .1 and .2 carry the CVE, .3 another one
EVS = [{"id": "r1", "ip": "192.0.2.1", "issues": ["CVE-2023-48795"], "extracted_date": "2026-11-13"},
       {"id": "r2", "ip": "192.0.2.2", "issues": ["CVE-2023-48795"], "extracted_date": "2026-11-13"},
       {"id": "r3", "ip": "192.0.2.3", "issues": ["CVE-2024-6387"], "extracted_date": "2026-11-13"}]
book, audited = Book(), []
book.put(SRC, {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"query": []}, "label": "a selection"})
tmp = tempfile.mkdtemp()
perms = {"researcher": {"definitions"}, "admin": {"settings"}}
CSRF = [True]


def cross_hosts(hosts):
    by = {}
    for e in EVS:
        if e["ip"] in hosts:
            for i in e["issues"]:
                by.setdefault(i, set()).add(e["ip"])
    return {"days": ["2026-11-13"], "issues": [{"name": n, "hosts": len(h), "ips": sorted(h)} for n, h in by.items()]}


app = Flask(__name__)
# as the app: a role without 'unmasked' (a researcher) is a masked viewer, is_demo() true for it
api = acodes.install(app, {"book": book, "findings": Findings(), "base_dir": tmp,
                           "is_demo": lambda: "unmasked" not in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                           "csrf_ok": lambda: CSRF[0], "fresh": lambda: True,
                           "has_perm": lambda p: p in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                           "audit": type("A", (), {"add": staticmethod(lambda *a, **k: audited.append((a, k)))})(),
                           "day": lambda platform, iso: Day(EVS), "cross_hosts": cross_hosts, "labels": dict,
                           "cross": lambda hosts, **kw: CROSS_CALLS.append(kw) or {},
                           "network": lambda a: "", "defined": dict, "people_name": lambda u: u})
api.paths["ids"] = os.path.join(tmp, "acodes")
os.makedirs(api.paths["ids"], exist_ok=True)
with open(os.path.join(api.paths["ids"], f"{SRC}.json"), "w") as fh:
    json.dump(["r1", "r2", "r3"], fh)


def tick(name, role="researcher", user="rachel", code=SRC):
    path = f"/api/intel/acode/{code}/issue"
    with app.test_request_context(path, method="POST", json={"name": name}):
        g.user = {"user": user, "role": role}
        ep, kw = app.url_map.bind("localhost").match(path, method="POST")
        rv = app.view_functions[ep](**kw)
        rv, st = rv if isinstance(rv, tuple) else (rv, 200)
        return st, rv.get_json()


print("A CVE ticked on the analyst code's page")
st, d = tick("CVE-2023-48795")
ok("a code for exactly the devices of the selection that carry it", st == 200 and d.get("hosts") == 2 and d.get("code", "").startswith("LG-A-"), str(d))
code = d.get("code", "")
e = book.get(code) or {}
ok("…its records are those two devices' records with that CVE", sorted(json.load(open(os.path.join(api.paths["ids"], f"{code}.json")))) == ["r1", "r2"])
ok("…made from the selection, marked with the CVE", (e.get("sel") or {}).get("from_code") == SRC and e["sel"].get("issue") == "CVE-2023-48795")
ok("…no address in the answer", "192.0.2" not in json.dumps(d))
ok("…and it is in the audit log", any(a and a[0] == "analyst_code" for a, _ in audited))
st2, d2 = tick("CVE-2023-48795")
ok("ticked again: the same code", st2 == 200 and d2.get("code") == code, str(d2))
ok("a CVE none of its devices carry: refused, said why", tick("CVE-1999-0001")[0] == 409)
ok("no name: refused", tick("")[0] == 400)
ok("someone outside the finding's channel: refused as unknown", tick("CVE-2024-6387", user="grace")[0] == 404)
ok("a role that does not read codes: refused", tick("CVE-2024-6387", role="external")[0] == 403)
CSRF[0] = False
ok("without the page's token: refused", tick("CVE-2024-6387")[0] == 403)
CSRF[0] = True

print("The ticked code belongs to its parent's channel (security review of 7db98d1)")
perms["analyst"] = {"unmasked", "export"}


def as_user(user, role, fn):
    with app.test_request_context("/"):
        g.user = {"user": user, "role": role}
        return fn()


def listed(user):
    def f():
        rv = app.view_functions["api_acode_list"]()
        rv = rv[0] if isinstance(rv, tuple) else rv
        return [c["code"] for c in (rv.get_json() or {}).get("codes") or []]
    return as_user(user, "analyst", f)


ok("an analyst outside the channel cannot open it (pages, searches, Executive)", not as_user("grace", "analyst", lambda: api.allowed(code)))
ok("…nor sees it in the analysts' list", code not in listed("grace") and SRC not in listed("grace"), str(listed("grace")))
ok("a participant can open it and sees it listed", as_user("rachel", "analyst", lambda: api.allowed(code)) and code in listed("rachel"))
ok("an admin can open it", as_user("ann", "admin", lambda: api.allowed(code)))
book.put("LG-A-0000CCCC", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"from_code": code, "issue": "x"}})
ok("a code ticked on the ticked code: still the first finding's channel", not as_user("grace", "analyst", lambda: api.allowed("LG-A-0000CCCC")))
print("A chain that cannot be followed to its end stays closed (security review of c0f9311)")
book.put("LG-A-0000DDDD", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"from_code": "LG-A-0000DDDD"}})
ok("a chain that loops back on itself: no endless walk, closed to analysts",
   not as_user("grace", "analyst", lambda: api.allowed("LG-A-0000DDDD")))
ok("…an admin can still open it", as_user("ann", "admin", lambda: api.allowed("LG-A-0000DDDD")))
prev = code
for i in range(40):                                        # 40 codes, each ticked on the one before
    c_ = f"LG-A-1{i:07X}"
    book.put(c_, {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"from_code": prev, "issue": "x"}})
    prev = c_
ok("a chain longer than the walk: closed to analysts, even participants", not as_user("rachel", "analyst", lambda: api.allowed(prev)))
book.put("LG-A-0000EEEE", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"from_code": "LG-A-0000GONE"}})
ok("a parent code no longer kept: closed to analysts", not as_user("grace", "analyst", lambda: api.allowed("LG-A-0000EEEE")))
book.put("LG-A-0000FFFF", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"query": []}})
ok("a code made before channels (no parent, no finding): open to analysts, as before",
   as_user("grace", "analyst", lambda: api.allowed("LG-A-0000FFFF")))
perms["admin"] = {"settings", "unmasked", "export"}         # an admin reads the analysts' list too
admin_list = as_user("ann", "admin", lambda: [c["code"] for c in app.view_functions["api_acode_list"]().get_json()["codes"]])
ok("the admins' list still works with closed chains in it", "LG-A-0000DDDD" in admin_list)

print("A selection made from decoded beacons keeps the 5-device rule for researchers (security review of 3ba9e60)")
SRCB = "LG-A-0000BEAC"
book.put(SRCB, {"kind": "a", "platform": "services", "day": "2026-11-13", "label": "beacons",
                "sel": {"from_code": SRC, "beacon": {"name": "android.badbox2", "os_family": "windows"}}})
with open(os.path.join(api.paths["ids"], f"{SRCB}.json"), "w") as fh:
    json.dump(["r1", "r2", "r3"], fh)


def tick_as(name, role, perms_, code):
    path = f"/api/intel/acode/{code}/issue"
    with app.test_request_context(path, method="POST", json={"name": name}):
        g.user = {"user": "rachel", "role": role, "perms": perms_}
        ep, kw = app.url_map.bind("localhost").match(path, method="POST")
        rv = app.view_functions[ep](**kw)
        rv, st = rv if isinstance(rv, tuple) else (rv, 200)
        return st, rv.get_json()


st_r, d_r = tick_as("CVE-2023-48795", "researcher", ["definitions"], SRCB)
ok("a researcher ticking a CVE 2 of its devices carry: refused, no code (fewer than 5 devices)",
   st_r == 409 and "code" not in d_r and "5" in d_r.get("error", ""), f"{st_r} {d_r}")
st_a, d_a = tick_as("CVE-2023-48795", "analyst", ["unmasked", "export"], SRCB)
ok("…an analyst, who sees the devices, gets its code", st_a == 200 and d_a.get("code", "").startswith("LG-A-"), f"{st_a} {d_a}")
def devices_as(role, perms_, code):
    path = f"/api/intel/acode/{code}/devices"
    with app.test_request_context(path):
        g.user = {"user": "rachel", "role": role, "perms": perms_}
        ep, kw = app.url_map.bind("localhost").match(path)
        rv = app.view_functions[ep](**kw)
        rv = rv[0] if isinstance(rv, tuple) else rv
        return rv.get_json() or {}


as_analyst = devices_as("analyst", ["unmasked", "export"], SRCB)           # an analyst opens it first (the cache warms)
as_researcher = devices_as("researcher", ["definitions"], SRCB)
small = sorted({c for c in json.dumps(as_analyst).split('"') if c.startswith(("LG-C-", "LG-X-"))})
ok("the devices of a beacon selection: an analyst's answer is not served to a researcher afterwards (review of 04696d5)",
   bool(small) and not any(c in json.dumps(as_researcher) for c in small) and "null" not in json.dumps(as_researcher),
   f"{as_analyst} / {as_researcher}")
SRCB2 = "LG-A-0000BEA2"                      # a fresh beacon selection: nothing of it cached yet
book.put(SRCB2, dict(book.get(SRCB), label="beacons again"))
with open(os.path.join(api.paths["ids"], f"{SRCB2}.json"), "w") as fh:
    json.dump(["r1", "r2", "r3"], fh)
CROSS_CALLS.clear(); devices_as("researcher", ["definitions"], SRCB2)
ok("…its every-category section holds small patterns back for a researcher too (review of d3e2bf6)",
   any(c.get("hold_small") for c in CROSS_CALLS), str(CROSS_CALLS))
CROSS_CALLS.clear(); devices_as("analyst", ["unmasked", "export"], SRC)
ok("…an analyst's handed-over selection keeps every code there, as before", CROSS_CALLS and not any(c.get("hold_small") for c in CROSS_CALLS),
   str(CROSS_CALLS))
# security review of bc92a26: the page's chain named the beacon code a selection came from, with its parts. The code
# book describes a held beacon code to nobody who may not see it (combos.described); the chain follows that answer.
HELDB = "LG-B-0000HE1D"
book.put(HELDB, {"kind": "b", "section": "infections", "name": "android.badbox2", "text": "beacons of operator HTM"})
book.describe = lambda c: ("Decoded beacons: beacons of operator HTM" if "unmasked" in g.user["perms"] else "") if c == HELDB else ""
SRCB3 = "LG-A-0000BEA3"
book.put(SRCB3, dict(book.get(SRCB), label="beacons handed over", sel={"from_code": HELDB, "beacon": {"name": "android.badbox2", "operator": "HTM"}}))
with open(os.path.join(api.paths["ids"], f"{SRCB3}.json"), "w") as fh:
    json.dump(["r1", "r2", "r3"], fh)
def page_as(role, perms_, code):
    """The analyst code's page (/api/intel/acode/<code>), where the chain is."""
    path = f"/api/intel/acode/{code}"
    with app.test_request_context(path):
        g.user = {"user": "rachel", "role": role, "perms": perms_}
        ep, kw = app.url_map.bind("localhost").match(path)
        rv = app.view_functions[ep](**kw)
        rv = rv[0] if isinstance(rv, tuple) else rv
        return rv.get_json() or {}


ch_r = page_as("researcher", ["definitions"], SRCB3).get("chain") or []
ch_a = page_as("analyst", ["unmasked", "export"], SRCB3).get("chain") or []
ok("a selection made from a held beacon code: the chain names it to nobody who may not see it",
   ch_r and ch_r[0].get("hidden") is True and "HTM" not in json.dumps(ch_r) and "label" not in ch_r[0], str(ch_r))
ok("...not even its code (it would confirm a guess offline; security review of 84bfb69)",
   ch_r and ch_r[0].get("code") == "" and HELDB not in json.dumps(ch_r) and ch_r[0].get("held") is True, str(ch_r))
ok("…an analyst still sees where it came from", ch_a and ch_a[0]["code"] == HELDB and "HTM" in ch_a[0].get("label", ""), str(ch_a))
del book.describe
ok("…and the code made from it carries the beacon mark on (the rule follows it)",
   ((book.get(d_a.get("code", "")) or {}).get("sel") or {}).get("beacon") == {"name": "android.badbox2", "os_family": "windows"})

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
