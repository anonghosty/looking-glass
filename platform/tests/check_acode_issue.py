#!/usr/bin/env python3
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
        return ({"id": "7", "participants": ["rachel"], "title": "a finding", "status": "analyst", "user": "rachel"}
                if c == SRC else None)

    def sees(self, f, user, admin, strict=False):
        return admin or user in (f.get("participants") or [])


SRC = "LG-A-00000AAA"
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
book.put("LG-A-0000DDDD", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"from_code": "LG-A-0000DDDD"}})
ok("a code whose chain loops back on itself: no endless walk, open as a code without a finding",
   as_user("grace", "analyst", lambda: api.allowed("LG-A-0000DDDD")))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
