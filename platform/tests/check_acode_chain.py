#!/usr/bin/env python3
"""An analyst code's page shows how its selection came about: the codes it was made from (sel.from_code), oldest first,
each with its finding's note; a code in a finding the reader is not part of is named but not shown; a loop or a long
chain stops; no address anywhere. Stand-in code book and findings; nothing real touched.
Run: .venv/bin/python tests/check_acode_chain.py"""
import json, os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, g  # noqa: E402
import acodes  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


class Book:
    def __init__(self, data):
        self.data = data
    def get(self, c):
        e = self.data.get(c)
        return dict(e, code=c) if e else None
    def describe(self, c):
        return f"described {c}"


class Findings:
    def __init__(self, items, sees):
        self.items, self._sees = items, sees
        self.asked_of = None
    def of_code(self, c):
        return self.items.get(c)
    def sees(self, f, user, admin):
        return admin or user in self._sees.get(f["id"], ())


book = Book({
    "LG-C-AAAA0001": {"kind": "c", "day": "2026-11-08"},
    "LG-A-AAAA0002": {"kind": "a", "platform": "comms", "day": "2026-11-09", "label": "The devices of LG-C-AAAA0001", "sel": {"from_code": "LG-C-AAAA0001"}},
    "LG-A-AAAA0003": {"kind": "a", "platform": "comms", "day": "2026-11-10", "label": "The devices of LG-A-AAAA0002", "sel": {"from_code": "LG-A-AAAA0002"}},
    "LG-A-AAAA0004": {"kind": "a", "platform": "comms", "day": "2026-11-10", "label": "The devices of LG-A-AAAA0003", "sel": {"from_code": "LG-A-AAAA0003"}},
    "LG-A-LOOP0001": {"kind": "a", "platform": "comms", "day": "2026-11-10", "sel": {"from_code": "LG-A-LOOP0002"}},
    "LG-A-LOOP0002": {"kind": "a", "platform": "comms", "day": "2026-11-10", "sel": {"from_code": "LG-A-LOOP0001"}},
})
findings = Findings({
    "LG-A-AAAA0002": {"id": 2, "title": "First look", "text": "Kindly look at the patterns that are normally seen", "user": "ana", "at": 1794600000},
    "LG-A-AAAA0003": {"id": 3, "title": "Second look", "text": "Now only the badbox ones", "user": "ana", "at": 1794610000},
}, sees={2: {"res"}, 3: set()})
app = Flask("t")
who = {"user": "res", "role": "researcher"}
import tempfile  # noqa: E402
api = acodes.install(app, {"book": book, "findings": findings, "base_dir": tempfile.mkdtemp(prefix="lg-chain-"),
                           "has_perm": lambda p: p == "settings" and (getattr(g, "user", None) or {}).get("role") == "admin",
                           "people_name": lambda u: {"ana": "Ama Analyst"}.get(u, u)})
with app.test_request_context("/"):
    g.user = who
    ch = api.chain("LG-A-AAAA0004")
    ok("oldest first, back to the first code", [x["code"] for x in ch] == ["LG-C-AAAA0001", "LG-A-AAAA0002", "LG-A-AAAA0003"], str([x["code"] for x in ch]))
    a2 = next(x for x in ch if x["code"] == "LG-A-AAAA0002")
    ok("an earlier code's note, title, author and date", a2.get("note") == "Kindly look at the patterns that are normally seen"
       and a2["title"] == "First look" and a2["by"] == "Ama Analyst" and a2["at"] and a2["finding"] == "#2" and a2["page"] == "/intel/LG-A-AAAA0002", str(a2))
    a3 = next(x for x in ch if x["code"] == "LG-A-AAAA0003")
    ok("a code in a finding the reader is not part of: named, not shown", a3 == {"code": "LG-A-AAAA0003", "hidden": True}, str(a3))
    c1 = ch[0]
    ok("a combination code with no finding: shown with what it is, no note", c1["kind"] == "combination" and not c1["note"] and c1["label"] == "described LG-C-AAAA0001" and not c1["page"], str(c1))
    ok("the first code has no chain", api.chain("LG-C-AAAA0001") == [])
    ok("a loop stops", [x["code"] for x in api.chain("LG-A-LOOP0001")] == ["LG-A-LOOP0002"])
    long = {f"LG-A-L{i:07d}": {"kind": "a", "platform": "comms", "day": "2026-11-10", "sel": {"from_code": f"LG-A-L{i + 1:07d}"}} for i in range(40)}
    book.data.update(long)
    n = len(api.chain("LG-A-L0000000"))
    ok("a very long chain stops at its limit (12)", n == 12, str(n))
    g.user = {"user": "boss", "role": "admin"}
    findings._sees = {}
    ok("an admin sees every step", not any(x.get("hidden") for x in api.chain("LG-A-AAAA0004")))
    raw = json.dumps(ch)
    ok("no address in the chain", not re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
