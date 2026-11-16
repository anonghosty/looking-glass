#!/usr/bin/env python3
"""Decoded beacons handed over as a finding (beacon_findings.py): who sees what, per role.

Made-up check-ins only (encoded by tests/check_beacon_decode.py's encoder), in a throwaway findings file.

1. Handing over: refused without the page's token, a recipient, or for a role that may not; a researcher may hand
   over only what 5 or more devices carry; the finding names the person and lands in their channel.
2. Opening it, per role: the analyst it went to gets every record with the host, the time, the report's readable name
   and the decoded JSON; a manager gets counts and the selection, no address, MAC, UUID, cpuid, cpumd5 or memory; a
   researcher outside the channel gets nothing (the same answer as no such finding).
3. Fewer than 5 devices (an analyst's hand-over to a manager): the manager sees counts only, the selection held back,
   and the title names no operator or version.
4. The path gate: the researchers', management's and advisors' paths include it; Peace of mind closes it.
Run: .venv/bin/python tests/check_beacon_findings.py"""
import datetime
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import logging  # noqa: E402
logging.disable(logging.WARNING)
from flask import Flask, g  # noqa: E402

import beacon_decode as B  # noqa: E402
import beacon_findings as BF  # noqa: E402
import findings as F  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from beacon_samples import encode, line, made_up, rkey  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


class Day:
    def __init__(self, events):
        self.start, self.serial, self.events = datetime.datetime(2026, 11, 14), 1, events


class People:
    def name(self, u, default=None):
        return {"rita": "Rita Researcher", "ana": "Ana Analyst", "max": "Max Manager"}.get(u, u)

    def full_name(self, u, default=None):          # notes.py names a note's author this way
        return self.name(u, default)


events, made = [], []
for i in range(6):
    o = made_up(i, operator="WT", version="WT:1.0.0")
    made.append(o)
    events.append({"src_ip": f"192.0.2.{20 + i}", "src_port": "4431", "timestamp": "2026-11-14T08:00:00", "infection": "android.badbox2",
                   "source": "event4_sinkhole_http", "http_url": line(encode(o, rkey())), "http_host": "c2.example"})
o = made_up(99, operator="HTM", version="HTM:1.0.0")       # one device only
made.append(o)
events.append({"src_ip": "192.0.2.99", "src_port": "4431", "timestamp": "2026-11-14T09:00:00", "infection": "android.badbox2",
               "source": "event4_sinkhole_http", "http_url": line(encode(o, rkey())), "http_host": "c2.example"})
store = type("S", (), {"days": {0: Day(events)}})()

tmp = tempfile.mkdtemp()
fnd = F.Findings(os.path.join(tmp, "findings.json"), People())
fnd.people_of = lambda kind: {"analyst": [{"user": "ana", "name": "Ana Analyst"}], "management": [{"user": "max", "name": "Max Manager"}],
                              "researcher": [{"user": "rita", "name": "Rita Researcher"}, {"user": "rob", "name": "Rob"}]}.get(kind, [])
audit = []
ROLES = {"rita": ("researcher", {"definitions"}), "rob": ("researcher", {"definitions"}), "ana": ("analyst", {"unmasked", "export", "view"}),
         "max": ("management", {"management"}), "adele": ("advisor", {"advisory"})}
app = Flask(__name__)
BF.install(app, {"store": store, "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}, "findings": fnd,
                 "has_perm": lambda p: p in g.user["perms"], "sees_hosts": lambda: "unmasked" in g.user["perms"],
                 "csrf_ok": lambda: g.user.get("tok") == "T", "fresh": lambda: True,
                 "audit": type("A", (), {"add": lambda self, *a, **k: audit.append((a, k))})()})


def call(user, method, path, body=None, tok="T"):
    role, perms = ROLES[user]
    with app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": perms, "tok": tok}
        ep, args = app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = app.view_functions[ep](**args)
        r, code = (r if isinstance(r, tuple) else (r, 200))
        return code, r.get_json()


WT = {"name": "android.badbox2", "operator": "WT", "version": "WT:1.0.0", "os_family": "windows"}
print("1. Handing over")
ok("refused without the page's token", call("rita", "POST", "/api/beacon/finding", {**WT, "kind": "analyst", "to": "ana"}, tok="")[0] == 403)
ok("refused without a recipient", call("rita", "POST", "/api/beacon/finding", {**WT, "kind": "analyst"})[0] == 400)
ok("refused to management (it decides, it does not hand beacons over)", call("max", "POST", "/api/beacon/finding", {**WT, "kind": "analyst", "to": "ana"})[0] == 403)
HTM = {"name": "android.badbox2", "operator": "HTM"}
few = call("rita", "POST", "/api/beacon/finding", {**HTM, "kind": "analyst", "to": "ana"})
none = call("rita", "POST", "/api/beacon/finding", {"name": "android.badbox2", "operator": "NOPE", "kind": "analyst", "to": "ana"})
ok("a researcher cannot hand over what fewer than 5 devices carry", few[0] == 404)
ok("... and gets exactly the answer for nothing matching: a guess can't tell a held-back value from a missing one",
   few[0] == none[0] == 404 and few[1] == none[1], f"{few} / {none}")
code, j = call("rita", "POST", "/api/beacon/finding", {**WT, "kind": "analyst", "to": "ana", "comment": "Windows beacons under an Android name."})
ok("a researcher hands 6 devices' beacons to a named analyst", code == 200 and j["finding"]["number"].startswith("#"), json.dumps(j))
fid = j["finding"]["id"]
item = fnd.get(fid)
ok("the finding is in the analyst's hands, its channel is the two of them", item["status"] == "analyst" and item["assignee"] == "ana"
   and item["participants"] == ["rita", "ana"])
ok("it holds the selection, never a device", item["beacon"] == WT and "192.0.2" not in json.dumps(item))
ok("the hand-over is in the audit log", any("finding_created" in a for a, k in audit))
ok("the Findings page marks it as carrying beacons", fnd.shown(item)["beacon"] is True)

print("2. Opening it, per role")
code, a0 = call("ana", "GET", f"/api/beacon/finding/{fid}")
ok("the Findings page shows the analyst no address until asked (Show the devices)", code == 200 and a0["can_records"]
   and "records_list" not in a0 and "192.0.2" not in json.dumps(a0) and a0["selection"])
code, a = call("ana", "GET", f"/api/beacon/finding/{fid}?records=1")
recs = a.get("records_list") or []
ok("the analyst gets every record: host, time, report's readable name", code == 200 and len(recs) == 6
   and {r["host"] for r in recs} == {f"192.0.2.{20 + i}" for i in range(6)} and all(r["report"] == "Sinkhole HTTP" for r in recs))
ok("... with the decoded JSON of each device", sorted(r["beacons"][0]["json"]["mac"] for r in recs) == sorted(x["mac"] for x in made[:6]))
# it is sent on to a manager (a hand-over names the person); then the manager opens it
it, err = fnd.set_status(fid, "management", "Please decide.", "rita", "researcher", to="max", is_manager=True)
ok("sent on to a manager", it is not None and "max" in it["participants"], err)
code, m = call("max", "GET", f"/api/beacon/finding/{fid}")
text = json.dumps(m)
ok("the manager gets counts and the selection", code == 200 and m["records"] == 6 and m["devices"] == 6 and m["reports"] == ["Sinkhole HTTP"]
   and {x["value"] for x in m["selection"]} == {"WT", "WT:1.0.0", "Windows"} and not m["held"])
ok("... the parts by their readable names, never their codes", "clogin" not in {x["value"] for x in m["selection"]}
   and all(x["value"] != "windows" for x in m["selection"]), str(m["selection"]))
ok("... and no record list", "records_list" not in m)
leak = [f for o in made for f in B.DEVICE_FIELDS if len(str(o[f])) > 4 and str(o[f]) in text] + [ip for ip in (e["src_ip"] for e in events) if ip in text]
ok("... and no address, MAC, UUID, cpuid, cpumd5 or memory", not leak, ",".join(leak))
ok("a researcher outside the channel gets nothing", call("rob", "GET", f"/api/beacon/finding/{fid}")[0] == 404)
ok("the researcher who sent it sees counts, no records", "records_list" not in call("rita", "GET", f"/api/beacon/finding/{fid}")[1])
code, m2 = call("max", "GET", f"/api/beacon/finding/{fid}?records=1")
ok("asking for the records without seeing hosts gives none", code == 200 and "records_list" not in m2 and not m2["can_records"])

print("3. Fewer than 5 devices: an analyst's hand-over to a manager")
code, j = call("ana", "POST", "/api/beacon/finding", {**HTM, "kind": "management", "to": "max"})
ok("an analyst may hand over a single device's beacon", code == 200, json.dumps(j))
fid2 = j["finding"]["id"]
ok("the title names no operator or version", "HTM" not in fnd.get(fid2)["title"] and "HTM" not in fnd.get(fid2)["text"], fnd.get(fid2)["title"])
code, m = call("max", "GET", f"/api/beacon/finding/{fid2}")
ok("the manager sees counts only, the selection held back", code == 200 and m["held"] and m["selection"] == [] and m["records"] == 1
   and "HTM" not in json.dumps(m) and "192.0.2.99" not in json.dumps(m))
code, a = call("ana", "GET", f"/api/beacon/finding/{fid2}?records=1")
ok("the analyst sees the record", code == 200 and len(a["records_list"]) == 1 and a["records_list"][0]["host"] == "192.0.2.99")

print("4. The path gate")
import auth  # noqa: E402
ok("researchers, management and advisors may reach it", any("/api/beacon/finding".startswith(p) or p.startswith("/api/beacon/finding") for p in auth.DEFINITIONS_PATHS)
   and "/api/beacon/finding/" in auth.MANAGEMENT_PATHS and "/api/beacon/finding/" in auth.ADVISORY_PATHS)
ok("Peace of mind closes it", "/api/beacon/" in auth.PEACE_CLOSED)
import data_access  # noqa: E402
ok("an analyst's view of the devices is in the audit log (data_access)", "/api/beacon/finding/<fid>" in data_access.SENSITIVE)

print("4. Beacon codes (LG-B): Move to notes, and a note sent on as a finding (the user, 2026-11-16)")
import combos as C  # noqa: E402
import notes as N  # noqa: E402
book = C.CodeBook(os.path.join(tmp, "combo_codes.json"))
made_sel = []                                   # the analyst selections asked for (acodes.make_selection stands in)


class ACodes:
    def make_selection(self, platform, evs, from_code, label, extra=None):
        made_sel.append({"platform": platform, "n": len(evs), "ips": {e["src_ip"] for e in evs}, "from": from_code, "label": label, "extra": extra})
        return f"LG-A-{len(made_sel):08X}"
os.makedirs(os.path.join(tmp, "data"), exist_ok=True)          # notes.py keeps data/notes.json
app2 = Flask("lgb")
BF.install(app2, {"store": store, "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}, "findings": fnd, "book": book,
                  "defined": lambda: {("infections", "android.badbox2"): "BADBOX 2.0"}, "acodes": ACodes(),
                  "has_perm": lambda p: p in g.user["perms"], "sees_hosts": lambda: "unmasked" in g.user["perms"],
                  "csrf_ok": lambda: g.user.get("tok") == "T", "fresh": lambda: True,
                  "audit": type("A", (), {"add": lambda self, *a, **k: audit.append((a, k))})()})
notes = N.install(app2, {"people": People(), "audit": type("A", (), {"add": lambda self, *a, **k: audit.append((a, k))})(),
                         "allowed": lambda: True, "change_allowed": lambda: "definitions" in g.user["perms"], "fresh": lambda: True,
                         "base_dir": tmp})
book.resolve = book.get
book.describe = lambda c: C.describe(book.get(c))
notes.codes, notes.findings = book, fnd


def call2(user, method, path, body=None):
    role, perms = ROLES[user]
    with app2.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": perms, "tok": "T"}
        ep, args = app2.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = app2.view_functions[ep](**args)
        r, code = (r if isinstance(r, tuple) else (r, 200))
        return code, r.get_json()


q = "/api/beacon/code?name=android.badbox2&os_family=windows"
code, r = call2("rita", "GET", q)
bcode = (r or {}).get("code", "")
ok("a researcher gets the code of a selection 7 devices carry, with what it stands for in words",
   code == 200 and C.ANY_RX.match(bcode) and bcode.startswith("LG-B-") and "say Windows" in r["text"] and r["devices"] == 7, str(r))
ok("... the same selection always has the same code", call2("rita", "GET", q)[1].get("code") == bcode)
ok("... and the code carries no address", "192.0.2." not in json.dumps(book.get(bcode)))
few_c = call2("rita", "GET", "/api/beacon/code?name=android.badbox2&operator=HTM")
none_c = call2("rita", "GET", "/api/beacon/code?name=android.badbox2&operator=NOPE")
ok("fewer than 5 devices: no code for a researcher, the same answer as nothing at all", few_c[0] == none_c[0] == 404 and few_c[1] == none_c[1],
   f"{few_c} / {none_c}")
ok("... an analyst, who sees the devices, gets it", call2("ana", "GET", "/api/beacon/code?name=android.badbox2&operator=HTM")[0] == 200)
ok("management gets no code (it decides, it does not drill down)", call2("max", "GET", q)[0] == 403)
ok("the code book says what it is, in words", C.describe(book.get(bcode)).startswith("Decoded beacons:") and "android.badbox2" in C.describe(book.get(bcode)))
code, r = call2("rita", "POST", "/api/notes", {"section": "infections", "name": "android.badbox2", "text": "Windows beacons under an Android name",
                                              "codes": [bcode], "finding": {"to": "max", "title": "Windows beacons under android.badbox2"}})
ok("the note carrying it is saved and sent on as a finding", code == 200 and r.get("saved"), str(r)[:200])
item = max(fnd.data["items"].values(), key=lambda x: int(x["id"]))
ok("the finding holds exactly that drill-down (the name and the OS), never a device",
   item.get("beacon") == {"name": "android.badbox2", "os_family": "windows"} and item.get("beacon_code") == bcode
   and "192.0.2." not in json.dumps(item), str(item.get("beacon")))
ok("... and its combination codes stay combination codes only", bcode not in item.get("codes", []))
item = fnd.get(item["id"])
ok("management's normal view: the finding carries an analyst selection of exactly its records (Show in Executive)",
   item.get("beacon_selection", "").startswith("LG-A-") and item["beacon_selection"] in item.get("codes", [])
   and made_sel and made_sel[-1]["n"] == 7 and made_sel[-1]["platform"] == "comms" and made_sel[-1]["from"] == bcode,
   f"{item.get('beacon_selection')} {made_sel[-1:] and {k: v for k, v in made_sel[-1].items() if k != 'ips'}}")
ok("... its label says what it is, with the finding's number",
   made_sel and made_sel[-1]["label"].startswith("BADBOX 2.0 beacons from Windows machines") and f"#{item['id']}" in made_sel[-1]["label"])
n_before = len(made_sel)
import beacon_findings  # noqa: E402
ok("... made once: asking again gives the same code, no second selection",
   beacon_findings.attach_selection(item["id"]) == item["beacon_selection"] and len(made_sel) == n_before)
code, r = call2("max", "GET", f"/api/beacon/finding/{item['id']}")
ok("the manager it went to opens it on the Findings page: counts and the selection", code == 200 and r["records"] == 7 and not r.get("records_list"), str(r)[:200])
import auth  # noqa: E402
ok("researchers' pages may reach the code (auth.py's list for their role, or Move to notes stays empty)",
   any("/api/beacon/code".startswith(p) for p in auth.DEFINITIONS_PATHS))
code, r = call2("rita", "POST", "/api/notes", {"section": "infections", "name": "android.badbox2", "text": "No title typed",
                                              "codes": [bcode], "finding": {"to": "max"}})
item2 = max(fnd.data["items"].values(), key=lambda x: int(x["id"]))
ok("no title typed: the finding reads at a glance for management and advisors",
   item2["title"] == "BADBOX 2.0 beacons from Windows machines (android.badbox2)", item2["title"])
ok("... a typed title wins", item["title"] == "Windows beacons under android.badbox2", item["title"])
ok("... and a title for parts held back names none of them",
   BF.finding_title({"name": "android.badbox2", "os_family": "windows"}, "BADBOX 2.0", held=True) == "BADBOX 2.0 decoded beacons (android.badbox2)")
ok("every beacon case gets a title that reads at a glance (OS, operator, format, generic decoding)",
   [BF.finding_title({"name": "android.badbox2", **s}, "BADBOX 2.0") for s in
    ({"operator": "WT"}, {"format": "clogin"}, {"format": "generic"})] ==
   ["BADBOX 2.0 beacons from operator WT (android.badbox2)", "BADBOX 2.0 CLogin check-in beacons (android.badbox2)",
    "BADBOX 2.0 values found by generic decoding (android.badbox2)"])
# a code worked out offline for a selection fewer than 5 devices carry: as unknown as any other (review of 373c1e2)
hcode = call2("ana", "GET", "/api/beacon/code?name=android.badbox2&operator=HTM")[1]["code"]      # an analyst records it
ghost = "LG-B-" + "0" * 8
saw = [call2(u, "POST", "/api/notes", {"section": "infections", "name": "android.badbox2", "text": "guess", "codes": [c]})
       for u, c in (("rita", hcode), ("rita", ghost))]
ok("a researcher attaching a recorded code of fewer than 5 devices gets exactly the answer for an unknown code",
   saw[0][0] == saw[1][0] == 400 and saw[0][1]["error"].replace(hcode, "X") == saw[1][1]["error"].replace(ghost, "X"), str(saw))
def visible_to(user, c):
    role, perms = ROLES[user]
    with app2.test_request_context("/"):
        g.user = {"user": user, "role": role, "perms": perms, "tok": "T"}
        return book.beacon_visible(c)


ok("... the code book's own rule says the same: hidden from a researcher, shown to an analyst; 5+ devices shown to both",
   visible_to("rita", hcode) is False and visible_to("ana", hcode) is True and visible_to("rita", bcode) is True)
ok("a paste of the code on the Combinations page is told where it is worked on",
   C.ANY_RX.match(bcode) and C.describe(book.get(bcode)) and N.CODE_RX.match(bcode))

print(f"\n{checks - len(fails)}/{checks} checks passed")
if fails:
    print("FAILED: " + "; ".join(fails))
    sys.exit(1)
