#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Analyst codes (acodes.py) on a throwaway Flask app with stand-ins for the code book, the findings and the days
(r91 coverage; made-up records, documentation addresses only):
- making a code: refused for roles that do not see addresses, in demo mode, without CSRF, after an old sign-in, without
  a title, a researcher or a selection, or with no records; the selection in words with every host replaced by a count
  (networks, reports, the time, several hosts); a services selection from its query; a day that cannot be read
- from a combination search: an expired search, no device, no title, no manager, records without a day; across reports
- reading: a malformed or unknown code, a code outside the reader's channel, a chain that loops (closed: admins
  only), the every-category section failing, the device counts per answering code, the analysts' list
- a CVE ticked on a code's page: each refusal (role, CSRF, code, no name, not an analyst code, no services devices,
  nobody carrying it, a beacon selection under 5 devices, records not readable) and the same code when ticked again
- the counts kept per key (the oldest dropped first) and worked out ahead after a start (stopped on request, one
  failing code never stopping the others)
No database, no server. Run: .venv/bin/python tests/check_cov_acodes.py"""
import json, logging, os, shutil, sys, tempfile, threading
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
    def __init__(self):
        self.lock, self.data, self.jobs = threading.RLock(), {}, {}

    def _load(self):
        pass

    def get(self, c):
        e = self.data.get(c)
        return dict(e, code=c) if e else None

    def put(self, c, e):
        self.data[c] = dict(e)

    def record(self, *a, **k):
        pass

    def describe(self, c):
        return "" if c.startswith("LG-B-") else f"made-up combination {c}"

    def own_job(self, jid):
        return self.jobs.get(jid)


class Day:
    def __init__(self, events):
        self.events = events


class Findings:
    asked_of = None

    def __init__(self):
        self.made, self.by_code = [], {}

    def recipient(self, role, to):
        return (to, "") if to in ("rachel", "kofi") else (None, f"Choose the {role} it goes to.")

    def create_analyst(self, code, section, label, title, text, me, role, to, to_role, ask=None):
        f = {"id": str(len(self.made) + 1), "title": title, "text": text, "status": "analyst", "user": me, "participants": [me, to], "at": 1_700_000_000}
        self.made.append(f)
        self.by_code[code] = f
        return f

    def of_code(self, c):
        return self.by_code.get(c)

    def sees(self, f, user, admin, strict=False):
        return admin or user in (f.get("participants") or [])

    def all_open(self):
        return [{"codes": list(self.by_code)}] + [{"codes": ["LG-A-BADBAD00", "not-a-code"]}]


COMMS = [{"id": f"c{i}", "src_ip": f"192.0.2.{i}", "infection": ("examplebot" if i % 2 else "samplerat"), "source": "event4_sinkhole",
          "extracted_date": "2026-11-13", "src_asn": 64500} for i in range(1, 9)]
SVC = [{"id": f"s{i}", "ip": f"198.51.100.{i}", "issues": ["CVE-2023-48795"] if i < 7 else ["openssl"], "report": "scan_ssh",
        "extracted_date": "2026-11-13", "tag": "ssh;openssl"} for i in range(1, 9)]
ROLE = {"r": "analyst", "u": "grace"}
PERMS = {"analyst": {"unmasked", "export"}, "researcher": {"definitions"}, "admin": {"settings", "unmasked", "export"}, "external": {"view"}}
FLAGS = {"demo": False, "csrf": True, "fresh": True, "cross_fail": False, "day_none": False}
audited = []
tmp = tempfile.mkdtemp(prefix="lg-cov-acodes-")
book, findings = Book(), Findings()


def cross(hosts, **kw):
    if FLAGS["cross_fail"]:
        raise RuntimeError("services index busy")
    return {"services": [{"combinations": [{"code": "LG-C-0000000S", "hosts": 3}, {"code": ""}]}], "cross": [{"code": "LG-X-0000000X", "hosts": 2}],
            "infections": [{"code": "LG-C-0000000I", "hosts": 4}], "issues": [{"code": ""}]}


def cross_hosts(hosts):
    by = {}
    for e in SVC:
        if e["ip"] in hosts:
            for i in e["issues"]:
                by.setdefault(i, set()).add(e["ip"])
    return {"days": ["2026-11-13"], "issues": [{"name": n, "ips": sorted(h)} for n, h in by.items()] + [{"name": "CVE-0000-0000", "ips": []}]}


ctx = {"book": book, "findings": findings, "base_dir": tmp, "is_demo": lambda: FLAGS["demo"], "csrf_ok": lambda: FLAGS["csrf"],
       "fresh": lambda: FLAGS["fresh"], "has_perm": lambda p: p in PERMS.get(ROLE["r"], set()),
       "audit": type("A", (), {"add": staticmethod(lambda *a, **k: audited.append((a, k)))})(),
       "day": lambda platform, iso: None if FLAGS["day_none"] else Day(COMMS if platform == "comms" else SVC),
       "slice": lambda day, kind, value: (None, None, [e for e in day.events if kind != "none" and (kind != "infection" or e["infection"] == value)]),
       "svc_scope": lambda args, day: [e for e in day.events if not args.get("issue") or args.get("issue") in e["issues"]],
       "labels": lambda: {"event4_sinkhole": "Devices calling sinkholes"}, "network": lambda a: "Example Telecom" if str(a) == "64500" else "",
       "defined": lambda: {("infections", "examplebot"): "A made-up bot"}, "people_name": lambda u: u.title(),
       "cross": cross, "cross_hosts": cross_hosts}
app = Flask(__name__)
app.logger.setLevel(logging.CRITICAL)


@app.before_request
def _who():
    g.user = {"user": ROLE["u"], "role": ROLE["r"], "perms": PERMS.get(ROLE["r"], set())}


api = acodes.install(app, ctx)
api.paths["ids"] = os.path.join(tmp, "acodes")
c = app.test_client()
try:
    print("Making an analyst code")
    new = lambda b: c.post("/api/analyst-codes", json=b)
    good = {"platform": "comms", "kind": "filters", "value": "src_asn=64500&source=event4_sinkhole&time=600%2B60&src_ip=192.0.2.1&src_ip=192.0.2.3&n=5&infection=examplebot",
            "title": "Bots in one network", "text": "made-up note", "to": "rachel", "at": "2026-11-13T10:00:00Z"}
    ROLE["r"] = "researcher"
    ok("a role that does not see addresses: 403", new(good).status_code == 403)
    ROLE["r"] = "analyst"
    for flag, val, label in (("demo", True, "demo mode on"), ("csrf", False, "no CSRF token"), ("fresh", False, "an old sign-in")):
        FLAGS[flag] = val
        ok(f"{label}: 403", new(good).status_code == 403)
        FLAGS[flag] = not val if flag != "demo" else False
    ok("no title: 400", new(dict(good, title=" ")).status_code == 400)
    ok("no researcher named: 400", "researcher" in new(dict(good, to="nobody")).json["error"])
    ok("no selection: 400", new(dict(good, kind="")).status_code == 400)
    ok("a selection with no records that day: 400", "no records" in new(dict(good, kind="none")).json["error"])
    r = new(good)
    j = r.json or {}
    ok("made: a code, a finding, the records and hosts counted", r.status_code == 200 and acodes.ACODE_RX.match(j.get("code", ""))
       and j["finding"] == "#1" and j["records"] == 8 and j["hosts"] == 8 and j["to"] == "Rachel", str(j))
    ok("…the selection in words: network named, report named, the time, the hosts held back as a count",
       j.get("label") == "Source network: Example Telecom (AS64500) · Report: Devices calling sinkholes · Time: from 10:00 UTC · "
                         "Infection: examplebot · 2 hosts (addresses held back)", j.get("label"))
    ok("…no address anywhere in the answer", "192.0.2." not in json.dumps(j))
    CODE1 = j.get("code", "")
    r = new(dict(good, value="infection=examplebot&time=late&src_ip=192.0.2.1", at="not a time", focus="across"))
    ok("a time that is not a number kept as written; one host; a day that cannot be read is today; across reports asked",
       r.status_code == 200 and "Time: late" in r.json["label"] and r.json["label"].endswith("1 host (address held back)")
       and book.get(r.json["code"])["focus"] == "across")
    ok("…the finding says what was asked", findings.asked_of(r.json["code"]) == acodes.ASKED["across"] and findings.asked_of(CODE1) == acodes.ASKED["everything"]
       and findings.asked_of("not-a-code") == "")
    r = new(dict(good, kind="infection", value="samplerat"))
    ok("a single-kind selection (Infection: samplerat)", r.status_code == 200 and r.json["label"] == "Infection: samplerat" and r.json["records"] == 4)
    r = new({"platform": "services", "query": "issue=CVE-2023-48795&ip=198.51.100.1&demo=1", "title": "SSH hosts", "to": "rachel"})
    ok("a services selection from its query: the hosts held back", r.status_code == 200 and r.json["records"] == 6
       and r.json["label"] == "Issue: CVE-2023-48795 · 1 host (address held back)", str(r.json))
    SCODE = r.json.get("code", "")
    r = new({"platform": "services", "query": "", "title": "everything", "to": "rachel"})
    ok("a services selection of nothing in particular: the whole day", r.status_code == 200 and r.json["label"] == "Whole day, all services")

    print("From a combination search")
    fs = lambda jid, b: c.post(f"/api/combos/search/{jid}/acode", json=b)
    ROLE["r"] = "external"
    ok("not an analyst: 403", fs("j1", {}).status_code == 403)
    ROLE["r"] = "analyst"
    for flag, val in (("demo", True), ("csrf", False), ("fresh", False)):
        FLAGS[flag] = val
        ok(f"{flag} refused: 403", fs("j1", {}).status_code == 403)
        FLAGS[flag] = not val if flag != "demo" else False
    ok("an expired search: 404", fs("gone", {}).status_code == 404)
    book.jobs["empty"] = {"inputs": [{"code": "LG-C-0000ABCD", "section": "infections"}, []]}
    ok("a search that found no device: 400", fs("empty", {"title": "t"}).status_code == 400)
    book.jobs["j1"] = {"inputs": [{"code": "LG-C-0000ABCD", "section": "infections"}, COMMS[:4]]}
    ok("no title: 400", fs("j1", {"title": ""}).status_code == 400)
    ok("no manager named: 400", fs("j1", {"title": "t", "to": "x"}).status_code == 400)
    book.jobs["noday"] = {"inputs": [{"code": "LG-C-0000ABCD", "platform": "comms"}, [{"src_ip": "192.0.2.1"}]]}
    ok("records without a day: 400", fs("noday", {"title": "t", "to": "kofi"}).status_code == 400)
    r = fs("j1", {"title": "Across reports, please", "to": "kofi", "focus": "across"})
    ok("made from the search: its days, its devices, to the manager", r.status_code == 200 and r.json["days"] == ["2026-11-13"]
       and r.json["hosts"] == 4 and "made-up combination LG-C-0000ABCD" in r.json["label"])
    FCODE = r.json.get("code", "")

    print("Reading a code")
    ROLE.update(r="researcher", u="rachel")
    ok("a malformed code: 400", c.get("/api/intel/acode/LG-A-xyz").status_code == 400)
    ok("an unknown code: 404", c.get("/api/intel/acode/LG-A-00000000").status_code == 404)
    v = c.get(f"/api/intel/acode/{CODE1.lower()}").json
    ok("the researcher of the channel reads it (any case): names, definitions, no address",
       v["code"] == CODE1 and {n["name"] for n in v["names"]} == {"examplebot", "samplerat"}
       and next(n for n in v["names"] if n["name"] == "examplebot")["defined"] == "A made-up bot" and "192.0.2." not in json.dumps(v))
    ok("…the every-category section from the services index", v["cross"]["cross"][0]["code"] == "LG-X-0000000X")
    FLAGS["cross_fail"] = True
    v = c.get(f"/api/intel/acode/{CODE1}").json
    ok("the every-category section failing: the page still shows the selection", v["cross"] is None and v["records"] == 8)
    FLAGS["cross_fail"] = False
    ROLE.update(r="researcher", u="ama")
    ok("a researcher outside the channel: 404 (reading and counts)", c.get(f"/api/intel/acode/{CODE1}").status_code == 404
       and c.get(f"/api/intel/acode/{CODE1}/devices").status_code == 404)
    ROLE.update(r="external", u="x")
    ok("a role that reads no codes: 403 (reading, counts, ticking)", c.get(f"/api/intel/acode/{CODE1}").status_code == 403
       and c.get(f"/api/intel/acode/{CODE1}/devices").status_code == 403 and c.post(f"/api/intel/acode/{CODE1}/issue", json={"name": "x"}).status_code == 403)
    ok("…and its list: 403", c.get("/api/analyst-codes").status_code == 403)
    ROLE.update(r="researcher", u="rachel")
    d = c.get(f"/api/intel/acode/{CODE1}/devices").json["devices"]
    ok("the device counts: the code with all its devices, every answering code with its own count, held-back codes not listed",
       d[CODE1] == 8 and d.get("LG-C-0000000S") == 3 and d.get("LG-X-0000000X") == 2 and d.get("LG-C-0000000I") == 4 and "" not in d, str(d))
    # a code whose chain loops (no finding anywhere): closed, only admins open it
    book.put("LG-A-10000001", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"from_code": "LG-A-10000002"}, "label": "loop 1"})
    book.put("LG-A-10000002", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"from_code": "LG-A-10000001"}, "label": "loop 2"})
    ok("a chain that loops: closed to a researcher", c.get("/api/intel/acode/LG-A-10000001").status_code == 404)
    book.put("LG-A-10000003", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"from_code": "LG-A-0FFFFFFF"}, "label": "orphan"})
    ok("a parent code no longer kept: closed too", c.get("/api/intel/acode/LG-A-10000003").status_code == 404)
    ROLE.update(r="admin", u="root-admin")
    v = c.get("/api/intel/acode/LG-A-10000001").json
    ok("…an administrator opens it; its records come from the selection, not kept ids (from a code: none)", v["records"] == 0 and v["chain"])
    lst = c.get("/api/analyst-codes").json["codes"]
    ok("the admin's list: every code, the closed ones without a finding", any(x["code"] == "LG-A-10000001" and x["finding"] is None for x in lst)
       and any(x["code"] == CODE1 and x["finding"]["by"] == "Grace" for x in lst))
    # a chain with a hidden step: a beacon code the viewer may not see described, and a finding of someone else's channel
    book.put("LG-B-0000000B", {"kind": "b", "day": "2026-11-13"})
    book.put("LG-A-20000001", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"from_code": "LG-A-20000002"}})
    book.put("LG-A-20000002", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"from_code": "LG-B-0000000B"}})
    findings.by_code["LG-A-20000001"] = {"id": "90", "participants": ["rachel"], "title": "t", "text": "", "status": "open", "user": "rachel"}
    findings.by_code["LG-A-20000002"] = {"id": "91", "participants": ["someone-else"], "title": "t", "text": "", "status": "open", "user": "x"}
    ROLE.update(r="researcher", u="rachel")
    with app.test_request_context("/"):
        g.user = {"user": "rachel", "role": "researcher", "perms": PERMS["researcher"]}
        ch = api.chain("LG-A-20000001")
    ok("the chain: a beacon code not named at all, another channel's code named but hidden", ch == [{"code": "", "hidden": True, "held": True},
                                                                                                  {"code": "LG-A-20000002", "hidden": True}], str(ch))

    print("A CVE ticked on a code's page")
    tick = lambda code, b: c.post(f"/api/intel/acode/{code}/issue", json=b)
    FLAGS["csrf"] = False
    ok("without CSRF: 403", tick(SCODE, {"name": "CVE-2023-48795"}).status_code == 403)
    FLAGS["csrf"] = True
    ok("a malformed code: 404", tick("LG-A-ZZ", {"name": "x"}).status_code == 404)
    ok("no name: 400", tick(SCODE, {"name": ""}).status_code == 400)
    book.put("LG-A-30000001", {"kind": "c", "sel": {}})
    ROLE.update(r="admin", u="root-admin")
    ok("a code that is not an analyst code: 404", tick("LG-A-30000001", {"name": "x"}).status_code == 404)
    ROLE.update(r="researcher", u="rachel")
    r = tick(SCODE, {"name": "CVE-2023-48795"})
    ok("ticked: a code for the devices carrying it", r.status_code == 200 and r.json["hosts"] == 6, str(r.json))
    r2 = tick(SCODE, {"name": "CVE-2023-48795"})
    ok("…ticked again: the same code", r2.json.get("code") == r.json.get("code"))
    ok("nobody in the selection carries it: 409", tick(SCODE, {"name": "CVE-0000-0000"}).status_code == 409)
    ok("a CVE not in the index at all: 409", tick(SCODE, {"name": "CVE-1999-0001"}).status_code == 409)
    book.put("LG-A-40000001", {"kind": "a", "platform": "services", "day": "2026-11-13", "sel": {"query": [], "beacon": {"x": 1}}, "label": "beacons"})
    findings.by_code["LG-A-40000001"] = {"id": "40", "participants": ["rachel"], "title": "b", "text": "", "status": "open", "user": "rachel"}
    os.makedirs(api.paths["ids"], exist_ok=True)
    with open(os.path.join(api.paths["ids"], "LG-A-40000001.json"), "w") as fh:
        json.dump(["s7", "s8"], fh)
    r = tick("LG-A-40000001", {"name": "openssl"})
    ok("a beacon selection narrowed below 5 devices for a viewer who does not see hosts: 409, held", r.status_code == 409
       and r.json["error"] == acodes.small_codes.HELD, str(r.json))
    book.put("LG-A-50000001", {"kind": "a", "platform": "comms", "day": "2026-11-13", "sel": {"kind": "none", "value": ""}, "label": "empty"})
    findings.by_code["LG-A-50000001"] = {"id": "50", "participants": ["rachel"], "title": "e", "text": "", "status": "open", "user": "rachel"}
    ok("a selection with no devices: 409", tick("LG-A-50000001", {"name": "CVE-2023-48795"}).status_code == 409)
    saved_ch = ctx["cross_hosts"]
    ctx["cross_hosts"] = lambda hosts: {"days": ["2026-11-14"], "issues": [{"name": "CVE-2023-99999", "ips": ["198.51.100.99"]}]}
    r = tick(SCODE, {"name": "CVE-2023-99999"})
    ok("the index names devices whose records cannot be read just now: 409, try again", r.status_code == 409 and "try again" in r.json["error"])
    ctx["cross_hosts"] = saved_ch

    print("Records, counts kept, counts worked out ahead")
    FLAGS["day_none"] = True
    ok("a code whose day cannot be loaded: no records", api.records(book.get(CODE1) | {"code": "LG-A-60000000"}) == [])
    FLAGS["day_none"] = False
    e1 = dict(book.get(CODE1), code=CODE1)
    first = api.records(e1)
    ok("its kept records, then the same from the few minutes' cache", len(first) == 8 and api.records(e1) == first)
    ok("a code made from a search, with no kept records: none", api.records({"code": "LG-A-0000FFFF", "platform": "comms", "day": "2026-11-13",
                                                                            "sel": {"from_code": "LG-C-1"}}, day=Day(COMMS)) == [])
    pk = acodes.PerKeyCache(ttl=600, size=2)
    calls = []
    for k in ("a", "b", "a", "c"):
        pk.get(k, lambda k=k: calls.append(k) or k.upper())
    ok("counts kept per key: asked again, not worked out again; the oldest put in dropped when full",
       calls == ["a", "b", "c"] and list(pk.cache) == ["b", "c"], str((calls, list(pk.cache))))
    book.put("LG-A-BADBAD00", {"kind": "a", "platform": "comms", "sel": {}})       # broken: no day, its count fails
    n = api.warm(stop=lambda: True)
    ok("worked out ahead: stops when asked", n == 0)
    n = api.warm()
    ok("…every open finding's code at both viewer levels (a code that fails does not stop the others)", n >= 2 and api.cached(CODE1, True) and api.cached(CODE1, False))
    ok("describe: the day and the platform in words", api.describe({"day": "2026-11-13", "platform": "services", "label": "x"}).startswith("Analyst selection on 2026-11-13 (services)"))
    ok("day span of a code from a search", acodes.day_span({"days": ["2026-11-10", "2026-11-13"]}) == "2026-11-10 to 2026-11-13")
    ok("a selection of no records makes no code", api.make_selection("comms", [], "LG-A-1", "x") is None)
    ROLE.update(r="analyst", u="grace")
    again = new(good).json.get("code")
    ok("the made codes are all distinct; the same selection asked again gets a code of its own", len({CODE1, FCODE, SCODE}) == 3
       and again not in (CODE1, None) and book.get(again)["label"] == book.get(CODE1)["label"], str(again))
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
