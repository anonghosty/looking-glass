#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase audit of 2026-11-27, batch 03 (connectors, the connectors' sender, the beacon findings, the code
check, the Malpedia batch), each finding kept fixed. In-process, made-up data, temporary folders: no database, no
network (the platforms, the probe and MongoDB are faked).
  3-1  /api/connectors/test sends a saved key only to that target's own platform and address
  3-2  the sender reads the kept beacon summaries (a list of [field, value] pairs) without stopping
  3-3  a failed revocation of a purged day is tried again; purged days older than the back-fill window are revoked
  3-5  "created_by" of a target is the full name, else the person code, never the sign-in name
  3-7  approving a file kept as ours writes no false "no longer in the code folder" entry
  3-8  beacon finding summary: exact days only for viewers who see hosts, a day count for everyone
  3-9  an LG-B code's "5 or more devices" answer is not scanned again while the days in memory stay the same
  3-10 MISP's ATT&CK summary says each technique's own status (not always "suggested")
  3-11 the Malpedia batch's names are made unique in linear time
  3-12 the Audit portal's Data sent out: a day is the UTC day whatever the server's time zone (summer time)
Run: .venv/bin/python tests/check_fix_b03.py   (LG_FIX_ROOT=<folder> runs it against another copy of the code)"""
import calendar
import datetime as dt
import json
import os
import re
import sys
import tempfile
import time
import types

ROOT = os.environ.get("LG_FIX_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_QUIET", "1")
os.environ["CONNECTOR_KEY_SECRET"] = "ab" * 32
if not os.environ.get("LG_PERSON_CODE_DIR"):
    os.environ["LG_PERSON_CODE_DIR"] = tempfile.mkdtemp(prefix="lg-b03-pc-")

from flask import Flask, g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{str(info)[:400]}]"), flush=True)
    if not cond:
        fails.append(label)


def section(title, fn):
    """A section that raises counts as one failed check, so the rest still run (the old code crashes on some)."""
    print(title)
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        ok(f"{title}: ran without an error", False, f"{type(e).__name__}: {e}")


TMP = tempfile.mkdtemp(prefix="lg-b03-")


# ------------------------------------------------------------------ connectors.py (3-1, 3-5, 3-12)
def connectors_app():
    import connectors as C
    base = tempfile.mkdtemp(dir=TMP)
    os.makedirs(os.path.join(base, "data"))
    app = Flask(__name__)
    app.config["TESTING"] = True

    @app.before_request
    def _who():
        g.user = {"user": "ada.admin", "role": "admin"}

    class Audit:
        def add(self, *a, **k):
            pass
    api = C.install(app, {"base_dir": base, "audit": Audit(), "has_perm": lambda p: True, "csrf_ok": lambda: True,
                          "fresh": lambda: True, "settings": None,
                          "people_name": lambda u: {"ada.admin": "Ada Admin"}.get(u, "")})
    api["paths"]["log"] = os.path.join(base, "data", "connectors_log.jsonl")
    return C, app, api


def s_3_1():
    C, app, api = connectors_app()
    addr = "https://opencti.lab.test/taxii2/root/collections/c1/objects/"
    api["targets"].save("abcd1234", {"name": "Lab OpenCTI", "kind": "opencti", "address": addr, "tlp": "amber", "on": False,
                                     "scope": {}, "created": 1, "created_by": "ada.admin"})
    api["vault"].put("abcd1234", "the-saved-key")
    probed = []
    real = C.probe
    C.probe = lambda kind, address, key, tlp, send_test=True: (probed.append((kind, address, key)), (True, []))[1]
    try:
        c = app.test_client()
        r = c.post("/api/connectors/test", json={"kind": "opencti", "address": "https://elsewhere.example/taxii2/x/", "tlp": "amber",
                                                 "id": "abcd1234"})
        ok("3-1 a saved target's id with ANOTHER address: refused, the saved key sent nowhere",
           r.status_code == 400 and not any(k == "the-saved-key" for _, _, k in probed), (r.status_code, probed))
        probed.clear()
        r = c.post("/api/connectors/test", json={"kind": "misp", "address": addr, "tlp": "amber", "id": "abcd1234"})
        ok("3-1 ...another platform at the same address: refused too",
           r.status_code == 400 and not probed, (r.status_code, probed))
        r = c.post("/api/connectors/test", json={"kind": "opencti", "address": addr, "tlp": "amber", "id": "abcd1234"})
        ok("3-1 ...its own address and platform: tested again with its own key",
           r.status_code == 200 and probed == [("opencti", addr, "the-saved-key")], (r.status_code, probed))
        probed.clear()
        r = c.post("/api/connectors/test", json={"kind": "opencti", "address": "https://elsewhere.example/taxii2/x/", "tlp": "amber",
                                                 "key": "a-typed-key"})
        ok("3-1 ...a key typed in: tested at any allowed address, as before",
           r.status_code == 200 and probed == [("opencti", "https://elsewhere.example/taxii2/x/", "a-typed-key")], probed)
    finally:
        C.probe = real


def s_3_5():
    C, app, api = connectors_app()
    for tid, who in (("aaaa0001", "ada.admin"), ("aaaa0002", "bob.smith")):
        api["targets"].save(tid, {"name": tid, "kind": "misp", "address": "https://misp.lab.test", "tlp": "amber", "on": False,
                                  "scope": {}, "created": int(tid[-1]), "created_by": who})
    j = app.test_client().get("/api/connectors").get_json() or {}
    by = {t["id"]: t["created_by"] for t in j.get("targets", [])}
    ok("3-5 created_by: the full name when there is one", by.get("aaaa0001") == "Ada Admin", by)
    ok("3-5 ...else the person code: never the sign-in name", by.get("aaaa0002") and by["aaaa0002"] != "bob.smith"
       and "bob.smith" not in json.dumps(j), by)


def s_3_12():
    C, app, api = connectors_app()
    old_tz = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/London"
    time.tzset()
    try:
        inside = calendar.timegm((2026, 7, 1, 23, 30, 0))       # 1 July, 23:30 UTC: that day
        before = calendar.timegm((2026, 6, 30, 23, 30, 0))      # 30 June, 23:30 UTC: the day before
        with open(api["paths"]["log"], "w", encoding="utf-8") as f:
            for at, day in ((inside, "in"), (before, "out")):
                f.write(json.dumps({"at": at, "target": "x", "day": day, "status": "sent", "devices": 1, "objects": 1}) + "\n")
        j = app.test_client().get("/api/audit/connectors?from=2026-07-01&to=2026-07-01").get_json() or {}
        got = sorted(e["day"] for e in j.get("events", []))
        ok("3-12 a server on summer time: 1 July is 1 July UTC (23:30 UTC in, 23:30 UTC the day before out)", got == ["in"], got)
    finally:
        if old_tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old_tz
        time.tzset()


# ------------------------------------------------------------------ connectors_worker.py (3-2, 3-3)
class Col:
    def __init__(self, docs):
        self.docs = docs

    def find(self, q, fields=None):
        out = []
        for d in self.docs:
            if "filename" in q and not re.match(q["filename"]["$regex"], d.get("filename", "")):
                continue
            if "$or" in q:
                ips = set(q["$or"][0]["src_ip"]["$in"])
                if d.get("src_ip") not in ips and d.get("ip") not in ips:
                    continue
            out.append(dict(d))
        return out

    def count_documents(self, q):
        return len(self.find(q))


class DB:
    def __init__(self, cols):
        self.cols = cols

    def list_collection_names(self):
        return list(self.cols)

    def __getitem__(self, k):
        return self.cols.setdefault(k, Col([]))


def s_3_2():
    import beacon_keep
    import connectors_worker as W
    url, host = "GET /c.php?id=x HTTP/1.1", "c2.example"
    db = DB({"event4_sinkhole_http": Col([{"filename": "2026-11-23-event4_sinkhole_http.csv", "src_ip": "198.18.144.7", "src_asn": 64514,
                                            "timestamp": "2026-11-23 10:00:00", "infection": "m0yv", "http_url": url, "http_host": host}])})
    # as beacon_keep.SummaryStore.flush writes it: one summary per key, as [field, value] pairs
    kept = {beacon_keep.key_of(url, host): [["format", "CLogin check-in"], ["id", "clogin"], ["operator", ""], ["os_family", ""],
                                             ["state", "decoded"], ["version", ""]],
            beacon_keep.key_of("GET /other HTTP/1.1", host): []}
    out = W.devices_of(db, ["event4_sinkhole_http"], "2026-11-23", lambda asn, ip: True, TMP, kept)
    b = out["198.18.144.7"]["reports"]["event4_sinkhole_http"]["beacons"]
    ok("3-2 a device with a kept beacon summary: read as one beacon (family, format), the sender does not stop",
       [tuple(x) for x in b] == [("clogin", "CLogin check-in")], b)


def s_3_3():
    import auth
    import connector_net as net
    import connector_payload as cp
    import connectors as C
    import connectors_worker as W
    import pymongo
    base = tempfile.mkdtemp(dir=TMP)
    data = os.path.join(base, "data")
    os.makedirs(data)
    today = dt.datetime.now(dt.timezone.utc).date()
    d_old = (today - dt.timedelta(days=45)).isoformat()      # older than the 30-day back-fill: where the purge removes days
    d_in = (today - dt.timedelta(days=10)).isoformat()
    with open(os.path.join(data, "connectors.json"), "w", encoding="utf-8") as f:
        json.dump({"targets": {"t1": {"name": "Lab MISP", "kind": "misp", "address": "https://misp.lab.test", "tlp": "amber", "on": True,
                                      "scope": {"networks": {"64514": "whole"}}, "turned_on": time.time() - 60 * 86400}}}, f)
    with open(os.path.join(data, "connectors_state.json"), "w", encoding="utf-8") as f:
        json.dump({"t1": {"days": {d_old: {"sig": "a", "objects": {"event": "ev-old"}, "devices": 1},
                                   d_in: {"sig": "b", "objects": {"event": "ev-in"}, "devices": 1}}, "fails": 0}}, f)
    os.environ["LG_TARGET_T1_KEY"] = "made-up-key"
    STATUS, CALLS = [500], []

    def fake_request(method, url, headers=None, body=None):
        CALLS.append((method, url))
        return STATUS[0], b"{}", {}

    class FakeAudit:
        def __init__(self, *a, **k):
            pass

        def add(self, *a, **k):
            pass
    saved = (net.request, C.probe, cp.know_from, pymongo.MongoClient, auth.Audit, sys.modules.get("advisory"), sys.modules.get("db_connect"))
    net.request = fake_request
    C.probe = lambda *a, **k: (True, [])
    cp.know_from = lambda *a, **k: {"facts": {}, "amap": {}, "attack": {}, "kb": {}, "flags": {}, "impact": None, "org": "X"}
    pymongo.MongoClient = lambda *a, **k: {os.environ.get("MONGO_DB", "shadowserver"): DB({"scan_http": Col([])})}
    auth.Audit = FakeAudit
    sys.modules["advisory"] = types.SimpleNamespace(Impact=lambda b: None)
    sys.modules["db_connect"] = types.SimpleNamespace(kwargs=lambda get: {})

    def days():
        with open(os.path.join(data, "connectors_state.json"), encoding="utf-8") as f:
            return set(json.load(f)["t1"]["days"])
    try:
        W.run(base_dir=base, log=lambda *a: None)
        ok("3-3 a revocation that fails (MISP answers 500): the day is kept, to be tried again",
           d_in in days() and d_old in days(), days())
        STATUS[0] = 200
        CALLS.clear()
        W.run(base_dir=base, log=lambda *a: None)
        asked = {u.rsplit("/", 1)[-1] for m, u in CALLS if "/events/delete/" in u}
        ok("3-3 ...the next run revokes it (the event deleted) and forgets it", "ev-in" in asked and d_in not in days(), (asked, days()))
        ok("3-3 a purged day older than the back-fill window: revoked too (the purge removes exactly such days)",
           "ev-old" in asked and d_old not in days(), (asked, days()))
    finally:
        net.request, C.probe, cp.know_from, pymongo.MongoClient, auth.Audit = saved[:5]
        for name, mod in (("advisory", saved[5]), ("db_connect", saved[6])):
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        os.environ.pop("LG_TARGET_T1_KEY", None)


# ------------------------------------------------------------------ connector_payload.py (3-10)
def s_3_10():
    import connector_payload as cp
    know = {"facts": {}, "attack": {"techniques": {"T1071.001": {"name": "Web Protocols"}}}, "kb": {}, "flags": {}, "impact": None, "org": "X",
            "amap": {"event4_sinkhole_http": {"techniques": ["T1071.001"], "status": "reviewed", "certainty": "observed", "why": "C2"},
                     "scan_http": {"techniques": ["T1071.001"], "status": "check", "certainty": "possible"}}}
    rep = {"count": 1, "first": "2026-11-23T10:00:00.000Z", "last": "2026-11-23T10:00:00.000Z", "infections": [], "tags": [],
           "beacons": [], "cves": [], "days_seen": 1, "first_reported": "2026-11-23"}
    devs = [{"ip": "198.18.144.7", "asn": 64514, "reports": {"event4_sinkhole_http": dict(rep)}}]
    md = cp.misp_event(devs, "2026-11-23", "amber", know, "t1")["Event"]["EventReport"][0]["content"]
    summary = md.split("## Devices")[0]
    ok("3-10 MISP summary: a reviewed technique says reviewed, not 'suggested'",
       "suggested" not in summary and "T1071.001 Web Protocols (reviewed)" in summary, summary)
    note = cp.note_text("198.18.144.7", "2026-11-23", "HTTP scan", "services", rep, [], know, "scan_http")
    ok("3-10 a mapping to check reads 'please check' (attack_map's words)", "ATT&CK (please check, possible)" in note, note)


# ------------------------------------------------------------------ code_integrity.py (3-7)
def s_3_7():
    import code_integrity as CI
    base = tempfile.mkdtemp(dir=TMP)
    os.makedirs(os.path.join(base, "data"))
    os.makedirs(os.path.join(base, "tools"))
    with open(os.path.join(base, "tools", "kept.py"), "w") as f:
        f.write("# kept as ours\n")
    state = {"decided": {"platform/tools/kept.py": {"sha256": "a" * 64, "by": "ada.admin"},
                         "platform/tools/moved.py": {"sha256": "b" * 64, "by": "ada.admin"},
                         "database/x.py": {"sha256": "c" * 64, "by": "ada.admin"}}}
    with open(os.path.join(base, "data", CI.STATE), "w") as f:
        json.dump(state, f)
    AUD = []

    class Audit:
        def add(self, event, **k):
            AUD.append((event, k.get("target")))
    real = CI.scan
    # kept.py approved as ours (still there, no longer flagged); moved.py moved out; the database folder not checked
    CI.scan = lambda b: {"checked": True, "why": "", "problem": "", "findings": [],
                         "parts": {"platform": {"checked": True, "why": "", "files": 1, "folder": base},
                                   "database": {"checked": False, "why": "list not trusted", "files": 0, "folder": os.path.join(base, "nope")}}}
    try:
        st = CI.check(base, Audit())
    finally:
        CI.scan = real
    removed = {t for e, t in AUD if e == "code_integrity_removed"}
    ok("3-7 a file kept as ours (still in the folder): no 'no longer in the code folder' entry", "platform/tools/kept.py" not in removed, AUD)
    ok("3-7 ...a file really moved out: recorded as before", "platform/tools/moved.py" in removed, AUD)
    ok("3-7 ...a folder not checked this time: its decision kept, nothing recorded",
       "database/x.py" not in removed and "database/x.py" in (st.get("decided") or {}), (AUD, st.get("decided")))


# ------------------------------------------------------------------ beacon_findings.py (3-8, 3-9)
def beacon_setup():
    import beacon_findings as BF

    class Day:
        def __init__(self, start, events):
            self.start, self.events = start, events
    days = {}
    for i in range(3):
        start = dt.datetime(2026, 11, 20 + i, tzinfo=dt.timezone.utc)
        days[start.date().isoformat()] = Day(start, [{"infection": "fam", "src_ip": f"198.18.144.{i * 3 + k}", "source": "event4_sinkhole_http",
                                                       "http_url": "GET /x?id=1 HTTP/1.1"} for k in range(3)])
    store = types.SimpleNamespace(days=days)

    class Book:
        def get(self, code):
            return {"kind": "b", "name": "fam", "beacon": {}} if code == "LG-B-0000AAAA" else None
    book = Book()
    ctx = {"store": store, "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP Events"}, "findings": None,
           "has_perm": lambda p: False, "sees_hosts": lambda: False, "csrf_ok": lambda: True, "fresh": lambda: True,
           "audit": None, "book": book}
    return BF, ctx, book, store, Day


def s_3_8():
    BF, ctx, book, store, Day = beacon_setup()
    real = BF.matches
    BF.matches = lambda e, sel: {"format": "x"} if e.get("infection") == sel["name"] else None
    try:
        bf = BF.BeaconFindings(ctx)
        masked = bf.summary({"name": "fam"}, False)
        full = bf.summary({"name": "fam"}, True, records=False)
    finally:
        BF.matches = real
    dates = re.compile(r"\d{4}-\d{2}-\d{2}")
    ok("3-8 a viewer who does not see hosts: no exact day in the summary, only how many",
       not dates.search(json.dumps(masked.get("days"))) and masked.get("day_count") == 3, masked)
    ok("3-8 ...a viewer who sees hosts: the days as before", full.get("days") == ["2026-11-20", "2026-11-21", "2026-11-22"], full)


def s_3_9():
    BF, ctx, book, store, Day = beacon_setup()
    bf = BF.install(Flask(__name__), ctx)
    scans = []
    real = bf.scan
    bf.scan = lambda sel, want: (scans.append(1), real(sel, want))[1]
    realm = BF.matches
    BF.matches = lambda e, sel: {"format": "x"} if e.get("infection") == sel["name"] else None
    try:
        a = book.beacon_visible("LG-B-0000AAAA")
        b = book.beacon_visible("LG-B-0000AAAA")
        ok("3-9 the same LG-B code asked twice, the days unchanged: one scan, the same answer", a is True and b is True and len(scans) == 1,
           (a, b, len(scans)))
        store.days["2026-11-23"] = Day(dt.datetime(2026, 11, 23, tzinfo=dt.timezone.utc), [])
        book.beacon_visible("LG-B-0000AAAA")
        ok("3-9 ...a day added to memory: worked out again", len(scans) == 2, len(scans))
        ok("3-9 ...an unknown code: not visible", book.beacon_visible("LG-B-FFFFFFFF") is False)
    finally:
        BF.matches = realm


# ------------------------------------------------------------------ card_notes.py (3-11)
def s_3_11():
    import flask

    import card_notes as CN
    app = Flask(__name__)
    asked = []
    fake = types.SimpleNamespace(AUTH={"has_perm": lambda p: True}, request=flask.request, jsonify=flask.jsonify,
                                 is_demo=lambda: False, mp_resolve=lambda v: (asked.append(v), ({"found": False}, {}))[1],
                                 security=types.SimpleNamespace(public_error=lambda e, d="": str(e)),
                                 malpedia=types.SimpleNamespace(enabled=False))
    CN.install(app, fake)
    c = app.test_client()
    j = c.get("/api/malpedia/batch?values=A,%20a%20,b,,B,c").get_json() or {}
    ok("3-11 the batch's names: once each (any case), in order", asked == ["A", "b", "c"] and j.get("looked_up") == 3, (asked, j))
    asked.clear()
    vals = ",".join(f"n{i}" for i in range(20000))
    t = time.time()
    r = c.get("/api/malpedia/batch", query_string={"values": vals})
    took = time.time() - t
    ok("3-11 ...a list of 20,000 names: refused (at most 80) in linear time, nothing looked up",
       r.status_code == 400 and not asked and took < 1.5, (r.status_code, len(asked), round(took, 2)))


for title, fn in (("1. /api/connectors/test and a saved key (3-1)", s_3_1), ("2. who added a target (3-5)", s_3_5),
                  ("3. Data sent out, the UTC day (3-12)", s_3_12), ("4. the sender and kept beacon summaries (3-2)", s_3_2),
                  ("5. revoking purged days (3-3)", s_3_3), ("6. ATT&CK status in what is sent (3-10)", s_3_10),
                  ("7. the code check's removed entry (3-7)", s_3_7), ("8. beacon finding days (3-8)", s_3_8),
                  ("9. LG-B visibility answers (3-9)", s_3_9), ("10. the Malpedia batch's names (3-11)", s_3_11)):
    section(title, fn)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
