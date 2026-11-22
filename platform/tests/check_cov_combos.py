#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The combination search's refusals and its downloads kept over a restart (combos.py), offline and in-process: the
code book, the searches and the kept downloads are in a temporary folder, the audit entries are caught here (the real
data/combo_codes.json, data/combo_exports and the audit log are never touched), and the codes are made up.
- only analysts (addresses + export) search; a malformed code is 400, an unknown one 404, a decoded-beacons code 400
- dates: not YYYY-MM-DD 400, more than 31 days 400; "within": only an analyst code of your channels, with devices left
- one running search per person (429); stopping, enriching and a network's summary only for your own search
- the review gate: a search with across-report data waits for management's decision (409), also after a restart
- a download kept on disk: only its owner's, at most an hour old, never with an id that is not one; every download audited
No database needed. Run: .venv/bin/python tests/check_cov_combos.py"""
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import combos as C  # noqa: E402
from flask import g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


ANALYST = {"view", "unmasked", "export"}
RESEARCHER = {"definitions"}
ME = "lg-cov-analyst"


def call(path, perms, method="GET", body=None, user=ME):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": "analyst", "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        data = r.encode() if isinstance(r, str) else r.get_data()       # a rendered page is text
        try:
            return code, json.loads(data or b"{}")
        except ValueError:
            return code, data


tmp = tempfile.mkdtemp(prefix="lg-cov-combos-")
book = A.COMBOS
KEYS = ("path", "data", "loaded", "resolve_any", "get", "acode_allowed", "acode_records", "review_gate")
saved = {k: book.__dict__[k] for k in KEYS if k in book.__dict__}         # what the instance itself holds (the rest: its class)
real_exports = book.export_paths["dir"]
book.export_paths["dir"] = EXPORTS = os.path.join(tmp, "combo_exports")
book.path, book.data, book.loaded = os.path.join(tmp, "combo_codes.json"), {}, True
audit = A.AUTH["audit"]
real_add = audit.add
audited = []
audit.add = lambda *a, **k: audited.append((a, k))
ENTRIES = {"LG-B-0000000B": {"code": "LG-B-0000000B", "kind": "b"},
           "LG-A-0000000A": {"code": "LG-A-0000000A", "kind": "a", "platform": "services", "day": "2026-11-16", "days": ["2026-11-16"]},
           "LG-A-000000AE": {"code": "LG-A-000000AE", "kind": "a", "platform": "comms", "day": "2026-11-16"},
           "LG-A-000000FF": {"code": "LG-A-000000FF", "kind": "a", "platform": "services", "day": "2026-11-16"},
           "LG-C-0000000C": {"code": "LG-C-0000000C", "kind": "c", "section": "infections", "name": "examplebot", "items": []}}
book.resolve_any = lambda c: ENTRIES.get(c)
book.get = lambda c: ENTRIES.get(c)
book.acode_allowed = lambda c: c != "LG-A-000000FF"
book.acode_records = lambda e: [] if e["code"] == "LG-A-000000AE" else [{"ip": "192.0.2.1"}]
book.review_gate = None
S = "/api/combos/search"
try:
    print("Who may search, and what")
    ok("a researcher: 403", call(S, RESEARCHER, "POST", {"code": "LG-C-0000000C"})[0] == 403)
    c, d = call(S, ANALYST, "POST", {"code": "LG-Q-1"})
    ok("a malformed code: 400, with what a code looks like", c == 400 and "LG-C-1A2B3C4D" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "lg-c-0000dead"})
    ok("an unknown code (any case): 404", c == 404 and "LG-C-0000DEAD is not known here" in d["error"])
    ok("another channel's analyst code: 404", call(S, ANALYST, "POST", {"code": "LG-A-000000FF"})[0] == 404)
    c, d = call(S, ANALYST, "POST", {"code": "LG-B-0000000B"})
    ok("a decoded-beacons code: 400, worked on in Findings", c == 400 and "decoded beacons" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C", "from": "17/11/2026"})
    ok("dates not YYYY-MM-DD: 400", c == 400 and "YYYY-MM-DD" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C", "from": "2026-11-17", "to": "2026-09-01"})
    ok("more than 31 days (the dates in either order): 400", c == 400 and "At most 31 days" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C", "within": "LG-C-0000000C"})
    ok("within something that is no analyst code: 400", c == 400 and "Within: an analyst code" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "LG-A-0000000A", "within": "LG-A-0000000A"})
    ok("…an analyst code within an analyst code: 400", c == 400)
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C", "within": "LG-A-000000FF"})
    ok("…another channel's analyst code: 404", c == 404 and "not an analyst code of your channels" in d["error"])
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C", "within": "LG-A-000000AE"})
    ok("…an analyst code with no devices left: 409", c == 409 and "no devices left" in d["error"])
    book.jobs["f" * 16] = {"id": "f" * 16, "user": ME, "state": "running", "at": time.time(), "result": None}
    c, d = call(S, ANALYST, "POST", {"code": "LG-C-0000000C"})
    ok("a second search while one runs: 429", c == 429 and "already have a combination search running" in d["error"])

    print("Your own search only")
    J = "a" * 16
    book.jobs[J] = {"id": J, "user": ME, "code": "LG-C-0000000C", "state": "done", "done": 1, "total": 1, "log": [], "at": time.time(),
                    "result": {"name": "LG-C-0000000C.zip", "bytes": b"PK-made-up", "audit": "1 device"}, "error": "", "summary": {"devices": 1},
                    "_secret": "never shown", "inputs": None}
    c, d = call(f"{S}/{J}", ANALYST)
    ok("its status, without the internals (no user, no inputs, no _private keys)", c == 200 and d["file"] == "LG-C-0000000C.zip"
       and "user" not in d and "_secret" not in d and "inputs" not in d)
    ok("…another analyst does not see it (404)", call(f"{S}/{J}", ANALYST, user="someone-else")[0] == 404)
    ok("…a researcher: 403", call(f"{S}/{J}", RESEARCHER)[0] == 403)
    ok("stop: someone else's: 404; yours: stopping", call(f"{S}/{J}/stop", ANALYST, "POST", user="someone-else")[0] == 404
       and call(f"{S}/{J}/stop", ANALYST, "POST")[1] == {"stopping": True} and book.jobs[J]["cancel"] is True)
    ok("…a researcher: 403", call(f"{S}/{J}/stop", RESEARCHER, "POST")[0] == 403)
    ok("enrich without the search's records: expired (404)", call(f"{S}/{J}/enrich", ANALYST, "POST")[0] == 404)
    ok("a network's summary without the records: expired (404)", call(f"{S}/{J}/summary?network=Example", ANALYST)[0] == 404)
    ok("…a researcher: 403", call(f"{S}/{J}/summary", RESEARCHER)[0] == 403 and call(f"{S}/{J}/enrich", RESEARCHER, "POST")[0] == 403)

    class NoHost:
        def host(self, e):
            return ""
    K = "b" * 16
    book.jobs[K] = dict(book.jobs[J], id=K, inputs=[ENTRIES["LG-C-0000000C"], [{"src_ip": ""}], None, None, None, NoHost()], summary={"devices": 0})
    c, d = call(f"{S}/{K}/enrich", ANALYST, "POST")
    ok("enrich a search that found no device: 400", c == 400 and "no device" in d["error"])
    ok("…a network's summary without a network: the whole search's", call(f"{S}/{K}/summary", ANALYST)[1] == {"summary": {"devices": 0}, "network": ""})
    book.jobs[K]["needs_review"] = True
    c, d = call(f"{S}/{K}/enrich", ANALYST, "POST")
    ok("enrich a search with across-report data: management decides first (409)", c == 409 and d.get("needs_review"))

    print("Downloads")
    c, d = call(f"{S}/{J}/download", ANALYST)
    ok("your finished search: the ZIP, no-store, audited", c == 200 and d == b"PK-made-up" and audited[-1][0][0] == "combo_export"
       and "1 device · LG-C-0000000C.zip" in audited[-1][1]["detail"])
    ok("…a researcher: 403", call(f"{S}/{J}/download", RESEARCHER)[0] == 403)
    book.review_gate = lambda j: (False, "Waiting for management.")
    c, d = call(f"{S}/{K}/download", ANALYST)
    ok("the review gate says no: 409, its reason", c == 409 and d["error"] == "Waiting for management." and d["needs_review"])
    book.review_gate = None
    c, d = call(f"{S}/{J}/download?network=Example%20Net", ANALYST)
    ok("one network's report without the search's records: expired (404)", c == 404)
    os.makedirs(EXPORTS, exist_ok=True)

    def keep(jid, user=ME, age=0, **meta):
        m = dict({"user": user, "name": f"{jid}.zip", "at": time.time() - age, "summary": {"devices": 2}, "code": "LG-C-0000000C"}, **meta)
        json.dump(m, open(os.path.join(EXPORTS, jid + ".json"), "w"))
        open(os.path.join(EXPORTS, jid + ".zip"), "wb").write(b"PK-kept")
    keep("1" * 16)
    c, d = call(f"{S}/{'1' * 16}", ANALYST)
    ok("after a restart: a kept search still answers, finished", c == 200 and d["state"] == "done" and d["file"] == "1" * 16 + ".zip")
    ok("…for its owner only", call(f"{S}/{'1' * 16}", ANALYST, user="someone-else")[0] == 404)
    c, d = call(f"{S}/{'1' * 16}/download", ANALYST)
    ok("…its download, audited as kept on disk", c == 200 and d == b"PK-kept" and "kept on disk before a restart" in audited[-1][1]["detail"])
    ok("…someone else's: 404", call(f"{S}/{'1' * 16}/download", ANALYST, user="someone-else")[0] == 404)
    keep("2" * 16, gated=True)
    c, d = call(f"{S}/{'2' * 16}/download", ANALYST)
    ok("…kept while waiting for management: 409", c == 409 and d["needs_review"])
    book.review_gate = lambda j: (j["inputs"][0]["code"] != "LG-C-0000000C", "Sent to management since.")
    keep("3" * 16)
    c, d = call(f"{S}/{'3' * 16}/download", ANALYST)
    ok("…the gate asked again now (sent to management since it was kept): 409", c == 409 and d["error"] == "Sent to management since.")
    keep("4" * 16, code="")
    c, d = call(f"{S}/{'4' * 16}/download", ANALYST)
    ok("…kept by an older version (no code): 409, run it again", c == 409 and "older version" in d["error"])
    book.review_gate = None
    keep("5" * 16, age=C.JOB_TTL + 60)
    ok("…older than an hour: gone (404)", call(f"{S}/{'5' * 16}", ANALYST)[0] == 404)
    ok("an id that is not one: 404, nothing read", call(f"{S}/not-an-id", ANALYST)[0] == 404 and call(f"{S}/{'Z' * 16}/download", ANALYST)[0] == 404)
    open(os.path.join(EXPORTS, "6" * 16 + ".json"), "w").write("{broken")
    ok("a kept file that cannot be read: 404", call(f"{S}/{'6' * 16}", ANALYST)[0] == 404)
    old = os.path.join(EXPORTS, "7" * 16 + ".zip")
    open(old, "wb").write(b"x")
    os.utime(old, (time.time() - C.JOB_TTL - 60,) * 2)
    book.jobs["c" * 16] = {"id": "c" * 16, "user": ME, "state": "done", "at": time.time() - C.JOB_TTL - 60, "result": None}
    call(f"{S}/{J}/download", ANALYST)
    ok("the sweep: kept files and finished searches older than an hour go", not os.path.exists(old) and "c" * 16 not in book.jobs)

    print("The page")
    c, _ = call("/combinations", RESEARCHER)
    ok("the Combinations page: refused to a researcher (403)", c == 403)
finally:
    for k in KEYS:
        if k in saved:
            setattr(book, k, saved[k])
        else:
            book.__dict__.pop(k, None)
    for k in [k for k, j in list(book.jobs.items()) if j.get("user") in (ME, "someone-else")]:
        book.jobs.pop(k, None)
    book.export_paths["dir"] = real_exports
    audit.add = real_add
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
