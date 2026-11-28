#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The fixes of the code review, round 1 (28 Nov 2026), each a behaviour that failed before:

r1-1 an analyst code's label masks a services selection's banner filters (vendor, device type, product, version):
     a host name or address in them never reaches the researchers (acodes.label, as services.banner_mask)
r1-2 an update whose code move is stopped by its time limit (124), or that moved HEAD and failed, is rolled back:
     the stale .git/index.lock removed, the tree and HEAD back (deploy/update_run.py, in a temporary git repository)
r1-3 an analyst code made from a search whose kept records are gone loads no day (acodes.view)
r1-4 the sender looks at the sent days outside the back-fill window at most once a day (connectors_worker.run)
r1-5 a revocation that always fails counts toward the failures in a row: the target is paused
r1-6 a kept beacon summary is found for a record whose host has capitals (the decoder keeps the lower-cased host)
r1-7 a roll back whose last log line cannot be written still ends "rolled_back", never "running"
r1-8 executive_pdf.hard_lines breaks a 2,000-character word without a quadratic number of width measures, and gives
     the same lines as before for ordinary text
The re-review of these fixes (28 Nov 2026):
rr-1 a request path and a user agent in a selection are held back in the label (app.REF_KINDS); the C2 domain stays
rr-2 a label stored before the fixes is worked out again when it is served (page, list, chain, describe), never rewritten
rr-3 a roll back removes the files the release adds that a stopped step already wrote (only those); a step that died
     with another code but changed tracked files is rolled back too
rr-4 the tree is checked clean again after the backup; a .git/index.lock is removed only when this run killed a git
rr-5 a run counts once toward the failures in a row, and the pause says "Three runs in a row failed"
rr-6 the test's temporary folders are removed
rr-7 the code book (combos.py) and the findings (findings.py) serve an analyst code's label with the same rule: a code
     look-up, book.describe, a finding's name made from an analyst code; never rewritten

Stand-ins for the code book, the findings, the days, MongoDB and the targets; temporary folders only; nothing outside
this computer. LG_FIX_SRC=<folder> runs the checks against another copy of the changed modules (the code before the
fix, to show they fail there). Run: .venv/bin/python tests/check_fix_r1.py"""
import datetime as dt
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
SRC_DIR = os.path.abspath(os.environ.get("LG_FIX_SRC") or REPO)
sys.path.insert(0, SRC_DIR)
if SRC_DIR != REPO:
    sys.path.insert(1, REPO)                                # the modules not changed come from the platform
os.environ.setdefault("LG_QUIET", "1")
from flask import Flask, g  # noqa: E402

checks, fails = 0, []
TMP = tempfile.mkdtemp(prefix="lg-fixr1-")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def call(app, path, user, role, perms, method="GET", body=None):
    """A route called in-process: (status, json). An exception is a 500, as the browser would get."""
    with app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms)}
        try:
            ep, kw = app.url_map.bind("localhost").match(path.split("?")[0], method=method)
            rv = app.view_functions[ep](**kw)
        except Exception as exc:                           # noqa: BLE001
            return 500, {"exception": repr(exc)}
        rv, st = rv if isinstance(rv, tuple) else (rv, rv.status_code)
        try:
            return st, rv.get_json() or {}
        except Exception:                                  # noqa: BLE001
            return st, {}


def section(name, fn):
    try:
        fn()
    except Exception as exc:                               # noqa: BLE001 (a section that stops is a failed check)
        ok(f"{name}: ran to the end", False, repr(exc))


# ====================================================================== analyst codes (r1-1, r1-3)
def s_acodes():
    import acodes

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

    SRC = "LG-A-00000AAA"

    class Findings:
        asked_of = None

        def of_code(self, c):
            return ({"id": "7", "participants": ["rachel"], "title": "a finding", "text": "", "status": "analyst", "user": "rachel"}
                    if c == SRC else None)

        def sees(self, f, user, admin, strict=False):
            return admin or user in (f.get("participants") or [])

        def recipient(self, kind, to):
            return "rachel", ""

        def create_analyst(self, *a, **k):
            return {"id": "9"}

        def all_open(self):
            return []

    class Day:
        def __init__(self, events):
            self.events = events

    DAYS = [f"2026-11-0{i}" for i in range(1, 5)]
    loads = []

    def day(platform, iso):
        loads.append(iso)
        return Day([{"id": f"r-{iso}", "src_ip": "192.0.2.10", "infection": "examplebot", "source": "event4_sinkhole"}])

    SVC = [{"id": "s1", "ip": "192.0.2.20", "issues": ["CVE-2023-48795"], "product": "Apache on mail.ministry.example",
            "vendor": "router 198.51.100.7"}]
    book, tmp = Book(), tempfile.mkdtemp(dir=TMP)
    perms = {"researcher": {"definitions"}, "analyst": {"unmasked", "export"}, "admin": {"settings"}}
    app = Flask("acodes_r1")
    api = acodes.install(app, {"book": book, "findings": Findings(), "base_dir": tmp,
                               "is_demo": lambda: "unmasked" not in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                               "csrf_ok": lambda: True, "fresh": lambda: True,
                               "has_perm": lambda p: p in perms.get(getattr(g, "user", {}).get("role", ""), set()),
                               "audit": type("A", (), {"add": staticmethod(lambda *a, **k: None)})(),
                               "day": day, "slice": lambda d, k, v: (d, d.events, list(d.events)), "kinds": None,
                               "svc_scope": lambda q, d: list(SVC), "labels": dict, "cross": lambda hosts, **kw: {},
                               "network": lambda a: "", "defined": dict, "people_name": lambda u: u})
    api.paths["ids"] = os.path.join(tmp, "acodes")
    os.makedirs(api.paths["ids"], exist_ok=True)
    book.put(SRC, {"kind": "a", "platform": "comms", "day": DAYS[0], "sel": {"kind": "infection", "value": "examplebot"}, "label": "src"})

    print("r1-1 A services selection's banner filters in the analyst code's label")
    q = "product=Apache on mail.ministry.example&vendor=router 198.51.100.7&version=2.4.58&issue=CVE-2023-48795"
    st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
                 {"platform": "services", "query": q, "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel"})
    lab = d.get("label", "")
    stored = (book.get(d.get("code", "")) or {}).get("label", "")
    ok("the code is made", st == 200 and d.get("code", "").startswith("LG-A-"), f"{st} {d}")
    for made_up in ("mail.ministry.example", "198.51.100.7"):      # made-up host name and documentation address
        ok(f"{made_up}: not in the label researchers read, nor in the code book (was: printed raw)",
           st == 200 and made_up not in lab and made_up not in stored, repr(lab))
    ok("…the software and its version stay readable", "Product: Apache" in lab and "Version: 2.4.58" in lab, repr(lab))
    ok("…a field that is no banner is as before", "Issue: CVE-2023-48795" in lab, repr(lab))

    print("r1-3 An analyst code from a search, its kept records gone: no day is loaded")
    MC = "LG-A-00000C03"
    book.put(MC, {"kind": "a", "platform": "comms", "day": DAYS[-1], "days": DAYS, "label": "the devices of a search",
                  "sel": {"from_code": SRC, "days": DAYS}})           # no data/acodes/<code>.json for it
    loads.clear()
    st, v = call(app, f"/api/intel/acode/{MC}", "rachel", "researcher", ["definitions"])
    ok("the page still opens, with no records", st == 200 and v.get("records") == 0, f"{st} {v}")
    ok("…and no day was loaded for nothing (was: every day of the code)", loads == [], str(loads))
    MC2 = "LG-A-00000C04"                                   # the same code with its kept records: its days are read
    book.put(MC2, {"kind": "a", "platform": "comms", "day": DAYS[-1], "days": DAYS, "label": "the devices of a search",
                   "sel": {"from_code": SRC, "days": DAYS}})
    with open(os.path.join(api.paths["ids"], f"{MC2}.json"), "w") as fh:
        json.dump([f"r-{d}" for d in DAYS], fh)
    loads.clear()
    st, v = call(app, f"/api/intel/acode/{MC2}", "rachel", "researcher", ["definitions"])
    ok("…a code with its kept records still reads its days (records and the across loop)",
       st == 200 and v.get("records") == 4 and len(loads) == 8, f"{st} {v.get('records')} {loads}")

    print("rr-1 A request path and a user agent in the label (masked viewers only get opaque references for them)")
    req = "GET /gate.php?id=4F2A9C&pc=FINANCE-PC07"
    st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
                 {"platform": "comms", "kind": "request", "value": req, "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel"})
    lab = d.get("label", "")
    ok("a single-kind request selection: no bot id, no machine name (was: printed raw)",
       st == 200 and "4F2A9C" not in lab and "FINANCE-PC07" not in lab and "1 request (held back)" in lab, f"{st} {lab!r}")
    st, d = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"], "POST",
                 {"platform": "comms", "kind": "filters", "at": f"{DAYS[0]}T10:00:00Z", "title": "t", "to": "rachel",
                  "value": "http_agent=Mozilla/5.0 (FINANCE-PC07)&http_host=c2.example.net&infection=examplebot"})
    lab = d.get("label", "")
    ok("…a user agent inside a filters query: held back (was: printed raw)",
       st == 200 and "FINANCE-PC07" not in lab and "1 user agent (held back)" in lab, f"{st} {lab!r}")
    ok("…the C2 domain stays, as Intel gathered shows it to researchers", "C2 domain: c2.example.net" in lab
       and "Infection: examplebot" in lab, repr(lab))

    print("rr-2 A label stored before the fix is masked when it is served (the stored file left as it is)")
    OLD = "LG-A-00000D01"
    raw = "Product: Apache on mail.ministry.example · Vendor: router 198.51.100.7"
    book.put(OLD, {"kind": "a", "platform": "services", "day": DAYS[0], "label": raw, "records": 1, "hosts": 1, "names": [],
                   "sel": {"query": [["product", "Apache on mail.ministry.example"], ["vendor", "router 198.51.100.7"]]}})
    with open(os.path.join(api.paths["ids"], f"{OLD}.json"), "w") as fh:
        json.dump(["s1"], fh)
    REQ = "LG-A-00000D02"
    book.put(REQ, {"kind": "a", "platform": "comms", "day": DAYS[0], "label": f"Request path: {req}", "records": 1, "hosts": 1,
                   "names": [], "sel": {"kind": "request", "value": req}})
    CHILD = "LG-A-00000D03"
    book.put(CHILD, {"kind": "a", "platform": "services", "day": DAYS[0], "days": [DAYS[0]], "label": "a CVE on its devices",
                     "sel": {"from_code": OLD, "days": [DAYS[0]], "drill": True}})
    made_up = ("mail.ministry.example", "198.51.100.7", "4F2A9C", "FINANCE-PC07")   # made-up host values

    def clean(s):
        return isinstance(s, str) and s and not any(x in s for x in made_up)
    st, v = call(app, f"/api/intel/acode/{OLD}", "rachel", "researcher", ["definitions"])
    ok("the code's page (was: the stored label as it is)", st == 200 and clean(v.get("label")) and "Product: Apache" in v["label"],
       f"{st} {v.get('label')!r}")
    st, v = call(app, f"/api/intel/acode/{REQ}", "rachel", "researcher", ["definitions"])
    ok("…a stored request label too", st == 200 and clean(v.get("label")) and "1 request (held back)" in v["label"], f"{st} {v.get('label')!r}")
    st, v = call(app, "/api/analyst-codes", "ann", "analyst", ["unmasked", "export"])
    listed = {c["code"]: c["label"] for c in v.get("codes") or []}
    ok("…the analysts' list", st == 200 and clean(listed.get(OLD)) and clean(listed.get(REQ)), str(listed.get(OLD)))
    with app.test_request_context("/"):
        g.user = {"user": "rachel", "role": "researcher", "perms": {"definitions"}}
        chain = api.chain(CHILD)
    ok("…the chain of a code made from it", chain and chain[0].get("code") == OLD and clean(chain[0].get("label")), str(chain)[:300])
    ok("…what other pages describe it as (api.describe)", clean(api.describe(book.get(OLD))), api.describe(book.get(OLD)))
    ok("…and the stored label is not rewritten", book.data[OLD]["label"] == raw)
    ok("…a code made from a search keeps its stored label", call(app, f"/api/intel/acode/{CHILD}", "rachel", "researcher", ["definitions"])[1].get("label") == "a CVE on its devices")


# ====================================================================== the code book and findings serve the label (rr-7)
def s_combos_findings():
    import acodes
    import combos
    import findings as FM

    class People:
        def name(self, u, default=None):
            return u

    perms = {"researcher": {"definitions"}, "analyst": {"unmasked", "export"}}
    base = tempfile.mkdtemp(dir=TMP)
    os.makedirs(os.path.join(base, "data"))
    app = Flask("combos_findings_r1")
    hp = lambda p: p in perms.get(getattr(g, "user", {}).get("role", ""), set())     # noqa: E731
    book = combos.install(app, {"intel": types.SimpleNamespace(index=lambda *a: {"by": {}, "xcombos": {}}), "base_dir": base, "has_perm": hp, "labels": dict,
                                "csrf_ok": lambda: True, "is_demo": lambda: False, "network": lambda a: "",
                                "audit": types.SimpleNamespace(add=lambda *a, **k: None), "notes": types.SimpleNamespace(list=lambda *a: [])})
    F = FM.Findings(os.path.join(base, "data", "findings.json"), People())
    acodes.install(app, {"book": book, "findings": F, "base_dir": base, "is_demo": lambda: False, "csrf_ok": lambda: True,
                         "fresh": lambda: True, "has_perm": hp, "audit": types.SimpleNamespace(add=lambda *a, **k: None),
                         "day": lambda platform, iso: None, "slice": lambda d, k, v: (d, [], []), "kinds": None,
                         "svc_scope": lambda q, d: [], "labels": dict, "cross": lambda hosts, **kw: {}, "network": lambda a: "",
                         "defined": dict, "people_name": lambda u: u})
    OLD = "LG-A-00000E01"
    raw = "Product: Apache on mail.ministry.example · Vendor: router 198.51.100.7"
    book.put(OLD, {"kind": "a", "platform": "services", "day": "2026-11-01", "label": raw, "records": 1, "hosts": 1, "names": [],
                   "sel": {"query": [["product", "Apache on mail.ministry.example"], ["vendor", "router 198.51.100.7"]]}})
    made_up = ("mail.ministry.example", "198.51.100.7")       # made-up host values

    def clean(s):
        return isinstance(s, str) and bool(s) and not any(x in s for x in made_up)

    print("rr-7 The code book serves an analyst code's stored label with acodes' rule (combos.py)")
    st, d = call(app, f"/api/combo-codes/{OLD}", "rachel", "researcher", ["definitions"])
    ok("the code look-up's label (was: the stored label as it is)", st == 200 and clean(d.get("label")) and "Product: Apache" in d["label"],
       f"{st} {d.get('label')!r}")
    ok("…and its text", st == 200 and clean(d.get("text")), f"{d.get('text')!r}")
    ok("…what every other page is told the code stands for (book.describe)", clean(book.describe(OLD)), book.describe(OLD))
    ok("…without the analyst codes installed: the stored label, as before", combos.describe(book.get(OLD)).endswith(raw))
    ok("…and the stored label is not rewritten", (book.get(OLD) or {}).get("label") == raw)

    print("rr-7 A finding made from an analyst code before the fix (findings.py)")
    a = F.create_analyst(OLD, "issues", raw, "A request", "t", "ann", "analyst", to="rachel")
    rv = F.create_review(OLD, "issues", f"Analyst selection on 2026-11-01 (services): {raw}"[:200], "A review", "t", "ann", "analyst",
                         "mgr", {"source": OLD, "codes": []})
    lost = F.create_analyst("LG-A-00000E09", "issues", "Request path: GET /gate.php?id=4F2A9C&pc=FINANCE-PC07 on 198.51.100.7",
                            "Its code is gone", "t", "ann", "analyst", to="rachel")
    mine = F.create({"id": "n1", "text": "a researcher's note", "codes": ["LG-C-00000001"]}, "infections", "examplebot", "Mine",
                    "rachel", "researcher", "mgr")
    shown = F.shown(F.get(a["id"]), book.describe)
    ok("its name and display name: worked out from the code (was: the stored label)",
       clean(shown.get("name")) and clean(shown.get("display_name")) and "Product: Apache" in shown["name"], f"{shown.get('name')!r}")
    s_rv = F.shown(F.get(rv["id"]), book.describe)
    ok("…a review made from it: what the code stands for, masked", clean(s_rv.get("name")) and "Analyst selection" in s_rv["name"],
       f"{s_rv.get('name')!r}")
    s_lost = F.shown(F.get(lost["id"]), book.describe)
    ok("…a code no longer kept: a fixed text, never the stored name (no bot id, machine name or address)",
       s_lost.get("name") == "An analyst selection (its code is no longer kept)"
       and not any(x in json.dumps(s_lost) for x in ("4F2A9C", "FINANCE-PC07", "198.51.100.7")), f"{s_lost.get('name')!r}")
    listed = {x["id"]: x["name"] for x in F.list(False, book.describe)}
    ok("…the Findings list too", clean(listed.get(a["id"])) and clean(listed.get(rv["id"])), str(listed))
    ok("…a researcher's finding keeps its name", listed.get(mine["id"]) == "examplebot", listed.get(mine["id"]))
    ok("…and the stored findings are not rewritten", F.get(a["id"])["name"] == raw)


# ====================================================================== deploy/update_run.py (r1-2, r1-7)
def git(cwd, *args):
    r = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, GIT_TERMINAL_PROMPT="0", LC_ALL="C"))
    return r.stdout.strip()


def s_update():
    if os.path.join(REPO, "deploy") not in sys.path:
        sys.path.append(os.path.join(REPO, "deploy"))       # verify_install's own helpers (stale_files), for another copy
    src = os.path.join(SRC_DIR, "deploy", "update_run.py")
    if not os.path.exists(src):                             # a copy that holds other modules only
        src = os.path.join(REPO, "deploy", "update_run.py")
    spec = importlib.util.spec_from_file_location("update_run_r1", src)
    U = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(U)
    VI = U.VI
    base = tempfile.mkdtemp(dir=TMP)
    proj = os.path.join(base, "proj")
    os.makedirs(proj)
    git(proj, "init", "-q", "-b", "main")
    git(proj, "config", "user.email", "test@example.invalid")
    git(proj, "config", "user.name", "Test")
    git(proj, "config", "commit.gpgsign", "false")
    for n, s in (("a.txt", "one\n"), ("d.txt", "admin's file\n")):
        with open(os.path.join(proj, n), "w") as f:
            f.write(s)
    git(proj, "add", "a.txt", "d.txt")
    git(proj, "commit", "-q", "-m", "A")
    A = git(proj, "rev-parse", "HEAD")
    with open(os.path.join(proj, "a.txt"), "w") as f:
        f.write("two\n")
    with open(os.path.join(proj, "c.txt"), "w") as f:             # a file the release ADDS
        f.write("new in the release\n")
    git(proj, "add", "c.txt")
    git(proj, "commit", "-q", "-am", "B")
    TAG = "v2026.11.28"
    git(proj, "tag", TAG)
    git(proj, "reset", "-q", "--hard", A)
    lock = os.path.join(proj, ".git", "index.lock")

    U.PROJECT = proj
    U.STATE = os.path.join(base, "state")
    U.REQUEST, U.STATUS, U.LOG, U.LOCK = (os.path.join(U.STATE, n) for n in ("request.json", "status.json", "log.jsonl", "lock"))
    LOG0 = U.LOG
    U.audit = lambda *a, **k: None
    U.preflight = lambda run: proj
    U.remote_tags = lambda run: [TAG]
    real_git = VI.git
    saved = (VI.installed_tag, VI.signers_file, VI.github_keys, VI.git)
    VI.installed_tag = lambda p: "v2026.11.20"
    VI.signers_file = lambda *a, **k: 1
    VI.github_keys = lambda *a, **k: []                     # never GitHub

    def fake_git(args, cwd=None, timeout=180):
        if "verify-tag" in args:
            return subprocess.CompletedProcess(args, 0, "", f'Good "git" signature with key {VI.KEY_FINGERPRINT}')
        if "cat-file" in args:
            return subprocess.CompletedProcess(args, 0, "tag\n", "")
        return real_git(args, cwd=cwd, timeout=timeout)
    VI.git = fake_git
    mode = {"v": ""}

    class Run(U.Run):
        def cmd(self, args, cwd=None, timeout=300, quiet=False):
            name = os.path.basename(args[0])
            if name == "backup.sh" and mode["v"] == "edit-during-backup":
                with open(os.path.join(proj, "d.txt"), "w") as f:     # an admin edits a shipped file meanwhile
                    f.write("edited during the backup\n")
                return 0, ""
            if name in ("backup.sh", "reload.sh"):
                return 0, ""
            if name == "update_libraries.sh":
                if mode["v"] == "finish-raises":
                    U.LOG = U.STATE                         # a folder: every log line from here on fails to be written
                    return 1, ""
                return 0, ""
            if "fetch" in args:
                return 0, ""
            if "merge" in args and mode["v"] in ("timeout", "edit-during-backup"):
                # a merge killed by its time limit part way: a file moved, a file the release adds written, the lock
                # left behind (as Run.cmd's timer marks it: killed)
                with open(os.path.join(proj, "a.txt"), "w") as f:
                    f.write("two\n")
                with open(os.path.join(proj, "c.txt"), "w") as f:
                    f.write("new in the release\n")
                open(lock, "w").close()
                self.killed = True
                return 124, ""
            if ("merge" in args or ("checkout" in args and f"refs/tags/{TAG}" in args)) and mode["v"] == "died":
                # a merge / checkout that died with another code (128, a full disk): a tracked file changed, HEAD not moved
                with open(os.path.join(proj, "a.txt"), "w") as f:
                    f.write("two\n")
                return 128, ""
            if "merge" in args and mode["v"] == "foreign-lock":
                # another git holds the lock, and the step stops with an error before any process of ours was killed
                open(lock, "w").close()
                raise OSError("the step could not be started")
            if "merge" in args and mode["v"] == "moved":
                return 1, ""                                # not a fast-forward: the checkout is tried
            if "checkout" in args and mode["v"] == "moved" and f"refs/tags/{TAG}" in args:
                U.Run.cmd(self, args, cwd=proj, timeout=timeout, quiet=quiet)
                return 1, ""                                # HEAD moved, and the step failed all the same
            return U.Run.cmd(self, args, cwd=proj, timeout=timeout, quiet=quiet)

    def reset_repo():
        U.LOG = LOG0
        if os.path.exists(lock):
            os.remove(lock)
        git(proj, "checkout", "-q", "-f", "main")
        git(proj, "reset", "-q", "--hard", A)
        if os.path.exists(os.path.join(proj, "c.txt")):
            os.remove(os.path.join(proj, "c.txt"))

    def status():
        try:
            with open(U.STATUS, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def text():
        with open(os.path.join(proj, "a.txt")) as f:
            return f.read()
    try:
        print("r1-2 The code move stopped by its time limit (124)")
        reset_repo()
        mode["v"] = "timeout"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        s = status()
        ok("the run ends rolled_back (was: failed, 'nothing else was changed')", s.get("state") == "rolled_back", f"{rc} {s}")
        ok("…the stale .git/index.lock is removed", not os.path.exists(lock))
        ok("…the half-moved file is back and HEAD is the previous commit", text() == "one\n" and git(proj, "rev-parse", "HEAD") == A,
           f"{text()!r} {git(proj, 'rev-parse', 'HEAD')[:12]}")
        ok("…still on its branch", git(proj, "symbolic-ref", "-q", "--short", "HEAD") == "main")

        print("rr-3a The killed step had already written a file the release adds")
        reset_repo()
        with open(os.path.join(proj, "keep.txt"), "w") as f:          # an untracked file of the installation's own
            f.write("mine\n")
        mode["v"] = "timeout"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        ok("rolled back, and the release's new file is removed (was: left untracked)",
           status().get("state") == "rolled_back" and not os.path.exists(os.path.join(proj, "c.txt")), f"{rc} {status().get('state')}")
        ok("…an untracked file that is not the release's stays (never git clean)", os.path.exists(os.path.join(proj, "keep.txt")))
        mode["v"] = ""
        U.LOG = LOG0
        rc = U.update(Run("update", TAG, "t"))
        ok("…and the next update goes through (was: 'untracked working tree files would be overwritten')",
           rc == 0 and status().get("state") == "done", f"{rc} {status().get('result')}")
        os.remove(os.path.join(proj, "keep.txt"))

        print("rr-3b A merge / checkout that died with another code (128), tracked files changed, HEAD not moved")
        reset_repo()
        mode["v"] = "died"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        ok("rolled back, the file as it was (was: failed, 'nothing else was changed', the file changed)",
           status().get("state") == "rolled_back" and text() == "one\n" and git(proj, "rev-parse", "HEAD") == A,
           f"{rc} {status().get('state')} {text()!r}")

        print("rr-4 A shipped file edited during the backup")
        reset_repo()
        mode["v"] = "edit-during-backup"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        with open(os.path.join(proj, "d.txt")) as f:
            dtxt = f.read()
        ok("not updated, nothing changed: the edit is kept (was: thrown away by the roll back's reset)",
           status().get("state") == "failed" and "while the backup ran" in status().get("result", "")
           and dtxt == "edited during the backup\n" and git(proj, "rev-parse", "HEAD") == A, f"{rc} {status().get('result')} {dtxt!r}")

        print("rr-4 A lock no process of this run left is never removed")
        reset_repo()
        mode["v"] = "foreign-lock"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        ok("a step stopped by an error, no git of ours killed: the other git's .git/index.lock is still there (was: removed)",
           os.path.exists(lock), f"{rc} {status().get('state')}")

        print("r1-2 A failed step that moved HEAD all the same")
        reset_repo()
        mode["v"] = "moved"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        s = status()
        ok("the run ends rolled_back (was: failed, the code left on the new release)", s.get("state") == "rolled_back", f"{rc} {s}")
        ok("…HEAD is the previous commit, on its branch, the file as it was",
           git(proj, "rev-parse", "HEAD") == A and git(proj, "symbolic-ref", "-q", "--short", "HEAD") == "main" and text() == "one\n",
           f"{git(proj, 'rev-parse', 'HEAD')[:12]} {text()!r}")

        print("r1-2 An update that goes through is not touched")
        reset_repo()
        mode["v"] = ""
        rc = U.update(Run("update", TAG, "t"))
        ok("done, on the new release", rc == 0 and status().get("state") == "done" and text() == "two\n", f"{rc} {status()}")

        print("r1-7 The roll back's last log line cannot be written")
        reset_repo()
        mode["v"] = "finish-raises"
        try:
            rc = U.update(Run("update", TAG, "t"))
        except Exception as exc:                            # noqa: BLE001
            rc = repr(exc)
        s = status()
        ok("the page says rolled_back, not running (was: the error escaped, the page stayed 'running')",
           s.get("state") == "rolled_back" and s.get("ended"), f"{rc} {s.get('state')}")
        ok("…and the code is back", git(proj, "rev-parse", "HEAD") == A and text() == "one\n")
    finally:
        VI.installed_tag, VI.signers_file, VI.github_keys, VI.git = saved
        U.LOG = LOG0


# ====================================================================== connectors_worker.py (r1-4, r1-5, r1-6)
class Col:
    counted = []

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
        Col.counted.append(q.get("filename", {}).get("$regex", ""))
        return len(self.find(q))


class DB:
    def __init__(self, cols):
        self.cols = cols

    def list_collection_names(self):
        return list(self.cols)

    def __getitem__(self, k):
        return self.cols.setdefault(k, Col([]))


def s_connectors():
    import auth
    import beacon_keep
    import connector_net as net
    import connector_payload as cp
    import connectors as C
    import connectors_worker as W
    import pymongo

    print("r1-6 A kept beacon summary for a host written with capitals")
    url, host = "GET /c.php?id=x HTTP/1.1", "C2.Example.COM"
    db = DB({"event4_sinkhole_http": Col([{"filename": "2026-11-23-event4_sinkhole_http.csv", "src_ip": "198.18.144.7", "src_asn": 64514,
                                            "timestamp": "2026-11-23 10:00:00", "infection": "m0yv", "http_url": url, "http_host": host}])})
    kept = {beacon_keep.key_of(url, "c2.example.com"): [["format", "CLogin check-in"], ["id", "clogin"]]}   # as the decoder keeps it
    out = W.devices_of(db, ["event4_sinkhole_http"], "2026-11-23", lambda asn, ip: True, TMP, kept)
    b = out["198.18.144.7"]["reports"]["event4_sinkhole_http"]["beacons"]
    ok("found under the lower-cased host (was: no beacon)", [tuple(x) for x in b] == [("clogin", "CLogin check-in")], b)

    today = dt.datetime.now(dt.timezone.utc)
    d_old = (today.date() - dt.timedelta(days=45)).isoformat()   # outside the 30-day back-fill, not purged yet
    d_in = (today.date() - dt.timedelta(days=10)).isoformat()    # in the window, purged
    DBS = {}

    def make(name, state, docs):
        base = os.path.join(TMP, name)
        data = os.path.join(base, "data")
        os.makedirs(data)
        with open(os.path.join(data, "connectors.json"), "w", encoding="utf-8") as f:
            json.dump({"targets": {"t1": {"name": "Lab MISP", "kind": "misp", "address": "https://misp.lab.test", "tlp": "amber", "on": True,
                                          "scope": {"networks": {"64514": "whole"}}, "turned_on": time.time() - 60 * 86400}}}, f)
        with open(os.path.join(data, "connectors_state.json"), "w", encoding="utf-8") as f:
            json.dump({"t1": state}, f)
        DBS[base] = DB({"scan_http": Col(docs)})
        return base
    STATUS, CALLS, CUR = [200], [], [None]

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
    pymongo.MongoClient = lambda *a, **k: {os.environ.get("MONGO_DB", "shadowserver"): DBS[CUR[0]]}
    auth.Audit = FakeAudit
    sys.modules["advisory"] = types.SimpleNamespace(Impact=lambda b: None)
    sys.modules["db_connect"] = types.SimpleNamespace(kwargs=lambda get: {})
    os.environ["LG_TARGET_T1_KEY"] = "made-up-key"
    try:
        print("r1-4 The sent days outside the back-fill window: looked at once a day")
        base = make("cw4", {"days": {d_old: {"sig": "a", "objects": {"event": "ev-old"}, "devices": 1}}, "fails": 0},
                    [{"filename": f"{d_old}-scan_http.csv", "ip": "192.0.2.9", "asn": 64514}])
        CUR[0] = base
        old_rx = "^" + re.escape(d_old)
        per_run = []
        for when in (today, today + dt.timedelta(minutes=15), today + dt.timedelta(days=1)):
            Col.counted.clear()
            W.run(base_dir=base, now=when, log=lambda *a: None)
            per_run.append(Col.counted.count(old_rx))
        ok("the first run counts the old day", per_run[0] >= 1, per_run)
        ok("…the next run 15 minutes later does not count it again (was: every run)", per_run[1] == 0, per_run)
        ok("…the next day it is looked at again", per_run[2] >= 1, per_run)

        print("r1-5 A target that always refuses the revocation")
        base = make("cw5", {"days": {d_in: {"sig": "b", "objects": {"event": "ev-in"}, "devices": 1}}, "fails": 0}, [])
        CUR[0] = base
        STATUS[0] = 500
        for _ in range(3):
            W.run(base_dir=base, log=lambda *a: None)
        with open(os.path.join(base, "data", "connectors.json"), encoding="utf-8") as f:
            t1 = json.load(f)["targets"]["t1"]
        with open(os.path.join(base, "data", "connectors_state.json"), encoding="utf-8") as f:
            st1 = json.load(f)["t1"]
        ok("three failed runs in a row pause it (was: never paused)", bool(t1.get("paused")), f"{t1.get('paused')} fails={st1.get('fails')}")
        ok("…and the day is still kept, to be revoked later", d_in in st1["days"], sorted(st1["days"]))
        base = make("cw5b", {"days": {d_in: {"sig": "b", "objects": {"event": "ev-in"}, "devices": 1},
                                      d_old: {"sig": "a", "objects": {"event": "ev-old"}, "devices": 1}}, "fails": 0}, [])
        CUR[0] = base
        W.run(base_dir=base, log=lambda *a: None)
        with open(os.path.join(base, "data", "connectors_state.json"), encoding="utf-8") as f:
            st2 = json.load(f)["t1"]
        ok("…two failed revocations in one run count once", st2.get("fails") == 1, st2.get("fails"))
        ok("…and an old day whose revocation failed is tried again in the next run (not marked checked)",
           st2.get("old_checked") != today.date().isoformat(), st2.get("old_checked"))

        print("rr-5 A failed revocation and a failed send in the same run")
        d_send = (today.date() - dt.timedelta(days=5)).isoformat()
        base = make("cw5c", {"days": {d_in: {"sig": "b", "objects": {"event": "ev-in"}, "devices": 1}}, "fails": 0},
                    [{"filename": f"{d_send}-scan_http.csv", "ip": "192.0.2.9", "asn": 64514, "timestamp": f"{d_send} 10:00:00"}])
        CUR[0] = base
        STATUS[0] = 500
        CALLS.clear()
        W.run(base_dir=base, log=lambda *a: None)
        with open(os.path.join(base, "data", "connectors_state.json"), encoding="utf-8") as f:
            st3 = json.load(f)["t1"]
        posts = [u for m, u in CALLS if m == "POST"]
        ok("both were tried (the revocation and the send)", any("/events/delete/" in u for u in posts)
           and any(u.endswith("/events/add") for u in posts), posts)
        ok("…the run counts once (was: 2)", st3.get("fails") == 1, st3.get("fails"))
        for _ in range(2):
            W.run(base_dir=base, log=lambda *a: None)
        with open(os.path.join(base, "data", "connectors.json"), encoding="utf-8") as f:
            t3 = json.load(f)["targets"]["t1"]
        ok("…three such runs pause it, said as runs (was: 'Three sends in a row failed')",
           str(t3.get("paused") or "").startswith("Three runs in a row failed"), t3.get("paused"))
    finally:
        net.request, C.probe, cp.know_from, pymongo.MongoClient, auth.Audit = saved[:5]
        for name, mod in (("advisory", saved[5]), ("db_connect", saved[6])):
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
        os.environ.pop("LG_TARGET_T1_KEY", None)


# ====================================================================== executive_pdf.hard_lines (r1-8)
def s_hard_lines():
    import executive_pdf as X
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfbase import pdfmetrics
    calls = [0]

    def sw(t, f, s):
        calls[0] += 1
        return pdfmetrics.stringWidth(t, f, s)

    class FakeDoc:
        c = types.SimpleNamespace(stringWidth=sw)

    def before(doc, lines, font, size, width):
        """hard_lines as it was (one character at a time): the reference for the same output."""
        out = []
        for ln in lines:
            while ln and doc.c.stringWidth(ln, font, size) > width:
                k = len(ln)
                while k > 1 and doc.c.stringWidth(ln[:k], font, size) > width:
                    k -= 1
                soft = max((i + 1 for i in range(1, k) if ln[i] in "-./:_"), default=0)
                if soft > k // 3:
                    k = soft
                out.append(ln[:k]); ln = ln[k:].lstrip()
            out.append(ln)
        return out

    print("r1-8 hard_lines: the same lines as before, without the quadratic cost")
    texts = ["The devices of this network call the sinkholes of avalanche-andromeda every day.",
             "2001:db8:85a3:0000:0000:8a2e:0370:7334 and 198.51.100.7 seen together",
             "a.very.long.host.name.without.spaces.example.org/and/a/path_with_underscores",
             "W", "", "Ordinary words only, every one shorter than the column."]
    same = True
    for t in texts:
        for width in (6, 30, 55, 90, 140, 400):
            for font, size in (("Helvetica", 8), ("Helvetica-Bold", 11), ("Courier", 9)):
                lines = simpleSplit(t, font, size, width) or [t]
                a, b = X.hard_lines(FakeDoc(), list(lines), font, size, width), before(FakeDoc(), list(lines), font, size, width)
                if a != b:
                    same = False
                    print(f"    differs: {t[:30]!r} width {width} {font}: {a} vs {b}")
    ok("ordinary text, addresses and long names: the same lines as before (many widths and fonts)", same)
    word = "x7Qa" * 500                                     # a 2,000-character word with no place to break
    calls[0] = 0
    out = X.hard_lines(FakeDoc(), [word], "Helvetica", 8, 200)
    n = calls[0]
    ok("a 2,000-character word: every character kept, every line inside the column",
       "".join(out) == word and all(pdfmetrics.stringWidth(x, "Helvetica", 8) <= 200 for x in out))
    ok("…with a few hundred width measures, not tens of thousands (was: one per character tried)", n < 3000, f"{n} measures")
    ok("…the same lines as before", out == before(FakeDoc(), [word], "Helvetica", 8, 200))


section("r1-1/r1-3", s_acodes)
section("rr-7", s_combos_findings)
section("r1-2/r1-7", s_update)
section("r1-4/r1-5/r1-6", s_connectors)
section("r1-8", s_hard_lines)
shutil.rmtree(TMP, ignore_errors=True)                     # no lg-fixr1-* folder left behind
ok("the temporary folders are removed", not os.path.exists(TMP))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
