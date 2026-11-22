#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Executive portal's routes and its kept past days (management.py) on a throwaway Flask app with stand-ins
(r91 coverage; made-up names and documentation addresses only):
- only the management permission: the data, an explanation and the report are refused (403) for other roles
- an unknown platform: 400 (data and report); an explanation needs kind (infection or issue) and a name of at most
  100 characters; a CVE / issue comes from the issue look-up, an infection from Malpedia's; a look-up that refuses
  the name: 400 with its own words; one that does not answer yet: "Not checked yet", 200, try again
- worker numbers in .env that are not numbers: the defaults
- a baseline file from an older version or broken: not used
- a day's MongoDB signature that cannot be read: none (tried again later)
- a past day kept in compact form: the fields the portal counts, read like the record; a newer signature loads it
  again; never more records than MGMT_PAST_RECORDS (the oldest day dropped)
No database, no server. Run: .venv/bin/python tests/check_cov_mgmt.py"""
import json, logging, os, shutil, sys, tempfile, types
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
from flask import Flask, g  # noqa: E402
import management as M  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-cov-mgmt-")
saved = {k: os.environ.get(k) for k in ("EXEC_BASELINE_WORKERS", "EXEC_BASELINE_QUEUE", "MGMT_PAST_RECORDS")}
PERMS = {"p": {"management"}}


def mp_resolve(name):
    if name == "bad-name":
        raise ValueError("That name cannot be looked up.")
    if name == "slow-name":
        raise RuntimeError("Malpedia busy")
    return [{"name": name, "found": True, "kind": "malware"}]


class Store:
    def __init__(self):
        self.days, self.loads = {}, 0

    def signature(self, start):
        if start.day == 1:
            raise RuntimeError("MongoDB unreachable")
        return {"event4_sinkhole": start.day}

    def _load(self, start):
        self.loads += 1
        return types.SimpleNamespace(start=start, events=[{"src_ip": f"192.0.2.{i}", "infection": "examplebot", "source": "event4_sinkhole",
                                                           "src_asn": 64500, "unused": "x"} for i in range(1, 4)])


try:
    os.environ.update(EXEC_BASELINE_WORKERS="many", EXEC_BASELINE_QUEUE="lots", MGMT_PAST_RECORDS="5")
    with open(os.path.join(tmp, "mgmt_baseline.json"), "w") as fh:
        json.dump({"version": 1, "days": {"comms|2026-11-01|x": {"at": 1}}}, fh)
    store = Store()
    logged = []
    app = Flask(__name__)
    app.logger.setLevel(logging.CRITICAL)

    @app.before_request
    def _me():
        g.user = {"user": "cov-mgr"}
    ctx = {"AUTH": {"has_perm": lambda p: p in PERMS["p"], "audit": types.SimpleNamespace(add=lambda *a, **k: logged.append(a))},
           "public_demo": lambda: False, "data_dir": tmp, "mp_resolve": mp_resolve, "store": store, "svc_store": store,
           "issues_resolve": lambda names: {"CVE-2023-48795": {"name": "CVE-2023-48795", "kind": "cve", "found": True}},
           "scope_text": lambda: "Made-up constituency", "country": lambda: "GH"}
    reg = M.register(app, ctx)
    I = reg["internals"]
    c = app.test_client()

    print("Who may use it")
    PERMS["p"] = {"view"}
    ok("another role: the data, an explanation and the report are refused (403)",
       all(c.get(p).status_code == 403 for p in ("/api/mgmt/comms", "/api/mgmt/explain?kind=issue&name=x", "/api/mgmt/report")))
    PERMS["p"] = {"management"}
    ok("an unknown platform: 400 (data and report)", c.get("/api/mgmt/elsewhere").status_code == 400
       and c.get("/api/mgmt/report?platform=elsewhere").status_code == 400)

    print("What one infection or issue is")
    ex = lambda q: c.get("/api/mgmt/explain?" + q)
    ok("no kind, an unknown kind, no name, a name over 100 characters: 400",
       all(ex(q).status_code == 400 for q in ("name=x", "kind=device&name=x", "kind=issue&name=", "kind=issue&name=" + "x" * 101)))
    r = ex("kind=issue&name=CVE-2023-48795")
    ok("a CVE: from the issue look-up", r.status_code == 200 and r.json["kind"] == "cve")
    ok("an issue the look-up does not know: an empty card", ex("kind=issue&name=unknown-issue").json == {})
    r = ex("kind=infection&name=examplebot")
    ok("an infection: from Malpedia's look-up", r.status_code == 200 and r.json["name"] == "examplebot" and r.json["found"])
    r = ex("kind=infection&name=bad-name")
    ok("a name the look-up refuses: 400 with its own words", r.status_code == 400 and r.json["error"] == "That name cannot be looked up.")
    r = ex("kind=infection&name=slow-name")
    ok("a look-up that does not answer yet: not checked yet, try again (200)", r.status_code == 200 and r.json["pending"] is True
       and r.json["reason"].startswith("Not checked yet") and "minute" in r.json["reason"])

    print("Kept past days")
    d1 = datetime(2026, 11, 1, tzinfo=timezone.utc)
    ok("a signature that cannot be read: none", I["sig_of"]("comms", d1) is None)
    d10 = datetime(2026, 11, 10, tzinfo=timezone.utc)
    sig = I["sig_of"]("comms", d10)
    ok("…one that can: the rows per report", sig == {"event4_sinkhole": 10})
    day = I["past_day"]("comms", d10, sig)
    rec = day.events[0]
    ok("a past day in compact form: the counted fields, read like the record; others not kept",
       len(day.events) == 3 and rec["src_ip"] == "192.0.2.1" and rec.get("infection") == "examplebot" and rec.get("unused") is None
       and rec.get("severity", "-") is None)
    loads = store.loads
    ok("asked again with the same signature: not loaded again", I["past_day"]("comms", d10, sig) is day and store.loads == loads)
    day2 = I["past_day"]("comms", d10, {"event4_sinkhole": 99})
    ok("a new signature: loaded again, one copy kept for that day", day2 is not day and store.loads == loads + 1
       and sum(1 for k in I["past"] if k[1] == d10) == 1)
    I["past_day"]("comms", d10 + timedelta(days=1), {"event4_sinkhole": 11})
    ok("more records than MGMT_PAST_RECORDS (5): the oldest day dropped", sum(len(v["day"].events) for v in I["past"].values()) <= 5
       and all(k[1] != d10 for k in I["past"]))
    I["past_day"]("comms", d10 + timedelta(days=30), {"event4_sinkhole": 40})
    ok("days too old for a baseline are dropped", all(k[1] >= d10 + timedelta(days=30) - timedelta(days=7 + 1) for k in I["past"]))
    comp = I["compact"]("services", types.SimpleNamespace(start=d10, events=[{"ip": "198.51.100.1", "issues": ["openssl"], "x": 1}]))
    ok("the compact form of a services day", comp.events[0]["ip"] == "198.51.100.1" and comp.events[0].get("issues") == ["openssl"])
    s = I["summarise"]("comms", {"kpis": {"devices": 5}, "item_counts": {"examplebot": 5}})
    ok("a day's summary: every item, marked complete, missing figures 0", s["all"] is True and s["items"] == {"examplebot": 5}
       and s["kpis"]["devices"] == 5 and all(v == 0 for k, v in s["kpis"].items() if k != "devices"))
finally:
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
