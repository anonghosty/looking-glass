#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase audit's batch 08 findings (2026-11-27), each kept fixed:
  8-1  the services definitions' figures are kept while the same days are in memory (the cache never hit);
  8-2  Intel gathered's shares are raw fractions: 1 host of 30,000 never reads "0%", 29,999 never "100%";
  8-3  the severity map's "rated by": the full name, else the person code, never the sign-in name;
  8-4  small_codes.viewer_sees_hosts() fails closed when deciding fails inside a request;
  8-5  a cut event extra says so in words, no "…";
  8-6  tools/diagnose_reports.py finds db_connect (the platform folder is on the path first);
  8-7  a damaged local pattern-fields / product-rules file is never replaced by one person's change;
  8-8  a JSON body that is not an object is a 4xx, never an error 500 (services_kb, severity_map, signin_check,
       stepup, task_monitor, tour_prefs, unusual);
  8-9  services_intel.patterns_of never serves one list's result for another list given the same id();
  8-10 tools/discover.py writes data/discovery.json, masked and owner-only, never into the code folder;
  8-11 tools/check_reports.py and tools/malpedia_check.py use this installation's port (lgauth.BASE), not :5000;
  8-12 the administrators' bell and the task monitor name people by full name or person code; bell keys hold the code;
  8-13 timezones' world table is published whole (a request during the first read saw it empty).
In-process, made-up data in temporary folders, no database, no network, no running service.
LG_B08_ROOT: run against another copy of the platform (the old code, to see these checks fail there).
Run: .venv/bin/python tests/check_fix_b08.py"""
import collections
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import types

ROOT = os.environ.get("LG_B08_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_PERSON_CODE_DIR", tempfile.mkdtemp(prefix="lg-b08-pc-"))
os.environ.pop("SIGNIN_CHECK", None)

from flask import Flask, g  # noqa: E402

import person_code  # noqa: E402
import shares  # noqa: E402

checks, fails = 0, []
TMP = tempfile.mkdtemp(prefix="lg-b08-")
SIGNIN = "kofi.mensah"                                   # a made-up sign-in name that must never be shown


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


def guard(label, fn):
    """Runs fn; an exception is a failed check (the old code raises where the new one answers)."""
    try:
        return fn()
    except Exception as e:  # noqa: BLE001
        ok(label, False, f"{type(e).__name__}: {e}")
        return None


class _Audit:
    def __init__(self):
        self.rows = []

    def add(self, kind, **kw):
        self.rows.append((kind, kw))


def _app(name, user=None):
    app = Flask(name)
    who = user or {"user": "r1", "perms": {"definitions", "settings", "unmasked"}}

    @app.before_request
    def _u():
        g.user = dict(who)
    return app


# --------------------------------------------------------------------------------------------- 8-1
print("8-1. the services definitions' figures are kept while the same days are in memory")
import services_kb  # noqa: E402


class _Day:
    def __init__(self, events, serial=1):
        self.events, self.serial = events, serial


store = types.SimpleNamespace(days={"2026-11-25": _Day([{"report": "scan_rdp", "ip": "h1", "product": "x"}]),
                                    "2026-11-26": _Day([{"report": "scan_rdp", "ip": "h2", "product": "y"}])})
calls = {"n": 0}
_bm = services_kb.banner_mask


def _counting(v):
    calls["n"] += 1
    return _bm(v)


services_kb.banner_mask = _counting
services_kb._STATS.update(at=0.0, data=None, days=[], key=None)
s1 = guard("first count", lambda: services_kb._stats(store))
n1 = calls["n"]
s2 = guard("second count", lambda: services_kb._stats(store))
ok("the second call with the same days is served from the cache (no record read again)", n1 > 0 and calls["n"] == n1,
   f"banner reads {n1} then {calls['n']}")
ok("...with the same figures", bool(s1) and s1 == s2)
store.days["2026-11-26"] = _Day(store.days["2026-11-26"].events + [{"report": "scan_rdp", "ip": "h3"}], serial=2)
s3 = guard("third count", lambda: services_kb._stats(store))
ok("a changed day is counted again", bool(s3) and s3[0]["scan_rdp"]["records"] == 3, s3 and s3[0].get("scan_rdp"))
services_kb.banner_mask = _bm

# --------------------------------------------------------------------------------------------- 8-2 / 8-9
print("8-2. Intel gathered's shares are raw fractions (1 of 30,000 is not '0%', 29,999 not '100%')")
import services_intel  # noqa: E402

N = 30000
hosts = [f"h{i}" for i in range(N)]
item = ("Product", "Example")
vals = {"r": {item: collections.Counter({h: 1 for h in hosts[:-1]})}}
combo_hosts = {"r": {(item,): collections.Counter({h: 1 for h in hosts[:-1]}), (): collections.Counter({hosts[-1]: 1})}}
data = {"fields": {"r": [{"field": "product", "kind": "exact", "label": "Product"}]}, "vals": vals,
        "showable": {"r": {item}}, "combos": {"r": collections.Counter({(item,): N - 1, (): 1})}, "combo_hosts": combo_hosts,
        "hosts": {"r": set(hosts)}, "host_reports": {h: {"r"} for h in hosts}, "host_items": {}, "host_issues": {},
        "host_cves": {}, "infected": {hosts[-1]: {"Examplebot"}}, "sink_rep": {hosts[-1]: {"Sinkhole HTTP": {"Examplebot"}}},
        "records": {"r": N}, "host_levels": {}, "host_ports": {}, "days": ["2026-11-26"]}
sv = services_intel.ServicesIntel({"patterns": types.SimpleNamespace(fields_for=lambda b: data["fields"]["r"])})
sv.index = lambda *a, **k: data
sv.for_hosts = lambda *a, **k: {}
gt = guard("gathered()", lambda: sv.gathered("r"))
if gt:
    v = gt["patterns"][0]["values"][0]
    ok("a pattern value on 29,999 of 30,000 hosts: its share is below 1, read '>99%'", 0 < 1 - v["share"] < 1e-3
       and shares.pct(v["share"]) == ">99%", (v["share"], shares.pct(v["share"])))
    c = gt["combinations"][0]
    ok("...its exact combination too", c["share"] < 1 and shares.pct(c["share"]) == ">99%", c["share"])
    sk = gt["sinkholes"]
    ok("one infected host of 30,000: its share is above 0, read '<1%'", sk["share"] > 0 and shares.pct(sk["share"]) == "<1%",
       sk["share"])
iv = guard("intel_view()", lambda: sv.intel_view("r"))
if iv:
    vv = iv["reports"][0]["indicators"][0]["values"][0]
    ok("intel_view: a value on 29,999 of 30,000 records reads '>99%'", vv["share"] < 1 and shares.pct(vv["share"]) == ">99%",
       vv["share"])
    cc = iv["reports"][0]["combinations"][0]
    ok("intel_view: its combination reads '>99%'", cc["share"] < 1 and shares.pct(cc["share"]) == ">99%", cc["share"])

print("8-9. patterns_of never serves one list's result for a new list that got the same id()")


class _M:
    def __init__(self):
        self.data, self.sink_rep, self.e = object(), {}, {"parts": [("r", [])]}

    def host(self, e):
        return e["ip"]

    def report(self, e):
        return e["report"]

    def items(self, e):
        return ()


m = _M()
e_first, e_last = {"ip": "a", "report": "r"}, {"ip": "z", "report": "r"}
sv2 = services_intel.ServicesIntel({"patterns": None})
seen_same_id = False
stale = False
for _ in range(20):
    ev1 = [e_first, {"ip": "b", "report": "r"}, e_last]
    sv2.patterns_of(ev1, m)
    addr = id(ev1)
    del ev1
    ev2 = [e_first, {"ip": "NEW", "report": "r"}, e_last]           # same length, same first and last record
    seen_same_id = seen_same_id or id(ev2) == addr
    mine, _pat = sv2.patterns_of(ev2, m)
    if not any(e["ip"] == "NEW" for e in mine):
        stale = True
    del ev2
ok("a new list's own records are counted, even when it got the freed list's id()", not stale,
   f"stale result served (id reused: {seen_same_id})")

# --------------------------------------------------------------------------------------------- 8-3
print("8-3. the severity map's 'rated by' is never the sign-in name")
import severity_map  # noqa: E402

rows = guard("build_rows", lambda: severity_map.build_rows({}, {"quietbot": "Infection"},
                                                           {"quietbot": {"level": "high", "by": SIGNIN, "at": "x"}},
                                                           lambda u: ""))
r0 = (rows or [{}])[0]
ok("no full name known: the person code, not the sign-in name", r0.get("rated_by") == person_code.code(SIGNIN)
   and SIGNIN not in json.dumps(rows), r0.get("rated_by"))
rows = severity_map.build_rows({}, {"quietbot": "Infection"}, {"quietbot": {"level": "high", "by": SIGNIN}}, None)
ok("...also without a people_name at all", rows[0].get("rated_by") == person_code.code(SIGNIN), rows[0].get("rated_by"))
rows = severity_map.build_rows({}, {"quietbot": "Infection"}, {"quietbot": {"level": "high", "by": SIGNIN}},
                               lambda u: "Kofi Mensah")
ok("a full name is shown as it is", rows[0].get("rated_by") == "Kofi Mensah", rows[0].get("rated_by"))

# --------------------------------------------------------------------------------------------- 8-4
print("8-4. viewer_sees_hosts() fails closed inside a request")
import small_codes  # noqa: E402

ok("outside a request (tools, tests): True, as before", small_codes.viewer_sees_hosts() is True)


class _Boom(dict):
    def get(self, *a, **k):
        raise RuntimeError("broken user record")


app = Flask("b08-small")
with app.test_request_context("/api/x"):
    g.user = _Boom({"user": "r"})                           # signed in, but its permissions cannot be read
    r = guard("viewer_sees_hosts in a failing request", small_codes.viewer_sees_hosts)
    ok("deciding fails inside a request: False (the codes are held)", r is False, r)
    ok("...so a pattern of 2 hosts gets no lasting code", small_codes.code_for("LG-C-TEST", 2) is None)
with app.test_request_context("/api/x"):
    g.user = {"user": "a", "perms": ["unmasked"]}
    ok("an analyst (unmasked) still sees hosts", small_codes.viewer_sees_hosts() is True)
    g.user = {"user": "r", "perms": ["definitions"]}
    ok("a researcher does not", small_codes.viewer_sees_hosts() is False)

# --------------------------------------------------------------------------------------------- 8-5
print("8-5. a cut event extra says so in words")
import sources  # noqa: E402

doc = {"src_ip": "192.0.2.1", "src_geo": "KE", "extracted_date": "2026-11-26", "long_field": "x" * 2000}
ev = guard("normalise", lambda: sources.normalise(doc, {"layout": "standard", "name": "event4_x", "label": "X", "class": "C"}))
lf = ((ev or {}).get("extras") or {}).get("long_field", "")
ok("no '…' and no '...' in a cut value", lf and "…" not in lf and "..." not in lf, lf[-60:])
ok("...it says it was cut and its full length", "cut" in lf and "2,000" in lf and lf.startswith("x" * sources.EXTRA_MAX), lf[-60:])

# --------------------------------------------------------------------------------------------- 8-7 / 8-8 (services_kb)
print("8-7. a damaged local pattern-fields or product-rules file is never replaced")
import svc_patterns  # noqa: E402

pbase = os.path.join(TMP, "pat")
os.makedirs(os.path.join(pbase, "data"))
local = os.path.join(pbase, "data", "pattern_fields_local.json")
rules_local = os.path.join(pbase, "data", "product_rules_local.json")
DAMAGED = '{"reports": {"scan_a": {"fields": [{"field": "x", "kind": "exact"}], "by": "someone"}, "scan_b": '
for p in (local, rules_local):
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(DAMAGED)
pat = svc_patterns.Patterns(pbase)
for what, fn in (("save", lambda: pat.save("scan_c", [{"field": "banner", "kind": "template"}], "r1")),
                 ("reset", lambda: pat.reset("scan_c")),
                 ("add_rule", lambda: pat.add_rule("RouterOS", "MikroTik RouterOS", True, "r1"))):
    raised = False
    try:
        fn()
    except ValueError:
        raised = True
    except Exception:  # noqa: BLE001
        raised = False
    path = rules_local if what == "add_rule" else local
    with open(path, encoding="utf-8") as fh:
        ok(f"{what}: refused with a reason, the damaged file left exactly as it was", raised and fh.read() == DAMAGED)
os.remove(local)
ok("a missing file is still created by a save", bool(pat.save("scan_c", [{"field": "banner", "kind": "template"}], "r1"))
   and os.path.exists(local))

print("8-8. a JSON body that is not an object is never an error 500")


def status(resp):
    return resp.status_code


with open(local, "w", encoding="utf-8") as fh:
    fh.write(DAMAGED)
rmap = types.SimpleNamespace(get=lambda: {"reports": {"scan_x": {"section": "Services", "title": "Accessible X"}}},
                             description=lambda n: {}, descriptions=lambda: {}, rules=lambda: {})
kapp = _app("b08-kb")
services_kb.install(kapp, {"report_map": rmap, "svc_store": types.SimpleNamespace(days={}), "report_info": lambda n: {},
                           "notes": types.SimpleNamespace(list=lambda *a: []), "allowed": lambda: True,
                           "cve_card": lambda n: {}, "issues_kb": lambda: {}, "collections": lambda: [],
                           "patterns": svc_patterns.Patterns(pbase), "services_intel": None,
                           "change_allowed": lambda: True, "fresh": lambda: True, "audit": _Audit(),
                           "user": lambda: {"user": "r1"}})
kc = kapp.test_client()
st = status(kc.post("/api/kb/service/fields", json=[1, 2]))
ok("services_kb pattern fields: a list as the body is a 4xx", 400 <= st < 500, st)
st = status(kc.post("/api/kb/service/fields", json={"name": "scan_x", "fields": ["banner"]}))
ok("services_kb pattern fields: a field that is not {field, kind} is a 400", st == 400, st)
st = status(kc.post("/api/kb/product-rules", json=[1]))
ok("services_kb product rules: a list as the body is a 4xx", 400 <= st < 500, st)
r = kc.post("/api/kb/service/fields", json={"name": "scan_x", "reset": True})
with open(local, encoding="utf-8") as fh:
    ok("8-7 through the page: a reset on a damaged file is refused (409) and the file kept", r.status_code == 409
       and fh.read() == DAMAGED, r.status_code)

sbase = os.path.join(TMP, "sev")
os.makedirs(os.path.join(sbase, "data"))
sapp = _app("b08-sev")
severity_map.install(sapp, {"base_dir": sbase, "has_perm": lambda p: True, "csrf_ok": lambda: True, "audit": _Audit(),
                            "people_name": lambda u: ""})
st = status(sapp.test_client().post("/api/kb/severity-map/rate", json=[1]))
ok("severity map rate: a list as the body is a 4xx", 400 <= st < 500, st)

import tour_prefs  # noqa: E402
tapp = _app("b08-tour")
tour_prefs.install(tapp, {"base_dir": os.path.join(TMP, "tour"), "csrf_ok": lambda: True})
st = status(tapp.test_client().post("/api/tour", json=[1]))
ok("tour: a list as the body is not an error 500", st < 500, st)

import task_monitor  # noqa: E402
mapp = _app("b08-tm")
task_monitor.install(mapp, {"base_dir": TMP, "has_perm": lambda p: True, "csrf_ok": lambda: True, "fresh": lambda: True,
                            "audit": _Audit(), "cache": None})
st = status(mapp.test_client().post("/api/admin/monitor/cache", json=[1]))
ok("task monitor cache: a list as the body is a 400", st == 400, st)

import signin_check  # noqa: E402
capp = _app("b08-sc")
signin_check.install(capp, {"base_dir": os.path.join(TMP, "sc"), "has_perm": lambda p: True, "csrf_ok": lambda: True,
                            "fresh": lambda: True, "audit": _Audit(), "store": types.SimpleNamespace(count=lambda u: 0),
                            "min_passkeys": 2})
st = status(capp.test_client().post("/api/admin/signin-check", json=[1]))
ok("sign-in check: a list as the body is a 400", st == 400, st)

import stepup  # noqa: E402
with Flask("b08-su").test_request_context("/api/admin/update", method="POST", json=[1]):
    hit = guard("stepup rule_for with a list body", lambda: stepup.rule_for("POST", "/api/admin/update"))
    ok("step-up gate: a list as the body matches no rule and raises nothing", hit is None and "stepup rule_for with a list body"
       not in fails, hit)
with Flask("b08-su2").test_request_context("/api/intelligence", method="POST", json=["reveal"]):
    hit = guard("stepup _arg with a list body", lambda: stepup.rule_for("POST", "/api/intelligence"))
    ok("step-up gate: /api/intelligence with a list body raises nothing", "stepup _arg with a list body" not in fails, hit)

import unusual  # noqa: E402
ubase = os.path.join(TMP, "unusual")
os.makedirs(os.path.join(ubase, "data", "unusual"))
TID = "0123456789ab"
with open(os.path.join(ubase, "data", "unusual", "suggestions.json"), "w", encoding="utf-8") as fh:
    json.dump({"day": "2026-11-26", "suggestions": [{"id": TID, "kind": "asn", "key": "AS1", "asn": "1", "reports": ["r"],
                                                     "value": 9, "day": "2026-11-26", "new": True, "normal": 0,
                                                     "ratio": 9}]}, fh)
with open(os.path.join(ubase, "data", "unusual", "decisions.json"), "w", encoding="utf-8") as fh:
    json.dump({"confirmed": {"ba9876543210": {"name": "Watched", "kind": "asn", "key": "AS2", "asn": "2", "reports": ["r"],
                                              "by": SIGNIN, "at": 1}}}, fh)
uapp = _app("b08-un")
unusual.install(uapp, {"base_dir": ubase, "has_perm": lambda p: True, "csrf_ok": lambda: True, "audit": _Audit(),
                       "db": None, "settings": None, "network": lambda a: "", "svc_label": lambda n: n})
uc = uapp.test_client()
st = status(uc.post(f"/api/unusual/{TID}/confirm", json=[1]))
ok("unusual confirm: a list as the body is a 400", st == 400, st)
r = uc.get("/api/unusual")
conf = (r.get_json() or {}).get("confirmed") or [{}] if r.status_code == 200 else [{}]
ok("unusual: 'confirmed by' without a full name is the person code, never the sign-in name (8-3's rule)",
   conf[0].get("confirmed_by") == person_code.code(SIGNIN), (r.status_code, conf[0].get("confirmed_by")))

# --------------------------------------------------------------------------------------------- 8-6 / 8-10 (tools, subprocess)
print("8-6 / 8-10. the tools, run with a stand-in database (no MongoDB, no network)")
stubs = os.path.join(TMP, "stubs")
os.makedirs(os.path.join(stubs, "pymongo"))
os.makedirs(os.path.join(stubs, "dotenv"))
with open(os.path.join(stubs, "dotenv", "__init__.py"), "w") as fh:
    fh.write("def load_dotenv(*a, **k):\n    return False\n")
STUB_MONGO = '''
import os
class _Cur(list):
    def sort(self, *a, **k): return self
    def limit(self, n): return _Cur(self[:n])
class _Coll:
    DOC = {"_id": 1, "src_ip": "198.51.100.7", "src_hostname": "mail.example-host.org", "src_geo": "KE",
           "filename": "2026-11-26-event4_x-kenya.csv", "contact": "admin@example-host.org"}
    def estimated_document_count(self): return 1
    def list_indexes(self): return [{"key": {"filename": 1}}]
    def find(self, *a, **k): return _Cur([dict(self.DOC)])
    def count_documents(self, q): return 1
    def distinct(self, f, q): return ["2026-11-26-event4_x-198.51.100.7.csv"]
class _DB:
    def list_collection_names(self): return ["event4_x"]
    def __getitem__(self, n): return _Coll()
class MongoClient:
    def __init__(self, *a, **k):
        if os.environ.get("B08_STUB_EXIT"):
            raise SystemExit(int(os.environ["B08_STUB_EXIT"]))
    def __getitem__(self, n): return _DB()
'''
with open(os.path.join(stubs, "pymongo", "__init__.py"), "w") as fh:
    fh.write(STUB_MONGO)


def run_tool(tree, script, extra_env=None):
    # the stand-ins first, then the suite's outside-connection guard when it is set (tests/no_outside)
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "PYTHONPATH": os.pathsep.join(p for p in (stubs, os.environ.get("PYTHONPATH", "")) if p), "HOME": TMP,
           "LG_PERSON_CODE_DIR": os.environ["LG_PERSON_CODE_DIR"], **(extra_env or {})}
    if os.environ.get("LG_NO_OUTSIDE"):
        env["LG_NO_OUTSIDE"] = os.environ["LG_NO_OUTSIDE"]
    return subprocess.run([sys.executable, os.path.join(tree, "tools", script)], cwd=TMP, env=env,
                          capture_output=True, text=True, timeout=120)


r = run_tool(ROOT, "diagnose_reports.py", {"B08_STUB_EXIT": "42"})
ok("diagnose_reports.py gets as far as connecting (db_connect and sources found)", r.returncode == 42,
   (r.returncode, (r.stderr or "").strip().splitlines()[-1:]))

tree = os.path.join(TMP, "tree")
os.makedirs(os.path.join(tree, "tools"))
for f in ("db_connect.py", "hostmask.py", "ip_find.py"):
    if os.path.exists(os.path.join(ROOT, f)):
        shutil.copy(os.path.join(ROOT, f), os.path.join(tree, f))
shutil.copy(os.path.join(ROOT, "tools", "discover.py"), os.path.join(tree, "tools", "discover.py"))
r = run_tool(tree, "discover.py")
ok("discover.py ran", r.returncode == 0, (r.returncode, (r.stderr or "").strip().splitlines()[-1:]))
written = [os.path.join(dp, f) for dp, _d, fs in os.walk(tree) for f in fs if f.endswith(".json")]
in_code = [p for p in written if os.sep + "tools" + os.sep in p]
ok("nothing is written into the code folder (tools/)", not in_code, in_code)
out = os.path.join(tree, "data", "discovery.json")
ok("the survey is data/discovery.json", os.path.exists(out), written)
if os.path.exists(out):
    body = open(out, encoding="utf-8").read()
    ok("...owner-only (0600)", stat.S_IMODE(os.stat(out).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(out).st_mode)))
    ok("...masked: no address, host name or e-mail from the records", "198.51.100.7" not in body
       and "mail.example-host.org" not in body and "admin@example-host.org" not in body, body[:300])
    ok("...the layout is still there (field names, the src/dst fields)", '"src_ip"' in body and '"srcdst"' in body)

# --------------------------------------------------------------------------------------------- 8-11
print("8-11. the tools that call the service use this installation's port")
for script in ("check_reports.py", "malpedia_check.py"):
    src = open(os.path.join(ROOT, "tools", script), encoding="utf-8").read()
    ok(f"{script}: no fixed 127.0.0.1:5000, the address from lgauth.BASE (source check: it needs the running service)",
       "127.0.0.1:5000" not in src and "lgauth.BASE" in src)

# --------------------------------------------------------------------------------------------- 8-12
print("8-12. the administrators' bell and the task monitor never show a sign-in name")
import system_alerts  # noqa: E402

abase = os.path.join(TMP, "alerts")
os.makedirs(os.path.join(abase, "data"))
import time as _t  # noqa: E402
now = _t.time()
users = {SIGNIN: {"status": "pending", "created": now - 60, "profile": {"full_name": ""},
                  "last_login": {"at": now - 100, "ip": "8.8.8.8"}},
         "ama.owusu": {"status": "pending", "created": now - 30, "profile": {"full_name": "Ama Owusu"}}}
with open(os.path.join(abase, "data", "users.json"), "w", encoding="utf-8") as fh:
    json.dump({"users": users}, fh)
try:
    import insider
    limit = insider.SMALL_TRACE_ALERT
except Exception:  # noqa: BLE001
    limit = 10
with open(os.path.join(abase, "data", "trace_watch.json"), "w", encoding="utf-8") as fh:
    json.dump({SIGNIN: [now - i for i in range(limit + 1)]}, fh)
al = system_alerts.Alerts(abase, env={"ACCESS_MODE": "local"})
got = (guard("signups", al._signups) or []) + (guard("public sign-ins", lambda: al._public_signins(now)) or []) \
    + (guard("small traces", lambda: al._small_traces(now)) or [])
blob = json.dumps(got)
ok("three alerts made (sign-ups, sign-ins from the internet, small traces)", len(got) == 3, [a.get("key") for a in got])
ok("no sign-in name in their titles, texts or keys", SIGNIN not in blob and "ama.owusu" not in blob, blob[:400])
ok("...the person code instead where there is no full name", person_code.code(SIGNIN) in blob)
ok("...the full name where there is one", "Ama Owusu" in blob)
tr = [a for a in got if a["key"].startswith("small-traces:")]
ok("the small-traces key holds the person code", bool(tr) and tr[0]["key"].split(":")[1] == person_code.code(SIGNIN),
   tr and tr[0]["key"])

task_monitor.request_tracker = types.SimpleNamespace(
    processes=lambda: [{"route": "/api/x", "method": "GET", "user": SIGNIN, "role": "analyst", "seconds": 1.0},
                       {"route": "/login", "method": "POST", "user": "(signing in)", "role": "", "seconds": 0.1}],
    users=lambda: [{"user": SIGNIN, "role": "analyst", "requests": 3, "seconds": 1.0, "share": 1.0}],
    WINDOW_S=600)
task_monitor._at_rest = lambda *a: None
task_monitor._cron = lambda: ([], True)
task_monitor._front = lambda: {}
task_monitor._mongod = lambda: {"running": False}
task_monitor.pipeline_link = types.SimpleNamespace(find_dir=lambda b: None)
snap = guard("task monitor snapshot", lambda: task_monitor.snapshot({"base_dir": abase}))
if snap:
    tblob = json.dumps({"p": snap["processes"], "u": snap["users"]})
    ok("task monitor: requests and accounts name no sign-in name", SIGNIN not in tblob, tblob[:300])
    ok("...the person code instead; '(signing in)' as it is", person_code.code(SIGNIN) in tblob and "(signing in)" in tblob)
    lbl = [p.get("user_label") for p in snap["processes"] if p.get("route") == "/api/x"] + [snap["users"][0].get("user_label")]
    ok("...each row's user_label (what the page shows) is the person code when no full name is known",
       lbl == [person_code.code(SIGNIN)] * 2, lbl)
    import people  # noqa: E402
    people.People(types.SimpleNamespace(get=lambda u: {"profile": {"full_name": "Kofi Mensah"}} if u == SIGNIN else None))
    snap = task_monitor.snapshot({"base_dir": abase})
    ok("...and the full name when there is one", snap["users"][0].get("user_label") == "Kofi Mensah"
       and SIGNIN not in json.dumps(snap["users"]), snap["users"][0])

# --------------------------------------------------------------------------------------------- 8-13
print("8-13. the world's time zones are never read half-filled")
import timezones  # noqa: E402

lines = ["# zone.tab\n", "KE\t-0117+03649\tAfrica/Nairobi\n", "US\t+404251-0740023\tAmerica/New_York\n",
         "FR\t+4852+00220\tEurope/Paris\n"]
started, release = threading.Event(), threading.Event()
first = {"done": False}


class _SlowFile:
    def __init__(self, slow):
        self.slow = slow

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def __iter__(self):
        for i, ln in enumerate(lines):
            if self.slow and i == 2:
                started.set()
                release.wait(10)
            yield ln


def _open(path, *a, **k):
    if not str(path).endswith("zone.tab"):
        return open(path, *a, **k)
    slow = not first["done"]
    first["done"] = True
    return _SlowFile(slow)


timezones.open = _open
timezones._WORLD = None
th = threading.Thread(target=timezones._world, daemon=True)
th.start()
started.wait(10)
mid = list(timezones.zones_of("FR"))          # asked while the first read is still going
release.set()
th.join(10)
del timezones.open
ok("a country asked while the first read is still going gets its zone", mid == ["Europe/Paris"], mid)
ok("...and the table is whole afterwards", timezones.zones_of("US") == ["America/New_York"], timezones.zones_of("US"))
timezones._WORLD = None

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
