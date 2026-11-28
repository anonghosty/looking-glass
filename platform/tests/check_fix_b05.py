#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Audit batch 05 fixes (2026-11-27). Made-up data only.
1. intel.py (5-3): a viewer who does not see hosts never gets another viewer's lead list (no shared attribute): an
   analyst's leads() running between a researcher's leads() and its read gives the researcher nothing carried by fewer
   than MIN_HOSTS devices.
2. intel_match.py (5-7): a lead past the first 60 can be explored.
3. insider.py (5-4): a ZIP that unpacks beyond the budget is read only up to it.
Run: .venv/bin/python tests/check_fix_b05.py"""
import datetime
import io
import json
import os
import sys
import threading
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import logging  # noqa: E402
logging.disable(logging.WARNING)
from flask import Flask, g  # noqa: E402
import intel as I  # noqa: E402
import intel_match as IM  # noqa: E402
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


def store(events):
    return type("S", (), {"days": {0: Day(events)}})()


LABELS = {"event4_sinkhole_http": "Sinkhole HTTP"}


def intel_of(evs):
    return I.Intel({"store": store(evs), "svc_store": store([]), "labels": lambda: LABELS, "defined": lambda: {},
                    "allowed": lambda: True})


app = Flask(__name__)
RESEARCHER, ANALYST = {"definitions"}, {"unmasked", "view"}


def as_role(perms, fn):
    with app.test_request_context("/api/intel"):
        g.user = {"user": "t", "perms": set(perms), "csrf": "tok"}
        return fn()


print("1. Two viewers at once (5-3)")
# one device: its decoded beacon (a "contradicts its name" lead) is for viewers who see hosts only
evs = [{"src_ip": "192.0.2.10", "infection": "android.badbox2", "source": "event4_sinkhole_http",
        "http_url": line(encode(made_up(0), rkey())), "http_host": "c2.example", "http_agent": "Lingjiang"}]
intel = intel_of(evs)
ok("an analyst gets the 1-device beacon lead", any(x["priority"] == 5 for x in as_role(ANALYST, intel.leads)["leads"]))
WHICH = "leads_all" if hasattr(intel, "leads_all") else "leads"     # what gathered() calls (the old code: leads)
orig = getattr(intel, WHICH)


def interleaved():
    """The researcher's leads, then an analyst's in another thread before the researcher reads the list."""
    mine = orig()
    t = threading.Thread(target=lambda: as_role(ANALYST, orig))
    t.start(); t.join()
    return mine


setattr(intel, WHICH, interleaved)
gr = as_role(RESEARCHER, lambda: intel.gathered("infections", "android.badbox2"))
setattr(intel, WHICH, orig)
ok("the researcher's window carries no lead from the analyst's list", not any(x["priority"] == 5 for x in gr["leads"]),
   json.dumps([x["value"] for x in gr["leads"]]))
blob = json.dumps(gr["reports"], default=str)
ok("... and no beacon kind value fewer than MIN_HOSTS devices carry",
   all(not k["values"] for r in gr["reports"] for k in r["indicators"] if k["kind"] in I.BEACON_KINDS) and "windows" not in blob)
ok("the lead list is not kept on the shared object", not hasattr(intel, "_all_leads"))

print("2. Explore past the first 60 leads (5-7)")
evs2 = []
for i in range(70):
    for n, ip in (("alpha", "192.0.2.1"), ("beta", "192.0.2.2")):
        evs2.append({"src_ip": ip, "infection": n, "source": "event4_sinkhole_http", "http_host": f"c2-{i:02d}.example"})
intel2 = intel_of(evs2)
ld = as_role(ANALYST, intel2.leads)
ok("more than 60 leads, 60 listed", ld["leads_total"] > 60 and len(ld["leads"]) == 60, str(ld["leads_total"]))
listed = {x["value"] for x in ld["leads"]}
ok("leads() answers as before (no full list in it)", "all_leads" not in ld)
full_list = as_role(ANALYST, intel2.leads_all)["all_leads"] if hasattr(intel2, "leads_all") else []
past = next((x for x in full_list if x["value"] not in listed), None)
mv = IM.MatchView(intel2, {"labels": lambda: LABELS})
ok("a lead past the 60th can be explored", past is not None and as_role(ANALYST, lambda: mv.view(past["kind"], past["value"])) is not None)

print("3. A zip bomb in Trace a leak (5-4)")
import insider  # noqa: E402
insider.ZIP_UNPACK_MAX = 3_000_000                 # a small budget for the test (the old code had none)
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    for i in range(6):
        z.writestr(f"f{i}.txt", b"a" * 2_000_000)
data = buf.getvalue()
s = insider.Sealer(b"k", "/nonexistent/seals.jsonl")
f = s.seal_file(data, "x.zip")
ok("the small ZIP is small", len(data) < 5_000_000, str(len(data)))
ok("only what fits the unpack budget is read", len(f["files"]) == 1, str(len(f["files"])))

print("4. The Malpedia token over redirects (5-6)")
import tempfile  # noqa: E402
import urllib.request  # noqa: E402
import https_only  # noqa: E402
import malpedia  # noqa: E402

h = next(x for x in https_only._OPENER.handlers if isinstance(x, urllib.request.HTTPRedirectHandler))


def redirected(to):
    req = urllib.request.Request("https://malpedia.example/api/x", headers={"Authorization": "apitoken secret-test-value",
                                                                            "Accept": "application/json"})
    return h.redirect_request(req, None, 302, "Found", {}, to)


other, same = redirected("https://elsewhere.example/y"), redirected("https://malpedia.example/api/y")
ok("a redirect to another host carries no Authorization", other is not None and not other.has_header("Authorization")
   and other.has_header("Accept"), str(other and other.header_items()))
ok("... one on the same host keeps it", same is not None and same.has_header("Authorization"))
try:
    redirected("http://malpedia.example/api/y")
    ok("a redirect to http is refused", False)
except https_only.NotHttps:
    ok("a redirect to http is refused", True)
used = []


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


_real_open, _real_urlopen = https_only.open, urllib.request.urlopen
https_only.open = lambda req, timeout: (used.append("https_only"), _Resp(b"[]"))[1]
urllib.request.urlopen = lambda *a, **k: (used.append("urlopen"), _Resp(b"[]"))[1]
try:
    with tempfile.TemporaryDirectory() as td:
        malpedia.Malpedia("test-token", os.path.join(td, "cache.json"))._get("find/family/x")
finally:
    https_only.open, urllib.request.urlopen = _real_open, _real_urlopen
ok("Malpedia is asked through https_only.open", used == ["https_only"], str(used))

print("5. No raw address in the audit log (5-9)")
import intelligence as INTL  # noqa: E402


class _Coll:
    def __init__(self, rows):
        self.rows = rows

    def find(self, q=None, proj=None):
        rows = [dict(r) for r in self.rows if r.get("ip") == (q or {}).get("ip")]
        return type("C", (list,), {"limit": lambda self, n: self[:n]})(rows)

    def count_documents(self, q):
        return 0

    def estimated_document_count(self):
        return len(self.rows)


class _DB(dict):
    def list_collection_names(self):
        return list(self)


day = (datetime.datetime.now(datetime.timezone.utc).date() - datetime.timedelta(days=1)).isoformat()
audited = []
app2 = Flask("intel2")
INTL.install(app2, {"db": _DB(blocklist=_Coll([{"ip": "192.0.2.44", "filename": f"{day}-x.csv", "asn": "64500"}])),
                    "report_map": type("M", (), {"get": lambda self: {"reports": {"blocklist": {
                        "section": "Intelligence", "group": "", "title": "Block List", "has_ip": True}}}})(),
                    "settings": type("St", (), {"restricted": False, "version": 1})(),
                    "has_perm": lambda p: p in g.user["perms"], "is_demo": lambda: False, "csrf_ok": lambda: True,
                    "audit": type("A", (), {"add": lambda self, ev, **k: audited.append((ev, k))})(),
                    "svc_reports": lambda: set(), "network": lambda a: "", "cross": lambda hosts: {}})
with app2.test_request_context("/api/intelligence/host", method="POST", json={"ip": "192.0.2.44"}):
    g.user = {"user": "lg-check", "role": "analyst", "perms": {"view", "unmasked", "export"}, "csrf": "tok"}
    r = app2.view_functions["api_intelligence_host"]()
hl = [k for ev, k in audited if ev == "intelligence_host"]
ok("the host look-up is logged", len(hl) == 1, str(audited))
ok("... with the host's label, never the address", hl and "192.0.2.44" not in json.dumps(hl) and hl[0]["target"].startswith("Host "),
   str(hl))

print("6. Dates masked for researchers (5-8)")
import hostmask  # noqa: E402
for s in ("valid until 27 Nov 2026", "Nov 27, 2026", "notAfter=Nov 27 10:22:31 2026 GMT", "on 27/11/2026", "11/27/26",
          "27.11.2026", "2026/11/27", "27-Nov-2026", "November 27th, 2026"):
    m = hostmask.mask(s)
    ok(f"{s!r} masked", "<date>" in m and "2026" not in m and "/26" not in m, m)
for s, want in (("PHP/7.4.33", "PHP/7.4.33"), ("OpenSSL 1.1.1", "OpenSSL 1.1.1"), ("ratio 3/4", "ratio 3/4"),
                ("10-20-30-40.static.example.com", "<host>")):
    ok(f"{s!r} unchanged by the date rules", hostmask.mask(s) == want, hostmask.mask(s))

print("7. A torn line in the seals file (5-5)")
import time as _time  # noqa: E402
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "seals.jsonl")
    old_t, new_t = _time.time() - 500 * 86400, _time.time()
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(json.dumps({"id": "S-old", "t": old_t}) + "\n")
        fh.write('{"id": "S-torn", "t": 12\n')                  # a write cut short
        fh.write("5\n")                                         # JSON, not a seal
        fh.write(json.dumps({"id": "S-new", "t": new_t}) + "\n")
    sl = insider.Sealer(b"k", p)
    try:
        n = sl.prune(400)
        err = ""
    except Exception as e:                                      # noqa: BLE001
        n, err = None, f"{type(e).__name__}: {e}"
    left = open(p, encoding="utf-8").read()
    ok("the old seal is pruned despite the torn line", n == 1 and "S-old" not in left, err or str(n))
    ok("... the new seal and the unreadable lines are kept", "S-new" in left and "S-torn" in left and "\n5\n" in left)

print("8. Account changes by the server script are audited (5-12)")
import runpy  # noqa: E402
import auth  # noqa: E402
SRC = os.path.join(os.environ.get("B05_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "manage", "manage_users.py")          # B05_ROOT: the old copy, to show this check fails on it
with tempfile.TemporaryDirectory() as td:
    os.makedirs(os.path.join(td, "manage")); os.makedirs(os.path.join(td, "data"))
    fake = os.path.join(td, "manage", "manage_users.py")
    with open(SRC, encoding="utf-8") as fh, open(fake, "w", encoding="utf-8") as out:
        out.write(fh.read())
    u0 = auth.Users(os.path.join(td, "data", "users.json"))
    u0.data = {"users": {"grace": {"role": "analyst", "status": "active"}}, "deleted_names": []}
    u0.save()
    mod = runpy.run_path(fake, run_name="manage_users_check")
    mod["main"](["role", "grace", "researcher"])
    mod["main"](["remove", "grace"])
    log = os.path.join(td, "data", "audit.log")
    lines = [json.loads(x) for x in open(log, encoding="utf-8")] if os.path.exists(log) else []
    evs = [(x.get("event"), x.get("target"), x.get("detail")) for x in lines]
    ok("the role change is in the audit log", ("user_role", "grace", "analyst -> researcher") in evs, str(evs))
    ok("... and the removal", any(e == "user_delete" and t == "grace" for e, t, _ in evs), str(evs))
    ok("... made by the manage script", lines and all(x.get("user") == "manage script" for x in lines if x.get("event") in ("user_role", "user_delete")))

print("9. A count is never started twice after a long wait (5-10)")
import index_refresh  # noqa: E402
gate = index_refresh.Gate("check-b05")
gate.background = False
gate.busy["s"] = type("Ev", (), {"wait": lambda self, t=None: False, "set": lambda self: None})()   # a count still running
built = []


def build(cached_only=False):
    if cached_only:
        return None
    built.append(1)
    return {"n": 1}


try:
    got = gate.serve("s", None, None, build)
except RuntimeError:
    got = "refused"
ok("a request that waited out a running count does not count again", not built and got == "refused", str((built, got)))
ok("... with earlier counts it answers with those", gate.serve("s", None, {"old": 1}, build) == {"old": 1} and not built)
gate.busy.clear()
index_refresh.GATES.remove(gate)

print("10. host_label without its unused patterns (5-11)")
import host_label  # noqa: E402
ok("the unused patterns and helper are gone", not any(hasattr(host_label, n) for n in ("_V4", "_V6", "_sub")))
ok("... labels still made the same way", host_label.label_text("from 192.0.2.7.") == "from " + host_label.label("192.0.2.7") + ".")

print(f"{checks - len(fails)}/{checks} checks passed")
sys.exit(1 if fails else 0)
