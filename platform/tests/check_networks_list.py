#!/usr/bin/env python3
"""The network list (Settings and the Definitions page) lists every network in the reports from the start (2026-11-13: a
fresh install showed an empty list until Identify networks had run). In-process, on a throwaway registry file and
made-up days: no database, nothing real touched.
- a network in the reports but not in the registry: listed, not reviewed, not identified, with its events
- a network in the registry: listed as before, not twice
- naming one that is not identified yet saves it (and starts the registry file on a fresh install); one not in the
  reports is refused
Run: .venv/bin/python tests/check_networks_list.py"""
import json, os, shutil, sys, tempfile
from types import SimpleNamespace
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


USER, UA = auth.TEST_PREFIX + "nets-admin", "lg-check-networks"
users, sessions, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["audit"]
real = (users.get, audit.add, A.asn_registry.path, A.asn_registry.mtime, A.asn_registry.asns, dict(A.store.days), dict(A.svc["store"].days))
users.get = lambda name: ({"status": "active", "role": "admin", "changed": 0} if name == USER else real[0](name))
audit.add = lambda *a, **k: None
tmp = tempfile.mkdtemp(prefix="lg-nets-")
reg = os.path.join(tmp, "asns.json")


def use_registry(content):
    if content is None:
        if os.path.exists(reg):
            os.remove(reg)
    else:
        json.dump({"asns": content}, open(reg, "w"))
    A.asn_registry.path, A.asn_registry.mtime, A.asn_registry.asns = reg, None, {}
    A._NETS_CACHE.update(key=None)


ev = lambda src, dst="": {"src_asn": src, "dst_asn": dst, "src_geo": "GH", "dst_geo": "US", "events": 1}
A.store.days.clear(); A.svc["store"].days.clear()
A.store.days["d1"] = SimpleNamespace(events=[ev("64500", "64501"), ev("64500"), ev("64502")], asn_raw={"64500": 2, "64502": 1, "64501": 1})
A.svc["store"].days["d1"] = SimpleNamespace(events=[{"asn": "64503", "geo": "GH"}], asn_raw={"64503": 1})
token = sessions.create(USER, "127.0.0.1", UA)
csrf = max((s for s in sessions.s.values() if s["user"] == USER and s.get("csrf")), key=lambda s: s["created"])["csrf"]
c = A.app.test_client(); c.set_cookie("lg_session", token)
H = {"User-Agent": UA}
try:
    print("A fresh install: no registry file")
    use_registry(None)
    j = c.get("/api/networks", headers=H).json
    got = {r["asn"]: r for r in j["networks"]}
    ok("every network in the reports is listed", set(got) == {"64500", "64501", "64502", "64503"}, ", ".join(sorted(got)))
    ok("…not reviewed and not identified, no name", all(not r["reviewed"] and r.get("identified") is False and r["name"] == "" for r in got.values()))
    ok("…with its events, busiest first", got["64500"]["events"] == 2 and j["networks"][0]["asn"] == "64500", str([r["asn"] for r in j["networks"]]))
    print("A registry that knows some of them")
    use_registry({"64500": {"name": "Example Telecom", "type": "isp", "reviewed": True, "events_last_check": 2}})
    j = c.get("/api/networks", headers=H).json
    ids = [r["asn"] for r in j["networks"]]
    ok("a network in the registry is listed once, as it is", ids.count("64500") == 1
       and next(r for r in j["networks"] if r["asn"] == "64500")["name"] == "Example Telecom")
    ok("…the others are listed for review", {"64501", "64502", "64503"} <= set(ids))
    print("Naming one that is not identified yet")
    use_registry(None)
    hdr = dict(H, **{"X-CSRF-Token": csrf})
    r = c.post("/api/networks/entry", json={"asn": "64502", "name": "Sample University", "type": "unknown", "note": ""}, headers=hdr)
    ok("saved, the registry file started", r.status_code == 200 and os.path.exists(reg), f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    saved = json.load(open(reg))["asns"].get("64502", {}) if os.path.exists(reg) else {}
    ok("…named, reviewed, with its country", saved.get("name") == "Sample University" and saved.get("reviewed") is True and saved.get("country") == "GH", str(saved))
    r = c.post("/api/networks/entry", json={"asn": "65999", "name": "Made Up", "type": "unknown"}, headers=hdr)
    ok("a network that is not in the reports: refused", r.status_code == 404, str(r.status_code))
finally:
    sessions.end(key=auth._h(token))
    users.get, audit.add = real[0], real[1]
    A.asn_registry.path, A.asn_registry.mtime, A.asn_registry.asns = real[2], None, {}
    A.store.days.clear(); A.store.days.update(real[5]); A.svc["store"].days.clear(); A.svc["store"].days.update(real[6])
    A._NETS_CACHE.update(key=None)
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
