#!/usr/bin/env python3
"""Settings → Task monitor (task_monitor.py): admins only; every section present; no address in it; the two actions
(clear the kept answers, how long they are kept) need CSRF and a fresh sign-in, refuse bad values, take effect and are
in the audit log. A throwaway file for the chosen time: the real setting is never changed.
Run: .venv/bin/python tests/check_task_monitor.py"""
import json, os, re, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0"); os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402
import response_cache as RC  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


users, sessions, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["audit"]
ADMIN, ANALYST, UA = auth.TEST_PREFIX + "mon-admin", auth.TEST_PREFIX + "mon-analyst", "lg-check-monitor"
real_get, real_add, logged = users.get, audit.add, []
users.get = lambda n: ({"status": "active", "role": "admin", "changed": 0} if n == ADMIN else
                       {"status": "active", "role": "analyst", "changed": 0} if n == ANALYST else real_get(n))
audit.add = lambda ev, **k: logged.append((ev, k))
tmp = tempfile.mkdtemp(prefix="lg-monitor-")
real_override = dict(RC.OVERRIDE)
RC.OVERRIDE.update(path=os.path.join(tmp, "performance.json"), mtime=None, ttl=None)
ta, tn = sessions.create(ADMIN, "127.0.0.1", UA), sessions.create(ANALYST, "127.0.0.1", UA)
csrf = max((s for s in sessions.s.values() if s["user"] == ADMIN and s.get("csrf")), key=lambda s: s["created"])["csrf"]
a = A.app.test_client(); a.set_cookie("lg_session", ta)
n = A.app.test_client(); n.set_cookie("lg_session", tn)
H = {"User-Agent": UA}; HC = dict(H, **{"X-CSRF-Token": csrf})
try:
    print("Reading")
    ok("an analyst cannot open the monitor (403)", n.get("/api/admin/monitor", headers=H).status_code == 403)
    r = a.get("/api/admin/monitor", headers=H); j = r.json or {}
    ok("an admin gets it", r.status_code == 200, str(r.status_code))
    ok("every section is there", all(k in j for k in ("service", "requests", "jobs", "slow", "cache", "mongodb", "machine",
                                                     "pipeline", "restarts", "locks", "alerts")), str(sorted(j)))
    ok("the service: memory, threads, uptime", j.get("service", {}).get("memory_mb", 0) > 0 and j["service"].get("threads", 0) > 0
       and "uptime_s" in j["service"])
    ok("requests: running now, per minute over the last hour", j.get("requests", {}).get("running", 0) >= 1
       and len(j["requests"].get("per_minute", [])) == 60)
    ok("the background jobs are named in plain words", all(x.get("name") and " " in x["name"] for x in j.get("jobs", [])))
    ok("the cache: time, entries, hits and misses", all(k in (j.get("cache") or {}) for k in ("ttl_s", "entries", "hit", "miss")))
    ok("the machine: load, memory, disk", all(k in j.get("machine", {}) for k in ("memory_available_mb", "disk_free_gb")))
    print("Processes, users, performance")
    import request_tracker as RT, time as _t
    ok("the new sections are there", all(k in j for k in ("processes", "users", "performance", "users_window_min")), str(sorted(j)))
    ok("the monitor's own request is a running process, named by account", any(p["user"] == ADMIN and p["route"] == "/api/admin/monitor"
       for p in j["processes"]), str(j["processes"][:3]))
    for _ in range(3):
        n.get("/api/admin/monitor", headers=H)                 # the analyst: three refused requests, still theirs
    us = {u["user"]: u for u in RT.users()}
    ok("each account's requests are counted, with time and CPU", us.get(ANALYST, {}).get("requests", 0) >= 3
       and us[ANALYST]["seconds"] >= 0 and "cpu_seconds" in us[ANALYST] and us[ANALYST]["role"] == "analyst", str(us.get(ANALYST)))
    ok("…and the heaviest first, with its share", RT.users()[0]["seconds"] >= RT.users()[-1]["seconds"] and "share" in RT.users()[0])
    ok("no address in processes or users", not re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", json.dumps([RT.processes(), RT.users()])))
    import task_monitor as TM
    _t.sleep(TM.Sampler.STEP_S * 2 + 0.5)
    perf = a.get("/api/admin/monitor", headers=H).json.get("performance", [])
    ok("the performance history fills while someone looks (CPU, memory, disk, network)", perf and all(k in perf[-1] for k in
       ("cpu", "memory_used_mb", "net_rx_kbs", "service_mb")), str(perf[-1] if perf else perf))
    j2 = a.get("/api/admin/monitor", headers=H).json
    ok("CPU use appears from the second reading", "cpu_percent" in j2.get("service", {}))
    raw = json.dumps(j2)
    ips = [x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw) if x not in ("127.0.0.1",)]
    ok("no address anywhere in it", not ips, str(ips[:5]))
    print("Clearing the kept answers")
    ok("an analyst cannot (403)", n.post("/api/admin/monitor/cache", json={"action": "clear"}, headers=H).status_code == 403)
    ok("no CSRF token: refused", a.post("/api/admin/monitor/cache", json={"action": "clear"}, headers=H).status_code == 403)
    s = sessions.s[auth._h(ta)]; keep = (s.get("persist"), s.get("created"))
    s["persist"], s["created"] = True, s["created"] - 13 * 3600
    r = a.post("/api/admin/monitor/cache", json={"action": "clear"}, headers=HC)
    ok("a stay-signed-in session older than 12 h must sign in again", r.status_code == 403 and (r.json or {}).get("reauth"))
    s["persist"], s["created"] = keep
    rc = A.RESPONSE_CACHE
    rc._put(("x",), (0, rc.gen, 200, [], b"{}"))
    logged.clear()
    r = a.post("/api/admin/monitor/cache", json={"action": "clear"}, headers=HC)
    ok("an admin clears them", r.status_code == 200 and not rc.entries, str(r.json))
    ok("…written to the audit log", any(e == "cache_cleared" and k.get("user") == ADMIN for e, k in logged), str(logged))
    print("How long answers are kept")
    for bad in ("60", -1, RC.TTL_MAX + 1, True, 1.5, None):
        r = a.post("/api/admin/monitor/cache", json={"ttl": bad}, headers=HC)
        ok(f"refused: {bad!r}", r.status_code == 400, str(r.status_code))
    logged.clear()
    r = a.post("/api/admin/monitor/cache", json={"ttl": 60}, headers=HC)
    ok("set to 60 s: taken at once", r.status_code == 200 and RC.ttl() == 60, f"{r.status_code} {RC.ttl()}")
    ok("…kept in its own private file (600)", oct(os.stat(RC.OVERRIDE["path"]).st_mode & 0o777) == "0o600")
    ok("…written to the audit log with old and new", any(e == "cache_time_changed" and "-> 60 s" in k.get("detail", "") for e, k in logged), str(logged))
    ok("…and the monitor shows it, from Settings", (a.get("/api/admin/monitor", headers=H).json or {}).get("cache", {}).get("ttl_from_settings") is True)
    r = a.post("/api/admin/monitor/cache", json={"ttl": 0}, headers=HC)
    ok("0 switches the cache off", r.status_code == 200 and RC.ttl() == 0)
    open(RC.OVERRIDE["path"], "w").write("not json")
    ok("a broken file falls back to .env", RC.ttl() == RC.env_ttl())
    import audit_portal
    ok("the Audit portal names both actions", audit_portal.LABEL.get("cache_cleared") and audit_portal.LABEL.get("cache_time_changed")
       and audit_portal.TAB_OF.get("cache_time_changed") == "config")
finally:
    users.get, audit.add = real_get, real_add
    RC.OVERRIDE.clear(); RC.OVERRIDE.update(real_override)
    for t in (ta, tn):
        sessions.end(key=auth._h(t))
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
