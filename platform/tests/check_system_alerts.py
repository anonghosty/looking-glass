#!/usr/bin/env python3
"""System alerts in the admins' bell (system_alerts.py, notifications.py): restarts, a failed or missing pipeline run,
a low disk, a failed name refresh; admins only; cleared per person; a new event shows again; a broken file never
breaks the bell. Throwaway folders only; no database. Run: .venv/bin/python tests/check_system_alerts.py"""
import json, os, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0"); os.environ["TRUST_PROXY"] = "0"
import system_alerts as SA  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


root = tempfile.mkdtemp(prefix="lg-sysalerts-")
plat, pipe = os.path.join(root, "platform"), os.path.join(root, "database")
os.makedirs(os.path.join(plat, "data")); os.makedirs(os.path.join(pipe, "reports"))
open(os.path.join(pipe, "shadowserver_pipeline.py"), "w").write("# stand-in\n")
open(os.path.join(pipe, ".env"), "w").write(f"DATA_DIR={os.path.join(pipe, 'reports')}\n")
keep_env = os.environ.pop("PIPELINE_DIR", None)
try:
    now = time.time()
    A = SA.Alerts(plat, env={})
    keys = lambda: {a["key"].split(":")[0] for a in A.current(now)}  # noqa: E731
    print("Nothing to say")
    ok("no files: no alert", A.current(now) == [])
    print("Restarts")
    SA.note_start(os.path.join(plat, "data"), now=now - 3600)
    SA.note_start(os.path.join(plat, "data"), now=now - 3 * 86400)
    r = [a for a in A.current(now) if a["key"].startswith("restart")]
    ok("a start in the last 24 h is shown, an older one not", len(r) == 1 and not r[0]["problem"], str(r))
    ok("the restart file is private (600)", oct(os.stat(os.path.join(plat, "data", "restarts.jsonl")).st_mode & 0o777) == "0o600")
    for i in range(60):
        SA.note_start(os.path.join(plat, "data"), now=now - 5 * 86400 + i)
    ok("only the last 50 starts are kept", len(open(os.path.join(plat, "data", "restarts.jsonl")).read().splitlines()) == 50)
    SA.note_start(os.path.join(plat, "data"), now=now - 1800)          # a recent one again, for the checks below
    for k in (3, 2):
        SA.note_start(os.path.join(plat, "data"), now=now - k * 600)
    r = [a for a in A.current(now) if a["key"].startswith("restart")]
    ok("several starts in a day are one alert, the latest, with how many", len(r) == 1 and r[0]["key"] == f"restart:{round(now - 1200)}"
       and "3 times" in r[0]["title"], str(r))
    A.clear("ann", ["sys:" + r[0]["key"]])
    SA.note_start(os.path.join(plat, "data"), now=now - 60)
    ok("…cleared, a new start shows it again", any(i["id"] == f"sys:restart:{round(now - 60)}" for i in A.for_user("ann", now)))
    print("The pipeline's run (its status file, found beside the platform)")
    stp = os.path.join(pipe, "reports", "pipeline_status.json")
    json.dump({"finished": round(now - 600), "ok": True, "free_gb": 900, "min_free_gb": 5, "disk_low": False}, open(stp, "w"))
    ok("a good recent run: nothing", not keys() & {"pipeline-failed", "pipeline-stale", "disk-low"}, str(keys()))
    json.dump({"finished": round(now - 600), "ok": False, "file_errors": 2, "email_failed": 0, "disk_low": False}, open(stp, "w"))
    f = [a for a in A.current(now) if a["key"].startswith("pipeline-failed")]
    ok("a failed run is a problem, with what failed", f and f[0]["problem"] and "2 file error" in f[0]["text"], str(f))
    json.dump({"finished": round(now - 30 * 3600), "ok": True, "disk_low": True, "free_gb": 2.1, "min_free_gb": 5}, open(stp, "w"))
    ok("no run for over 26 h, and a low disk: both", {"pipeline-stale", "disk-low"} <= keys(), str(keys()))
    ok("PIPELINE_STALE_HOURS is used", "pipeline-stale" not in {a["key"].split(":")[0] for a in SA.Alerts(plat, env={"PIPELINE_STALE_HOURS": "48"}).current(now)})
    print("The name refresh")
    json.dump({"at": "2026-11-14T04:17:00+00:00", "ok": False}, open(os.path.join(plat, "data", "names_refresh.json"), "w"))
    n = [a for a in A.current(now) if a["key"].startswith("names-failed")]
    ok("a failed refresh is shown, at its UTC time", n and abs(n[0]["at"] - 1794629820) < 2, str(n))
    print("Per person")
    items = A.for_user("ann", now)
    ok("bell items carry what the bell shows (System, title, text, when, link, waiting for problems)",
       all(i["id"].startswith("sys:") and i["number"] == "System" and i["title"] and i["when"] and i["link"].startswith("/") for i in items)
       and any(i["waiting"] for i in items) and any(not i["waiting"] for i in items))
    first = items[0]["id"]
    ok("clearing one hides it for that person", A.clear("ann", [first]) == 1 and first not in {i["id"] for i in A.for_user("ann")})
    ok("…not for another admin", first in {i["id"] for i in A.for_user("bob")})
    ok("ids that are not system alerts are ignored", A.clear("ann", ["12", "abc"]) == 0)
    json.dump({"finished": round(time.time() + 5), "ok": False, "file_errors": 1, "disk_low": False}, open(stp, "w"))
    ok("a new failed run shows again although the last one was cleared",
       any(i["id"].startswith("sys:pipeline-failed") and i["id"] not in A._seen().get("ann", []) for i in A.for_user("ann")))
    ok("the seen file is private (600)", oct(os.stat(A.seen_path).st_mode & 0o777) == "0o600")
    print("Broken files")
    open(stp, "w").write("{not json"); open(os.path.join(plat, "data", "restarts.jsonl"), "w").write("garbage\n")
    try:
        A.current(now); ok("broken status and restart files: no crash", True)
    except Exception as e:  # noqa: BLE001
        ok("broken status and restart files: no crash", False, repr(e))

    print("In the bell: admins only")
    import app as APP
    import auth
    users, sessions = APP.AUTH["users"], APP.AUTH["sessions"]
    ADMIN, ANALYST, UA = auth.TEST_PREFIX + "sys-admin", auth.TEST_PREFIX + "sys-analyst", "lg-check-sysalerts"
    real_get = users.get
    users.get = lambda u: ({"status": "active", "role": "admin", "changed": 0} if u == ADMIN else
                           {"status": "active", "role": "analyst", "changed": 0} if u == ANALYST else real_get(u))
    fake = SA.Alerts(plat, env={})
    json.dump({"finished": round(time.time() - 60), "ok": False, "file_errors": 3, "disk_low": False}, open(stp, "w"))
    import notifications as N
    # the app's bell, with this throwaway Alerts in place of the real one
    sysfn = None
    for name, fn in APP.app.view_functions.items():
        if name == "api_notifications":
            sysfn = fn
    cl = sysfn.__closure__ if sysfn else None
    swapped = False
    for c in cl or []:
        if callable(getattr(c.cell_contents, "__closure__", None) and c.cell_contents) and getattr(c.cell_contents, "__name__", "") == "system_for":
            for cc in c.cell_contents.__closure__ or []:
                if isinstance(cc.cell_contents, SA.Alerts):
                    cc.cell_contents = fake; swapped = True
    ok("(the test reaches the bell's alerts)", swapped)
    ta, tn = sessions.create(ADMIN, "127.0.0.1", UA), sessions.create(ANALYST, "127.0.0.1", UA)
    csrf = max((s for s in sessions.s.values() if s["user"] == ADMIN and s.get("csrf")), key=lambda s: s["created"])["csrf"]
    a = APP.app.test_client(); a.set_cookie("lg_session", ta)
    n = APP.app.test_client(); n.set_cookie("lg_session", tn)
    try:
        ja = a.get("/api/notifications", headers={"User-Agent": UA}).json or {}
        jn = n.get("/api/notifications", headers={"User-Agent": UA}).json or {}
        sys_a = [i for i in ja.get("items", []) if i["id"].startswith("sys:")]
        ok("an admin's bell lists the failed run first, waiting", sys_a and ja["items"][0]["id"].startswith("sys:") and sys_a[0]["waiting"], str(ja)[:200])
        ok("an analyst's bell has no system alert", not any(i["id"].startswith("sys:") for i in jn.get("items", [])))
        r = a.post("/api/notifications/clear", json={"ids": [sys_a[0]["id"]]}, headers={"User-Agent": UA, "X-CSRF-Token": csrf})
        ja2 = a.get("/api/notifications", headers={"User-Agent": UA}).json or {}
        ok("clearing it from the bell hides it", r.status_code == 200 and sys_a[0]["id"] not in {i["id"] for i in ja2.get("items", [])})
    finally:
        users.get = real_get
        for t in (ta, tn):
            sessions.end(key=auth._h(t))
finally:
    if keep_env is not None:
        os.environ["PIPELINE_DIR"] = keep_env
    shutil.rmtree(root, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
