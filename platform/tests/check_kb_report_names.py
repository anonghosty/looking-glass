#!/usr/bin/env python3
"""A services report's name is never taken for malware (2026-11-13): on 10 November the combination reports asked
Malpedia about scan_mikrotik_service, scan_http and scan_http_vulnerable as if they were malware names; they were
recorded and stayed on the Definitions to-do list ("Malpedia doesn't know"). Now such a name is never recorded, and
never listed even if an old record holds it; a real name still is. In-process, a throwaway record file; no database.
Run: .venv/bin/python tests/check_kb_report_names.py"""
import json, os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0"); os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-kbnames-")
real_path = A._MISSES_PATH
A._MISSES_PATH = os.path.join(tmp, "malpedia_names.json")
old = {n: {"first": "2026-11-10T21:16:46+00:00", "count": 5, "family": "", "checked": "2026-11-10T21:16:46+00:00"}
       for n in ("scan_mikrotik_service", "scan_http", "scan_http_vulnerable", "greedyrat-test")}
json.dump(old, open(A._MISSES_PATH, "w"))
USER, UA = auth.TEST_PREFIX + "kbnames-admin", "lg-check-kbnames"
users, sessions = A.AUTH["users"], A.AUTH["sessions"]
real_get = users.get
users.get = lambda n: ({"status": "active", "role": "admin", "changed": 0} if n == USER else real_get(n))
tok = sessions.create(USER, "127.0.0.1", UA)
c = A.app.test_client(); c.set_cookie("lg_session", tok)
try:
    print("Which names are services reports")
    for n in ("scan_mikrotik_service", "scan_http", "SCAN_HTTP_VULNERABLE"):
        ok(f"{n}: a services report", A._is_services_report(n))
    for n in ("greedyrat", "android.badbox2", "", None):
        ok(f"{n!r}: not a services report", not A._is_services_report(n))
    print("Never recorded as checked against Malpedia")
    A._record_check("scan_ssh", "")
    A._record_check("new-name-test", "")
    rec = json.load(open(A._MISSES_PATH))
    ok("a services report name is not recorded", "scan_ssh" not in rec)
    ok("…a real name still is", "new-name-test" in rec)
    print("Never listed, even from an old record")
    # with or without the report database (GitHub's checks have none): the list still answers with its names; only
    # "seen in" may be missing then, and the answer says so (external review, 2026-11-14: it came back empty)
    r = c.get("/api/kb/unresolved", headers={"User-Agent": UA}); j = r.json or {}
    todo = {x["name"] for x in j.get("unresolved", [])}
    ok("the to-do list answers, database or not", r.status_code == 200 and isinstance(j.get("unresolved"), list), str(r.status_code))
    ok("…and says whether the report database could be read", isinstance(j.get("database"), bool)
       and (j["database"] or bool(j.get("database_note"))), str(j.get("database")))
    ok("the three old report names are not on the to-do list", not todo & {"scan_mikrotik_service", "scan_http", "scan_http_vulnerable"}, str(sorted(todo)[:8]))
    ok("…a real unknown name stays on it", "greedyrat-test" in todo, str(sorted(todo)[:8]))
finally:
    sessions.end(key=auth._h(tok)); users.get = real_get
    A._MISSES_PATH = real_path
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
