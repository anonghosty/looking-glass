#!/usr/bin/env python3
"""The security self-test clears this computer's login counters on request instead of restarting the service
(retest_reset.py, 2026-11-11): only with the automation key, only for the loopback addresses, never anyone else's
counters, and it is audited. In-process, on a throwaway counter state (the service's real counters are untouched).
Run: .venv/bin/python tests/check_retest_reset.py"""
import os, sys
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
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


T = A.AUTH["throttle"]
saved = dict(T.fail)
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append(a[0] if a else "")
KEY = open(os.path.join(A.BASE_DIR, "data", "automation.key")).read().strip()
URL, UA = "/api/selftest/reset-login-counters", "lg-check-retest-reset"
users, roles = A.AUTH["users"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
ADMIN = auth.TEST_PREFIX + "reset-admin"
users.get = lambda n: {"status": "active", "role": "lg-admin", "changed": 0} if n == ADMIN else real_get(n)
roles.perms = lambda r: set(auth.PERMS) if r == "lg-admin" else real_perms(r)
token = None
try:
    with T.lock:
        T.fail.clear()
    for _ in range(5):
        T.failed("127.0.0.1", "lg-selftest-viewer")
        T.failed("203.0.113.9", "admin")              # someone guessing from elsewhere
    ok("before: this computer is locked for that name, and so is the other address",
       T.locked("127.0.0.1", "lg-selftest-viewer") and T.locked("203.0.113.9", "admin"))

    c = A.app.test_client()
    r = c.post(URL, headers={"User-Agent": UA})
    ok("without signing in: refused (login required)", r.status_code == 401, str(r.status_code))
    token = A.AUTH["sessions"].create(ADMIN, "127.0.0.1", UA)
    csrf = next(s["csrf"] for s in A.AUTH["sessions"].s.values() if s["user"] == ADMIN)
    c2 = A.app.test_client(); c2.set_cookie("lg_session", token)
    r = c2.post(URL, headers={"User-Agent": UA, "X-CSRF-Token": csrf})
    ok("an administrator's own login cannot do it (only the self-test's key)", r.status_code == 403, str(r.status_code))
    r = c.post(URL, headers={"User-Agent": UA, "X-LG-Automation": "not-the-key"})
    ok("a wrong key: refused", r.status_code in (401, 403), str(r.status_code))
    r = c.post(URL, headers={"User-Agent": UA, "X-LG-Automation": KEY}, environ_base={"REMOTE_ADDR": "203.0.113.50"})
    ok("the right key from another computer: refused", r.status_code in (401, 403), str(r.status_code))
    ok("…none of that cleared anything", T.locked("127.0.0.1", "lg-selftest-viewer"))

    r = c.post(URL, headers={"User-Agent": UA, "X-LG-Automation": KEY})
    ok("the key from this computer: done", r.status_code == 200 and r.json.get("cleared", 0) >= 2, str(r.json))
    ok("this computer's counters are clear", not T.locked("127.0.0.1", "lg-selftest-viewer") and T.left("127.0.0.1", "lg-selftest-viewer") == 5)
    ok("the other address is still locked (it never unlocks anyone else)", T.locked("203.0.113.9", "admin"))
    ok("it is in the audit log", "selftest_counters_reset" in audited, ", ".join(audited))
finally:
    users.get, roles.perms = real_get, real_perms
    audit.add = real_add
    if token:
        A.AUTH["sessions"].end(token=token)
    with T.lock:
        T.fail.clear(); T.fail.update(saved)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
