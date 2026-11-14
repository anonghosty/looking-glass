#!/usr/bin/env python3
"""Locked sign-ins (auth.Throttle limits from .env within bounds; lockouts.py: the admin's list and Unlock). In-process,
no database, nothing real touched: a fresh Throttle for the counters, the app's own for the routes (test addresses only).
Run: .venv/bin/python tests/check_lockouts.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0"); os.environ["TRUST_PROXY"] = "0"
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def with_env(**kv):
    keep = {k: os.environ.get(k) for k in kv}
    os.environ.update({k: str(v) for k, v in kv.items()})
    try:
        return auth.Throttle()
    finally:
        for k, v in keep.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


print("Limits from .env, within bounds")
t = auth.Throttle()
ok("defaults: 5 tries / 15 min per account, 20 / 60 min per address",
   (t.account_fails, t.account_window, t.address_fails, t.address_window) == (5, 900, 20, 3600))
t = with_env(LOGIN_ACCOUNT_FAILS=1, LOGIN_ADDRESS_FAILS=1, LOGIN_ACCOUNT_LOCK_MIN=0, LOGIN_ADDRESS_WINDOW_MIN=0)
ok("too low is raised to the floor (3 tries, 10 per address, 5 and 15 min)",
   (t.account_fails, t.address_fails, t.account_window, t.address_window) == (3, 10, 300, 900))
t = with_env(LOGIN_ACCOUNT_FAILS=999, LOGIN_ADDRESS_FAILS=99999, LOGIN_ACCOUNT_LOCK_MIN=99999, LOGIN_ADDRESS_WINDOW_MIN=99999)
ok("too high is capped (20, 500, 240 min, 24 h)", (t.account_fails, t.address_fails, t.account_window, t.address_window) == (20, 500, 14400, 86400))
t = with_env(LOGIN_ACCOUNT_FAILS="lots")
ok("nonsense falls back to the default", t.account_fails == 5)
t = with_env(LOGIN_ADDRESS_FAILS=40)
for _ in range(25):
    t.failed("192.0.2.9", f"u{_}")
ok("a bigger address limit is used (25 failures, limit 40: not locked)", not t.locked("192.0.2.9", "new"))
ok("…the old records are kept as long as the longest window", t.sweeper.longest >= t.address_window)

print("What is locked, and lifting it")
t = auth.Throttle()
for _ in range(5):
    t.failed("192.0.2.1", "Alice")
for i in range(20):
    t.failed("198.51.100.7", f"name{i % 3}")
t.count(("register", "192.0.2.1"), 3600, add=True)
L = t.lockouts()
acc = [x for x in L if x["kind"] == "account"]; adr = [x for x in L if x["kind"] == "address"]
ok("an account locked from one address is listed (name lower-cased, failures, until)",
   any(x["ip"] == "192.0.2.1" and x["name"] == "alice" and x["failures"] == 5 and x["until"] > 0 for x in acc), str(acc))
ok("an address locked is listed", any(x["ip"] == "198.51.100.7" and x["failures"] == 20 for x in adr), str(adr))
ok("registration and reset counters are never listed", not any(x["ip"] == "register" or x["name"] == "192.0.2.1" for x in L))
ok("unlock one account from its address", t.unlock("192.0.2.1", "ALICE") == 1 and not t.locked("192.0.2.1", "alice"))
ok("…the registration counter stays", t.count(("register", "192.0.2.1"), 3600) == 1)
ok("unlock a whole address: every account tried from it", t.unlock("198.51.100.7") == 4
   and not t.locked("198.51.100.7", "name0") and not t.lockouts())
ok("unlocking what is not locked clears nothing", t.unlock("203.0.113.5") == 0 and t.unlock("203.0.113.5", "bob") == 0)

print("The admin's routes")
import app as A  # noqa: E402
users, sessions, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["audit"]
throttle = A.AUTH["throttle"]
ADMIN, ANALYST, UA = auth.TEST_PREFIX + "locks-admin", auth.TEST_PREFIX + "locks-analyst", "lg-check-lockouts"
real_get, real_add, logged = users.get, audit.add, []
users.get = lambda n: ({"status": "active", "role": "admin", "changed": 0} if n == ADMIN else
                       {"status": "active", "role": "analyst", "changed": 0} if n == ANALYST else real_get(n))
audit.add = lambda ev, **k: logged.append((ev, k))
tok_a = sessions.create(ADMIN, "127.0.0.1", UA)
csrf = max((s for s in sessions.s.values() if s["user"] == ADMIN and s.get("csrf")), key=lambda s: s["created"])["csrf"]
tok_n = sessions.create(ANALYST, "127.0.0.1", UA)
a = A.app.test_client(); a.set_cookie("lg_session", tok_a)
n = A.app.test_client(); n.set_cookie("lg_session", tok_n)
H = {"User-Agent": UA}; HC = dict(H, **{"X-CSRF-Token": csrf})
try:
    for _ in range(5):
        throttle.failed("192.0.2.77", "Carol")
    r = n.get("/api/admin/lockouts", headers=H)
    ok("an analyst cannot see the locks (403)", r.status_code == 403, str(r.status_code))
    r = a.get("/api/admin/lockouts", headers=H); j = r.json or {}
    ok("an admin sees the lock, with minutes left and the limits", r.status_code == 200
       and any(x["ip"] == "192.0.2.77" and x["name"] == "carol" and x["minutes_left"] >= 1 for x in j.get("locked", []))
       and j.get("limits", {}).get("account_fails") == throttle.account_fails, str(j)[:200])
    r = n.post("/api/admin/lockouts/unlock", json={"ip": "192.0.2.77", "name": "carol"}, headers=H)
    ok("an analyst cannot unlock (403)", r.status_code == 403 and throttle.locked("192.0.2.77", "carol"))
    r = a.post("/api/admin/lockouts/unlock", json={"ip": "192.0.2.77", "name": "carol"}, headers=H)
    ok("no CSRF token: refused", r.status_code == 403 and throttle.locked("192.0.2.77", "carol"))
    r = a.post("/api/admin/lockouts/unlock", data="ip=192.0.2.77", headers=HC, content_type="application/x-www-form-urlencoded")
    ok("not JSON: refused", r.status_code == 403)
    r = a.post("/api/admin/lockouts/unlock", json={"ip": "not-an-ip"}, headers=HC)
    ok("not an address: 400", r.status_code == 400)
    r = a.post("/api/admin/lockouts/unlock", json={"ip": "192.0.2.77", "name": "x" * 65}, headers=HC)
    ok("an over-long name: 400", r.status_code == 400)
    s = sessions.s[auth._h(tok_a)]; keep = (s.get("persist"), s.get("created"))
    s["persist"], s["created"] = True, s["created"] - 13 * 3600
    r = a.post("/api/admin/lockouts/unlock", json={"ip": "192.0.2.77", "name": "carol"}, headers=HC)
    ok("a stay-signed-in session older than 12 h must sign in again", r.status_code == 403 and (r.json or {}).get("reauth"))
    s["persist"], s["created"] = keep
    logged.clear()
    r = a.post("/api/admin/lockouts/unlock", json={"ip": "192.0.2.77", "name": "carol"}, headers=HC)
    ok("an admin unlocks it", r.status_code == 200 and not throttle.locked("192.0.2.77", "carol"), str(r.status_code))
    ok("…written to the audit log as login_unlocked, with who and what", any(e == "login_unlocked" and k.get("user") == ADMIN
       and "192.0.2.77" in k.get("detail", "") for e, k in logged), str(logged))
    import audit_portal
    ok("the Audit portal names it and counts it as a privileged action",
       audit_portal.LABEL.get("login_unlocked") and "login_unlocked" in audit_portal.PRIVILEGED and audit_portal.TAB_OF.get("login_unlocked") == "accounts")
finally:
    throttle.unlock("192.0.2.77")
    users.get, audit.add = real_get, real_add
    for tok in (tok_a, tok_n):
        sessions.end(key=auth._h(tok))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
