#!/usr/bin/env python3
"""Values of the wrong kind are refused, never a 500 (review 2026-11-13): a role sent as a list or a number, a time
window like 1..2+3, a limit that is not a number. In-process, a throwaway admin session; no database needed.
Run: .venv/bin/python tests/check_wrong_types.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0"); os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402
import services as S  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


print("A time window that is not two numbers: no window, never a 500")
for v in ("1..2+3", "1+2..3", "+", "abc", "1e9+1", ".+.", ""):
    try:
        r = S.parse_time(v)
        ok(f"parse_time({v!r}) -> {r}", r is None or (isinstance(r, tuple) and len(r) == 2))
    except Exception as e:      # noqa: BLE001
        ok(f"parse_time({v!r})", False, f"{type(e).__name__}: {e}")
ok("a good window still works: 1080+60", S.parse_time("1080+60") == (64800.0, 68400.0), str(S.parse_time("1080+60")))

USER, UA = auth.TEST_PREFIX + "types-admin", "lg-check-types"
users, sessions = A.AUTH["users"], A.AUTH["sessions"]
real_get = users.get
users.get = lambda n: ({"status": "active", "role": "admin", "changed": 0} if n == USER else real_get(n))
tok = sessions.create(USER, "127.0.0.1", UA)
csrf = max((s for s in sessions.s.values() if s["user"] == USER and s.get("csrf")), key=lambda s: s["created"])["csrf"]
c = A.app.test_client(); c.set_cookie("lg_session", tok)
H = {"User-Agent": UA, "X-CSRF-Token": csrf}
try:
    print("The services stream with a bad time or limit")
    for q in ("time=1..2%2B3", "limit=abc", "limit=abc&time=1..2%2B3&latest=1"):
        st = c.get(f"/api/svc/events?{q}", headers=H).status_code
        ok(f"/api/svc/events?{q}: not a 500", st != 500 and st < 500 or st == 503, str(st))
    print("A role of the wrong kind, on an account that does not even need to exist")
    target = next(iter(n for n in users.all() if not n.startswith(auth.TEST_PREFIX)), "nobody")
    for role in (["admin"], 5, {"r": 1}, None):
        st = c.post(f"/api/admin/users/{target}", json={"action": "role", "role": role}, headers=H).status_code
        ok(f"role={role!r}: refused (400), never a 500", st in (400, 404), str(st))
    print("A new address of this machine (a network change) is answered without a restart; any other name is not")
    import security  # noqa: E402
    real_names, real_every = security._own_names, security.NAMES_REFRESH
    try:
        security.NAMES_REFRESH = 0
        security._own_names = lambda: real_names() | {"10.99.88.77"}
        st = c.get("/healthz", base_url="http://10.99.88.77:5000", headers={"User-Agent": UA}).status_code
        ok("this machine's new address: answered", st == 200, str(st))
        st = c.get("/healthz", base_url="http://evil.example.org:5000", headers={"User-Agent": UA}).status_code
        ok("a name that is not this machine's: still refused (400)", st == 400, str(st))
    finally:
        security._own_names, security.NAMES_REFRESH = real_names, real_every
finally:
    sessions.end(key=auth._h(tok))
    users.get = real_get
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
