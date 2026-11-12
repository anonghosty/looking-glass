#!/usr/bin/env python3
"""Every write route checks the CSRF token, tested the way a browser reaches it (external review, 2026-11-12: most
checks called view functions directly with the automation user, skipping sign-in, the path gate and CSRF).

1. Source: every POST/PUT/PATCH/DELETE route of the app calls one of the CSRF checks (csrf_ok, need(..., change=...),
   guard_write, guard(change=True), the settings/definitions change checks), or is a public form or the self-test's
   automation-key route. A new route that forgets it fails here.
2. For real: a signed-in session (a real cookie, through _require_login and the path gate) with every permission, but
   without the page's CSRF token, is refused (403) on every route that needs a session; nothing is changed.
Run: .venv/bin/python tests/check_csrf_routes.py"""
import inspect
import os
import re
import sys

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
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


PUBLIC = {"/login", "/logout", "/register", "/forgot"}            # forms before a session exists (Origin checks apply)
AUTOMATION_ONLY = {"/api/selftest/reset-login-counters"}
MARK = re.compile(r"csrf_ok|guard_write|guard\(change=True\)|need\(\s*\"\w+\",\s*change=|_settings_change_allowed|"
                  r"_kb_change_allowed|change_allowed\"\]\(|can_note\"\]\(")
routes = []
for r in A.app.url_map.iter_rules():
    ms = (r.methods or set()) - {"GET", "HEAD", "OPTIONS"}
    if ms:
        routes.append((r, sorted(ms)))
missing = []
for r, ms in routes:
    if r.rule in PUBLIC or r.rule in AUTOMATION_ONLY:
        continue
    src = inspect.getsource(A.app.view_functions[r.endpoint])
    if not MARK.search(src):
        missing.append(r.rule)
print(f"Source: {len(routes)} write routes")
ok("every write route calls a CSRF check (or is a public form / the automation-only self-test)", not missing, ", ".join(missing))

print("For real: a signed-in session without the CSRF token")
users, sessions, roles = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
NAME, UA = "chk-csrf-admin", "lg-check-csrf"
users.get = lambda name: {"status": "active", "role": "lg-csrf-all", "changed": 0} if name == NAME else real_get(name)
roles.perms = lambda role: set(auth.PERMS) if role == "lg-csrf-all" else real_perms(role)
token = sessions.create(NAME, "127.0.0.1", UA)
refused, acted = [], []
try:
    c = A.app.test_client()
    c.set_cookie("lg_session", token)
    for r, ms in routes:
        if r.rule in PUBLIC or r.rule in AUTOMATION_ONLY:
            continue
        path = re.sub(r"<[^>]+>", "1", r.rule)
        resp = c.post(path, json={}, headers={"User-Agent": UA})          # no X-CSRF-Token
        (refused if resp.status_code == 403 else acted).append(f"{r.rule} {resp.status_code}")
    ok("every one refuses it with 403 (sign-in and path gate passed, the token missing)", not acted, "; ".join(acted[:6]))
    ok(f"…{len(refused)} routes checked through the real sign-in", len(refused) >= 35, str(len(refused)))
finally:
    users.get, roles.perms = real_get, real_perms
    sessions.end(token=token)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
