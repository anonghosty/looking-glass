#!/usr/bin/env python3
"""Settings have one rule: a signed-in account with the Settings permission (administrators), plus the page's CSRF
token for changes. The old SETTINGS_TOKEN / X-Settings-Token shortcut is gone (external review, 2026-11-11): even
with SETTINGS_TOKEN set in the environment, the header opens nothing. Nothing is saved: the administrator's change is
sent as text so it stops at the JSON check, after the permission check.
Run: .venv/bin/python tests/check_settings_access.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)
os.environ["SETTINGS_TOKEN"] = "an-old-token"      # as if an old .env still had it: it must do nothing
import app as A  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


TOK = {"X-Settings-Token": "an-old-token"}
users, sessions, roles = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
ANALYST, ADMIN, UA = auth.TEST_PREFIX + "settings-analyst", auth.TEST_PREFIX + "settings-admin", "lg-check-settings"
FAKE = {ANALYST: "lg-no-settings", ADMIN: "lg-settings"}
users.get = lambda name: ({"status": "active", "role": FAKE[name], "changed": 0} if name in FAKE else real_get(name))
roles.perms = lambda role: ({"view", "unmasked"} if role == "lg-no-settings" else {"view", "settings"} if role == "lg-settings"
                            else real_perms(role))


MADE = []


def client(user):
    token = sessions.create(user, "127.0.0.1", UA)
    MADE.append(token)
    csrf = next(s["csrf"] for s in sessions.s.values() if s["user"] == user)
    c = A.app.test_client(); c.set_cookie("lg_session", token)
    return c, csrf


try:
    print("No session, only the old token header")
    c = A.app.test_client()
    ok("reading settings: login required", c.get("/api/settings", headers=TOK).status_code == 401)
    ok("changing settings: login required", c.post("/api/settings", json={"country": "GH"}, headers=TOK).status_code == 401)
    ok("the shortcut is gone from the code", not hasattr(A, "SETTINGS_TOKEN") and not hasattr(A, "hmac_compare"))

    print("Signed in, without the Settings permission, with the old token header")
    c, csrf = client(ANALYST)
    H = dict(TOK, **{"User-Agent": UA, "X-CSRF-Token": csrf})
    r = c.get("/api/settings", headers=H)
    ok("cannot even read the settings (403: accounts without the permission do not see Settings)", r.status_code == 403, str(r.status_code))
    r = c.post("/api/settings", json={"country": "GH", "networks": [], "cidrs": []}, headers=H)
    ok("a change is refused (403)", r.status_code == 403 and "Settings permission" in r.json.get("error", ""), str(r.status_code))
    r = c.post("/api/asns/identify", json={}, headers=H)
    ok("starting a network look-up is refused", r.status_code == 403, str(r.status_code))

    print("Signed in as an administrator (Settings permission), no token")
    c, csrf = client(ADMIN)
    H = {"User-Agent": UA, "X-CSRF-Token": csrf}
    r = c.get("/api/settings", headers=H)
    ok("reads settings, writable", r.status_code == 200 and r.json.get("writable") is True, str(r.status_code))
    ok("the answer no longer offers a token", "token_required" not in (r.json or {}))
    r = c.post("/api/settings", data="not json", content_type="text/plain", headers=H)
    ok("a change passes the permission check (stops at 'send JSON', nothing saved)", r.status_code == 415, str(r.status_code))
    r = c.post("/api/settings", data="not json", content_type="text/plain", headers={"User-Agent": UA})
    ok("…but not without the page's CSRF token", r.status_code == 403, str(r.status_code))

    print("The Settings page")
    root = os.path.dirname(A.__file__)
    rd = lambda p: open(os.path.join(root, p), encoding="utf-8").read()
    js = rd("static/js/settings.js") + rd("static/js/net-editor.js") + rd("static/js/kb-settings.js")
    ok("no token box or token header in the page's scripts", "X-Settings-Token" not in js and "Use token" not in js)
    ok("the read-only line names the Settings permission", "needs an account with the Settings permission" in rd("static/js/settings.js"))
    ok("the page no longer tells people to set SETTINGS_TOKEN", "SETTINGS_TOKEN" not in rd("templates/settings.html"))
finally:
    users.get, roles.perms = real_get, real_perms
    for t in MADE:                                  # the test's own sessions end with it
        sessions.end(token=t)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
