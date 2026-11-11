#!/usr/bin/env python3
"""The Audit portal and its permission: a role with only 'audit' opens /audit, reads the audit log and the signed-in
sessions, but cannot end a session ('users' does that) nor open Admin's user list. Settings waits behind its loading line.
Run: .venv/bin/python tests/check_audit_portal.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
import app as A
import auth

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


USER, UA = auth.TEST_PREFIX + "auditor", "lg-check-audit"
users, sessions, roles = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
users.get = lambda name: ({"status": "active", "role": "lg-auditor", "changed": 0} if name == USER else real_get(name))
roles.perms = lambda role: ({"audit"} if role == "lg-auditor" else real_perms(role))
token = sessions.create(USER, "127.0.0.1", UA)
csrf = next(s["csrf"] for s in sessions.s.values() if s["user"] == USER)
c = A.app.test_client()
c.set_cookie("lg_session", token)
H = {"User-Agent": UA}
try:
    print("The permission")
    ok("'audit' is described as the Audit portal", auth.PERMS["audit"].startswith("The Audit portal"), auth.PERMS["audit"])
    print("An audit-only role")
    r = c.get("/audit", headers=H)
    page = r.get_data(as_text=True)
    ok("opens the Audit portal", r.status_code == 200, str(r.status_code))
    ok("the page has the Sessions tab", 'data-tab="sessions"' in page)
    ok("…and its Sessions panel with the table (not only the tab)", 'id="pane-sessions"' in page and 'id="sessionsTable"' in page)
    ok("…marked read only for a role that cannot end sessions", "Read only: ending a session" in page)
    ok("the page has its loading line", "st-loading" in page)
    ok("reads the audit log", c.get("/api/admin/audit", headers=H).status_code == 200)
    r = c.post("/api/admin/sessions/0000000000000000/end", json={}, headers=dict(H, **{"X-CSRF-Token": csrf}))
    ok("ending a session is refused", r.status_code == 403, str(r.status_code))
    ok("Admin's user list is refused", c.get("/api/admin/users", headers=H).status_code == 403)
    ok("roles cannot be changed", c.post("/api/admin/roles", json={"roles": {}}, headers=dict(H, **{"X-CSRF-Token": csrf})).status_code == 403)
    # last: listing the sessions drops those of accounts not in the user file, and this test account is not in it
    r = c.get("/api/admin/sessions", headers=H)
    ok("reads the sessions", r.status_code == 200 and isinstance(r.json.get("sessions"), list), str(r.status_code))
    ok("…but may not end them (can_end false)", r.json.get("can_end") is False)
    print("Settings")
    tpl = open(os.path.join(os.path.dirname(A.__file__), "templates", "settings.html"), encoding="utf-8").read()
    js = open(os.path.join(os.path.dirname(A.__file__), "static", "js", "settings.js"), encoding="utf-8").read()
    ok("the cards wait behind the loading line", 'class="st-main st-pending"' in tpl and 'classList.remove("st-pending")' in js)
    print("Tabs load with the animation")
    rd = lambda p: open(os.path.join(os.path.dirname(A.__file__), "static", p), encoding="utf-8").read()
    ok("loader.js has LGLoader.pane", "async pane(el, label, work)" in rd("js/loader.js"))
    ok("a busy pane hides all but its heading and loading line", ".lg-pane-busy > :not(h2):not(.lg-pane-loading)" in rd("css/app.css"))
    ok("Admin: Users and Roles tabs use it", 'LGLoader.pane($(`pane-${tab}`)' in rd("js/admin.js") and "Opening the roles and their permissions" in rd("js/admin.js"))
    ok("Audit: Audit log and Sessions tabs use it", 'LGLoader.pane($("pane-sessions")' in rd("js/audit.js") and 'LGLoader.pane($("pane-audit")' in rd("js/audit.js"))
finally:
    users.get, roles.perms = real_get, real_perms
    sessions.end(key=auth._h(token)) if hasattr(auth, "_h") else None

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
