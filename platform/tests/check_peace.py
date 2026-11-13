#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Peace of mind (peace.py, auth.py), through the real sign-in check and request guard: a throwaway admin session (a
reserved test name, never a real account; ended afterwards) on a throwaway peace file. With it off the admin opens
everything; with it on, only Admin, the audit log and Settings: the platforms, Findings, the portals and their APIs are
refused, the start page goes to the Overview, its Overview shows Settings, Admin and the audit log only, no findings
notification comes in; only an admin has the switch, the change needs the page's token and is in the audit log; off
again, everything is back.
Usage: tests/check_peace.py"""
import os, re, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"     # the app is called in-process, not through a reverse proxy (proxy_guard.py)
import app as A  # noqa: E402
import auth  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


USER, UA = auth.TEST_PREFIX + "peace-admin", "lg-check-peace"
users, sessions = A.AUTH["users"], A.AUTH["sessions"]
real_get = users.get
users.get = lambda name: ({"status": "active", "role": "admin", "changed": 0} if name == USER else real_get(name))
tmp = tempfile.mkdtemp(prefix="lg-peace-")
real_path = A.PEACE.path
A.PEACE.path = os.path.join(tmp, "peace_of_mind.json"); A.PEACE._c = (None, {})
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append((a[0] if a else "", k.get("user")))
token = sessions.create(USER, "127.0.0.1", UA)
csrf = next(s["csrf"] for s in sessions.s.values() if s["user"] == USER)
c = A.app.test_client()
c.set_cookie("lg_session", token)
H = {"User-Agent": UA}


def get(path):
    return c.get(path, headers=H)


def post(path, body, tok=True):
    return c.post(path, json=body, headers=dict(H, **({"X-CSRF-Token": csrf} if tok else {})))


CLOSED = ["/findings", "/api/findings", "/management", "/api/advisory/dashboard", "/advisory", "/definitions", "/combinations", "/services"]
OPEN = ["/admin", "/audit", "/api/admin/audit", "/settings", "/api/settings", "/?intro=1", "/api/peace", "/api/notifications"]
try:
    print("Off: the admin opens everything")
    r = get("/api/peace")
    ok("the admin has the switch, off", r.status_code == 200 and r.json == {"on": False, "can": True}, str(r.json))
    ok("Findings opens", get("/api/findings").status_code == 200)
    print("On: Admin, the audit log and Settings only")
    r = post("/api/peace", {"on": True}, tok=False)
    ok("turning it on without the page's token is refused", r.status_code == 403)
    r = post("/api/peace", {"on": "yes"})
    ok("on must be true or false", r.status_code == 400)
    r = post("/api/peace", {"on": True})
    ok("the admin turns it on", r.status_code == 200 and r.json.get("on") is True, str(r.json))
    ok("…and it is in the audit log, as theirs", ("peace_of_mind", USER) in audited)
    for p in CLOSED:
        st = get(p).status_code
        ok(f"{p}: closed", st in (302, 403), str(st))
    for p in OPEN:
        st = get(p).status_code
        ok(f"{p}: open", st == 200, str(st))
    r = get("/")
    ok("the start page goes to the platforms' Overview, never the map", r.status_code == 302 and r.headers["Location"].endswith("/?intro=1"), r.headers.get("Location", ""))
    html = get("/?intro=1").get_data(as_text=True)
    ok("the Overview keeps an eye on the database, the platforms not offered",
       'data-itab="glossary" hidden' in html and 'id="btnExplore" hidden' in html and 'id="btnServices" href="/services" hidden' in html)
    import needs_db  # noqa: E402
    if needs_db.reachable()[0]:          # its figures need the reports database (none on a fresh clone or in CI)
        ok("…and its figures load", get("/api/clock").status_code == 200)
    cards = set(re.findall(r'class="portal-card pc-\w+" href="([^"]+)"', html))
    ok("its Overview: Settings, Admin and the audit log only", cards == {"/settings", "/admin", "/audit"}, ", ".join(sorted(cards)))
    ok("…saying Peace of mind is on", "Peace of mind is on" in html)
    nav = set(re.findall(r'aria-label="([^"]+)"', get("/audit").get_data(as_text=True)))
    ok("its header: Overview, Settings, Admin; no Findings, Definitions, platforms or portals", {"Overview", "Settings", "Admin"} <= nav
       and not {"Network communications", "Publicly accessible services"} & nav
       and not {"Findings", "Definitions", "Executive", "Advisory", "Combinations"} & nav,
       ", ".join(sorted(nav)))
    nav2 = set(re.findall(r'aria-label="([^"]+)"', get("/admin").get_data(as_text=True)))
    ok("…and on its other pages, the Overview icon", "Overview" in nav2 and "Findings" not in nav2, ", ".join(sorted(nav2)))
    r = get("/api/notifications")
    ok("no findings notification comes in", r.status_code == 200 and r.json.get("count") == 0 and r.json.get("peace") is True)
    print("Off again: everything is back")
    r = post("/api/peace", {"on": False})
    ok("the admin turns it off", r.status_code == 200 and r.json.get("on") is False)
    ok("Findings opens again", get("/api/findings").status_code == 200)
    ok("…and the platforms", get("/services").status_code == 200)
    print("Only admins")
    with A.app.test_request_context("/api/peace", method="POST", json={"on": True}):
        from flask import g
        g.user = {"user": "lg-check-analyst", "role": "analyst", "perms": set(auth.DEFAULT_ROLES["analyst"]), "csrf": None, "automation": True}
        r = A.app.view_functions["api_peace_set"]()
        st = r[1] if isinstance(r, tuple) else r.status_code
    ok("an analyst has no switch", st == 403)
finally:
    sessions.end(key=auth._h(token)) if hasattr(auth, "_h") else None
    users.get = real_get
    audit.add = real_add
    A.PEACE.path = real_path; A.PEACE._c = (None, {})
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} peace-of-mind checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
