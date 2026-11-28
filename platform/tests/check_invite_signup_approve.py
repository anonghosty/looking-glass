#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Accounts through the real routes (reviewers' findings, production release 2026-11-26), in-process on made-up
accounts in a temporary folder: the installation's accounts, sessions, counters, roles, sign-up links, first-run code
and audit log are never touched (each store pointed at the temporary folder, the audit log at a list).

1. A sign-up link made on the Admin page (POST /api/admin/invites) and used through /register (both steps): the account
   is active with the link's role, approved_by is the administrator who made the link; the same link a second time is
   refused (opening it and posting with it: 403), and nothing is created by it.
2. An administrator's Approve with a role picked: the account is active with that role, also after the users file is
   read again from disk (a reload, and a fresh reader).
3. The sign-up link route asked for more than it allows: more links than may be open at once, a name over 100
   characters, a role a link may not give: 400 each, with the fixed words.
Run: .venv/bin/python tests/check_invite_signup_approve.py"""
import base64
import json
import os
import re
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ["LG_STEPUP_TESTS_OFF"] = "1"          # the step-up gate is tested on its own (tests/check_stepup.py)
import app as A  # noqa: E402
import auth  # noqa: E402
import invites as INV  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:300]}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-check-invite-")
AU = A.AUTH
users, sessions, throttle, audit, roles, setup = AU["users"], AU["sessions"], AU["throttle"], AU["audit"], AU["roles"], AU["setup"]
inv_store = A.FEATURES["invites"]["invites"]
saved = dict(users=(users.path, users.mtime, users.data), sessions=(sessions.path, dict(sessions.s)),
             throttle=(throttle.path, dict(throttle.fail)), roles=(roles.path, dict(roles.roles)), audit=audit.add,
             setup=setup.path, profile=auth.profile_problem, inv=inv_store.path, maxopen=INV.INVITES_OPEN_MAX)
logged = []
audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("target", ""), k.get("detail", "")))
setup.path = os.path.join(tmp, "setup_code")
sessions.path, throttle.path, roles.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
inv_store.path = os.path.join(tmp, "invites.json")
sessions.s.clear()
throttle.fail.clear()
auth.profile_problem = lambda *a, **k: None          # no DNS look-up of the made-up domains
PW = "Steady-Harbour-Lantern-63!"
H_ = generate_password_hash(PW)


def sec():
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def acct(role, status="active"):
    return {"hash": H_, "role": role, "status": status, "totp": sec(), "changed": 0, "created": 1, "pw_set_at": int(time.time()),
            "profile": {"full_name": f"Made-up {role.title()}", "email": f"made-up-{role}-{status}@csirt-made-up.org"}}


with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": {"inv-admin": acct("admin"), "inv-waiting": acct("external", "pending")}}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-invite-approve"
HD = {"User-Agent": UA}


def admin_client():
    tok = sessions.create("inv-admin", "127.0.0.1", UA)
    c = A.app.test_client()
    c.set_cookie("lg_session", tok)
    return c, sessions.s[auth._h(tok)]["csrf"]


def post_json(c, path, body, csrf):
    return c.post(path, json=body, headers=dict(HD, **{"X-CSRF-Token": csrf}))


def fresh_code(secret):
    while not (1 <= time.time() % 30 <= 27):
        time.sleep(0.5)
    return auth.totp_at(secret, int(time.time() // 30))


try:
    adm, csrf = admin_client()
    print("1. A sign-up link, used through /register")
    r = post_json(adm, "/api/admin/invites", {"role": "analyst", "name": "Ama Owusu"}, csrf)
    link = (r.json or {}).get("link", "")
    token = link.split("invite=", 1)[-1] if "invite=" in link else ""
    ok("the administrator makes a link for the analyst role", r.status_code == 200 and token, (r.status_code, r.json))
    form = {"username": "ama.invited", "full_name": "Ama Owusu", "organisation": "Made-up CSIRT", "email": "ama@csirt-made-up.org",
            "country": "GH", "password": "Bright-Ocean-Window-58!", "password2": "Bright-Ocean-Window-58!", "invite": token}
    c = A.app.test_client()
    ok("the link opens the sign-up form", c.get(f"/register?invite={token}", headers=HD).status_code == 200)
    r = c.post("/register", data=form, headers=HD)
    m = re.search(r"secret=([A-Z2-7]+)", r.get_data(as_text=True))
    ok("…the details are taken: the authenticator step", r.status_code == 200 and m, r.status_code)
    r = c.post("/register", data={"step": "enrol", "code": fresh_code(m.group(1) if m else "")}, headers=HD)
    users.mtime = None
    nu = users.get("ama.invited") or {}
    ok("finished: the account is active at once", r.status_code == 200 and nu.get("status") == "active", (r.status_code, nu.get("status")))
    ok("…with the link's role (analyst), not the lowest role", nu.get("role") == "analyst", nu.get("role"))
    ok("…approved by the administrator who made the link", nu.get("approved_by") == "inv-admin" and nu.get("approved_at"), nu.get("approved_by"))
    ok("…the link is marked used, by this account", any(v.get("used_by") == "ama.invited" for v in inv_store._load().values()))
    ok("…written down: registered and invite_used", {"registered", "invite_used"} <= {e for e, *_ in logged})
    c2 = A.app.test_client()
    r = c2.get(f"/register?invite={token}", headers=HD)
    ok("the same link a second time: refused when opened (403, ask for a new one)",
       r.status_code == 403 and "no longer works" in r.get_data(as_text=True), r.status_code)
    r = c2.post("/register", data=dict(form, username="second.use", email="second@csirt-made-up.org"), headers=HD)
    ok("…and when posted with (403), no account made", r.status_code == 403 and users.get("second.use") is None, r.status_code)

    print("2. Approve keeps the role picked")
    r = post_json(adm, "/api/admin/users/inv-waiting", {"action": "approve", "role": "researcher"}, csrf)
    u = users.get("inv-waiting") or {}
    ok("approved with the researcher role: active, researcher, approved by the administrator", r.status_code == 200
       and u.get("status") == "active" and u.get("role") == "researcher" and u.get("approved_by") == "inv-admin", (r.status_code, u.get("role")))
    users.mtime = None
    users._load()
    ok("…after the users file is read again: still researcher", (users.data["users"].get("inv-waiting") or {}).get("role") == "researcher")
    fresh = auth.Users(users.path)
    ok("…and for a fresh reader of the file", (fresh.get("inv-waiting") or {}).get("role") == "researcher"
       and (fresh.get("inv-waiting") or {}).get("status") == "active")
    r = post_json(adm, "/api/admin/users/inv-waiting", {"action": "approve", "role": "admin"}, csrf)
    ok("approving it again (now active) is refused and leaves the role", r.status_code == 400
       and (users.get("inv-waiting") or {}).get("role") == "researcher")

    print("3. The sign-up link route asked for more than it allows")
    INV.INVITES_OPEN_MAX = 2                    # the limit itself is tested in tests/check_invite_limit.py
    codes = [post_json(adm, "/api/admin/invites", {"role": "analyst", "name": f"Person {n}"}, csrf).status_code for n in range(2)]
    r = post_json(adm, "/api/admin/invites", {"role": "analyst", "name": "One Too Many"}, csrf)
    ok("links up to the open limit are made, one more answers 400 in fixed words", codes == [200, 200] and r.status_code == 400
       and "2 sign-up links are open" in (r.json or {}).get("error", ""), (codes, r.status_code, r.json))
    INV.INVITES_OPEN_MAX = saved["maxopen"]
    r = post_json(adm, "/api/admin/invites", {"role": "analyst", "name": "x" * 101}, csrf)
    ok("a name over 100 characters: 400", r.status_code == 400, r.status_code)
    r = post_json(adm, "/api/admin/invites", {"role": "admin", "name": "Would Be Admin"}, csrf)
    ok("a role a link may not give (admin): 400", r.status_code == 400, r.status_code)
    r = post_json(adm, "/api/admin/invites", {"role": ["analyst"], "name": "List Role"}, csrf)
    ok("a role that is not text: 400, not an error page", r.status_code == 400, r.status_code)
finally:
    users.path, users.mtime, users.data = saved["users"]
    sessions.path = saved["sessions"][0]
    sessions.s.clear()
    sessions.s.update(saved["sessions"][1])
    throttle.path = saved["throttle"][0]
    throttle.fail.clear()
    throttle.fail.update(saved["throttle"][1])
    roles.path, roles.roles = saved["roles"]
    audit.add, setup.path, auth.profile_problem = saved["audit"], saved["setup"], saved["profile"]
    inv_store.path, INV.INVITES_OPEN_MAX = saved["inv"], saved["maxopen"]
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
