#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Accounts (the user, 2026-11-19), with a scratch folder and made-up names; the installation's accounts are never
changed (the full sign-up through a link is in security_testing/security_retest.py, with its temporary accounts):
1. one-time sign-up links (invites.py): only a hash kept, once, expiring, revocable, at most 50 open; never for a role
   with administrators' or auditors' rights (the external review, 2026-11-19), checked again when the link is used;
2. the Admin page's API: administrators only ('users'), the CSRF token and a recent sign-in for changes; audited, never
   the link;
3. sign-up: a link opens it also when it is closed (REGISTRATION=0); a used, expired or revoked link is refused and
   says so; the first administrator always signs up with the setup code, whatever REGISTRATION says;
4. the bell: people waiting for approval, one notice for all, back when someone new signs up.
Usage: tests/check_accounts.py"""
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
import invites as I  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:200]}]" if info else ""), flush=True)


print("1. Sign-up links")
tmp = tempfile.mkdtemp()
store = I.Invites(os.path.join(tmp, "data", "invites.json"))
tok, e = store.make("analyst", "Grace Mensah", "admin1")
raw = open(store.path).read()
ok("only the link's hash is kept: the file holds no working link", tok not in raw and I.h(tok) in raw, raw[:120])
ok("the file is owner-only", oct(os.stat(store.path).st_mode & 0o777) == "0o600")
ok("a fresh link is open, with its role and who made it", (store.check(tok) or {}).get("role") == "analyst" and store.check(tok)["by"] == "admin1")
ok("an unknown or empty token: nothing", store.check("made-up-token") is None and store.check("") is None and store.check(None) is None)
used = store.use(tok, "grace")
ok("used once: it works", used and used["role"] == "analyst")
ok("…and never again", store.use(tok, "someone-else") is None and store.check(tok) is None)
tok2, e2 = store.make("researcher", "", "admin1")
ok("revoked: it no longer works", store.revoke(e2["id"], "admin1") and store.check(tok2) is None and store.use(tok2, "x") is None)
ok("…revoking again: nothing to revoke", store.revoke(e2["id"], "admin1") is None)
tok3, e3 = store.make("analyst", "", "admin1")
d = json.load(open(store.path)); d[I.h(tok3)]["expires"] = time.time() - 1; json.dump(d, open(store.path, "w"))
ok("expired: it no longer works", store.check(tok3) is None and store.use(tok3, "x") is None)
os.environ["INVITE_HOURS"] = "5"
ok("INVITE_HOURS sets how long a link lasts", I.hours() == 5)
os.environ.pop("INVITE_HOURS")
real_max = I.INVITES_OPEN_MAX
I.INVITES_OPEN_MAX = 2
try:
    store.make("analyst", "", "a"); store.make("analyst", "", "a")
    try:
        store.make("analyst", "", "a"); too_many = False
    except ValueError:
        too_many = True
    ok("at most INVITES_OPEN_MAX links open at a time", too_many)
finally:
    I.INVITES_OPEN_MAX = real_max

print("2. The Admin page's API")
from flask import Flask, g  # noqa: E402
app = Flask("acc-check")
who = {"user": "admin1", "perms": {"users"}, "csrf": True, "fresh": True}
audit, hook = [], {"check": None, "use": None}


class Audit:
    def add(self, kind, **kw):
        audit.append((kind, kw))


@app.before_request
def _u():
    g.user = {"user": who["user"]}


base = tempfile.mkdtemp()
# made-up roles with their permissions: an administrator, an auditor, and a custom role given administrators' rights
ROLE_PERMS = {"admin": {"users", "settings"}, "analyst": {"view", "export"}, "auditor": {"audit"},
              "custom-boss": {"view", "settings"}, "researcher": {"definitions"}}
api = I.install(app, {"base_dir": base, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: who["csrf"],
                      "fresh": lambda: who["fresh"], "audit": Audit(),
                      "roles": lambda: ["admin", "analyst", "auditor", "custom-boss", "researcher"],
                      "perms_of": lambda r: ROLE_PERMS.get(r, set()),
                      "hook": hook, "people_name": lambda u: {"admin1": "Ama Owusu"}.get(u, "")})
c = app.test_client()
ok("auth.py is given the link check (the hook)", hook["check"] is not None and hook["use"] is not None)
r = c.post("/api/admin/invites", json={"role": "analyst", "name": "Grace Mensah"}, base_url="https://lg.example.org")
link = (r.get_json() or {}).get("link", "")
ok("an administrator makes a link: this site's address, /register?invite=", r.status_code == 200 and link.startswith("https://lg.example.org/register?invite="), link[:60])
ok("…audited: who, for whom, which role; never the link", audit and audit[-1][0] == "invite_made" and audit[-1][1]["user"] == "admin1"
   and "analyst" in audit[-1][1]["detail"] and link.split("=", 1)[1] not in json.dumps(audit))
lst = c.get("/api/admin/invites").get_json()
ok("the open links are listed, with who made them (full name), never the link", len(lst["open"]) == 1 and lst["open"][0]["by"] == "Ama Owusu"
   and "link" not in lst["open"][0] and link.split("=", 1)[1] not in json.dumps(lst), lst["open"])
ok("a role that does not exist: refused", c.post("/api/admin/invites", json={"role": "superuser"}).status_code == 400)
# the external review (2026-11-19): a forwarded or leaked link must not make an administrator nobody approved
for role in ("admin", "auditor", "custom-boss"):
    r = c.post("/api/admin/invites", json={"role": role})
    ok(f"no sign-up link for the {role} role (administrators' or auditors' rights): refused, saying why",
       r.status_code == 400 and "approved" in (r.get_json() or {}).get("error", ""), str(r.get_json()))
ok("…and the Admin page is offered only the roles a link may give", c.get("/api/admin/invites").get_json()["roles"] == ["analyst", "researcher"],
   str(c.get("/api/admin/invites").get_json()["roles"]))
tok_ok = link.split("=", 1)[1]
ROLE_PERMS["analyst"] = {"view", "users"}                 # the role was given administrators' rights after the link was made
ok("a link whose role gained those rights since: no longer opens sign-up, nor can be used",
   hook["check"](tok_ok) is None and hook["use"](tok_ok, "someone") is None)
ROLE_PERMS["analyst"] = {"view", "export"}
ok("…back to an analyst's rights: the link works again (it was not used up)", hook["check"](tok_ok) is not None)
ok("markup in the name: refused", c.post("/api/admin/invites", json={"role": "analyst", "name": "<b>x</b>"}).status_code == 400)
who["csrf"] = False
ok("without the page's CSRF token: refused", c.post("/api/admin/invites", json={"role": "analyst"}).status_code == 403)
who["csrf"], who["fresh"] = True, False
ok("from a session older than 12 hours: refused", c.post("/api/admin/invites", json={"role": "analyst"}).status_code == 403)
who["fresh"] = True
for role, perms in (("analyst", {"view", "export"}), ("auditor", {"audit"}), ("researcher", {"definitions"})):
    who["perms"] = perms
    ok(f"the {role} role: refused, to list and to make", c.get("/api/admin/invites").status_code == 403
       and c.post("/api/admin/invites", json={"role": "analyst"}).status_code == 403)
who["perms"] = {"users"}
iid = lst["open"][0]["id"]
r = c.post(f"/api/admin/invites/{iid}/revoke")
ok("revoked from the list, audited", r.status_code == 200 and audit[-1][0] == "invite_revoked" and c.get("/api/admin/invites").get_json()["open"] == [])
ok("…a made-up id: not found", c.post("/api/admin/invites/zzzz/revoke").status_code == 404)

print("3. Sign-up (auth.py)")
src = open(os.path.join(HERE, "auth.py"), encoding="utf-8").read()
ok("the first administrator always signs up: sign-up is open while there is no administrator, whatever REGISTRATION says",
   'kw.setdefault("registration", registration_open or kw["no_admin"])' in src
   and "closed = not registration_open and not inv and bool(active_admins())" in src)
ok("a link opens sign-up when it is closed; a used, expired or revoked one says so", "This sign-up link no longer works" in src
   and 'view="register", registration=True, invite=inv_tok if inv else ""' in src)
ok("the account made through a link is active with the link's role, approved by its maker; the link is used once",
   'role = "admin" if first_admin else (inv["role"] if inv else LOWEST_ROLE)' in src and "approved_by=inv.get" in src
   and 'audit.add("invite_used"' in src)
S = os.environ.get("LG_HELD_DIR", "")
lp = os.path.join(S, "login.html.new") if S and os.path.exists(os.path.join(S, "login.html.new")) else os.path.join(HERE, "templates", "login.html")
ok("the sign-up form carries the link (and says the person was invited)", 'name="invite" value="{{ invite }}"' in open(lp, encoding="utf-8").read())

print("4. The bell: people waiting for approval")
import system_alerts as SA  # noqa: E402
b2 = tempfile.mkdtemp(); os.makedirs(os.path.join(b2, "data"))
now = time.time()
users = {"admin1": {"status": "active", "role": "admin"},
         "grace": {"status": "pending", "profile": {"full_name": "Grace Mensah"}, "registered": {"at": now - 60}},
         "lg-selftest-x": {"status": "pending", "registered": {"at": now}}}
json.dump({"users": users}, open(os.path.join(b2, "data", "users.json"), "w"))
al = SA.Alerts(b2)
one = al._signups()
ok("one person waiting: named, leading to the Admin page", len(one) == 1 and one[0]["title"] == "Grace Mensah (grace) asks for an account"
   and one[0]["link"] == "/admin", one)
ok("…the self-test's temporary accounts are not announced", "lg-selftest" not in json.dumps(one))
users["kofi"] = {"status": "pending", "registered": {"at": now}}
json.dump({"users": users}, open(os.path.join(b2, "data", "users.json"), "w"))
two = al._signups()
ok("two waiting: one notice, \"2 people are waiting for your approval\", naming them", len(two) == 1
   and two[0]["title"] == "2 people are waiting for your approval" and "kofi" in two[0]["text"] and "Grace Mensah" in two[0]["text"], two)
ok("…a new person changes the notice (cleared ones come back)", two[0]["key"] != one[0]["key"])
users["grace"]["status"] = "active"
json.dump({"users": users}, open(os.path.join(b2, "data", "users.json"), "w"))
ok("…someone approved: the notice stays the same (no new one for an approval)", al._signups()[0]["key"] == two[0]["key"])
users["kofi"]["status"] = "active"
json.dump({"users": users}, open(os.path.join(b2, "data", "users.json"), "w"))
ok("nobody waiting: no notice", al._signups() == [])

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
