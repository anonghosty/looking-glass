#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The Audit portal's routes and wording beyond check_audit_portal.py and check_auditor_portal.py (r91 coverage):
- every Audit portal route refuses an account without the 'audit' permission (403), the page too
- the log by tab: alerts only, a search, a bad paging value (the defaults, never a 500), the counts per tab
- the access review flags: no authenticator, dormant, pending too long, every permission (administrators)
- Verify writes its own audit entry; the CSV export refuses an unknown tab and names the tab in the file
- entries read as sentences: role changes, approvals, the constituency, roles saved, Peace of mind
Made-up accounts only (the copy's own temporary data folder). Run: .venv/bin/python tests/check_cov_audit_portal.py"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import audit_portal as AP  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


print("Entries as sentences")
ok("a role change", AP.pretty("user_role", "analyst -> researcher") == "Role changed from analyst to researcher")
ok("…in an odd form: the arrow in words", AP.pretty("user_role", "a b -> c d") == "a b to c d")
ok("an approval", AP.pretty("user_approve", "role analyst") == "Approved with the role analyst"
   and AP.pretty("user_approve", "something else") == "something else")
ok("the constituency: networks and ranges, time zone, kept ranges",
   AP.pretty("settings_changed", "country GH, time zone Africa/Accra, 2 networks, 1 ranges (1 kept with their network)")
   == "Country set to GH; time zone Africa/Accra; constituency: 2 networks and 1 address range (1 with their network)")
ok("…the whole country", AP.pretty("settings_changed", "country GH, 0 networks, 0 ranges") == "Country set to GH; constituency: the whole country")
ok("…another form: as logged", AP.pretty("settings_changed", "changed things") == "changed things")
ok("roles saved: each role's permissions", AP.pretty("roles_changed", json.dumps({"analyst": ["view"], "guest": []}))
   == "analyst now: view; guest now: no permission")
ok("…saved without changes; not JSON: as logged", AP.pretty("roles_changed", "{}") == "Saved without changes"
   and AP.pretty("roles_changed", "{broken") == "{broken")
ok("Peace of mind off / on", AP.pretty("peace_of_mind", "off") == "Turned off" and AP.pretty("peace_of_mind", "on").startswith("Turned on"))
ok("anything else: arrows in words", AP.pretty("login", "a -> b") == "a to b" and AP.fmt(1234) == "1,234" and AP.fmt("x") == "x")
os.environ["AUDIT_DORMANT_DAYS"] = "not a number"
ok("a setting that is not a number: its default", AP._num("AUDIT_DORMANT_DAYS", 45) == 45)
os.environ.pop("AUDIT_DORMANT_DAYS")

users, sessions, roles, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["roles"], A.AUTH["audit"]
real_get, real_perms, real_all = users.get, roles.perms, users.all
AUD, NOPE, UA = auth.TEST_PREFIX + "cov-auditor", auth.TEST_PREFIX + "cov-viewer", "lg-check-cov-audit"
FAKE = {AUD: "lg-cov-audit", NOPE: "lg-cov-view"}
now = time.time()
PEOPLE = {
    # half a day past each boundary: a test system's clock is corrected now and then (WSL steps it back a little), and
    # an exact "100 days ago" then reads as 99.99 days, shown as 99
    "grace": {"status": "active", "role": "analyst", "created": now - 400 * 86400, "last_login": {"at": now - 100.5 * 86400}},
    "daniel": {"status": "active", "role": "admin", "totp": "made-up", "created": now - 10 * 86400, "last_login": {"at": now - 3600},
               "profile": {"full_name": "Daniel Example", "organisation": "Example CSIRT"}, "recovery": ["x", "y"]},
    "sarah": {"status": "pending", "registered": {"at": now - 30.5 * 86400}, "role": "researcher"},
    "lg-selftest-x": {"status": "active", "role": "admin"},
}
users.get = lambda name: ({"status": "active", "role": FAKE[name], "changed": 0} if name in FAKE else real_get(name))
users.all = lambda: dict(PEOPLE)
roles.perms = lambda role: ({"view", "audit"} if role == "lg-cov-audit" else {"view", "unmasked"} if role == "lg-cov-view" else real_perms(role))
MADE = []


def client(user):
    token = sessions.create(user, "127.0.0.1", UA)
    MADE.append(token)
    c = A.app.test_client()
    c.set_cookie("lg_session", token)
    return c


H = {"User-Agent": UA}
try:
    print("Without the 'audit' permission")
    v = client(NOPE)
    for path in ("/api/audit/events", "/api/audit/access", "/api/audit/verify", "/api/audit/overview", "/api/audit/export.csv",
                 "/api/audit/report.pdf"):
        r = v.get(path, headers=H)
        ok(f"{path}: refused (403)", r.status_code == 403 and "Audit portal" in (r.json or {}).get("error", ""), r.get_data(as_text=True)[:200])
    r = v.get("/audit", headers=H)
    ok("/audit: the refusal page", r.status_code == 403)

    print("With it")
    c = client(AUD)
    audit.add("login_failed", user="grace", detail="wrong code (made-up)", ip="192.0.2.10", ua="x")
    audit.add("roles_changed", user="daniel", detail=json.dumps({"analyst": ["view", "unmasked"]}), ip="192.0.2.11", ua="x")
    audit.add("peace_of_mind", user="daniel", detail="off", ip="192.0.2.11", ua="x")
    r = c.get("/api/audit/events?alerts=1&tab=all", headers=H)
    r = r.json
    ok("alerts only: the failed sign-in, nothing else", r["rows"] and all(x["alert"] for x in r["rows"])
       and any(x["event"] == "login_failed" for x in r["rows"]), str(r["rows"][:2])[:300])
    r = c.get("/api/audit/events?q=Peace&limit=x&offset=y", headers=H).json
    ok("a search, with paging values that are not numbers: the defaults", r["total"] >= 1 and any(x["detail"] == "Turned off" for x in r["rows"]))
    r = c.get("/api/audit/events?tab=access&from=0001-01-01&to=9999-12-31", headers=H)
    ok("a tab and an out-of-range period: answered, counts per tab", r.status_code == 200 and isinstance(r.json["counts"], dict)
       and r.json["period"]["to"] <= time.strftime("%Y-%m-%d", time.gmtime(now + 86400)), str(r.json.get("period")))
    ok("…roles saved shown as a sentence", any(x["detail"] == "analyst now: view, unmasked" for x in
                                              c.get("/api/audit/events?q=roles", headers=H).json["rows"]))
    r = c.get("/api/audit/access", headers=H).json
    acc = {a["name"]: a for a in r["accounts"]}
    ok("the access review leaves the self-test account out", "lg-selftest-x" not in acc and set(acc) == {"grace", "daniel", "sarah"})
    ok("…no authenticator and no sign-in for 100 days", "no authenticator" in acc["grace"]["flags"]
       and any(f.startswith("no sign-in for 100 days") for f in acc["grace"]["flags"]), str(acc["grace"]["flags"]))
    ok("…pending for 30 days", any(f.startswith("pending for 30 days") for f in acc["sarah"]["flags"]))
    ok("…an administrator has every permission; name, organisation, recovery codes left",
       acc["daniel"]["flags"] == ["every permission"] and acc["daniel"]["full_name"] == "Daniel Example"
       and acc["daniel"]["recovery_left"] == 2 and acc["daniel"]["days_since_login"] == 0)
    ok("…the thresholds", r["thresholds"] == {"dormant_days": 45, "max_admins": 3, "pending_days": 7})
    r = c.get("/api/audit/verify", headers=H)
    ok("Verify answers and is itself logged", r.status_code == 200 and "head" in r.json
       and json.loads(open(audit.path).read().splitlines()[-1])["event"] == "audit_verified")
    r = c.get("/api/audit/export.csv?tab=nonsense", headers=H)
    ok("the CSV export: an unknown tab refused (it would go into the file name)", r.status_code == 400)
    r = c.get("/api/audit/export.csv?tab=auth", headers=H)
    ok("…a known tab: its file", r.status_code == 200 and 'filename="audit_auth_' in r.headers.get("Content-Disposition", ""))
    r = c.get("/api/audit/overview", headers=H)
    ok("the overview answers", r.status_code == 200)
finally:
    users.get, roles.perms, users.all = real_get, real_perms, real_all
    for t in MADE:
        try:
            sessions.end(key=auth._h(t))
        except Exception:  # noqa: BLE001  (best effort: the copy's data folder is thrown away)
            pass

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
