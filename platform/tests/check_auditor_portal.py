#!/usr/bin/env python3
"""The auditor role and the Audit portal (audit_portal.py, audit_chain.py, audit_report.py), in-process, on a
temporary audit log (the real data/audit.log is never written by this check):
* the auditor role is exactly 'audit' and no one can change or remove it;
* an auditor reaches the Audit portal only, read only, and never platform data;
* the log by tab, the dashboard and its control checks, the access review;
* the chain: whole after normal writing, broken when a line is changed, inserted or removed (also at the end);
  archives on rotation, retention that removes old archives without breaking the chain, the old .1 copy adopted;
* evidence: CSV (formula-safe) and the PDF report, each export logged.
Run: .venv/bin/python tests/check_auditor_portal.py"""
import gzip, io, json, os, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import auth  # noqa: E402
import audit_chain  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-auditor-")
audit, roles, users, sessions = A.AUTH["audit"], A.AUTH["roles"], A.AUTH["users"], A.AUTH["sessions"]
real_chain, real_path = audit.chain, audit.path
audit.path = os.path.join(tmp, "audit.log"); audit.chain = audit_chain.Chain(audit.path)
real_roles_path, real_roles = roles.path, dict(roles.roles)
roles.path = os.path.join(tmp, "roles.json")
real_get, real_perms = users.get, roles.perms
AUD, UA = auth.TEST_PREFIX + "auditor", "lg-check-auditor"
users.get = lambda n: {"status": "active", "role": "auditor", "changed": 0, "totp": "x"} if n == AUD else real_get(n)
tokens = []


def client(user):
    t = sessions.create(user, "127.0.0.1", UA); tokens.append(t)
    c = A.app.test_client(); c.set_cookie("lg_session", t)
    return c, next(s["csrf"] for s in sessions.s.values() if s["user"] == user)


try:
    print("The auditor role is fixed")
    ok("the role exists with exactly 'audit'", roles.roles.get("auditor") == ["audit"], str(roles.roles.get("auditor")))
    roles.save(dict(roles.roles, auditor=["audit", "users", "settings", "unmasked"]))
    ok("saving the roles with more permissions for it changes nothing", roles.roles["auditor"] == ["audit"], str(roles.roles["auditor"]))
    roles.save({k: v for k, v in roles.roles.items() if k != "auditor"})
    ok("…and removing it brings it back as it was", roles.roles.get("auditor") == ["audit"])
    ok("a fresh start reads it as fixed too, whatever the file says", auth.Roles(roles.path).roles["auditor"] == ["audit"])
    ok("described for the admin page", "fixed" in auth.ROLE_INFO["auditor"] and "read only" in auth.ROLE_INFO["auditor"])

    print("Permanent roles and exclusive permissions")
    tried = dict(roles.roles, advisor=["advisory", "view", "unmasked"], researcher=["definitions"], analyst=["view", "definitions", "advisory", "users", "export"],
                 custom=["view", "users", "definitions"])
    tried.pop("management", None)
    roles.save(tried)
    ok("advisor and researcher keep exactly their permissions", roles.roles["advisor"] == ["advisory"] and roles.roles["researcher"] == ["definitions", "networks"],
       f"{roles.roles['advisor']} · {roles.roles['researcher']}")
    ok("'definitions', 'advisory' and 'users' cannot be given to another role", roles.roles["analyst"] == ["export", "view"] and roles.roles["custom"] == ["view"],
       f"{roles.roles['analyst']} · {roles.roles['custom']}")
    roles.save({k: v for k, v in roles.roles.items() if k not in ("advisor", "researcher", "custom")})
    ok("removing advisor or researcher brings them back", roles.roles.get("advisor") == ["advisory"] and roles.roles.get("researcher") == ["definitions", "networks"])
    ok("management stays the portal only", roles.roles["management"] == ["management"])
    roles.save(dict(roles.roles, external=["view", "unmasked", "export"]))
    ok("external stays masked viewing only (view), whatever is saved", roles.roles["external"] == ["view"], str(roles.roles["external"]))
    js = open(os.path.join(os.path.dirname(A.__file__), "static", "js", "admin.js"), encoding="utf-8").read()
    ok("the Roles editor takes fixed roles and exclusive permissions from the server (no Remove, locked boxes)",
       "rolesState.fixed" in js and "rolesState.exclusive" in js and "!fixedRoles.has(r)" in js)

    print("An auditor reaches the Audit portal only, read only")
    c, csrf = client(AUD)
    H = {"User-Agent": UA}
    r = c.get("/audit", headers=H)
    page = r.get_data(as_text=True)
    ok("opens the Audit portal", r.status_code == 200 and "Audit portal" in page, str(r.status_code))
    for tab in ("auth", "accounts", "sessions", "config", "data", "workflow", "system", "access", "live", "evidence", "overview"):
        if f'data-tab="{tab}"' not in page:
            ok(f"the page has the {tab} tab", False)
    ok("every tab is on the page (overview, 7 kinds of event, access review, signed in now, evidence)", all(f'data-tab="{t}"' in page for t in ("overview", "auth", "accounts", "sessions", "config", "data", "workflow", "system", "access", "live", "evidence")))
    ok("its loading line", "st-loading" in page)
    for path in ("/", "/services", "/findings", "/definitions", "/management", "/settings"):
        r = c.get(path, headers=H)
        if not (r.status_code in (301, 302) and r.headers.get("Location", "").endswith("/audit")):
            ok(f"{path} sends the auditor to the Audit portal", False, f"{r.status_code} {r.headers.get('Location')}")
    ok("the platforms, findings, definitions, Executive and Settings all send the auditor to the portal", True)
    r = c.get("/admin", headers=H)
    ok("Admin sends the auditor to the portal too", r.status_code in (301, 302) and r.headers.get("Location", "").endswith("/audit"))
    for path in ("/api/svc/stats", "/api/stats", "/api/findings", "/api/mgmt/comms", "/api/intel?name=x"):
        r = c.get(path, headers=H)
        if r.status_code != 403:
            ok(f"no platform data: {path}", False, str(r.status_code))
    ok("no platform data (map, services, findings, Executive, intel): all refused", True)
    ok("the account list of Admin is refused (the access review is the auditor's)", c.get("/api/admin/users", headers=H).status_code == 403)
    W = dict(H, **{"X-CSRF-Token": csrf})
    ok("cannot change roles", c.post("/api/admin/roles", json={"roles": {}}, headers=W).status_code == 403)
    ok("cannot change settings", c.post("/api/settings", json={"country": "GH"}, headers=W).status_code in (401, 403))
    ok("cannot end a session", c.post("/api/admin/sessions/0000000000000000/end", json={}, headers=W).status_code == 403)
    ok("cannot change an account", c.post(f"/api/admin/users/{AUD}", json={"action": "revoke"}, headers=W).status_code == 403)

    print("The log, by tab")
    now = time.time()
    for e, u, tgt, ip in (("login", "grace", "", "41.66.1.2"), ("login_failed", "grace", "", "203.0.113.5"), ("login_failed", "x", "", "203.0.113.5"),
                          ("login_locked", "x", "", "203.0.113.5"), ("user_role", "rachel", "daniel", "10.0.0.2"), ("settings_changed", "rachel", "", "10.0.0.2"),
                          ("report_pdf", "daniel", "comms:hosts", "10.0.0.3"), ("finding_created", "daniel", "#1", "10.0.0.3"),
                          ("kicked", "rachel", "daniel", "10.0.0.2"), ("login", AUD, "", "127.0.0.1"),
                          ("detail_formula", "daniel", "", "10.0.0.3")):
        audit.add(e, user=u, target=tgt, detail="=1+1" if e == "detail_formula" else "x", ip=ip, ua="Mozilla/5.0 (Windows NT 10.0) Chrome/130")
    audit.add("login", user="lg-selftest-viewer", detail="self-test", ip="127.0.0.1", ua="LookingGlass-retest/1.0")
    day = time.strftime("%Y-%m-%d", time.gmtime())
    P = f"from={day}&to={day}"
    d = c.get(f"/api/audit/events?tab=auth&{P}", headers=H).json
    ok("Authentication: sign-ins, failures and the lockout", sorted(r["event"] for r in d["rows"]) == ["login", "login_failed", "login_failed", "login_locked"],
       ", ".join(sorted(r["event"] for r in d["rows"])))
    ok("…the self-test's sign-in is left out", all(not r["selftest"] for r in d["rows"]))
    ok("…readable, with failures marked", any(r["label"] == "Failed sign-in" and r["alert"] for r in d["rows"]))
    tabs = {t: [r["event"] for r in c.get(f"/api/audit/events?tab={t}&{P}", headers=H).json["rows"]] for t in ("accounts", "config", "data", "workflow", "sessions", "system")}
    ok("Accounts and access: the role change", tabs["accounts"] == ["user_role"], str(tabs["accounts"]))
    ok("Configuration: the settings change", tabs["config"] == ["settings_changed"])
    ok("Data access and exports: the report download", tabs["data"] == ["report_pdf"])
    ok("Workflow: the finding", tabs["workflow"] == ["finding_created"])
    ok("Sessions: the session an admin ended", tabs["sessions"] == ["kicked"])
    ok("System and self-test: the self-test's events (and unknown events)", "login" in tabs["system"] and "detail_formula" in tabs["system"])
    ok("the counts per tab", d["counts"].get("auth") == 4 and d["counts"].get("accounts") == 1, str(d["counts"]))
    ok("a period without events shows none", c.get("/api/audit/events?tab=auth&from=2001-01-01&to=2001-01-31", headers=H).json["total"] == 0)
    ok("search within a tab", c.get(f"/api/audit/events?tab=auth&{P}&q=203.0.113.5", headers=H).json["total"] == 3)

    print("The dashboard and the control checks")
    o = c.get(f"/api/audit/overview?{P}", headers=H).json
    ok("key figures (the self-test account's own sign-in left out)", o["kpis"]["signins"] == 1 and o["kpis"]["failed"] == 2 and o["kpis"]["lockouts"] == 1
       and o["kpis"]["privileged"] == 3, json.dumps(o["kpis"]))
    ok("sign-ins per day, for every day of the period", len(o["per_day"]) == 1 and o["per_day"][0]["ok"] == 1)
    ok("sign-ins by hour", len(o["hours"]) == 24 and sum(o["hours"]) == 1)
    ok("failed sign-ins by address", o["fail_sources"][0]["ip"] == "203.0.113.5" and o["fail_sources"][0]["n"] == 3)
    ids = [x["id"] for x in o["checks"]]
    ok("13 control checks, in five areas", len(ids) == 13 and len({x["area"] for x in o["checks"]}) == 5, ", ".join(ids))
    ok("each with its evidence", all(x["evidence"] for x in o["checks"]))
    ok("AC-5: the auditor role is fixed", next(x for x in o["checks"] if x["id"] == "AC-5")["ok"])
    ok("AU-1: the log is unbroken", next(x for x in o["checks"] if x["id"] == "AU-1")["ok"] and o["integrity"]["ok"])

    print("The access review")
    a = c.get("/api/audit/access", headers=H).json
    ok("every account, without the self-test's", a["accounts"] and not any(x["name"].startswith("lg-selftest-") for x in a["accounts"]))
    ok("each with role, permissions, authenticator, last sign-in, approval and flags",
       all({"role", "permissions", "mfa", "last_login", "approved_by", "flags"} <= set(x) for x in a["accounts"]))
    ok("the roles matrix marks the fixed roles", {r["role"] for r in a["roles"] if r["fixed"]} >= {"admin", "management", "auditor"})

    print("The chain: tamper evident")
    v = audit.chain.verify()
    lines = open(audit.path, encoding="utf-8").read().splitlines()
    ok("after normal writing: whole", v["ok"] and v["chained"] == v["entries"] == len(lines), json.dumps({k: v[k] for k in ("ok", "entries", "chained")}))
    def write(ls):
        with open(audit.path, "w", encoding="utf-8") as f:
            f.write("\n".join(ls) + "\n")
    changed = list(lines); rec = json.loads(changed[4]); rec["user"] = "someone-else"; changed[4] = json.dumps(rec, ensure_ascii=False)
    write(changed); v = audit.chain.verify()
    ok("a line changed: broken right after it", not v["ok"] and v["break"]["entry"] == 6, json.dumps(v["break"]))
    write(lines[:6] + lines[7:]); v = audit.chain.verify()
    ok("a line removed: broken", not v["ok"] and v["break"]["entry"] == 7, json.dumps(v["break"]))
    write(lines[:3] + [json.dumps({"t": time.time(), "event": "login", "user": "ghost", "prev": "f" * 64})] + lines[3:]); v = audit.chain.verify()
    ok("a line inserted: broken", not v["ok"] and v["break"]["entry"] == 4, json.dumps(v["break"]))
    write(lines[:-2]); v = audit.chain.verify()
    ok("lines cut from the end: caught by the head", not v["ok"] and "audit.head" in v["break"]["what"], json.dumps(v["break"]))
    write(lines); v = audit.chain.verify()
    ok("the original again: whole", v["ok"])
    r = c.get("/api/audit/verify", headers=H).json
    ok("the portal's Verify says so, with the head hash", r["ok"] and len(r["head"]) == 64)
    ok("…and the check itself is logged", json.loads(open(audit.path).read().splitlines()[-1])["event"] == "audit_verified")

    print("Retention: archives, not deletion")
    before = len(open(audit.path).read().splitlines())
    audit.chain.rotate_bytes = 1                         # the next write rotates
    audit.add("login", user="grace", ip="10.0.0.9", ua="x")
    arch = audit.chain.archives()
    ok("the full file went to the archive, compressed (owner only)", len(arch) == 1 and arch[0].endswith(".log.gz")
       and oct(os.stat(arch[0]).st_mode & 0o777) == "0o600" and gzip.open(arch[0], "rt").read().count("\n") == before)
    audit.chain.rotate_bytes = 5_000_000
    v = audit.chain.verify()
    ok("the chain goes on across the archive", v["ok"] and v["entries"] == before + 1 and v["archives"] == 1, json.dumps({k: v[k] for k in ("ok", "entries", "archives")}))
    ok("the portal still reads the archived entries (4 archived + 1 new)", c.get(f"/api/audit/events?tab=auth&{P}", headers=H).json["total"] == 5)
    audit.chain.retention_days = 0                       # everything archived is past the retention
    audit.chain.prune(now=time.time() + 10)
    ok("past the retention the archive is removed, and noted", not audit.chain.archives() and audit.chain.removed()[-1]["entries"] == before)
    v = audit.chain.verify()
    ok("…and the chain still checks out from the removed archive's last link", v["ok"] and v["removed_archives"] == 1, json.dumps(v.get("break")))
    audit.chain.retention_days = 400
    old_dir = os.path.join(tmp, "old"); os.makedirs(old_dir)
    with open(os.path.join(old_dir, "audit.log.1"), "w") as f:
        f.write(json.dumps({"t": 1.0, "event": "login", "user": "old"}) + "\n")
    ch = audit_chain.Chain(os.path.join(old_dir, "audit.log"))
    ok("an older version's audit.log.1 is adopted as the first archive", len(ch.archives()) == 1 and not os.path.exists(os.path.join(old_dir, "audit.log.1")))
    ch.append({"t": 2.0, "event": "login", "user": "new"})
    v = ch.verify()
    ok("…entries from before the chain are counted, the chain starts after them", v["ok"] and v["before_chain"] == 1 and v["chained"] == 1)

    print("Evidence exports")
    audit.add("definition_saved", user="daniel", detail="=1+1", ip="10.0.0.3", ua="x")   # a value a spreadsheet would run
    r = c.get(f"/api/audit/export.csv?tab=all&{P}", headers=H)
    body = r.get_data(as_text=True)
    ok("CSV for the period", r.status_code == 200 and body.lstrip("﻿").startswith("time_utc,tab,event,by") and "attachment" in r.headers.get("Content-Disposition", ""))
    ok("…formula-safe", "'=1+1" in body and ",=1+1" not in body)
    r = c.get(f"/api/audit/report.pdf?{P}", headers=H)
    ok("the evidence report (PDF)", r.status_code == 200 and r.data[:4] == b"%PDF" and len(r.data) > 3000, str(len(r.data)))
    if os.environ.get("LG_SAVE_PDF"):
        open(os.environ["LG_SAVE_PDF"], "wb").write(r.data)
    tail = [json.loads(x) for x in open(audit.path).read().splitlines()[-2:]]
    ok("both exports are in the audit log, with who and which period", [x["event"] for x in tail] == ["audit_export", "audit_export"]
       and all(x["user"] == AUD and day in x["detail"] for x in tail))
    ok("…and the chain is still whole", audit.chain.verify()["ok"])

    print("The admin page and the nav")
    rd = lambda p: open(os.path.join(os.path.dirname(A.__file__), p), encoding="utf-8").read()
    ok("the Roles editor treats permanent roles as fixed (no Remove, locked boxes; the auditor among them)",
       "A permanent role" in rd("static/js/admin.js") and '"auditor"' in rd("static/js/admin.js"))
    ok("auditors are not offered Findings", 'lg_role != "auditor"' in rd("templates/_page_nav.html") and 'lg_role != "auditor"' in rd("templates/_portal_cards.html"))
finally:
    users.get, roles.perms = real_get, real_perms
    roles.path, roles.roles = real_roles_path, real_roles
    audit.chain, audit.path = real_chain, real_path
    for t in tokens:
        sessions.end(token=t)
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
