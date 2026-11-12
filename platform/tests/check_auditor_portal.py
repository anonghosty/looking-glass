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
    C = {x["id"]: x for x in o["checks"]}
    ok("15 control checks LG-01 to LG-15, in four NIST families", ids == [f"LG-{i:02d}" for i in range(1, 16)]
       and {x["area"] for x in o["checks"]} == {"Identification and authentication", "Access control", "System and communications protection",
                                                 "Audit and accountability"}, ", ".join(ids))
    ok("each with its evidence", all(x["evidence"] for x in o["checks"]))
    import audit_portal as AP
    ok("every check maps to NIST SP 800-53 Rev. 5 controls, with their official titles", all(x["nist"] and all(n["title"] == AP.NIST[n["id"]]
       for n in x["nist"]) for x in o["checks"]) and o.get("nist_release") == "NIST SP 800-53 Rev. 5, Release 5.2.0")
    ok("…the mapping the auditor asked for: MFA → IA-2(1)/(2), lockouts → AC-7, audit protection → AU-9/AU-9(3), retention → AU-11",
       [n["id"] for n in C["LG-01"]["nist"]] == ["IA-2(1)", "IA-2(2)"] and [n["id"] for n in C["LG-06"]["nist"]] == ["AC-7"]
       and [n["id"] for n in C["LG-10"]["nist"]] == ["AU-9", "AU-9(3)"] and [n["id"] for n in C["LG-11"]["nist"]] == ["AU-11"])
    ok("LG-01 states what sign-in enforces, not only enrolment", "requires the password and a one-time code" in C["LG-01"]["evidence"])
    ok("no check gives a verdict (no pass or fail: the auditor decides)", all("ok" not in x for x in o["checks"])
       and not any(w in x["evidence"].lower() for x in o["checks"] for w in ("passed", "attention", "within normal")))
    ok("LG-05: the auditor role is fixed and the portal only reads", "holds exactly 'audit'" in C["LG-05"]["evidence"] and "only reads" in C["LG-05"]["evidence"])
    ia1 = C["LG-06"]
    ok("LG-06 (AC-7): the lockout, the address and day that failed most, against the alert level", " 0 lockout" not in ia1["evidence"]
       and "203.0.113.5" in ia1["evidence"] and "AUDIT_FAIL_ALERT" in ia1["evidence"], ia1["evidence"])
    au2 = C["LG-11"]
    ok("LG-11 (AU-11): judged from when the system started, said in the evidence", "system started" in au2["evidence"], au2["evidence"])
    ok("every check but HTTPS opens its evidence (tab to show)", all(x["view"] for x in o["checks"] if x["id"] != "LG-14")
       and C["LG-06"]["view"] == {"tab": "auth", "alerts": True})
    ok("the overview says when the system started and how long it runs", o.get("started") and o.get("running_days") is not None)
    for i in range(3):                                   # three typing mistakes from another address: normal
        audit.add("login_failed", user="grace", ip="10.0.0.40", ua="x")
    ok("LG-10: the log is unbroken", "chain whole" in C["LG-10"]["evidence"] and o["integrity"]["ok"])

    print("Details read as sentences (the CSV keeps them as logged too)")
    import audit_portal as AP
    for ev, raw, want in (("user_role", "analyst -> management", "Role changed from analyst to management"),
                          ("settings_changed", "country GH, 0 networks, 0 ranges", "Country set to GH; constituency: the whole country"),
                          ("settings_changed", "country KE, 2 networks, 1 ranges", "Country set to KE; constituency: 2 networks and 1 address range"),
                          ("user_approve", "role external", "Approved with the role external"),
                          ("roles_changed", '{"analyst": ["export", "view"]}', "analyst now: export, view"),
                          ("roles_changed", "{}", "Saved without changes"),
                          ("peace_of_mind", "off", "Turned off")):
        if AP.pretty(ev, raw) != want:
            ok(f"{ev}: {raw!r}", False, AP.pretty(ev, raw))
    ok("role changes, settings, approvals, role permissions and Peace of mind read as sentences", True)
    import people as PE
    class _U:
        def get(self, n): return {"profile": {"full_name": "Ghost"}} if n == "ghost" else {"profile": {"full_name": "Grace Mensah"}}
    ok("a full name that is just the username is not repeated (“Ghost”, not “Ghost (ghost)”)",
       PE.People(_U()).audit("ghost") == "Ghost" and PE.People(_U()).audit("grace") == "Grace Mensah (grace)")

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
    auth_before = c.get(f"/api/audit/events?tab=auth&{P}", headers=H).json["total"]
    audit.chain.rotate_bytes = 1                         # the next write rotates
    audit.add("login", user="grace", ip="10.0.0.9", ua="x")
    arch = audit.chain.archives()
    ok("the full file went to the archive, compressed (owner only)", len(arch) == 1 and arch[0].endswith(".log.gz")
       and oct(os.stat(arch[0]).st_mode & 0o777) == "0o600" and gzip.open(arch[0], "rt").read().count("\n") == before)
    audit.chain.rotate_bytes = 5_000_000
    v = audit.chain.verify()
    ok("the chain goes on across the archive", v["ok"] and v["entries"] == before + 1 and v["archives"] == 1, json.dumps({k: v[k] for k in ("ok", "entries", "archives")}))
    ok("the portal still reads the archived entries (the archived ones + 1 new)", c.get(f"/api/audit/events?tab=auth&{P}", headers=H).json["total"] == auth_before + 1)
    audit.chain.retention_days = 0                       # everything archived is past the retention
    audit.chain.prune(now=time.time() + 10)
    ok("past the retention the archive is removed, and noted", not audit.chain.archives() and audit.chain.removed()[-1]["entries"] == before)
    v = audit.chain.verify()
    ok("…and the chain still checks out from the removed archive's last link", v["ok"] and v["removed_archives"] == 1, json.dumps(v.get("break")))
    ok("…the removal is waiting to be recorded in the chain with the next entry", v["removals_pending"] == 1 and v["removals_recorded"] == 0)
    audit.add("login", user="grace", ip="10.0.0.9", ua="x")
    lines_now = [json.loads(x) for x in open(audit.path).read().splitlines()]
    rm = [x for x in lines_now if x["event"] == "audit_archive_removed"]
    note = audit.chain.removed()[-1]
    ok("the removal is recorded in the chain itself: which archive, how many entries, its last link",
       len(rm) == 1 and rm[0]["target"] == note["archive"] and rm[0]["removed"]["last_hash"] == note["last_hash"]
       and rm[0]["removed"]["entries"] == before and lines_now[-1]["event"] == "login", json.dumps(rm[:1])[:200])
    v = audit.chain.verify()
    ok("…and the check counts it as recorded", v["ok"] and v["removals_recorded"] == 1 and v["removals_pending"] == 0, json.dumps(v.get("break")))
    audit.add("login", user="grace", ip="10.0.0.9", ua="x")
    ok("…once only", sum(1 for x in open(audit.path).read().splitlines() if '"audit_archive_removed"' in x) == 1)
    rj, rc = os.path.join(audit.chain.dir, "removed.jsonl"), os.path.join(audit.chain.dir, "removed.recorded")
    saved_rj, saved_rc = open(rj).read(), open(rc).read()
    # someone notes a removal outside Looking Glass, before the real one and with no entries, so the link to the entries
    # kept and the head's count still hold: only the missing chain entry gives it away (the other checks catch the rest)
    forged = json.dumps(dict(note, archive="audit-20260101-000000.log.gz", last_hash="e" * 64, removed_at=time.time(), entries=0))
    open(rj, "w").write(forged + "\n" + saved_rj)
    open(rc, "w").write("2")
    v = audit.chain.verify()
    ok("a retention note with no entry in the chain: detected", not v["ok"] and "no entry in the chain" in v["break"]["what"], json.dumps(v.get("break")))
    open(rj, "w").write(saved_rj); open(rc, "w").write(saved_rc)
    ok("…and whole again without it", audit.chain.verify()["ok"])
    audit.chain.retention_days = 400
    old_dir = os.path.join(tmp, "old"); os.makedirs(old_dir)
    with open(os.path.join(old_dir, "audit.log.1"), "w") as f:
        f.write(json.dumps({"t": 1.0, "event": "login", "user": "old"}) + "\n")
    ch = audit_chain.Chain(os.path.join(old_dir, "audit.log"))
    ok("an older version's audit.log.1 is adopted as the first archive", len(ch.archives()) == 1 and not os.path.exists(os.path.join(old_dir, "audit.log.1")))
    ch.append({"t": 2.0, "event": "login", "user": "new"})
    v = ch.verify()
    ok("…entries from before the chain are counted, the chain starts after them", v["ok"] and v["before_chain"] == 1 and v["chained"] == 1)

    print("The seal of entries written before the chain")
    sd = os.path.join(tmp, "sealed"); os.makedirs(sd)
    with open(os.path.join(sd, "audit.log"), "w") as f:
        for i in range(5):
            f.write(json.dumps({"t": 10.0 + i, "event": "login", "user": f"old{i}"}) + "\n")
    sc = audit_chain.Chain(os.path.join(sd, "audit.log"))
    sc.append({"t": 20.0, "event": "login", "user": "first-chained"})
    s = sc.seal()
    ok("the older entries are sealed once: count, SHA-256, time span", s and s["entries"] == 5 and len(s["sha256"]) == 64 and s["first"] == 10.0)
    ok("…not twice", sc.seal() is None)
    ok("…and the check reports the seal intact", sc.verify()["ok"] and sc.verify()["seal"]["state"] == "intact")
    ls = open(os.path.join(sd, "audit.log")).read().splitlines()
    r2 = json.loads(ls[2]); r2["user"] = "rewritten"; ls[2] = json.dumps(r2)
    open(os.path.join(sd, "audit.log"), "w").write("\n".join(ls) + "\n")
    vv = sc.verify()
    ok("an older entry changed after the seal: detected", not vv["ok"] and vv["seal"]["state"] == "changed", json.dumps(vv.get("break")))

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

    print("Proof to take away: the proof package and the independent verifier")
    import ast, hashlib, subprocess, zipfile
    r = c.get("/api/audit/proof.zip", headers=H)
    z = zipfile.ZipFile(io.BytesIO(r.data))
    names = set(z.namelist())
    ok("the proof package: the log as stored, a manifest, the verifier and a README", r.status_code == 200
       and {"MANIFEST.json", "README.txt", "verify_audit_log.py", "log/audit.log", "log/audit.head"} <= names
       and "attachment" in r.headers.get("Content-Disposition", ""), ", ".join(sorted(names)))
    man = json.loads(z.read("MANIFEST.json"))
    ok("…the manifest lists every file with its SHA-256", {f["path"] for f in man["files"]} == names - {"MANIFEST.json", "README.txt"}
       and all(hashlib.sha256(z.read(f["path"])).hexdigest() == f["sha256"] for f in man["files"]))
    ok("…the log files are byte for byte the stored ones", z.read("log/audit.log") == open(audit.path, "rb").read()[:len(z.read("log/audit.log"))])
    last = json.loads(open(audit.path).read().splitlines()[-1])
    ok("…its download is logged with the package's SHA-256 and the head it holds", last["event"] == "audit_export" and last["target"] == "proof"
       and hashlib.sha256(r.data).hexdigest() in last["detail"] and man["head"] in last["detail"], last.get("detail", ""))
    ok("…the head is sent with it (hash@entry) for the auditor to keep", r.headers.get("X-Audit-Head") == f"{man['head']}@{man['head_entry']}")
    vsrc = z.read("verify_audit_log.py").decode()
    mods = {a.name.split(".")[0] for n in ast.walk(ast.parse(vsrc)) if isinstance(n, ast.Import) for a in n.names} | \
           {n.module.split(".")[0] for n in ast.walk(ast.parse(vsrc)) if isinstance(n, ast.ImportFrom) and n.module}
    ok("the README gives the verifier's own SHA-256, to compare with the one published on GitHub",
       hashlib.sha256(z.read("verify_audit_log.py")).hexdigest() in z.read("README.txt").decode() and "github.com" in z.read("README.txt").decode())
    ok("the verifier needs the Python standard library only", mods <= {"argparse", "glob", "gzip", "hashlib", "json", "os", "re", "sys", "time"}, ", ".join(sorted(mods)))
    pkg = os.path.join(tmp, "pkg"); z.extractall(pkg)

    def run(*args):
        p = subprocess.run([sys.executable, "-I", os.path.join(pkg, "verify_audit_log.py"), "--json", *args], capture_output=True, text=True,
                           cwd=tempfile.gettempdir(), timeout=60)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"stdout": p.stdout, "stderr": p.stderr}
    rc, out = run()
    ok("run on its own (python -I, outside Looking Glass): verified, every file as packaged", rc == 0 and out.get("ok") and out["manifest"]["problems"] == []
       and out["head"] == man["head"] and out["head_entry"] == man["head_entry"], str(out)[:300])
    ok("…and it checks the retention's removal against its entry in the chain", out.get("removals_recorded") == 1 and out.get("removals_pending") == 0
       and "log/audit_archive/removed.recorded" in names)
    earlier = f"{man['head']}@{man['head_entry']}"
    rc, out = run("--earlier", earlier)
    ok("…--earlier with the head it holds: proven", rc == 0 and out["earlier"]["proven"], json.dumps(out.get("earlier")))
    rc, out = run("--earlier", f"{man['head']}@{man['head_entry'] + 3}")
    ok("…the right hash at another entry number: not proven", rc == 1 and out["earlier"]["found"] and not out["earlier"]["same_entry"])
    pl = os.path.join(pkg, "log", "audit.log")
    orig = open(pl, encoding="utf-8").read().splitlines()
    t = list(orig); x = json.loads(t[2]); x["user"] = "someone-else"; t[2] = json.dumps(x, ensure_ascii=False)
    open(pl, "w", encoding="utf-8").write("\n".join(t) + "\n")
    rc, out = run()
    ok("an entry changed in the package: chain broken and the file reported changed", rc == 1 and not out["ok"] and out["break"]["entry"]
       and any("log/audit.log" in p for p in out["manifest"]["problems"]), json.dumps(out.get("break")))
    # the strongest attack: someone with the server rewrites an entry AND every link after it, the head and the manifest
    sha = lambda s: hashlib.sha256(s.encode("utf-8")).hexdigest()
    forged = [t[0], t[1], t[2]]
    for ln in orig[3:]:
        y = json.loads(ln); y["prev"] = sha(forged[-1]); forged.append(json.dumps(y, ensure_ascii=False))
    open(pl, "w", encoding="utf-8").write("\n".join(forged) + "\n")
    hd = json.load(open(os.path.join(pkg, "log", "audit.head"))); hd["head"] = sha(forged[-1])
    json.dump(hd, open(os.path.join(pkg, "log", "audit.head"), "w"))
    for f in man["files"]:
        f["sha256"] = hashlib.sha256(open(os.path.join(pkg, *f["path"].split("/")), "rb").read()).hexdigest()
    json.dump(man, open(os.path.join(pkg, "MANIFEST.json"), "w"))
    rc, out = run()
    ok("a whole rewrite (entry, every link, head, manifest) looks whole on its own…", rc == 0 and out["ok"], str(out.get("break")))
    rc, out = run("--earlier", earlier)
    ok("…but the earlier audit's head exposes it: not found, not verified", rc == 1 and not out["earlier"]["found"], json.dumps(out.get("earlier")))

    print("Compare with an earlier audit (portal)")
    d = c.get(f"/api/audit/continuity?earlier={earlier}", headers=H).json
    ok("the earlier head at its entry: proven, with the head now", d["earlier"]["proven"] and d["earlier"]["entry"] == man["head_entry"]
       and d["head_entry"] > man["head_entry"], json.dumps(d)[:300])
    ok("…and the comparison is logged", (lambda l: l["event"] == "audit_verified" and l["target"] == "continuity" and "proven" in l["detail"])(
        json.loads(open(audit.path).read().splitlines()[-1])))
    d = c.get(f"/api/audit/continuity?earlier={'ab' * 32}@5", headers=H).json
    ok("a hash that is not in the log: not found, not proven", not d["earlier"]["found"] and not d["earlier"]["proven"])
    ok("a malformed value: refused", c.get("/api/audit/continuity?earlier=xyz", headers=H).status_code == 400)
    ok("both need the audit permission", A.app.test_client().get("/api/audit/proof.zip").status_code in (302, 401, 403)
       and A.app.test_client().get(f"/api/audit/continuity?earlier={earlier}").status_code in (302, 401, 403))
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
