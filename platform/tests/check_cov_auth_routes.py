#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The sign-in pages, the gate in front of every request and the admin's account tools, in-process on made-up accounts
in a temporary folder (r91 coverage). No server, no database; the installation's accounts, sessions, counters, roles,
first-run code and audit log are never touched (each store is pointed at the temporary folder, the audit log at a list).
- the gate: the automation key from this computer only; a session used from another address is ended and written down;
  a password changed after the sign-in ends the session; long sessions get a new id after 12 hours; signed out, the
  platform's files do not exist; Peace of mind closes the work pages and exports; external accounts, management,
  advisors, auditors and researchers are sent to their own portal or refused; no complete list without 'export'
- sign-in: only Looking Glass's own notices; HTTPS from other computers; an expired or missing step; an account revoked
  between the password and the code; revoked and waiting accounts; a lock; setting up the authenticator again after a
  reset (a wrong code, then the right one: back to approval); an expired password replaced at sign-in (rules, not the
  old one, too many tries)
- sign-up: a dead sign-up link, a bad or reserved name, the hourly limits, a name or address already used, the rules,
  a name taken between the steps; fields added to the request by hand (role=admin, isAdmin, status, ...) change
  nothing (mass assignment); forgot password: asking an administrator (the same answer for any name, a limit),
  a reset an administrator allowed (authenticator code only), the lock
- admin: approve, role, revoke, restore, reset authenticator, allow reset, end sessions, delete (the name stays
  reserved), each with its refusals (own account, last administrator, wrong kind of body, unknown role or action, CSRF,
  a 'stay signed in' session older than 12 hours); sessions (auditor reads, cannot end), the audit list, roles
Run: .venv/bin/python tests/check_cov_auth_routes.py"""
import base64, json, os, re, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
# another computer (a documentation address) may connect, so the sign-in's own "HTTPS from other computers" is reached
os.environ["ACCESS_MODE"] = "private"
os.environ["VIEWER_NETWORKS"] = "192.0.2.0/24"
os.environ.pop("ALLOW_INSECURE_REMOTE_LOGIN", None)
import app as A  # noqa: E402
import auth  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-cov-authroutes-")
AU = A.AUTH
users, sessions, throttle, audit, roles, setup, pwp = (AU["users"], AU["sessions"], AU["throttle"], AU["audit"], AU["roles"],
                                                       AU["setup"], AU["password_policy"])
saved = dict(users=(users.path, users.mtime, users.data), sessions=(sessions.path, dict(sessions.s)), throttle=(throttle.path, dict(throttle.fail)),
             roles=(roles.path, dict(roles.roles)), audit=audit.add, setup=setup.path, profile=auth.profile_problem,
             peace=auth.PEACE["of"], expired=pwp.expired)
logged = []
audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("target", ""), k.get("detail", "")))
setup.path = os.path.join(tmp, "setup_code")
sessions.path, throttle.path, roles.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
sessions.s.clear(); throttle.fail.clear()
PROFILE_ANSWER = {"v": None}
auth.profile_problem = lambda *a, **k: PROFILE_ANSWER["v"]       # no DNS look-up of the example domains
PW = "Steady-Harbour-Lantern-63!"
H = generate_password_hash(PW)
sec = lambda: base64.b32encode(os.urandom(20)).decode().rstrip("=")


def acct(role, status="active", totp=True, **kw):
    return dict({"hash": H, "role": role, "status": status, "totp": sec() if totp else None, "changed": 0, "created": 1,
                 "pw_set_at": int(time.time()), "profile": {"full_name": f"Cov {role.title()}", "email": f"cov-{role}-{status}@csirt-made-up.org"}}, **kw)


ACC = {"cov-admin": acct("admin"), "cov-analyst": acct("analyst"), "cov-mgmt": acct("management"), "cov-advisor": acct("advisor"),
       "cov-auditor": acct("auditor"), "cov-research": acct("researcher"), "cov-external": acct("external"),
       "cov-viewer": acct("cov-viewer"), "cov-pending": acct("external", "pending"), "cov-nototp": acct("analyst", totp=False),
       "cov-revoked": acct("analyst", "disabled"), "cov-waitnew": acct("external", "pending", totp=False)}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": ACC}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
roles.roles["cov-viewer"] = ["view", "unmasked"]
UA = "lg-check-cov-authroutes"
HD = {"User-Agent": UA}
FAR = {"REMOTE_ADDR": "192.0.2.50"}
with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "automation.key")) as fh:
    AKEY = fh.read().strip()


def client(user, persist=False, ip="127.0.0.1"):
    tok = sessions.create(user, ip, UA, persist=persist)
    c = A.app.test_client(); c.set_cookie("lg_session", tok)
    return c, sessions.s[auth._h(tok)]["csrf"], tok


def secret_of(r):
    m = re.search(r"secret=([A-Z2-7]+)", r.get_data(as_text=True))
    return m.group(1) if m else ""


def fresh_code(secret):
    """This 30-second step's code, away from the step's edges."""
    while not (1 <= time.time() % 30 <= 27):
        time.sleep(0.5)
    return auth.totp_at(secret, int(time.time() // 30))


def post_json(c, path, body, csrf, **kw):
    return c.post(path, json=body, headers=dict(HD, **{"X-CSRF-Token": csrf}), **kw)


try:
    print("The gate in front of every request")
    c = A.app.test_client()
    r = c.get("/api/me", headers=dict(HD, **{"X-LG-Automation": AKEY}))
    ok("the automation key from this computer: the automation account", r.status_code == 200 and r.json["user"] == "automation")
    r = c.get("/api/me", headers=dict(HD, **{"X-LG-Automation": AKEY}), environ_base=FAR)
    ok("…from another computer: nothing (login required)", r.status_code == 401)
    ok("signed out: the platform's files do not exist (404), the sign-in page's own do (200)",
       c.get("/static/js/app.js", headers=HD).status_code == 404 and c.get("/static/css/auth.css", headers=HD).status_code == 200)
    r = c.get("/findings?x=1", headers=HD)
    ok("signed out, a page: to the sign-in, with the page to come back to", r.status_code == 302 and "/login?next=/findings%3Fx%3D1" in r.headers["Location"], r.headers.get("Location"))
    cA, csrfA, tokA = client("cov-analyst")
    r = cA.get("/api/me", headers=HD, environ_base=FAR)
    ok("a session cookie used from another address: refused and ended", r.status_code == 401 and auth._h(tokA) not in sessions.s)
    ok("…written down as session misuse", any(e == "session_misuse" and u == "cov-analyst" for e, u, _, _ in logged))
    cA, csrfA, tokA = client("cov-analyst")
    with users.lock:
        users._load(); users.data["users"]["cov-analyst"]["changed"] = int(time.time()) + 5; users.save()
    ok("the password changed after the sign-in: the session ends", cA.get("/api/me", headers=HD).status_code == 401 and auth._h(tokA) not in sessions.s)
    with users.lock:
        users._load(); users.data["users"]["cov-analyst"]["changed"] = 0; users.save()
    cP, _, tokP = client("cov-analyst", persist=True)
    sessions.s[auth._h(tokP)]["rotated"] -= 13 * 3600
    r = cP.get("/api/me", headers=HD)
    ok("a 'stay signed in' session after 12 hours: a new id in a new cookie, the old one gone",
       r.status_code == 200 and "lg_session=" in r.headers.get("Set-Cookie", "") and auth._h(tokP) not in sessions.s)
    ok("…pages and API answers are not kept by the browser", r.headers.get("Cache-Control") == "no-store")

    print("Peace of mind")
    auth.PEACE["of"] = lambda u: u == "cov-admin"
    cAd, csrfAd, _ = client("cov-admin")
    r = cAd.get("/api/findings", headers=HD)
    ok("a work API: refused (403) with the reason", r.status_code == 403 and "Peace of mind" in r.json["error"])
    ok("a work page: to the Overview", cAd.get("/findings", headers=HD).headers.get("Location", "").endswith("/?intro=1"))
    ok("the map start page: to the Overview, never the map", cAd.get("/", headers=HD).headers.get("Location", "").endswith("/?intro=1"))
    r = cAd.get("/api/svc/clock?all=1", headers=HD)
    ok("a complete list (?all=1) on a page it keeps: refused", r.status_code == 403 and "no exports" in r.json["error"])
    r = cAd.get("/api/me", headers=HD)
    ok("…its permissions are the admin duties only", r.status_code == 200 and set(r.json["perms"]) <= auth.PEACE_PERMS, str(r.json.get("perms")))
    auth.PEACE["of"] = saved["peace"]

    print("Each role to its own pages")
    cE, _, _ = client("cov-external")
    ok("external, a page not on its list: refused (403)", cE.get("/settings", headers=HD).status_code == 403)
    r = cE.get("/api/settings", headers=HD)
    ok("…an API not on its list: 403 with the reason", r.status_code == 403 and r.json.get("error"))
    cM, _, _ = client("cov-mgmt")
    ok("management: the platforms send it to its portal", cM.get("/services", headers=HD).headers.get("Location", "").endswith("/management"))
    ok("…another page: 403", cM.get("/api/kb/names", headers=HD).status_code == 403)
    cV, _, _ = client("cov-advisor")
    ok("advisor: the start page sends it to its portal", cV.get("/", headers=HD).headers.get("Location", "").endswith("/advisory"))
    ok("…the platforms' data: 403", cV.get("/api/svc/stats", headers=HD).status_code == 403)
    cU, csrfU, _ = client("cov-auditor")
    ok("auditor: the platforms send it to the Audit portal", cU.get("/definitions", headers=HD).headers.get("Location", "").endswith("/audit"))
    ok("…another API: 403", cU.get("/api/kb/names", headers=HD).status_code == 403)
    cR, _, _ = client("cov-research")
    ok("researcher: the start page sends it to Definitions", cR.get("/", headers=HD).headers.get("Location", "").endswith("/definitions"))
    ok("…the platforms' data: 403", cR.get("/api/svc/stats", headers=HD).status_code == 403)
    cW, _, _ = client("cov-viewer")
    r = cW.get("/api/svc/hosts.csv", headers=HD)
    ok("a role without 'export': no hosts CSV", r.status_code == 403 and "export" in r.json["error"])
    ok("…and no ?all=1 complete list", cW.get("/api/svc/stats?all=1", headers=HD).status_code == 403)

    print("Sign-in page")
    c = A.app.test_client()
    body = c.get("/login?notice=" + "Your+account+is+suspended", headers=HD).get_data(as_text=True)
    ok("a notice Looking Glass did not send is not shown", "suspended" not in body)
    body = c.get("/login?notice=" + auth.PASSWORD_CHANGED.replace(" ", "+"), headers=HD).get_data(as_text=True)
    ok("its own notice is", "Password changed" in body)
    r = c.post("/login", data={"username": "cov-analyst", "password": PW}, headers=HD, environ_base=FAR)
    ok("signing in from another computer over plain HTTP: refused (403)", r.status_code == 403 and "HTTPS" in r.get_data(as_text=True))
    r = c.post("/login", data={"step": "mfa", "code": "123456"}, headers=HD)
    ok("the authenticator step without the first step: expired (401)", r.status_code == 401)
    r = c.post("/login", data={"step": "expired", "password": "x"}, headers=HD)
    ok("the expired-password step without the first step: 401", r.status_code == 401)
    r = c.post("/login", data={"step": "enrol", "code": "123456"}, headers=HD)
    ok("the set-up step without the first step: 401", r.status_code == 401)
    r = c.post("/login", data={"username": "cov-revoked", "password": PW}, headers=HD)
    ok("a revoked account with the right password: 403, revoked", r.status_code == 403 and "revoked" in r.get_data(as_text=True))
    r = c.post("/login", data={"username": "cov-pending", "password": PW}, headers=HD)
    ok("an account waiting for approval: 403, waiting", r.status_code == 403 and "waiting" in r.get_data(as_text=True))
    c = A.app.test_client()
    r = c.post("/login", data={"username": "cov-analyst", "password": PW}, headers=HD)
    with users.lock:
        users._load(); users.data["users"]["cov-analyst"]["status"] = "disabled"; users.save()
    r = c.post("/login", data={"step": "mfa", "code": "123456"}, headers=HD)
    ok("revoked between the password and the code: no session (403)", r.status_code == 403 and "cannot sign in" in r.get_data(as_text=True))
    with users.lock:
        users._load(); users.data["users"]["cov-analyst"]["status"] = "active"; users.save()
    for _ in range(throttle.account_fails):
        throttle.failed("127.0.0.1", "cov-mgmt")
    r = A.app.test_client().post("/login", data={"username": "cov-mgmt", "password": PW}, headers=HD)
    ok("a locked name: 429 with the minutes left, written down", r.status_code == 429 and "minute" in r.get_data(as_text=True)
       and any(e == "login_locked" for e, *_ in logged))
    throttle.clear_address("127.0.0.1")

    print("The authenticator set up again (after a reset)")
    c = A.app.test_client()
    r = c.post("/login", data={"username": "cov-nototp", "password": PW}, headers=HD)
    s_ = secret_of(r)
    ok("no authenticator: the set-up page with a new secret", r.status_code == 200 and len(s_) == 32 and "lg_step=" in r.headers.get("Set-Cookie", ""))
    r = c.post("/login", data={"step": "enrol", "code": "000000" if auth.totp_at(s_, int(time.time() // 30)) != "000000" else "111111"}, headers=HD)
    ok("a wrong code: 401, try again", r.status_code == 401)
    r = c.post("/login", data={"step": "enrol", "code": fresh_code(s_)}, headers=HD)
    u_ = users.get("cov-nototp")
    ok("the right code: recovery codes shown, the authenticator stored", r.status_code == 200 and u_.get("totp") == s_ and len(u_.get("recovery", [])) == 8)
    ok("…and the account goes back to an administrator for approval", u_["status"] == "pending")

    print("An expired password, replaced at sign-in")
    pwp.expired = lambda u: (True, "made-up expiry for the check")
    secA = users.get("cov-analyst")["totp"]
    c = A.app.test_client()
    c.post("/login", data={"username": "cov-analyst", "password": PW}, headers=HD)
    r = c.post("/login", data={"step": "mfa", "code": fresh_code(secA), "next": "/"}, headers=HD)
    ok("password and code right, but expired: the new-password step, no session", r.status_code == 200 and "lg_session=" not in r.headers.get("Set-Cookie", "")
       and any(e == "password_expired" for e, *_ in logged))
    r = c.post("/login", data={"step": "expired", "password": "short", "password2": "short"}, headers=HD)
    ok("a new password against the rules: 400", r.status_code == 400)
    r = c.post("/login", data={"step": "expired", "password": PW, "password2": PW}, headers=HD)
    ok("the expired password again: 400, not the one that expired", r.status_code == 400 and "not the one that expired" in r.get_data(as_text=True))
    pwp.expired = saved["expired"]
    NEWPW = "Quiet-Meadow-Compass-24!"
    r = c.post("/login", data={"step": "expired", "password": NEWPW, "password2": NEWPW}, headers=HD)
    ok("a good new password: the session opens at once", r.status_code == 302 and "lg_session=" in r.headers.get("Set-Cookie", ""))
    ok("…the new password is stored", auth.check_password_hash(users.get("cov-analyst")["hash"], NEWPW))
    pwp.expired = lambda u: (True, "made-up expiry")
    c = A.app.test_client()
    c.post("/login", data={"username": "cov-analyst", "password": NEWPW}, headers=HD)
    time.sleep(31 - time.time() % 30)
    c.post("/login", data={"step": "mfa", "code": fresh_code(secA)}, headers=HD)
    codes = [c.post("/login", data={"step": "expired", "password": "x", "password2": "x"}, headers=HD).status_code for _ in range(5)]
    ok("five refused new passwords: the step ends (sign in again)", codes[:4] == [400] * 4 and codes[4] == 401, str(codes))
    pwp.expired = saved["expired"]
    with users.lock:
        users._load(); users.data["users"]["cov-analyst"]["hash"] = H; users.save()

    print("Sign-up")
    c = A.app.test_client()
    r = c.get("/register?invite=not-a-real-link", headers=HD)
    ok("a sign-up link that does not work: 403, ask for a new one", r.status_code == 403 and "no longer works" in r.get_data(as_text=True))
    r = c.post("/register", data={"invite": "not-a-real-link", "username": "cov-new"}, headers=HD)
    ok("…posting with it: 403 too", r.status_code == 403)
    form = {"username": "cov-new", "full_name": "Ama Owusu", "organisation": "Made-up CSIRT", "email": "ama@csirt-made-up.org",
            "country": "GH", "password": "Bright-Ocean-Window-58!", "password2": "Bright-Ocean-Window-58!"}
    r = c.post("/register", data=form, headers=HD, environ_base=FAR)
    ok("from another computer over plain HTTP: 403", r.status_code == 403)
    r = c.post("/register", data=dict(form, username="a"), headers=HD)
    ok("a one-letter name: 400", r.status_code == 400)
    r = c.post("/register", data=dict(form, username=auth.TEST_PREFIX + "x"), headers=HD)
    ok("the self-test's reserved names without the automation key: 400", r.status_code == 400)
    PROFILE_ANSWER["v"] = "Choose your country."
    r = c.post("/register", data=form, headers=HD)
    ok("a profile problem: 400 with it", r.status_code == 400 and "Choose your country" in r.get_data(as_text=True))
    PROFILE_ANSWER["v"] = None
    r = c.post("/register", data=dict(form, username="COV-ADMIN"), headers=HD)
    ok("a name taken in another letter case: 409", r.status_code == 409)
    r = c.post("/register", data=dict(form, email="COV-ADMIN-ACTIVE@csirt-made-up.org"), headers=HD)
    ok("an e-mail address already used (any case): 409", r.status_code == 409, str(r.status_code))
    r = c.post("/register", data=dict(form, password2="Different-Ocean-58!"), headers=HD)
    ok("two different passwords: 400", r.status_code == 400)
    r = c.post("/register", data=form, headers=HD)
    s_ = secret_of(r)
    ok("a good sign-up: the authenticator step", r.status_code == 200 and s_)
    with users.lock:
        users._load(); users.data["users"]["cov-new"] = acct("external", "pending"); users.save()
    r = c.post("/register", data={"step": "enrol", "code": fresh_code(s_)}, headers=HD)
    ok("the name taken by someone else between the steps: 409", r.status_code == 409)
    with users.lock:
        users._load(); users.data["users"].pop("cov-new"); users.save()
    r = c.post("/register", data=dict(form, username="cov-new2", email="ama2@csirt-made-up.org"), headers=HD)
    s_ = secret_of(r)
    time.sleep(31 - time.time() % 30)
    r = c.post("/register", data={"step": "enrol", "code": fresh_code(s_)}, headers=HD)
    nu = users.get("cov-new2") or {}
    ok("finished: the account waits for approval, lowest role, profile kept", r.status_code == 200 and nu.get("status") == "pending"
       and nu.get("role") == auth.LOWEST_ROLE and nu.get("profile", {}).get("full_name") == "Ama Owusu")
    for _ in range(5):
        throttle.count(("register", "127.0.0.1"), 3600, add=True)
    r = c.post("/register", data=form, headers=HD)
    ok("five new accounts from one address in an hour: 429", r.status_code == 429)
    throttle.clear_address("127.0.0.1")
    for _ in range(auth.REGISTER_DNS_PER_HOUR):
        throttle.count(("register-dns", "127.0.0.1"), 3600, add=True)
    r = c.post("/register", data=dict(form, username="cov-new3", email="ama3@csirt-made-up.org"), headers=HD)
    ok("thirty e-mail domain look-ups from one address in an hour: 429", r.status_code == 429 and "hour" in r.get_data(as_text=True))
    throttle.clear_address("127.0.0.1")
    # mass assignment: fields the form never asks for, added to the request by hand at both steps, change nothing; the
    # role comes only from the setup code, a sign-up link or the lowest role
    SMUGGLED = {"role": "admin", "isAdmin": "true", "is_admin": "1", "admin": "1", "status": "active", "perms": "users",
                "approved_by": "cov-admin", "invite": "", "setup": "1", "totp": "AAAA", "recovery": "x", "profile": "x"}
    r = c.post("/register", data=dict(form, username="cov-smuggle", email="ama4@csirt-made-up.org", **SMUGGLED), headers=HD)
    s_ = secret_of(r)
    time.sleep(31 - time.time() % 30)
    r = c.post("/register", data=dict(SMUGGLED, step="enrol", code=fresh_code(s_)), headers=HD)
    nu = users.get("cov-smuggle") or {}
    ok("sign-up with role=admin, isAdmin, status=active and more added to both steps: lowest role, waiting for approval",
       r.status_code == 200 and nu.get("role") == auth.LOWEST_ROLE and nu.get("status") == "pending"
       and not nu.get("approved_by") and not any(k in nu for k in ("isAdmin", "is_admin", "admin", "perms")),
       f"{r.status_code} {nu.get('role')} {nu.get('status')}")
    ok("…its profile holds only the four profile fields, as typed",
       set(nu.get("profile", {})) == {"full_name", "organisation", "email", "country"} and nu["profile"]["full_name"] == "Ama Owusu",
       str(nu.get("profile")))
    ok("…and its authenticator is the one it enrolled, not a value sent with the request", nu.get("totp") == s_)
    r = c.post("/register", json=dict(form, username="cov-smuggle2", email="ama5@csirt-made-up.org", **SMUGGLED), headers=HD)
    ok("the same as a JSON body: no account is made from it", "cov-smuggle2" not in (users.all() or {}), str(r.status_code))
    with users.lock:
        users._load(); users.data["users"].pop("cov-smuggle", None); users.save()
    throttle.clear_address("127.0.0.1")

    print("Forgot password")
    f = A.app.test_client()
    ok("an unknown mode is the authenticator mode", f.get("/forgot?mode=bogus", headers=HD).status_code == 200)
    ok("from another computer over plain HTTP: 403", f.post("/forgot", data={"username": "cov-admin"}, headers=HD, environ_base=FAR).status_code == 403)
    r1 = f.post("/forgot", data={"mode": "ask", "username": "cov-research"}, headers=HD)
    r2 = f.post("/forgot", data={"mode": "ask", "username": "nobody-made-up"}, headers=HD)
    ok("asking an administrator: the same answer for a real and an unknown name", r1.status_code == r2.status_code == 200
       and r1.get_data(as_text=True) == r2.get_data(as_text=True))
    ok("…the real one's request is on the account for the admin page", users.get("cov-research").get("reset_requested", {}).get("at"))
    codes = [f.post("/forgot", data={"mode": "ask", "username": "x"}, headers=HD).status_code for _ in range(5)]
    ok("more than five requests from one address in an hour: 429", codes[-1] == 429, str(codes))
    throttle.clear_address("127.0.0.1")
    secR = users.get("cov-research")["totp"]
    with users.lock:
        users._load(); users.data["users"]["cov-research"]["reset_allowed_until"] = int(time.time()) + 3600; users.save()
    r = f.post("/forgot", data={"username": "cov-research", "code": "000000" if auth.totp_at(secR, int(time.time() // 30)) != "000000" else "111111",
                                "password": "Bright-Ocean-Window-58!", "password2": "Bright-Ocean-Window-58!"}, headers=HD)
    ok("allowed by an administrator, but a wrong code: 401", r.status_code == 401)
    cd = fresh_code(secR)
    r = f.post("/forgot", data={"username": "cov-research", "code": cd, "password": "weak", "password2": "weak"}, headers=HD)
    ok("the right code, a weak new password: 400 (rules after the proof)", r.status_code == 400)
    r = f.post("/forgot", data={"username": "cov-research", "code": cd, "password": "Bright-Ocean-Window-58!", "password2": "Bright-Ocean-Window-58!"}, headers=HD)
    ru = users.get("cov-research")
    ok("the right code and a good password: done, to the sign-in with the notice", r.status_code == 302 and "notice=" in r.headers["Location"])
    ok("…no recovery code needed; the request and the permission are cleared",
       "reset_allowed_until" not in ru and "reset_requested" not in ru and any(e == "password_reset" and "administrator" in d for e, _, _, d in logged))
    for _ in range(throttle.account_fails):
        throttle.failed("127.0.0.1", "cov-research")
    ok("a locked name: 429", f.post("/forgot", data={"username": "cov-research", "code": "1"}, headers=HD).status_code == 429)
    throttle.clear_address("127.0.0.1")

    print("Sign out")
    ok("a link (GET) cannot sign out: only to the sign-in page", A.app.test_client().get("/logout", headers=HD).status_code == 302)
    cL, _, tokL = client("cov-external")
    r = cL.post("/logout", headers=HD)
    ok("signing out ends the session and is written down", r.status_code == 302 and auth._h(tokL) not in sessions.s and any(e == "logout" for e, *_ in logged))

    print("Admin pages")
    cU, csrfU, _ = client("cov-auditor")
    ok("an auditor on /admin: to the Audit portal", cU.get("/admin", headers=HD).headers.get("Location", "").endswith("/audit"))
    cAn, csrfAn, _ = client("cov-analyst")
    ok("an analyst on /admin: refused", cAn.get("/admin", headers=HD).status_code == 403)
    cAd, csrfAd, tokAd = client("cov-admin")
    sessions.create("cov-revoked", "127.0.0.1", UA)          # an orphan: the account is revoked
    r = cAd.get("/api/admin/users", headers=HD)
    me_row = next((x for x in r.json["users"] if x["name"] == "cov-admin"), {})
    ok("the account list: every account, 'you' marked, roles described", r.status_code == 200 and me_row.get("you") and "cov-viewer" in r.json["info"])
    ok("…sessions of accounts no longer active are ended on the way", not any(v["user"] == "cov-revoked" for v in sessions.s.values()))
    act = lambda name, body, c=cAd, csrf=csrfAd: post_json(c, f"/api/admin/users/{name}", body, csrf)
    ok("a change without the CSRF token: 403", cAd.post("/api/admin/users/cov-analyst", json={"action": "kick"}, headers=HD).status_code == 403)
    ok("a change sent as a form: 403", cAd.post("/api/admin/users/cov-analyst", data={"action": "kick"}, headers=dict(HD, **{"X-CSRF-Token": csrfAd})).status_code == 403)
    ok("a JSON list instead of an object: 400", act("cov-analyst", ["kick"]).status_code == 400)
    ok("no such account: 404", act("cov-nobody", {"action": "kick"}).status_code == 404)
    ok("revoking your own account: 400", act("cov-admin", {"action": "revoke"}).status_code == 400)
    ok("approving an active account: 400", act("cov-analyst", {"action": "approve"}).status_code == 400)
    ok("approving with an unknown role (or a list): 400", act("cov-pending", {"action": "approve", "role": ["admin"]}).status_code == 400)
    ok("approving an account without its authenticator: 400", act("cov-waitnew", {"action": "approve"}).status_code == 400)
    r = act("cov-pending", {"action": "approve", "role": "analyst"})
    ok("approving a waiting account: active with the role, approved by whom", r.status_code == 200 and users.get("cov-pending")["status"] == "active"
       and users.get("cov-pending")["approved_by"] == "cov-admin")
    ok("a role that does not exist: 400", act("cov-pending", {"action": "role", "role": "chief"}).status_code == 400)
    ok("the last administrator giving away the admin role: 400", act("cov-admin", {"action": "role", "role": "analyst"}).status_code == 400)
    cAuto = A.app.test_client()
    AH = dict(HD, **{"X-LG-Automation": AKEY})
    for a_ in ("revoke", "reset_mfa", "delete"):
        r = cAuto.post("/api/admin/users/cov-admin", json={"action": a_}, headers=AH)
        ok(f"{a_} on the last administrator: 400", r.status_code == 400 and "last admin" in r.json["error"])
    cX, _, tokX = client("cov-pending")
    r = act("cov-pending", {"action": "role", "role": "external"})
    ok("changing a role: the person's sessions restart", r.status_code == 200 and users.get("cov-pending")["role"] == "external" and auth._h(tokX) not in sessions.s)
    ok("restoring an account that is not revoked: 400", act("cov-pending", {"action": "restore"}).status_code == 400)
    ok("revoking", act("cov-pending", {"action": "revoke"}).status_code == 200 and users.get("cov-pending")["status"] == "disabled")
    ok("…restoring gives back what it was (active)", act("cov-pending", {"action": "restore"}).status_code == 200 and users.get("cov-pending")["status"] == "active")
    ok("resetting the authenticator", act("cov-pending", {"action": "reset_mfa"}).status_code == 200 and not users.get("cov-pending").get("totp"))
    ok("allowing a reset with no authenticator: 400", act("cov-pending", {"action": "allow_reset"}).status_code == 400)
    ok("allowing a reset: 24 hours", act("cov-viewer", {"action": "allow_reset"}).status_code == 200
       and users.get("cov-viewer")["reset_allowed_until"] > time.time() + 86000)
    client("cov-viewer"); client("cov-viewer")
    r = act("cov-viewer", {"action": "kick"})
    ok("ending a person's sessions: how many", r.status_code == 200 and r.json["ended"] >= 2 and not any(v["user"] == "cov-viewer" for v in sessions.s.values()))
    ok("an unknown action: 400", act("cov-viewer", {"action": "promote"}).status_code == 400)
    ok("deleting", act("cov-viewer", {"action": "delete"}).status_code == 200 and users.get("cov-viewer") is None)
    ok("…the name stays reserved", "cov-viewer" in users.data.get("deleted_names", []))
    r = A.app.test_client().post("/register", data=dict(form, username="Cov-Viewer", email="z@csirt-made-up.org"), headers=HD)
    ok("…signing up with it later: taken (409)", r.status_code == 409)
    cOld, csrfOld, tokOld = client("cov-admin", persist=True)
    sessions.s[auth._h(tokOld)]["created"] -= 13 * 3600
    sessions.s[auth._h(tokOld)]["rotated"] = time.time()
    r = post_json(cOld, "/api/admin/users/cov-analyst", {"action": "kick"}, csrfOld)
    ok("a 'stay signed in' session older than 12 hours can view but not change: 403, sign in again", r.status_code == 403 and r.json.get("reauth"))

    print("Sessions, the audit list, roles")
    r = cU.get("/api/admin/sessions", headers=HD)
    ok("the auditor reads the sessions but cannot end them", r.status_code == 200 and r.json["can_end"] is False)
    cE, _, _ = client("cov-external")
    ok("an external account: 403", cE.get("/api/admin/sessions", headers=HD).status_code == 403)
    r = cAd.get("/api/admin/sessions", headers=HD)
    mine = [s for s in r.json["sessions"] if s["current"]]
    ok("the admin's own session is marked current", r.status_code == 200 and len(mine) == 1 and r.json["can_end"])
    ok("ending a session by a malformed id: 400", post_json(cAd, "/api/admin/sessions/zz/end", {}, csrfAd).status_code == 400)
    ok("…by an unknown id: 404", post_json(cAd, "/api/admin/sessions/0123456789abcdef/end", {}, csrfAd).status_code == 404)
    _, _, tokE = client("cov-external")
    r = post_json(cAd, f"/api/admin/sessions/{auth._h(tokE)[:16]}/end", {}, csrfAd)
    ok("…by its id: ended, written down", r.status_code == 200 and auth._h(tokE) not in sessions.s and any(e == "kicked" and t == "cov-external" for e, _, t, _ in logged))
    r = cAd.get("/api/admin/audit?limit=many&offset=x", headers=HD)
    ok("the audit list with a limit that is not a number: the default, no error", r.status_code == 200 and "rows" in r.json)
    ok("an analyst cannot read the audit list", cAn.get("/api/admin/audit", headers=HD).status_code == 403)
    r = cAd.get("/api/admin/roles", headers=HD)
    ok("roles: the list, which are fixed, which permissions are exclusive", r.status_code == 200 and "auditor" in r.json["fixed"]
       and r.json["exclusive"]["users"] == "admin" and r.json["in_use"].get("admin", 0) >= 1)
    rp = lambda body: post_json(cAd, "/api/admin/roles", body, csrfAd)
    ok("roles not as {roles: {...}}: 400", rp({"roles": ["analyst"]}).status_code == 400)
    ok("a role name with capitals: 400", rp({"roles": {"Analyst": ["view"]}}).status_code == 400)
    ok("removing a role still in use: 400, named", "analyst" in rp({"roles": {"external": ["view"]}}).json.get("error", ""))
    cur = {k: v for k, v in roles.roles.items() if k != "admin"}
    r = rp({"roles": dict(cur, **{"cov-reader": ["view", "users", "bogus"]})})
    ok("adding a role: saved without unknown or exclusive permissions", r.status_code == 200 and r.json["roles"]["cov-reader"] == ["view"])
    ok("…written down", any(e == "roles_changed" for e, *_ in logged))
finally:
    users.path, users.mtime, users.data = saved["users"]
    sessions.path = saved["sessions"][0]; sessions.s.clear(); sessions.s.update(saved["sessions"][1])
    throttle.path = saved["throttle"][0]; throttle.fail.clear(); throttle.fail.update(saved["throttle"][1])
    roles.path = saved["roles"][0]; roles.roles = saved["roles"][1]
    audit.add, setup.path, auth.profile_problem = saved["audit"], saved["setup"], saved["profile"]
    auth.PEACE["of"], pwp.expired = saved["peace"], saved["expired"]
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
