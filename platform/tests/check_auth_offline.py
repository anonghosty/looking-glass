#!/usr/bin/env python3
"""Sign-in, the authenticator and the role gates, offline (review 2026-11-13: these were only tested against a live
installation, by the security retest). In-process, on throwaway accounts: no server, no database, nothing real touched.
- password + authenticator code opens a session; a wrong code, or the same code again, does not
- a recovery code works once, then never again
- /forgot with the authenticator: name + code + one recovery code + a new password; each part missing or wrong is
  refused with the same answer as an unknown name; the old password stops working, the new one works
- /forgot asking an administrator: the same answer for a real and an unknown name
- names that differ only in letter case are the same name
- each portal opens for its own role only: Executive (management), Advisories (advisor), Definitions (researcher),
  Audit (auditor), Admin (admin)
Run: .venv/bin/python tests/check_auth_offline.py"""
import base64, hashlib, hmac, json, os, shutil, struct, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
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


def code(secret, step=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", step if step is not None else int(time.time()) // 30), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


tmp = tempfile.mkdtemp(prefix="lg-authoffline-")
users, sessions, throttle, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["throttle"], A.AUTH["audit"]
setup = A.AUTH["setup"]
real = (users.path, users.mtime, users.data, audit.add, setup.path, auth.profile_problem)
logged = []
audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("detail", "")))
setup.path = os.path.join(tmp, "setup_code")             # never the installation's own first-run code
auth.profile_problem = lambda *a, **k: None               # no DNS look-up of the example e-mail domains
PW = "Steady-Harbour-Lantern-63!"
SEC = {r: base64.b32encode(os.urandom(20)).decode().rstrip("=") for r in
       ("analyst", "management", "advisor", "researcher", "auditor", "admin", "external")}
RECOVERY = ["1a2b-3c4d-5e6f", "0f0f-1e1e-2d2d"]
accounts = {f"chk-{r}": {"hash": generate_password_hash(PW), "role": r, "status": "active", "totp": SEC[r], "changed": 0,
                         "pw_set_at": int(time.time()), "profile": {"full_name": f"Check {r.title()}", "email": f"{r}@example.org"}}
            for r in SEC}
accounts["chk-analyst"]["recovery"] = [generate_password_hash(c) for c in RECOVERY]
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": accounts}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = {"User-Agent": "lg-check-authoffline"}
has_session = lambda r: "lg_session=" in r.headers.get("Set-Cookie", "") and "lg_session=;" not in r.headers.get("Set-Cookie", "")


def fresh_window(name):
    """Wait for a 30-second window this account has not used, away from its edges (a code works once)."""
    last = (users.get(name) or {}).get("totp_last")
    while True:
        now = time.time()
        if (last is None or int(now) // 30 > last) and 1 <= now % 30 <= 27:
            return
        time.sleep(0.5)


def password_step(name, pw=PW):
    c = A.app.test_client()
    r = c.post("/login", data={"username": name, "password": pw}, headers=UA)
    return c, r


def mfa(c, value):
    return c.post("/login", data={"step": "mfa", "code": value, "next": "/"}, headers=UA)


try:
    throttle.clear_address("127.0.0.1")
    print("Password and authenticator")
    fresh_window("chk-analyst")
    c, r = password_step("chk-analyst")
    ok("the right password leads to the authenticator step, no session yet", r.status_code == 200 and not has_session(r), str(r.status_code))
    good = code(SEC["analyst"])
    r = mfa(c, "000000" if good != "000000" else "111111")
    ok("a wrong code: refused, no session", r.status_code == 401 and not has_session(r), str(r.status_code))
    r = mfa(c, good)
    ok("the right code: the session opens", r.status_code == 302 and has_session(r), str(r.status_code))
    c2, _ = password_step("chk-analyst")
    r = mfa(c2, good)
    ok("the same code again (replayed) in a second sign-in: refused", r.status_code == 401 and not has_session(r), str(r.status_code))
    ok("…logged as a wrong or reused code", any(e == "login_failed" and u == "chk-analyst" and "reused" in d for e, u, d in logged))
    c, r = password_step("chk-analyst", "Not-the-password-11!")
    ok("a wrong password: refused before the authenticator", r.status_code == 401, str(r.status_code))
    c, r = password_step("nobody-at-all", "Not-the-password-11!")
    ok("…an unknown name gets the same answer", r.status_code == 401, str(r.status_code))
    throttle.clear_address("127.0.0.1")

    print("Recovery codes")
    c, _ = password_step("chk-analyst")
    r = mfa(c, RECOVERY[0])
    ok("a recovery code in place of the authenticator code: the session opens", r.status_code == 302 and has_session(r), str(r.status_code))
    ok("…it is used up (one left)", len(users.get("chk-analyst").get("recovery", [])) == 1)
    c, _ = password_step("chk-analyst")
    r = mfa(c, RECOVERY[0])
    ok("…and refused the second time", r.status_code == 401 and not has_session(r), str(r.status_code))
    throttle.clear_address("127.0.0.1")

    print("Forgot password, with the authenticator")
    NEW = "Quiet-Meadow-Compass-24!"
    base = {"username": "chk-analyst", "password": NEW, "password2": NEW}
    f = A.app.test_client()
    fresh_window("chk-analyst")
    now_code = code(SEC["analyst"])
    for label, form in (("without a recovery code", dict(base, code=now_code)),
                        ("with a wrong recovery code", dict(base, code=now_code, recovery="9999-9999-9999")),
                        ("with the used-up recovery code", dict(base, code=now_code, recovery=RECOVERY[0])),
                        ("with a wrong authenticator code", dict(base, code="000000" if now_code != "000000" else "111111", recovery=RECOVERY[1]))):
        r = f.post("/forgot", data=form, headers=UA)
        ok(f"{label}: refused", r.status_code == 401, str(r.status_code))
    r = f.post("/forgot", data=dict(base, username="nobody-at-all", code=now_code, recovery=RECOVERY[1]), headers=UA)
    ok("…an unknown name gets the same answer", r.status_code == 401, str(r.status_code))
    throttle.clear_address("127.0.0.1")
    r = f.post("/forgot", data=dict(base, code=now_code, recovery=RECOVERY[1]), headers=UA)
    ok("name + code + recovery code + new password: changed", r.status_code == 302 and "Password%20changed" in r.headers.get("Location", ""),
       f"{r.status_code} {r.headers.get('Location', '')}")
    ok("…the recovery code it used is gone", not users.get("chk-analyst").get("recovery"))
    _, r = password_step("chk-analyst", PW)
    ok("…the old password no longer works", r.status_code == 401, str(r.status_code))
    _, r = password_step("chk-analyst", NEW)
    ok("…the new one does", r.status_code == 200, str(r.status_code))
    throttle.clear_address("127.0.0.1")
    r1 = f.post("/forgot?mode=ask", data={"username": "chk-management", "mode": "ask"}, headers=UA)
    r2 = f.post("/forgot?mode=ask", data={"username": "nobody-at-all", "mode": "ask"}, headers=UA)
    ok("asking an administrator: the same answer for a real and an unknown name",
       r1.status_code == r2.status_code == 200 and r1.get_data() == r2.get_data(), f"{r1.status_code} {r2.status_code}")

    print("The sign-in page shows only its own notices")
    page_ = A.app.test_client().get("/login?notice=" + "Your%20account%20is%20compromised.%20Call%20%2B000", headers=UA).get_data(as_text=True)
    ok("a made-up ?notice= text is not shown", "compromised" not in page_)
    page_ = A.app.test_client().get("/login?notice=" + "Password%20changed.%20Log%20in%20with%20the%20new%20password.", headers=UA).get_data(as_text=True)
    ok("…the one Looking Glass sends (after a password reset) is", "Password changed. Log in with the new password." in page_)
    print("A JSON array sent in chunks is refused like any other (it reached a route and failed with a 500)")
    tok = sessions.create("chk-admin", "127.0.0.1", UA["User-Agent"])
    cl = A.app.test_client(); cl.set_cookie("lg_session", tok)
    csrf = sessions.s[auth._h(tok)]["csrf"]          # this session's own token (never another one left behind)

    import io  # noqa: E402
    # as gunicorn hands a chunked request to the app: no Content-Length, the body read to its end
    r = cl.open("/api/settings", method="POST", input_stream=io.BytesIO(b"[1, 2, 3]"),
                headers=dict(UA, **{"Content-Type": "application/json", "X-CSRF-Token": csrf, "Transfer-Encoding": "chunked"}),
                environ_overrides={"wsgi.input_terminated": True})
    ok("a chunked JSON array: 400, not a crash", r.status_code == 400, str(r.status_code))
    sessions.end(token=tok)
    print("Names that differ only in letter case are one name")
    reg = A.app.test_client()
    form = {"username": "CHK-Management", "full_name": "Someone Else", "organisation": "Example Org", "country": "GH",
            "email": "someone@example.org", "password": "a long enough pass phrase 42", "password2": "a long enough pass phrase 42"}
    r = reg.post("/register", data=form, base_url="https://localhost", headers=UA)
    ok("'CHK-Management' cannot register beside 'chk-management'", r.status_code == 409, str(r.status_code))
    r = reg.post("/register", data=dict(form, username="chk-other", email="Management@Example.org"), base_url="https://localhost", headers=UA)
    ok("…nor an e-mail address that differs only in case", r.status_code == 409, str(r.status_code))

    print("/forgot does the same work for an active account and an unknown name (review 2026-11-13)")
    real_check, hashes = auth.check_password_hash, []
    auth.check_password_hash = lambda h, p: (hashes.append(1), real_check(h, p))[1]
    try:
        throttle.clear_address("127.0.0.1")
        work = {}
        for who in ("chk-auditor", "nobody-at-all"):
            hashes.clear()
            A.app.test_client().post("/forgot", data={"username": who, "code": "000000", "recovery": "9999-9999-9999",
                                                      "password": NEW, "password2": NEW}, headers=UA)
            work[who] = len(hashes)
        ok("a wrong code on an active account and an unknown name: one password hash each", work["chk-auditor"] == work["nobody-at-all"] == 1, str(work))
    finally:
        auth.check_password_hash = real_check
        throttle.clear_address("127.0.0.1")

    print("A deleted account's name is not given out again (review 2026-11-13)")
    tok = sessions.create("chk-admin", "127.0.0.1", UA["User-Agent"])
    cl = A.app.test_client(); cl.set_cookie("lg_session", tok)
    csrf = sessions.s[auth._h(tok)]["csrf"]
    r = cl.post("/api/admin/users/chk-external", json={"action": "delete"}, headers=dict(UA, **{"X-CSRF-Token": csrf}))
    ok("an administrator deletes chk-external", r.status_code == 200 and not users.get("chk-external"), f"{r.status_code} {r.get_data(as_text=True)[:120]}")
    ok("…its name is kept as reserved", "chk-external" in (json.load(open(users.path)).get("deleted_names") or []))
    sessions.end(token=tok)
    r = reg.post("/register", data=dict(form, username="chk-external", email="new-person@example.org"), base_url="https://localhost", headers=UA)
    ok("…so nobody can register it again", r.status_code == 409, str(r.status_code))
    r = reg.post("/register", data=dict(form, username="CHK-External", email="new-person@example.org"), base_url="https://localhost", headers=UA)
    ok("…in any letter case", r.status_code == 409, str(r.status_code))

    print("Each portal opens for its own role only")
    PAGES = {"/management": {"management", "admin"}, "/advisory": {"advisor", "admin"}, "/definitions": {"researcher", "admin"},
             "/audit": {"auditor", "admin"}, "/admin": {"admin"}}       # admin holds every permission (SECURITY.md)
    for role in SEC:
        if role == "external":
            continue                                   # deleted above
        tok = sessions.create(f"chk-{role}", "127.0.0.1", UA["User-Agent"])
        cl = A.app.test_client(); cl.set_cookie("lg_session", tok)
        for page, allowed in PAGES.items():
            st = cl.get(page, headers=UA).status_code
            ok(f"{role:<10} {page:<12} {'opens' if role in allowed else 'refused'}", (st == 200) == (role in allowed), str(st))
        sessions.end(token=tok)
finally:
    users.path, users.mtime, users.data, audit.add, setup.path, auth.profile_problem = real
    throttle.clear_address("127.0.0.1")
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
