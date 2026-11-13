#!/usr/bin/env python3
"""Password expiry (password_policy.py, auth.py), through the real sign-in: name and password, the authenticator code,
then, when the password has expired, the new-password step BEFORE any session exists, and straight into the platform
afterwards (no second sign-in). Accounts, the policy and the audit log are temporary: nothing real is touched.
- policy off: sign-in as before
- switching it on (admin's own password): every account must choose a new password at its next sign-in
- the expired step: no session cookie yet; the old password, a weak one or two that differ are refused; a good one opens
  the session at once, records when it was set, ends the account's other sessions; the next sign-in is normal again
- passwords older than N days expire; "every account now" makes even a fresh password expire once
- only administrators, with their own password (a wrong one counts as a failed sign-in); every step in the audit log
Run: .venv/bin/python tests/check_password_policy.py"""
import base64, hashlib, hmac, json, os, shutil, struct, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
from werkzeug.security import generate_password_hash, check_password_hash  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def code(secret, step=None):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    d = hmac.new(key, struct.pack(">Q", step if step is not None else int(time.time()) // 30), hashlib.sha1).digest()
    o = d[-1] & 0x0F
    return f"{(struct.unpack('>I', d[o:o + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


tmp = tempfile.mkdtemp(prefix="lg-pwpolicy-")
tpl = os.environ.get("LG_TEMPLATES_DIR")              # held-back templates (login.html with the expired step)
if tpl:
    import jinja2
    A.app.jinja_loader = jinja2.ChoiceLoader([jinja2.FileSystemLoader(tpl), A.app.jinja_loader])
users, sessions, throttle, audit = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["throttle"], A.AUTH["audit"]
policy = A.AUTH["password_policy"]
real = (users.path, users.mtime, users.data, policy.path, audit.add)
logged = []
audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("detail", "")))
policy.path = os.path.join(tmp, "password_policy.json")
SEC_U, SEC_A = base64.b32encode(os.urandom(20)).decode().rstrip("="), base64.b32encode(os.urandom(20)).decode().rstrip("=")
PW_U, PW_A, NEW_U = "Old-pass-phrase-41!", "Admin-pass-phrase-77!", "Fresh-Kettle-Morning-58!"
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": {
        "chkadmin": {"hash": generate_password_hash(PW_A), "role": "admin", "status": "active", "totp": SEC_A, "pw_set_at": int(time.time()), "changed": 0},
        "chkuser": {"hash": generate_password_hash(PW_U), "role": "external", "status": "active", "totp": SEC_U, "changed": 0}}}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
# the throwaway accounts hold an administrator: the first-run code must follow them to the throwaway folder, or the
# first page shown would delete the real installation's data/setup_code (review 2026-11-13)
setup = A.AUTH["setup"]; real_setup = setup.path; setup.path = os.path.join(tmp, "setup_code")
UA = {"User-Agent": "lg-check-pwpolicy"}


def sign_in(name, pw, secret):
    """(client, response after the authenticator step). Each code works once (the server refuses a reused one), so
    wait for a 30-second window this account has not used yet, and never start in a window's last 3 seconds: a
    sign-in that crossed the boundary could otherwise land on a used window and be refused, as a real reuse would."""
    last = (users.get(name) or {}).get("totp_last")
    while True:
        now = time.time()
        if (last is None or int(now) // 30 > last) and 1 <= now % 30 <= 27:
            break
        time.sleep(0.5)
    c = A.app.test_client()
    r = c.post("/login", data={"username": name, "password": pw}, headers=UA)
    r = c.post("/login", data={"step": "mfa", "code": code(secret, int(time.time()) // 30), "next": "/"}, headers=UA)
    return c, r


has_session = lambda r: "lg_session=" in r.headers.get("Set-Cookie", "") and "lg_session=;" not in r.headers.get("Set-Cookie", "")
try:
    throttle.clear_address("127.0.0.1")
    print("Policy off: sign-in as before")
    c, r = sign_in("chkuser", PW_U, SEC_U)
    ok("password + authenticator code opens the session", r.status_code == 302 and has_session(r), str(r.status_code))

    print("An administrator switches the policy on (90 days)")
    a, ra = sign_in("chkadmin", PW_A, SEC_A)
    csrf = max((s for s in sessions.s.values() if s["user"] == "chkadmin" and s.get("csrf")), key=lambda s: s["created"])["csrf"]   # the newest: the one this check made
    H = dict(UA, **{"X-CSRF-Token": csrf})
    r = a.post("/api/password-policy", json={"enabled": True, "days": 90, "password": "wrong"}, headers=H)
    ok("…not with a wrong password (refused, counted, logged)", r.status_code == 403 and not policy.get()["enabled"]
       and any(e == "password_policy_refused" for e, *_ in logged), str(r.status_code))
    throttle.clear_address("127.0.0.1")
    r = a.post("/api/password-policy", json={"enabled": True, "days": 0, "password": PW_A}, headers=H)
    ok("…not with 0 days", r.status_code == 400)
    r = a.post("/api/password-policy", json={"enabled": True, "days": 90, "password": PW_A}, headers=H)
    ok("…with their own password: on, 90 days, every account due", r.status_code == 200 and r.json["enabled"] and r.json["days"] == 90
       and r.json["due"] == 2, str(r.json))
    ok("…logged as a privileged change", any(e == "password_policy_changed" and "every account" in d for e, _, d in logged))
    u2 = A.app.test_client()
    ok("an account without the Settings permission cannot read or change it",
       u2.get("/api/password-policy", headers=UA).status_code in (401, 403))

    print("The next sign-in: the expired step, before any session")
    c, r = sign_in("chkuser", PW_U, SEC_U)
    page = r.get_data(as_text=True)
    ok("after the authenticator code: no session yet, the 'password has expired' box instead", r.status_code == 200 and not has_session(r)
       and 'value="expired"' in page and "expired" in page.lower(), str(r.status_code))
    ok("…logged as an expired password", any(e == "password_expired" and u == "chkuser" for e, u, _ in logged))
    r = c.get("/api/me", headers=UA)
    ok("…the platform stays closed meanwhile", r.status_code in (401, 302), str(r.status_code))
    for pw, pw2, why in ((PW_U, PW_U, "the expired password again"), ("short1!", "short1!", "a weak password"),
                         (NEW_U, NEW_U + "x", "two that differ")):
        r = c.post("/login", data={"step": "expired", "password": pw, "password2": pw2, "next": "/"}, headers=UA)
        ok(f"refused: {why} (still no session)", r.status_code == 400 and not has_session(r), str(r.status_code))
    other, _ = sign_in("chkadmin", PW_A, SEC_A)          # (the admin too must change, but that is their own step)
    r = c.post("/login", data={"step": "expired", "password": NEW_U, "password2": NEW_U, "next": "/"}, headers=UA)
    ok("a good new password opens the session at once, no second sign-in", r.status_code == 302 and has_session(r) and r.headers["Location"].endswith("/"), str(r.status_code))
    u = users.get("chkuser")
    ok("…stored (the old one no longer works), with the time it was set", check_password_hash(u["hash"], NEW_U) and not check_password_hash(u["hash"], PW_U)
       and abs(u.get("pw_set_at", 0) - time.time()) < 60)
    ok("…logged", any(e == "password_changed" and u_ == "chkuser" for e, u_, _ in logged))
    c, r = sign_in("chkuser", NEW_U, SEC_U)
    ok("the next sign-in is normal again", r.status_code == 302 and has_session(r), str(r.status_code))

    print("Passwords older than N days, and 'every account now'")
    policy._save(dict(policy.get(), enforced_at=time.time() - 200 * 86400))   # a policy in force for 200 days already
    with users.lock:
        users._load(); users.data["users"]["chkuser"]["pw_set_at"] = int(time.time()) - 91 * 86400; users.save()
    ok("a password older than 90 days has expired", policy.expired(users.get("chkuser"))[0] and "90 days" in policy.expired(users.get("chkuser"))[1])
    with users.lock:
        users._load(); users.data["users"]["chkuser"]["pw_set_at"] = int(time.time()) - 10; users.save()
    ok("a fresh one has not", not policy.expired(users.get("chkuser"))[0])
    time.sleep(1)
    r = a.post("/api/password-policy/force", json={"password": PW_A}, headers=H)
    ok("'every account now' (admin's password): even a fresh password must change once", r.status_code == 200
       and policy.expired(users.get("chkuser"))[0] and any(e == "password_change_forced" for e, *_ in logged), str(r.status_code))
    r = a.post("/api/password-policy", json={"enabled": False, "days": 90, "password": PW_A}, headers=H)
    ok("switching the policy off keeps the 'every account now' request", r.status_code == 200 and not r.json["enabled"]
       and policy.expired(users.get("chkuser"))[0])

    print("Forgot password: nothing about the account before its owner proves who they are (external review, 2026-11-12)")
    with users.lock:
        users._load(); users.data["users"]["chkuser"]["profile"] = {"full_name": "Kwabena Asante", "email": "kasante@example.org"}
        users.save()
    throttle.clear_address("127.0.0.1")
    f = A.app.test_client()
    tries = []
    for name, pw in (("chkuser", "Kwabena-Asante-2026!"), ("nobody-here", "Kwabena-Asante-2026!"), ("chkuser", "Totally-Different-77!")):
        r = f.post("/forgot", data={"mode": "self", "username": name, "password": pw, "password2": pw, "code": "000000"}, headers=UA)
        tries.append((r.status_code, "not right" in r.get_data(as_text=True)))
    ok("a wrong code gets the same answer whether the account exists or the password contains its owner's name",
       len(set(tries)) == 1 and tries[0] == (401, True), str(tries))
    ok("…and each is counted as a failed try", throttle.left("127.0.0.1", "chkuser") < 5)
    throttle.clear_address("127.0.0.1")
    with users.lock:
        users._load(); users.data["users"]["chkuser"]["reset_allowed_until"] = int(time.time()) + 600; users.save()
    last = users.get("chkuser").get("totp_last") or 0
    while int(time.time()) // 30 <= last or time.time() % 30 > 27:
        time.sleep(0.5)
    r = f.post("/forgot", data={"mode": "self", "username": "chkuser", "password": "Kwabena-Asante-2026!", "password2": "Kwabena-Asante-2026!",
                                "code": code(SEC_U)}, headers=UA)
    ok("once proven (authenticator, reset allowed), the password rules apply: one built from the owner's name is refused",
       r.status_code == 400, str(r.status_code))
finally:
    users.path, users.mtime, users.data, policy.path, audit.add = real
    setup.path = real_setup
    throttle.clear_address("127.0.0.1")
    for s in list(sessions.s.values()):
        if s.get("user") in ("chkuser", "chkadmin"):
            sessions.end_user(s["user"])
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
