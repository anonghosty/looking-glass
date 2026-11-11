#!/usr/bin/env python3
"""The reverse-proxy trap and the first administrator (external review, 2026-11-11).

1. proxy_guard.py: behind a proxy (TRUST_PROXY=1) a request from the loopback peer without X-Forwarded-For is refused
   (it would look like "this computer"); /healthz still answers; forwarded headers from any other peer are ignored.
2. first_run.py: the one-time setup code (file mode 600, readable format, typed loosely, gone once used).
3. auth.py on a fresh, throwaway data folder: the first administrator needs the setup code, even from this computer;
   a wrong code is refused and audited; from another computer only over HTTPS (through the reverse proxy); the right
   code makes the administrator and deletes the code.
Run: .venv/bin/python tests/check_first_admin_proxy.py"""
import logging, os, re, stat, sys, tempfile, time, shutil
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import proxy_guard  # noqa: E402
import first_run  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  ({info})" if info and not cond else ""))


print("1. Reverse proxy (TRUST_PROXY=1)")
from flask import Flask, request  # noqa: E402
pa = Flask("proxytest")


@pa.route("/who")
def who():
    return f"{request.remote_addr} {request.scheme}"


@pa.route("/healthz")
def hz():
    return "ok"


proxy_guard.install(pa, True)
c = pa.test_client()
r = c.get("/who", environ_base={"REMOTE_ADDR": "127.0.0.1"})
ok("from the proxy's address without X-Forwarded-For: refused (would look like this computer)", r.status_code == 400 and b"X-Forwarded-For" in r.data)
ok("/healthz still answers without it (service checks)", c.get("/healthz", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200)
r = c.get("/who", headers={"X-Forwarded-For": "203.0.113.5", "X-Forwarded-Proto": "https"}, environ_base={"REMOTE_ADDR": "127.0.0.1"})
ok("through the proxy: the visitor's real address and https", r.data == b"203.0.113.5 https", r.data.decode())
r = c.get("/who", headers={"X-Forwarded-For": "127.0.0.1", "X-Forwarded-Proto": "https"}, environ_base={"REMOTE_ADDR": "198.51.100.7"})
ok("straight to the app port from elsewhere: forwarded headers ignored, cannot claim 127.0.0.1", r.data == b"198.51.100.7 http", r.data.decode())
r = c.get("/who", headers={"X-Forwarded-For": "  "}, environ_base={"REMOTE_ADDR": "::1"})
ok("an empty X-Forwarded-For counts as missing (IPv6 loopback too)", r.status_code == 400)
pb = Flask("noproxy")
pb.add_url_rule("/who", "who", who)
ok("without TRUST_PROXY nothing changes", proxy_guard.install(pb, False) is False and
   pb.test_client().get("/who", headers={"X-Forwarded-For": "203.0.113.5"}, environ_base={"REMOTE_ADDR": "127.0.0.1"}).data == b"127.0.0.1 http")

print("\n2. The setup code")
tmp = tempfile.mkdtemp(prefix="lg-firstrun-")
try:
    s = first_run.SetupCode(tmp)
    s.sync(True)
    code = s.read()
    ok("created while there is no administrator, readable format", re.fullmatch(r"[A-HJ-NP-Z2-9]{4}(-[A-HJ-NP-Z2-9]{4}){3}", code) is not None, code and "format")
    ok("only the owner can read it (600)", stat.S_IMODE(os.stat(s.path).st_mode) == 0o600)
    s.sync(True)
    ok("a second start keeps the same code", s.read() == code)
    ok("typed loosely (lower case, spaces) still matches", s.matches(code.lower().replace("-", " ")))
    ok("a wrong or empty code does not", not s.matches("AAAA-BBBB-CCCC-DDDD") and not s.matches("") and not s.matches(None))
    s.sync(False)
    ok("gone once an administrator exists, and then nothing matches", not os.path.exists(s.path) and not s.matches(code))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\n3. The first administrator (fresh, throwaway data folder)")
base = tempfile.mkdtemp(prefix="lg-firstadmin-")
os.makedirs(os.path.join(base, "data"))
try:
    import auth  # noqa: E402
    auth.profile_problem = lambda *a, **k: None          # no DNS look-up of the example e-mail domain
    SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
    auth.totp_new_secret = lambda: SECRET
    app = Flask("firstadmin", root_path=ROOT)
    app.secret_key = "unit-test"
    auth.install(app, base, logging.getLogger("t"))
    sc = first_run.SetupCode(os.path.join(base, "data"))
    code = sc.read()
    ok("a fresh install has a setup code at start", bool(code))
    c = app.test_client()
    page = c.get("/login").get_data(as_text=True)
    ok("the first-run page asks for it (never shows it)", 'name="setup_code"' in page and code not in page)
    form = {"full_name": "Grace Example", "organisation": "Example CSIRT", "email": "grace@example.org", "country": "GH",
            "username": "grace", "password": "Correct-Horse-Battery-9", "password2": "Correct-Horse-Battery-9"}
    r = c.post("/register", data=form)
    ok("from this computer without the code: refused", r.status_code == 403 and "setup code" in r.get_data(as_text=True))
    r = c.post("/register", data=dict(form, setup_code="AAAA-BBBB-CCCC-DDDD"))
    ok("with a wrong code: refused", r.status_code == 403)
    log = open(os.path.join(base, "data", "audit.log")).read()
    ok("wrong codes are in the audit log", log.count('"setup_code_wrong"') == 2)
    far = {"REMOTE_ADDR": "198.51.100.7"}           # another computer (behind a proxy: the real visitor)
    r = c.post("/register", data=dict(form, setup_code=code), environ_base=far)
    ok("another computer over plain HTTP: refused even with the code", r.status_code == 403 and "HTTPS" in r.get_data(as_text=True))
    ok("the code still exists after refusals", os.path.exists(sc.path))
    h = app.test_client()                          # through the reverse proxy: another address, over HTTPS
    r = h.post("/register", data=dict(form, setup_code=code), environ_base=far, base_url="https://localhost")
    ok("over HTTPS with the right code: the authenticator step", r.status_code == 200 and SECRET in r.get_data(as_text=True))
    r = h.post("/register", data={"step": "enrol", "code": auth.totp_at(SECRET, int(time.time() // 30))},
               environ_base=far, base_url="https://localhost")
    users = auth.Users(os.path.join(base, "data", "users.json")); users._load()
    u = users.data["users"].get("grace") or {}
    ok("the first account is an active administrator", u.get("role") == "admin" and u.get("status") == "active", str({k: u.get(k) for k in ("role", "status")}))
    ok("the setup code is gone", not os.path.exists(sc.path))
    page = c.get("/login").get_data(as_text=True)
    ok("the page asks for no setup code any more", 'name="setup_code"' not in page)
finally:
    shutil.rmtree(base, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
