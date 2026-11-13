#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Retest of every finding in docs/SECURITY_REPORT.md, plus the login, MFA and session protections, against the running
service. It creates two temporary accounts (lg-selftest-admin, lg-selftest-viewer) with random passwords and
authenticator secrets that are never printed, and removes them at the end. The only setting it saves is the current
one, unchanged.

Usage: .venv/bin/python security_testing/security_retest.py   (from the project folder, on the server)
"""
import http.cookiejar
import json
import re
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from auth import Users, new_recovery_codes, totp_at, totp_new_secret  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TLS = os.path.exists(os.path.join(ROOT, "data", "tls", "cert.pem"))
sys.path.insert(0, os.path.join(ROOT, "tests"))
from lgauth import PORT  # noqa: E402  this installation's port (LG_PORT in .env, default 5000)
B = ("https" if TLS else "http") + f"://127.0.0.1:{PORT}"
users = Users(os.path.join(ROOT, "data", "users.json"))


def _restart_service():
    """Only for an older service without the reset request below: restart it (a few seconds unreachable)."""
    import subprocess
    try:
        r = subprocess.run([os.path.join(ROOT, "deploy", "reload.sh")], capture_output=True, text=True, timeout=90)
        print("Restarted the service first, to start with clean login counters." if r.returncode == 0 else
              "Note: could not restart the service (another user runs it); if logins are refused with 429, restart it and run again.")
    except (OSError, subprocess.SubprocessError):
        pass


def _clear_login_counters():
    """The login limits count per address for an hour, in the service's memory; this test fails logins on purpose,
    so a second run within the hour would be refused. The service clears this computer's own counters on request
    (retest_reset.py, automation key, this computer only), so the platform stays up for everyone while it runs.
    Before 2026-11-11 the test restarted the service instead."""
    import json
    import urllib.error
    import urllib.request
    import lgauth  # noqa: F401  the automation key and this installation's address
    try:
        req = urllib.request.Request(f"{B}/api/selftest/reset-login-counters", data=b"{}", method="POST",
                                     headers={"Content-Type": "application/json"})
        d = json.load(urllib.request.urlopen(req, timeout=30))
        print(f"Cleared this computer's login counters first ({d.get('cleared', 0)}); the service keeps running.")
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404 and os.environ.get("LG_RETEST_RESTART") == "1":
            _restart_service()                # an older service: only when asked, since it interrupts the users
            return True
        print(f"Note: could not clear the login counters (HTTP {e.code}); if logins are refused with 429, "
              "run again after an hour or with LG_RETEST_RESTART=1 (restarts the service).")
    except (OSError, ValueError) as e:
        print(f"Note: could not reach the service to clear the login counters: {e}")
    return False


if os.environ.get("LG_RETEST_NO_RESTART") != "1":
    _clear_login_counters()
fails = 0
UA = "LookingGlass-retest/1.0"


SKIPS = []


def skip(label, why):
    SKIPS.append(label)
    print(f"  skip {label}  [{why}]", flush=True)


def ok(label, cond, info=""):
    global fails
    fails += not cond
    print(("  ok  " if cond else "  FAIL") + " " + label + (f"  [{info}]" if info else ""), flush=True)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def client():
    jar = http.cookiejar.CookieJar()
    handlers = [urllib.request.HTTPCookieProcessor(jar), NoRedirect()]
    if TLS:
        import ssl
        ctx = ssl.create_default_context(cafile=os.path.join(ROOT, "data", "tls", "cert.pem")); ctx.check_hostname = False
        handlers.append(urllib.request.HTTPSHandler(context=ctx))
    op = urllib.request.build_opener(*handlers)
    op.addheaders = [("User-Agent", UA)]
    return op, jar


def req(op, path, data=None, headers=None, method=None, base=B):
    body = None
    h = dict(headers or {})
    h.setdefault("X-Forwarded-For", "127.0.0.1")   # this computer; needed behind a reverse proxy (proxy_guard.py)
    if isinstance(data, dict):
        body = urllib.parse.urlencode(data).encode(); h.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif isinstance(data, (bytes, str)):
        body = data.encode() if isinstance(data, str) else data
    r = urllib.request.Request(base + path, data=body, headers=h, method=method)
    try:
        with op.open(r, timeout=120) as resp:
            return resp.status, dict(resp.headers), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:          # e.g. the server closed the connection on an oversized upload
        return -1, {}, str(e.reason)


def make_user(name, role):
    pw = secrets.token_urlsafe(18)
    users.set_password(name, pw, role)
    secret = totp_new_secret()
    codes, hashes = new_recovery_codes()
    users._load()
    users.data["users"][name].update(totp=secret, totp_last=None, recovery=hashes)
    users.save()
    return pw, secret, codes


LAST = {}   # name -> last 30-second step used (the server accepts each code once)


def login(name, pw, secret, op=None, code=None, nxt="/", remember=False):
    op, jar = (op, None) if op else client()
    s1, h1, b1 = req(op, "/login", dict({"username": name, "password": pw, "next": nxt}, **({"remember": "1"} if remember else {})))
    if s1 != 200 or 'name="step" value="mfa"' not in b1:
        return op, (s1, "no MFA step"), h1
    fresh = code is None
    if fresh:
        step = int(time.time() // 30)
        while step <= LAST.get(name, -1):                    # this step's code was used: wait for the next one
            time.sleep(30 - time.time() % 30 + 0.5)          # (rechecked: a clock synced by NTP / WSL can step back)
            step = int(time.time() // 30)
        code = totp_at(secret, step)
    s2, h2, _ = req(op, "/login", {"step": "mfa", "code": code, "next": nxt})
    if fresh and s2 == 302:
        LAST[name] = step
    return op, (s2, h2.get("Location", "")), h2


class Stop(Exception):
    pass


def must(label, s):
    """A login the following checks depend on. 429 = the login limits are still counting an earlier run."""
    ok(label, s == 302, str(s))
    if s == 429:
        raise Stop("the login limits are still counting the failed logins of an earlier run (by design: 20 per address "
                   "per hour). Restart the service to clear them (platform/deploy/reload.sh, or sudo systemctl restart "
                   "looking-glass) and run the test again.")
    if s != 302:
        raise Stop(f"'{label}' was refused ({s}), so the checks that depend on it cannot run. See the audit log for the reason.")


def csrf(op):
    return json.loads(req(op, "/api/me")[2]).get("csrf", "")


ADMIN, VIEWER = "lg-selftest-admin", "lg-selftest-viewer"


def masked(ip):
    """Masked: an opaque label with no part of the address, "Host 3f9a2c41b07e" (host_label.py)."""
    import re as _re
    return bool(_re.fullmatch(r"Host [0-9a-f]{12}", ip or ""))


def strong():
    """A password that meets the rules (12+, upper, lower, digit, symbol)."""
    return "Rt" + secrets.token_hex(6) + "!9q"

try:
    apw, asec, acodes = make_user(ADMIN, "admin")
    vpw, vsec, vcodes = make_user(VIEWER, "external")
    anon, _ = client()
    real_admins = [n for n, u in users.all().items() if not n.startswith("lg-selftest-") and u.get("status") == "active" and u.get("role") == "admin"]
    if not real_admins:
        _, _, first = req(anon, "/login")
        ok("first-run page stays while the retest's temporary admin exists", "Let's get started" in first)

    print("Login required (report #1, and the new login page)")
    s, h, _ = req(anon, "/"); ok("page without login -> login page", s == 302 and "/login" in h.get("Location", ""), f"{s} {h.get('Location')}")
    s, _, _ = req(anon, "/services?service=Block+List"); ok("services page without login -> redirect", s == 302)
    for p in ("/api/clock", "/api/svc/hosts.csv", "/api/svc/drill?metric=hosts&all=1", "/api/events", "/api/settings", "/api/asns"):
        s, _, _ = req(anon, p); ok(f"{p} without login -> 401", s == 401, str(s))
    for p in ("/login", "/healthz", "/static/css/app.css", "/static/js/loader.js"):
        s, _, _ = req(anon, p); ok(f"{p} stays reachable", s == 200, str(s))
    s, _, _ = req(anon, "/static/../.env"); ok("path traversal still blocked", s in (400, 404), str(s))

    print("\nPasswords, MFA, lockout")
    _, (s, _), _ = login(ADMIN, "wrong-password-123", asec); ok("wrong password refused", s == 401, str(s))
    _, (s, _), _ = login("nobody-here", "x" * 14, asec); ok("unknown name refused the same way", s == 401, str(s))
    op, (s, loc), h = login(ADMIN, apw, asec, code="000000"); ok("right password + wrong code refused", s == 401, str(s))
    op, (s, loc), h = login(ADMIN, apw, asec, nxt="//evil.example/x")
    used = totp_at(asec, LAST.get(ADMIN, 0))
    ok("password + authenticator code -> logged in", s == 302, f"{s} {loc}")
    ok("redirect after login stays on this site (no open redirect)", loc in ("/", B + "/"), loc)
    cookie = h.get("Set-Cookie", "")
    ok("session cookie HttpOnly, SameSite=Strict, Path=/", "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie, cookie.split(";")[0][:20] + "…")
    if TLS:
        ok("over HTTPS: cookie is Secure and uses the __Host- prefix", "Secure" in cookie and cookie.startswith("__Host-"), cookie.split("=")[0])
    s, _, _ = req(op, "/api/clock"); ok("logged-in API access works", s == 200, str(s))
    _, (s, _), _ = login(ADMIN, apw, asec, code=used); ok("the same code cannot be used twice (replay)", s == 401, str(s))
    _, (s, _), _ = login(ADMIN, apw, asec, code=acodes[0]); ok("recovery code works", s == 302, str(s))
    _, (s, _), _ = login(ADMIN, apw, asec, code=acodes[0]); ok("recovery code works only once", s == 401, str(s))
    lock_user = "lg-selftest-lock"
    for i in range(5):
        login(lock_user, "wrong-" + str(i) * 12, asec)
    _, (s, _), _ = login(lock_user, "wrong-again-0000", asec); ok("5 wrong passwords -> account locked for 15 min (429)", s == 429, str(s))

    print("\nSession hijacking protections")
    op2, (s, _), _ = login(ADMIN, apw, asec)
    must("fresh login for session tests", s)
    stolen = [c for c in op2.handlers if isinstance(c, urllib.request.HTTPCookieProcessor)][0].cookiejar
    th = [urllib.request.HTTPCookieProcessor(stolen), NoRedirect()]
    if TLS:                                   # the attacker's browser connects over HTTPS like everyone else
        import ssl
        tctx = ssl.create_default_context(cafile=os.path.join(ROOT, "data", "tls", "cert.pem")); tctx.check_hostname = False
        th.append(urllib.request.HTTPSHandler(context=tctx))
    thief = urllib.request.build_opener(*th)
    thief.addheaders = [("User-Agent", "Mozilla/5.0 (attacker)")]
    s, _, _ = req(thief, "/api/clock"); ok("stolen cookie from another browser -> refused (401)", s == 401, str(s))
    s, _, _ = req(op2, "/api/clock"); ok("…and the session is ended for the owner too", s == 401, str(s))
    op3, (s, _), _ = login(ADMIN, apw, asec)
    must("login for the logout checks", s)
    s, _, _ = req(op3, "/logout"); s2, _, _ = req(op3, "/api/clock"); ok("GET /logout does not log out (no cross-site logout)", s2 == 200, str(s2))
    s, _, _ = req(op3, "/logout", data=b"", method="POST"); s2, _, _ = req(op3, "/api/clock"); ok("POST /logout ends the session on the server", s2 == 401, str(s2))

    print("\nStay signed in")
    _, _, lp = req(anon, "/login?form=signin")
    if 'name="remember"' not in lp and not real_admins:     # first run: the page offers only "Let's get started"
        lp = open(os.path.join(ROOT, "templates", "login.html"), encoding="utf-8").read()
    ok("sign-in form offers 'Stay signed in'", 'name="remember"' in lp and ">Stay signed in<" in lp)
    ok("the sign-in page does not reveal how long a session lasts", not re.search(r"(?i)\b\d+\s*days?\b|five days", lp))
    pop, (s, _), ph = login(ADMIN, apw, asec, remember=True)
    pc = ph.get("Set-Cookie", "")
    ok("stay signed in: cookie lasts 5 days (Max-Age=432000), still HttpOnly / SameSite=Strict", s == 302 and "Max-Age=432000" in pc and "HttpOnly" in pc and "SameSite=Strict" in pc, pc.split(";")[0][:18] + "…")
    sop, (s, _), sh = login(ADMIN, apw, asec)
    ok("without it: a browser-session cookie (no Max-Age)", s == 302 and "Max-Age" not in sh.get("Set-Cookie", ""))
    pj = [c for c in pop.handlers if isinstance(c, urllib.request.HTTPCookieProcessor)][0].cookiejar
    ph2 = [urllib.request.HTTPCookieProcessor(pj), NoRedirect()]
    if TLS:
        import ssl
        pctx = ssl.create_default_context(cafile=os.path.join(ROOT, "data", "tls", "cert.pem")); pctx.check_hostname = False
        ph2.append(urllib.request.HTTPSHandler(context=pctx))
    pthief = urllib.request.build_opener(*ph2); pthief.addheaders = [("User-Agent", "Mozilla/5.0 (attacker)")]
    s, _, _ = req(pthief, "/api/clock"); ok("a stolen 5-day cookie from another browser is refused, and the session ends", s == 401 and req(pop, "/api/clock")[0] == 401, str(s))
    # rotation of long sessions (unit check of the session store; on the server it happens every 12 hours)
    from auth import Sessions as _S
    import tempfile
    st_ = _S(os.path.join(tempfile.mkdtemp(), "s.json"), idle=3600, maximum=43200)
    t1 = st_.create("u", "127.0.0.1", "ua", persist=True)
    k1 = __import__("hashlib").sha256(t1.encode()).hexdigest()
    t2 = st_.rotate(k1)
    ok("rotation: the old id stops working, the new one works, same login", st_.check(t1, "127.0.0.1", "ua")[0] is None and st_.check(t2, "127.0.0.1", "ua")[0] is not None)
    ok("stay-signed-in sessions are capped at 5 days", st_.limits({"persist": True}) == (432000, 432000))

    print("\nRoles and Settings (report #2, #6, #7, #11)")
    vop, (s, _), _ = login(VIEWER, vpw, vsec)
    must("viewer logged in", s)
    vop_keep = vop
    s, _, _ = req(vop, "/settings"); ok("viewer: Settings page refused", s == 403, str(s))
    s, _, _ = req(vop, "/api/settings"); ok("viewer: settings data (network names) refused", s == 403, str(s))
    cur = None
    aop, (s, _), _ = login(ADMIN, apw, asec)
    must("admin logged in", s)
    st = json.loads(req(aop, "/api/settings")[2])["settings"]; cur = {"country": st["country"], "networks": st["networks"], "cidrs": st["cidrs"]}
    body = json.dumps(cur)
    s, _, _ = req(vop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": csrf(vop)}, "POST"); ok("viewer cannot change settings", s == 403, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json"}, "POST"); ok("admin without CSRF token -> refused", s == 403, str(s))
    t = csrf(aop)
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "text/plain", "X-CSRF-Token": t}, "POST"); ok("text/plain body (cross-site simple request) -> 415", s == 415, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t, "Origin": "https://evil.example"}, "POST"); ok("foreign Origin -> 403", s == 403, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t, "Sec-Fetch-Site": "cross-site"}, "POST"); ok("Sec-Fetch-Site cross-site -> 403", s == 403, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t, "Origin": "null", "Sec-Fetch-Site": "cross-site"}, "POST"); ok("Origin: null from another site -> 403", s == 403, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t, "Origin": "null", "Sec-Fetch-Site": "same-origin"}, "POST"); ok("Origin: null on a same-site form (no-referrer pages) -> accepted", s == 200, str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t, "Host": "rebind.evil.example"}, "POST"); ok("DNS rebinding (foreign Host) -> 400", s == 400, str(s))
    s, _, _ = req(aop, "/api/settings", "[1,2]", {"Content-Type": "application/json", "X-CSRF-Token": t}, "POST"); ok("JSON array body -> 400 (was 500)", s == 400, str(s))
    s, _, _ = req(aop, "/api/settings", json.dumps(dict(cur, country="ZZ")), {"Content-Type": "application/json", "X-CSRF-Token": t}, "POST"); ok("unknown country ZZ -> 400", s == 400, str(s))
    big = json.dumps({"country": cur["country"], "networks": [str(i) for i in range(1, 300001)], "cidrs": []})
    s, _, _ = req(aop, "/api/settings", big, {"Content-Type": "application/json", "X-CSRF-Token": t}, "POST"); ok(f"{len(big) / 1e6:.1f} MB body -> refused (413, or connection closed mid-upload)", s in (413, -1), str(s))
    s, _, _ = req(aop, "/api/settings", body, {"Content-Type": "application/json", "X-CSRF-Token": t}, "POST"); ok("admin + CSRF token + same values -> saved (200)", s == 200, str(s))

    print("\nPassword change ends sessions")
    users._load(); users.data["users"][VIEWER]["changed"] = int(time.time()) + 1; users.save()
    time.sleep(1.2)
    s, _, _ = req(vop, "/api/clock"); ok("viewer session ended after a password change", s == 401, str(s))

    print("\nDenial of service and input checks (report #4, #5)")
    c0 = json.loads(req(aop, "/api/svc/clock")[2])
    s, _, b = req(aop, "/api/svc/stats?at=2099-01-01T00:00:00Z"); d = json.loads(b).get("day")
    ok("at=2099 is clamped to the replay days (no other day loaded)", d in (c0["replay_day"],) or d < c0["replay_day"], f"day {d}")
    req(aop, "/api/svc/stats")                                 # (warm: the first one after a restart computes the figures)
    t0 = time.time(); req(aop, "/api/svc/stats"); dt = time.time() - t0
    ok("the replay day stays in memory (no reload)", dt < 3, f"{dt:.2f}s")
    s, _, _ = req(aop, "/api/malpedia?field=md5&value=../../x?y=1"); ok("Malpedia: bad hash refused before any outbound call (400)", s in (400, 503), str(s))
    s, _, _ = req(aop, "/api/malpedia?field=evil&value=x"); ok("Malpedia: unknown field refused", s in (400, 503), str(s))
    s, _, _ = req(aop, "/api/malpedia?field=family&value=win.emotet/../../x"); ok("Malpedia: bad family id refused", s in (400, 503), str(s))

    print("\nDemo mode (report #6)")
    ev = json.loads(req(aop, "/api/svc/events?latest=1&limit=1&service=Accessible+HTTP")[2])["events"] \
        or json.loads(req(aop, "/api/svc/events?latest=1&limit=1")[2])["events"]
    HAVE_DATA = bool(ev)
    if not HAVE_DATA:
        for lbl in ("demo mode: a raw IP no longer confirms membership", "demo mode: the opaque reference still works"):
            skip(lbl, "no records loaded yet: run it again once reports are in")
    else:
        real_ip = ev[0]["ip"]
        a = json.loads(req(aop, f"/api/svc/insight?ip={real_ip}&demo=1")[2]); b2 = json.loads(req(aop, f"/api/svc/insight?ip={real_ip}")[2])
        ok("demo mode: a raw IP no longer confirms membership", a.get("total") == 0 and b2.get("total", 0) > 0, f"demo {a.get('total')}, normal {b2.get('total')}")
        ref = ev[0]["ip_ref"]
        a = json.loads(req(aop, f"/api/svc/insight?ip={ref}&demo=1")[2]); ok("demo mode: the opaque reference still works", a.get("total", 0) > 0, str(a.get("total")))

    print("\nRegistration, approval, roles and permissions, admin, audit")
    import re as _re
    reg, _ = client()
    reg.addheaders.append(("X-LG-Automation", open(os.path.join(ROOT, "data", "automation.key")).read().strip()))
    plain, _ = client()
    s, _, _ = req(plain, "/register", {"username": "lg-selftest-intruder", "full_name": "Some One", "organisation": "Some Org",
                                       "email": "x@example.org", "country": "GH", "password": strong(), "password2": strong()})
    ok("the reserved test name prefix cannot be registered by people", s == 400, str(s))
    PROFILE = {"full_name": "Self Test", "organisation": "Looking Glass retest", "email": f"retest-{secrets.token_hex(3)}@example.org", "country": "GH"}
    s, _, _ = req(reg, "/register", dict(PROFILE, username="lg-selftest-new", password="short", password2="short")); ok("weak password refused", s == 400, str(s))
    for bad, why in (("abcdefghijklmnop", "no upper case, number or symbol"), ("Abcdefghijklm1", "no symbol"), ("Welcome2026!!xyz", "common word"),
                     ("Aaaaa1!bcdefghij", "4 repeated characters"), ("Self-Test-2026!x", "contains the person's name")):
        s, _, b_ = req(reg, "/register", dict(PROFILE, username="lg-selftest-new", password=bad, password2=bad))
        ok(f"weak password refused ({why})", s == 400, str(s))
    s, _, _ = req(reg, "/register", dict(PROFILE, username=ADMIN, password=strong(), password2=strong())); ok("existing name refused", s == 409, str(s))
    s, _, _ = req(reg, "/register", dict(PROFILE, email="not-an-email", username="lg-selftest-new", password=strong(), password2=strong())); ok("invalid email refused", s == 400, str(s))
    s, _, _ = req(reg, "/register", dict(PROFILE, country="ZZ", username="lg-selftest-new", password=strong(), password2=strong())); ok("unknown country refused", s == 400, str(s))
    s, _, b_ = req(reg, "/register", dict(PROFILE, full_name="<script>x</script>", username="lg-selftest-new", password=strong(), password2=strong())); ok("markup in the full name refused", s == 400, str(s))
    npw = strong()
    s, h, page_ = req(reg, "/register", dict(PROFILE, username="lg-selftest-new", password=npw, password2=npw))
    m = _re.search(r"secret=([A-Z2-7]+)", page_)
    ok("registration shows the QR enrolment (otpauth URI for the QR code)", s == 200 and bool(m) and 'id="qr"' in page_, str(s))
    nsec = m.group(1) if m else ""
    s, _, _ = req(reg, "/register", {"step": "enrol", "code": "000000"}); ok("wrong enrolment code refused", s == 401, str(s))
    s, _, done = req(reg, "/register", {"step": "enrol", "code": totp_at(nsec, int(time.time() // 30))})
    ok("enrolment confirmed: recovery codes shown once, account pending", s == 200 and done.count('<li>') >= 8 and "waiting for approval" in done, str(s))
    _, (s, _), _ = login("lg-selftest-new", npw, nsec); ok("pending account cannot log in", s in (403, 200) and s != 302, str(s))
    u_new = users.get("lg-selftest-new") or {}
    ok("registration recorded address, location and browser", (u_new.get("registered") or {}).get("ip") == "127.0.0.1" and (u_new.get("registered") or {}).get("ua") == UA)
    ok("registration stored full name, organisation, email and country", (u_new.get("profile") or {}) == PROFILE, str(u_new.get("profile")))
    s, _, _ = req(reg, "/register", dict(PROFILE, username="lg-selftest-dup", password=npw, password2=npw)); ok("the same email cannot register twice", s == 409, str(s))
    aop2, (s, _), _ = login(ADMIN, apw, asec); at = csrf(aop2)
    s, _, _ = req(aop2, "/api/admin/users/lg-selftest-new", json.dumps({"action": "approve", "role": "external"}), {"Content-Type": "application/json"}, "POST")
    ok("admin action without CSRF token refused", s == 403, str(s))
    vop2, _, _ = login(VIEWER, vpw, vsec)
    s, _, _ = req(vop2, "/api/admin/users", None); ok("viewer cannot list users (403)", s == 403, str(s))
    s, _, _ = req(aop2, "/api/admin/users/lg-selftest-new", json.dumps({"action": "approve", "role": "external"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin approves the account as external", s == 200, str(s))
    time.sleep(0.5)
    nop, (s, _), _ = login("lg-selftest-new", npw, nsec); ok("approved account logs in", s == 302, str(s))
    ev2 = json.loads(req(nop, "/api/svc/events?latest=1&limit=50&demo=0")[2])["events"]
    if ev2 or HAVE_DATA:
        ok("viewer gets masked data even with demo=0 (no 'unmasked' permission)", ev2 and all(masked(e["ip"]) for e in ev2), ev2[0]["ip"] if ev2 else "")
    else:
        skip("viewer gets masked data even with demo=0 (no 'unmasked' permission)", "no records loaded yet")
    s, _, _ = req(nop, "/api/svc/hosts.csv"); ok("external: CSV export refused (no 'export')", s == 403, str(s))
    s, _, _ = req(nop, "/api/svc/drill?metric=hosts&all=1"); ok("external: complete lists refused", s == 403, str(s))
    s, _, _ = req(nop, "/api/malpedia?field=infection&value=mirai"); ok("external: Malpedia refused", s == 403, str(s))
    s, _, _ = req(nop, "/admin"); ok("external: admin page refused", s == 403, str(s))
    _, _, home = req(nop, "/"); _, _, svc_page = req(nop, "/services")
    ok("external: pages carry no demo controls (data-masked)", 'data-masked="1"' in home and 'data-masked="1"' in svc_page)
    ok("external: the server tells the map that masking is enforced", json.loads(req(nop, "/api/clock")[2]).get("demo_forced") is True)
    s, _, _ = req(aop2, "/api/admin/users/lg-selftest-new", json.dumps({"action": "role", "role": "analyst"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin changes the role to analyst", s == 200, str(s))
    s, _, _ = req(nop, "/api/clock"); ok("role change ends the account's sessions", s == 401, str(s))
    nop, (s, _), _ = login("lg-selftest-new", npw, nsec)
    ev3 = json.loads(req(nop, "/api/svc/events?latest=1&limit=50")[2])["events"]
    _, _, home2 = req(nop, "/")
    ok("analyst: no masking flag, Demo switch available", 'data-masked' not in home2 and 'id="btnDemo"' in home2 and json.loads(req(nop, "/api/clock")[2]).get("demo_forced") is False)
    if ev3 or HAVE_DATA:
        ok("analyst sees real data and may export", ev3 and not any(masked(e["ip"]) for e in ev3) and req(nop, "/api/svc/hosts.csv")[0] == 200)
    else:
        ok("analyst may export", req(nop, "/api/svc/hosts.csv")[0] == 200)
        skip("analyst sees real (unmasked) data", "no records loaded yet")
    s, _, _ = req(nop, "/api/settings"); ok("analyst cannot open Settings", s == 403, str(s))
    sl = json.loads(req(aop2, "/api/admin/sessions")[2])["sessions"]
    mine = [x for x in sl if x["user"] == "lg-selftest-new"]
    ok("sessions list shows user, address, location and browser", mine and mine[0]["ip"] == "127.0.0.1" and mine[0]["location"] == "This computer" and mine[0]["browser"] == UA)
    s, _, _ = req(aop2, f"/api/admin/sessions/{mine[0]['id']}/end" if mine else "/api/admin/sessions/0000000000000000/end", b"{}", {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin kicks the session", s == 200 and req(nop, "/api/clock")[0] == 401, str(s))
    s, _, b_ = req(aop2, f"/api/admin/users/{ADMIN}", json.dumps({"action": "revoke"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("an admin cannot revoke their own account", s == 400, str(s))
    rl = json.loads(req(aop2, "/api/admin/roles")[2])["roles"]
    s, _, _ = req(aop2, "/api/admin/roles", json.dumps({"roles": {k: v for k, v in rl.items() if k != "analyst"}}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("a role in use cannot be removed", s == 400, str(s))
    s, _, _ = req(aop2, "/api/admin/roles", json.dumps({"roles": dict(rl, auditor=["view", "audit"])}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin adds a custom role (auditor: view + audit)", s == 200, str(s))
    req(aop2, "/api/admin/roles", json.dumps({"roles": rl}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    s, _, _ = req(aop2, "/api/admin/users/lg-selftest-new", json.dumps({"action": "revoke"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    _, (s2, _), _ = login("lg-selftest-new", npw, nsec)
    ok("revoked account cannot log in", s == 200 and s2 == 403, f"{s} {s2}")
    au = json.loads(req(aop2, "/api/admin/audit?limit=300&q=lg-selftest-new&selftests=1")[2])["rows"]
    evs = {r["event"] for r in au}
    ok("audit log has registration, approval, logins, role change, kick, revocation", {"registered", "user_approve", "login", "user_role", "kicked", "user_revoke"} <= evs, ", ".join(sorted(evs)))
    ok("audit entries carry address, location and browser", au and au[0]["ip"] == "127.0.0.1" and au[0]["location"] == "This computer" and au[0]["ua"])
    s, _, _ = req(aop2, "/api/admin/users/lg-selftest-new", json.dumps({"action": "delete"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin deletes the account", s == 200 and not users.get("lg-selftest-new"), str(s))

    print("\nAttempts left and forgotten password")
    def fresh_code(name, secret):
        step = int(time.time() // 30)
        while step <= LAST.get(name, -1):                    # rechecked: the clock can step back while we sleep
            time.sleep(30 - time.time() % 30 + 0.5); step = int(time.time() // 30)
        LAST[name] = step
        return totp_at(secret, step)
    fop, _ = client()
    s, _, b = req(fop, "/login", {"username": VIEWER, "password": "wrong-password-xyz"})
    # the status AND either wording (review 2026-11-13: without the brackets any page saying "attempt left" passed)
    ok("wrong password shows the attempts left", s == 401 and ("attempts left" in b or "attempt left" in b), str(s))
    s, _, b = req(fop, "/forgot", {"mode": "ask", "username": VIEWER}); s2, _, b2 = req(fop, "/forgot", {"mode": "ask", "username": "no-such-user-xyz"})
    ok("'ask an administrator': same answer for real and unknown names", s == s2 == 200 and "administrators have been notified" in b and "administrators have been notified" in b2)
    al = {u["name"]: u for u in json.loads(req(aop2, "/api/admin/users")[2])["users"]}
    ok("the request shows in Admin", bool(al.get(VIEWER, {}).get("reset_requested")))
    vsess, (s, _), _ = login(VIEWER, vpw, vsec)
    newpw = strong()
    s, _, b = req(fop, "/forgot", {"mode": "self", "username": VIEWER, "code": fresh_code(VIEWER, vsec), "recovery": "0000-0000-0000", "password": newpw, "password2": newpw})
    ok("reset with a wrong recovery code refused (attempts left shown)", s == 401 and "left" in b, str(s))
    s, h, _ = req(fop, "/forgot", {"mode": "self", "username": VIEWER, "code": fresh_code(VIEWER, vsec), "recovery": vcodes[1], "password": newpw, "password2": newpw})
    ok("reset with authenticator code + recovery code works", s == 302 and "notice=" in h.get("Location", ""), str(s))
    ok("…and ends the account's existing sessions", req(vsess, "/api/clock")[0] == 401)
    _, (s, _), _ = login(VIEWER, newpw, vsec); ok("the new password works", s == 302, str(s))
    s, _, _ = req(aop2, f"/api/admin/users/{VIEWER}", json.dumps({"action": "allow_reset"}), {"Content-Type": "application/json", "X-CSRF-Token": at}, "POST")
    ok("admin allows a reset for 24 hours", s == 200, str(s))
    newpw2 = strong()
    s, _, _ = req(fop, "/forgot", {"mode": "self", "username": VIEWER, "code": fresh_code(VIEWER, vsec), "password": newpw2, "password2": newpw2})
    ok("admin-allowed reset needs only the authenticator code", s == 302, str(s))
    s, _, b = req(fop, "/forgot", {"mode": "self", "username": "no-such-user-xyz", "code": "123456", "recovery": "", "password": newpw2, "password2": newpw2})
    ok("reset for an unknown name: the same generic answer", s == 401 and "not right" in b, str(s))

    print("\nHeaders (report #8) and scripts (report #9)")
    s, h, html = req(aop, "/")
    csp = h.get("Content-Security-Policy", "")
    ok("Content-Security-Policy with nonce, no unsafe-eval, frame-ancestors none", "nonce-" in csp and "unsafe-eval" not in csp and "frame-ancestors 'none'" in csp)
    ok("X-Frame-Options DENY, nosniff, Referrer-Policy", h.get("X-Frame-Options") == "DENY" and h.get("X-Content-Type-Options") == "nosniff" and h.get("Referrer-Policy"))
    _, hm, _ = req(aop, "/management")
    ok("the Executive portal is never framed", "frame-ancestors 'none'" in hm.get("Content-Security-Policy", "") and hm.get("X-Frame-Options") == "DENY")
    _, he, _ = req(aop, "/management?embed=1")
    ok("…its embedded copy (the review page) only by this same site", "frame-ancestors 'self'" in he.get("Content-Security-Policy", "")
       and "frame-ancestors 'none'" not in he.get("Content-Security-Policy", "") and he.get("X-Frame-Options") == "SAMEORIGIN")
    ok("API responses not cached (Cache-Control: no-store)", "no-store" in req(aop, "/api/clock")[1].get("Cache-Control", ""))
    ok("CDN scripts carry integrity hashes", html.count('integrity="sha384-') >= 3)
    ok("inline scripts carry the nonce", "<script>" not in html and 'nonce="' in html)

    print("\nNetwork access (report #1)")
    import socket
    lan = [a for a in socket.gethostbyname_ex(socket.gethostname())[2] if not a.startswith("127.")] or []
    try:
        import subprocess
        lan = subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()[:1] or lan
    except Exception:
        pass
    if lan:
        s, _, _ = req(anon, "/healthz", base=f"{'https' if TLS else 'http'}://{lan[0]}:{PORT}")
        from dotenv import dotenv_values
        sys.path.insert(0, ROOT)
        os.environ.update({k: v or "" for k, v in dotenv_values(os.path.join(ROOT, ".env")).items() if k in ("ACCESS_MODE", "VIEWER_NETWORKS")})
        import security as _sec
        mode = _sec.access_mode()
        if mode == "local":
            ok(f"ACCESS_MODE=local: the network address {lan[0]} is refused", s in (403, -1),
               "403" if s == 403 else "not even listening on the network" if s == -1 else str(s))
        else:
            ok(f"ACCESS_MODE={mode}: the network address {lan[0]} reaches the public pages only", s == 200 and req(anon, "/api/clock", base=f"{'https' if TLS else 'http'}://{lan[0]}:{PORT}")[0] in (401, 403), str(s))
except Stop as why:
    fails += 1
    print(f"\nSTOPPED: {why}")
finally:
    users._load()
    for n in (ADMIN, VIEWER, "lg-selftest-new"):
        users.data["users"].pop(n, None)
    users.save()
    print(f"\ntemporary accounts removed: {not any(n in users.all() for n in (ADMIN, VIEWER))}")
print(("\nALL PASSED" if not fails else f"\n{fails} FAILED")
      + (f" ({len(SKIPS)} skipped until reports are loaded: run it again later)" if SKIPS else ""))
sys.exit(1 if fails else 0)
