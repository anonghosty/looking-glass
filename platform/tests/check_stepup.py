#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The fresh check before high-value actions, and passkeys (stepup.py, passkeys.py; the user 2026-11-24), in-process.

- every high-value rule matches a real route, and the high-value routes the user named are all covered
- internal installation: a high-value request without a check is refused with {"stepup": "code"}; a wrong code, a
  reused code and a request without the form token are refused; a right code opens a 10-minute window; after it, asked
  again
- the most dangerous actions ask every time: a one-time grant for that request only (not twice, not another path,
  not another session)
- public installation: {"stepup": "passkey"}, codes refused; a person with fewer than 2 passkeys is held on the passkey
  page after signing in; registering real passkeys (a software authenticator: ES256, attestation "none") opens the
  account; a passkey check opens the window; a wrong origin, a replayed challenge, another person's passkey are refused
- signing in on a public installation: name and password, then the passkey (no authenticator code)
- removing a passkey never goes below 2 on a public installation; an administrator's reset needs a fresh check every
  time, ends the person's sessions, and cannot be done on oneself
- external accounts reach their own passkey page and nothing more
- the bell: sign-ins from public addresses on an internal installation
Nothing is written outside a temporary folder; no database, no network.
Run: .venv/bin/python tests/check_stepup.py"""
import base64
import hashlib
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.pop("LG_STEPUP_TESTS_OFF", None)            # this check tests the gate itself
os.environ["ACCESS_MODE"] = "local"
os.environ.pop("VIEWER_NETWORKS", None)

import cbor2  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

import app as A  # noqa: E402
import auth  # noqa: E402
import passkeys  # noqa: E402
import stepup  # noqa: E402
import system_alerts  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info != "" and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-stepup-")
# the pages that ship next: the held templates (<name>.html.new in LG_HELD_DIR) over the installed ones
HELD = os.environ.get("LG_HELD_DIR", "")
if HELD and os.path.isdir(HELD):
    import glob
    import shutil

    import jinja2
    tdir = os.path.join(tmp, "templates")
    shutil.copytree(os.path.join(os.path.dirname(A.__file__), "templates"), tdir)
    for f in glob.glob(os.path.join(HELD, "*.html.new")):
        shutil.copy(f, os.path.join(tdir, os.path.basename(f)[:-4]))
    A.app.jinja_env.loader = jinja2.FileSystemLoader(tdir)
AU = A.AUTH
users, sessions, throttle, audit = AU["users"], AU["sessions"], AU["throttle"], AU["audit"]
AUDIT = []
audit.add = lambda ev, **k: AUDIT.append((ev, k))
sessions.path, throttle.path = os.path.join(tmp, "sessions.json"), os.path.join(tmp, "login_counters.json")
AU["setup"].path = os.path.join(tmp, "setup_code")
sessions.s.clear()
throttle.fail.clear()
ST = A.FEATURES["stepup"]
store = ST["store"]
store.path = os.path.join(tmp, "passkeys.json")
PW = "Steady-Harbour-Lantern-63!"
H = generate_password_hash(PW)
SECRET = {n: base64.b32encode(os.urandom(20)).decode().rstrip("=") for n in ("lgsu-admin", "lgsu-analyst", "lgsu-ext", "lgsu-other")}
ROLE = {"lgsu-admin": "admin", "lgsu-analyst": "analyst", "lgsu-ext": "external", "lgsu-other": "analyst"}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": {n: {"hash": H, "role": ROLE[n], "status": "active", "totp": SECRET[n], "changed": 0, "created": 1,
                             "pw_set_at": int(time.time()), "profile": {"full_name": n}} for n in SECRET}}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-stepup"
STEP = {n: int(time.time() // 30) - 1 for n in SECRET}   # the next authenticator step each person may use (c-1, c, c+1)


def code(name):
    """A fresh authenticator code. Only the steps around now are accepted, each once: when they are used up, the
    account's 'last used' is cleared in the temporary store (this check runs many confirmations within 30 seconds)."""
    now_c = int(time.time() // 30)
    if STEP[name] > now_c + 1:
        with users.lock:
            users._load()
            users.data["users"][name]["totp_last"] = None
            users.save()
        STEP[name] = now_c - 1
    # the clock may have moved into the next 30-second step meanwhile: never a step older than the oldest accepted
    s = STEP[name] = max(STEP[name], now_c - 1)
    STEP[name] += 1
    return auth.totp_at(SECRET[name], s)


def client(name):
    tok = sessions.create(name, "127.0.0.1", UA)
    c = A.app.test_client()
    c.set_cookie("lg_session", tok)
    return c, sessions.s[auth._h(tok)]["csrf"], auth._h(tok)


def call(c, csrf, method, path, body=None, headers=None):
    h = {"User-Agent": UA, "X-CSRF-Token": csrf, **(headers or {})}
    return c.open(path, method=method, json=body if method != "GET" else None, headers=h)


def asked(r):
    j = r.get_json(silent=True) or {}
    return r.status_code == 403 and bool(j.get("stepup")), j


# ---------------- 1. the rules
print("== the rules cover the high-value routes")
routes = {(m, r.rule) for r in A.app.url_map.iter_rules() for m in r.methods - {"HEAD", "OPTIONS"}}


def sample(rule):
    """A path the route answers: every <part> replaced by x."""
    import re
    return re.sub(r"<[^>]+>", "x", rule)


for methods, rx, test, kind, every in stepup._RULES:
    if kind == "connector" or test is not None:
        continue                       # the connectors arrive later in this release; the conditional rules are below
    hit = [rule for m, rule in routes if m in methods and rx.match(sample(rule))]
    ok(f"rule {kind} {rx.pattern} matches a real route", bool(hit), rx.pattern)
NAMED = [("GET", "/api/svc/hosts.csv", "export"), ("GET", "/api/combos/search/x/download", "export"),
         ("GET", "/api/intelligence/export.csv", "export"), ("GET", "/api/advisory/x/export", "export"),
         ("POST", "/api/audit/trace", "trace"), ("POST", "/api/admin/users/x", "accounts"), ("POST", "/api/admin/roles", "accounts"),
         ("POST", "/api/admin/invites", "accounts"), ("POST", "/api/admin/invites/x/revoke", "accounts"),
         ("POST", "/api/settings", "settings"), ("POST", "/api/admin/config", "settings"), ("POST", "/api/admin/quarterly/purge", "purge"),
         ("POST", "/api/advisory/x/generate", "advisory"), ("POST", "/api/advisory/x/send", "advisory"),
         ("POST", "/api/admin/users/x/passkeys/reset", "accounts"), ("POST", "/api/passkeys/x/remove", "passkeys")]
for m, p, kind in NAMED:
    with A.app.test_request_context(p, method=m):
        ok(f"{m} {p} is high-value ({kind})", (stepup.rule_for(m, p) or ("",))[0] == kind, stepup.rule_for(m, p))
with A.app.test_request_context("/api/intelligence?reveal=1"):
    ok("showing leaked accounts unmasked (reveal=1) is high-value", stepup.rule_for("GET", "/api/intelligence") == ("reveal", False))
with A.app.test_request_context("/api/intelligence"):
    ok("…the masked view is not", stepup.rule_for("GET", "/api/intelligence") is None)
with A.app.test_request_context("/api/svc/events?all=1"):
    ok("a complete list (all=1) is high-value", stepup.rule_for("GET", "/api/svc/events") == ("export", False))
with A.app.test_request_context("/api/svc/stats"):
    ok("ordinary viewing never asks", stepup.rule_for("GET", "/api/svc/stats") is None)
every = {k for _, _, _, k, e in stepup.RULES if e}
ok("every time: accounts, roles, sign-up links, connectors, passkeys", every == {"accounts", "connector", "passkeys"}, every)

# ---------------- 2. internal installation: authenticator codes
print("== internal installation (ACCESS_MODE=local): authenticator codes")
an, an_csrf, an_key = client("lgsu-analyst")
r = call(an, an_csrf, "GET", "/api/svc/hosts.csv")
a, j = asked(r)
ok("a complete list without a check: refused, asking for a code", a and j.get("stepup") == "code" and not j.get("every_time"), (r.status_code, j))
ok("…in plain words, naming the action", "download a complete or unmasked list" in (j.get("error") or ""), j.get("error"))
ok("…and audited", any(e == "stepup_asked" for e, _ in AUDIT))
r = call(an, "", "POST", "/api/stepup/code", {"code": code("lgsu-analyst")})
ok("a code without the form token: refused", r.status_code == 403, r.status_code)
r = call(an, an_csrf, "POST", "/api/stepup/code", {"code": "000000"})
ok("a wrong code: refused and audited", r.status_code == 401 and any(e == "stepup_failed" for e, _ in AUDIT), r.status_code)
good = code("lgsu-analyst")
r = call(an, an_csrf, "POST", "/api/stepup/code", {"code": good, "method": "GET", "path": "/api/svc/hosts.csv"})
ok("the right code: accepted (10 minutes)", r.status_code == 200 and (r.get_json() or {}).get("window") == stepup.WINDOW, r.get_json())
r = call(an, an_csrf, "POST", "/api/stepup/code", {"code": good})
ok("…the same code a second time: refused (each code works once)", r.status_code == 401, r.status_code)
r = call(an, an_csrf, "GET", "/api/svc/hosts.csv")
ok("within the window: the list is no longer refused for the check", not asked(r)[0], (r.status_code, (r.get_json(silent=True) or {}).get("error")))
with sessions.lock:
    sessions.s[an_key]["stepup_at"] = time.time() - stepup.WINDOW - 5
r = call(an, an_csrf, "GET", "/api/svc/hosts.csv")
ok("after 10 minutes: asked again", asked(r)[0], r.status_code)
st = call(an, an_csrf, "GET", "/api/stepup/status").get_json() or {}
ok("the status: a code, no window left", st.get("how") == "code" and st.get("window_left") == 0, st)

# ---------------- 3. every time
print("== the most dangerous actions ask every time")
ad, ad_csrf, ad_key = client("lgsu-admin")
r = call(ad, ad_csrf, "POST", "/api/admin/roles", {})
a, j = asked(r)
ok("changing roles: asked, every time", a and j.get("every_time") is True and j.get("kind") == "accounts", j)
g = call(ad, ad_csrf, "POST", "/api/stepup/code", {"code": code("lgsu-admin"), "method": "POST", "path": "/api/admin/roles"}).get_json() or {}
ok("the check gives a one-time grant for that request", bool(g.get("grant")), g)
r = call(ad, ad_csrf, "POST", "/api/admin/roles", {}, {"X-LG-Stepup": g.get("grant", "")})
ok("…the request with the grant passes the check", not asked(r)[0], (r.status_code, r.get_json(silent=True)))
r = call(ad, ad_csrf, "POST", "/api/admin/roles", {}, {"X-LG-Stepup": g.get("grant", "")})
ok("…the same grant again: asked again (used once)", asked(r)[0], r.status_code)
r = call(ad, ad_csrf, "POST", "/api/admin/roles", {})
ok("…the 10-minute window does not cover an every-time action", asked(r)[0], r.status_code)
g2 = call(ad, ad_csrf, "POST", "/api/stepup/code", {"code": code("lgsu-admin"), "method": "POST", "path": "/api/admin/roles"}).get_json() or {}
r = call(ad, ad_csrf, "POST", "/api/admin/invites", {}, {"X-LG-Stepup": g2.get("grant", "")})
ok("a grant for one path does not open another", asked(r)[0], r.status_code)
r = call(an, an_csrf, "POST", "/api/admin/roles", {}, {"X-LG-Stepup": g2.get("grant", "")})
ok("…nor another person's session", asked(r)[0] or r.status_code == 403, r.status_code)

# ---------------- 4. public installation: passkeys
print("== public installation (ACCESS_MODE=public): passkeys")
os.environ["ACCESS_MODE"] = "public"
ORIGIN, RP = "http://localhost", "localhost"


class Authenticator:
    """A software passkey: an ES256 key, attestation "none", user present and verified."""

    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cid = os.urandom(16)
        self.count = 0

    @staticmethod
    def b64(b):
        return base64.urlsafe_b64encode(b).decode().rstrip("=")

    def _client(self, typ, challenge, origin):
        return json.dumps({"type": typ, "challenge": challenge, "origin": origin, "crossOrigin": False}).encode()

    def create(self, opts, origin=ORIGIN):
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        ad = hashlib.sha256(opts["rp"]["id"].encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big") \
            + bytes(16) + len(self.cid).to_bytes(2, "big") + self.cid + cose
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": self.b64(self.cid), "rawId": self.b64(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": self.b64(self._client("webauthn.create", opts["challenge"], origin)),
                             "attestationObject": self.b64(att), "transports": ["internal"]}}

    def get(self, opts, origin=ORIGIN):
        self.count += 1
        ad = hashlib.sha256(opts["rpId"].encode()).digest() + bytes([0x05]) + self.count.to_bytes(4, "big")
        cd = self._client("webauthn.get", opts["challenge"], origin)
        sig = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": self.b64(self.cid), "rawId": self.b64(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": self.b64(cd), "authenticatorData": self.b64(ad), "signature": self.b64(sig),
                             "userHandle": None}}


assert serialization  # the module is used for the key type above only
# a person with no passkey, signing in on a public installation: held on the passkey page
ps, ps_csrf, ps_key = client("lgsu-other")
with sessions.lock:
    sessions.s[ps_key]["needs_passkeys"] = True
r = ps.get("/overview", headers={"User-Agent": UA})
ok("fewer than 2 passkeys: every page leads to the passkey page", r.status_code in (302, 303) and "/account?enrol=1" in r.headers.get("Location", ""),
   (r.status_code, r.headers.get("Location")))
r = call(ps, ps_csrf, "GET", "/api/svc/stats")
ok("…and every other call is refused, saying why", r.status_code == 403 and (r.get_json() or {}).get("passkeys_needed"), r.status_code)
r = ps.get("/account", headers={"User-Agent": UA})
ok("…the passkey page itself opens", r.status_code == 200 and b"Passkeys" in r.data, r.status_code)
keys = [Authenticator(), Authenticator()]
for i, k in enumerate(keys):
    o = call(ps, ps_csrf, "POST", "/api/passkeys/options", {}).get_json() or {}
    r = call(ps, ps_csrf, "POST", "/api/passkeys", {"credential": k.create(o), "name": f"Device {i + 1}"})
    ok(f"registering passkey {i + 1} (no fresh check while enrolling)", r.status_code == 200, (r.status_code, r.get_json(silent=True)))
ok("two passkeys kept: only their public keys", store.count("lgsu-other") == 2 and all("pk" in c and len(c["pk"]) > 40 for c in store.of("lgsu-other")))
r = ps.get("/overview", headers={"User-Agent": UA})
ok("…the account is open now (the Overview, not the passkey page)", r.status_code in (200, 302, 303) and "/account" not in r.headers.get("Location", ""),
   (r.status_code, r.headers.get("Location")))
r = call(ps, ps_csrf, "GET", "/api/svc/hosts.csv")
a, j = asked(r)
ok("a high-value request asks for the passkey", a and j.get("stepup") == "passkey", j)
r = call(ps, ps_csrf, "POST", "/api/stepup/code", {"code": code("lgsu-other")})
ok("…an authenticator code is refused on a public installation", r.status_code == 400, r.status_code)
o = call(ps, ps_csrf, "POST", "/api/stepup/passkey/options", {}).get_json() or {}
r = call(ps, ps_csrf, "POST", "/api/stepup/passkey", {"credential": keys[0].get(o, origin="https://look-alike.example"),
                                                       "method": "GET", "path": "/api/svc/hosts.csv"})
ok("a passkey answer for another site (a look-alike's origin): refused", r.status_code == 401, (r.status_code, r.get_json(silent=True)))
o = call(ps, ps_csrf, "POST", "/api/stepup/passkey/options", {}).get_json() or {}
answer = keys[0].get(o)
r = call(ps, ps_csrf, "POST", "/api/stepup/passkey", {"credential": answer, "method": "GET", "path": "/api/svc/hosts.csv"})
ok("the person's own passkey: accepted", r.status_code == 200, (r.status_code, r.get_json(silent=True)))
r = call(ps, ps_csrf, "POST", "/api/stepup/passkey", {"credential": answer})
ok("…the same answer again (a replayed challenge): refused", r.status_code == 401, r.status_code)
r = call(ps, ps_csrf, "GET", "/api/svc/hosts.csv")
ok("…and the window is open", not asked(r)[0], r.status_code)
# another person's passkey
o2 = call(an, an_csrf, "POST", "/api/stepup/passkey/options", {})
ok("someone with no passkey cannot ask for a passkey check", o2.status_code == 400, o2.status_code)
# removing: never below two; every time
lst = (call(ps, ps_csrf, "GET", "/api/passkeys").get_json() or {}).get("passkeys") or []
r = call(ps, ps_csrf, "POST", f"/api/passkeys/{lst[0]['id']}/remove", {})
a, j = asked(r)
ok("removing a passkey asks every time", a and j.get("every_time"), j)
o = call(ps, ps_csrf, "POST", "/api/stepup/passkey/options", {}).get_json() or {}
g = call(ps, ps_csrf, "POST", "/api/stepup/passkey", {"credential": keys[1].get(o), "method": "POST",
                                                       "path": f"/api/passkeys/{lst[0]['id']}/remove"}).get_json() or {}
r = call(ps, ps_csrf, "POST", f"/api/passkeys/{lst[0]['id']}/remove", {}, {"X-LG-Stepup": g.get("grant", "")})
ok("…and never leaves fewer than 2 on a public installation", r.status_code == 400 and store.count("lgsu-other") == 2, (r.status_code, r.get_json(silent=True)))
# signing in with a passkey
print("== signing in on a public installation: password, then passkey")
c = A.app.test_client()
r = c.post("/login", data={"username": "lgsu-other", "password": PW}, headers={"User-Agent": UA})
ok("name and password: the passkey step (no authenticator code)", r.status_code == 200 and b'data-v="passkey"' in r.data and b'data-v="mfa"' not in r.data, r.status_code)
o = c.post("/login/passkey-options", headers={"User-Agent": UA}).get_json() or {}
ok("…the step's challenge", bool(o.get("challenge")) and o.get("rpId") == RP, o)
r = c.post("/login", data={"step": "passkey", "credential": json.dumps(keys[1].get(o))}, headers={"User-Agent": UA})
ok("…the passkey signs the person in", r.status_code in (302, 303) and "/welcome" in r.headers.get("Location", ""), (r.status_code, r.headers.get("Location")))
c2 = A.app.test_client()
c2.post("/login", data={"username": "lgsu-other", "password": PW}, headers={"User-Agent": UA})
o = c2.post("/login/passkey-options", headers={"User-Agent": UA}).get_json() or {}
evil = Authenticator()
cred = evil.get(o)
r = c2.post("/login", data={"step": "passkey", "credential": json.dumps(cred)}, headers={"User-Agent": UA})
ok("…a passkey that is not this person's: refused", r.status_code == 401, r.status_code)
c3 = A.app.test_client()
r = c3.post("/login", data={"username": "lgsu-admin", "password": PW}, headers={"User-Agent": UA})
ok("a person without passkeys signs in with the authenticator code (then registers them)", b'data-v="mfa"' in r.data, r.status_code)

# ---------------- 5. the administrator's reset
print("== an administrator's passkey reset")
os.environ["ACCESS_MODE"] = "local"
r = call(ad, ad_csrf, "POST", "/api/admin/users/lgsu-other/passkeys/reset", {})
a, j = asked(r)
ok("resetting someone's passkeys asks every time", a and j.get("every_time"), j)
g = call(ad, ad_csrf, "POST", "/api/stepup/code", {"code": code("lgsu-admin"), "method": "POST",
                                                   "path": "/api/admin/users/lgsu-other/passkeys/reset"}).get_json() or {}
n_sessions = sum(1 for v in sessions.s.values() if v["user"] == "lgsu-other")
r = call(ad, ad_csrf, "POST", "/api/admin/users/lgsu-other/passkeys/reset", {}, {"X-LG-Stepup": g.get("grant", "")})
ok("…done: every passkey removed, the person's sessions ended, audited",
   r.status_code == 200 and store.count("lgsu-other") == 0 and n_sessions > 0
   and not any(v["user"] == "lgsu-other" for v in sessions.s.values()) and any(e == "passkeys_reset" for e, _ in AUDIT), (r.status_code, r.get_json(silent=True)))
g = call(ad, ad_csrf, "POST", "/api/stepup/code", {"code": code("lgsu-admin"), "method": "POST",
                                                   "path": "/api/admin/users/lgsu-admin/passkeys/reset"}).get_json() or {}
r = call(ad, ad_csrf, "POST", "/api/admin/users/lgsu-admin/passkeys/reset", {}, {"X-LG-Stepup": g.get("grant", "")})
ok("…never on oneself", r.status_code == 400, r.status_code)
r = call(an, an_csrf, "POST", "/api/admin/users/lgsu-other/passkeys/reset", {})
ok("…and only by an administrator", r.status_code == 403, r.status_code)

# ---------------- 6. external accounts
print("== external accounts reach their own passkeys and nothing more")
ex, ex_csrf, _ = client("lgsu-ext")
ok("the passkey page", ex.get("/account", headers={"User-Agent": UA}).status_code == 200)
ok("their passkeys", call(ex, ex_csrf, "GET", "/api/passkeys").status_code == 200)
ok("…but still not the Findings", ex.get("/api/findings", headers={"User-Agent": UA}).status_code == 403)

# ---------------- 7. the bell
print("== the bell: sign-ins from the internet on an internal installation")
bd = tempfile.mkdtemp(prefix="lg-stepup-bell-")
os.makedirs(os.path.join(bd, "data"))
with open(os.path.join(bd, "data", "users.json"), "w") as fh:
    json.dump({"users": {"pat": {"last_login": {"at": time.time() - 3600, "ip": "8.8.8.8"}},
                         "sam": {"last_login": {"at": time.time() - 3600, "ip": "192.168.1.20"}}}}, fh)
al = system_alerts.Alerts(bd, env={"ACCESS_MODE": "private"})._public_signins(time.time())
ok("a private installation, a sign-in from a public address: an alert naming it", len(al) == 1 and "8.8.8.8" in al[0]["text"], al)
ok("…a public installation: no alert", system_alerts.Alerts(bd, env={"ACCESS_MODE": "public"})._public_signins(time.time()) == [])
with open(os.path.join(bd, "data", "users.json"), "w") as fh:
    json.dump({"users": {"sam": {"last_login": {"at": time.time() - 3600, "ip": "10.1.2.3"}}}}, fh)
ok("…only private addresses: no alert", system_alerts.Alerts(bd, env={"ACCESS_MODE": "private"})._public_signins(time.time()) == [])

# ---------------- 8. the passkey rules on their own
print("== passkeys need a host name over HTTPS")
ok("an IP address: refused", passkeys.rp_of("192.0.2.10:5000", True)[0] is None)
ok("plain HTTP on another computer: refused", passkeys.rp_of("lg.example.org", False)[0] is None)
ok("a host name over HTTPS: its name, and the origin with the port", passkeys.rp_of("lg.example.org:8443", True) == ("lg.example.org", "https://lg.example.org:8443"))
ok("the test switch is off unless set", stepup.tests_off() is False)

print(f"\n{checks - len(fails)} of {checks} step-up and passkey checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
