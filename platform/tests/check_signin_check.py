#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""How sign-in is checked, a passkey or the authenticator code (signin_check.py, the user 2026-11-25).

1. The default: passkey only for ACCESS_MODE=public with Caddy in front for a domain (set up by Looking Glass);
   "public" without it (an office network from before the installer's internal choice), Caddy for an internal site,
   local and private: the authenticator code. Nobody is locked out by an update.
2. Where it comes from: SIGNIN_CHECK in .env wins, then the administrators' choice (owner-only file), then the default;
   a broken or unknown value counts as unset.
3. The API: administrators only ('settings'), CSRF, a recent sign-in, plain refusals; passkeys refused on an IP address,
   without HTTPS, or before the administrator has their own 2 passkeys; .env's value cannot be overridden from here;
   every change in the audit log with the old and new mode.
4. The wiring: the step-up gate asks for a confirmation every time for this route, and both sign-in (auth.py) and the
   gate (stepup.py) ask signin_check alone, not ACCESS_MODE.
Made-up accounts and a temporary folder only. Run: .venv/bin/python tests/check_signin_check.py"""
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


import signin_check as SC  # noqa: E402

tmp = tempfile.mkdtemp(prefix="lg-signin-check-")
saved_env = {k: os.environ.get(k) for k in ("ACCESS_MODE", "VIEWER_NETWORKS", "SIGNIN_CHECK")}
saved_caddy = SC.CADDYFILE
try:
    print("1. the default")
    domain_cf, internal_cf, own_cf = (os.path.join(tmp, n) for n in ("cf-domain", "cf-internal", "cf-own"))
    open(domain_cf, "w").write("# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced.\n"
                               "lookingglass.example.org:443 {\n}\n")
    open(internal_cf, "w").write("# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced.\n"
                                 "# internal: lg.corp.example\nhttps://:8999 {\n}\n")
    open(own_cf, "w").write("example.org {\n  reverse_proxy 127.0.0.1:5000\n}\n")
    os.environ.pop("SIGNIN_CHECK", None); os.environ["VIEWER_NETWORKS"] = ""
    SC.configure(tmp)
    cases = [("public", domain_cf, "passkey", "public with Caddy in front for a domain: passkey"),
             ("public", os.path.join(tmp, "none"), "code", "public without Caddy (an office network from before): the code"),
             ("public", internal_cf, "code", "public with Caddy for an internal site: the code"),
             ("public", own_cf, "code", "public with a Caddyfile Looking Glass did not write: the code"),
             ("private", domain_cf, "code", "private: the code"), ("local", domain_cf, "code", "local: the code")]
    for mode, cf, want, label in cases:
        os.environ["ACCESS_MODE"] = mode; SC.CADDYFILE = cf
        ok(label, SC.mode() == want and SC.source() == "default", (SC.mode(), SC.source()))
    os.environ["ACCESS_MODE"] = "private"; os.environ["VIEWER_NETWORKS"] = "any"; SC.CADDYFILE = domain_cf
    ok("VIEWER_NETWORKS=any counts as public (with Caddy for a domain: passkey)", SC.mode() == "passkey")
    os.environ["VIEWER_NETWORKS"] = ""

    print("2. where it comes from")
    os.environ["ACCESS_MODE"] = "public"
    SC._write("code")
    ok("the administrators' choice beats the default", SC.mode() == "code" and SC.source() == "settings")
    ok("…kept owner-only (0600)", (os.stat(os.path.join(tmp, "data", SC.FILE)).st_mode & 0o777) == 0o600)
    os.environ["SIGNIN_CHECK"] = "passkey"
    ok(".env's SIGNIN_CHECK wins over the choice", SC.mode() == "passkey" and SC.source() == "env")
    os.environ["SIGNIN_CHECK"] = "Code "
    ok("…written in any case, with spaces", SC.mode() == "code" and SC.source() == "env")
    os.environ["SIGNIN_CHECK"] = "sms"
    ok("…an unknown value counts as unset", SC.source() == "settings" and SC.mode() == "code")
    os.environ.pop("SIGNIN_CHECK")
    open(os.path.join(tmp, "data", SC.FILE), "w").write("{broken")
    ok("a broken choice file counts as unset (the default)", SC.source() == "default" and SC.mode() == "passkey")
    open(os.path.join(tmp, "data", SC.FILE), "w").write(json.dumps({"mode": "passkey"}))
    ok("…and is read again once it changes", SC.source() == "settings" and SC.mode() == "passkey")
    os.remove(os.path.join(tmp, "data", SC.FILE))
    ok("…and once it is gone", SC.source() == "default")

    print("3. the API")
    from flask import Flask, g
    app = Flask(__name__)
    ME = {"user": "grace", "perms": {"settings"}}
    FLAGS = {"csrf": True, "fresh": True}
    logged = []
    counts = {"grace": 0}

    class Store:
        def count(self, name):
            return counts.get(name, 0)

    @app.before_request
    def _me():
        g.user = dict(ME, perms=set(ME["perms"]))
    SC.install(app, {"base_dir": tmp, "has_perm": lambda p: p in g.user["perms"], "csrf_ok": lambda: FLAGS["csrf"],
                     "fresh": lambda: FLAGS["fresh"],
                     "audit": type("A", (), {"add": staticmethod(lambda ev, **k: logged.append((ev, k.get("detail", ""))))})(),
                     "store": Store(), "min_passkeys": 2})
    c = app.test_client()
    URL = "/api/admin/signin-check"
    os.environ["ACCESS_MODE"] = "private"
    post = lambda body, host="localhost", https=False: c.post(URL, json=body, base_url=f"{'https' if https else 'http'}://{host}")
    ME["perms"] = {"view"}
    ok("without 'settings': 403, reading and changing", c.get(URL).status_code == 403 and post({"mode": "code"}).status_code == 403)
    ME["perms"] = {"settings"}
    r = c.get(URL)
    ok("an administrator reads it: the mode, where from, the default, the words", r.status_code == 200
       and r.json["mode"] == "code" and r.json["source"] == "default" and r.json["words"]["passkey"] == "Passkey", r.json)
    FLAGS["csrf"] = False
    ok("a change without the page's CSRF token: 403", post({"mode": "passkey"}).status_code == 403)
    FLAGS["csrf"] = True; FLAGS["fresh"] = False
    ok("…from a session older than 12 hours: 403, sign in again", post({"mode": "passkey"}).status_code == 403)
    FLAGS["fresh"] = True
    ok("an unknown mode: 400", post({"mode": "sms"}).status_code == 400 and post({}).status_code == 400)
    r = post({"mode": "passkey"}, host="192.0.2.10", https=True)
    ok("passkeys from an IP address: refused, saying why", r.status_code == 400 and "IP address" in r.json["error"], r.json)
    r = post({"mode": "passkey"}, host="lg.example.org", https=False)
    ok("…without HTTPS: refused", r.status_code == 400 and "HTTPS" in r.json["error"], r.json)
    r = post({"mode": "passkey"}, host="lg.example.org", https=True)
    ok("…before the administrator has their own 2 passkeys: refused, saying how many", r.status_code == 400
       and "2 passkeys" in r.json["error"] and "You have 0" in r.json["error"], r.json)
    ok("…nothing written, nothing logged", SC.source() == "default" and not logged)
    counts["grace"] = 2
    r = post({"mode": "passkey"}, host="lg.example.org", https=True)
    ok("with HTTPS, a host name and 2 passkeys: passkeys in force, chosen here", r.status_code == 200
       and SC.mode() == "passkey" and SC.source() == "settings", r.json)
    ok("…in the audit log, old and new", logged and logged[-1] == ("signin_check_changed", "Authenticator code -> Passkey"), logged)
    r = post({"mode": "code"}, host="192.0.2.10")
    ok("back to the code (the step-up gate asks for the passkey first): allowed from anywhere", r.status_code == 200
       and SC.mode() == "code" and logged[-1][1] == "Passkey -> Authenticator code", r.json)
    n = len(logged)
    ok("choosing what is in force already: no change, nothing logged", post({"mode": "code"}).status_code == 200 and len(logged) == n)
    os.environ["SIGNIN_CHECK"] = "code"
    r = post({"mode": "passkey"}, host="lg.example.org", https=True)
    ok(".env's value cannot be changed from the browser: 400, saying where", r.status_code == 400 and ".env" in r.json["error"], r.json)
    os.environ.pop("SIGNIN_CHECK")

    print("4. the wiring")
    import stepup
    with app.test_request_context(URL, method="POST"):
        hit = stepup.rule_for("POST", URL)
    ok("the step-up gate asks every time for this route", hit == ("signin", True), hit)
    with app.test_request_context(URL):
        ok("…reading it needs no confirmation", stepup.rule_for("GET", URL) is None)
    src_s = open(os.path.join(HERE, "stepup.py"), encoding="utf-8").read()
    src_a = open(os.path.join(HERE, "auth.py"), encoding="utf-8").read()
    ok("stepup.py asks signin_check, not ACCESS_MODE", "signin_check.passkeys_required()" in src_s
       and 'access_mode() == "public"' not in src_s)
    ok("auth.py's sign-in asks signin_check, not ACCESS_MODE",
       "signin_check.passkeys_required()" in src_a and not re.search(r'access_mode\(\) == "public"', src_a))
    feats = open(os.path.join(HERE, "features.py"), encoding="utf-8").read()
    ok("installed from features.py", "signin_check.install(app" in feats)
finally:
    for k, v in saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    SC.CADDYFILE = saved_caddy
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
