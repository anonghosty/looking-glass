#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The request guards and security headers (security.py) on small throwaway Flask apps, one per setting (r91 coverage):
- who may connect: local (this computer only), private (VIEWER_NETWORKS, "internal" = every private range), public
  (ACCESS_MODE=public or VIEWER_NETWORKS=any); a malformed range is ignored; an unreadable client address is refused
- host names: only this computer's names and ALLOWED_HOSTS; "*" serves any; [::1]:port is understood
- cross-site writes: a foreign Origin, Origin "null" without Sec-Fetch-Site same-origin, Sec-Fetch-Site cross-site:
  403; a JSON array or bare value: 400; GETs pass
- headers: CSP with the nonce (report-only when asked), framing only for /management?embed=1, a frame-src for the
  review pages, HSTS only over HTTPS (max-age, includeSubDomains, preload from .env; a bad value: one year), no Server
  header, a download name outside Latin-1 sent as an ASCII name plus filename*
- error text: only Looking Glass's own messages reach the browser, a library's error gets the generic text
No server, no database. Run: .venv/bin/python tests/check_cov_security.py"""
import logging, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, Response, jsonify  # noqa: E402
import security  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


ENV = ("ACCESS_MODE", "VIEWER_NETWORKS", "ALLOWED_HOSTS", "TRUST_PROXY", "CSP_REPORT_ONLY", "HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS", "HSTS_PRELOAD")
saved = {k: os.environ.get(k) for k in ENV}


def make(**env):
    for k in ENV:
        os.environ.pop(k, None)
    os.environ.update(env)
    app = Flask(__name__)
    security.install(app, logging.getLogger("lg-cov-security"))

    @app.route("/x", methods=["GET", "POST"])
    def x():
        return jsonify(ok=True)

    @app.route("/management")
    def mgmt():
        return "m"

    @app.route("/review/1")
    def review():
        return "r"

    @app.route("/dl")
    def dl():
        return Response("a", headers={"Content-Disposition": 'attachment; filename="Advisory Ọ̀ṣun Ẹ̀ka.pdf"'})
    return app.test_client()


try:
    print("Who may connect")
    ok("access mode: nothing set = local; a range = private; any/0.0.0.0/0 = public; ACCESS_MODE wins otherwise",
       [(make(), security.access_mode())[1], (make(VIEWER_NETWORKS="10.0.0.0/8"), security.access_mode())[1],
        (make(VIEWER_NETWORKS="0.0.0.0/0", ACCESS_MODE="local"), security.access_mode())[1],
        (make(ACCESS_MODE="public"), security.access_mode())[1]] == ["local", "private", "public", "public"])
    c = make()
    ok("local: this computer passes", c.get("/x").status_code == 200)
    ok("…another computer: 403", c.get("/x", environ_base={"REMOTE_ADDR": "192.0.2.10"}).status_code == 403)
    ok("…an unreadable client address: 403", c.get("/x", environ_base={"REMOTE_ADDR": "not-an-address"}).status_code == 403)
    c = make(VIEWER_NETWORKS="192.0.2.0/28, not-a-range, internal")
    ok("private: an address in VIEWER_NETWORKS passes", c.get("/x", environ_base={"REMOTE_ADDR": "192.0.2.5"}).status_code == 200)
    ok("…'internal' = every private range (10.x, 192.168.x)", c.get("/x", environ_base={"REMOTE_ADDR": "10.9.8.7"}).status_code == 200
       and c.get("/x", environ_base={"REMOTE_ADDR": "192.168.4.4"}).status_code == 200)
    ok("…an address outside them: 403", c.get("/x", environ_base={"REMOTE_ADDR": "198.51.100.7"}).status_code == 403)
    c = make(ACCESS_MODE="public")
    ok("public: any address", c.get("/x", environ_base={"REMOTE_ADDR": "198.51.100.7"}).status_code == 200)

    print("Host names")
    c = make()
    ok("a name that is not this computer's: 400 (DNS rebinding)", c.get("/x", headers={"Host": "attacker.example"}).status_code == 400)
    ok("localhost with a port, and [::1]:port: served", c.get("/x", headers={"Host": "localhost:5000"}).status_code == 200
       and c.get("/x", headers={"Host": "[::1]:5000"}).status_code == 200)
    c = make(ALLOWED_HOSTS="lg.csirt-made-up.org")
    ok("a name in ALLOWED_HOSTS: served", c.get("/x", headers={"Host": "lg.csirt-made-up.org"}).status_code == 200)
    c = make(ALLOWED_HOSTS="*")
    ok("ALLOWED_HOSTS=*: any name", c.get("/x", headers={"Host": "anything.example"}).status_code == 200)

    print("Cross-site writes")
    c = make()
    ok("a POST from this site: passes", c.post("/x", headers={"Origin": "http://localhost"}).status_code == 200)
    ok("a foreign Origin: 403", c.post("/x", headers={"Origin": "https://evil.example"}).status_code == 403)
    ok("Origin null without Sec-Fetch-Site same-origin: 403", c.post("/x", headers={"Origin": "null"}).status_code == 403)
    ok("Origin null from a same-origin form: passes", c.post("/x", headers={"Origin": "null", "Sec-Fetch-Site": "same-origin"}).status_code == 200)
    ok("Sec-Fetch-Site cross-site (no Origin): 403", c.post("/x", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403)
    ok("a JSON array: 400, a JSON object: passes", c.post("/x", json=[1, 2]).status_code == 400 and c.post("/x", json={"a": 1}).status_code == 200)
    ok("a bare JSON number: 400", c.post("/x", data="5", content_type="application/json").status_code == 400)

    print("Headers")
    r = c.get("/x")
    h = r.headers
    ok("CSP with a nonce, framing refused, nosniff, no Server header",
       "nonce-" in h.get("Content-Security-Policy", "") and "frame-ancestors 'none'" in h["Content-Security-Policy"]
       and h.get("X-Frame-Options") == "DENY" and h.get("X-Content-Type-Options") == "nosniff" and "Server" not in h)
    ok("no HSTS over plain HTTP", "Strict-Transport-Security" not in h)
    h = c.get("/management?embed=1").headers
    ok("/management?embed=1: framed by this site only", "frame-ancestors 'self'" in h["Content-Security-Policy"] and h["X-Frame-Options"] == "SAMEORIGIN")
    ok("the review pages may frame this site", "frame-src 'self'" in c.get("/review/1").headers["Content-Security-Policy"])
    h = c.get("/x", base_url="https://localhost").headers
    ok("HSTS over HTTPS: one year by default", h.get("Strict-Transport-Security") == "max-age=31536000")
    c = make(HSTS_MAX_AGE="600", HSTS_INCLUDE_SUBDOMAINS="1", HSTS_PRELOAD="1", CSP_REPORT_ONLY="1")
    h = c.get("/x", base_url="https://localhost").headers
    ok("HSTS from .env: max-age, includeSubDomains, preload", h.get("Strict-Transport-Security") == "max-age=600; includeSubDomains; preload")
    ok("CSP_REPORT_ONLY=1: report only", "Content-Security-Policy-Report-Only" in h and "Content-Security-Policy" not in h)
    os.environ["HSTS_MAX_AGE"] = "soon"
    ok("a max-age that is not a number: one year", security.hsts_value().startswith("max-age=31536000"))
    os.environ["HSTS_MAX_AGE"] = "0"
    ok("max-age 0: browsers forget it, no subdomains or preload", security.hsts_value() == "max-age=0")
    cd = c.get("/dl").headers["Content-Disposition"]
    ok("a download name outside Latin-1: an ASCII name plus the real one as filename*",
       cd.isascii() and 'filename="Advisory' in cd and "filename*=UTF-8''Advisory%20" in cd, cd)

    print("Error text for the browser")
    try:
        raise ValueError("That network list is too long.")
    except ValueError as e:
        ours = security.public_error(e)
    ok("an error Looking Glass raised: its own words", ours == "That network list is too long.")
    try:
        import json
        json.loads("{bad")
    except ValueError as e:
        lib = security.public_error(e, fallback="generic")
    ok("an error raised inside a library: the generic text", lib == "generic")
    ok("an error never raised (no traceback): the generic text", security.public_error(RuntimeError("x"), "generic") == "generic")
    ok("own names: at least one host name or address of this computer", len(security._own_names()) >= 1)
finally:
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
