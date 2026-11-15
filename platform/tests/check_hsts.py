#!/usr/bin/env python3
"""Strict-Transport-Security (security.py, review of d82a436): sent on every answer over HTTPS (Looking Glass serving
HTTPS itself, or behind a trusted proxy that says https), never over plain HTTP; one year by default;
includeSubDomains and preload only when asked; HSTS_MAX_AGE=0 sends max-age=0 so browsers forget it. No database
needed.  Run: .venv/bin/python tests/check_hsts.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
for k in ("HSTS_MAX_AGE", "HSTS_INCLUDE_SUBDOMAINS", "HSTS_PRELOAD", "TRUST_PROXY"):
    os.environ.pop(k, None)
os.environ["ACCESS_MODE"] = "local"
from flask import Flask  # noqa: E402

import security  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def client(trust_proxy=False):
    if trust_proxy:
        os.environ["TRUST_PROXY"] = "1"
    else:
        os.environ.pop("TRUST_PROXY", None)
    app = Flask(__name__)
    security.install(app)

    @app.route("/x")
    def x():
        return "ok"
    return app.test_client()


c = client()
h = lambda r: r.headers.get("Strict-Transport-Security")  # noqa: E731
r = c.get("/x", base_url="https://localhost")
ok("over HTTPS: one year", h(r) == "max-age=31536000", h(r))
r = c.get("/x", base_url="http://localhost")
ok("over plain HTTP: not sent (browsers ignore it there, and it must not stop a local HTTP install)", h(r) is None, h(r))
r = c.get("/nothing-here", base_url="https://localhost")
ok("on errors too (404)", h(r) == "max-age=31536000", h(r))
os.environ["HSTS_INCLUDE_SUBDOMAINS"] = "1"
os.environ["HSTS_PRELOAD"] = "1"
ok("includeSubDomains and preload only when asked", security.hsts_value() == "max-age=31536000; includeSubDomains; preload", security.hsts_value())
os.environ.pop("HSTS_INCLUDE_SUBDOMAINS"); os.environ.pop("HSTS_PRELOAD")
os.environ["HSTS_MAX_AGE"] = "0"
ok("HSTS_MAX_AGE=0 sends max-age=0 (browsers forget it), never the extras", security.hsts_value() == "max-age=0")
os.environ["HSTS_INCLUDE_SUBDOMAINS"] = "1"
ok("…not even when asked", security.hsts_value() == "max-age=0")
os.environ.pop("HSTS_INCLUDE_SUBDOMAINS")
os.environ["HSTS_MAX_AGE"] = "nonsense"
ok("a wrong value falls back to one year", security.hsts_value() == "max-age=31536000")
os.environ.pop("HSTS_MAX_AGE")
p = client(trust_proxy=True)
r = p.get("/x", base_url="http://localhost", headers={"X-Forwarded-For": "203.0.113.5", "X-Forwarded-Proto": "https"},
          environ_base={"REMOTE_ADDR": "127.0.0.1"})
ok("behind a trusted proxy that says https: sent", h(r) == "max-age=31536000", f"{r.status_code} {h(r)}")
r = c.get("/x", base_url="http://localhost", headers={"X-Forwarded-Proto": "https"})
ok("a forwarded https without a trusted proxy is not believed", h(r) is None, h(r))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
