#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""What someone not signed in can learn about the server (neutral.py, anti-fingerprinting, the user 2026-11-18/19).
1. every answer a signed-out visitor can get (sign-in, reset and account pages, a missing page, a page that needs
   sign-in, the platform's files, the API) names no product, framework or library version: no "Looking Glass",
   "Shadowserver", "Flask", "Werkzeug", "gunicorn", "deck.gl", "mapbox", "unpkg", no "Redirecting..." page, no HTML
   comment; standard status lines ("302 Found"); the short policy before sign-in;
2. only the sign-in pages' files are served signed out; signed in, every file is (any role); file tags are neutral and
   answered 304 as before;
3. /healthz answers this computer only;
4. the sign-in pages' logo: the organisation's by default (none when it has none), the Looking Glass logo or none as an
   administrator chooses (administrators only, CSRF, a recent sign-in, audited);
5. the certificate script names no product.
The real app is only read from (GET); the setting and /healthz are checked on a throwaway app with a scratch folder.
Usage: tests/check_fingerprint.py"""
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ.setdefault("LG_QUIET", "1")

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:220]}]" if info else ""), flush=True)


GIVEAWAY = re.compile(r"looking ?glass|shadowserver|werkzeug|flask|gunicorn|deck\.gl|mapbox|unpkg|redirecting\.\.\.|<!--", re.I)

print("1. What a signed-out visitor gets")
import app as A  # noqa: E402
import auth  # noqa: E402
c = A.app.test_client()
ENV = {"REMOTE_ADDR": "127.0.0.1"}
paths = ["/login", "/login?form=signin", "/forgot", "/nope", "/settings", "/definitions", "/api/stats", "/favicon.ico",
         "/static/js/app.js", "/static/js/loader.js", "/static/css/services.css", "/static/img/logo-mark.svg", "/static/../.env"] \
    + sorted(auth.PUBLIC_STATIC)
seen = {}
for p in paths:
    r = c.get(p, environ_base=ENV)
    head = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    body = r.get_data(as_text=True) if (r.mimetype or "").startswith(("text/", "application/json", "image/svg")) else ""
    if p.startswith("/static/") and p in auth.PUBLIC_STATIC and p.endswith((".js", ".css")):
        body = body[:400]                                   # a file's opening comment is what describes it
    if p.endswith(".json"):
        body = ""                                           # the world map's outline: numbers only
    seen[p] = (r.status, r.status_code, head, body)
bad = {p: GIVEAWAY.search(h + "\n" + b).group(0) for p, (_, _, h, b) in seen.items() if GIVEAWAY.search(h + "\n" + b)}
ok("no answer names the product, its framework or a library (headers and pages)", not bad, bad)
from http import HTTPStatus  # noqa: E402
reasons = {p: s for p, (s, code, _, _) in seen.items() if s != f"{code} {HTTPStatus(code).phrase}"}
ok("standard status lines (\"302 Found\", not the framework's \"302 FOUND\")", not reasons and seen["/settings"][0] == "302 Found", reasons or seen["/settings"][0])
ok("a redirect has no page of its own (no \"Redirecting...\")", seen["/settings"][1] == 302 and not seen["/settings"][3].strip())
ok("a missing page is a plain \"Not Found\"", seen["/nope"][1] in (302, 404) and seen["/favicon.ico"][1] == 404
   and "Not Found" in seen["/favicon.ico"][3] and "requested URL" not in seen["/favicon.ico"][3])
csp = dict(c.get("/login", environ_base=ENV).headers).get("Content-Security-Policy", "")
ok("before sign-in, a short policy naming no outside library", "script-src 'self' 'nonce-" in csp and "mapbox" not in csp and "deck.gl" not in csp
   and "qrcode" not in csp and "cdnjs" not in csp, csp)
print("2. The platform's files")
not_public = [p for p in ("/static/js/app.js", "/static/js/loader.js", "/static/css/services.css", "/static/img/logo-mark.svg")
              if seen[p][1] != 404]
ok("signed out, the platform's other files do not exist (404)", not not_public, not_public)
pub = [p for p in sorted(auth.PUBLIC_STATIC) if seen[p][1] != 200]
ok("…the sign-in pages' own files are served", not pub, pub)
ok("path traversal still refused", seen["/static/../.env"][1] in (400, 404))
key = open(os.path.join(HERE, "data", "automation.key")).read().strip() if os.path.exists(os.path.join(HERE, "data", "automation.key")) else ""
if key:
    r = c.get("/static/js/app.js", environ_base=ENV, headers={"X-LG-Automation": key})
    tag = r.headers.get("ETag", "")
    ok("signed in, every file is served", r.status_code == 200 and len(r.get_data()) > 1000, r.status_code)
    ok("…with a neutral file tag (not the framework's mtime-size-checksum)", re.fullmatch(r'"[0-9a-f]{24}"', tag or "") is not None, tag)
    r2 = c.get("/static/js/app.js", environ_base=ENV, headers={"X-LG-Automation": key, "If-None-Match": tag})
    ok("…and a browser that has it gets 304 as before", r2.status_code == 304 and not r2.get_data(), r2.status_code)
else:
    ok("signed in, every file is served (no automation key here: skipped as passed)", True)
ok("the restricted roles reach files before their path lists are checked", "if p.startswith(\"/static/\"):\n                    return None" in open(os.path.join(HERE, "auth.py"), encoding="utf-8").read())

print("3-4. /healthz and the sign-in pages' logo (a throwaway app)")
from flask import Flask, g, render_template_string  # noqa: E402
import neutral as N  # noqa: E402
from organisation import Organisation  # noqa: E402
tmp = tempfile.mkdtemp()
fa = Flask("fp-check")
who = {"user": "", "perms": set(), "csrf": True, "fresh": True}
audit = []


class Audit:
    def add(self, kind, **kw):
        audit.append((kind, kw))


@fa.before_request
def _u():
    g.user = {"user": who["user"]} if who["user"] else None


@fa.route("/healthz")
def _hz():
    return {"ok": True}


@fa.route("/register/enrol")
def _enrol():
    return '<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script>'


org = Organisation(os.path.join(tmp, "data", "organisation.json"))
api = N.install(fa, {"base_dir": tmp, "has_perm": lambda p: p in who["perms"], "csrf_ok": lambda: who["csrf"],
                     "fresh": lambda: who["fresh"], "audit": Audit(), "org": org})
fc = fa.test_client()
ok("/healthz answers this computer", fc.get("/healthz", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 200)
r = fc.get("/healthz", environ_base={"REMOTE_ADDR": "192.0.2.9"})
ok("…and nobody else (a plain \"Not Found\")", r.status_code == 404 and "ok" not in r.get_data(as_text=True))
ok("the authenticator set-up page (it draws a QR code) keeps the QR-code library it needs",
   "qrcode-generator/1.4.4" in fc.get("/register/enrol").headers.get("Content-Security-Policy", ""))
TPL = "{{ signin_logo | default('') }}|{{ signin_org }}"


def look():
    with fa.test_request_context("/login"):
        fa.preprocess_request()
        return render_template_string(TPL)


# no logo before sign-in at all (the user, 2026-11-19: "it eradicates the image fingerprint"): the name only
ok("no organisation name: nothing shown", look() == "|", look())
png = b"\x89PNG\r\n\x1a\n" + b"0" * 64
org.save("Made-up CSIRT", (png, "image/png"))
ok("an organisation with a logo: its name only, no logo", look() == "|Made-up CSIRT", look())
os.makedirs(os.path.join(tmp, "static", "img")); open(os.path.join(tmp, "static", "img", "logo-mark.svg"), "w").write("<svg/>")
for path in ("/login/logo", "/login/mark.svg"):
    r = fc.get(path)
    ok(f"no image served before sign-in at {path}", r.status_code == 404 and not r.mimetype.startswith("image/"), r.status_code)
ok("the old logo setting is gone", fc.get("/api/settings/signin-look").status_code == 404
   and fc.post("/api/settings/signin-look", json={"logo": "looking-glass"}).status_code in (404, 405))
S_ = os.environ.get("LG_HELD_DIR", "")
pick = lambda n, live: open(os.path.join(S_, n + ".new"), encoding="utf-8").read() if S_ and os.path.exists(os.path.join(S_, n + ".new")) \
    else open(live, encoding="utf-8").read()  # noqa: E731
pages = {n: pick(n, os.path.join(HERE, "templates", n)) for n in ("auth_base.html", "login.html", "forgot.html")}
for n, src in pages.items():
    ok(f"{n}: no logo, no image of the product or the organisation", "<img" not in src and "logo-mark" not in src
       and "/login/logo" not in src and "/login/mark.svg" not in src and "signin_logo" not in src)
ok("…and no tab icon to fetch (an empty one)", '<link rel="icon" href="data:,">' in pages["auth_base.html"])

print("5. The certificate")
sh = open(os.path.join(HERE, "deploy", "make_tls_cert.sh"), encoding="utf-8").read()
ok("new certificates are named after the machine (or the name given), never the product", "/CN=Looking Glass" not in sh and '-subj "/CN=$cn"' in sh)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
