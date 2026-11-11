#!/usr/bin/env python3
"""The libraries the platform runs on: installed, inside the versions requirements.txt allows, and doing what the
platform relies on. Needs no database, no reports and no running service, so it means something on a fresh install
(the installer runs it before the checks that need yesterday's reports).

If a newer library changes behaviour, this is meant to fail first, with the library's name in the line.
Run: .venv/bin/python tests/check_libraries.py"""
import io
import os
import re
import sys
import tempfile
from importlib import metadata

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def attempt(label, fn):
    try:
        res = fn()
        ok(label, res is not False, "" if res in (True, None) else str(res))
    except Exception as e:
        ok(label, False, f"{type(e).__name__}: {str(e)[:160]}")


def vtuple(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3]) + (0,) * (3 - len(re.findall(r"\d+", v)[:3]))


print("Versions (requirements.txt)")
reqs = []
for line in open(os.path.join(ROOT, "requirements.txt"), encoding="utf-8"):
    line = line.split("#", 1)[0].strip()
    if not line:
        continue
    m = re.match(r"^([A-Za-z0-9_.-]+)\s*(.*)$", line)
    reqs.append((m.group(1), [c.strip() for c in m.group(2).split(",") if c.strip()]))
ok("every requirement has a lower and an upper limit", all(any(c.startswith(">=") for c in cs) and any(c.startswith("<") for c in cs)
                                                           for _, cs in reqs), ", ".join(n for n, cs in reqs if len(cs) < 2))
for name, cons in reqs:
    try:
        have = metadata.version(name)
    except metadata.PackageNotFoundError:
        ok(f"{name} installed", False, "not installed: .venv/bin/pip install -r requirements.txt"); continue
    good = True
    for c in cons:
        op, v = re.match(r"(>=|<=|==|<|>)\s*(.+)", c).groups()
        a, b = vtuple(have), vtuple(v)
        good &= {">=": a >= b, "<": a < b, "<=": a <= b, ">": a > b, "==": a == b}[op]
    ok(f"{name} {have} is inside {','.join(cons)}", good)

print("Flask and Werkzeug (pages, sessions, forms, passwords, proxy)")


def flask_app():
    from flask import Flask, jsonify, make_response, render_template_string, request
    app = Flask("lg-check")

    @app.post("/j")
    def j():
        d = request.get_json(silent=True)
        return (jsonify(error="send JSON"), 415) if d is None else jsonify(got=d)

    @app.get("/c")
    def c():
        r = make_response("ok")
        r.set_cookie("lg_session", "x", httponly=True, samesite="Strict", secure=True)
        return r

    @app.get("/t")
    def t():
        return render_template_string("<b>{{ v }}</b>", v="<script>")
    return app


def flask_json():
    c = flask_app().test_client()
    r1 = c.post("/j", json={"a": 1}); r2 = c.post("/j", data="x", content_type="text/plain")
    return r1.status_code == 200 and r1.json == {"got": {"a": 1}} and r2.status_code == 415


def flask_cookie():
    h = flask_app().test_client().get("/c").headers.get("Set-Cookie", "")
    return all(x in h for x in ("HttpOnly", "SameSite=Strict", "Secure")) or h


def jinja_escape():
    return flask_app().test_client().get("/t").get_data(as_text=True) == "<b>&lt;script&gt;</b>"


def passwords():
    from werkzeug.security import check_password_hash, generate_password_hash
    h = generate_password_hash("correct horse battery")
    return h.startswith("scrypt:") and check_password_hash(h, "correct horse battery") and not check_password_hash(h, "wrong") or h[:12]


def proxyfix_multidict():
    from werkzeug.datastructures import MultiDict
    from werkzeug.middleware.proxy_fix import ProxyFix
    app = flask_app(); app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    from flask import request
    seen = {}

    @app.get("/ip")
    def ip():
        seen["ip"], seen["scheme"] = request.remote_addr, request.scheme
        return "ok"
    app.test_client().get("/ip", headers={"X-Forwarded-For": "192.0.2.7", "X-Forwarded-Proto": "https"})
    md = MultiDict([("a", "1"), ("a", "2")])
    return seen == {"ip": "192.0.2.7", "scheme": "https"} and md.getlist("a") == ["1", "2"] or seen


attempt("Flask reads JSON and refuses non-JSON", flask_json)
attempt("session cookie flags (HttpOnly, SameSite=Strict, Secure)", flask_cookie)
attempt("Jinja escapes HTML in pages", jinja_escape)
attempt("Werkzeug password hashing (scrypt)", passwords)
attempt("Werkzeug ProxyFix and MultiDict", proxyfix_multidict)

print("pymongo (no connection made)")


def mongo():
    from bson import ObjectId
    from pymongo import ASCENDING, MongoClient
    c = MongoClient("mongodb://127.0.0.1:1/?serverSelectionTimeoutMS=200", connect=False)
    c.close()
    return len(str(ObjectId())) == 24 and ASCENDING == 1


attempt("MongoClient, ObjectId and index constants", mongo)

print("ReportLab (the PDF reports)")


def pdf():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import CondPageBreak, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    st, buf = getSampleStyleSheet(), io.BytesIO()
    t = Table([["Report", "Records"], ["Sinkhole", "11,761"]]); t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.5, "grey")]))
    SimpleDocTemplate(buf, pagesize=A4).build([Paragraph("Looking Glass check", st["Title"]), Spacer(1, 6), CondPageBreak(40),
                                              KeepTogether([t])])
    b = buf.getvalue()
    return b.startswith(b"%PDF") and len(b) > 800 or len(b)


attempt("builds a PDF with a title, table and page-break rules", pdf)

print("python-dotenv and gunicorn")


def dotenv():
    from dotenv import dotenv_values
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
        f.write("COUNTRY=KE\n# comment\nMONGO_DB='lg_demo'\n")
    try:
        return dotenv_values(f.name) == {"COUNTRY": "KE", "MONGO_DB": "lg_demo"}
    finally:
        os.unlink(f.name)


def gunicorn_conf():
    from gunicorn.app.wsgiapp import WSGIApplication  # noqa: F401  the service starts through this
    from gunicorn.config import Config
    cfg, conf = Config(), os.path.join(ROOT, "gunicorn.conf.py")
    ns = {"__file__": conf, "__name__": "gunicorn_conf"}
    exec(compile(open(conf, encoding="utf-8").read(), conf, "exec"), ns)
    unknown = [k for k in ns if not k.startswith("_") and k not in ("os",) and k not in cfg.settings]
    for k, v in ns.items():
        if k in cfg.settings:
            cfg.set(k, v)
    return (not unknown and cfg.timeout == 120 and cfg.limit_request_line == 8190) or f"unknown settings: {unknown}"


attempt("reads a .env file", dotenv)
attempt("gunicorn starts its app class and accepts gunicorn.conf.py", gunicorn_conf)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
