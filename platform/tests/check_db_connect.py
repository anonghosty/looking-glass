#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Where the reports database may be (db_connect.py, 2026-11-14): this computer or an internal network address only,
never a public one; TLS for another computer (refused without it, unless MONGO_ALLOW_PLAINTEXT=1); certificate files
that exist. The same file ships in the database pipeline. Run: .venv/bin/python tests/check_db_connect.py"""
import os
import sys
import tempfile
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import db_connect as D  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def kw(**env):
    try:
        return D.kwargs(lambda k: env.get(k)), None
    except D.Refused as e:
        return None, str(e)


print("This computer")
k, e = kw()
ok("nothing set: 127.0.0.1:27017, no TLS needed", k == {"host": "127.0.0.1", "port": 27017}, str(k or e))
for h in ("localhost", "127.0.0.1", "::1", "[::1]", "127.0.0.53"):
    ok(f"{h}: loopback, accepted", kw(MONGO_HOST=h)[0] is not None)

print("An internal server")
for h in ("10.1.2.3", "172.16.0.9", "172.31.255.1", "192.168.1.20", "100.64.0.5", "fd12:3456::1"):
    k, e = kw(MONGO_HOST=h, MONGO_TLS="1")
    ok(f"{h} with TLS: accepted, TLS on", k is not None and k.get("tls") is True, e or "")
k, e = kw(MONGO_HOST="10.1.2.3")
ok("internal without TLS: refused, saying why", k is None and "MONGO_TLS" in e, e or "")
k, e = kw(MONGO_HOST="10.1.2.3", MONGO_ALLOW_PLAINTEXT="1")
ok("…unless MONGO_ALLOW_PLAINTEXT=1 (a link you trust)", k is not None and "tls" not in k)
with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.9.8.7", 27017))]):
    ok("a name that resolves to an internal address: accepted", kw(MONGO_HOST="mongo.internal.example", MONGO_TLS="1")[0] is not None)

print("Never the public internet")
for h in ("8.8.8.8", "203.0.113.10", "172.32.0.1", "2001:4860::8888", "::ffff:8.8.8.8"):
    k, e = kw(MONGO_HOST=h, MONGO_TLS="1", MONGO_ALLOW_PLAINTEXT="1")
    ok(f"{h}: refused even with TLS and the plain-text switch", k is None and "public address" in e, e or str(k))
with mock.patch("socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 27017)), (2, 1, 6, "", ("198.51.100.7", 27017))]):
    k, e = kw(MONGO_HOST="db.example.org", MONGO_TLS="1")
    ok("a name with any public address among its addresses: refused", k is None and "198.51.100.7" in e, e or "")
with mock.patch("socket.getaddrinfo", side_effect=OSError("no such host")):
    k, e = kw(MONGO_HOST="nowhere.invalid", MONGO_TLS="1")
    ok("a name that does not resolve: refused", k is None and "does not resolve" in e, e or "")

print("Certificates")
tmp = tempfile.mkdtemp(); ca = os.path.join(tmp, "ca.pem"); open(ca, "w").write("x")
k, e = kw(MONGO_HOST="10.1.2.3", MONGO_TLS="1", MONGO_TLS_CA_FILE=ca)
ok("a CA file that exists is used", k is not None and k.get("tlsCAFile") == ca)
k, e = kw(MONGO_HOST="10.1.2.3", MONGO_TLS="1", MONGO_TLS_CA_FILE=os.path.join(tmp, "missing.pem"))
ok("a CA file that does not exist: refused", k is None and "does not exist" in e)
ok("no switch turns certificate checking off", not any("Invalid" in x or "insecure" in x.lower() for x in (k or {})))
src = open(D.__file__, encoding="utf-8").read()
ok("…tlsInsecure / tlsAllowInvalid* never appear", "tlsInsecure" not in src and "tlsAllowInvalid" not in src)

print("Both programs use it")
here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ok("the platform connects through it", "db_connect.kwargs" in open(os.path.join(here, "app.py"), encoding="utf-8").read())
db = next((d for d in ("../database", "../shadowserver") if os.path.isfile(os.path.join(here, d, "db_connect.py"))), None)
if db:
    same = open(os.path.join(here, db, "db_connect.py"), encoding="utf-8").read() == src
    ok("the pipeline ships the same db_connect.py", same)
    ok("…and connects through it", "db_connect.kwargs" in open(os.path.join(here, db, "shadowserver_pipeline.py"), encoding="utf-8").read())

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
