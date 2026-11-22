#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Behind the reverse proxy (TRUST_PROXY=1, proxy_guard.py): a visitor cannot pass as this computer (review 2026-11-15).
A proxy that appends to X-Forwarded-For (nginx's $proxy_add_x_forwarded_for) passes on whatever the visitor sent first;
Looking Glass believes only the right-most address, the one the proxy itself added, and the same for the scheme. A
visitor who reaches the app port directly has the headers ignored. A throwaway Flask app; no service.
Run: .venv/bin/python tests/check_proxy_chain.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, jsonify, request  # noqa: E402
import proxy_guard  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


app = Flask(__name__)


@app.route("/")
def _r():
    # JSON, never the request echoed into HTML (CodeQL alert 31: a test-only route, but no reason to reflect it)
    return jsonify(addr=request.remote_addr, scheme=request.scheme)


proxy_guard.install(app, True)
c = app.test_client()


def see(xff=None, proto=None, peer="127.0.0.1"):
    h = {k: v for k, v in (("X-Forwarded-For", xff), ("X-Forwarded-Proto", proto)) if v is not None}
    r = c.get("/", headers=h, environ_base={"REMOTE_ADDR": peer})
    d = r.get_json(silent=True) or {}
    return r.status_code, (f"{d['addr']} {d['scheme']}" if r.status_code == 200 and "addr" in d else r.get_data(as_text=True))


print("Through the proxy on this computer")
ok("a proxy that overwrites: the visitor's address", see("203.0.113.9", "https") == (200, "203.0.113.9 https"))
ok("a proxy that appends, visitor sent 127.0.0.1: still the visitor's address, never loopback",
   see("127.0.0.1, 203.0.113.9", "https") == (200, "203.0.113.9 https"), see("127.0.0.1, 203.0.113.9", "https"))
ok("the scheme the same way: a visitor's 'https' in front of the proxy's 'http' is plain http",
   see("203.0.113.9", "https, http")[1].endswith(" http"))
ok("no X-Forwarded-For from the proxy: refused, not taken as this computer", see()[0] == 400)
print("Straight to the app port")
ok("a visitor's X-Forwarded-For is ignored", see("127.0.0.1", "https", peer="198.51.100.7") == (200, "198.51.100.7 http"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
