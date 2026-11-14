#!/usr/bin/env python3
"""The cache for heavy read-only answers (response_cache.py): kept for a while, computed once when many ask at once,
started afresh after any change, kept apart per role and permissions (masking can never leak across), never an error
kept, switch-off works; and the app wraps the five heavy endpoints. No database. Run: .venv/bin/python tests/check_response_cache.py"""
import os, sys, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask, g, jsonify, request  # noqa: E402
import response_cache as RC  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


app = Flask("t")
calls = {"n": 0}
LIVE = {"progress": 1}


@app.before_request
def _who():
    role = request.headers.get("X-Role", "admin")
    g.user = {"user": "u-" + role, "role": role, "perms": ("view",) if role == "researcher" else ("view", "unmasked"),
              "peace": request.headers.get("X-Peace") == "1"}


@app.route("/heavy")
def heavy():
    calls["n"] += 1
    time.sleep(float(request.args.get("sleep", "0")))
    masked = "unmasked" not in g.user["perms"] or request.args.get("demo") == "1"
    return jsonify(host="ref-1" if masked else "203.0.113.9", n=calls["n"], progress=0)


@app.route("/broken")
def broken():
    calls["n"] += 1
    return jsonify(error="no"), 503


@app.route("/save", methods=["POST"])
def save():
    return jsonify(ok=True)


os.environ["CACHE_TTL_S"] = "60"
rc = RC.install(app, ("heavy", "broken"), live={"heavy": lambda: {"progress": LIVE["progress"]}})
c = app.test_client()
print("Kept, and computed once")
a = c.get("/heavy").json; b = c.get("/heavy").json
ok("a second request within the time is not computed again", calls["n"] == 1 and a["n"] == b["n"] == 1, str(calls))
LIVE["progress"] = 7
ok("a live field is current on a kept answer", c.get("/heavy").json["progress"] == 7)
print("Kept apart: what a person may see")
r = c.get("/heavy", headers={"X-Role": "researcher"}).json
ok("a researcher never gets the admin's unmasked answer", r["host"] == "ref-1" and calls["n"] == 2, str(r))
ok("…nor the admin the researcher's", c.get("/heavy").json["host"] == "203.0.113.9")
ok("demo=1 is its own answer (masked)", c.get("/heavy?demo=1").json["host"] == "ref-1" and calls["n"] == 3)
ok("Peace of mind is its own answer", c.get("/heavy", headers={"X-Peace": "1"}).json["n"] == 4)
print("Any change starts afresh")
before = calls["n"]
ok("a successful change", c.post("/save").status_code == 200)
ok("…and the next request computes again", c.get("/heavy").json["n"] == before + 1)
c.post("/nothing-here")                                 # a refused or failed change does not
n0 = calls["n"]; c.get("/heavy")
ok("a failed change does not throw the cache away", calls["n"] == n0)
print("Errors are never kept")
c.get("/broken"); c.get("/broken")
ok("a 503 is computed again each time", calls["n"] == n0 + 2)
print("Many at once after it ran out")
rc.bump(); calls["n"] = 0
c.get("/heavy?sleep=0.05")                              # an answer exists (this generation)
with rc.lock:
    for k in list(rc.entries):
        at, gen, st, h, body = rc.entries[k]; rc.entries[k] = (at - 120, gen, st, h, body)   # it ran out
calls["n"] = 0; out = []
ts = [threading.Thread(target=lambda: out.append(app.test_client().get("/heavy?sleep=0.4").status_code)) for _ in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]
ok("eight at once after it ran out: computed once, all answered", calls["n"] == 1 and out == [200] * 8, f"{calls['n']} computed, {out}")
rc.bump(); calls["n"] = 0; out = []
ts = [threading.Thread(target=lambda: out.append(app.test_client().get("/heavy?sleep=0.3").json["n"])) for _ in range(6)]
[t.start() for t in ts]; [t.join() for t in ts]
ok("six at once with nothing kept yet: computed once, all get it", calls["n"] == 1 and set(out) == {1}, str(out))
print("Switched off")
os.environ["CACHE_TTL_S"] = "0"; calls["n"] = 0
c.get("/heavy"); c.get("/heavy")
ok("CACHE_TTL_S=0: every request computes", calls["n"] == 2)
os.environ["CACHE_TTL_S"] = "60"
print("No cookie is ever kept")
with rc.lock:
    ok("kept headers hold no Set-Cookie", all(k.lower() != "set-cookie" for e in rc.entries.values() for k, _ in e[3]))

print("The app wraps the five heavy answers")
import app as A  # noqa: E402
eps = ("api_kb_services", "api_intel_summary", "api_intel_leads", "api_kb_unresolved", "api_attack")
ok("each is wrapped (the cache sits in front of the view)", all(getattr(A.app.view_functions[e], "__wrapped__", None) for e in eps),
   str([e for e in eps if not getattr(A.app.view_functions[e], "__wrapped__", None)]))
ok("per-person pages are not cached", not any(getattr(A.app.view_functions.get(e), "__wrapped__", None) for e in
   ("api_notifications", "api_findings") if e in A.app.view_functions))

print("Accuracy: a kept answer is the same as a fresh one, for each of the five")
import auth  # noqa: E402
users, sessions = A.AUTH["users"], A.AUTH["sessions"]
real_get = users.get
for role in ("admin", "researcher"):
    U = auth.TEST_PREFIX + "cache-" + role
    users.get = lambda n, U=U, role=role: ({"status": "active", "role": role, "changed": 0} if n == U else real_get(n))
    tok = sessions.create(U, "127.0.0.1", "lg-check-cache")
    cl = A.app.test_client(); cl.set_cookie("lg_session", tok)
    try:
        for path in ("/api/kb/services", "/api/intel/summary", "/api/intel/leads", "/api/kb/unresolved", "/api/attack"):
            os.environ["CACHE_TTL_S"] = "0"
            r0 = cl.get(path, headers={"User-Agent": "lg-check-cache"})
            os.environ["CACHE_TTL_S"] = "180"
            A.RESPONSE_CACHE.bump()
            r1 = cl.get(path, headers={"User-Agent": "lg-check-cache"}); r2 = cl.get(path, headers={"User-Agent": "lg-check-cache"})
            strip = lambda r: {k: v for k, v in (r.get_json(silent=True) or {}).items() if k != "check"}  # noqa: E731
            same = r0.status_code == r1.status_code == r2.status_code and strip(r0) == strip(r1) == strip(r2)
            ok(f"{role:10s} {path}: kept = fresh ({r0.status_code}, {len(r0.get_data())} bytes)", same,
               f"{r0.status_code}/{r1.status_code}/{r2.status_code}")
    finally:
        users.get = real_get
        sessions.end(key=auth._h(tok))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
