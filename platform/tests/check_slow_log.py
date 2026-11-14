#!/usr/bin/env python3
"""Slow requests are logged by route pattern only (slow_log.py), and the name index is rebuilt once when many requests
arrive after it expired (app._name_evidence). No database, no network; a throwaway folder.
Run: .venv/bin/python tests/check_slow_log.py"""
import json, os, shutil, sys, tempfile, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask, g  # noqa: E402
import slow_log  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-slowlog-")
try:
    print("Only slow requests, by route pattern")
    os.environ["SLOW_REQUEST_S"] = "0.2"
    app = Flask("t")
    path = slow_log.install(app, tmp)

    @app.before_request
    def _who():
        g.user = {"user": "alice", "role": "analyst"}

    @app.route("/fast")
    def fast():
        return "ok"

    @app.route("/api/host/<ip>")
    def host(ip):
        time.sleep(0.3)
        return "slow", 200

    @app.route("/api/fails")
    def fails_route():
        time.sleep(0.3)
        return "no", 503

    c = app.test_client()
    c.get("/fast")
    ok("a fast request leaves no line", not os.path.exists(path) or not open(path).read().strip())
    c.get("/api/host/41.66.1.2?q=203.0.113.7&name=secret")
    c.get("/api/fails")
    lines = [json.loads(x) for x in open(path)] if os.path.exists(path) else []
    raw = open(path).read() if os.path.exists(path) else ""
    ok("a slow request is one line", len(lines) == 2, str(lines))
    r = lines[0] if lines else {}
    ok("…with the route pattern, not the address", r.get("route") == "/api/host/<ip>", r.get("route"))
    ok("…no address, query text, value or name anywhere in the file",
       not any(s in raw for s in ("41.66.1.2", "203.0.113.7", "secret", "alice")), raw[:200])
    ok("…the role, method, time and requests running", r.get("role") == "analyst" and r.get("method") == "GET"
       and r.get("s", 0) >= 0.2 and r.get("running", 0) >= 1, str(r))
    ok("…and the answer's status", r.get("status") == 200 and (lines[1] if len(lines) > 1 else {}).get("status") == 503)
    ok("the file is private (mode 600)", oct(os.stat(path).st_mode & 0o777) == "0o600", oct(os.stat(path).st_mode & 0o777))
    print("Switched off and kept small")
    os.environ["SLOW_REQUEST_S"] = "0"
    c.get("/api/host/1.2.3.4")
    ok("SLOW_REQUEST_S=0 records nothing", len(open(path).readlines()) == 2)
    os.environ["SLOW_REQUEST_S"] = "0.2"
    keep = slow_log.MAX_BYTES; slow_log.MAX_BYTES = 50
    c.get("/api/host/1.2.3.4")
    slow_log.MAX_BYTES = keep
    ok("at its size limit the log moves to .1 and starts again", os.path.exists(path + ".1") and len(open(path).readlines()) == 1)
    s = slow_log.summary(path, 7)
    ok("the summary lists each route with count and slowest time",
       any(x["route"] == "GET /api/host/<ip>" and x["count"] == 2 and x["slowest"] >= 0.2 for x in s), str(s))
    os.environ["SLOW_REQUEST_S"] = "nonsense"
    ok("a bad SLOW_REQUEST_S falls back to 2 s", slow_log.threshold() == 2.0)
    os.environ.pop("SLOW_REQUEST_S", None)

    print("The name index: one rebuild when many requests arrive after it expired")
    import app as A
    calls = {"n": 0}
    real = A._build_name_evidence

    def slow_build():
        calls["n"] += 1
        time.sleep(0.4)
        A._EVIDENCE.update(at=time.time(), data={"x": {"classes": set(), "reports": set()}})
        return A._EVIDENCE["data"]
    A._build_name_evidence = slow_build
    try:
        A._EVIDENCE.update(at=0.0, data={"old": {"classes": set(), "reports": set()}})     # expired, a copy present
        got = []
        ts = [threading.Thread(target=lambda: got.append(A._name_evidence())) for _ in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        ok("eight requests after expiry: rebuilt once", calls["n"] == 1, str(calls["n"]))
        ok("…the others answered at once from the last copy", sum(1 for x in got if "old" in x) == 7, str([list(x) for x in got]))
        calls["n"] = 0; A._EVIDENCE.update(at=0.0, data={})                                   # no copy yet: wait, build once
        got = []
        ts = [threading.Thread(target=lambda: got.append(A._name_evidence())) for _ in range(6)]
        [t.start() for t in ts]; [t.join() for t in ts]
        ok("first build with six waiting: built once, all get it", calls["n"] == 1 and all("x" in x for x in got), f"{calls['n']} builds")

        def broken():
            raise RuntimeError("database gone")
        A._build_name_evidence = broken; A._EVIDENCE.update(at=0.0, data={"old": {}})
        try:
            A._name_evidence()
        except RuntimeError:
            pass
        ok("a failed rebuild releases the lock", A._EV_BUILD.acquire(blocking=False))
        A._EV_BUILD.release()
    finally:
        A._build_name_evidence = real
        A._EVIDENCE.update(at=0.0, data={})
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
