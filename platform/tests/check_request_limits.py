#!/usr/bin/env python3
"""Heavy views per person (request_limits.py, review of d82a436): at most HEAVY_PER_USER at once (the rest wait their
turn, then 429 with Retry-After), at most HEAVY_PER_MINUTE a minute; each person on their own, light pages never
limited, automation never limited, the slot always given back (errors too). No database needed.
Run: .venv/bin/python tests/check_request_limits.py"""
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.update(HEAVY_PER_USER="2", HEAVY_PER_MINUTE="6", HEAVY_WAIT_S="1")
from flask import Flask, g, request  # noqa: E402

import request_limits as RL  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


app = Flask(__name__)
gate = threading.Event()


@app.before_request
def _who():
    u = request.headers.get("X-User")
    g.user = {"user": u, "automation": u == "robot"} if u else None


state = RL.install(app, ("/heavy", "/boom"), lambda: None if (g.user or {}).get("automation") else ("u:" + g.user["user"]) if g.user else "a:x")


@app.route("/heavy")
def heavy():
    if request.args.get("hold"):
        gate.wait(5)
    return "ok"


@app.route("/boom")
def boom():
    raise RuntimeError("fails")


@app.route("/light")
def light():
    return "ok"


c = app.test_client()
res = []


def call(user, path="/heavy?hold=1"):
    res.append(app.test_client().get(path, headers={"X-User": user}).status_code)


t = [threading.Thread(target=call, args=("ama",)) for _ in range(2)]
[x.start() for x in t]
time.sleep(0.3)
r = c.get("/heavy", headers={"X-User": "ama"})
ok("a third heavy request at once waits its turn, then 429", r.status_code == 429 and r.headers.get("Retry-After") == "5", r.status_code)
ok("…and says why", "still being worked on" in r.get_json()["error"])
r = c.get("/heavy", headers={"X-User": "kofi"})
ok("another person is not held up by it", r.status_code == 200)
r = c.get("/light", headers={"X-User": "ama"})
ok("light pages are never limited", r.status_code == 200)
gate.set(); [x.join() for x in t]
ok("the two running ones finished normally", res == [200, 200], str(res))
ok("once they are done, the person may ask again", c.get("/heavy", headers={"X-User": "ama"}).status_code == 200)
for _ in range(3):
    c.get("/boom", headers={"X-User": "esi"})
ok("a request that fails gives its slot back", c.get("/heavy", headers={"X-User": "esi"}).status_code == 200)
codes = [c.get("/heavy", headers={"X-User": "yaw"}).status_code for _ in range(8)]
ok("more than HEAVY_PER_MINUTE in a minute: 429", codes[:6] == [200] * 6 and codes[6:] == [429, 429], str(codes))
r = c.get("/heavy", headers={"X-User": "yaw"})
ok("…with Retry-After and a reason", r.headers.get("Retry-After") == "30" and "last minute" in r.get_json()["error"])
ok("automation is never limited", all(c.get("/heavy", headers={"X-User": "robot"}).status_code == 200 for _ in range(10)))
ok("counted for the Task monitor", state["refused_busy"] >= 1 and state["refused_rate"] >= 3, str(state))
os.environ.update(HEAVY_PER_USER="0", HEAVY_PER_MINUTE="0")
app2 = Flask("off")
RL.install(app2, ("/heavy",), lambda: "a:x")
app2.add_url_rule("/heavy", "heavy", lambda: "ok")
ok("0 switches the limits off", all(app2.test_client().get("/heavy").status_code == 200 for _ in range(20)))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
