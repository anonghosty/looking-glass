"""Slow requests, recorded so the pages that are slow in use can be found and fixed (a test installation with little
data cannot show what a large one costs).

Every request that takes longer than SLOW_REQUEST_S seconds (.env, default 2; 0 switches it off) adds one line to
data/slow_requests.jsonl: when, the route PATTERN (for example /api/svc/insight, never the address, query text or any
value from the request), the method, the answer's status, how long it took, the role of the person (never the name),
and how many requests were running at that moment. The file stays small: at 2 MB it moves to slow_requests.jsonl.1
(the one before is dropped). Read it with manage/slow_requests.py.
"""
import json
import os
import threading
import time

_LOCK = threading.Lock()
_INFLIGHT = {"n": 0, "total": 0}
_MINUTES = {}                                   # minute (epoch // 60) -> requests started in it (the last 60 kept)
MAX_BYTES = 2 * 1024 * 1024


def counts():
    """For the task monitor: running now, since start, in the last minute, per minute over the last hour."""
    now = int(time.time() // 60)
    with _LOCK:
        per = [_MINUTES.get(m, 0) for m in range(now - 59, now + 1)]
        return {"running": _INFLIGHT["n"], "total": _INFLIGHT["total"], "last_minute": _MINUTES.get(now - 1, 0) + 0,
                "this_minute": _MINUTES.get(now, 0), "per_minute": per}


def threshold():
    try:
        return max(0.0, float(os.environ.get("SLOW_REQUEST_S", "2") or 0))
    except ValueError:
        return 2.0


def record(path, line):
    """Append one record (a dict) to the log at `path`, moving it aside at MAX_BYTES."""
    with _LOCK:
        try:
            if os.path.exists(path) and os.path.getsize(path) > MAX_BYTES:
                os.replace(path, path + ".1")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                f.write(json.dumps(line, separators=(",", ":")) + "\n")
        except OSError:
            pass                                    # never let the log break a request


def install(app, data_dir):
    """Register the timing hooks (call before the other modules, so it times the whole request)."""
    from flask import g, request
    path = os.path.join(data_dir, "slow_requests.jsonl")

    @app.before_request
    def _slow_start():
        g._slow_t0 = time.monotonic()
        m = int(time.time() // 60)
        with _LOCK:
            _INFLIGHT["n"] += 1
            _INFLIGHT["total"] += 1
            _MINUTES[m] = _MINUTES.get(m, 0) + 1
            if len(_MINUTES) > 60:
                for k in sorted(_MINUTES)[:-60]:
                    del _MINUTES[k]
        g._slow_counted = True

    @app.teardown_request
    def _slow_end(exc=None):
        if not getattr(g, "_slow_counted", False):
            return
        g._slow_counted = False
        with _LOCK:
            running = _INFLIGHT["n"]
            _INFLIGHT["n"] = max(0, _INFLIGHT["n"] - 1)
        limit = threshold()
        took = time.monotonic() - getattr(g, "_slow_t0", time.monotonic())
        if not limit or took < limit:
            return
        rule = request.url_rule.rule if request.url_rule is not None else "(no route)"
        u = getattr(g, "user", None) or {}
        record(path, {"t": round(time.time()), "route": rule, "method": request.method,
                      "status": getattr(g, "_slow_status", 0), "s": round(took, 2),
                      "role": (u.get("role") if isinstance(u, dict) else "") or ("automation" if isinstance(u, dict) and u.get("automation") else ""),
                      "running": running, "error": bool(exc)})

    @app.after_request
    def _slow_status(resp):
        g._slow_status = resp.status_code
        return resp

    return path


def summary(path, days=7, now=None):
    """Per route over the last `days` days: count, median and slowest seconds, most running at once (slowest first)."""
    now = now or time.time()
    rows = {}
    for p in (path + ".1", path):
        try:
            with open(p, encoding="utf-8") as f:
                for ln in f:
                    try:
                        r = json.loads(ln)
                    except ValueError:
                        continue
                    if not isinstance(r, dict) or now - (r.get("t") or 0) > days * 86400:
                        continue
                    x = rows.setdefault(f"{r.get('method', '')} {r.get('route', '')}", {"s": [], "running": 0, "roles": set()})
                    x["s"].append(float(r.get("s") or 0)); x["running"] = max(x["running"], int(r.get("running") or 0))
                    if r.get("role"):
                        x["roles"].add(r["role"])
        except OSError:
            continue
    out = []
    for k, x in rows.items():
        s = sorted(x["s"])
        out.append({"route": k, "count": len(s), "median": s[len(s) // 2], "slowest": s[-1], "running_max": x["running"],
                    "roles": sorted(x["roles"])})
    return sorted(out, key=lambda r: -r["slowest"])
