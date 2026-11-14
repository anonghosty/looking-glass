"""Who is using the service, and what each request costs (Settings → Task monitor: Processes and Users).

Every request is tracked while it runs: its route pattern (never an address or query text), the account and role once
the sign-in check has run, when it started, and the CPU time its thread used. When it ends, the account's totals over
the last WINDOW_S (15 minutes) are updated: requests, seconds spent answering, CPU seconds, the slowest, the last page.
Kept in memory only (nothing written), for the administrators' monitor; the account name and role are shown, as on
the Admin page, never an address.

install(app) is called twice: start() before the other modules (it times the whole request), tag() after the sign-in
check (it knows the account then).
"""
import itertools
import threading
import time
from collections import defaultdict, deque

WINDOW_S = 15 * 60
MAX_PER_USER = 2000
_LOCK = threading.Lock()
_IDS = itertools.count(1)
RUNNING = {}                                   # id -> {route, method, user, role, t0, cpu0, thread}
DONE = defaultdict(deque)                      # user -> deque of (end time, seconds, cpu seconds, route, status)
META = {}                                      # user -> {role}


def _thread_cpu():
    try:
        return time.thread_time()
    except (AttributeError, OSError):
        return 0.0


def install_start(app):
    from flask import g, request

    @app.before_request
    def _rt_start():
        rid = next(_IDS)
        g._rt_id = rid
        with _LOCK:
            RUNNING[rid] = {"route": request.url_rule.rule if request.url_rule is not None else "(no route)",
                            "method": request.method, "user": "", "role": "", "t0": time.time(),
                            "cpu0": _thread_cpu(), "thread": threading.get_ident()}

    @app.teardown_request
    def _rt_end(exc=None):
        rid = getattr(g, "_rt_id", None)
        if rid is None:
            return
        g._rt_id = None
        u = getattr(g, "user", None) or {}
        with _LOCK:
            r = RUNNING.pop(rid, None)
            if not r:
                return
            user = (u.get("user") if isinstance(u, dict) else "") or r["user"] or ""
            if not user:
                return                                  # sign-in pages, static files: no account to count
            now = time.time()
            d = DONE[user]
            d.append((now, now - r["t0"], max(0.0, _thread_cpu() - r["cpu0"]), r["route"], getattr(g, "_rt_status", 0)))
            while d and (now - d[0][0] > WINDOW_S or len(d) > MAX_PER_USER):
                d.popleft()
            META[user] = {"role": (u.get("role") if isinstance(u, dict) else "") or r["role"]}

    @app.after_request
    def _rt_status(resp):
        g._rt_status = resp.status_code
        return resp


def install_tag(app):
    """After the sign-in check: the running request now knows its account."""
    from flask import g

    @app.before_request
    def _rt_tag():
        rid = getattr(g, "_rt_id", None)
        u = getattr(g, "user", None) or {}
        if rid is None or not isinstance(u, dict):
            return
        with _LOCK:
            r = RUNNING.get(rid)
            if r:
                r["user"], r["role"] = u.get("user", "") or ("automation" if u.get("automation") else ""), u.get("role", "")


def processes(now=None):
    """The requests running now, longest first: [{route, method, user, role, seconds}] (CPU so far is only known
    for the thread asking, so it is not shown for others)."""
    now = now or time.time()
    with _LOCK:
        rows = [{"route": r["route"], "method": r["method"], "user": r["user"] or "(signing in)", "role": r["role"],
                 "seconds": round(now - r["t0"], 1)} for r in RUNNING.values()]
    return sorted(rows, key=lambda r: -r["seconds"])


def users(now=None):
    """Per account over the last WINDOW_S: requests, seconds answering, CPU seconds, slowest, running now, last page
    and when; heaviest (seconds answering) first."""
    now = now or time.time()
    out = []
    with _LOCK:
        running = defaultdict(int)
        for r in RUNNING.values():
            if r["user"]:
                running[r["user"]] += 1
        for user, d in list(DONE.items()):
            rows = [x for x in d if now - x[0] <= WINDOW_S]
            if not rows and not running.get(user):
                continue
            last = rows[-1] if rows else None
            slow = max(rows, key=lambda x: x[1]) if rows else None
            out.append({"user": user, "role": META.get(user, {}).get("role", ""), "requests": len(rows),
                        "seconds": round(sum(x[1] for x in rows), 1), "cpu_seconds": round(sum(x[2] for x in rows), 1),
                        "slowest": round(slow[1], 1) if slow else 0, "slowest_route": slow[3] if slow else "",
                        "running": running.get(user, 0), "last_route": last[3] if last else "",
                        "last_ago": round(now - last[0]) if last else None,
                        "errors": sum(1 for x in rows if (x[4] or 0) >= 500)})
        for user, n in running.items():
            if user not in DONE:
                out.append({"user": user, "role": "", "requests": 0, "seconds": 0, "cpu_seconds": 0, "slowest": 0,
                            "slowest_route": "", "running": n, "last_route": "", "last_ago": None, "errors": 0})
    total = sum(x["seconds"] for x in out) or 1
    for x in out:
        x["share"] = round(100 * x["seconds"] / total)
    return sorted(out, key=lambda x: (-x["seconds"], -x["running"]))
