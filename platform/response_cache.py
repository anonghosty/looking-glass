"""A short-lived cache for a few heavy read-only answers. With a large amount of data the Definitions services list,
Intel summary and leads and the to-do list take seconds each to compute, and with one web process the other pages
queue behind them when several people work at once.

For the endpoints named in install():
  - an answer is kept for TTL seconds (Settings → Task monitor, else CACHE_TTL_S in .env, default 180; 0 switches the
    cache off). A kept answer is exactly what was computed: only how recent it is changes (new report data shows
    within the time), never whether it is right; a person's own change shows at once;
  - only one request computes an answer at a time: the others get the last one at once instead of queuing (or, when
    there is none yet, wait for it rather than compute it again);
  - any successful change (POST, PUT, DELETE: a definition saved, a note, a mapping) starts a new generation, so the
    next request computes again and nobody sees an answer from before their change;
  - the key holds everything that changes what a person may see: the role, the permissions (masking: researchers and
    external viewers never get an unmasked answer), Peace of mind, and the full address with its query (demo=1).
    Answers that differ per person (Findings, the advisor's dashboard, notifications) are never cached here.
Only answers with status 200 are kept; at most MAX_ENTRIES (the oldest go first).
"""
import functools
import json
import os
import threading
import time
from collections import OrderedDict

MAX_ENTRIES = 200
TTL_MAX = 3600
# the time chosen on Settings → Task monitor (data/performance.json) takes precedence over .env; read when it changes
OVERRIDE = {"path": None, "mtime": None, "ttl": None}


def _override():
    p = OVERRIDE["path"]
    if not p:
        return None
    try:
        m = os.path.getmtime(p)
    except OSError:
        OVERRIDE.update(mtime=None, ttl=None)
        return None
    if m != OVERRIDE["mtime"]:
        try:
            with open(p, encoding="utf-8") as f:
                v = json.load(f).get("cache_ttl_s")
            OVERRIDE.update(mtime=m, ttl=min(TTL_MAX, max(0, int(v))) if isinstance(v, int) and not isinstance(v, bool) else None)
        except (OSError, ValueError, AttributeError, TypeError):
            OVERRIDE.update(mtime=m, ttl=None)
    return OVERRIDE["ttl"]


def env_ttl():
    try:
        return min(TTL_MAX, max(0, int(os.environ.get("CACHE_TTL_S", "180") or 0)))
    except ValueError:
        return 180


def ttl():
    o = _override()
    return env_ttl() if o is None else o


def save_ttl(seconds):
    """Keep the time chosen on Settings → Task monitor (0..TTL_MAX). Returns the value kept."""
    v = min(TTL_MAX, max(0, int(seconds)))
    p = OVERRIDE["path"]
    tmp = p + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"cache_ttl_s": v, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, f)
    os.replace(tmp, p)
    OVERRIDE["mtime"] = None
    return v


class ResponseCache:
    def __init__(self):
        self.gen = 0
        self.entries = OrderedDict()          # key -> (at, gen, status, headers, body)
        self.locks = {}
        self.lock = threading.Lock()
        self.stats = {"hit": 0, "stale": 0, "miss": 0}

    def bump(self):
        with self.lock:
            self.gen += 1

    def _key(self, endpoint):
        from flask import g, request
        u = getattr(g, "user", None) or {}
        return (endpoint, request.full_path, u.get("role", ""), tuple(sorted(u.get("perms", ()) or ())), bool(u.get("peace")))

    def _get(self, key):
        with self.lock:
            e = self.entries.get(key)
            if e:
                self.entries.move_to_end(key)
            return e, self.gen

    def _put(self, key, entry):
        with self.lock:
            self.entries[key] = entry
            self.entries.move_to_end(key)
            while len(self.entries) > MAX_ENTRIES:
                self.entries.popitem(last=False)

    def wrap(self, app, endpoint, live=None):
        """Cache the view registered as `endpoint`. live(): fields recomputed on every answer (cheap, always current),
        merged into a JSON object answer."""
        from flask import Response
        view = app.view_functions[endpoint]

        def answer(entry):
            _at, _gen, status, headers, body = entry
            if live:
                try:
                    d = json.loads(body)
                    if isinstance(d, dict):
                        d.update(live())
                        body = json.dumps(d).encode("utf-8")
                except (ValueError, TypeError):
                    pass
            return Response(body, status=status, headers=headers)

        @functools.wraps(view)
        def cached(*a, **kw):
            limit = ttl()
            if not limit:
                return view(*a, **kw)
            key = self._key(endpoint)
            e, gen = self._get(key)
            if e and e[1] == gen and time.time() - e[0] < limit:
                self.stats["hit"] += 1
                return answer(e)
            with self.lock:
                klock = self.locks.setdefault(key, threading.Lock())
            if e and e[1] == gen and not klock.acquire(blocking=False):
                self.stats["stale"] += 1          # someone is computing it: the last answer now, not a queue
                return answer(e)
            if not (e and e[1] == gen):
                klock.acquire()                     # nothing usable yet: wait for the one computing it
                e2, gen2 = self._get(key)
                if e2 and e2[1] == gen2 and time.time() - e2[0] < limit:
                    klock.release()
                    self.stats["hit"] += 1
                    return answer(e2)
            try:
                self.stats["miss"] += 1
                started_gen = self.gen
                resp = app.make_response(view(*a, **kw))
                if resp.status_code == 200 and not resp.is_streamed and started_gen == self.gen:
                    headers = [(k, v) for k, v in resp.headers.items() if k.lower() not in ("content-length", "set-cookie")]
                    self._put(key, (time.time(), started_gen, 200, headers, resp.get_data()))
                return resp
            finally:
                klock.release()

        app.view_functions[endpoint] = cached


def install(app, endpoints, live=None, data_dir=None):
    """Wrap these endpoints; every successful change starts a new generation. live: {endpoint: fn() -> dict}.
    data_dir: where the time chosen in Settings is kept (performance.json)."""
    from flask import request
    if data_dir:
        OVERRIDE["path"] = os.path.join(data_dir, "performance.json")
    rc = ResponseCache()
    for ep in endpoints:
        if ep in app.view_functions:
            rc.wrap(app, ep, (live or {}).get(ep))

    @app.after_request
    def _cache_new_generation(resp):
        if request.method in ("POST", "PUT", "PATCH", "DELETE") and resp.status_code < 400:
            rc.bump()
        return resp

    return rc
