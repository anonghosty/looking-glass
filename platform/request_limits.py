# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Limits on the heavy views per person (review of d82a436): Looking Glass answers from one process with 8 threads, and
a view with new filters (statistics, map, analysis, drill-down lists, regions) works through the whole day. Without a
limit, one signed-in person (an external viewer too) sending many such requests at once makes everyone else wait.

* At most HEAVY_PER_USER (default 3) heavy requests of one person are worked on at the same time: a page that asks
  for several at once still works (the others wait their turn, up to HEAVY_WAIT_S seconds, default 20), but one person
  can never hold more than that many of the threads. A request that waited too long gets 429 with Retry-After.
* At most HEAVY_PER_MINUTE (default 240) heavy requests per person per minute; more get 429 with Retry-After.
* "A person" is the signed-in account; before sign-in (or with automation) the address.
Generous defaults (limits-for-other-CSIRTs), tunable in .env; 0 switches a limit off. Cached answers count too: the
limit is about how often, not how costly. Counted in the Task monitor (state()).

install(app, heavy_paths, who) -> state dict.  who(): the person's key, or None for no limit.
"""
import collections
import os
import threading
import time

from flask import g, jsonify, request


def _int(name, default):
    try:
        return max(0, int(os.environ.get(name, default)))
    except ValueError:
        return default


def install(app, heavy_paths, who):
    per_user = _int("HEAVY_PER_USER", 3)
    per_minute = _int("HEAVY_PER_MINUTE", 240)
    wait_s = _int("HEAVY_WAIT_S", 20)
    lock = threading.Lock()
    sems = {}
    recent = collections.defaultdict(collections.deque)
    state = {"waited": 0, "refused_busy": 0, "refused_rate": 0, "per_user": per_user, "per_minute": per_minute}
    heavy = tuple(heavy_paths)

    def refuse(msg, retry):
        r = jsonify(error=msg)
        r.status_code = 429
        r.headers["Retry-After"] = str(retry)
        return r

    @app.before_request
    def _heavy_in():
        if request.path not in heavy:
            return None
        key = who()
        if key is None:
            return None
        now = time.monotonic()
        if per_minute:
            with lock:
                q = recent[key]
                while q and now - q[0] > 60:
                    q.popleft()
                if len(q) >= per_minute:
                    state["refused_rate"] += 1
                    return refuse("Too many requests in the last minute: wait a moment, then try again.", 30)
                q.append(now)
                if len(recent) > 5000:                     # forget people who have gone quiet
                    for k in [k for k, v in recent.items() if not v or now - v[-1] > 60][:2500]:
                        recent.pop(k, None)
        if not per_user:
            return None
        with lock:
            sem = sems.get(key)
            if sem is None:
                sem = sems[key] = threading.BoundedSemaphore(per_user)
        if not sem.acquire(blocking=False):
            state["waited"] += 1
            if not sem.acquire(timeout=wait_s):
                state["refused_busy"] += 1
                return refuse("Your other requests are still being worked on: wait for them, then try again.", 5)
        g._heavy_sem = sem
        return None

    @app.teardown_request
    def _heavy_out(_exc=None):
        sem = g.pop("_heavy_sem", None)
        if sem is not None:
            sem.release()

    return state
