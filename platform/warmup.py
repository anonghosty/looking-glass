# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Warm-up: the heavy summaries of the Definitions page are worked out in the background, not by the first person who
opens it (speed review, 2026-11-15: on the first visit after a start, or after the days changed, the page waited 14 s
for Intel gathered and over 15 s for the services definitions, and its loading logo stayed 21 s).

Every CHECK_SECONDS a background thread looks at which copies of the days are in memory (both platforms). When they
differ from the ones it last warmed (a start, a new report, the hourly refresh), it runs each job in turn: each job is
one of the existing cached functions (Intel gathered's index, the services definitions' figures, the sinkholes per
report, the names' evidence), so the next request finds its answer ready. Nothing new is computed and nothing is sent
anywhere: the same answers, earlier. A job that fails is logged and tried again at the next change.

install(ctx) -> the state dict (for the Task monitor and tests). ctx: stores() -> [store, ...] (objects with .days),
jobs -> [(label, callable)], logger, check_seconds (optional), start (default True: start the thread).
"""
import threading
import time

CHECK_SECONDS = 30


def days_key(stores):
    """Which copies of the days are in memory: (start, serial, rows) of every loaded day of every store."""
    out = []
    for s in stores:
        for k, d in sorted(list(getattr(s, "days", {}).items())):
            out.append((str(k), getattr(d, "serial", 0), len(getattr(d, "events", ()) or ())))
    return tuple(out)


def run_once(ctx, state):
    """Warm every job if the days changed since the last warm-up. Returns True when it ran the jobs."""
    key = days_key(ctx["stores"]())
    if not key or key == state.get("key"):
        return False
    t0 = time.time()
    done, failed = [], []
    for label, job in ctx["jobs"]:
        t = time.time()
        try:
            job()
            done.append((label, round(time.time() - t, 1)))
        except Exception as e:                                # noqa: BLE001  (logged; tried again at the next change)
            failed.append((label, type(e).__name__))
            if ctx.get("logger"):
                ctx["logger"].warning("Warm-up: %s failed: %s", label, e)
    state.update(key=key, at=time.time(), took=round(time.time() - t0, 1), done=done, failed=failed, runs=state.get("runs", 0) + 1)
    if ctx.get("logger"):
        ctx["logger"].warning("Warm-up after a change of the days in memory: %s in %.1fs", ", ".join(f"{a} {b}s" for a, b in done) or "nothing",
                              time.time() - t0)
    return True


def install(ctx):
    state = {"key": None, "at": 0.0, "runs": 0}
    if not ctx.get("start", True):
        return state

    def loop():
        time.sleep(ctx.get("first_delay", 20))           # let the start-up load the days first
        while True:
            try:
                run_once(ctx, state)
            except Exception:                                 # noqa: BLE001
                if ctx.get("logger"):
                    ctx["logger"].exception("Warm-up check failed")
            time.sleep(ctx.get("check_seconds", CHECK_SECONDS))

    threading.Thread(target=loop, name="warmup", daemon=True).start()
    return state
