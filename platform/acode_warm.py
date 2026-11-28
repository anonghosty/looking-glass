# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The analyst codes' device counts worked out ahead, after a start (2026-11-18: right after a restart, the Findings page
waited 30-45 s for four codes' counts, each loading a whole older day from the database).

ANALYST_WARM_DELAY_S seconds after the service starts (default 30, so the days in memory are loaded first; 0 = off),
one background thread counts every analyst code the open findings carry, at both viewer levels (acodes.api.warm). Only
in the running service (index_refresh.SERVING): a check or a tool importing the app never starts it.
Installed from features.py: acode_warm.install(app, {"acodes": ACODES, "logger": ...})."""
import os
import threading
import time

import index_refresh


def delay():
    try:
        return max(0, min(600, int(os.environ.get("ANALYST_WARM_DELAY_S", "30"))))
    except ValueError:
        return 30


def install(app, ctx):
    api, log = ctx["acodes"], ctx.get("logger")
    state = {"started": False, "done": None, "made": 0, "seconds": None}

    def run():
        t = time.time()
        try:
            state["made"] = api.warm()
        except Exception:                                  # noqa: BLE001  (a failure only means the first open waits)
            if log:
                log.exception("Analyst code counts: not worked out ahead")
        state["seconds"], state["done"] = round(time.time() - t, 1), time.time()
        if log:
            log.warning("Analyst code counts worked out ahead: %s in %ss", state["made"], state["seconds"])

    d = delay()
    if index_refresh.SERVING and d > 0 and hasattr(api, "warm"):
        state["started"] = True
        timer = threading.Timer(d, run)
        timer.daemon = True                                # never holds the service up at a stop (audit 2026-11-27, 1-11)
        timer.name = "acode-warm"
        timer.start()
    return state
