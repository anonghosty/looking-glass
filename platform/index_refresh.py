# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Counting indexes worked out again behind the page, never while a person waits (the user, 2026-11-17).

Intel gathered (intel.py) and the services patterns (services_intel.py) count every record of the report day in
Python: about 22 s the first time after a start (the beacon decoder reads every request line), about 3 s each later
time. Measured with MongoDB's own command timing, that work is all Python, no query. warmup.py already counts
them in the background when the days change, but a request in the window before it (or after the hourly expiry, which
warmup does not see) counted the whole day again itself, and waited for it.

Gate.serve, used by both indexes:
- counts that are current are served as they are;
- counts that are out of date are served at once while ONE background thread works them out again, then replaced;
- with no counts yet, the first request counts and the others wait for that count, never starting a second one.
Background mode is on in the running service (gunicorn, the same test as app.py's _SERVING) and off in the checks,
which rely on counting at once; the tests switch it on to test it.

A count that fails (a record no rule expected, say) never takes the page or the service down: it is written to the
service log, kept in `last_error` (Settings → Task monitor shows it), and the earlier counts are served meanwhile. It is
not tried again for RETRY_SECONDS, so a count that keeps failing does not run over and over. With no earlier counts to
show, the request that counted gets the error, as before."""
import logging
import os
import sys
import threading
import time

SERVING = "gunicorn" in os.path.basename(sys.argv[0] if sys.argv else "")
RETRY_SECONDS = 30
log = logging.getLogger("looking-glass")
GATES = []                                       # every gate (the task monitor)


class Gate:
    def __init__(self, name):
        self.name = name
        self.background = SERVING
        self.lock = threading.Lock()
        self.busy = {}                           # scope -> threading.Event of the count running for it
        self.runs = 0                            # counts done (tests, the task monitor)
        self.failures = 0
        self.failed_at = {}                      # scope -> time of its last failed count
        self.last_error = None                   # (time, scope, "ErrorType: message") of the last failure
        self.last_seconds = None                 # how long the last count took
        GATES.append(self)

    def serve(self, sk, fresh, stale, build):
        """fresh: the current counts or None; stale: earlier counts or None; build(cached_only=False): works them out and
        stores them (cached_only: only the stored counts if current, else None). Returns the counts to answer with."""
        if fresh is not None:
            return fresh
        with self.lock:
            ev = self.busy.get(sk)
            if stale is not None and ev is None and time.time() - self.failed_at.get(sk, 0) < RETRY_SECONDS:
                return stale                     # failed a moment ago: the earlier counts, no new try yet
            mine = ev is None
            if mine:
                ev = self.busy[sk] = threading.Event()
        if self.background and stale is not None:
            if mine:                             # one recount at a time, behind the page
                threading.Thread(target=self._quiet, args=(sk, ev, build), daemon=True, name=f"{self.name}-{sk}").start()
            return stale
        if not mine:                             # a count is running: wait for it rather than count twice
            ev.wait(600)
            got = build(cached_only=True)
            if got is not None:
                return got
            if stale is not None:                # that count failed: the earlier counts rather than a second try now
                return stale
            return build()
        try:
            return self._run(sk, ev, build)
        except Exception:                        # noqa: BLE001  (logged in _run)
            if stale is not None:
                return stale
            raise

    def _quiet(self, sk, ev, build):
        try:
            self._run(sk, ev, build)
        except Exception:                        # noqa: BLE001  (logged in _run; the earlier counts stay)
            pass

    def _run(self, sk, ev, build):
        t0 = time.perf_counter()
        try:
            out = build()
            self.runs += 1
            self.last_seconds = round(time.perf_counter() - t0, 2)
            with self.lock:
                self.failed_at.pop(sk, None)
                if self.last_error and self.last_error[1] == sk:
                    self.last_error = None          # counted again since: no longer an alert (failures keeps the tally)
            return out
        except Exception as e:
            self.failures += 1
            with self.lock:
                self.failed_at[sk] = time.time()
            self.last_error = (time.time(), sk, f"{type(e).__name__}: {e}"[:300])
            log.exception("%s: counting %s failed; the earlier counts are kept", self.name, sk)
            raise
        finally:
            with self.lock:
                self.busy.pop(sk, None)
            ev.set()


def status():
    """For the task monitor: per gate, counts done, failures, the last error and how long the last count took."""
    return [{"name": g.name, "runs": g.runs, "failures": g.failures, "last_seconds": g.last_seconds,
             "last_error": None if not g.last_error else {"at": g.last_error[0], "scope": g.last_error[1],
                                                          "error": g.last_error[2]}} for g in GATES]
