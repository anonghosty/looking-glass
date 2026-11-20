"""Results that every viewer shares, computed once per change of the data.

The statistics, filter lists and overview are worked out from the whole replay day in memory. Many screens ask for the
same ones every few seconds, so each result is kept under a key that names everything it depends on: the loaded day
(its start, the moment it was loaded and its version, which changes whenever MongoDB has new or different rows), the
filters, demo mode, the constituency and the network names. When a new report arrives the day is reloaded, the key
changes and the next request recomputes from the fresh data; nothing is ever served from an older day.

When several requests for the same key come in at once, one computes and the others wait for its result instead of
repeating the work. Values are treated as read-only by the callers (they copy before adding per-request fields).
"""
import os
import threading
from collections import OrderedDict


class ResultCache:
    def __init__(self, size=256, wait_seconds=300):
        self.size, self.wait = size, wait_seconds
        self.data = OrderedDict()
        self.inflight = {}
        self.lock = threading.Lock()
        self.hits = self.misses = 0

    def get(self, key, compute):
        with self.lock:
            if key in self.data:
                self.data.move_to_end(key)
                self.hits += 1
                return self.data[key]
            ev = self.inflight.get(key)
            leader = ev is None
            if leader:
                ev = self.inflight[key] = threading.Event()
        if not leader:
            ev.wait(self.wait)
            with self.lock:
                if key in self.data:
                    self.hits += 1
                    return self.data[key]
            return compute()                      # the leader failed or took too long: work it out here
        try:
            value = compute()
            with self.lock:
                self.misses += 1
                self.data[key] = value
                while len(self.data) > self.size:
                    self.data.popitem(last=False)
            return value
        finally:
            with self.lock:
                self.inflight.pop(key, None)
            ev.set()

    def clear(self):
        with self.lock:
            self.data.clear()


SETTLE_MAX_SECONDS = int(os.environ.get("SETTLE_MAX_SECONDS", "120"))


def settled(day, sig, now):
    """New row counts for a loaded day: reload now? Yes when the same new counts were seen at the previous check (the
    pipeline has finished with this day for now), or SETTLE_MAX_SECONDS after the first change (a long run still shows
    its progress every couple of minutes). Otherwise the change is remembered on the day (day.pending) and it waits.
    Shared by both platforms' day stores (speed review, 2026-11-15)."""
    p = getattr(day, "pending", None)
    if p is None:
        day.pending = {"sig": dict(sig), "since": now}
        return False
    if p["sig"] == sig or now - p["since"] >= SETTLE_MAX_SECONDS:
        day.pending = None
        return True
    p["sig"] = dict(sig)
    return False


def day_key(day):
    """Identity of one loaded copy of a day: a reload (new rows, a changed constituency, the hourly refresh) makes a
    new copy with a new serial; a copy kept because MongoDB still holds the same rows keeps its key, so cached answers
    stay valid (speed review, 2026-11-15: they were thrown away every 10 minutes)."""
    return (day.start, getattr(day, "serial", None) or getattr(day, "loaded_at", 0), getattr(day, "version", ""), len(day.events))


def filters_key(flt):
    """{field: set(values)} -> a hashable, order-independent key. A hidden filter ("_…", worked out from the others and
    the day, such as the devices carrying every ticked infection) counts by its presence only: the day's key and the
    other filters name its values (and a set of thousands of devices is not sorted for every request)."""
    return tuple(sorted((k, ("*",) if str(k).startswith("_") else tuple(sorted(map(str, v)))) for k, v in (flt or {}).items()))
