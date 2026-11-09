"""Results that every viewer shares, computed once per change of the data.

The statistics, filter lists and overview are worked out from the whole replay day in memory. Many screens ask for the
same ones every few seconds, so each result is kept under a key that names everything it depends on: the loaded day
(its start, the moment it was loaded and its version, which changes whenever MongoDB has new or different rows), the
filters, demo mode, the constituency and the network names. When a new report arrives the day is reloaded, the key
changes and the next request recomputes from the fresh data; nothing is ever served from an older day.

When several requests for the same key come in at once, one computes and the others wait for its result instead of
repeating the work. Values are treated as read-only by the callers (they copy before adding per-request fields).
"""
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


def day_key(day):
    """Identity of one loaded day: a reload (new rows, a changed constituency, the periodic refresh) changes it."""
    return (day.start, getattr(day, "loaded_at", 0), getattr(day, "version", ""), len(day.events))


def filters_key(flt):
    """{field: set(values)} -> a hashable, order-independent key."""
    return tuple(sorted((k, tuple(sorted(map(str, v)))) for k, v in (flt or {}).items()))
