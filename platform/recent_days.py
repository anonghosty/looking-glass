"""Older days loaded from the database, kept a few minutes (2026-11-18: an analyst code on an older day loaded that whole
day - 44,252 records, 2.5-5 s - for its page, again for its records and again for each count; the same day three times
in 13 s, and after a restart the Findings page waited 30-45 s).

A day that is not among the days in memory is loaded once and kept for ANALYST_DAY_KEEP_S seconds (default 300): the
page, its records and its counts share it. At most ANALYST_DAY_KEEP days are kept (default 1; 0 = none: every request
loads again, as before), the oldest dropped first: each kept day costs memory, about as much as a day in memory.
A kept day is dropped when the constituency or the stored data change (the version given with it), so it is never
older than what a fresh load would give. Two requests for the same day at once load it once."""
import os
import threading
import time


def _env_int(name, default, lo, hi):
    try:
        return max(lo, min(hi, int(os.environ.get(name, str(default)))))
    except ValueError:
        return default


class RecentDays:
    def __init__(self, keep=None, ttl=None):
        self.keep = _env_int("ANALYST_DAY_KEEP", 1, 0, 7) if keep is None else keep
        self.ttl = _env_int("ANALYST_DAY_KEEP_S", 300, 30, 3600) if ttl is None else ttl
        self.days, self.locks, self.guard = {}, {}, threading.Lock()
        self.loads = 0                                     # how many loads were made (tests, the task monitor)

    def _hit(self, key, version):
        x = self.days.get(key)
        if x and x[1] == version and time.time() - x[0] < self.ttl:
            return x[2]
        return None

    def get(self, key, version, load):
        """The day for key (platform, iso date) at this version, loaded with load() when not kept."""
        if self.keep <= 0:
            self.loads += 1
            return load()
        d = self._hit(key, version)
        if d is not None:
            return d
        with self.guard:
            lock = self.locks.setdefault(key, threading.Lock())
        with lock:
            d = self._hit(key, version)                    # loaded meanwhile by the request this one waited for
            if d is not None:
                return d
            # room is made BEFORE the load, never after: with one day kept, a code spanning many days is still read one
            # day at a time, never two in memory together (review 2026-11-13; tests/check_acodes.py)
            with self.guard:
                self.days.pop(key, None)
                while self.days and len(self.days) >= self.keep:
                    self.days.pop(min(self.days, key=lambda k: self.days[k][0]), None)
            self.loads += 1
            d = load()
            if d is None:
                return None                                # nothing to keep: an unreadable day is asked again later
            with self.guard:
                while self.days and len(self.days) >= self.keep:      # another day kept meanwhile
                    self.days.pop(min(self.days, key=lambda k: self.days[k][0]), None)
                self.days[key] = (time.time(), version, d)
            return d

    def clear(self):
        with self.guard:
            self.days.clear()
