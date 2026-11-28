# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""How many of a selection's records have been replayed, worked out once per loaded day and selection.

The map and the services page ask every 2-3 seconds, per open tab, how many of the selected records the replay has
reached, how many there are in all, when the next one comes and how many hosts they are on. With a filter set, each of
those questions went through the whole day again (external review, 2026-11-12: about 75-90 ms per poll on a real day).
Now the matching records of a day and selection are found once and kept, in replay order, with their times; each poll
is then a binary search. The key names the loaded day (respcache.day_key: a reload with new rows changes it) and the
selection, so a new report or another filter is worked out afresh; the answers are exactly the ones before.

What is kept per selection is only the positions of its records in the day, 4 bytes each (audit 2026-11-27: two full
lists per selection, 64 selections, came to about 1 GB on a day of a million records); the times and records are read
from the day itself when asked, and nothing holds an older copy of a day in memory.
Used by app.py (/api/replayed) and services_api.py (/api/svc/replayed).
"""
import bisect
from array import array

from respcache import ResultCache, day_key

SIZE = 32


class _Picked:
    """The records (or times) of a day at the kept positions, as a read-only list: len(), [i] and bisect work on it."""
    __slots__ = ("src", "idx")

    def __init__(self, src, idx):
        self.src, self.idx = src, idx

    def __len__(self):
        return len(self.idx)

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self.src[j] for j in self.idx[i]]
        return self.src[self.idx[i]]

    def __iter__(self):
        return (self.src[j] for j in self.idx)


class ReplayCounts:
    def __init__(self, size=SIZE):
        self.cache = ResultCache(size=size)

    def of(self, day, selection_key, pred, host):
        """{keys, events, hosts} of the day's records that match pred, in the day's order. day.keys[i] is the replay
        time of day.events[i] (sorted); host(e) is the record's host, counted when it is not empty."""
        def compute():
            idx = array("I" if len(day.events) < 2 ** 32 else "Q", (i for i, e in enumerate(day.events) if pred(e)))
            return idx, len({h for h in (host(day.events[i]) for i in idx) if h})
        idx, hosts = self.cache.get((day_key(day), selection_key), compute)
        return {"keys": _Picked(day.keys, idx), "events": _Picked(day.events, idx), "hosts": hosts}

    @staticmethod
    def at(m, t):
        """(records replayed by time t, the next record after t or None)."""
        n = bisect.bisect_right(m["keys"], t)
        return n, (m["events"][n] if n < len(m["events"]) else None)
