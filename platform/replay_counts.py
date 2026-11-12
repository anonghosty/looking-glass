"""How many of a selection's records have been replayed, worked out once per loaded day and selection.

The map and the services page ask every 2-3 seconds, per open tab, how many of the selected records the replay has
reached, how many there are in all, when the next one comes and how many hosts they are on. With a filter set, each of
those questions went through the whole day again (external review, 2026-11-12: about 75-90 ms per poll on a real day).
Now the matching records of a day and selection are found once and kept, in replay order, with their times; each poll
is then a binary search. The key names the loaded day (respcache.day_key: a reload with new rows changes it) and the
selection, so a new report or another filter is worked out afresh; the answers are exactly the ones before.
Used by app.py (/api/replayed) and services_api.py (/api/svc/replayed).
"""
import bisect

from respcache import ResultCache, day_key


class ReplayCounts:
    def __init__(self, size=64):
        self.cache = ResultCache(size=size)

    def of(self, day, selection_key, pred, host):
        """{keys, events, hosts} of the day's records that match pred, in the day's order. day.keys[i] is the replay
        time of day.events[i] (sorted); host(e) is the record's host, counted when it is not empty."""
        def compute():
            idx = [i for i, e in enumerate(day.events) if pred(e)]
            return {"keys": [day.keys[i] for i in idx], "events": [day.events[i] for i in idx],
                    "hosts": len({h for h in (host(day.events[i]) for i in idx) if h})}
        return self.cache.get((day_key(day), selection_key), compute)

    @staticmethod
    def at(m, t):
        """(records replayed by time t, the next record after t or None)."""
        n = bisect.bisect_right(m["keys"], t)
        return n, (m["events"][n] if n < len(m["events"]) else None)
