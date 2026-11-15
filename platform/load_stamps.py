"""Load stamps: the pipeline marks each report and day it adds rows for (collection lg_load_stamps, written by
shadowserver_pipeline.stamp_loaded). Both platforms' 15-second check reads these marks, one small query, and counts
every report's rows only when a mark moved, or every COUNT_EVERY seconds anyway (review of d82a436: the check counted
every report's rows for up to four days on both platforms, every 15 seconds). Rows removed (retention, a report
deleted by hand) leave no mark: the regular count still finds them. With a pipeline that writes no marks (an older
one), nothing changes: the rows are counted every check, as before.

Stamps(db).of(days) -> a tuple that changes whenever a mark of those days changes; None when there are no marks at all
skip_count(day, stamp, now) -> True when the check may skip counting (same marks, counted recently, nothing pending)
counted(day, stamp, now)     remember what was seen at the last count
"""
import os
import time

COLLECTION = "lg_load_stamps"
COUNT_EVERY = int(os.environ.get("COUNT_EVERY_SECONDS", "600"))
EXISTS_EVERY = 600


class Stamps:
    def __init__(self, db):
        self.db = db
        self._exists = (0.0, False)

    def _there(self):
        at, ok = self._exists
        if time.monotonic() - at > EXISTS_EVERY:
            try:
                ok = COLLECTION in self.db.list_collection_names()
            except Exception:                                  # noqa: BLE001
                ok = False
            self._exists = (time.monotonic(), ok)
        return ok

    def of(self, days):
        if not self._there():
            return None
        try:
            docs = self.db[COLLECTION].find({"day": {"$in": list(days)}}, {"_id": 1, "at": 1, "rows": 1})
            return tuple(sorted((str(d["_id"]), str(d.get("at")), int(d.get("rows") or 0)) for d in docs))
        except Exception:                                      # noqa: BLE001  (counting is the safe answer)
            return None


def skip_count(day, stamp, now):
    return (stamp is not None and getattr(day, "pending", None) is None
            and getattr(day, "stamp", None) == stamp and now - getattr(day, "counted_at", 0) < COUNT_EVERY)


def counted(day, stamp, now):
    day.stamp, day.counted_at = stamp, now
