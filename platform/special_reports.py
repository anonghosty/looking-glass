"""Shadowserver's one-off Special Reports, kept apart from the daily replay (review, 2026-11-13).

Special Reports are not daily reports: Shadowserver shares a one-off dataset (a campaign's victims, a historical botnet,
a newly found exposure) under a file prefix "YYYY-MM-DD-special", where the date is when it was shared, and often with a
placeholder timestamp (midnight of that day) because the exact times are not known. The columns differ from one Special
Report to the next. Replayed like a daily report, a Special Report would put all its rows at 00:00 of one day: a false
spike on the map, in the day's totals, on the Executive portal and in its 7-day comparison.

So:
  * the pipeline loads them like any report, into their own collection ("special", or "special_<name>" when Shadowserver
    gives the special report a name of its own), never quarantined for its name (report_names.canonical in the pipeline);
  * both platforms' report discovery skips them (is_special): no replay, no totals, no baselines;
  * the Overview lists each one apart, with the date it was shared, its rows and its distinct hosts (counts only).

is_special(name) -> bool;  listing(db) -> [{"report", "title", "shared", "rows", "hosts", "first", "last"}]
"""
import re
import time
import threading

_RX = re.compile(r"^special(?:$|[_-])", re.I)
_DATE = re.compile(r"^(\d{4}-\d{2}-\d{2})-")
_cache = {"t": 0.0, "rows": []}
_lock = threading.Lock()
TTL = 600                       # seconds: a listing is cheap, but Special Reports change rarely


def is_special(name):
    """A Special Report's collection: "special", "special_<name>" (or "special-<name>" from an older loader)."""
    return bool(_RX.match(str(name or "")))


def title(name):
    rest = re.sub(r"^special[_-]?", "", str(name), flags=re.I)
    return "Special report" + (f": {rest.replace('_', ' ').replace('-', ' ')}" if rest else "")


def listing(db, force=False):
    """Every Special Report file in MongoDB: per collection and per shared date (the file's date prefix), the rows and
    distinct hosts. Counts only, never an address. Cached for TTL seconds."""
    with _lock:
        if not force and time.time() - _cache["t"] < TTL:
            return list(_cache["rows"])
    out = []
    try:
        names = [n for n in db.list_collection_names() if is_special(n)]
    except Exception:              # noqa: BLE001  (MongoDB unreachable: nothing to list)
        return []
    for name in sorted(names):
        try:
            groups = db[name].aggregate([
                {"$group": {"_id": "$filename", "rows": {"$sum": 1}, "hosts": {"$addToSet": "$ip"},
                            "first": {"$min": "$timestamp"}, "last": {"$max": "$timestamp"}}},
                {"$project": {"rows": 1, "hosts": {"$size": "$hosts"}, "first": 1, "last": 1}},
            ], allowDiskUse=True)
            for gr in groups:
                fn = str(gr.get("_id") or "")
                m = _DATE.match(fn)
                out.append({"report": name, "title": title(name), "shared": m.group(1) if m else "",
                            "rows": int(gr.get("rows") or 0), "hosts": int(gr.get("hosts") or 0),
                            "first": str(gr.get("first") or ""), "last": str(gr.get("last") or "")})
        except Exception:          # noqa: BLE001  (one odd collection never hides the others)
            continue
    out.sort(key=lambda r: (r["shared"], r["report"]), reverse=True)
    with _lock:
        _cache.update(t=time.time(), rows=out)
    return list(out)
