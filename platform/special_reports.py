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


def _in_scope_groups(coll, scope):
    """The same groups as the aggregation below, counted only over the rows inside the constituency (scope(asn, ip)),
    as the platforms count everything else (review of v2026.11.17). A row without an address stays, as elsewhere."""
    acc = {}
    for d in coll.find({}, {"_id": 0, "filename": 1, "ip": 1, "asn": 1, "timestamp": 1}):
        ip = d.get("ip")
        if ip and not scope(d.get("asn"), ip):
            continue
        g = acc.setdefault(d.get("filename"), {"_id": d.get("filename"), "rows": 0, "ips": set(), "first": None, "last": None})
        g["rows"] += 1
        if ip:
            g["ips"].add(ip)
        t = d.get("timestamp")
        if t is not None:
            g["first"] = t if g["first"] is None or str(t) < str(g["first"]) else g["first"]
            g["last"] = t if g["last"] is None or str(t) > str(g["last"]) else g["last"]
    return [{"_id": g["_id"], "rows": g["rows"], "hosts": len(g["ips"]), "first": g["first"], "last": g["last"]} for g in acc.values()]


def listing(db, force=False, scope=None, version=0):
    """Every Special Report file in MongoDB: per collection and per shared date (the file's date prefix), the rows and
    distinct hosts. Counts only, never an address. scope(asn, ip): the constituency when one is set (version: its
    version, part of the cache key), so a CSIRT that set its networks sees only its own part. Cached for TTL seconds.

    Counted in the background, never while a page waits (security review, 2026-11-17: with a constituency set, every
    row of every Special Report is read and filtered here): a request gets the last count straight away (none yet just
    after a start or a change of the constituency: the list then appears on the next visit) and, when it is older than
    TTL, starts one refresh. force=True counts now and waits (the checks)."""
    key = (scope is not None, version)
    with _lock:
        fresh = time.time() - _cache["t"] < TTL and _cache.get("key") == key
        if not force and fresh:
            return list(_cache["rows"])
        if not force:
            rows = list(_cache["rows"]) if _cache.get("key") == key else []
            if not _cache.get("running"):
                _cache["running"] = True
                threading.Thread(target=_refresh, args=(db, scope, key), daemon=True, name="special-reports").start()
            return rows
    return _count(db, scope, key)


def _refresh(db, scope, key):
    try:
        _count(db, scope, key)
    finally:
        with _lock:
            _cache["running"] = False


def _count(db, scope, key):
    out = []
    try:
        names = [n for n in db.list_collection_names() if is_special(n)]
    except Exception:              # noqa: BLE001  (MongoDB unreachable: nothing to list)
        return []
    for name in sorted(names):
        try:
            groups = _in_scope_groups(db[name], scope) if scope is not None else db[name].aggregate([
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
        _cache.update(t=time.time(), rows=out, key=key)
    return list(out)
