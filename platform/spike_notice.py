"""A spike (or a drop) on the Overview's buttons: the latest report day against the day before, per platform, with what
is behind it (the user, 2026-11-16). Counts only: no host, address or network name.

A day is counted exactly as its platform shows it (external review of v2026.11.17): the rows of the files dated that
day or the next (the indexed file-name prefix), whose event time falls in that day, inside the constituency (Settings)
when one is set. Never by a scan of a report's whole history: extracted_date has no index, and counting by it read every
record ever kept (about 7 s, on a page request). A day already in the platform's memory is counted from there.

Communications: the cause is the infections that changed most. Services: the reports that changed most.

A day is a spike when it has at least SPIKE_RATIO times the day before (default 1.5) and at least SPIKE_MIN_EVENTS more
records (default 500); a drop the other way round. A spike in one report (services) or one infection (communications)
is noticed too when the total is steady (scope "part"), so big steady reports never hide one that jumped.

A day still arriving is not compared: while it has fewer than SPIKE_COMPLETE_SHARE (default 0.8) of the reports the day
before had, the answer says so (complete false, with both report counts) and gives no notice, so the morning's first
report is never read as a drop.

Worked out in the background, never while a page waits: a request gets the last answer for the replay day (or none
yet) and, when it is older than SPIKE_CACHE_SECONDS (default 600), starts one refresh. A refresh first compares the
rows per report (cheap indexed counts) and the constituency's version with the last time, and counts again only when
something changed.

GET /api/overview/spikes -> {comms: {...}, services: {...}}; each: {day, before_day, today, before, change, kind
("spike" | "drop" | ""), scope ("all" | "part" | ""), causes: [{what, report, before, today}]}. For the roles whose
Overview buttons show it: the platforms ('view'), management, researchers ('definitions') and admins. Installed from
features.py.
"""
import collections
import os
import threading
import time
from datetime import timedelta

from flask import jsonify


def _env(name, default, cast):
    try:
        return cast(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


RATIO = _env("SPIKE_RATIO", 1.5, float)
MIN_EVENTS = _env("SPIKE_MIN_EVENTS", 500, int)
CACHE_S = _env("SPIKE_CACHE_SECONDS", 600, int)
# a day still arriving is not compared: no notice until it has at least this share of the reports the day before had
# (2026-11-17: the replay began a day when one report of about 50 had come in, and the notice read "drop")
COMPLETE_SHARE = _env("SPIKE_COMPLETE_SHARE", 0.8, float)
MAX_CAUSES = 3
DAY = timedelta(days=1)


def kind_of(today, before, ratio=None, min_events=None):
    ratio = RATIO if ratio is None else ratio
    min_events = MIN_EVENTS if min_events is None else min_events
    if today - before >= min_events and today >= before * ratio:
        return "spike"
    if before - today >= min_events and before >= today * ratio:
        return "drop"
    return ""


def change_of(today, before):
    return round((today - before) / before * 100) if before else None


def count_day(p, start):
    """{report: Counter(infection -> rows)} of one day, as the platform shows it. p: the platform's parts (see
    install). A day the platform holds in memory, loaded under the same constituency, is counted from there; any other
    is read report by report through the platform's own day reader (indexed file-name prefix, event time in the day),
    then the constituency is applied as the platform applies it."""
    by_inf = p.get("by_infection")
    tally = lambda rows: collections.Counter((e.get("infection") or "unknown") if by_inf else "" for e in rows)  # noqa: E731
    held = p["loaded"](start) if p.get("loaded") else None
    if held is not None:
        return {name: tally(rows) for name, rows in held.items() if rows}
    out = {}
    for s in p["sources"]():
        rows, _ = p["fetch"](s, start, start + DAY)
        keep = p.get("in_scope")
        if keep is not None:
            rows = [e for e in rows if keep(e)]
        if rows:
            out[s["name"]] = tally(rows)
    return out


def compare(today_counts, before_counts, labels, start, by_infection=False):
    """{day, before_day, today, before, change, kind, scope, causes} from two days' counts ({report: Counter}). scope
    "all": the platform's total moved, and causes are what moved it most. scope "part": the total is steady but one
    report (services) or one infection (communications) moved on its own; causes are those."""
    prev = start - DAY
    names = sorted(set(today_counts) | set(before_counts))
    today = sum(sum(today_counts.get(n, {}).values()) for n in names)
    before = sum(sum(before_counts.get(n, {}).values()) for n in names)
    rows = []
    for n in names:
        t, b = today_counts.get(n, collections.Counter()), before_counts.get(n, collections.Counter())
        if by_infection:
            rows += [{"what": k, "report": labels.get(n, n), "today": t.get(k, 0), "before": b.get(k, 0)} for k in sorted(set(t) | set(b))]
        else:
            rows.append({"what": labels.get(n, n), "report": "", "today": sum(t.values()), "before": sum(b.values())})
    n_today = sum(1 for n in names if sum(today_counts.get(n, {}).values()))
    n_before = sum(1 for n in names if sum(before_counts.get(n, {}).values()))
    complete = n_today >= n_before * COMPLETE_SHARE
    kind, scope, causes = (kind_of(today, before) if complete else ""), "", []
    if not complete:
        pass                                   # still arriving: no notice yet, and no cause
    elif kind:
        scope = "all"
        sign = 1 if kind == "spike" else -1
        total = abs(today - before)
        # only what moved the same way, and noticeably (a tenth of the change or more)
        causes = sorted((r for r in rows if sign * (r["today"] - r["before"]) > 0 and abs(r["today"] - r["before"]) * 10 >= total),
                        key=lambda r: -abs(r["today"] - r["before"]))[:MAX_CAUSES]
    else:
        parts = [r for r in rows if kind_of(r["today"], r["before"])]
        if parts:
            parts.sort(key=lambda r: -abs(r["today"] - r["before"]))
            kind, scope = kind_of(parts[0]["today"], parts[0]["before"]), "part"
            causes = [r for r in parts if kind_of(r["today"], r["before"]) == kind][:MAX_CAUSES]
    return {"day": start.date().isoformat(), "before_day": prev.date().isoformat(), "today": today, "before": before,
            "change": change_of(today, before), "kind": kind, "scope": scope, "causes": causes,
            "complete": complete, "reports": n_today, "reports_before": n_before}


class Spikes:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.cache = {}          # platform -> {"day", "key", "at", "res"}
        self.running = set()     # platforms with a refresh under way (one at a time each)

    def _key(self, p, start):
        """What the answer depends on: the rows per report of both days (cheap indexed counts) and the constituency."""
        sig = lambda d: tuple(sorted((p["signature"](d) or {}).items()))     # noqa: E731
        return sig(start), sig(start - DAY), p["version"]() if p.get("version") else 0

    def refresh(self, platform, start):
        """Works one platform's answer out (in a background thread; tests call it directly)."""
        p = self.ctx["platforms"][platform]
        try:
            key = self._key(p, start)
            with self.lock:
                hit = self.cache.get(platform)
                if hit and hit["day"] == start and hit["key"] == key:
                    hit["at"] = time.time()           # nothing changed: the answer stands
                    return hit["res"]
            labels = {s["name"]: s.get("label") or s["name"] for s in p["sources"]()}
            res = compare(count_day(p, start), count_day(p, start - DAY), labels, start, by_infection=p.get("by_infection", False))
            with self.lock:
                self.cache[platform] = {"day": start, "key": key, "at": time.time(), "res": res}
            return res
        except Exception:                             # noqa: BLE001  (the buttons simply show no notice)
            log = self.ctx.get("logger")
            if log:
                log.exception("Spike notice: %s could not be worked out", platform)
            return None
        finally:
            with self.lock:
                self.running.discard(platform)

    def get(self, wait=False):
        """The answers for the replay day. Never counts while a page waits (wait=True only for tests)."""
        out = {}
        for platform in self.ctx["platforms"]:
            start = self.ctx["day_of"](platform)
            if start is None:
                continue
            with self.lock:
                hit = self.cache.get(platform)
                fresh = hit is not None and hit["day"] == start
                if fresh:
                    out[platform] = hit["res"]
                due = not fresh or time.time() - hit["at"] >= CACHE_S
                start_now = due and platform not in self.running
                if start_now:
                    self.running.add(platform)
            if start_now:
                if wait:
                    res = self.refresh(platform, start)
                    if res is not None:
                        out[platform] = res
                else:
                    threading.Thread(target=self.refresh, args=(platform, start), daemon=True,
                                     name=f"spikes-{platform}").start()
        return out


def install(app, ctx):
    """ctx: platforms {"comms" | "services": {sources(), signature(start), fetch(src, start, end) -> (rows, last),
    loaded(start) -> {report: rows} or None, in_scope(row) or None, version(), by_infection}}, day_of(platform) -> the
    replay day's UTC midnight, has_perm(p), logger."""
    sp = Spikes(ctx)
    hp = ctx["has_perm"]

    @app.route("/api/overview/spikes")
    def api_overview_spikes():
        if not (hp("view") or hp("management") or hp("definitions") or hp("settings")):
            return jsonify(error="Not for this role."), 403
        return jsonify(sp.get())

    return sp
