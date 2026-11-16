"""A spike (or a drop) on the Overview's buttons: the latest report day against the day before, per platform, with what
is behind it (the user, 2026-11-16). Counts only, straight from MongoDB: no host, address or network name.

Communications: every report of the map's registry, by extracted_date; the cause is the infections that changed most.
Services: every report of the services registry; the cause is the reports that changed most.

A day is a spike when it has at least SPIKE_RATIO times the day before (default 1.5) and at least SPIKE_MIN_EVENTS more
records (default 500); a drop the other way round. Worked out at most every SPIKE_CACHE_SECONDS (default 600) per day.

A spike in one report (services) or one infection (communications) is noticed too when the total is steady (scope
"part"), so big steady reports never hide one that jumped.

GET /api/overview/spikes -> {comms: {...}, services: {...}}; each: {day, before_day, today, before, change, kind
("spike" | "drop" | ""), scope ("all" | "part" | ""), causes: [{what, report, before, today}]}. For the roles whose Overview buttons show it:
the platforms ('view'), management, researchers ('definitions') and admins. Installed from app.py.
"""
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
MAX_CAUSES = 3


def _q(start):
    """Records of one UTC day (extracted_date stored as a date or as an ISO string, as the pipeline writes it)."""
    end = start + timedelta(days=1)
    return {"$or": [{"extracted_date": {"$gte": start, "$lt": end}},
                    {"extracted_date": {"$gte": start.strftime("%Y-%m-%dT"), "$lt": end.strftime("%Y-%m-%dT")}}]}


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


def _rows(db, per, start, prev, by_infection):
    """What moved: each infection with its report (communications) or each report (services), today and the day before."""
    if not by_infection:
        return [{"what": p["label"], "report": "", "today": p["today"], "before": p["before"]} for p in per]
    rows = []
    for p in per:
        count = {}
        for when, key in ((start, "today"), (prev, "before")):
            for r in db[p["name"]].aggregate([{"$match": _q(when)}, {"$group": {"_id": "$infection", "n": {"$sum": 1}}}]):
                count.setdefault(r["_id"] or "unknown", {"today": 0, "before": 0})[key] = r["n"]
        rows += [{"what": k, "report": p["label"], **v} for k, v in count.items()]
    return rows


def compare(db, sources, start, by_infection=False):
    """{today, before, change, kind, scope, causes} for these reports (registry rows {name, label}) on the day starting
    at start. scope "all": the platform's total moved, and causes are what moved it most. scope "part": the total is
    steady but one report (services) or one infection (communications) moved on its own; causes are those."""
    prev = start - timedelta(days=1)
    per = []
    for s in sources:
        c = db[s["name"]]
        t, b = c.count_documents(_q(start)), c.count_documents(_q(prev))
        if t or b:
            per.append({"name": s["name"], "label": s.get("label") or s["name"], "today": t, "before": b})
    today, before = sum(p["today"] for p in per), sum(p["before"] for p in per)
    kind, scope, causes = kind_of(today, before), "", []
    rows = _rows(db, per, start, prev, by_infection) if per else []
    if kind:
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
            "change": change_of(today, before), "kind": kind, "scope": scope, "causes": causes}


class Spikes:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.cache = {}

    def get(self):
        out = {}
        for platform, sources, by_inf in (("comms", self.ctx["comms_sources"], True), ("services", self.ctx["svc_sources"], False)):
            start = self.ctx["day_of"](platform)
            if start is None:
                continue
            key = (platform, start.date().isoformat())
            with self.lock:
                hit = self.cache.get(key)
            if hit and time.time() - hit[0] < CACHE_S:
                out[platform] = hit[1]
                continue
            try:
                res = compare(self.ctx["db"], sources(), start, by_infection=by_inf)
            except Exception:                    # noqa: BLE001  (the buttons simply show no notice)
                continue
            with self.lock:
                self.cache = {k: v for k, v in self.cache.items() if k[0] != platform}   # one day per platform kept
                self.cache[key] = (time.time(), res)
            out[platform] = res
        return out


def install(app, ctx):
    """ctx: db, comms_sources() and svc_sources() (registry rows), day_of(platform) -> the replay day's UTC midnight,
    has_perm(p)."""
    sp = Spikes(ctx)
    hp = ctx["has_perm"]

    @app.route("/api/overview/spikes")
    def api_overview_spikes():
        if not (hp("view") or hp("management") or hp("definitions") or hp("settings")):
            return jsonify(error="Not for this role."), 403
        return jsonify(sp.get())

    return sp
