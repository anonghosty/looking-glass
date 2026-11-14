"""Findings over time (user, 2026-11-14): when a finding's records were reported, how many of its devices the latest
report shows again, and closing a finding whose time to act has passed.

    reported    the days the finding's records were reported: a review's kept search (its days with records), an
                analyst code's day(s); a finding opened from a name has none and its opening date stands
    again       of the finding's devices, those in the latest report day for the same combination (a combination code:
                its own exact pattern; an analyst's selection: the same reports). Counts for everyone in the channel;
                the addresses only for the roles that already see them (analysts, advisors, admins)
    expiry      an open finding whose last reported day is more than FINDING_ACT_DAYS days ago (.env, default 30;
                0 = never) is closed: "Time to act expired". The channel sees it in the history and the bell.

Everything heavy (loading past days from MongoDB) runs in one background worker, one finding at a time; the pages
read what is ready and say "counting" until then. Nothing here is written but the finding's reported days and its
closing.
"""
import os
import queue
import threading
import time
from datetime import datetime, timedelta, timezone

from flask import g, jsonify

SYSTEM_USER = "looking-glass"
EXPIRED = "Time to act expired"


def act_days():
    try:
        return max(0, int(os.environ.get("FINDING_ACT_DAYS", "30") or 30))
    except ValueError:
        return 30


def install(app, ctx):
    """ctx: findings (Findings), book (combination codes), acodes, labels(), svc_matcher(entry), comms_matcher(entry),
    stores {"comms","services"}, replay_now(), network(asn), has_perm(p), logger."""
    F, book, hp = ctx["findings"], ctx["book"], ctx["has_perm"]
    log = ctx.get("logger")
    cache, lock = {}, threading.Lock()                # fid -> {"key", "at", "result"}
    work, queued = queue.Queue(), set()

    # ---------------- what a finding is about
    def latest_iso(platform):
        st = ctx["stores"][platform]
        days = sorted(st.days)
        if not days:
            st.get(ctx["replay_now"]())
            days = sorted(st.days)
        return days[-1].date().isoformat() if days else ""

    def subject(x):
        """(platform, hosts, reported days, how to match the latest day) of a finding, or None (a finding from a name)."""
        fid = str(x["id"])
        rv = x.get("review") or {}
        if rv and getattr(book, "review_kept", None) and book.review_kept(fid):
            k, _ = book.review_records(fid)
            if not k:
                return None
            entry, m, plat = k["entry"], k["m"], k["plat"]
            comms = plat == "comms"
            host = m.host if m is not None else ((lambda e: e.get("src_ip") or "") if comms else (lambda e: e.get("ip") or ""))
            evs = k["found"]
            if x.get("network"):                       # one organisation's sub-finding: its own devices only
                asn = (lambda e: e.get("src_asn")) if comms else (lambda e: e.get("asn"))
                evs = [e for e in evs if (ctx["network"](asn(e)) or "") == x["network"]]
            days = sorted(d for d, n in k["per_day"] if n)
            return {"platform": plat, "hosts": {host(e) for e in evs if host(e)}, "days": days, "entry": entry,
                    "reports": {e.get("source") if comms else e.get("report") for e in evs}}
        for c in x.get("codes") or []:
            entry = book.get(c) if str(c).startswith("LG-A-") else None
            if not entry or entry.get("kind") != "a":
                continue
            evs = ctx["acodes"].records(entry)
            comms = entry["platform"] == "comms"
            host = (lambda e: e.get("src_ip") or "") if comms else (lambda e: e.get("ip") or "")
            return {"platform": entry["platform"], "hosts": {host(e) for e in evs if host(e)},
                    "days": sorted(entry.get("days") or [entry["day"]]), "entry": entry,
                    "reports": {e.get("source") if comms else e.get("report") for e in evs}}
        return None

    def latest_hosts(s):
        """The hosts of the latest day that match what the finding is about."""
        st = ctx["stores"][s["platform"]]
        day = st.get(ctx["replay_now"]())
        comms = s["platform"] == "comms"
        if s["entry"].get("kind") in ("r", "x"):
            m = ctx["comms_matcher"](s["entry"]) if comms else ctx["svc_matcher"](s["entry"])
            return {m.host(e) for e in m.match(day.events) if m.host(e)}, day.start.date().isoformat()
        rep = (lambda e: e.get("source")) if comms else (lambda e: e.get("report"))
        host = (lambda e: e.get("src_ip") or "") if comms else (lambda e: e.get("ip") or "")
        return {host(e) for e in day.events if rep(e) in s["reports"] and host(e)}, day.start.date().isoformat()

    def compute(x):
        s = subject(x)
        if not s:
            return {"state": "none"}
        latest = latest_iso(s["platform"])
        out = {"state": "ready", "reported_first": s["days"][0] if s["days"] else "", "reported_last": s["days"][-1] if s["days"] else "",
               "latest": latest, "devices": len(s["hosts"])}
        if s["days"] and s["days"][-1] >= latest:
            out.update(again=None, again_ips=[])        # reported in the latest report itself: nothing to compare yet
            return out
        now, latest = latest_hosts(s)
        again = sorted(s["hosts"] & now)
        out.update(latest=latest, again=len(again), again_ips=again)
        return out

    def key_of(x):
        return (x["history"][-1]["at"], tuple(x.get("codes") or []), latest_iso_quick())

    def latest_iso_quick():
        try:
            return max(max(st.days).date().isoformat() for st in ctx["stores"].values() if st.days)
        except ValueError:
            return ""

    def worker():
        while True:
            fid = work.get()
            try:
                x = F.get(fid)
                if x:
                    res = compute(x)
                    with lock:
                        cache[fid] = {"key": key_of(x), "at": time.time(), "result": res}
                    if res.get("reported_last"):
                        F.set_reported(fid, res["reported_first"], res["reported_last"])
            except Exception:                              # noqa: BLE001  (one finding never stops the others)
                if log:
                    log.exception("finding %s: reported days / repeats not worked out", fid)
                with lock:
                    cache[fid] = {"key": None, "at": time.time(), "result": {"state": "error"}}
            finally:
                with lock:
                    queued.discard(fid)

    threading.Thread(target=worker, daemon=True, name="finding-watch").start()

    def result(fid):
        """What is ready for this finding; queues it when missing or stale."""
        x = F.get(fid)
        if not x:
            return None
        with lock:
            hit = cache.get(fid)
            fresh = hit and hit["key"] == key_of(x)
            if not fresh and fid not in queued:
                queued.add(fid); work.put(fid)
        if hit and hit["result"].get("state") != "error":
            return dict(hit["result"], stale=not fresh)
        return {"state": "counting"}

    # ---------------- time to act
    def act_until(x):
        n = act_days()
        if not n:
            return ""
        rep = (x.get("reported") or {}).get("last")
        base = datetime.fromisoformat(rep).replace(tzinfo=timezone.utc) if rep else datetime.fromtimestamp(x["at"], timezone.utc)
        return (base + timedelta(days=n)).date().isoformat()

    def expire_due():
        """Close every open finding whose time to act has passed. Returns the numbers closed."""
        n = act_days()
        if not n:
            return []
        today = datetime.now(timezone.utc).date().isoformat()
        out = []
        for x in F.all_open():
            until = act_until(x)
            if until and until < today:
                rep = (x.get("reported") or {}).get("last")
                why = (f"{EXPIRED}: its records were reported on {rep}, more than {n} days ago." if rep else
                       f"{EXPIRED}: opened more than {n} days ago.")
                if F.expire(x["id"], why, SYSTEM_USER):
                    out.append(x["id"])
        return out

    def loop():
        time.sleep(120)                                    # let the service load its days first
        while True:
            try:
                for x in F.all_open():
                    result(str(x["id"]))                   # reported days and repeats, worked out in the background
                closed = expire_due()
                if closed and log:
                    log.info("findings closed, time to act expired: %s", ", ".join(f"#{i}" for i in closed))
            except Exception:                              # noqa: BLE001
                if log:
                    log.exception("finding watch")
            time.sleep(1800)

    if not ctx.get("no_loop"):
        threading.Thread(target=loop, daemon=True, name="finding-expiry").start()

    # ---------------- routes
    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def sees_addresses():
        return bool((hp("unmasked") and hp("export")) or hp("advisory") or hp("settings"))

    def visible(fid):
        x = F.get(fid)
        team = hp("definitions") or hp("management") or hp("settings") or (hp("unmasked") and hp("export")) or hp("advisory")
        return x if x and F.sees(x, me()[0], hp("settings"), strict=not team) else None

    @app.route("/api/findings/watch")
    def api_findings_watch():
        """For each finding this user sees: reported days, time to act, and how many devices are in the latest report
        again (counts only: no address)."""
        if not me()[0]:
            return jsonify(error="Sign in first."), 403
        out = {}
        for x in F.visible(me()[0], hp("settings"), strict=not (hp("definitions") or hp("management") or hp("settings")
                                                              or (hp("unmasked") and hp("export")) or hp("advisory"))):
            fid = str(x["id"])
            r = result(fid) if x["status"] in F.OPEN or (x.get("reported") or {}).get("last") else {"state": "none"}
            out[fid] = {k: v for k, v in (r or {}).items() if k != "again_ips"} | {
                "act_days": act_days(), "act_until": act_until(x) if x["status"] in F.OPEN else "",
                "reported_first": (x.get("reported") or {}).get("first", "") or (r or {}).get("reported_first", ""),
                "reported_last": (x.get("reported") or {}).get("last", "") or (r or {}).get("reported_last", "")}
        return jsonify(findings=out)

    @app.route("/api/findings/<fid>/again")
    def api_findings_again(fid):
        """The addresses of a finding's devices in the latest report again: for the roles that see addresses."""
        if not sees_addresses():
            return jsonify(error="The addresses are for analysts, advisors and administrators."), 403
        x = visible(str(fid)[:12])
        if not x:
            return jsonify(error="No such finding."), 404
        r = result(str(x["id"]))
        return jsonify(r or {"state": "none"})

    class Api:
        pass
    api = Api()
    api.result, api.expire_due, api.act_until, api.compute = result, expire_due, act_until, compute
    return api
