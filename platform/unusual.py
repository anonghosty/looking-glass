# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Unusual activity on the page (the user, 2026-11-24, decisions 3a, 4.1a, 4.2a, 5a; renamed from "patterns", the
researchers' word, the same day): the Unusual activity page, its cards and
the Executive portal's "unusual this week" card. unusual_worker.py finds the suggestions (unusual_detect.py).

- Analysts and administrators (the unmasked permission) see every card, the devices behind it, and Confirm or Dismiss.
- Researchers (the definitions permission) see the cards without devices or addresses.
- Management sees only the Executive card: how many unusual threads each day of the week, and the strongest in words.
Confirm makes a suggestion a thread the team watches, by its own name, every day (its chart and today's value against its
normal). Dismiss quiets that thread for DISMISS_DAYS; only a jump to twice the dismissed value brings it back early.
Both are in the audit log. Everything follows the constituency: the worker counts only its devices.
Stored: data/unusual/decisions.json (0600): {"confirmed": {tid: {...}}, "dismissed": {tid: {...}}}.
"""
import json
import os
import re
import threading
import time

from flask import abort, jsonify, render_template, request

import unusual_detect as pd

DISMISS_DAYS = 30
COMEBACK = 2.0                       # a dismissed thread comes back early at this many times its dismissed value
MAX_DEVICES_SHOWN = 500
MAX_CONFIRMED = 200
NAME_RX = re.compile(r"[^\w .,'()&/+\-]+")
TID_RX = re.compile(r"^[0-9a-f]{12}$")


def _read(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class Decisions:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def load(self):
        d = _read(self.path) or {}
        return {"confirmed": d.get("confirmed") or {}, "dismissed": d.get("dismissed") or {}, "learned": d.get("learned") or {}}

    @staticmethod
    def learn(d, reports, what):
        """One decision on a thread of these reports: their bars move a step (unusual_detect.sensitivity)."""
        for r in reports or []:
            x = d["learned"].setdefault(r, {"dismissed": 0, "confirmed": 0})
            x[what] = int(x.get(what, 0)) + 1

    def save(self, d):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, self.path)


def quiet(s, dismissed, now):
    """Is this suggestion quietened by a Dismiss? Until DISMISS_DAYS after it, unless it jumped to COMEBACK times the value
    it had when dismissed."""
    x = dismissed.get(s["id"])
    return bool(x) and now < x.get("until", 0) and s["value"] < COMEBACK * max(1, x.get("value", 0))


def install(app, ctx):
    base = ctx["base_dir"]
    data = os.path.join(base, "data", "unusual")
    has_perm, csrf_ok, audit = ctx["has_perm"], ctx["csrf_ok"], ctx["audit"]
    decisions = Decisions(os.path.join(data, "decisions.json"))
    network = ctx.get("network") or (lambda asn: f"AS{asn}")
    svc_label = ctx.get("svc_label") or (lambda name: name)
    people_name = ctx.get("people_name") or (lambda n: n)

    def titles():
        facts = (_read(os.path.join(base, "data", "report_map.json")) or {}).get("facts") or {}
        return lambda r: (facts.get(r) or {}).get("title") or r

    def me():
        from flask import g
        return (getattr(g, "user", None) or {}).get("user", "")

    def analyst():
        return has_perm("unmasked")

    def reader():
        return analyst() or has_perm("definitions")

    def net_name(asn):
        try:
            n = network(asn)
        except Exception:  # noqa: BLE001
            n = None
        return f"AS{asn}" + (f" {n}" if n and n != f"AS{asn}" else "")

    def summaries():
        out = []
        try:
            for f in sorted(os.listdir(os.path.join(data, "days"))):
                s = _read(os.path.join(data, "days", f)) if f.endswith(".json") else None
                if s and s.get("day"):
                    out.append(s)
        except OSError:
            pass
        return out

    def links(s, platform):
        """Where to look at the thread on the platforms (analysts and administrators only)."""
        if s["kind"] == "pair" or not analyst():
            return []
        r = s["reports"][0]
        if platform == "services":
            q = {"service": svc_label(r)} | ({"asn": s["asn"]} if s["asn"] != "*" else {})
            path = "/services"
        else:
            q = {"source": r} | ({"src_asn": s["asn"]} if s["asn"] != "*" else {})
            path = "/"
        from urllib.parse import urlencode
        return [{"text": "Open on the services platform" if platform == "services" else "Open on the map",
                 "href": f"{path}?{urlencode(q)}"}]

    def card(s, title, plat_of, learned=None):
        c = {k: s.get(k) for k in ("id", "kind", "day", "value", "normal", "ratio", "z", "new", "lift", "first_day", "days_above", "reports")}
        c["asn"] = s.get("asn")
        c["network"] = "the whole constituency" if s.get("asn") in ("*", None) else net_name(s["asn"])
        c["report_names"] = [title(r) for r in s.get("reports") or []]
        c["words"] = pd.words(s, title, net_name)
        c["history"] = [{"day": d, "value": v} for d, v in s.get("history") or []]
        c["links"] = links(s, plat_of(s["reports"][0]) if s.get("reports") else "comms")
        c["learned"] = pd.learned_words(s, learned, title) if learned and s.get("asked_from") is not None else ""
        return c

    def plat_finder(sums):
        plat = {}
        for x in sums:
            for r, v in (x.get("reports") or {}).items():
                plat.setdefault(r, v.get("platform", "comms"))
        return lambda r: plat.get(r, "comms")

    @app.route("/unusual")
    def unusual_page():
        # the analysts' workbench; researchers meet the same suggestions in "Looking Glass asks" on Definitions
        # (decision 1a), through /api/unusual, without devices
        if not analyst():
            abort(403)
        return render_template("unusual.html", can_decide=analyst(), masked=not analyst())

    @app.route("/api/unusual")
    def api_unusual():
        if not reader():
            abort(403)
        st = _read(os.path.join(data, "suggestions.json")) or {}
        dec = decisions.load()
        now = time.time()
        title, sums = titles(), summaries()
        plat_of = plat_finder(sums)
        shown, quieted, growing = [], 0, {}
        for s in st.get("suggestions") or []:
            if s["id"] in dec["confirmed"]:
                # a watched thread well above its normal again today: said on its card
                growing[s["id"]] = pd.words(s, title, net_name)
                continue
            if quiet(s, dec["dismissed"], now):
                quieted += 1
                continue
            shown.append(card(s, title, plat_of, dec["learned"]))
        tracked = []
        cfg = st.get("config") or {"window": 28, "min_history": 7}
        for tid, x in sorted(dec["confirmed"].items(), key=lambda kv: kv[1].get("at", 0), reverse=True):
            ser = pd.series(x["key"], x["kind"], sums)[-(cfg.get("window", 28) + 1):]
            latest = ser[-1] if ser else None
            prior = [v for _, v in ser[:-1]]
            m = pd.normal(prior)[0] if len(prior) >= 3 else None
            s = {"id": tid, "kind": x["kind"], "key": x["key"], "asn": x.get("asn"), "reports": x.get("reports") or [],
                 "value": latest[1] if latest else 0, "normal": round(m, 1) if m is not None else None,
                 "ratio": round((latest[1] if latest else 0) / max(m or 0, 1), 1) if m is not None else None,
                 "new": m == 0, "history": ser, "day": latest[0] if latest else None}
            c = card(dict(s, first_day=next((d for d, v in ser if v > 0), None), days_above=None, lift=None, z=None), title, plat_of)
            c.update(name=x.get("name"), confirmed_by=people_name(x.get("by", "")), confirmed_at=x.get("at"))
            if m is None:
                c["words"] = "Not enough days yet to know its normal."
            c["growing"] = growing.get(tid, "")
            tracked.append(c)
        return jsonify(day=st.get("day"), made=st.get("made"), partial_days=st.get("partial_days") or [],
                       config=st.get("config") or {}, suggestions=shown, quieted=quieted, confirmed=tracked,
                       can_decide=analyst(), masked=not analyst(), ready=bool(st))

    def find(tid):
        st = _read(os.path.join(data, "suggestions.json")) or {}
        for s in st.get("suggestions") or []:
            if s["id"] == tid:
                return s
        for day in (st.get("week") or {}).values():
            for s in day:
                if s["id"] == tid:
                    return s
        return None

    @app.route("/api/unusual/<tid>/devices")
    def api_unusual_devices(tid):
        """The devices behind a card on its day (analysts and administrators): address, network and records."""
        if not analyst():
            abort(403)
        if not TID_RX.match(tid):
            abort(404)
        s = find(tid) or (decisions.load()["confirmed"].get(tid))
        db, settings = ctx.get("db"), ctx.get("settings")
        if not s or db is None:
            abort(404)
        st = _read(os.path.join(data, "suggestions.json")) or {}
        day = s.get("day") or st.get("day")
        reports = s.get("reports") or []
        want_asn = None if s.get("asn") in ("*", None) else str(s["asn"])
        per = []
        for r in reports:
            seen = {}
            for rec in db[r].find({"filename": {"$regex": "^" + re.escape(str(day))}}, pd.FIELDS):
                dev = pd.device_of(rec, settings)
                if dev is None or (want_asn and str(dev[1]) != want_asn):
                    continue
                e = seen.setdefault(dev[0], {"ip": dev[0], "asn": dev[1], "records": 0})
                e["records"] += 1
            per.append(seen)
        common = set(per[0]) if per else set()
        for p in per[1:]:
            common &= set(p)
        rows = sorted(({"ip": ip, "asn": per[0][ip]["asn"], "network": net_name(per[0][ip]["asn"]) if per[0][ip]["asn"] else "",
                        "records": sum(p[ip]["records"] for p in per)} for ip in common), key=lambda x: -x["records"])
        return jsonify(day=day, total=len(rows), devices=rows[:MAX_DEVICES_SHOWN], more=max(0, len(rows) - MAX_DEVICES_SHOWN))

    def guard_write(tid):
        if not analyst():
            abort(403)
        if not csrf_ok():
            return None, (jsonify(error="Refused (sign in again)."), 403)
        if not TID_RX.match(tid):
            abort(404)
        return (request.get_json(silent=True) or {}), None

    @app.route("/api/unusual/<tid>/confirm", methods=["POST"])
    def api_unusual_confirm(tid):
        body, err = guard_write(tid)
        if err:
            return err
        s = find(tid)
        if not s:
            return jsonify(error="This suggestion is no longer on the list."), 404
        name = NAME_RX.sub("", str(body.get("name") or "")).strip()[:80]
        if not name:
            return jsonify(error="Give it a name."), 400
        with decisions.lock:
            d = decisions.load()
            if len(d["confirmed"]) >= MAX_CONFIRMED and tid not in d["confirmed"]:
                return jsonify(error=f"Your team already watches {MAX_CONFIRMED} threads: stop watching one first."), 400
            if tid not in d["confirmed"]:                  # a rename is not a second confirmation
                decisions.learn(d, s.get("reports"), "confirmed")
            d["confirmed"][tid] = {"name": name, "kind": s["kind"], "key": s["key"], "asn": s.get("asn"),
                                   "reports": s.get("reports"), "by": me(), "at": int(time.time()), "day": s.get("day")}
            d["dismissed"].pop(tid, None)
            decisions.save(d)
        audit.add("unusual_confirmed", user=me(), detail=f"{name}: {s['kind']} {s['key']} ({s.get('day')}, {s['value']} devices)")
        return jsonify(ok=True)

    @app.route("/api/unusual/<tid>/dismiss", methods=["POST"])
    def api_unusual_dismiss(tid):
        _body, err = guard_write(tid)
        if err:
            return err
        s = find(tid)
        if not s:
            return jsonify(error="This suggestion is no longer on the list."), 404
        with decisions.lock:
            d = decisions.load()
            d["dismissed"][tid] = {"until": int(time.time()) + DISMISS_DAYS * 86400, "value": s["value"], "by": me(),
                                   "at": int(time.time()), "kind": s["kind"], "key": s["key"]}
            # forget dismissals that have run out, so the file does not grow
            d["dismissed"] = {k: v for k, v in d["dismissed"].items() if v.get("until", 0) > time.time()}
            decisions.learn(d, s.get("reports"), "dismissed")
            decisions.save(d)
        audit.add("unusual_dismissed", user=me(), detail=f"{s['kind']} {s['key']} ({s.get('day')}, {s['value']} devices), "
                                                          f"quiet for {DISMISS_DAYS} days")
        return jsonify(ok=True)

    @app.route("/api/unusual/<tid>/untrack", methods=["POST"])
    def api_unusual_untrack(tid):
        _body, err = guard_write(tid)
        if err:
            return err
        with decisions.lock:
            d = decisions.load()
            x = d["confirmed"].pop(tid, None)
            decisions.save(d)
        if not x:
            return jsonify(error="This thread is not watched."), 404
        audit.add("unusual_untracked", user=me(), detail=f"{x.get('name')}: {x.get('kind')} {x.get('key')}")
        return jsonify(ok=True)

    @app.route("/api/mgmt/unusual-week")
    def api_unusual_week():
        """The Executive card: per day of the last week, how many threads were unusual; the strongest of the latest day
        in words (no address, no device)."""
        if not (has_perm("management") or has_perm("users")):
            abort(403)
        st = _read(os.path.join(data, "suggestions.json")) or {}
        dec = decisions.load()
        now, title = time.time(), titles()
        days = []
        for day, lst in sorted((st.get("week") or {}).items()):
            keep = [s for s in lst if not quiet(s, dec["dismissed"], now)]
            days.append({"day": day, "unusual": len(keep)})
        top = [pd.words(s, title, net_name) for s in (st.get("suggestions") or [])
               if not quiet(s, dec["dismissed"], now) and s["id"] not in dec["confirmed"]][:5]
        return jsonify(ready=bool(st), day=st.get("day"), days=days, top=top, confirmed=len(dec["confirmed"]))

    return {"decisions": decisions, "quiet": quiet}
