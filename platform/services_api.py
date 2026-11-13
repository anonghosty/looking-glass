"""HTTP API of the publicly accessible / vulnerable services platform (/services, /api/svc/...).

Same replay schedule as the map (one day, replayed from 00:00), same filter model (every list and chart value is
a filter), same demo masking. Registered from app.py with `register(app, ctx)`.
"""
import bisect
import csvsafe
import io
import os
import time
import urllib.parse
from collections import Counter
from datetime import timedelta

from flask import Response, jsonify, render_template, request
from werkzeug.datastructures import MultiDict

import masked_fields
from privacy import mask_ip
from respcache import ResultCache, day_key
from replay_counts import ReplayCounts
from services import (BANNER, banner_mask, EMPTY,FAMILIES, FILTER_KEYS, SEV_ORDER, ServiceRegistry, ServiceStore, matches, parse_filters,
                       parse_time, report_info)

DRILL_LIMIT = 300
# the request parameters that can change an answer: the filters and the view's own. Cache keys are built from these
# only, so a parameter nothing reads (&x=random) cannot make every request a new cache entry (external review, 2026-11-12)
KEY_PARAMS = frozenset(FILTER_KEYS) | {"cross", "multi", "time", "metric", "kind", "from", "to", "limit", "latest", "all", "id"}


def cache_args(args, drop=()):
    return tuple(sorted((k, v) for k, v in args.items(multi=True) if k in KEY_PARAMS and k not in drop))


def register(app, ctx):
    db, schedule, asns, refs, log = ctx["db"], ctx["schedule"], ctx["asns"], ctx["refs"], app.logger
    is_demo, replay_now, parse_iso, iso, utcnow = ctx["is_demo"], ctx["replay_now"], ctx["parse_iso"], ctx["iso"], ctx["utcnow"]
    registry = ServiceRegistry(db, exclude=ctx["exclude"], ttl=ctx["registry_ttl"], logger=log, fallback_scan=ctx["fallback"])
    store = ServiceStore(db, registry, refs, log, reload_seconds=ctx["reload_seconds"], fallback_scan=ctx["fallback"],
                         settings=ctx.get("settings"))
    svc_cache = ResultCache()       # whole-day statistics shared by every viewer, keyed on the loaded day
    replay_counts = ReplayCounts()  # the replayed counter of a selection, polled every few seconds (replay_counts.py)

    # ------------------------------------------------------------------ helpers
    country_upper = {"t": 0.0, "v": ""}

    def region_unknown(v):
        """Shadowserver writes the country name (for example GHANA) when only the country is known.
        The country name is looked up at most once a second (this runs for every record)."""
        now = time.monotonic()
        if now - country_upper["t"] > 1:
            country_upper.update(t=now, v=ctx["country_name"]().upper())
        return not v or v.upper() == country_upper["v"]

    def region_label(v):
        return "Region unknown" if region_unknown(v) else v.title()

    # network (company) names, looked up once per AS number: the registry check per record made lists slow
    net_cache = {"stamp": None, "checked": 0.0, "map": {}}

    def network(e, demo):
        a = e["asn"]
        if not a:
            return ""
        now = time.time()
        if now - net_cache["checked"] > 30:          # the registry file is re-checked at most every 30 s
            net_cache["checked"] = now
            try:
                stamp = os.path.getmtime(asns.path)
            except OSError:
                stamp = None
            if stamp != net_cache["stamp"]:
                net_cache.update(stamp=stamp, map={})
        v = net_cache["map"].get((a, demo))
        if v is None:
            v = net_cache["map"][(a, demo)] = asns.company(a, demo)
        return v

    def public(e, demo, full=False):
        out = {k: v for k, v in e.items() if k not in ("_t", "extras")}
        out["network"] = asns.label(e["asn"], demo) if e["asn"] else ""
        if demo:
            out["ip"] = mask_ip(e["ip"])
            out["hostname"] = "hidden" if e["hostname"] else ""
            out["asn"] = ""
            for k in BANNER:            # banners can carry the host's own name or address (review 2026-11-13)
                out[k] = banner_mask(out.get(k) or "")
            out["demo"] = True
        if full:
            ex = e.get("extras") or {}
            if demo:      # an allowlist (masked_fields.py): unknown and identifying fields are hidden, the rest masked
                out["extras"], out["extras_hidden"] = masked_fields.service_extras(ex)
            else:
                out["extras"] = ex
        return out

    def day_for(at=None):
        return store.get(parse_iso(at, replay_now()) if at else replay_now())

    def day_host_reports(day):
        """ip -> reports (services) the host is in on the whole day; cached per loaded day."""
        cache = getattr(day, "_host_reports", None)
        if cache is None:
            cache = {}
            for e in day.events:
                cache.setdefault(e["ip"], set()).add(e["service"])
            day._host_reports = cache
        return cache

    def day_host_issues(day):
        """ip -> issues the host has on the whole day, in any report; cached per loaded day. 'Hosts with multiple
        issues' counts these, so a Block List host with an old SSH server and an exposed admin panel elsewhere counts."""
        cache = getattr(day, "_host_issues", None)
        if cache is None:
            cache = {}
            for e in day.events:
                if e["issues"]:
                    cache.setdefault(e["ip"], set()).update(e["issues"])
            day._host_issues = cache
        return cache

    # host attributes: they describe the host, not one record, so they stay when a selection is widened to the
    # hosts' other reports
    HOST_KEYS = {"region", "city", "asn", "sector", "geo", "ip", "hostname"}
    scope_cache = {}

    def split_cross(args):
        """(filters that choose the hosts, filters applied to the hosts' widened records) for cross=...

        cross=1                     legacy: every filter chooses the hosts; the view keeps only host filters
        cross=seed:<k=v&k=v...>     the listed filters chose the hosts (they were set when "Hosts in several reports"
                                    was switched on); every OTHER filter narrows the widened view. So Blocklisted +
                                    several reports, then the Accessible HTTP bubble = the Accessible HTTP records of
                                    the blocklisted hosts that are in several reports (what the bubble counted)."""
        # the seed can travel on either widening flag (several reports / multiple issues)
        val = next((v for v in (args.get("cross") or "", args.get("multi") or "") if v.startswith("seed:")), "")
        items = [(k, v) for k, v in args.items(multi=True) if k not in ("cross", "multi", "at", "time", "from", "to", "limit", "latest", "n", "demo", "metric", "all", "kind")]
        if not val.startswith("seed:"):
            return parse_filters(args, refs, asns), {k: v for k, v in parse_filters(args, refs, asns).items() if k in HOST_KEYS}
        seed = urllib.parse.parse_qsl(val[5:], keep_blank_values=False)
        rest = list(items)
        for p in seed:               # each seed pair once; what is left was added after the switch
            if p in rest:
                rest.remove(p)
        seed_flt = parse_filters(MultiDict(seed), refs, asns)
        view_flt = parse_filters(MultiDict(rest), refs, asns)
        # host attributes of the seed (region, network ...) describe the hosts: they also limit the widened view
        for k, v in seed_flt.items():
            if k in HOST_KEYS and k not in view_flt:
                view_flt[k] = v
        return seed_flt, view_flt

    def scope(day, args):
        """Which records a request covers, as a predicate (None = every record of the day).

        Both host figures compare the selected hosts against ALL their reports of the day, then show those hosts with
        ALL their records (every report), narrowed only by filters added afterwards (see split_cross):
        cross (Hosts in several reports): hosts chosen by the selection that appear in more than one report. So
          'DNS Open Resolvers + Hosts in several reports' shows those resolvers' other exposed services too.
        multi (Hosts with multiple issues): hosts chosen by the selection that carry more than one issue across all
          their reports. So 'Block List + Hosts with multiple issues' shows blocklisted hosts with, for example, an old
          SSH server and an exposed admin panel elsewhere, with those records."""
        flt = parse_filters(args, refs, asns)
        on = lambda v: (v or "0") not in ("0", "")
        cross, multi = on(args.get("cross")), on(args.get("multi"))
        if not cross and not multi:
            return (lambda e: matches(e, flt)) if flt else None
        seed_flt, view_flt = split_cross(args)
        # a masked viewer's banner filter matches differently: its kind is part of the key
        key = (id(day), day.version, cross, multi, tuple(sorted((k, type(v).__name__, tuple(sorted(map(str, v)))) for k, v in seed_flt.items())))
        ips = scope_cache.get(key)
        if ips is None:
            ips = {e["ip"] for e in day.events if matches(e, seed_flt)}
            if multi:
                hi = day_host_issues(day)
                ips = {ip for ip in ips if len(hi.get(ip, ())) > 1}
            if cross:
                hr = day_host_reports(day)
                ips = {ip for ip in ips if len(hr.get(ip, ())) > 1}
            if len(scope_cache) > 64:
                scope_cache.clear()
            scope_cache[key] = ips
        return lambda e: e["ip"] in ips and matches(e, view_flt)

    def selection(args):
        """(day, whole-day events in scope, the time window if any)."""
        day = day_for(args.get("at"))
        pred = scope(day, args)
        evs = [e for e in day.events if pred(e)] if pred else day.events
        tw = parse_time(args.get("time"))
        if tw:
            t0 = day.start.timestamp()
            evs = [e for e in evs if t0 + tw[0] <= e["_t"] < t0 + tw[1]]
        return day, evs, tw

    def top(evs, key, demo, n=10, label=None):
        c = Counter()
        hosts = {}
        for e in evs:
            vals = key(e)
            for v in (vals if isinstance(vals, list) else [vals]):
                c[v] += 1
                hosts.setdefault(v, set()).add(e["ip"])
        rows = []
        for v, k in c.most_common(n if n else None):
            rows.append({"value": v if v != "" else "", "label": (label(v) if label else v) or "", "count": k, "hosts": len(hosts[v])})
        return rows

    def breakdowns(evs, demo, n=10):
        empty = lambda k: (lambda v: v or EMPTY.get(k, "unknown"))
        b = banner_mask if demo else (lambda v: v)
        return {
            "service": top(evs, lambda e: e["service"], demo, n),
            "family": top(evs, lambda e: e["family"], demo, n),
            "severity": sorted(top(evs, lambda e: e["severity"], demo, 0, empty("severity")), key=lambda r: SEV_ORDER.get(r["value"], 9)),
            "issue": top(evs, lambda e: e["issues"], demo, n),
            "tag": top(evs, lambda e: e["tags"], demo, n),
            "port": top(evs, lambda e: e["port"], demo, n),
            "network": [r for r in top(evs, lambda e: network(e, demo), demo, n) if r["value"]],
            "city": top(evs, lambda e: e["city"], demo, n, lambda v: (v or "unknown city").title()),
            "vendor": [r for r in top(evs, lambda e: b(e["vendor"]), demo, n) if r["value"]],
            "device_type": [r for r in top(evs, lambda e: b(e["device_type"]), demo, n) if r["value"]],
            "product": [r for r in top(evs, lambda e: b(e["product"]), demo, n) if r["value"]],
            "sector": [r for r in top(evs, lambda e: e["sector"], demo, n) if r["value"]],
            "protocol": [r for r in top(evs, lambda e: e["protocol"], demo, n) if r["value"]],
            "region": [r for r in top(evs, lambda e: e["region"], demo, n, region_label) if r["value"]],
        }

    def hours_by_family(evs, day):
        out = {}
        t0 = day.start.timestamp()
        for e in evs:
            arr = out.setdefault(e["family"], [0] * 24)
            arr[min(23, max(0, int((e["_t"] - t0) // 3600)))] += 1
        return out

    def severity_rows(evs):
        c = Counter(e["severity"] or "unrated" for e in evs)
        return sorted(({"value": k, "count": v} for k, v in c.items()), key=lambda r: SEV_ORDER.get(r["value"], 9))

    def host_profile(evs, whole):
        """Per host in the selection: records, issues, services; plus reports the host is in on the whole day."""
        sel = {}
        for e in evs:
            h = sel.setdefault(e["ip"], {"events": 0, "issues": set(), "services": set(), "crit": 0, "e": e, "t0": e["_t"], "t1": e["_t"]})
            h["events"] += 1; h["issues"].update(e["issues"]); h["services"].add(e["service"]); h["crit"] += e["severity"] == "critical"
            h["t0"] = min(h["t0"], e["_t"]); h["t1"] = max(h["t1"], e["_t"])
        day_reports = {}
        for e in whole:
            if e["ip"] in sel:
                day_reports.setdefault(e["ip"], set()).add(e["service"])
        return sel, day_reports

    def quarters(evs, day):
        q = [0] * 96
        t0 = day.start.timestamp()
        for e in evs:
            q[min(95, max(0, int((e["_t"] - t0) // 900)))] += 1
        return q

    def kpis(evs):
        hosts = {e["ip"] for e in evs}
        return {"total": len(evs), "hosts": len(hosts),
                "critical": sum(1 for e in evs if e["severity"] == "critical"),
                "high": sum(1 for e in evs if e["severity"] == "high"),
                "vulnerable": sum(1 for e in evs if e["vulnerable"]),
                "vulnerable_hosts": len({e["ip"] for e in evs if e["vulnerable"]}),
                "services": len({e["report"] for e in evs}),
                "networks": len({e["asn"] for e in evs if e["asn"]}),
                "cities": len({e["city"] for e in evs if e["city"]})}

    def host_rows(evs, demo, limit=DRILL_LIMIT):
        by = {}
        for e in evs:
            h = by.get(e["ip"])
            if h is None:
                h = by[e["ip"]] = {"e": e, "events": 0, "services": set(), "ports": set(), "issues": set(), "worst": 9,
                                   "t0": e["_t"], "t1": e["_t"], "crit": 0}
            h["events"] += 1; h["services"].add(e["service"]); h["ports"].add(e["port"]); h["issues"].update(e["issues"])
            h["worst"] = min(h["worst"], SEV_ORDER.get(e["severity"], 9)); h["t1"] = max(h["t1"], e["_t"]); h["t0"] = min(h["t0"], e["_t"])
            h["crit"] += e["severity"] == "critical"
        inv = {v: k for k, v in SEV_ORDER.items()}
        rows = []
        for ip, h in by.items():
            e = h["e"]
            score = 3 * bool(h["issues"]) + 2 * (h["worst"] <= 1) + min(3, len(h["services"]) - 1)
            rows.append({"ref": e["ip_ref"], "ip": mask_ip(ip) if demo else ip, "events": h["events"],
                         "services": sorted(h["services"]), "ports": sorted(p for p in h["ports"] if p),
                         "issues": sorted(h["issues"]), "severity": inv.get(h["worst"], ""),
                         "city": (e["city"] or "").title(), "network": asns.label(e["asn"], demo) if e["asn"] else "",
                         "vendor": banner_mask(e["vendor"]) if demo else e["vendor"],
                         "product": banner_mask(e["product"]) if demo else e["product"], "score": score,
                         "first": iso_t(h["t0"]), "last": iso_t(h["t1"])})
        rows.sort(key=lambda r: (-r["score"], -len(r["issues"]), -r["events"]))
        return rows if limit is None else rows[:limit], len(rows)

    from datetime import datetime, timezone

    def iso_t(t):
        return datetime.fromtimestamp(t, timezone.utc).isoformat().replace("+00:00", "Z")

    # ------------------------------------------------------------------ background (called from app's schedule loop)
    def tick(days):
        registry.check()
        for d in days:
            store.get(d)
            store.check(d)

    # ------------------------------------------------------------------ routes
    @app.route("/services")
    def services_page():
        return render_template("services.html", offset_hours=ctx["offset_hours"])

    @app.route("/api/svc/clock")
    def svc_clock():
        st = schedule.status()
        start = parse_iso(st["day_start"], replay_now())
        day = store.days.get(start)
        labels = {s["name"]: s["label"] for s in registry.items}
        reports = sorted(({"source": n, "label": labels.get(n, n), "rows": r, "arrived_at": day.arrived.get(n)}
                          for n, r in (day.per_source.items() if day else [])), key=lambda x: -x["rows"])
        return jsonify(server_now=iso(utcnow()), sources=len(registry.items), data_version=day.version if day else "0",
                       day_total=len(day.events) if day else 0, reports=reports,
                       report_changes=store.changes.get(start, [])[-20:], sources_version=registry.version,
                       new_sources=registry.added[-10:], unsupported=len(registry.unsupported),
                       # the display time zone on the replay day (Settings > Country; timezones.py)
                       tz=(ctx["settings"].tz(start + timedelta(hours=12)) if ctx.get("settings") else None), **st)

    @app.route("/api/svc/events")
    def svc_events():
        demo = is_demo()
        rn = replay_now()
        t_to = parse_iso(request.args.get("to"), rn)
        t_from = parse_iso(request.args.get("from"), t_to - timedelta(seconds=10))
        if t_to - t_from > timedelta(minutes=30):
            t_from = t_to - timedelta(minutes=30)
        try:                     # a limit that is not a number: the default (review 2026-11-13: it answered 500)
            limit = max(1, min(int(request.args.get("limit", 300) or 300), 2000))
        except (TypeError, ValueError):
            limit = 300
        if request.args.get("latest") == "1":
            # the most recent `limit` matching records of the replay day up to `to`, however long ago (a filtered
            # stream, e.g. Block List whose records all came at 01:00-03:00, is never empty once they have replayed)
            day = store.get(store.day_start(t_to))
            pred = scope(day, request.args)
            hi = bisect.bisect_left(day.keys, t_to.timestamp())
            if pred is None:                     # no filter: the last `limit` records, without copying the whole day
                out, total = day.events[max(0, hi - limit):hi], hi
            else:
                matched = [e for e in day.events[:hi] if pred(e)]
                out, total = matched[-limit:], len(matched)
            return jsonify(events=[public(e, demo) for e in out], total=total, returned=len(out), sampled=False)
        out = []
        d = store.day_start(t_from)
        while d < t_to:
            day = store.get(d)
            pred = scope(day, request.args)
            lo = bisect.bisect_left(day.keys, t_from.timestamp())
            hi = bisect.bisect_left(day.keys, t_to.timestamp())
            out.extend(e for e in day.events[lo:hi] if pred is None or pred(e))
            d += timedelta(days=1)
        total = len(out)
        if total > limit:
            step = total / limit
            out = [out[int(i * step)] for i in range(limit)]
        return jsonify(events=[public(e, demo) for e in out], total=total, returned=len(out), sampled=total > limit)

    @app.route("/api/svc/detail")
    def svc_detail():
        demo = is_demo()
        eid = request.args.get("id", "")
        day = day_for(request.args.get("at"))
        e = next((x for x in day.events if x["id"] == eid), None)
        if not e:
            return jsonify(error="not found"), 404
        same = [x for x in day.events if x["ip"] == e["ip"]]
        return jsonify(event=public(e, demo, full=True), host_records=len(same),
                       host_services=sorted({x["service"] for x in same}))

    @app.route("/api/svc/replayed")
    def svc_replayed():
        day = day_for(request.args.get("at"))
        at = parse_iso(request.args.get("at"), replay_now()).timestamp()
        pred = scope(day, request.args)
        if pred:      # a selection: its records found once per loaded day and kept (replay_counts.py), then a binary search
            # masked or not is part of the key: a masked viewer's filters resolve differently (a real network name
            # matches nothing for them), so the same words are a different selection
            sel_key = (is_demo(), cache_args(request.args))
            m = replay_counts.of(day, sel_key, pred, lambda e: e["ip"])
            done, nxt = replay_counts.at(m, at)
            total, hosts = len(m["keys"]), m["hosts"]
        else:
            hi = bisect.bisect_right(day.keys, at)
            done, total, hosts = hi, len(day.events), None
            # the next record after the replay position, so an empty stream can say when something will appear
            nxt = day.events[hi] if hi < len(day.events) else None
        return jsonify(replayed=done, total=total, day=day.start.date().isoformat(), next_at=iso_t(nxt["_t"]) if nxt else None, hosts=hosts)

    @app.route("/api/svc/stats")
    def svc_stats():
        demo = is_demo()
        try:
            n = max(5, min(int(request.args.get("n", 8)), 200))
        except ValueError:
            n = 8
        day = day_for(request.args.get("at"))
        # shared by every viewer of the same selection, until the day is reloaded (see respcache.py)
        args = cache_args(request.args)
        key = ("svc_stats", day_key(day), demo, n, registry.version, asns.mtime, args)
        return jsonify(svc_cache.get(key, lambda: svc_stats_core(request.args, demo, n)))

    def svc_stats_core(args, demo, n):
        day, evs, _ = selection(args)
        sel, day_reports = host_profile(evs, day.events)
        return dict(day=day.start.date().isoformat(), **kpis(evs), reports_with_data=len(day.per_source),
                    reports_monitored=len(registry.items), quarters=quarters(evs, day),
                    hours_by_family=hours_by_family(evs, day), severity=severity_rows(evs),
                    cross_report_hosts=sum(1 for ip in sel if len(day_reports.get(ip, ())) > 1),
                    multi_issue_hosts=sum(1 for ip in sel if len(day_host_issues(day).get(ip, ())) > 1),
                    breakdowns=breakdowns(evs, demo, n))

    facets_cache = {}

    @app.route("/api/svc/facets")
    def svc_facets():
        demo = is_demo()
        day = day_for(request.args.get("at"))
        # whole-day lists only change when the day is reloaded: cached per day version, demo mode and country
        key = (day.start, day.version, demo, ctx["country_name"]())
        b = facets_cache.get(key)
        if b is None:
            b = breakdowns(day.events, demo, 400)
            # masked and unmasked viewers each keep their own lists (review 2026-11-13: one entry only, so the two
            # kinds of viewer worked the whole day out again for each other, request after request)
            try:
                while len(facets_cache) >= 4:
                    facets_cache.pop(next(iter(facets_cache)))
            except (StopIteration, KeyError, RuntimeError):      # another request trimmed it at the same moment
                facets_cache.clear()
            facets_cache[key] = b
        return jsonify(day=day.start.date().isoformat(), total=len(day.events), facets=b,
                       reports=[{"name": s["name"], "label": s["label"], "family": s["family"],
                                 "rows": day.per_source.get(s["name"], 0), "warnings": s["diagnostic"]["warnings"]}
                                for s in sorted(registry.items, key=lambda s: (-day.per_source.get(s["name"], 0), s["label"]))],
                       unsupported=[{"name": s["name"], "label": s["label"], "missing": s["diagnostic"]["missing"]}
                                    for s in registry.unsupported])

    # the analysis, its drill-down lists and the regions map: worked out once per loaded day and selection, then shared
    # (external review, 2026-11-12: the analysis took about 1.4 s on every request, holding up everyone else). Kept
    # apart from svc_cache, and smaller: a drill-down list can be large. "Show all" lists (downloads) are not kept.
    view_cache = ResultCache(size=64)

    def view_key(name, args, demo):
        day = day_for(args.get("at"))
        return (name, day_key(day), demo, registry.version, asns.mtime, ctx["country_name"](), cache_args(args))

    @app.route("/api/svc/insight")
    def svc_insight():
        """Analysis of any selection, in the same shape as the map platform's analysis: figures (each with a
        drill-down list), key findings, composition donuts, hour / 15-minute charts, severity, breakdowns, hosts."""
        demo = is_demo()
        args = request.args
        out = view_cache.get(view_key("insight", args, demo), lambda: svc_insight_core(args, demo))
        # the one per-request field: the replay moment it was asked at (the rest depends on the day and selection only)
        return jsonify(dict(out, as_of=iso(parse_iso(args.get("at"), replay_now()))))

    def svc_insight_core(args, demo):
        day, evs, tw = selection(args)
        k = kpis(evs)
        sel, day_reports = host_profile(evs, day.events)
        day_issues = day_host_issues(day)
        multi_issue = sum(1 for ip in sel if len(day_issues.get(ip, ())) > 1)
        cross = sum(1 for ip in sel if len(day_reports.get(ip, ())) > 1)
        b = breakdowns(evs, demo, 10)
        tot = max(1, len(evs))
        for rows in b.values():
            for r in rows:
                r["share"] = r["count"] / tot
        # key findings, in plain words
        f = []
        if evs:
            f.append(f"{k['total']:,} records on {k['hosts']:,} hosts, {len(evs) / max(1, len(day.events)):.1%} of the day's records.")
            if k["vulnerable_hosts"]:
                ti = b["issue"][0] if b["issue"] else None
                f.append(f"{k['vulnerable_hosts']:,} hosts ({k['vulnerable_hosts'] / max(1, k['hosts']):.0%}) have a concrete issue"
                         + (f"; the most common is {ti['label']} ({ti['hosts']:,} hosts)." if ti else "."))
            if multi_issue:
                f.append(f"{multi_issue:,} hosts carry more than one issue across their reports of the day: follow these up first.")
            if cross:
                f.append(f"{cross:,} hosts appear in more than one report on the same day (several exposed services or findings).")
            if b["service"]:
                s0 = b["service"][0]
                f.append(f"Largest service: {s0['label']} with {s0['count']:,} records ({s0['share']:.0%}).")
            if b["network"]:
                n0 = b["network"][0]
                f.append(f"Most affected network: {n0['label']} with {n0['hosts']:,} hosts.")
            if b["region"]:
                r0 = b["region"][0]
                f.append(f"Most affected region: {r0['label']} ({r0['share']:.0%} of records).")
            if k["critical"]:
                f.append(f"{k['critical']:,} critical records.")
        rows, nhosts = host_rows(evs, demo, 15)
        hours = hours_by_family(evs, day)
        totals = [sum(v[i] for v in hours.values()) for i in range(24)]
        return dict(day=day.start.date().isoformat(),
                    **k, day_total=len(day.events), share=(len(evs) / len(day.events)) if day.events else 0,
                    multi_issue_hosts=multi_issue, cross_report_hosts=cross, issues=len({i for e in evs for i in e["issues"]}),
                    regions=len({e["region"] for e in evs if not region_unknown(e["region"])}),
                    quarters=quarters(evs, day), hours_by_family=hours, peak_hour=(totals.index(max(totals)) if evs else None),
                    severity=severity_rows(evs), breakdowns=b, findings=f,
                    host_rows=rows, hosts_total=nhosts, time=args.get("time") or "")

    @app.route("/api/svc/drill")
    def svc_drill():
        """The list behind one analysis figure (hosts to follow up, issues, services, networks, regions...)."""
        demo = is_demo()
        args = request.args
        if args.get("metric", "hosts") not in DRILL_METRICS:
            return jsonify(error="unknown metric"), 400
        if args.get("all") == "1":                         # the whole list (a download): worked out, not kept
            return jsonify(svc_drill_core(args, demo))
        return jsonify(view_cache.get(view_key("drill", args, demo), lambda: svc_drill_core(args, demo)))

    DRILL_METRICS = ("hosts", "events", "vulnerable", "multi", "cross", "issues", "services", "networks", "regions", "share")

    def svc_drill_core(args, demo):
        day, evs, _ = selection(args)
        metric = args.get("metric", "hosts")
        full = args.get("all") == "1"
        lim = None if full else DRILL_LIMIT
        sel, day_reports = host_profile(evs, day.events)
        day_issues = day_host_issues(day)
        cols = lambda *c: [list(x) for x in c]
        out = {"metric": metric, "row_kind": None, "intro": "", "empty": "Nothing to list for this selection."}

        def hosts_list(ips, title, intro, empty="No hosts.", wide=False):
            """wide: the host figures (several reports / multiple issues) list each host's issues and reports of the
            whole day, as they were compared; the other lists show the issues within the selection."""
            rows = []
            for ip in ips:
                h = sel[ip]; e = h["e"]
                iss = day_issues.get(ip, set()) if wide else h["issues"]
                reasons = []
                if len(iss) > 1: reasons.append(f"{len(iss)} issues")
                elif iss: reasons.append("issue")
                if h["crit"]: reasons.append("critical")
                if len(day_reports.get(ip, ())) > 1: reasons.append(f"{len(day_reports[ip])} reports")
                rows.append({"ref": e["ip_ref"], "ip": mask_ip(ip) if demo else ip, "followup": reasons,
                             "issues": sorted(iss), "services": sorted(day_reports.get(ip, h["services"])),
                             "events": h["events"], "city": (e["city"] or "").title(), "region": (e["region"] or "").title(),
                             "network": asns.label(e["asn"], demo) if e["asn"] else "", "device": " · ".join((banner_mask(x) if demo else x) for x in (e["vendor"], e["product"]) if x),
                             "first": iso_t(h["t0"]), "last": iso_t(h["t1"]),
                             "_s": (len(iss) * 3 + h["crit"] * 2 + len(day_reports.get(ip, ())))})
            rows.sort(key=lambda r: (-r["_s"], -r["events"]))
            for r in rows: r.pop("_s")
            out.update(title=title, intro=intro, empty=empty, row_kind="ip", total=len(rows), rows=rows if lim is None else rows[:lim],
                       columns=cols(("ip", "Host IP"), ("followup", "Follow-up"), ("issues", "Issues"), ("services", "Reports / services"),
                                    ("events", "Records"), ("city", "City"), ("region", "Region"), ("network", "Network"), ("device", "Device / product"),
                                    ("first", "First seen"), ("last", "Last seen")))

        def group_list(key, label_fn, title, intro, row_kind, extra=None):
            g = {}
            for e in evs:
                vals = key(e)
                for v in (vals if isinstance(vals, list) else [vals]):
                    if v in ("", None):
                        continue
                    x = g.setdefault(v, {"events": 0, "hosts": set(), "crit": 0, "issues": set(), "services": set()})
                    x["events"] += 1; x["hosts"].add(e["ip"]); x["crit"] += e["severity"] == "critical"
                    x["issues"].update(e["issues"]); x["services"].add(e["service"])
            rows = [{"value": v, "name": label_fn(v), "events": x["events"], "hosts": len(x["hosts"]), "critical": x["crit"],
                     "share": f"{x['events'] / max(1, len(evs)):.1%}", "issues": ", ".join(sorted(x["issues"])[:6]),
                     "services": ", ".join(sorted(x["services"])[:6])} for v, x in g.items()]
            rows.sort(key=lambda r: -r["events"])
            out.update(title=title, intro=intro, row_kind=row_kind, total=len(rows), rows=rows if lim is None else rows[:lim],
                       columns=cols(("name", title.split(" ")[0] if not extra else extra), ("events", "Records"), ("hosts", "Hosts"),
                                    ("critical", "Critical"), ("share", "Share"), ("services", "Services"), ("issues", "Issues")))

        n = len(sel)
        if metric in ("hosts", "events"):
            hosts_list(list(sel), "Hosts, ranked for follow-up",
                       f"{n:,} hosts. Hosts with several issues, critical records or several reports come first.")
        elif metric == "vulnerable":
            ips = [ip for ip, h in sel.items() if h["issues"]]
            hosts_list(ips, "Hosts with issues", f"{len(ips):,} hosts have a concrete issue (CVE, weak encryption, expired certificate, admin panel, implant or compromise).",
                       "No host in this selection has an issue.")
        elif metric == "multi":
            ips = [ip for ip in sel if len(day_issues.get(ip, ())) > 1]
            hosts_list(ips, "Hosts with multiple issues", f"{len(ips):,} hosts carry more than one issue across all their reports of the day. These have the largest attack surface. "
                       "Filter the view shows these hosts with all their reports.",
                       "No host in this selection has more than one issue, in any of its reports.", wide=True)
        elif metric == "cross":
            ips = [ip for ip in sel if len(day_reports.get(ip, ())) > 1]
            hosts_list(ips, "Hosts in several reports", f"{len(ips):,} hosts appear in more than one Shadowserver report on the same day, for example an exposed admin panel and an old SSH server. "
                       "Filter the view shows these hosts with all their reports.",
                       "None of these hosts appear in another report.", wide=True)
        elif metric == "issues":
            group_list(lambda e: e["issues"], lambda v: v, "Issues found", "Every issue in this selection; click one to analyse it.", "issue", "Issue")
        elif metric == "services":
            group_list(lambda e: e["service"], lambda v: v, "Services (reports)", "Every report in this selection; click one to analyse it.", "service", "Service")
        elif metric == "networks":
            group_list(lambda e: network(e, demo), lambda v: v, "Networks", "Networks (companies) of the hosts; click one to analyse it.", "asn", "Network")
        elif metric == "regions":
            group_list(lambda e: e["region"], region_label, "Regions", "Regions of the country; click one to analyse it.", "region", "Region")
        elif metric == "share":
            group_list(lambda e: e["family"], lambda v: v, "Report families", f"{len(evs):,} of the day's {len(day.events):,} records, by report family.", "family", "Family")
        return out

    @app.route("/api/svc/regions")
    def svc_regions():
        """Regions heatmap (country from Settings): records, hosts and what makes up each region (active filters)."""
        demo = is_demo()
        args = request.args
        return jsonify(view_cache.get(view_key("regions", args, demo), lambda: svc_regions_core(args, demo)))

    def svc_regions_core(args, demo):
        day, evs, _ = selection(args)
        g = {}
        for e in evs:
            r = "" if region_unknown(e["region"]) else e["region"]
            x = g.setdefault(r, {"events": 0, "hosts": set(), "vuln": set(), "crit": 0, "svc": Counter(), "iss": Counter(), "city": Counter(), "net": Counter()})
            x["events"] += 1; x["hosts"].add(e["ip"]); x["crit"] += e["severity"] == "critical"
            if e["issues"]: x["vuln"].add(e["ip"])
            x["svc"][e["service"]] += 1; x["city"][(e["city"] or "").title()] += 1
            for i in e["issues"]: x["iss"][i] += 1
            if e["asn"]: x["net"][network(e, demo)] += 1
        out = {r: {"events": x["events"], "hosts": len(x["hosts"]), "vulnerable_hosts": len(x["vuln"]), "critical": x["crit"],
                   "services": x["svc"].most_common(4), "issues": x["iss"].most_common(4), "cities": [c for c in x["city"].most_common(4) if c[0]],
                   "networks": x["net"].most_common(3)} for r, x in g.items()}
        return dict(day=day.start.date().isoformat(), total=len(evs), regions=out)

    @app.route("/api/svc/hosts.csv")
    def svc_hosts_csv():
        demo = is_demo()
        day, evs, _ = selection(request.args)
        rows, _ = host_rows(evs, demo, None)
        buf = io.StringIO()
        w = csvsafe.writer(buf)   # vendor / product come from the hosts: no spreadsheet formulas
        w.writerow(["ip", "events", "worst severity", "issues", "services", "ports", "city", "network", "vendor", "product", "first seen", "last seen"])
        for r in rows:
            w.writerow([r["ip"], r["events"], r["severity"], "; ".join(r["issues"]), "; ".join(r["services"]), "; ".join(r["ports"]),
                        r["city"], r["network"], r["vendor"], r["product"], r["first"], r["last"]])
        return Response(buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f"attachment; filename=services-hosts-{day.start.date()}.csv"})

    @app.route("/api/svc/glossary")
    def svc_glossary():
        """Every report the platform detected, with Shadowserver's definition, and the report families."""
        day = store.days.get(store.day_start(replay_now()))
        reps = []
        for s in registry.items + registry.unsupported:
            info = report_info(s["name"]) or {}
            reps.append({"name": s["name"], "label": s["label"], "family": s["family"],
                         "title": info.get("title") or s["label"], "rating": info.get("severity", ""),
                         "def": info.get("def", ""), "why": info.get("why", ""), "url": info.get("url", ""),
                         "ipv6": info.get("ipv6", False), "rows": day.per_source.get(s["name"], 0) if day else 0,
                         "supported": s in registry.items, "fields": s.get("fields", [])})
        return jsonify(reports=reps, families=[{"name": f, "def": d} for _, f, d in FAMILIES])

    @app.route("/api/svc/diagnostics")
    def svc_diagnostics():
        registry.get()
        pick = lambda s: {"name": s["name"], "label": s["label"], "family": s["family"], **s["diagnostic"]}
        return jsonify(supported=[pick(s) for s in registry.items], unsupported=[pick(s) for s in registry.unsupported])

    @app.route("/api/svc/summary")
    def svc_summary():
        day = store.days.get(store.day_start(replay_now()))
        return jsonify(reports_monitored=len(registry.items), reports_with_data=len(day.per_source) if day else 0,
                       total=len(day.events) if day else 0, hosts=len({e["ip"] for e in day.events}) if day else 0,
                       day=day.start.date().isoformat() if day else None)

    def scope_events(args, day):
        """The records of a selection (the analysis's query arguments) on a given day: analyst codes (combos.py)."""
        pred = scope(day, args)
        evs = [e for e in day.events if pred(e)] if pred else list(day.events)
        tw = parse_time(args.get("time"))
        if tw:
            t0 = day.start.timestamp()
            evs = [e for e in evs if t0 + tw[0] <= e["_t"] < t0 + tw[1]]
        return evs

    return {"tick": tick, "registry": registry, "store": store, "scope_events": scope_events}
