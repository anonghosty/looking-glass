# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""HTTP API of the publicly accessible / vulnerable services platform (/services, /api/svc/...).

Same replay schedule as the map (one day, replayed from 00:00), same filter model (every list and chart value is
a filter), same demo masking. Registered from app.py with `register(app, ctx)`.
"""
import bisect
import csvsafe
import io
import threading
import time
import urllib.parse
from collections import Counter
from datetime import timedelta

from flask import Response, jsonify, render_template, request
from werkzeug.datastructures import MultiDict

import masked_fields
import tls_facts
from privacy import mask_ip, masked_id

_MASKED = {}            # id(day) -> ((serial, records, list), {masked id: record}); only the days someone opened a record of
_MASKED_DAYS = 3
_MASKED_LOCK = threading.Lock()


def _by_masked_id(day):
    """{masked id: record} of one loaded day, built on the first click and kept while the same copy of the day is in
    memory (a new copy, a reload or more records, builds it again). At most _MASKED_DAYS days are kept."""
    key = (getattr(day, "serial", 0), len(day.events), id(day.events))
    with _MASKED_LOCK:
        hit = _MASKED.get(id(day))
    if hit is not None and hit[0] == key:
        return hit[1]
    table = {masked_id(x["id"]): x for x in day.events if x.get("id")}
    with _MASKED_LOCK:                   # two clicks at once: each builds, the last one kept; the dict is never iterated unlocked
        if id(day) not in _MASKED and len(_MASKED) >= _MASKED_DAYS:
            _MASKED.pop(next(iter(_MASKED)), None)
        _MASKED[id(day)] = (key, table)
    return table


def _detail_index(day):
    """({record id: record}, {host: [records, services]}) of one loaded copy of a day, built on the first record opened and kept on
    the day itself (it goes with the day). A record click no longer reads the whole day twice (audit 2026-11-27: a
    scan for the id and one for the host's other records, per click, on a day of a million records)."""
    key = (len(day.events), id(day.events))
    hit = getattr(day, "_detail_idx", None)
    if hit is not None and hit[0] == key:
        return hit[1], hit[2]
    by_id, per_host = {}, {}
    for x in day.events:
        if x.get("id"):
            by_id.setdefault(x["id"], x)          # the first record with the id, as the scan found it
        h = per_host.get(x["ip"])
        if h is None:
            h = per_host[x["ip"]] = [0, set()]
        h[0] += 1
        h[1].add(x["service"])
    day._detail_idx = (key, by_id, per_host)
    return by_id, per_host
from respcache import ResultCache, day_key
from replay_counts import ReplayCounts
from services import (BANNER, banner_mask, EMPTY,FAMILIES, FILTER_KEYS, SEV_ORDER, ServiceRegistry, ServiceStore, matches, parse_filters,
                       parse_time, report_info)

import facets as _facets  # noqa: E402  (drop-down counts that follow the other filters)
import counting_keys as _ck  # noqa: E402  (one rule for regions and networks on every page: count audit round 2)
import filesig  # noqa: E402
from shares import pct  # noqa: E402  (shares that never read "0%" for a part with records, nor "100%" for a part)

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
    _ck.default_registry(asns)      # the sectors (network types) of this registry, when app.py configured none
    replay_counts = ReplayCounts()  # the replayed counter of a selection, polled every few seconds (replay_counts.py)

    # ------------------------------------------------------------------ helpers
    country_upper = {"t": 0.0, "v": set()}
    # the administrator's region matches (region_matches.py): part of every cached services answer that names regions,
    # so a new match shows at once, not at the next reload (review of d82a436)
    region_version = ctx.get("region_version") or (lambda: 0)

    def _fold(s):
        import unicodedata
        return unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode().upper().strip()

    def region_unknown(v):
        """Shadowserver writes the country name (for example GHANA, or COTE D'IVOIRE without its accents) when only
        the country is known. The country's spellings are looked up at most once a second (this runs for every record)."""
        now = time.monotonic()
        if now - country_upper["t"] > 1:
            names = {_fold(ctx["country_name"]())} | {_fold(n) for n in (ctx.get("country_names") or (lambda: []))()}
            # a region of the map named like the country (Belize District, Djibouti...) is that region, unless the
            # administrator said the name means the country itself (2026-11-15)
            names -= {_fold(n) for n in (ctx.get("map_region_names") or (lambda: ()))()}
            names |= {_fold(n) for n in (ctx.get("country_chosen_names") or (lambda: ()))()}
            country_upper.update(t=now, v=names - {""})
        if _ck.configured():
            return _ck.is_unknown_region(_ck.region_key(v))
        return not v or _fold(v) in country_upper["v"]

    def region_label(v):
        """The one region rule (counting_keys.region_key: the administrator's matches, the map, the country's name);
        a standalone run without the platform's configuration keeps the country-name rule above."""
        if _ck.configured():
            return _ck.region_key(v)
        return _ck.UNKNOWN_REGION if region_unknown(v) else _ck.region_key(v)

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
                stamp = filesig.sig(asns.path)
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
            out["id"] = masked_id(e["id"])      # not the database record (privacy.masked_id); /api/svc/detail takes it back
            for k in BANNER:            # banners can carry the host's own name or address (review 2026-11-13)
                out[k] = banner_mask(out.get(k) or "")
            out["demo"] = True
        if full:
            ex = e.get("extras") or {}
            if demo:      # an allowlist (masked_fields.py): unknown and identifying fields are hidden, the rest masked
                out["extras"], out["extras_hidden"] = masked_fields.service_extras(ex)
            else:
                out["extras"] = ex
            # certificate and TLS facts (tls_facts.py), from the raw fields; masked viewers get them without dates
            tls = tls_facts.facts(ex, e.get("timestamp") or e.get("extracted_date"), dates=not demo)
            if tls:
                out["tls"] = tls
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
    HOST_KEYS = {"region", "city", "asn", "sector", "industry", "geo", "ip", "hostname"}
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
        ips = seed_hosts(day, cross, multi, seed_flt)
        return lambda e: e["ip"] in ips and matches(e, view_flt)

    def seed_hosts(day, cross, multi, seed_flt):
        """The hosts "Hosts in several reports" / "Hosts with multiple issues" chose (see scope)."""
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
        return ips

    def facet_scope(day, args):
        """(the records the drop-downs count over, the filters each field's counts follow but its own): every record of
        the day and every filter; with several reports / multiple issues on, the chosen hosts' records and the filters
        added after switching it on (split_cross). The time window narrows them like the view."""
        on = lambda v: (v or "0") not in ("0", "")        # noqa: E731
        cross, multi = on(args.get("cross")), on(args.get("multi"))
        if cross or multi:
            seed_flt, flt = split_cross(args)
            ips = seed_hosts(day, cross, multi, seed_flt)
            evs = [e for e in day.events if e["ip"] in ips]
        else:
            evs, flt = day.events, parse_filters(args, refs, asns)
        tw = parse_time(args.get("time"))
        if tw:
            t0 = day.start.timestamp()
            evs = [e for e in evs if t0 + tw[0] <= e["_t"] < t0 + tw[1]]
        return evs, flt

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

    def top(evs, key, demo, n=10, label=None, drop_empty=False, meta=None, unknown=None):
        """The n most common values (n=0: every one). drop_empty: an empty value is no row. meta (a dict): filled with
        what the rows leave out: distinct (every different value), other / other_hosts (records and hosts with a value
        outside the rows: an "Other" row), none / none_hosts (records and hosts without a value). 2026-11-26.
        unknown: the value that stands for "not known" (Unknown network, Unknown region): a row like the others, but not
        one of the distinct values (an unknown network is not a network), its records and hosts in meta apart."""
        c = Counter()
        hosts = {}
        for e in evs:
            vals = key(e)
            for v in (vals if isinstance(vals, list) else [vals]):
                if drop_empty and not v:
                    continue
                c[v] += 1
                hs = hosts.setdefault(v, set())
                if e["ip"]:                          # a record without an address is no host (count audit round 2)
                    hs.add(e["ip"])
        rows = []
        for v, k in c.most_common(n if n else None):
            rows.append({"value": v if v != "" else "", "label": (label(v) if label else v) or "", "count": k, "hosts": len(hosts[v])})
        if meta is not None:
            shown = {r["value"] for r in rows}
            other, none, oh, nh = 0, 0, set(), set()
            if len(c) > len(rows):                  # a record counts once in Other, however many of its values are cut
                for e in evs:
                    vals = key(e)
                    vals = [v for v in (vals if isinstance(vals, list) else [vals]) if not (drop_empty and not v)]
                    if any(v not in shown for v in vals):
                        other += 1
                        if e["ip"]:
                            oh.add(e["ip"])
            for e in evs:
                vals = key(e)
                vals = [v for v in (vals if isinstance(vals, list) else [vals]) if not (drop_empty and not v)]
                if not vals:
                    none += 1
                    if e["ip"]:
                        nh.add(e["ip"])
            meta.update(distinct=len(c), other=other, other_hosts=len(oh), none=none, none_hosts=len(nh))
            if unknown is not None:
                meta.update(distinct=len(c) - (unknown in c), unknown=c.get(unknown, 0), unknown_hosts=len(hosts.get(unknown, ())))
        return rows

    # lists short by nature: never cut (report families, severities, sectors, protocols, regions)
    UNCUT = ("family", "severity", "sector", "industry", "protocol", "region")

    def breakdowns(evs, demo, n=10, meta=None):
        """Every list of the analysis and the drop-downs; n=0: every value. meta (a dict): {list: what it leaves out}."""
        empty = lambda k: (lambda v: v or EMPTY.get(k, "unknown"))
        b = banner_mask if demo else (lambda v: v)
        spec = {   # list: (value of a record, label, drop an empty value)
            "service": (lambda e: e["service"], None, False),
            "family": (lambda e: e["family"], None, False),
            "severity": (lambda e: e["severity"], empty("severity"), False),
            "issue": (lambda e: e["issues"], None, False),
            "tag": (lambda e: e["tags"], None, False),
            "port": (lambda e: e["port"], None, False),
            # records without a network: an "Unknown network" row (count audit round 2: they were dropped), never
            # counted as a network (meta["network"]["unknown"])
            "network": (lambda e: network(e, demo) or _ck.UNKNOWN_NET, None, False),
            "city": (lambda e: e["city"], lambda v: (v or "unknown city").title(), False),
            "vendor": (lambda e: b(e["vendor"]), None, True),
            "device_type": (lambda e: b(e["device_type"]), None, True),
            "product": (lambda e: b(e["product"]), None, True),
            # Sectors: the network type of the host's network, as on the Executive portal and in the quarterly report;
            # Shadowserver's own sector column is the Industry (Shadowserver) list (the user, 2026-11-26)
            "sector": (lambda e: _ck.sector_now(e["asn"]), None, False),
            "industry": (lambda e: _ck.industry_of(e["sector"]), None, True),
            "protocol": (lambda e: e["protocol"], None, True),
            # one spelling per region (NAIROBI and Nairobi one row), an "Unknown region" row for none or the country
            # itself (count audit round 2: grouped by the raw value, empty regions dropped)
            "region": (lambda e: region_label(e["region"]), None, False),
        }
        unknowns = {"network": _ck.UNKNOWN_NET, "region": _ck.UNKNOWN_REGION}
        out = {}
        for name, (key, label, drop) in spec.items():
            m = {} if meta is not None else None
            out[name] = top(evs, key, demo, 0 if name in UNCUT else n, label, drop, m, unknown=unknowns.get(name))
            if m is not None:
                meta[name] = m
        out["severity"] = sorted(out["severity"], key=lambda r: SEV_ORDER.get(r["value"], 9))
        return out

    def with_totals(d, meta):
        """An answer with what each list leaves out, beside the lists: totals (different values), others / other_hosts
        (records and hosts outside the rows: an "Other" row), unrecorded / unrecorded_hosts (without a value)."""
        d.update(totals={k: m["distinct"] for k, m in meta.items()}, others={k: m["other"] for k, m in meta.items()},
                 other_hosts={k: m["other_hosts"] for k, m in meta.items()},
                 unrecorded={k: m["none"] for k, m in meta.items()},
                 unrecorded_hosts={k: m["none_hosts"] for k, m in meta.items()},
                 # records and hosts of the "Unknown network" / "Unknown region" rows, not counted as one (count audit)
                 unknowns={k: {"records": m["unknown"], "hosts": m["unknown_hosts"]} for k, m in meta.items() if "unknown" in m})
        return d

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
        # count audit round 2: a record without an address is no host (counted apart), networks are companies (as on
        # the Executive portal and in the quarterly report: two AS numbers of one company are one network), records
        # without a network are counted apart, never as a network
        hosts = {e["ip"] for e in evs if e["ip"]}
        nets = {network(e, False) for e in evs}
        return {"total": len(evs), "hosts": len(hosts), "no_address": sum(1 for e in evs if not e["ip"]),
                "critical": sum(1 for e in evs if e["severity"] == "critical"),
                "high": sum(1 for e in evs if e["severity"] == "high"),
                "vulnerable": sum(1 for e in evs if e["vulnerable"]),
                "vulnerable_hosts": len({e["ip"] for e in evs if e["vulnerable"] and e["ip"]}),
                "services": len({e["report"] for e in evs}),
                "networks": len(nets - {""}), "unknown_network": sum(1 for e in evs if not network(e, False)),
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
        # a masked viewer holds the masked id (privacy.masked_id), never the record's own: looked up in the day's own
        # table, built once (security review, 2026-11-17: working out every record's masked id on each click took up to
        # ~2 s on a day of a million records, on a request thread)
        by_id, per_host = _detail_index(day)
        e = _by_masked_id(day).get(eid) if demo else by_id.get(eid)
        if not e:
            return jsonify(error="not found"), 404
        n, services_ = per_host.get(e["ip"], (0, ()))
        return jsonify(event=public(e, demo, full=True), host_records=n, host_services=sorted(services_))

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
        key = ("svc_stats", day_key(day), demo, n, registry.version, asns.mtime, region_version(), args)
        return jsonify(svc_cache.get(key, lambda: svc_stats_core(request.args, demo, n)))

    def svc_stats_core(args, demo, n):
        day, evs, _ = selection(args)
        sel, day_reports = host_profile(evs, day.events)
        meta = {}
        b = breakdowns(evs, demo, n, meta)
        notes = dict(getattr(day, "load_notes", None) or {"dups": 0, "outside": 0, "undated": 0})
        notes["text"] = _ck.load_note(notes["dups"], notes["outside"], notes["undated"], day.start.date().isoformat())
        return with_totals(dict(day=day.start.date().isoformat(), **kpis(evs), reports_with_data=len(day.per_source),
                                load_notes=notes,
                                reports_monitored=len(registry.items), quarters=quarters(evs, day),
                                hours_by_family=hours_by_family(evs, day), severity=severity_rows(evs),
                                cross_report_hosts=sum(1 for ip in sel if len(day_reports.get(ip, ())) > 1),
                                multi_issue_hosts=sum(1 for ip in sel if len(day_host_issues(day).get(ip, ())) > 1),
                                breakdowns=b), meta)

    # masked and unmasked viewers each keep their own lists (review 2026-11-13); worked out once for everyone asking at
    # the same moment (ResultCache; review of d82a436: simultaneous requests computed it twice)
    facets_cache = ResultCache(size=64)       # one per day and choice of filters
    # a drop-down's list -> the filter it sets
    FACET_FILTER = {"service": "service", "family": "family", "severity": "severity", "issue": "issue", "tag": "tag",
                    "port": "port", "network": "asn", "city": "city", "vendor": "vendor", "device_type": "device_type",
                    "product": "product", "sector": "sector", "industry": "industry", "protocol": "protocol", "region": "region"}

    def facet_counts(day, args, demo):
        """(the drop-downs' lists, whether filters shaped them): each list counted over the records matching every
        other filter (facets.py), from one pass over the records in scope."""
        evs, flt = facet_scope(day, args)
        # every value of every list (n=0): a value past a cut of 400 could not be chosen, and nothing said so
        # (2026-11-26). They are names with two counts, so even a large country's networks stay small.
        if not flt and evs is day.events:
            return breakdowns(evs, demo, 0), False
        pool = _facets.pools(evs, flt, test=lambda e, f, vals: matches(e, {f: vals}))
        whole = breakdowns(pool.passed, demo, 0)
        out = {}
        for name, rows in whole.items():
            f = FACET_FILTER.get(name)
            out[name] = breakdowns(pool.of(f), demo, 0)[name] if f in flt else rows
        return out, True

    @app.route("/api/svc/facets")
    def svc_facets():
        demo = is_demo()
        day = day_for(request.args.get("at"))
        # whole-day lists change when the day is reloaded, the network names change (asns), a report type is added,
        # or an administrator matches a region name (review of d82a436: those three were left out of the key)
        # with filters, each list's counts follow every OTHER filter (facets.py; the user, 2026-11-19), cached per set
        key = (day_key(day), demo, ctx["country_name"](), asns.mtime, registry.version, region_version(), cache_args(request.args))
        b, filtered = facets_cache.get(key, lambda: facet_counts(day, request.args, demo))
        return jsonify(day=day.start.date().isoformat(), total=len(day.events), facets=b, filtered=filtered,
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
        return (name, day_key(day), demo, registry.version, asns.mtime, ctx["country_name"](), region_version(), cache_args(args))

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
        meta = {}
        b = breakdowns(evs, demo, 10, meta)
        tot = max(1, len(evs))
        for rows in b.values():
            for r in rows:
                r["share"] = r["count"] / tot
        # key findings, in plain words; one of a thing is singular ("1 records on 1 hosts", the docs screenshots 2026-11-27)
        def n_(c, word):
            return f"{c:,} {word}" + ("" if c == 1 else "s")
        f = []
        if evs:
            f.append(f"{n_(k['total'], 'record')} on {n_(k['hosts'], 'host')}, {pct(len(evs) / max(1, len(day.events)), 1)} of the day's records.")
            if k["vulnerable_hosts"]:
                ti = b["issue"][0] if b["issue"] else None
                f.append(f"{n_(k['vulnerable_hosts'], 'host')} ({pct(k['vulnerable_hosts'] / max(1, k['hosts']))}) "
                         + ("has" if k["vulnerable_hosts"] == 1 else "have") + " a concrete issue"
                         + (f"; the most common is {ti['label']} ({n_(ti['hosts'], 'host')})." if ti else "."))
            if multi_issue:
                f.append(f"{n_(multi_issue, 'host')} " + ("carries" if multi_issue == 1 else "carry")
                         + " more than one issue across their reports of the day: follow these up first.")
            if cross:
                f.append(f"{n_(cross, 'host')} " + ("appears" if cross == 1 else "appear")
                         + " in more than one report on the same day (several exposed services or findings).")
            if b["service"]:
                s0 = b["service"][0]
                f.append(f"Largest service: {s0['label']} with {n_(s0['count'], 'record')} ({pct(s0['share'])}).")
            if b["network"]:
                n0 = b["network"][0]
                f.append(f"Most affected network: {n0['label']} with {n_(n0['hosts'], 'host')}.")
            if b["region"]:
                r0 = b["region"][0]
                f.append(f"Most affected region: {r0['label']} ({pct(r0['share'])} of records).")
            if k["critical"]:
                f.append(f"{n_(k['critical'], 'critical record')}.")
        rows, nhosts = host_rows(evs, demo, 15)
        hours = hours_by_family(evs, day)
        totals = [sum(v[i] for v in hours.values()) for i in range(24)]
        return with_totals(dict(day=day.start.date().isoformat(),
                    **k, day_total=len(day.events), share=(len(evs) / len(day.events)) if day.events else 0,
                    multi_issue_hosts=multi_issue, cross_report_hosts=cross, issues=len({i for e in evs for i in e["issues"]}),
                    regions=len({region_label(e["region"]) for e in evs} - {_ck.UNKNOWN_REGION}),
                    quarters=quarters(evs, day), hours_by_family=hours, peak_hour=(totals.index(max(totals)) if evs else None),
                    severity=severity_rows(evs), breakdowns=b, findings=f,
                    # every service (report) of the selection, by records: the PDF explains each one
                    report_names=[v for v, _ in Counter(e["service"] for e in evs).most_common()],
                    host_rows=rows, hosts_total=nhosts, time=args.get("time") or ""), meta)

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
                             "events": h["events"], "city": (e["city"] or "").title(), "region": region_label(e["region"]),
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
                    x["events"] += 1; x["crit"] += e["severity"] == "critical"
                    if e["ip"]:
                        x["hosts"].add(e["ip"])
                    x["issues"].update(e["issues"]); x["services"].add(e["service"])
            rows = [{"value": v, "name": label_fn(v), "events": x["events"], "hosts": len(x["hosts"]), "critical": x["crit"],
                     # every issue and service (the CSV is the complete list; 2026-11-26: six, and no word of the rest)
                     "share": pct(x["events"] / max(1, len(evs)), 1), "issues": ", ".join(sorted(x["issues"])),
                     "services": ", ".join(sorted(x["services"]))} for v, x in g.items()]
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
            group_list(lambda e: network(e, demo) or _ck.UNKNOWN_NET, lambda v: v, "Networks",
                       "Networks (companies) of the hosts, and the records without a network as Unknown network; click one "
                       "to analyse it.", "asn", "Network")
        elif metric == "regions":
            group_list(lambda e: region_label(e["region"]), lambda v: v, "Regions", "Regions of the country, and the records "
                       "whose region is not known as Unknown region; click one to analyse it.", "region", "Region")
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
            # the region in its one spelling (counting_keys.region_key: the map's own name, which the map finds), ""
            # for an unknown one (the map's "Region unknown" area)
            lab = region_label(e["region"])
            r = "" if _ck.is_unknown_region(lab) else lab
            x = g.setdefault(r, {"events": 0, "hosts": set(), "vuln": set(), "crit": 0, "svc": Counter(), "iss": Counter(), "city": Counter(), "net": Counter()})
            x["events"] += 1; x["crit"] += e["severity"] == "critical"
            if e["ip"]:
                x["hosts"].add(e["ip"])
                if e["issues"]:
                    x["vuln"].add(e["ip"])
            x["svc"][e["service"]] += 1; x["city"][(e["city"] or "").title()] += 1
            for i in e["issues"]: x["iss"][i] += 1
            nn = network(e, demo)
            if nn: x["net"][nn] += 1
        # each short list with its full count beside it (totals), so the map's hover says "Top 4 of 9" (2026-11-26)
        out = {r: {"events": x["events"], "hosts": len(x["hosts"]), "vulnerable_hosts": len(x["vuln"]), "critical": x["crit"],
                   "services": x["svc"].most_common(4), "issues": x["iss"].most_common(4), "cities": [c for c in x["city"].most_common(5) if c[0]][:4],
                   "networks": x["net"].most_common(3),
                   "totals": {"services": len(x["svc"]), "issues": len(x["iss"]), "cities": len([c for c in x["city"] if c]),
                              "networks": len(x["net"])}} for r, x in g.items()}
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
                        headers={"Content-Disposition": f'attachment; filename="services-hosts-{day.start.date()}.csv"'})

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
