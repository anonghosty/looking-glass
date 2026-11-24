# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Analytics: the figures, breakdowns and drill-downs of the Analyse panels on both platforms

Moved out of app.py unchanged (the app.py refactor, 2026-11-24). Every name it uses from app.py, its own included, is
read from the app module when the code runs (_A.name), so it behaves exactly as it did inside app.py: a name replaced on
app.py reaches this code too. app.py calls install() where this code was, which registers the routes and hooks in the
same order, and keeps every name defined here under its old name.
"""
_A = None          # the app module (app.py), set by install()


class _Recorder:
    """@_R.route(...) and the like: kept in order, registered on the Flask app by install()."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, kind):
        def deco_or_factory(*args, **kwargs):
            if kind in ("before_request", "after_request", "teardown_request", "context_processor") and len(args) == 1 \
                    and callable(args[0]) and not kwargs:
                self.calls.append((kind, (), {}, args[0]))
                return args[0]

            def deco(fn):
                self.calls.append((kind, args, kwargs, fn))
                return fn
            return deco
        return deco_or_factory


_R = _Recorder()




def _parse_time_value(value):
    """'1080+60|infection|android.badbox2' -> (1080, 60, 'infection', 'android.badbox2')."""
    span, _, scope = (value or "").partition("|")
    start_s, _, dur_s = span.partition("+")
    try:   # minutes; fractions allowed so a window can end exactly at the replay position
        start, dur = max(0.0, min(1439.0, float(start_s))), max(1 / 60, min(1440.0, float(dur_s or 60)))
    except ValueError:
        start, dur = 0.0, 1440.0
    sk, _, sv = scope.partition("|")
    if sk not in _A.INSIGHT_KINDS or sk == "time":
        sk, sv = "", ""
    return start, dur, sk, sv


def _hm(minutes):
    if minutes >= 1440:
        return "24:00"
    m = int(minutes)
    s = int(round((minutes - m) * 60))
    return f"{m // 60 % 24:02d}:{m % 60:02d}" + (f":{s:02d}" if s else "")


def _place_parts(v):
    city, _, cc = (v or "").partition("|")
    return city, cc


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _top(events, field, n=8, label=None, key=None):
    c = _A.Counter((key(e[field]) if key else e[field]) for e in events if e[field])
    # a share is of the whole selection, events without a value included (review 2026-11-13: it was of the events
    # that had one, so a field filled in on a tenth of the events read as 100 %)
    total = len(events) or 1
    return [{"value": v, "label": label(v) if label else v, "count": k, "share": round(k / total, 4)} for v, k in c.most_common(n)]


def _request_path(url):
    # "GET /sck/29965/?m=a11&step=669 HTTP/1.0" -> "GET /sck/29965/"
    parts = url.split(" ")
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1].split('?')[0]}"
    return url.split("?")[0]


def _fmt_dur(seconds):
    if seconds is None:
        return None
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def _select_slice(kind, value, rn):
    """(day, all events of the whole replay day, events matching kind=value)."""
    return _A._slice_on(_A.store.get(rn), kind, value)


def _slice_on(day, kind, value):
    """The same selection on a given day (also one loaded from the history: analyst codes, combos.py)."""
    sofar = day.events
    if kind == "time":
        start, dur, sk, sv = _A._parse_time_value(value)
        t0 = day.start.timestamp() + start * 60
        t1 = t0 + dur * 60
        base = _A._slice_on(day, sk, sv)[2] if sk else sofar
        return day, sofar, [e for e in base if t0 <= e["_t"] < t1]
    if kind == "filters":
        # the same filter logic as the map, stream and Intel, so the numbers agree everywhere
        pairs = _A.parse_qsl(value or "", keep_blank_values=False)
        flt = _A.narrow_filters(_A.parse_filters(_A.MultiDict(pairs)), day, _A.MultiDict(pairs))
        # a time window ("time=1080+60") narrows by event time; it is not a map filter
        windows = []
        for k, v in pairs:
            if k == "time":
                start, dur, _, _ = _A._parse_time_value(v)
                t0 = day.start.timestamp() + start * 60
                windows.append((t0, t0 + dur * 60))
        return day, sofar, [e for e in sofar if _A.matches(e, flt) and all(a <= e["_t"] < b for a, b in windows)]
    if kind in _A.REF_KINDS:
        value = _A.host_refs.resolve(value)                # opaque reference (demo mode) or the value itself
    match_value = "" if value == _A.EMPTY_LABEL.get(kind) else value
    if kind == "request":
        ev = [e for e in sofar if e["http_url"] and _A._request_path(e["http_url"]) == value]
    elif kind == "dst_port":
        ev = [e for e in sofar if str(e["dst_port"] or "") == str(match_value)]
    elif kind in ("src_asn", "dst_asn"):
        wanted = _A.asn_registry.resolve(value)            # company name, demo alias or AS number
        ev = [e for e in sofar if e[kind] in wanted]
    elif kind == "src_ip":
        real_ip = _A.host_refs.resolve(value)              # opaque host reference or IP
        ev = [e for e in sofar if e["src_ip"] == real_ip]
    elif kind == "route":
        s, _, d = value.partition(">")
        (sc, sg), (dc, dg) = _A._place_parts(s), _A._place_parts(d)
        ev = [e for e in sofar if (e["src_city"] or "") == sc and (e["src_geo"] or "") == sg
              and (e["dst_city"] or "") == dc and (e["dst_geo"] or "") == dg]
    elif kind == "dst_place":
        dc, dg = _A._place_parts(value)
        ev = [e for e in sofar if (e["dst_city"] or "") == dc and (e["dst_geo"] or "") == dg]
    else:
        ev = [e for e in sofar if e[kind] == match_value]
    return day, sofar, ev


def _rhythm(ts):
    """(median gap in seconds, coefficient of variation) for a host's event times, or (None, None)."""
    if len(ts) < 3:
        return None, None
    d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(d) < 2:
        return None, None
    mean = sum(d) / len(d)
    sd = (sum((x - mean) ** 2 for x in d) / len(d)) ** 0.5
    return _A._median(d), (sd / mean if mean else None)


def _hhmmss(t):
    return _A.datetime.fromtimestamp(t, _A.timezone.utc).strftime("%H:%M:%S")


@_R.route("/api/insight/drill")
def api_insight_drill():
    """The list behind one figure of the analysis view: which hosts, domains, reports or destinations it counts,
    with follow-up priorities for hosts. Demo mode masks IPs, networks and domains like everywhere else."""
    kind = _A.request.args.get("kind", "")
    value = _A.request.args.get("value", "")
    metric = _A.request.args.get("metric", "")
    if kind not in _A.INSIGHT_KINDS or metric not in _A.DRILL_METRICS:
        return _A.jsonify(error="unknown kind or metric"), 400
    rn = _A.parse_iso(_A.request.args.get("at"), _A.replay_now())
    demo = _A.is_demo()
    day, sofar, ev = _A._select_slice(kind, value, rn)
    mip = _A.mask_ip if demo else (lambda s: s)
    mt = _A.mask_text if demo else (lambda s: s)
    labels = {s["name"]: s["label"] for s in _A.registry.get()}
    classes = {s["name"]: s["class"] for s in _A.registry.get()}
    n = len(ev)

    # per-host profile inside the selection, plus whole-day context for the same hosts
    hosts = {}
    for e in ev:
        if not e["src_ip"]:          # destination-only reports have no source host to follow up
            continue
        h = hosts.get(e["src_ip"])
        if h is None:
            h = hosts[e["src_ip"]] = {"ts": [], "e": e, "crit": 0}
        h["ts"].append(e["_t"])
        if e["severity"] == "critical":
            h["crit"] += 1
    day_src, day_inf = {}, {}
    for e in sofar:
        if e["src_ip"] in hosts:
            day_src.setdefault(e["src_ip"], set()).add(e["source"])
            day_inf.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")

    def host_row(ip):
        h = hosts[ip]
        s = h["e"]
        med, cv = _A._rhythm(h["ts"])
        srcs, infs = day_src.get(ip, set()), day_inf.get(ip, set())
        kinds = {classes.get(x) for x in srcs} - {None}
        reasons, score = [], 0
        if len(kinds) > 1:
            reasons.append("Several kinds of activity"); score += 4
        if len(srcs) > 1:
            reasons.append(f"In {len(srcs)} reports"); score += 2
        if len(infs) > 1:
            reasons.append(f"{len(infs)} infections / categories"); score += 2
        if cv is not None and cv < 0.5:
            reasons.append("Regular beaconing"); score += 1
        if h["crit"]:
            reasons.append("Critical"); score += 1
        return {
            "ref": s["src_ref"], "ip": mip(ip), "followup": reasons, "score": score, "events": len(h["ts"]),
            "infections": sorted(infs), "reports": sorted(labels.get(x, x) for x in srcs),
            "kinds": sorted(kinds), "city": s["src_city"], "network": _A.asn_registry.label(s["src_asn"], demo) or "",
            "interval": _A._fmt_dur(med) or "", "rhythm": "" if cv is None else ("Regular" if cv < 0.5 else "Irregular"),
            "first": _A._hhmmss(h["ts"][0]), "last": _A._hhmmss(h["ts"][-1]),
        }

    def ranked(ips):
        rows = [host_row(ip) for ip in ips]
        rows.sort(key=lambda r: (-r["score"], -r["events"]))
        return rows

    def group(field, key=None):
        g = {}
        for e in ev:
            v = e[field]
            if not v:
                continue
            v = key(v) if key else v
            x = g.get(v)
            if x is None:
                x = g[v] = {"events": 0, "hosts": set(), "crit": 0, "inf": set(), "dst": set(), "geo": set(),
                            "asn": set(), "ports": set(), "dom": set(), "src": set(), "t0": e["_t"], "t1": e["_t"]}
            x["events"] += 1; x["inf"].add(e["infection"] or "unknown")
            if e["src_ip"]: x["hosts"].add(e["src_ip"])
            if e["dst_ip"]: x["dst"].add(e["dst_ip"])
            x["src"].add(e["source"]); x["t1"] = e["_t"]
            if e["severity"] == "critical": x["crit"] += 1
            if e["dst_geo"]: x["geo"].add(e["dst_geo"])
            if e["dst_asn"]: x["asn"].add(e["dst_asn"])
            if e["dst_port"]: x["ports"].add(str(e["dst_port"]))
            if e["http_host"]: x["dom"].add(mt(e["http_host"]))
        return sorted(g.items(), key=lambda kv: -kv[1]["events"])

    H = {"ip": "Host IP", "followup": "Follow-up", "events": "Events", "infections": "Infections / categories",
         "reports": "Reports", "city": "City", "network": "Network", "interval": "Repeat interval",
         "rhythm": "Rhythm", "first": "First seen", "last": "Last seen", "kinds": "Kinds of activity"}
    cols = lambda *keys: [[k, H[k]] for k in keys]
    out = {"metric": metric, "row_kind": None, "intro": "", "empty": "Nothing to list for this selection yet."}

    if metric == "hosts":
        rows = ranked(hosts)
        n_fu = sum(1 for r in rows if r["score"] >= 2)
        out.update(title="Source hosts, ranked for follow-up", row_kind="src_ip",
                   intro=f"{len(rows):,} source hosts. {n_fu:,} of them have stronger signs of compromise "
                         "(several kinds of activity, several reports or several infections) and are listed first.",
                   columns=cols("ip", "followup", "events", "infections", "reports", "city", "network", "interval", "first", "last"),
                   rows=rows)
    elif metric == "cross":
        rows = ranked([ip for ip in hosts if len(day_src.get(ip, ())) > 1])
        mixed = sum(1 for r in rows if len(r["kinds"]) > 1)
        out.update(title="Hosts seen in more than one report", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts appear in several Shadowserver reports on the same day. "
                         f"{mixed:,} of them show more than one kind of activity (for example botnet C2 traffic and attacks) "
                         "and should be followed up first.",
                   columns=cols("ip", "reports", "kinds", "followup", "events", "infections", "city", "network", "first", "last"),
                   rows=rows, empty="None of these hosts appear in another report yet.")
    elif metric == "multi":
        rows = ranked([ip for ip in hosts if len(day_inf.get(ip, ())) > 1])
        out.update(title="Hosts with more than one infection / category", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts carry more than one infection or category on the same day. "
                         "This suggests several infections on one device, or proxy software bundled with malware.",
                   columns=cols("ip", "infections", "followup", "events", "reports", "city", "network", "first", "last"),
                   rows=rows, empty="No host in this selection shows more than one infection / category yet.")
    elif metric == "interval":
        rows = [r for r in (host_row(ip) for ip in hosts) if r["interval"]]
        rows.sort(key=lambda r: (r["rhythm"] != "Regular", -r["events"]))
        reg = sum(1 for r in rows if r["rhythm"] == "Regular")
        out.update(title="Repeat behaviour of hosts", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts were seen at least three times. {reg:,} repeat at a regular rhythm, "
                         "which points to automated beaconing or scripted attacks; they are listed first.",
                   columns=cols("ip", "interval", "rhythm", "events", "infections", "followup", "city", "network", "first", "last"),
                   rows=rows, empty="No host has been seen often enough (three times or more) to measure a rhythm yet.")
    elif metric in ("events", "reports"):
        if metric == "events":
            g = {}
            for e in ev:
                k = (e["infection"] or "unknown", e["source"])
                x = g.setdefault(k, {"events": 0, "hosts": set(), "crit": 0})
                x["events"] += 1; x["crit"] += e["severity"] == "critical"
                if e["src_ip"]: x["hosts"].add(e["src_ip"])
            rows = [{"value": inf, "infection": inf, "report": labels.get(src, src), "events": x["events"],
                     "hosts": len(x["hosts"]), "critical": x["crit"], "share": f"{x['events'] / max(1, n):.1%}"}
                    for (inf, src), x in sorted(g.items(), key=lambda kv: -kv[1]["events"])]
            out.update(title="Events by infection / category and report", row_kind="infection",
                       intro=f"{n:,} events, split by what Shadowserver reported and in which report.",
                       columns=[["infection", "Infection / category"], ["report", "Report"], ["events", "Events"],
                                ["hosts", "Source hosts"], ["critical", "Critical"], ["share", "Share of selection"]],
                       rows=rows)
        else:
            rows = [{"value": src, "report": labels.get(src, src), "kind": classes.get(src, ""), "events": x["events"],
                     "hosts": len(x["hosts"]), "critical": x["crit"], "infections": len(x["inf"]),
                     "share": f"{x['events'] / max(1, n):.1%}"} for src, x in group("source")]
            out.update(title="Reports in this selection", row_kind="source",
                       intro=f"{len(rows):,} Shadowserver report{'s' if len(rows) != 1 else ''} contain these events.",
                       columns=[["report", "Report"], ["kind", "Attack type"], ["events", "Events"], ["hosts", "Source hosts"],
                                ["infections", "Infections / categories"], ["critical", "Critical"], ["share", "Share of selection"]],
                       rows=rows)
    elif metric == "share":
        mine = _A.Counter(e["source"] for e in ev)
        allc = _A.Counter(e["source"] for e in sofar)
        tot = max(1, len(sofar))
        rows = [{"value": src, "report": labels.get(src, src), "kind": classes.get(src, ""), "all": k,
                 "share_all": f"{k / tot:.1%}", "mine": mine.get(src, 0),
                 "mine_share": f"{mine.get(src, 0) / k:.1%}" if k else ""} for src, k in allc.most_common()]
        out.update(title="How this selection compares with all events", row_kind="source",
                   intro=f"This selection has {n:,} of the {len(sofar):,} events Shadowserver reported for the day ({n / tot:.1%}). "
                         "Each report below shows its size and how much of it belongs to this selection.",
                   columns=[["report", "Report"], ["kind", "Attack type"], ["all", "All events"], ["share_all", "Share of all events"],
                            ["mine", "In this selection"], ["mine_share", "Selection's part of the report"]],
                   rows=rows)
    elif metric == "c2":
        rows = [{"value": _A.host_refs.ref(d) if demo else d, "domain": mt(d), "events": x["events"], "hosts": len(x["hosts"]),
                 "infections": sorted(x["inf"]), "dst": len(x["dst"]), "first": _A._hhmmss(x["t0"]), "last": _A._hhmmss(x["t1"])}
                for d, x in group("http_host")]
        out.update(title="C2 / sinkhole domains contacted", row_kind="http_host",
                   intro=f"{len(rows):,} domain names the hosts tried to reach, most contacted first.",
                   columns=[["domain", "Domain"], ["events", "Events"], ["hosts", "Source hosts"], ["infections", "Infections / categories"],
                            ["dst", "Destination IPs"], ["first", "First seen"], ["last", "Last seen"]],
                   rows=rows,
                   empty="These reports record only IP addresses, not domain names. Open Destination IPs to see where the hosts connected.")
    elif metric == "dst_ips":
        rows = []
        for d, x in group("dst_ip"):
            rows.append({"value": d, "dst": mip(d), "country": next(iter(x["geo"]), ""),
                         "network": _A.asn_registry.label(next(iter(x["asn"])), demo) if x["asn"] else "",
                         "ports": sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0), "domains": sorted(x["dom"])[:3],
                         "events": x["events"], "hosts": len(x["hosts"]), "infections": sorted(x["inf"])})
        out.update(title="Destination IPs contacted", row_kind="dst_ip",
                   intro=f"{len(rows):,} destination addresses (sinkholes, honeypot sensors or targets), most contacted first.",
                   columns=[["dst", "Destination IP"], ["country", "Country"], ["network", "Network"], ["ports", "Ports"],
                            ["domains", "Domains"], ["events", "Events"], ["hosts", "Source hosts"], ["infections", "Infections / categories"]],
                   rows=rows)
        if demo:
            for r in rows:
                r["value"] = _A.host_refs.ref(r["value"])   # concealed, but still clickable

    elif metric == "beacons":
        if demo:                          # analysts and admins only, like the figure
            out.update(title="Decoded beacons", rows=[], empty="Decoded beacons are shown to analysts and administrators.")
        elif not _A.beacon_stats.ready(day):
            out.update(title="Decoded beacons", rows=[], empty="The day's beacons are still being decoded. Try again in a minute.")
        else:
            out.update(_A.beacon_stats.drill(ev, mt))

    rows = out.get("rows", [])
    out["total"] = len(rows)
    out["rows"] = rows if _A.request.args.get("all") == "1" else rows[:_A.DRILL_LIMIT]   # all=1: CSV export
    out.setdefault("columns", [])
    return _A.jsonify(out)


def install(flask_app, app_module):
    """Register this code's routes and hooks on the Flask app, in their order, and use app_module for its names."""
    global _A
    _A = app_module
    for kind, args, kwargs, fn in _R.calls:
        target = getattr(flask_app, kind)
        if args or kwargs or kind not in ("before_request", "after_request", "teardown_request", "context_processor"):
            target(*args, **kwargs)(fn)
        else:
            target(fn)
