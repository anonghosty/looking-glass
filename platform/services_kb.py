"""Services on the researchers' page (the Definitions page): every publicly accessible / vulnerable services report as
something a researcher studies and defines, next to Infections and Issues.

The reports come from the report map (report_map.py: the "Services" section and its groups); an IPv6 report is shown
with its IPv4 twin (Accessible RDP = scan_rdp + scan6_rdp). For each one:

* what Shadowserver says: its title, severity and page, and what the report feed knows about that page (last updated,
  its fields; the description text only when the feed carries it: Shadowserver's wording, attributed);
* what Looking Glass says: the definition and "why it matters" of data/service_reports.json;
* what the reports show here, over the services days in memory: hosts and records (counts only), and on those hosts
  the products, devices and versions, ports, severities, and the issues (CVEs, with CISA KEV / CVSS / EPSS, and the
  other tags), which link to the Issues section;
* the researchers' notes on it (notes.py, section "services");
* "Looking Glass asks": a new services report type, a changed one, an updated Shadowserver description.

Researchers never see a host: no address, host name, network or place is in any answer (checked by
tests/check_services_kb.py).

API (the Definitions permission, as the rest of the page): GET /api/kb/services, GET /api/kb/service?name=.
Installed from app.py: services_kb.install(app, ctx).
"""
import collections
import re
import threading
import time

from flask import jsonify, request

from report_map import sibling
from svc_patterns import MIN_HOSTS

CACHE_SECONDS = 60
TOP = 12
_STATS = {"at": 0.0, "data": None, "days": []}
_LOCK = threading.Lock()


def _stats(store, load_day=None):
    """report -> aggregates over the services days in memory (counts only; the host sets never leave this function).
    load_day() brings the current replay day into memory first (after a restart nothing is loaded until asked)."""
    with _LOCK:
        if time.time() - _STATS["at"] < CACHE_SECONDS and _STATS["data"]:
            return _STATS["data"], _STATS["days"]
        if load_day:
            try:
                load_day()
            except Exception:                              # noqa: BLE001  (the days already in memory still count)
                pass
        acc = {}
        days = []
        for key, d in sorted(list(store.days.items())):
            n = 0
            for e in d.events:
                r = e.get("report") or ""
                x = acc.get(r)
                if x is None:
                    x = acc[r] = {"records": 0, "hosts": set(), "products": collections.Counter(), "devices": collections.Counter(),
                                  "versions": collections.Counter(), "ports": collections.Counter(), "severity": collections.Counter(),
                                  "issues": collections.defaultdict(set), "tags": collections.Counter(), "per_day": collections.Counter()}
                ip = e.get("ip")
                x["records"] += 1
                x["hosts"].add(ip)
                x["per_day"][str(key)] += 1
                if e.get("product"):
                    x["products"][e["product"]] += 1
                dev = " ".join(v for v in (e.get("vendor"), e.get("device_type")) if v)
                if dev:
                    x["devices"][dev] += 1
                if e.get("version"):
                    x["versions"][f"{e.get('product') or e.get('vendor') or ''} {e['version']}".strip()] += 1
                if e.get("port"):
                    x["ports"][f"{e['port']}/{(e.get('protocol') or '').lower() or '?'}"] += 1
                x["severity"][e.get("severity") or "unrated"] += 1
                for i in e.get("issues") or ():
                    x["issues"][i].add(ip)
                for t in e.get("tags") or ():
                    if not re.match(r"(?i)^cve-", t):
                        x["tags"][t] += 1
                n += 1
            days.append({"day": str(key), "records": n})
        out = {}
        for r, x in acc.items():
            out[r] = {"records": x["records"], "hosts": len(x["hosts"]),
                      "products": x["products"].most_common(TOP), "devices": x["devices"].most_common(TOP),
                      "versions": x["versions"].most_common(TOP), "ports": x["ports"].most_common(TOP),
                      "severity": dict(x["severity"]), "tags": x["tags"].most_common(TOP),
                      "issues": sorted(((i, len(h)) for i, h in x["issues"].items()), key=lambda t: -t[1]),
                      "per_day": dict(x["per_day"])}
        if out:                                            # an empty answer is never kept: the day may still be loading
            _STATS.update(at=time.time(), data=out, days=days)
        return out, days


def _merge(parts):
    """The aggregates of a report and its IPv6 twin, added up (hosts are counted per report: a host on both counts twice)."""
    out = {"records": 0, "hosts": 0, "severity": collections.Counter(), "per_day": collections.Counter()}
    lists = {k: collections.Counter() for k in ("products", "devices", "versions", "ports", "tags", "issues")}
    for p in parts:
        if not p:
            continue
        out["records"] += p["records"]; out["hosts"] += p["hosts"]
        out["severity"].update(p["severity"]); out["per_day"].update(p["per_day"])
        for k in lists:
            lists[k].update(dict(p[k]))
    for k, c in lists.items():
        out[k] = c.most_common(TOP if k != "issues" else 200)
    out["severity"], out["per_day"] = dict(out["severity"]), dict(out["per_day"])
    return out


def install(app, ctx):
    """ctx: report_map (ReportMap), svc_store, load_day() (the current replay day into memory), report_info(name),
    notes (Notes), allowed(), cve_card(name), issues_kb(), collections() (report collections in the database);
    for the patterns (phase 2b): patterns (svc_patterns.Patterns), services_intel (services_intel.ServicesIntel),
    change_allowed() (may write, CSRF checked), fresh() (recent sign-in), audit, user()."""
    rmap = ctx["report_map"]
    pat, sintel = ctx.get("patterns"), ctx.get("services_intel")

    def pattern_asks(base, names, hosts):
        """What Looking Glass asks a researcher about a report's pattern fields (empty: nothing to check)."""
        if not pat or not hosts:
            return []
        out = []
        fields = [f for f in pat.fields_for(base) if f["kind"] != "tags"]
        if not fields:
            out.append("Choose its pattern fields: only its tags are read so far.")
        if sintel and fields:
            seen = {lbl for (lbl, _v) in (sintel.index()["vals"].get(base) or {})}
            gone = [f["label"] for f in fields if f["label"] not in seen]
            if gone:
                out.append(f"{', '.join(gone)}: no longer in the records. Check its pattern fields.")
        own = pat.choice(base)
        if own and own.get("reviewed"):
            now = set()
            for n in names:
                p = rmap.description(n) or {}
                now.update(p.get("field_names") or [])
            new = sorted(now - set(own["reviewed"]))
            if new:
                out.append(f"Shadowserver added field{'s' if len(new) > 1 else ''} {', '.join(new[:6])}: check its pattern fields.")
        return out

    def services_reports():
        """base name -> {entry, names[]}: the Services section of the map, IPv6 twins folded into their IPv4 report."""
        out = {}
        for k, e in (rmap.get().get("reports") or {}).items():
            if e.get("section") != "Services":
                continue
            base = sibling(k)
            if base not in (rmap.get().get("reports") or {}):
                base = k
            g = out.setdefault(base, {"entry": None, "names": []})
            g["names"].append(k)
            if k == base:
                g["entry"] = e
        for base, g in out.items():
            g["entry"] = g["entry"] or (rmap.entry(g["names"][0]) or {})
        return out

    def issue_row(name, hosts):
        row = {"name": name, "hosts": hosts, "cve": bool(re.match(r"(?i)^cve-\d{4}-\d{4,7}$", name))}
        if row["cve"]:
            try:
                c = ctx["cve_card"](name)
                row.update(exploited=bool(c.get("exploited")), cvss=(c.get("cvss") or {}).get("score"), epss=c.get("epss"))
            except Exception:                              # noqa: BLE001  (a CVE without its card is still listed)
                pass
        else:
            row["defined"] = bool((ctx["issues_kb"]().get(name.lower()) or {}).get("description"))
        return row

    def page_facts(names):
        for n in names:
            p = rmap.description(n)
            if p:
                keep = {k: p[k] for k in ("title", "last_updated", "severity", "field_names", "fetched") if k in p}
                if (rmap.descriptions().get("text_included")) and p.get("blocks"):
                    keep.update(blocks=p["blocks"], notes=p.get("notes", []), fields=p.get("fields", {}),
                                source="The Shadowserver Foundation")
                return keep
        return {}

    def events_for(groups):
        names = {n for g in groups.values() for n in g["names"]}
        urls = {(g["entry"] or {}).get("url") for g in groups.values()}
        return [e for e in (rmap.get().get("events") or [])
                if e.get("report") in names or (e.get("kind") == "description_changed" and e.get("url") in urls)][:30]

    @app.route("/api/kb/services")
    def api_kb_services():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        groups = services_reports()
        stats, days = _stats(ctx["svc_store"], ctx.get("load_day"))
        try:
            in_db = set(ctx["collections"]())
        except Exception:                                  # noqa: BLE001  (no database: shown as not known)
            in_db = set()
        new = {e["report"] for e in (rmap.get().get("events") or []) if e.get("kind") == "new_report"}
        rows = []
        for base, g in groups.items():
            e = g["entry"]
            agg = _merge([stats.get(n) for n in g["names"]])
            info = ctx["report_info"](base) or {}
            notes = ctx["notes"].list("services", base)
            pf = page_facts(g["names"])
            top_issues = [issue_row(i, h) for i, h in agg["issues"][:40]]
            top_issues.sort(key=lambda r: (not r.get("exploited"), -(r.get("cvss") or 0), -r["hosts"]))
            rows.append({
                "name": base, "names": sorted(g["names"]), "title": re.sub(r"^IPv6 ", "", e.get("title") or info.get("title") or base),
                "group": e.get("group", ""), "severity": e.get("severity") or info.get("severity", ""), "url": e.get("url", ""),
                "received": any(n in in_db for n in g["names"]), "hosts": agg["hosts"], "records": agg["records"],
                "ipv6": [n for n in g["names"] if n != base],
                "products": [p for p, _ in agg["products"][:3]], "ports": [p for p, _ in agg["ports"][:3]],
                "issues": top_issues[:5], "issues_total": len(agg["issues"]),
                "exploited": sum(1 for r in top_issues if r.get("exploited")),
                "def": info.get("def", ""), "why": info.get("why", ""),
                "notes": len(notes), "last_note": notes[0]["date"] if notes else "",
                "page": {k: pf.get(k) for k in ("last_updated", "fetched") if pf.get(k)} | {"fields": len(pf.get("field_names") or [])},
                "new": any(n in new for n in g["names"]),
                "pattern_asks": pattern_asks(base, g["names"], agg["hosts"]),
                "pattern_fields": [f["label"] for f in pat.fields_for(base)] if pat else []})
        order = (ctx["report_map"].rules().get("group_order") or {}).get("Services") or []
        rows.sort(key=lambda r: (order.index(r["group"]) if r["group"] in order else 99, -r["hosts"], r["title"]))
        st = rmap.get().get("status") or {}
        return jsonify(groups=order, reports=rows, days=days, events=events_for(groups),
                       status={"source": st.get("source"), "schema_commit": str(st.get("schema_commit", ""))[:7],
                               "feed_checked": st.get("feed_checked", ""), "feed_error": st.get("feed_error", ""),
                               "text_included": bool(rmap.descriptions().get("text_included"))})

    @app.route("/api/kb/service")
    def api_kb_service():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        name = (request.args.get("name") or "").strip()[:80]
        groups = services_reports()
        base = name if name in groups else sibling(name)
        g = groups.get(base)
        if not g:
            return jsonify(error="No such services report."), 404
        stats, days = _stats(ctx["svc_store"], ctx.get("load_day"))
        agg = _merge([stats.get(n) for n in g["names"]])
        info = ctx["report_info"](base) or {}
        e = g["entry"]
        issues = [issue_row(i, h) for i, h in agg["issues"]]
        issues.sort(key=lambda r: (not r.get("exploited"), -(r.get("cvss") or 0), -r["hosts"]))
        return jsonify(
            name=base, names=sorted(g["names"]), title=re.sub(r"^IPv6 ", "", e.get("title") or base), group=e.get("group", ""),
            severity=e.get("severity", ""), url=e.get("url", ""), classification=f"{e.get('taxonomy') or '?'} / {e.get('type') or '?'}",
            classified=e.get("classified", ""), placed_by=e.get("placed_by", ""),
            definition={"def": info.get("def", ""), "why": info.get("why", ""), "by": "Looking Glass"},
            shadowserver=page_facts(g["names"]), hosts=agg["hosts"], records=agg["records"], days=days, per_day=agg["per_day"],
            products=agg["products"], devices=agg["devices"], versions=agg["versions"], ports=agg["ports"],
            severity_counts=agg["severity"], tags=agg["tags"], issues=issues[:60], issues_total=len(issues),
            notes=ctx["notes"].list("services", base), pattern_asks=pattern_asks(base, g["names"], agg["hosts"]))

    # ---------------- phase 2b: patterns, across reports, sinkholes; the pattern fields and product rules
    def _base_or_404(name):
        groups = services_reports()
        base = name if name in groups else sibling(name)
        return base if base in groups else None

    @app.route("/api/kb/service/intel")
    def api_kb_service_intel():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        base = _base_or_404((request.args.get("name") or "").strip()[:80])
        if not base or not sintel:
            return jsonify(error="No such services report."), 404
        return jsonify(sintel.gathered(base))

    @app.route("/api/kb/service/fields", methods=["GET", "POST"])
    def api_kb_service_fields():
        if request.method == "GET":
            if not ctx["allowed"]():
                return jsonify(error="Definitions are for researchers and admins."), 403
            base = _base_or_404((request.args.get("name") or "").strip()[:80])
            if not base or not pat:
                return jsonify(error="No such services report."), 404
            recs = sintel.records_of(base) if sintel else []
            own = pat.choice(base)
            return jsonify(report=base, fields=pat.fields_for(base), suggestions=pat.suggest(base, recs),
                           chosen_by=({"by": own.get("by"), "date": own.get("date")} if own else None),
                           shipped=bool((pat.shipped().get("reports") or {}).get(base)), records=len(recs),
                           min_hosts=MIN_HOSTS)
        if not ctx["change_allowed"]():
            return jsonify(error="Only researchers and admins can choose pattern fields."), 403
        if ctx.get("fresh") and not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        base = _base_or_404(str(b.get("name") or "").strip()[:80])
        if not base or not pat:
            return jsonify(error="No such services report."), 404
        user = (ctx["user"]() or {}).get("user", "") if ctx.get("user") else ""
        if b.get("reset"):
            pat.reset(base)
            ctx["audit"].add("pattern_fields_reset", user=user, target=f"service:{base}", detail="back to the shipped pattern fields")
            return jsonify(saved=True, fields=pat.fields_for(base))
        recs = sintel.records_of(base) if sintel else []
        allowed = {s["field"]: s for s in pat.suggest(base, recs)}
        fields = b.get("fields") or []
        if not isinstance(fields, list) or len(fields) > 12:
            return jsonify(error="Choose up to 12 pattern fields."), 400
        for f in fields:
            s = allowed.get(str((f or {}).get("field") or ""))
            if s is None:
                return jsonify(error=f"{(f or {}).get('field')}: not a field of this report's records."), 400
            if not s["may"]:
                return jsonify(error=f"{s['field']}: {s['why']}."), 400
        reviewed = set(allowed)                            # the fields known now: new ones are asked about later
        for n in services_reports()[base]["names"]:
            reviewed.update((rmap.description(n) or {}).get("field_names") or [])
        try:
            clean = pat.save(base, fields, user, reviewed)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        if sintel:
            sintel.cache["key"] = None                     # the patterns are recounted with the new fields
        ctx["audit"].add("pattern_fields_set", user=user, target=f"service:{base}",
                         detail=", ".join(f"{f['field']} ({f['kind']})" for f in clean)[:200])
        return jsonify(saved=True, fields=pat.fields_for(base))

    @app.route("/api/kb/product-rules", methods=["GET", "POST"])
    def api_kb_product_rules():
        if request.method == "GET":
            if not ctx["allowed"]():
                return jsonify(error="Definitions are for researchers and admins."), 403
            return jsonify(rules=pat.rules() if pat else [])
        if not ctx["change_allowed"]():
            return jsonify(error="Only researchers and admins can add product rules."), 403
        if ctx.get("fresh") and not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        user = (ctx["user"]() or {}).get("user", "") if ctx.get("user") else ""
        try:
            pat.add_rule(b.get("contains"), b.get("product"), b.get("version"), user)
        except ValueError as e:
            return jsonify(error=str(e)), 400
        if sintel:
            sintel.cache["key"] = None
        ctx["audit"].add("product_rule_added", user=user, target=str(b.get("product"))[:60], detail=f"text: {str(b.get('contains'))[:60]}")
        return jsonify(saved=True, rules=pat.rules())
