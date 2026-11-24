# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The PDF and ZIP reports of an analysis figure, on both platforms

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


# ------------------------------------------------------------------ PDF reports of an analysis figure (both platforms)
def _scope_text():
    idx = _A._country_index().get(_A.settings.data["country"], {})
    c = idx.get("country", _A.settings.data["country"])
    if _A.settings.restricted:
        n, k = len(_A.settings.data["networks"]), len(_A.settings.data["cidrs"])
        return f"{c} · constituency: {n} network{'s' if n != 1 else ''}" + (f" and {k} address range{'s' if k != 1 else ''}" if k else "")
    return f"{c} · whole country"


def _view_json(name):
    """Run another endpoint's view with this request's arguments; (data, None) or (None, error response)."""
    res = _A.app.view_functions[name]()
    if isinstance(res, tuple):
        return None, res
    return res.get_json(), None


def _pdf_label():
    import re as _re
    return _re.sub(r"[\x00-\x1f]", " ", _A.request.args.get("label") or "").strip()[:160]


def _file_base(parts):
    import re as _re
    return "looking-glass_" + ("_".join(_re.sub(r"[^\w.-]+", "-", str(p)).strip("-")[:40] for p in parts if p) or "report")


def _report_response(pdf, base, cols, prow):
    """format=pdf: the PDF alone. Otherwise (default) a ZIP with the PDF and the complete list as CSV."""
    import io as _io, zipfile
    if _A.request.args.get("format") == "pdf":
        return _A.Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{base}.pdf"', "Cache-Control": "no-store"})
    import csvsafe   # no spreadsheet formulas in any cell
    buf = _io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow([lbl for _, lbl in cols])
    for r in prow:
        w.writerow([r.get(k, "") for k, _ in cols])
    z = _io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{base}.pdf", pdf)
        zf.writestr(f"{base}.csv", "\ufeff" + buf.getvalue())
    return _A.Response(z.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{base}.zip"', "Cache-Control": "no-store"})


def _short(x):
    if x.get("kind") == "cve":
        bits = [f"CVSS {x['cvss']['score']} {x['cvss'].get('severity', '')}".strip()] if x.get("cvss") else []
        if x.get("exploited"):
            bits.append("ACTIVELY EXPLOITED (CISA KEV)")
        if x.get("epss") is not None:
            bits.append(f"EPSS {x['epss']:.1%}")
        if x.get("pending"):
            bits.append("not looked up yet")
        elif not x.get("found"):
            bits.append("no public record")
        name = (x.get("kev") or {}).get("name") or __import__("cves").short_title(x.get("description"))   # whole first sentence
        return f"{name} ({', '.join(bits)})" if name else ", ".join(bits)
    if x.get("found") and x.get("kind") == "actor":
        return f"{x.get('name')} (threat actor)"
    if x.get("found"):
        return f"{x.get('name')} ({x.get('family')})"
    if x.get("curated"):
        return f"{x.get('title')} (Looking Glass definition)"
    if x.get("reference"):
        return f"{x.get('name')} ({x.get('source_label')})"
    if x.get("nosource"):
        return f"no source knows this name: {x.get('title')}"
    return x.get("title") or "no source knows this name"


def _enrich_names(ordered):
    """[(name, stat)] -> ({name: card}, {name: stat}, note). At most 60 names (Malpedia answers are cached)."""
    if not _A.AUTH["has_perm"]("malpedia"):
        return {}, {}, ""
    out, stats = {}, {}
    for name, stat in ordered:
        if len(out) >= 60:
            break
        if not name or name.startswith("ref:") or name in out:
            continue
        try:
            out[name] = _A.mp_resolve(name)[0]
        except ValueError:
            continue
        except RuntimeError as exc:
            out[name] = {"found": False, "pending": True, "title": "Not checked yet",
                         "reason": f"Malpedia did not answer in time ({_A.security.public_error(exc, 'no answer')}). Download the report again in a minute."}
        stats[name] = stat
    note = ("Each infection / category was looked up on Malpedia, the malware encyclopedia of Fraunhofer FKIE (malware "
            "families, and threat actors for group names). Names Malpedia does not list are explained from the definitions "
            "written by the security researchers of the organisation that uses this platform, with their references, then "
            "from MISP Galaxy and MITRE ATT&CK (copies kept on the server), or from the evidence in the reports."
            if _A.malpedia.enabled else
            "Malpedia is not set up on this platform, so the infections / categories are explained from the definitions "
            "written by the security researchers of the organisation that uses this platform (with their references) and "
            "the Looking Glass knowledge base, then from MISP Galaxy and MITRE ATT&CK (copies kept on the server), or from "
            "the evidence in the reports.")
    return out, stats, note


def _bd_rows(rows, total, hosts=False):
    out = []
    for r in rows:
        share = r.get("share")
        share = share if isinstance(share, (int, float)) else (r.get("count", 0) / max(1, total))
        row = [r.get("label") or r.get("value") or "(none)", f"{r.get('count', 0):,}"]
        if hosts:
            row.append(f"{r.get('hosts', 0):,}")
        out.append(row + [f"{share:.1%}"])
    return out


def _pdf_rows(columns, rows, enr, issues=False, row_name=False):
    """Cells as printed text; plus what each infection (or issue) is, when the list has them."""
    has_inf = enr and (row_name or any(k in (("issues",) if issues else ("infections", "infection")) for k, _ in columns))
    label = "What it is (CVE: NVD / CISA KEV / EPSS; others: definition)" if issues else "What it is"
    cols = columns + ([["_explained", label]] + ([] if issues else [["_source", "Source"]]) + [["_attack", "MITRE ATT&CK"]]
                      if has_inf else [])
    out = []
    for r in rows:
        x = {}
        for k, _ in cols:
            v = r.get(k)
            if k == "_explained":
                names = ([r.get("name")] if row_name else (r.get("issues") or [])) if issues else \
                    [n for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n]
                v = "; ".join(f"{n}: {_A._short(enr[n])}" for n in names if n in enr)
            elif k == "_attack":                  # the ATT&CK techniques (IDs) of each name / issue, with the version used
                names = ([r.get("name")] if row_name else (r.get("issues") or [])) if issues else \
                    [n for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n]
                v = "; ".join(f"{n}: {_A.attack_map.ids_text(enr[n].get('attack'))}" for n in names if n in enr and enr[n].get("attack"))
            elif k == "_source":                  # which source answered, and the others that know the name
                names = [n for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n]
                v = "; ".join(f"{n}: {', '.join(enr[n].get('sources') or []) or 'no source knows this name'}" for n in names if n in enr)
            elif k == "followup":
                v = "; ".join(v or []) or "Monitor"
            elif isinstance(v, list):
                v = ", ".join(str(i) for i in v)
            elif isinstance(v, (int, float)):
                v = f"{v:,}"
            elif k in ("first", "last") and isinstance(v, str) and "T" in v:
                v = v.replace("T", " ")[:19]
            elif k == "city":
                v = (v or "").title()
            x[k] = "" if v is None else v
        out.append(x)
    return cols, out


SOURCES_TEXT = [
    "Data: the Shadowserver Foundation's free daily network reports for the constituency (sinkholes, honeypots and "
    "internet-wide scans). An event is one report row; one host can appear in many rows and reports.",
    "Malware families and threat actors: Malpedia (Fraunhofer FKIE), malpedia.caad.fkie.fraunhofer.de.",
    "Looking Glass definitions: written by the security researchers of the organisation that uses this platform, for "
    "names that Malpedia does not list and for issues that are not CVEs, each with its references (evidence) and the "
    "name of the researcher who wrote it.",
    "Names neither Malpedia nor the researchers explain: MISP Galaxy (its Malpedia cluster is Malpedia content, "
    "CC BY-NC-SA 3.0; Botnet and Tool clusters CC0 1.0 / BSD 2-Clause) and MITRE ATT&CK (© The MITRE Corporation, "
    "reproduced and distributed with the permission of The MITRE Corporation), read from copies kept on the server.",
    "Vulnerabilities (CVEs): NIST National Vulnerability Database (description, CVSS score), CISA Known Exploited "
    "Vulnerabilities catalog (confirmed active exploitation) and FIRST EPSS (probability of exploitation in the next 30 days).",
    "Figures describe the replay day up to the time of the analysis. The complete list is in the CSV file delivered "
    "with this report.",
]


@_R.route("/api/insight/report.pdf")
@_R.route("/api/insight/report")
def api_insight_report_pdf():
    """PDF of one analysis figure on the network-communications platform (same arguments as the drill-down + all=1)."""
    if not _A.AUTH["has_perm"]("export"):
        return _A.jsonify(error="Your role cannot download reports (permission 'export')."), 403
    if _A.request.args.get("all") != "1":
        return _A.jsonify(error="all=1 expected"), 400
    I, err = _A._view_json("api_insight")
    if err:
        return err
    D, err = _A._view_json("api_insight_drill")
    if err:
        return err
    import reports_pdf
    rows = D.get("rows") or []
    # what to explain: the selection's infections by events, then any other name in the list
    inf_b = (I.get("breakdowns") or {}).get("infection") or []
    ordered = [(r["value"], f"{r['count']:,} events ({r['share']:.1%} of the selection)") for r in inf_b if r.get("value")]
    if I.get("kind") == "infection":
        ordered.insert(0, (I["value"], f"{I['total']:,} events"))
    seen = _A.Counter(n for r in rows for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n)
    ordered += [(n, f"on {k:,} listed entr{'y' if k == 1 else 'ies'}") for n, k in seen.most_common()]
    enr, stats, note = _A._enrich_names(ordered)

    pts = list(I.get("insights") or [])
    hostish = D.get("row_kind") == "src_ip"
    priorities = None
    if hostish and rows:
        top = [r for r in rows if r.get("score", 0) >= 2][:15] or rows[:10]
        priorities = (["Host IP", "Follow-up", "Events", "Infections / categories", "Reports", "Network"],
                      [[r.get("ip"), "; ".join(r.get("followup") or []) or "Monitor", f"{r.get('events', 0):,}",
                        ", ".join(r.get("infections") or []), ", ".join(r.get("reports") or []), r.get("network")] for r in top],
                      [0.12, 0.2, 0.07, 0.23, 0.23, 0.15])
    if enr:
        f = sum(1 for x in enr.values() if x.get("found") and x.get("kind") != "actor")
        a = sum(1 for x in enr.values() if x.get("kind") == "actor")
        c = sum(1 for x in enr.values() if x.get("curated"))
        o = sum(1 for x in enr.values() if x.get("reference"))      # MISP Galaxy / MITRE ATT&CK answered (name_sources.py)
        rest = len(enr) - f - a - c - o
        pts.append(f"Of the {len(enr)} infections / categories explained in this report, {f} are malware families in Malpedia"
                   + (f", {a} {'is a threat actor' if a == 1 else 'are threat actors'}" if a else "")
                   + (f", {c} {'has' if c == 1 else 'have'} a Looking Glass definition" if c else "")
                   + (f", {o} {'is' if o == 1 else 'are'} described by MISP Galaxy or MITRE ATT&CK" if o else "")
                   + (f" and {rest} {'is' if rest == 1 else 'are'} known to no source (explained from the report evidence)"
                      if rest else "") + ".")
    peak = I.get("peak_hour")
    kpis = [(f"{I.get('total', 0):,}", "events in this selection"), (f"{I.get('share', 0):.1%}", f"of the day's {I.get('all_total', 0):,} events"),
            (f"{I.get('hosts', 0):,}", "source hosts"), (f"{I.get('reports', 0):,}", "reports"),
            (f"{I.get('cross_report_hosts', 0):,}", "hosts in several reports"), (f"{I.get('multi_infected', 0):,}", "hosts with several infections"),
            (f"{I.get('regular_beacons', 0):,}", "hosts beaconing regularly"), (I.get("beacon_median_label") or "", "typical repeat interval"),
            (f"{I.get('c2_hosts', 0):,}", "C2 / sinkhole domains"), (f"{I.get('dst_ips', 0):,}", "destination IPs"),
            (f"{peak:02d}:00 UTC" if peak is not None else "", "peak hour"), (f"{len(rows):,}", "entries in this list")]
    if I.get("decoded_beacons") is not None:
        kpis.append((f"{I['decoded_beacons']:,}", "decoded beacons"))
    B = I.get("breakdowns") or {}
    for r in B.get("src_city") or []:
        r["label"] = str(r.get("label") or "").title()
    titles = [("source", "Reports"), ("attack_class", "Attack types"), ("infection", "Infections / categories"), ("severity", "Severity"),
              ("src_city", "Cities"), ("src_asn", "Source networks"), ("http_host", "C2 / sinkhole domains"), ("dst_geo", "Destination countries"),
              ("dst_asn", "Destination networks"), ("dst_ip", "Destination IPs"), ("dst_port", "Destination ports"), ("tag", "Tags"),
              ("request", "Requested paths"), ("http_agent", "User agents")]
    total = I.get("total", 0)
    bds = [(lbl, [lbl, "Events", "Share"], _A._bd_rows(B[k], total)) for k, lbl in titles if B.get(k)]
    charts = [(lbl, B[k]) for k, lbl in (("source", "Reports"), ("infection", "Infections / categories"), ("src_asn", "Source networks"),
                                          ("src_city", "Cities"), ("attack_class", "Attack types"), ("dst_geo", "Destination countries")) if B.get(k)]
    gl = []
    labels = {x["name"]: x["label"] for x in _A.registry.get()}
    for r in B.get("source") or ([{"value": I["value"]}] if I.get("kind") == "source" else []):
        d = _A._report_def(r["value"])
        item = (d.get("title") or labels.get(r["value"], r["value"]), " ".join(v for v in (d.get("def"), d.get("why")) if v), d.get("url"))
        if item[0] not in {x[0] for x in gl}:
            gl.append(item)
    cols, prow = _A._pdf_rows(D.get("columns") or [], rows, enr)
    sel = _A._pdf_label() or f"{I.get('kind_label', '')}: {I.get('value_label') or I.get('value', '')}"
    base = _A._file_base([(I.get("as_of") or "")[:10], sel, D.get("metric")])
    spec = {"platform_label": "Network communications", "csv_name": f"{base}.csv", "title": D.get("title"), "selection": sel, "day": (I.get("as_of") or "")[:10],
            "generated_by": (getattr(_A.g, "user", None) or {}).get("user", ""), "scope": _A._scope_text(), "demo": _A.is_demo(),
            "intro": D.get("intro"), "summary_points": pts, "kpis": kpis, "hours": I.get("hours"), "peak_hour": peak,
            "priorities": priorities, "enrichment": enr, "enrichment_stats": stats, "enrichment_note": note,
            "columns": cols, "rows": prow, "total": D.get("total", len(rows)), "breakdowns": bds, "charts": charts,
            "glossary": gl, "sources": _A.SOURCES_TEXT}
    pdf = reports_pdf.build(spec)
    _A.AUTH["audit"].add("report_pdf", user=(getattr(_A.g, "user", None) or {}).get("user", ""), target=f"comms:{D.get('metric')}",
                      detail=f"{sel[:80]} · {len(rows)} rows")
    return _A._report_response(pdf, base, cols, prow)


@_R.route("/api/svc/report.pdf")
@_R.route("/api/svc/report")
def api_svc_report_pdf():
    """PDF of one analysis figure on the publicly accessible / vulnerable services platform."""
    if not _A.AUTH["has_perm"]("export"):
        return _A.jsonify(error="Your role cannot download reports (permission 'export')."), 403
    if _A.request.args.get("all") != "1":
        return _A.jsonify(error="all=1 expected"), 400
    I, err = _A._view_json("svc_insight")
    if err:
        return err
    D, err = _A._view_json("svc_drill")
    if err:
        return err
    import reports_pdf
    rows = D.get("rows") or []
    pts = list(I.get("findings") or [])
    priorities = None
    if D.get("row_kind") == "ip" and rows:
        top = [r for r in rows if len(r.get("issues") or []) > 1 or "critical" in (r.get("followup") or [])][:15] or rows[:10]
        priorities = (["Host IP", "Follow-up", "Issues", "Reports / services", "Records", "Network", "Device / product"],
                      [[r.get("ip"), "; ".join(r.get("followup") or []) or "Monitor", ", ".join(r.get("issues") or []),
                        ", ".join(r.get("services") or []), f"{r.get('events', 0):,}", r.get("network"), r.get("device")] for r in top],
                      [0.11, 0.13, 0.22, 0.22, 0.06, 0.13, 0.13])
    hours = None
    hb = I.get("hours_by_family") or {}
    if hb:
        hours = [sum(v[i] for v in hb.values()) for i in range(24)]
    peak = I.get("peak_hour")
    kpis = [(f"{I.get('total', 0):,}", "records in this selection"), (f"{I.get('share', 0):.1%}", f"of the day's {I.get('day_total', 0):,} records"),
            (f"{I.get('hosts', 0):,}", "hosts"), (f"{I.get('vulnerable_hosts', 0):,}", "hosts with a concrete issue"),
            (f"{I.get('multi_issue_hosts', 0):,}", "hosts with several issues"), (f"{I.get('cross_report_hosts', 0):,}", "hosts in several reports"),
            (f"{I.get('critical', 0):,}", "critical records"), (f"{I.get('high', 0):,}", "high-severity records"),
            (f"{I.get('services', 0):,}", "services (reports)"), (f"{I.get('networks', 0):,}", "networks"),
            (f"{I.get('issues', 0):,}", "different issues"), (f"{I.get('regions', 0):,}", "regions")]
    B = I.get("breakdowns") or {}
    total = I.get("total", 0)
    titles = [("service", "Services (reports)"), ("family", "Report families"), ("issue", "Issues"), ("severity", "Severity"),
              ("network", "Networks"), ("region", "Regions"), ("city", "Cities"), ("port", "Ports"), ("tag", "Tags"),
              ("vendor", "Vendors"), ("product", "Products"), ("device_type", "Device types"), ("sector", "Sectors")]
    bds = [(lbl, [lbl, "Records", "Hosts", "Share"], _A._bd_rows(B[k], total, hosts=True)) for k, lbl in titles if B.get(k)]
    charts = [(lbl, B[k]) for k, lbl in (("service", "Services (reports)"), ("issue", "Issues"), ("network", "Networks"),
                                          ("region", "Regions"), ("port", "Ports"), ("vendor", "Vendors")) if B.get(k)]
    G, _ = _A._view_json("svc_glossary")
    gl = []
    names = {str(r.get("value")) for r in B.get("service") or []} | {str(r.get("label")) for r in B.get("service") or []}
    for x in (G or {}).get("reports", []):
        if x["name"] in names or x["label"] in names:
            if (x.get("title") or x["label"]) not in {y[0] for y in gl}:
                gl.append((x.get("title") or x["label"], " ".join(v for v in (x.get("def"), x.get("why")) if v), x.get("url")))
    # the issues explained: CVEs (NVD, CISA KEV, EPSS) and the others (definitions; never looked up)
    enr, stats, note = {}, {}, ""
    if _A.AUTH["has_perm"]("malpedia"):
        counts = {}
        for r in B.get("issue") or []:
            counts[r["value"]] = (r.get("count", 0), r.get("hosts", 0))
        listed = _A.Counter(i for r in rows for i in ([r.get("name")] if D.get("row_kind") == "issue" else (r.get("issues") or [])) if i)
        order = sorted(set(counts) | set(listed), key=lambda i: (-counts.get(i, (0, 0))[1], -listed.get(i, 0)))[:80]
        enr = _A.issues_resolve(order, budget=20)
        for i in order:
            c = counts.get(i)
            stats[i] = f"{c[0]:,} records on {c[1]:,} hosts" if c else f"on {listed.get(i, 0):,} listed entr{'y' if listed.get(i, 0) == 1 else 'ies'}"
        kev = [i for i, x in enr.items() if x.get("exploited")]
        if kev:
            pts.insert(0, f"{len(kev)} of the issues in this selection {'is a vulnerability' if len(kev) == 1 else 'are vulnerabilities'} "
                          f"that CISA confirms {'is' if len(kev) == 1 else 'are'} being actively exploited (Known Exploited Vulnerabilities "
                          f"catalog): {', '.join(kev[:8])}"
                          # the rest named as a count, never cut off with "…" (2026-11-18)
                          + (f" and {len(kev) - 8} more, each explained under Issues explained" if len(kev) > 8 else "")
                          + ". Hosts with these should be patched first.")
        crit = [i for i, x in enr.items() if (x.get("cvss") or {}).get("score") and x["cvss"]["score"] >= 9]
        if crit:
            pts.append(f"{len(crit)} CVE{'s' if len(crit) != 1 else ''} in this selection {'is' if len(crit) == 1 else 'are'} rated critical (CVSS 9 or more).")
        note = ("Issues that are CVEs were looked up in the NIST National Vulnerability Database (description, CVSS score), "
                "CISA's Known Exploited Vulnerabilities catalog (confirmed active exploitation, required action) and FIRST EPSS "
                "(probability of exploitation in the next 30 days). Other issues are not looked up anywhere: they are explained "
                "from the definitions written by the security researchers of the organisation that uses this platform and the "
                "Looking Glass knowledge base, with their references.")
    cols, prow = _A._pdf_rows(D.get("columns") or [], rows, enr, issues=True, row_name=D.get("row_kind") == "issue")
    sel = _A._pdf_label() or "Selection"
    base = _A._file_base([I.get("day"), sel, D.get("metric")])
    spec = {"platform_label": "Publicly accessible / vulnerable services", "title": D.get("title"), "selection": sel,
            "csv_name": f"{base}.csv", "enrichment": enr, "enrichment_stats": stats, "enrichment_note": note,
            "enrichment_title": "Issues explained",
            "day": I.get("day"), "generated_by": (getattr(_A.g, "user", None) or {}).get("user", ""), "scope": _A._scope_text(),
            "demo": _A.is_demo(), "intro": D.get("intro"), "summary_points": pts, "kpis": kpis, "hours": hours, "peak_hour": peak,
            "priorities": priorities, "columns": cols, "rows": prow, "total": D.get("total", len(rows)), "breakdowns": bds,
            "charts": charts, "glossary": gl[:40], "sources": [_A.SOURCES_TEXT[0], _A.SOURCES_TEXT[2], _A.SOURCES_TEXT[3], _A.SOURCES_TEXT[4]]}
    pdf = reports_pdf.build(spec)
    _A.AUTH["audit"].add("report_pdf", user=(getattr(_A.g, "user", None) or {}).get("user", ""), target=f"services:{D.get('metric')}",
                      detail=f"{sel[:80]} · {len(rows)} rows")
    return _A._report_response(pdf, base, cols, prow)


@_R.route("/api/insight")
def api_insight():
    """Analytics for one entity (city, infection, C2 host, country, host, ASN) over the whole replay day."""
    kind = _A.request.args.get("kind", "")
    value = _A.request.args.get("value", "")
    if kind not in _A.INSIGHT_KINDS:
        return _A.jsonify(error="unknown kind"), 400
    rn = _A.parse_iso(_A.request.args.get("at"), _A.replay_now())
    demo = _A.is_demo()
    day, sofar, ev = _A._select_slice(kind, value, rn)
    n = len(ev)
    mip = _A.mask_ip if demo else (lambda s: s)

    # per-host timing -> beaconing analysis
    by_host = {}
    for e in ev:
        if e["src_ip"]:
            by_host.setdefault(e["src_ip"], []).append(e["_t"])
    intervals, regular = [], 0
    multi = 0
    for ip, ts in by_host.items():
        if len(ts) >= 3:
            d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
            if len(d) >= 2:
                m = _A._median(d)
                intervals.append(m)
                mean = sum(d) / len(d)
                sd = (sum((x - mean) ** 2 for x in d) / len(d)) ** 0.5
                if mean and sd / mean < 0.5:
                    regular += 1
    host_infections = {}
    for e in ev:
        if e["src_ip"]:
            host_infections.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")
    # co-infection: hosts in this slice that show >1 infection anywhere today
    all_inf = {}
    for e in sofar:
        if e["src_ip"] in by_host:
            all_inf.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")
    multi = sum(1 for s in all_inf.values() if len(s) > 1)

    hours = [0] * 24
    for e in ev:
        hours[int((e["_t"] - day.start.timestamp()) // 3600) % 24] += 1
    peak_hour = max(range(24), key=lambda h: hours[h]) if n else None

    # --- extra chart data for the analysis view
    t0 = day.start.timestamp()
    cur_hour = max(0, min(23, int((rn.timestamp() - t0) // 3600)))   # replay position marker only
    hours_by_class = {}
    timeline = [0] * 96
    for e in ev:
        hours_by_class.setdefault(e["attack_class"], [0] * 24)[int((e["_t"] - t0) // 3600) % 24] += 1
        timeline[min(95, int((e["_t"] - t0) // 900))] += 1
    severity = [{"value": v or "unrated", "count": k} for v, k in _A.Counter(e["severity"] for e in ev).most_common()]

    hosts_sorted = sorted(by_host.items(), key=lambda kv: -len(kv[1]))
    top_hosts = []
    for ip, ts in hosts_sorted[:10]:
        sample = next(e for e in ev if e["src_ip"] == ip)
        top_hosts.append({
            "ip": mip(ip), "ref": sample["src_ref"], "count": len(ts), "city": sample["src_city"],
            "asn": _A.asn_registry.label(sample["src_asn"], demo),
            "infections": sorted(host_infections.get(ip, [])),
            "first": _A.iso(_A.datetime.fromtimestamp(ts[0], _A.timezone.utc)), "last": _A.iso(_A.datetime.fromtimestamp(ts[-1], _A.timezone.utc)),
        })
    top10_share = sum(len(ts) for _, ts in hosts_sorted[:10]) / n if n else 0
    company = lambda a: _A.asn_registry.company(a, demo)

    labels = {s["name"]: s["label"] for s in _A.registry.get()}
    mt = _A.mask_text if demo else (lambda s: s)
    breakdowns = {
        "source": _A._top(ev, "source", 12, label=lambda v: labels.get(v, v)),
        "attack_class": _A._top(ev, "attack_class"),
        "infection": _A._top(ev, "infection"),
        "src_city": _A._top(ev, "src_city"),
        "src_asn": _A._top(ev, "src_asn", key=company),          # grouped by company (or alias)
        # grouped by the real value, shown masked in demo mode (the value becomes an opaque reference below)
        "http_host": _A._top(ev, "http_host", label=mt),
        "dst_ip": _A._top(ev, "dst_ip", label=mip),
        "dst_geo": _A._top(ev, "dst_geo"),
        "dst_asn": _A._top(ev, "dst_asn", key=company),
        "dst_port": _A._top(ev, "dst_port"),
        "http_agent": _A._top(ev, "http_agent", 5, label=mt),
        "severity": _A._top(ev, "severity"),
        "tag": _A._top(ev, "tag", 6),
    }
    paths = _A.Counter(_A._request_path(e["http_url"]) for e in ev if e["http_url"])
    breakdowns["request"] = [{"value": v, "label": mt(v), "count": k, "share": round(k / (len(ev) or 1), 4)} for v, k in paths.most_common(6)]
    if demo:
        for key in _A.REF_KINDS:
            for r in breakdowns.get(key, []):
                r["value"] = _A.host_refs.ref(r["value"])
    for r in breakdowns["dst_port"]:
        r["value"] = str(r["value"])
    breakdowns = {k: v for k, v in breakdowns.items() if v and not (k == kind)}

    # cross-report correlation: the same hosts seen in other collections today
    slice_hosts = set(by_host)
    host_sources = {}
    for e in sofar:
        if e["src_ip"] in slice_hosts:
            host_sources.setdefault(e["src_ip"], set()).add(e["source"])
    cross_hosts = [ip for ip, s in host_sources.items() if len(s) > 1]
    other_src = _A.Counter(s for ip in cross_hosts for s in host_sources[ip] if not (kind == "source" and s == value))
    n_reports = len({e["source"] for e in sofar})

    # plain-language findings
    insights = []
    if n:
        day_txt = rn.strftime("%Y-%m-%d")
        share = n / max(1, len(sofar))
        share_txt = "less than 0.1%" if 0 < share < 0.001 else f"{share:.1%}"
        insights.append(f"Shadowserver reported {n:,} event{'' if n == 1 else 's'} for {day_txt}. "
                        f"That is {share_txt} of all {len(sofar):,} events across {n_reports} reports.")
        src_b = breakdowns.get("source")
        if src_b and kind != "source":
            parts = ", ".join(f"{r['label']} {r['share']:.0%}" for r in src_b[:4])
            insights.append(f"Found in {len(src_b)} report{'s' if len(src_b) > 1 else ''}: {parts}.")
        insights.append(f"{len(by_host):,} different source hosts were involved. The 10 most active hosts account for {top10_share:.0%} of these events.")
        if cross_hosts and kind != "src_ip":
            top_other = ", ".join(f"{labels.get(s, s)} ({k:,})" for s, k in other_src.most_common(3))
            cls = {s["name"]: s["class"] for s in _A.registry.get()}
            mixed = sum(1 for ip in cross_hosts if len({cls.get(s) for s in host_sources[ip]}) > 1)
            msg = f"{len(cross_hosts):,} of these hosts also appear in other reports on the same day, most often in {top_other}."
            if mixed:
                msg += (f" {mixed:,} of them {'shows' if mixed == 1 else 'show'} more than one kind of activity"
                        " (for example botnet C2 traffic and attacks), which strongly suggests a compromised device.")
            else:
                msg += " They contact several sinkholes, which suggests several infections or command channels on the same device."
            insights.append(msg)
        # the host's address, not its reference: host_sources is keyed by address (review 2026-11-13: the reference
        # never matched, so this sentence never showed)
        host_ip = _A.host_refs.resolve(value) if kind == "src_ip" else None
        if kind == "src_ip" and len(host_sources.get(host_ip, ())) > 1:
            insights.append(f"This host appears in {len(host_sources[host_ip])} different reports on the same day.")
        if intervals:
            insights.append(f"Hosts seen more than once typically repeat every {_A._fmt_dur(_A._median(intervals))} (median). "
                            f"{regular:,} of these {len(intervals):,} hosts repeat at a regular rhythm, which points to automated beaconing or scripted attacks.")
        if multi:
            insights.append(f"{multi:,} of these hosts show more than one infection / category on the same day, which suggests several infections on one device or proxy software bundled with malware.")
        if peak_hour is not None:
            insights.append(f"Activity peaked between {peak_hour:02d}:00 and {(peak_hour + 1) % 24:02d}:00 UTC, with {hours[peak_hour]:,} events.")
        for key, what in (("source", "report"), ("infection", "infection / category"), ("src_asn", "source network"), ("http_host", "C2 domain"), ("src_city", "affected city")):
            b = breakdowns.get(key)
            if b and b[0]["share"] >= 0.5 and len(b) > 1:
                lbl = b[0]["label"].title() if key == "src_city" else b[0]["label"]
                insights.append(f"By {what}, {lbl} accounts for most of these events ({b[0]['share']:.0%}).")
        hosts_n = len({e["http_host"] for e in ev if e["http_host"]})
        if kind != "http_host" and hosts_n > 1:
            insights.append(f"{hosts_n:,} different C2 / sinkhole domains were contacted.")

    return _A.jsonify(
        kind=kind, kind_label=_A.INSIGHT_KINDS[kind], value=value, as_of=_A.iso(rn),
        total=n, share=round(n / max(1, len(sofar)), 4), all_total=len(sofar),
        # an empty value is not a network or an address (review 2026-11-13: both counts included it)
        hosts=len(by_host), asns=len({e["src_asn"] for e in ev if e["src_asn"]}), c2_hosts=len({e["http_host"] for e in ev if e["http_host"]}),
        dst_ips=len({e["dst_ip"] for e in ev if e["dst_ip"]}),
        first=ev[0]["extracted_date"] if ev else None, last=ev[-1]["extracted_date"] if ev else None,
        beacon_median=_A._median(intervals), beacon_median_label=_A._fmt_dur(_A._median(intervals)), regular_beacons=regular,
        multi_infected=multi, hours=hours, peak_hour=peak_hour,
        # decoded_beacons, beacon_devices: analysts and admins, once the day is labelled (beacon_stats.ready)
        **({} if _A.is_demo() or not _A.beacon_stats.ready(day) else _A.beacon_stats.counts(ev)),
        hours_by_class=hours_by_class, current_hour=cur_hour, timeline=timeline, severity=severity,        insights=insights, breakdowns=breakdowns, top_hosts=top_hosts,
        cross_report_hosts=len(cross_hosts), reports=len({e["source"] for e in ev}),
        value_label=_A._value_label(kind, value, demo, labels),
        scope=dict(zip(("kind", "value"), _A._parse_time_value(value)[2:])) if kind == "time" else None,
        scope_label=(lambda s: _A._value_label(s[2], s[3], demo, labels) if s[2] else None)(_A._parse_time_value(value)) if kind == "time" else None,
        asns_covered=[] if demo or kind not in ("src_asn", "dst_asn") else sorted(_A.asn_registry.resolve(value)),
    )


def _value_label(kind, value, demo, labels):
    """Human (and, in demo mode, concealed) title for the entity being analysed."""
    if kind == "time":
        start, dur, sk, sv = _A._parse_time_value(value)
        return f"{_A._hm(start)} to {_A._hm(start + dur)} UTC"   # the browser adds the selection it belongs to
    if kind == "source":
        return labels.get(value, value)
    if kind in ("src_asn", "dst_asn"):
        asns = sorted(_A.asn_registry.resolve(value))
        if demo:
            return _A.asn_registry.alias(asns[0]) if asns else value
        name = _A.asn_registry.name(asns[0]) if asns else None
        return f"{name} ({', '.join('AS' + a for a in asns)})" if name else f"AS{value}"
    if kind == "src_ip":
        ip = _A.host_refs.resolve(value)
        return _A.mask_ip(ip) if demo else ip
    if kind in _A.REF_KINDS:
        value = _A.host_refs.resolve(value)
    if kind == "dst_ip":
        return _A.mask_ip(value) if demo else value
    if kind in ("http_host", "http_agent", "request"):
        return _A.mask_text(value) if demo else value
    if kind == "dst_port":
        return f"Port {value}"
    return None   # route / dst_place: the browser writes them with full country names


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
