"""Intel gathered: the indicators behind each infection / category and each issue, for researchers.

The reports carry more than a name: the C2 domain a device called, the DNS name it looked up, the URL and user agent
it used, the usernames a bot tried, the software and certificate fingerprints of a service. This module collects those
indicators from the days in memory, per name and per report, and looks for the same indicator in more than one place:

* the same value under two names (one family under two names, or shared infrastructure), with a hint when one of the
  names has no definition yet and the other has;
* a C2 / looked-up domain of an infection that is also the certificate name of a publicly accessible service;
* the same value in two reports for one name (a DNS lookup and an HTTP connection to the same C2).

Those become "leads": Looking Glass asks the researcher to look into them.

Researchers do not see the hosts: no source address, host name or constituent address is collected. Values from free
text (URLs, banners, user agents) have any IP address inside them masked; C2 hosts (the destination side) are kept as
they are, since they are the threat's infrastructure, not the constituency's.

API (researchers and admins, the Definitions permission): GET /api/intel?section=infections|issues&name=…,
GET /api/intel/leads. Installed from app.py: intel.install(app, ctx).
"""
import collections
import hashlib
import re
import threading
import time

from flask import jsonify, request

from privacy import partial_mask_text
import hostmask

# Researchers never see what identifies a constituent host (a host name, address, e-mail, date or ID). What the services
# reports say about a constituent's own hosts is masked (hostmask.py) before it is counted, and a value is shown only
# when at least MIN_HOSTS hosts share it. Only the match index behind the leads keeps a certificate name as it is, and a
# lead shows it only when it is also a C2 domain from the communications reports (threat-side, not constituent data).
MIN_HOSTS = 5

# (what it is, where it is: a record field, or x:<name> for the report's extra fields)
COMMS_FIELDS = [
    ("C2 domain", "http_host"), ("C2 domain", "dst_hostname"), ("TLS server name (SNI)", "ssl_servername"),
    ("DNS lookup", "x:query"), ("URL", "http_url"), ("User agent", "http_agent"), ("Request pattern", "x:pattern"),
    ("Brute-force username", "x:username"), ("Brute-force password", "x:password"), ("SSH client", "x:client_version"),
    ("Family named by the report", "family"), ("Application", "application"),
]
SVC_FIELDS = [
    ("Server software", "x:server"), ("SSH software", "x:serverid_software"), ("SSH fingerprint (HASSH)", "x:hassh"),
    ("TLS fingerprint (JARM)", "x:jarm"), ("Certificate SHA-256", "x:sha256_fingerprint"),
    ("Certificate name", "x:subject_common_name"), ("Certificate issuer", "x:issuer_common_name"),
    ("Web page hash", "x:page_sha256fp"), ("Product", "vp"),
    ("Other CVEs on the same hosts", "tags:cve"), ("Associated tags", "tags:other"),
]
CVE_RX = re.compile(r"^cve-\d{4}-\d{4,7}$", re.I)
# kinds whose values are counted together per record: which exact sets occur ("iot + mikrotik + winbox: 872")
COMBO_KINDS = {"Associated tags", "Other CVEs on the same hosts"}
# on the communications side a combination is also what a host keeps doing: the C2 it calls (or looks up in DNS, or
# names in TLS) and the client it uses (URLs change with every request, so they stay out). Without the DNS lookup a
# Sinkhole DNS record would look like "the name only" although it carries the domain looked up.
COMMS_COMBO_KINDS = COMBO_KINDS | {"C2 domain", "User agent", "DNS lookup", "TLS server name (SNI)"}
COMMS_FIELDS.append(("Associated tags", "tag"))


def _norm(s):
    """'Exposed admin panel', 'exposed-admin-panel' and 'exposed_admin_panel' are the same name."""
    return re.sub(r"[\s_.-]+", "-", (s or "").strip().lower())
DOMAIN_KINDS = {"C2 domain", "TLS server name (SNI)", "DNS lookup", "Certificate name"}     # compared as one kind
EXACT_KINDS = {"SSH fingerprint (HASSH)", "TLS fingerprint (JARM)", "Certificate SHA-256", "Web page hash"}
KEEP_AS_IS = {"C2 domain"}                    # the threat's side: an IP literal here is a C2 server, kept
# kinds whose values are shared by nature (common usernames, stock patterns, labels): shown, never a lead
NO_LEADS = {"Family named by the report", "Application", "Product", "Associated tags", "Other CVEs on the same hosts",
            "Brute-force password", "Brute-force username", "Request pattern"}
# stock browser user agents: bots copy them, so two names sharing one says nothing
BROWSER_UA = re.compile(r"^Mozilla/5\.0 \((Windows NT|Macintosh|X11|iPhone|iPad|Linux; Android \d+; K\))", re.I)
TOO_COMMON = 12                               # a value shared by more names than this is noise, not a lead
TOP = 15                                      # values shown per kind and report
DOMAIN_RX = re.compile(r"^(?=.{4,253}$)[a-z0-9_-]+(\.[a-z0-9_-]+)+$")
# user agents of common HTTP libraries: shared by countless programs, so a match on them is not a lead
GENERIC_UA = re.compile(r"^(okhttp|dalvik|python-requests|python-urllib|curl|wget|go-http-client|java|apache-httpclient|"
                        r"mozilla/5\.0$|mozilla/4\.0$)(/|$)", re.I)


def _get(e, key):
    if key.startswith("tags:"):                   # a services record's tags: the CVEs, and the rest
        tags = e.get("tags") or []
        return [t.upper() for t in tags if CVE_RX.match(t)] if key == "tags:cve" else [t for t in tags if not CVE_RX.match(t)]
    if key == "vp":
        return " ".join(x for x in (e.get("vendor"), e.get("product")) if x)
    if key.startswith("x:"):
        return (e.get("extras") or {}).get(key[2:])
    return e.get(key)


def _values(e, key, kind, svc=False, raw=False):
    """The values of one indicator in one record. svc: the record is a services record (it describes a constituent's own
    host), so everything but fingerprints is masked (hostmask.py) unless raw (only for the leads' match index)."""
    v = _get(e, key)
    vals = v if isinstance(v, (list, tuple, set)) else [v]
    for x in vals:
        if x in (None, "", "-") or isinstance(x, (dict,)):
            continue
        s = str(x).strip()
        if kind in EXACT_KINDS and not s.strip("0:"):
            continue                              # an all-zero fingerprint means "none", not a shared value
        if kind in DOMAIN_KINDS:
            s = s.lower().rstrip(".").split(":")[0] if not s.startswith("[") else s.lower()
            if kind != "C2 domain" and not DOMAIN_RX.match(s) and not (svc and not raw):
                continue
        if svc and not raw and kind not in EXACT_KINDS:
            s = hostmask.mask(s)
            if not s or hostmask.looks_like_host(s):
                continue                          # nothing left but "<host>": it named a host and nothing else
        elif kind not in KEEP_AS_IS and kind not in EXACT_KINDS:
            s = partial_mask_text(s)       # attacker infrastructure, never a stable host ID (privacy.py)
        if s:
            yield s[:300]


# the heading of each kind of match: what Looking Glass saw, nothing more (the researcher draws the conclusions)
VERDICT = {
    1: "Seen on both platforms",
    2: "Shared with a name that has no definition",
    3: "Shared by two names",
    4: "Seen in two reports",
}


def hosts(per_host):
    """Counts only: how many hosts carry it, and how many of them repeat it (more than one record)."""
    per_host = per_host or {}
    return {"hosts": len(per_host), "repeat_hosts": sum(1 for c in per_host.values() if c > 1)}


def combo_code(section, name, report, items):
    """The code of one exact combination in one report (LG-C-XXXXXXXX): the same name, report and indicators always give
    the same code, so a researcher's note and an analyst's export talk about exactly the same thing. No address in it."""
    raw = "\x1e".join(["r", section, (name or "").strip().lower(), report or "", "\x1f".join(sorted(items))])
    return "LG-C-" + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


def cross_code(section, name, parts):
    """The code of one cross-report pattern: per report, everything the devices carried there (LG-X-XXXXXXXX)."""
    raw = "\x1e".join(["x", section, (name or "").strip().lower()] +
                      [r + "\x1d" + "\x1f".join(sorted(items)) for r, items in sorted((r, tuple(i)) for r, i in parts)])
    return "LG-X-" + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


def record_items(section, e, me):
    """The combination one record carries, exactly as index() counts it (tests/check_combos.py compares the two)."""
    fields, kinds = (COMMS_FIELDS, COMMS_COMBO_KINDS) if section == "infections" else (SVC_FIELDS, COMBO_KINDS)
    together = [v for kind, f in fields if kind in kinds for v in _values(e, f, kind, svc=section != "infections")]
    return tuple(sorted({v for v in together if _norm(v) != me}))


def _match_key(kind, value):
    return ("domain" if kind in DOMAIN_KINDS else kind, value.lower() if kind in DOMAIN_KINDS else value)


class Intel:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.cache = {"key": None, "at": 0.0, "data": None}

    def _days(self):
        comms = list(self.ctx["store"].days.values())
        svc = list(self.ctx["svc_store"].days.values())
        return comms, svc

    def index(self):
        """{(platform, name): {report: {"records": n, kinds: {kind: Counter}}}}, the match index and the days covered."""
        comms, svc = self._days()
        key = tuple((d.start, len(d.events)) for d in comms) + tuple((d.start, len(d.events)) for d in svc)
        with self.lock:
            if self.cache["key"] == key and time.time() - self.cache["at"] < 300:
                return self.cache["data"]
        labels = self.ctx["labels"]()
        # per value and per combination: records, and records per host (hosts are counted, never kept in an answer)
        by = collections.defaultdict(lambda: collections.defaultdict(lambda: {
            "records": 0, "kinds": collections.defaultdict(collections.Counter), "combos": collections.Counter(),
            "vh": collections.defaultdict(collections.Counter), "ch": collections.defaultdict(collections.Counter)}))

        # across reports: for each name, the reports each device was seen in, and what it carried in each (devices counted,
        # never returned)
        dev_reps = collections.defaultdict(lambda: collections.defaultdict(set))
        dev_items = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(set)))

        def combo(slot, vals, me, host, key=None, rep=None):
            items = tuple(sorted({v for v in vals if _norm(v) != me}))
            slot["combos"][items] += 1
            if host:
                slot["ch"][items][host] += 1
                if key is not None:
                    dev_items[key][host][rep].update(items)
        match = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(int)))
        for d in comms:
            for e in d.events:
                n = (e.get("infection") or "").lower()
                if not n:
                    continue
                rep = labels.get(e.get("source"), e.get("source") or "")
                slot = by[("infections", n)][rep]
                slot["records"] += 1
                together, host = [], e.get("src_ip") or ""
                for kind, f in COMMS_FIELDS:
                    for v in _values(e, f, kind):
                        slot["kinds"][kind][v] += 1
                        if host:
                            slot["vh"][(kind, v)][host] += 1
                        if kind in COMMS_COMBO_KINDS:
                            together.append(v)
                        if kind not in NO_LEADS:
                            match[_match_key(kind, v)][("infections", n)][rep] += 1
                combo(slot, together, _norm(n), host, ("infections", n), rep)
                if host:
                    dev_reps[("infections", n)][host].add(rep)
        for d in svc:
            for e in d.events:
                rep = e.get("report_label") or e.get("report") or ""
                for issue in (e.get("issues") or []):
                    slot = by[("issues", issue)][rep]
                    slot["records"] += 1
                    together, host = [], e.get("ip") or ""
                    for kind, f in SVC_FIELDS:
                        for v in _values(e, f, kind, svc=True):          # masked: what researchers may see
                            slot["kinds"][kind][v] += 1
                            if host:
                                slot["vh"][(kind, v)][host] += 1
                            if kind in COMBO_KINDS:
                                together.append(v)
                        # services take part in leads only with their certificate names (a constituent service carrying
                        # an infection's C2 domain); the name as it is, for matching only: a lead shows it only when the
                        # communications reports carry it too (leads(): services alone are never a lead)
                        if kind in DOMAIN_KINDS:
                            for v in _values(e, f, kind, svc=True, raw=True):
                                match[_match_key(kind, v)][("issues", issue)][rep] += 1
                    combo(slot, together, _norm(issue), host, ("issues", issue), rep)
                    if host:
                        dev_reps[("issues", issue)][host].add(rep)
        days = sorted({d.start.date().isoformat() for d in comms + svc})
        # only the sets are kept: {(section, name): Counter({(report, report): devices})}
        sets = {k: collections.Counter(tuple(sorted(r)) for r in hosts_.values()) for k, hosts_ in dev_reps.items()}
        # the cross-report pattern of each device seen in two or more reports: per report, everything it carried there
        xcombos = {k: collections.Counter(tuple(sorted((rep, tuple(sorted(items))) for rep, items in per.items()))
                                          for per in hosts_.values() if len(per) > 1)
                   for k, hosts_ in dev_items.items()}
        del dev_items
        data = {"by": by, "match": match, "days": days, "sets": sets, "xcombos": xcombos}
        with self.lock:
            self.cache.update(key=key, at=time.time(), data=data)
        return data

    def hosts_of(self, section, name):
        """The hosts behind a name in the days in memory (never returned: for the analysis across every category)."""
        key = (section, name if section == "issues" else (name or "").lower())
        out = set()
        for slot in (self.index()["by"].get(key) or {}).values():
            for per in slot["ch"].values():
                out.update(per)
        out.discard("")
        return out

    def gathered(self, section, name):
        data = self.index()
        key = (section, name if section == "issues" else (name or "").lower())
        reports = []
        me = _norm(name)
        for rep, slot in sorted(data["by"].get(key, {}).items(), key=lambda kv: -kv[1]["records"]):
            total = slot["records"] or 1
            kinds = []
            for k, c in slot["kinds"].items():
                c = collections.Counter({v: n for v, n in c.items() if _norm(v) != me})   # not itself
                hidden = 0
                if section == "issues":            # services: a value is shown only when MIN_HOSTS hosts share it
                    rare = {v for v in c if len(slot["vh"].get((k, v)) or ()) < MIN_HOSTS}
                    hidden = len(rare)
                    c = collections.Counter({v: n for v, n in c.items() if v not in rare})
                if c or hidden:
                    kinds.append({"kind": k, "distinct": len(c), "hidden": hidden,
                                  "values": [{"value": v, "count": n, "share": round(n / total, 4), **hosts(slot["vh"].get((k, v)))}
                                             for v, n in c.most_common(TOP)]})
            kinds.sort(key=lambda k: (k["kind"] in NO_LEADS, -k["distinct"]))
            # which associated tags / CVEs (and, for communications, C2 + client) come together on the same record: why
            # one counts less than another, and how many hosts keep repeating that exact combination
            combos = [{"items": list(items), "count": n, "share": round(n / total, 4), **hosts(slot["ch"].get(items)),
                       "code": combo_code(section, key[1], rep, items)}
                      for items, n in slot["combos"].most_common(12)]
            self._shown(section, key[1], rep, [c["items"] for c in combos])
            single = None
            if len(slot["combos"]) < 2:
                single = combos[0] if combos else None   # one combination only: its code, for the analyst
                combos = []                           # the counts above already say it all
            reports.append({"report": rep, "records": slot["records"], "indicators": kinds, "combinations": combos, "single": single,
                            "combinations_total": len(slot["combos"]),
                            "combo_of": "C2 domain, DNS lookup, TLS name, user agent and tags" if section == "infections" else "associated tags and CVEs"})
        leads = [x for x in self.leads()["leads"] if any(p == section and n == key[1] for p, n in x["names_key"])]
        across = self._across(data, key, me)
        for x in across["cross_combos"]:
            x["code"] = cross_code(section, key[1], [(p["report"], p["items"]) for p in x["parts"]])
        self._shown(section, key[1], None, [[(p["report"], p["items"]) for p in x["parts"]] for x in across["cross_combos"]])
        return {"name": name, "section": section, "days": data["days"], "reports": reports, "leads": leads[:20],
                "across": across}

    def _shown(self, section, name, report, combos):
        """Tell combos.py which codes a researcher was shown, so an analyst can resolve them later (even from history)."""
        hook = getattr(self, "on_codes", None)
        if hook and combos:
            try:
                hook(section, name, report, combos)
            except Exception:             # a failed bookkeeping write must never break the researcher's window
                pass

    @staticmethod
    def _across(data, key, me):
        """Across the reports of one name: which sets of reports the devices were seen in, and which indicators turn up in
        more than one report (a domain looked up in Sinkhole DNS and contacted in Sinkhole HTTP counts as the same)."""
        sets = data["sets"].get(key) or collections.Counter()
        devices = sum(sets.values()) or 1
        report_sets = [{"reports": list(rs), "devices": n, "share": round(n / devices, 4)} for rs, n in sets.most_common(12)]
        seen = collections.defaultdict(lambda: {"kinds": set(), "value": "", "where": collections.Counter()})
        for rep, slot in data["by"].get(key, {}).items():
            for kind, c in slot["kinds"].items():
                if kind == "Family named by the report":
                    continue
                for v, n in c.items():
                    if _norm(v) == me:
                        continue
                    if key[0] == "issues" and len(slot["vh"].get((kind, v)) or ()) < MIN_HOSTS:
                        continue                  # services: only values MIN_HOSTS hosts share
                    s = seen[_match_key(kind, v)]
                    s["kinds"].add(kind); s["value"] = s["value"] or v; s["where"][rep] += n
        shared = [{"value": s["value"], "kinds": sorted(s["kinds"]), "where": dict(s["where"].most_common()), "records": sum(s["where"].values())}
                  for s in seen.values() if len(s["where"]) > 1]
        shared.sort(key=lambda x: (-len(x["where"]), -x["records"]))
        xc = data.get("xcombos", {}).get(key) or collections.Counter()
        multi = sum(xc.values()) or 1
        cross_combos = [{"parts": [{"report": rep, "items": list(items)} for rep, items in pattern], "devices": n, "share": round(n / multi, 4)}
                        for pattern, n in xc.most_common(12)]
        return {"cross_combos": cross_combos, "cross_combos_total": len(xc),
                "devices": sum(sets.values()), "multi_devices": sum(n for rs, n in sets.items() if len(rs) > 1),
                "report_sets": report_sets, "report_sets_total": len(sets), "shared": shared[:40], "shared_total": len(shared)}

    def summary(self):
        """For the Definitions tables: per name, per report, how many kinds of indicator it carries (0 = the name only)."""
        data = self.index()
        out = {"infections": {}, "issues": {}}
        for (section, name), reps in data["by"].items():
            me = _norm(name)
            row = {}
            for rep, slot in reps.items():
                kinds = sum(1 for k, c in slot["kinds"].items() if k != "Family named by the report" and any(_norm(v) != me for v in c))
                row[rep] = {"kinds": kinds, "records": slot["records"]}
            out[section][name if section == "issues" else name.lower()] = row
        # across reports: per name, how many devices / hosts were seen in two or more of its reports (counted only)
        across = {"infections": {}, "issues": {}}
        for (section, name), sets in data["sets"].items():
            n = sum(c for reps, c in sets.items() if len(reps) > 1)
            if n:
                across[section][name if section == "issues" else name.lower()] = {
                    "devices": n, "reports": sorted({r for reps in sets if len(reps) > 1 for r in reps})}
        return {"days": data["days"], **out, "across": across}

    def leads(self):
        data = self.index()
        defined = self.ctx["defined"]()           # {("infections"|"issues", name): title}
        out = []
        for (kind, value), names in data["match"].items():
            if len(names) > TOO_COMMON or (kind == "User agent" and (GENERIC_UA.match(value) or BROWSER_UA.match(value))):
                continue
            if kind == "URL" and len(re.sub(r"^(GET|POST|HEAD|PUT|OPTIONS)\s+|\s+HTTP/[\d.]+$", "", value).strip("/ ")) < 4:
                continue                              # "/" and other bare paths: every scanner asks for them
            reps = {r for rs in names.values() for r in rs}
            plats = {p for p, _ in names}
            if plats == {"issues"}:
                continue                              # services alone: one host's several issues, not a lead
            total = sum(n for rs in names.values() for n in rs.values())
            label = "domain" if kind == "domain" else kind
            nk = sorted(names)
            pretty = lambda pn: pn[1]
            if len(plats) > 1:
                inf = [n for p, n in nk if p == "infections"]; iss = [n for p, n in nk if p == "issues"]
                out.append({"priority": 1, "kind": label, "value": value, "names_key": nk, "reports": sorted(reps), "count": total,
                            "text": f"Looking Glass saw the {label} {value} for {', '.join(inf)} (network communications) and as the "
                                    f"certificate name of a publicly accessible service with {', '.join(iss)}."})
            elif len(names) > 1:
                low = lambda x: (x[0], x[1].lower())
                undefined = [pretty(x) for x in nk if low(x) not in defined]
                known = [(pretty(x), defined[low(x)]) for x in nk if low(x) in defined]
                hint = ""
                if undefined and known:
                    hint = (f" {', '.join(undefined)} {'has' if len(undefined) == 1 else 'have'} no definition yet; "
                            f"{known[0][0]} is defined as \"{known[0][1]}\".")
                out.append({"priority": 2 if hint else 3, "kind": label, "value": value, "names_key": nk, "reports": sorted(reps),
                            "count": total,
                            "text": f"Looking Glass saw the same {label} {value} for {' and '.join(pretty(x) for x in nk)} "
                                    f"(in {', '.join(sorted(reps))}): possibly one family under two names, or shared infrastructure.{hint}"})
            elif len(reps) > 1:
                out.append({"priority": 4, "kind": label, "value": value, "names_key": nk, "reports": sorted(reps), "count": total,
                            "text": f"Looking Glass saw the {label} {value} for {nk[0][1]} in {' and '.join(sorted(reps))}: "
                                    f"a probable indicator of {nk[0][1]}, worth putting in its notes."})
            if out and out[-1]["value"] == value and "_seen" not in out[-1]:
                out[-1]["_seen"] = names          # where it was seen: name -> {report: records}, for the analysis box
        out.sort(key=lambda x: (x["priority"], -x["count"]))
        # one-report confirmations are many: keep the strongest few per name
        per, kept = collections.Counter(), []
        for x in out:
            if x["priority"] == 4:
                per[tuple(x["names_key"])] += 1
                if per[tuple(x["names_key"])] > 3:
                    continue
            kept.append(x)
        for x in kept:
            low = lambda pn: (pn[0], pn[1].lower())
            x["names"] = [{"section": p, "name": n, "defined": defined.get(low((p, n)), "")} for p, n in x["names_key"]]
            # the evidence: every name and report where Looking Glass saw the indicator, with its records
            x["where"] = sorted(({"section": p, "name": n, "report": r, "records": c, "defined": bool(defined.get(low((p, n))))}
                                 for (p, n), reps in (x.get("_seen") or {}).items() for r, c in reps.items()), key=lambda w: -w["records"])
            x["verdict"] = VERDICT[x["priority"]]
        return {"days": data["days"], "leads": kept[:60]}


def install(app, ctx):
    """ctx: store, svc_store, labels() -> {collection: report name}, defined() -> {(section, name): title},
    allowed() -> may this request see the researchers' work."""
    intel = Intel(ctx)

    @app.route("/api/intel")
    def api_intel():
        if not ctx["allowed"]():
            return jsonify(error="Intel gathered is for researchers and admins."), 403
        name = (request.args.get("name") or "").strip()[:120]
        if not name:
            return jsonify(error="name= is needed"), 400
        if request.args.get("section") == "services":     # a services report: services_intel.py, in the same shape
            v = ctx["services_view"](name) if ctx.get("services_view") else None
            return jsonify(v) if v else (jsonify(error="No such services report."), 404)
        section = "issues" if request.args.get("section") == "issues" else "infections"
        g = intel.gathered(section, name)
        g["leads"] = [{k: v for k, v in x.items() if k not in ("names_key", "_seen")} for x in g["leads"]]
        # the same hosts in every other category: services reports (pattern codes), CVEs and issues, infections
        if ctx.get("cross"):
            try:
                hs = intel.hosts_of(section, name)
                g["cross"] = ctx["cross"](hs) if hs else None
            except Exception:                              # noqa: BLE001  (the window still shows the name itself)
                g["cross"] = None
        return jsonify(g)

    @app.route("/api/intel/summary")
    def api_intel_summary():
        if not ctx["allowed"]():
            return jsonify(error="Intel gathered is for researchers and admins."), 403
        return jsonify(intel.summary())

    @app.route("/api/intel/leads")
    def api_intel_leads():
        if not ctx["allowed"]():
            return jsonify(error="Intel gathered is for researchers and admins."), 403
        d = intel.leads()
        return jsonify(days=d["days"], leads=[{k: v for k, v in x.items() if k not in ("names_key", "_seen")} for x in d["leads"]])

    return intel
