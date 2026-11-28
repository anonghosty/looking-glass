# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Intel gathered: the indicators behind each infection / category and each issue, for researchers.

The reports carry more than a name: the C2 domain a device called, the DNS name it looked up, the URL and user agent
it used, the usernames a bot tried, the software and certificate fingerprints of a service. This module collects those
indicators from the report day (report_day.py: the day the Executive portal shows; the user, 2026-11-17), per name and
per report, and looks for the same indicator in more than one place:

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
import beacon_decode
import index_refresh
import report_day
import hostmask
import small_codes

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
# a beacon decoded from the request (beacon_decode.py): only its threat-side parts, each shown to a viewer who does not
# see hosts only when MIN_HOSTS devices carry the value (held()); the device's own details never come here
COMMS_FIELDS.extend((k, "beacon:" + beacon_decode.FIELD_OF_KIND[k]) for k in beacon_decode.KINDS)
BEACON_KINDS = set(beacon_decode.KINDS)
BEACON_NO_MATCH = {"Beacon format", "Beacon OS"}      # shared by every beacon of a format: never a match between names
# Inbound reports (sources.py layout "inbound": Shadowserver's Spam URL report). The constituent is the sender: src_ip is
# the spam relay that delivered the message (last hop). ip / hostname (dst_* here) and url are where a link found in
# the spam points: often a spammer's site, sometimes a legitimate one hidden among them, and never a C2. So those hosts
# are a "Spam link host", not a "C2 domain"; and when the link points into the constituency (dst_geo is the platform's
# country) it is a constituent's own host, masked like the services reports' constituent data (review 2026-11-13,
# checked against Shadowserver's Spam URL report page). Both filled from the registry and settings.
INBOUND = set()
COUNTRY = {"code": ""}
SPAM_HOST = "Spam link host"
COMMS_INBOUND = [(SPAM_HOST if k == "C2 domain" else k, f) for k, f in COMMS_FIELDS]


def _comms(e):
    """(fields, masked) for a communications record: an inbound record names spam link hosts, masked when they are in
    the constituency."""
    if e.get("source") not in INBOUND:
        return COMMS_FIELDS, False
    here = bool(COUNTRY["code"]) and (e.get("dst_geo") or "").upper() == COUNTRY["code"]
    return COMMS_INBOUND, here


def _norm(s):
    """'Exposed admin panel', 'exposed-admin-panel' and 'exposed_admin_panel' are the same name."""
    return re.sub(r"[\s_.-]+", "-", (s or "").strip().lower())
DOMAIN_KINDS = {"C2 domain", "TLS server name (SNI)", "DNS lookup", "Certificate name", "Spam link host"}  # compared as one kind
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
    if key.startswith("beacon:"):
        return beacon_decode.field(e, key[7:])
    return e.get(key)


def held(section, kind, c, slot, full):
    """The values to hold back: services values and, for a viewer who does not see hosts, decoded beacon values that
    fewer than MIN_HOSTS devices carry (counted, never shown)."""
    if section == "issues" or (kind in BEACON_KINDS and not full):
        return {v for v in c if len(slot["vh"].get((kind, v)) or ()) < MIN_HOSTS}
    return set()


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
            if kind == "URL":
                s = beacon_decode.mask_url(s)     # a beacon blob decodes to the device's MAC, UUID...: never shown
            # IP addresses inside threat data are partly masked; the C2 host itself is kept as it is, an IP literal
            # too: researchers need the C2 servers for their analysis (the user's decision, 2026-11-12, after the
            # external review raised it; written in SECURITY.md). A C2 server is the threat's side, not a constituent.
            s = partial_mask_text(s)
        if s:
            yield s[:300]


# the heading of each kind of match: what Looking Glass saw, nothing more (the researcher draws the conclusions)
VERDICT = {
    1: "Seen on both platforms",
    2: "Shared with a name that has no definition",
    3: "Shared by two names",
    4: "Seen in two reports",
    5: "Decoded beacon contradicts its name",
}


def hosts(per_host):
    """Counts only: how many hosts carry it, and how many of them repeat it (more than one record)."""
    per_host = per_host or {}
    return {"hosts": len(per_host), "repeat_hosts": sum(1 for c in per_host.values() if c > 1)}


# The code book (combos.CodeBook) that hands out codes: set by combos.install. Codes keep 8 hex characters (people type
# and quote them), so two different combinations can share one (about 4.5% at 20,000 codes); the book checks what a code
# already stands for and gives the second one a code of its own (external review, 2026-11-14).
CODE_BOOK = {"book": None}


def combo_key(section, name, report, items):
    """What one exact combination is: the text its code is made from."""
    return "\x1e".join(["r", section, (name or "").strip().lower(), report or "", "\x1f".join(sorted(items))])


def cross_key(section, name, parts):
    """What one cross-report pattern is: the text its code is made from."""
    return "\x1e".join(["x", section, (name or "").strip().lower()] +
                       [r + "\x1d" + "\x1f".join(sorted(items)) for r, items in sorted((r, tuple(i)) for r, i in parts)])


def code_from(prefix, key, n=1):
    """The n-th candidate code for a key: the first is the plain hash (every code made so far), later ones add n."""
    raw = key if n == 1 else f"{key}\x1e{n}"
    return prefix + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


def _assign(prefix, key):
    book = CODE_BOOK["book"]
    return book.assign(prefix, key) if book is not None else code_from(prefix, key)


def combo_code(section, name, report, items):
    """The code of one exact combination in one report (LG-C-XXXXXXXX): the same name, report and indicators always give
    the same code, so a researcher's note and an analyst's export talk about exactly the same thing. No address in it.
    A different combination never gets the same code (CodeBook.assign)."""
    return _assign("LG-C-", combo_key(section, name, report, items))


def cross_code(section, name, parts):
    """The code of one cross-report pattern: per report, everything the devices carried there (LG-X-XXXXXXXX)."""
    return _assign("LG-X-", cross_key(section, name, parts))


def record_items(section, e, me):
    """The combination one record carries, exactly as index() counts it (tests/check_combos.py compares the two)."""
    if section == "infections":
        (fields, masked), kinds = _comms(e), COMMS_COMBO_KINDS
    else:
        fields, masked, kinds = SVC_FIELDS, True, COMBO_KINDS
    together = [v for kind, f in fields if kind in kinds for v in _values(e, f, kind, svc=masked)]
    return tuple(sorted({v for v in together if _norm(v) != me}))


def _match_key(kind, value):
    return ("domain" if kind in DOMAIN_KINDS else kind, value.lower() if kind in DOMAIN_KINDS else value)


class Intel:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.cache = {"key": None, "at": 0.0, "data": None}       # the report day's (what is shown)
        self.others = {}                                           # the other scopes' (report_day.py)
        self.gate = index_refresh.Gate("intel")                    # counted again behind the page (index_refresh.py)

    def _days(self, scope=None):
        """The day copies counted (report_day.py): the report day by default, as the Executive portal counts it (the
        user, 2026-11-17); "memory" (every day in memory) for the analysts' combination search and code look-ups."""
        rn = self.ctx.get("replay_now")
        comms = report_day.select(list(self.ctx["store"].days.values()), scope, rn)
        svc = report_day.select(list(self.ctx["svc_store"].days.values()), scope, rn)
        return comms, svc

    def _slot(self, scope):
        """(days, key, scope key, cache slot): a named day that IS the report day shares the report day's counts (the
        Executive portal's code filter asked for its own copy of the same 22 s count, 2026-11-17)."""
        comms, svc = self._days(scope)
        # kept while the same copies of the days are in memory (speed review, 2026-11-15: worked out again every 5
        # minutes, 14 s on the first visit); an hour at most. One cache per scope
        key = (tuple((d.start, getattr(d, "serial", 0), len(d.events)) for d in comms)
               + tuple((d.start, getattr(d, "serial", 0), len(d.events)) for d in svc))
        sk = report_day.scope_key(scope)
        if sk not in ("report", "memory"):
            rc, rs = self._days(None)
            if [d.start for d in comms] == [d.start for d in rc] and [d.start for d in svc] == [d.start for d in rs]:
                sk = "report"
        with self.lock:
            if sk != "report" and sk not in self.others and len(self.others) >= 6:
                self.others.pop(next(iter(self.others)))   # days that left memory: their counts are not kept forever
            # its own name: "slot" below is a report's counts (2026-11-17: sharing the name, the cache was never kept and
            # every answer counted the days again, about 3 s each)
            cache = self.cache if sk == "report" else self.others.setdefault(sk, {"key": None, "at": 0.0, "data": None})
        return comms, svc, key, sk, cache

    def index(self, scope=None):
        """{(platform, name): {report: {"records": n, kinds: {kind: Counter}}}}, the match index and the days covered.
        Out of date while the service runs: the earlier counts at once, counted again behind the page (index_refresh)."""
        _c, _s, key, sk, cache = self._slot(scope)
        with self.lock:
            fresh = cache["data"] if cache["key"] == key and time.time() - cache["at"] < 3600 else None
            stale = cache["data"]
        return self.gate.serve(sk, fresh, stale, lambda cached_only=False: self._build(scope, cached_only))

    def _build(self, scope=None, cached_only=False):
        comms, svc, key, sk, cache = self._slot(scope)
        with self.lock:
            if cache["key"] == key and time.time() - cache["at"] < 3600:
                return cache["data"]
        if cached_only:
            return None
        labels = self.ctx["labels"]()
        _refresh_inbound(self.ctx)                 # a report found since start-up
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
                fields, masked = _comms(e)
                for kind, f in fields:
                    for v in _values(e, f, kind, svc=masked):
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
        # and, for the 12 patterns shown, which devices carry each: they never leave the server; the window gets what they
        # carry in the services reports (CVEs, issues, infections) as names and counts (ctx "carried", the user 2026-11-19)
        xcombos, xhosts = {}, {}
        for k, hosts_ in dev_items.items():
            pat_h = collections.defaultdict(list)
            for h, per in hosts_.items():
                if len(per) > 1:
                    pat_h[tuple(sorted((rep, tuple(sorted(items))) for rep, items in per.items()))].append(h)
            c = collections.Counter({p: len(hs) for p, hs in pat_h.items()})
            xcombos[k] = c
            xhosts[k] = {p: frozenset(pat_h[p]) for p, _n in c.most_common(12)}
        dev_items.clear()            # freed now (the device sets are large); the name stays for combo() above
        data = {"by": by, "match": match, "days": days, "sets": sets, "xcombos": xcombos, "xhosts": xhosts}
        with self.lock:
            cache.update(key=key, at=time.time(), data=data)
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
        full = small_codes.viewer_sees_hosts()
        key = (section, name if section == "issues" else (name or "").lower())
        reports = []
        me = _norm(name)
        for rep, slot in sorted(data["by"].get(key, {}).items(), key=lambda kv: -kv[1]["records"]):
            total = slot["records"] or 1
            kinds = []
            for k, c in slot["kinds"].items():
                c = collections.Counter({v: n for v, n in c.items() if _norm(v) != me})   # not itself
                # services, and decoded beacons for viewers who do not see hosts: shown when MIN_HOSTS hosts share it
                rare = held(section, k, c, slot, full)
                hidden = len(rare)
                if rare:
                    c = collections.Counter({v: n for v, n in c.items() if v not in rare})
                if c or hidden:
                    kinds.append({"kind": k, "distinct": len(c), "hidden": hidden,
                                  "values": [{"value": v, "count": n, "share": round(n / total, 4), **hosts(slot["vh"].get((k, v)))}
                                             for v, n in c.most_common(TOP)]})
            kinds.sort(key=lambda k: (k["kind"] in NO_LEADS, -k["distinct"]))
            # which associated tags / CVEs (and, for communications, C2 + client) come together on the same record: why
            # one counts less than another, and how many hosts keep repeating that exact combination
            # a lasting code only for a pattern MIN_HOSTS or more hosts share, unless the viewer sees the hosts
            # (small_codes.py; external review, 2026-11-12: these codes bypassed it)
            combos = [{"items": list(items), "count": n, "share": round(n / total, 4), **hosts(slot["ch"].get(items)),
                       "code": small_codes.code_for(combo_code(section, key[1], rep, items), len(slot["ch"].get(items) or ()), full)}
                      for items, n in slot["combos"].most_common(12)]
            self._shown(section, key[1], rep, [c["items"] for c in combos])
            single = None
            if len(slot["combos"]) < 2:
                single = combos[0] if combos else None   # one combination only: its code, for the analyst
                combos = []                           # the counts above already say it all
            reports.append({"report": rep, "records": slot["records"], "indicators": kinds, "combinations": combos, "single": single,
                            "combinations_total": len(slot["combos"]), "totals": {"combinations": len(slot["combos"])},
                            "combo_of": "C2 domain, DNS lookup, TLS name, user agent and tags" if section == "infections" else "associated tags and CVEs"})
        # the name's leads out of every lead (not only the first 60 the Leads card lists)
        d_ = self.leads_all()
        leads = [x for x in d_["all_leads"] if any(p == section and n == key[1] for p, n in x["names_key"])]
        across = self._across(data, key, me)
        carried = self.ctx.get("carried")
        for x in across["cross_combos"]:
            x["code"] = small_codes.code_for(cross_code(section, key[1], [(p["report"], p["items"]) for p in x["parts"]]),
                                             x["devices"], full)
            hs = x.pop("_hosts", None)                   # the device set never leaves: only what it carries, counted
            if carried and hs:
                try:
                    x["carries"] = carried(hs)
                except Exception:                        # noqa: BLE001  (the card shows without its summary line)
                    pass
        self._shown(section, key[1], None, [[(p["report"], p["items"]) for p in x["parts"]] for x in across["cross_combos"]])
        # the top 20 leads of the name, with how many there are ("20 of N" on the page)
        return {"name": name, "section": section, "days": data["days"], "reports": reports, "leads": leads[:20],
                "leads_total": len(leads), "totals": {"leads": len(leads)}, "across": across}

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
        full = small_codes.viewer_sees_hosts()
        for rep, slot in data["by"].get(key, {}).items():
            for kind, c in slot["kinds"].items():
                if kind == "Family named by the report":
                    continue
                rare = held(key[0], kind, c, slot, full)
                for v, n in c.items():
                    if _norm(v) == me:
                        continue
                    if v in rare:
                        continue                  # services, and beacons for researchers: only values MIN_HOSTS hosts share
                    s = seen[_match_key(kind, v)]
                    s["kinds"].add(kind); s["value"] = s["value"] or v; s["where"][rep] += n
        shared = [{"value": s["value"], "kinds": sorted(s["kinds"]), "where": dict(s["where"].most_common()), "records": sum(s["where"].values())}
                  for s in seen.values() if len(s["where"]) > 1]
        shared.sort(key=lambda x: (-len(x["where"]), -x["records"]))
        xc = data.get("xcombos", {}).get(key) or collections.Counter()
        multi = sum(xc.values()) or 1
        xh = data.get("xhosts", {}).get(key) or {}
        cross_combos = [{"parts": [{"report": rep, "items": list(items)} for rep, items in pattern], "devices": n, "share": round(n / multi, 4),
                         "_hosts": xh.get(pattern)}          # taken out before the answer leaves (view)
                        for pattern, n in xc.most_common(12)]
        return {"cross_combos": cross_combos, "cross_combos_total": len(xc),
                "devices": sum(sets.values()), "multi_devices": sum(n for rs, n in sets.items() if len(rs) > 1),
                "report_sets": report_sets, "report_sets_total": len(sets), "shared": shared[:40], "shared_total": len(shared),
                # each top list's full count beside it, in one place ("12 of N" on the page)
                "totals": {"cross_combos": len(xc), "report_sets": len(sets), "shared": len(shared)}}

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
        """The leads as the Leads card gets them (the first 60, with the totals)."""
        d = self.leads_all()
        d.pop("all_leads", None)
        return d

    def leads_all(self):
        """leads() and "all_leads": every lead of THIS viewer (for gathered() and the match view; never sent)."""
        data = self.index()
        defined = self.ctx["defined"]()           # {("infections"|"issues", name): title}
        full = small_codes.viewer_sees_hosts()
        out = []
        for (kind, value), names in data["match"].items():
            if len(names) > TOO_COMMON or (kind == "User agent" and (GENERIC_UA.match(value) or BROWSER_UA.match(value))):
                continue
            if kind in BEACON_NO_MATCH:
                continue
            if kind in BEACON_KINDS and not full and len(set().union(*(
                    slot["vh"].get((kind, value)) or () for nm in names for slot in data["by"].get(nm, {}).values()))) < MIN_HOSTS:
                continue                              # a decoded beacon value fewer than MIN_HOSTS devices carry
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
        for x in kept:                            # each kept one-report lead says how many its name has ("3 of 11")
            if x["priority"] == 4:
                x["same_name_total"] = per[tuple(x["names_key"])]
        one_report_held = sum(max(0, n - 3) for n in per.values())
        one_report_total = sum(per.values())
        # a decoded beacon whose contents contradict the name it is filed under (beacon_decode.py), first in the list
        kept = beacon_decode.contradiction_leads(data["by"], full, MIN_HOSTS) + kept
        for x in kept:
            low = lambda pn: (pn[0], pn[1].lower())
            x["names"] = [{"section": p, "name": n, "defined": defined.get(low((p, n)), "")} for p, n in x["names_key"]]
            # the evidence: every name and report where Looking Glass saw the indicator, with its records
            x["where"] = sorted(({"section": p, "name": n, "report": r, "records": c, "defined": bool(defined.get(low((p, n))))}
                                 for (p, n), reps in (x.get("_seen") or {}).items() for r, c in reps.items()), key=lambda w: -w["records"])
            x["verdict"] = VERDICT[x["priority"]]
        # how much was compared, day by day: "nothing to ask" must never read as "nothing there" when a day holds only
        # its first reports (2026-11-15: after a restart the card compared one day's first five reports)
        comms, svc = self._days()
        per = collections.defaultdict(lambda: {"events": 0, "records": 0})
        for d in comms:
            per[d.start.date().isoformat()]["events"] += len(d.events)
        for d in svc:
            per[d.start.date().isoformat()]["records"] += len(d.events)
        compared = [{"day": k, **v} for k, v in sorted(per.items())]
        # the first 60 leads, with how many there are, and how many one-report leads were held back (3 kept per name);
        # "all_leads": every lead of THIS viewer (gathered() and the match view read it from the answer); never sent.
        # Never kept on self: a shared attribute let one viewer read another's list (audit 2026-11-27, 5-3)
        return {"days": data["days"], "leads": kept[:60], "all_leads": kept, "compared": compared,
                "leads_total": len(kept), "one_report_held": one_report_held,
                "totals": {"leads": len(kept), "one_report_leads": one_report_total}}


def _refresh_inbound(ctx):
    try:
        names = set(ctx.get("inbound", lambda: ())())
        COUNTRY["code"] = str(ctx.get("country", lambda: "")() or "").upper()
    except Exception:                                      # noqa: BLE001  (the registry not ready: keep what is known)
        return
    INBOUND.clear()
    INBOUND.update(names)


def install(app, ctx):
    """ctx: store, svc_store, labels() -> {collection: report name}, defined() -> {(section, name): title},
    allowed() -> may this request see the researchers' work; inbound() -> the names of the inbound reports."""
    intel = Intel(ctx)
    _refresh_inbound(ctx)

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
        return jsonify(days=d["days"], compared=d.get("compared", []),
                       leads=[{k: v for k, v in x.items() if k not in ("names_key", "_seen")} for x in d["leads"]],
                       # the first 60, with how many there are ("60 of N leads") and the one-report leads held back
                       leads_total=d.get("leads_total", len(d["leads"])), one_report_held=d.get("one_report_held", 0),
                       totals=d.get("totals") or {"leads": len(d["leads"])})

    return intel
