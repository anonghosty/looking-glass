"""Intel gathered for a publicly accessible / vulnerable services report (the researchers' Services section): what its
pattern fields (svc_patterns.py) show across the hosts of the days in memory, and what else those hosts do.

For one report (its IPv6 twin included):
* patterns: per pattern field, the values shared by at least MIN_HOSTS hosts (masked: never a host), and how many
  values fewer hosts share (counted, not shown);
* exact combinations: the full set of pattern items one record carries, the hosts carrying each set and how many of
  them repeat it, with its combination code (LG-C-...), shared by at least MIN_HOSTS hosts;
* across reports: the other services reports the same hosts appear in (the sets of reports, counted), and the exact
  cross-report patterns (per report, the items the host carried there) with their codes (LG-X-...);
* sinkholes: how many of these hosts also appear in the network communications reports (an exposed service on a
  device that is already infected), the infection names there (the threat's names, not constituent data), each with
  a code (LG-X-..., a part on SINK) an analyst resolves to exactly those hosts.

intel_view() gives the same answer in the shape of /api/intel (intel.py), so the researchers' Intel gathered window and
the Notes window (codes to attach) work for Services as they do for infections and issues.
Matcher: the analysts' combination search (combos.py) for a services code, with the same rule as the counts here.

The host sets never leave this module: answers hold counts, codes, and values shared by at least MIN_HOSTS hosts.
ServicesIntel(ctx): ctx svc_store, comms_store, patterns (svc_patterns.Patterns), load_day(), on_codes(section, name,
report, combos) (combos.py records the codes a researcher was shown).
"""
import collections
import threading
import time

import small_codes
from intel import combo_code, cross_code
from report_map import sibling
from svc_patterns import MIN_HOSTS

SECTION = "services"
SINK = "Botnet sinkholes"     # the part of a sinkhole code: the host also calls a sinkhole as this infection
TOP = 15
MIN_NETWORKS = 2      # free text (templates) must also be seen in two networks: one organisation's own wording is not shown


def _label(item):
    return f"{item[0]}: {item[1]}"


def _repeat(per_host):
    return sum(1 for c in per_host.values() if c > 1)


KIND_ORDER = ["Sinkhole reports", "Vulnerability reports", "Services reports"]


def grouped(counts, title_of, kind_of, sinks=None):
    """Reports with their hosts, grouped by kind for people: [{kind, reports: [{title, hosts}]}], the sinkhole reports
    first, then vulnerability, services, and the other categories. counts: services report -> hosts; sinks: sinkhole
    report -> hosts."""
    by = collections.defaultdict(list)
    for r, n in sorted((sinks or {}).items(), key=lambda kv: -kv[1]):
        by["Sinkhole reports"].append({"title": r, "hosts": n})
    for r, n in sorted(counts.items(), key=lambda kv: -kv[1]):
        by[kind_of(r)].append({"title": title_of(r), "hosts": n})
    out = [{"kind": k, "reports": by[k]} for k in KIND_ORDER if by.get(k)]
    return out + [{"kind": k, "reports": v} for k, v in sorted(by.items()) if k not in KIND_ORDER]


def host_pattern(data, h):
    """A host's exact cross-report pattern: per services report, the pattern items that may be shown; per sinkhole
    report it calls, the infections ("Infection: name")."""
    per = data["host_items"].get(h) or {}
    parts = [(r, tuple(sorted(_label(i) for i in per.get(r, ()) if i in data["showable"].get(r, ())))) for r in data["host_reports"].get(h, ())]
    parts += [(r, tuple(sorted(f"Infection: {n}" for n in names))) for r, names in (data["sink_rep"].get(h) or {}).items()]
    return tuple(sorted(parts))


class ServicesIntel:
    def __init__(self, ctx):
        self.ctx = ctx
        self.title_of = lambda n: n                       # services_kb.py sets the readable titles and kinds of reports
        self.kind_of = lambda n: "Services reports"
        self.lock = threading.Lock()
        self.cache = {"key": None, "at": 0.0, "data": None}

    def index(self):
        try:
            self.ctx.get("load_day") and self.ctx["load_day"]()
        except Exception:                                  # noqa: BLE001  (the days already in memory still count)
            pass
        svc = list(self.ctx["svc_store"].days.values())
        comms = list(self.ctx["comms_store"].days.values())
        key = tuple((d.start, len(d.events)) for d in svc) + tuple((d.start, len(d.events)) for d in comms)
        with self.lock:
            if self.cache["key"] == key and time.time() - self.cache["at"] < 300:
                return self.cache["data"]
        pat = self.ctx["patterns"]
        fields = {}
        vals = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))   # base -> item -> host -> records
        nets = collections.defaultdict(lambda: collections.defaultdict(set))       # base -> (label, value) -> networks
        combos = collections.defaultdict(collections.Counter)                     # base -> items -> records
        combo_hosts = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
        hosts = collections.defaultdict(set)
        host_reports = collections.defaultdict(set)                               # host -> bases
        host_items = collections.defaultdict(lambda: collections.defaultdict(set))  # host -> base -> items
        records = collections.Counter()
        for d in svc:
            for e in d.events:
                rep = e.get("report") or ""
                base = sibling(rep)
                if base not in fields:
                    fields[base] = pat.fields_for(base)
                ip = e.get("ip")
                items = tuple(sorted(set(pat.items(base, e, fields[base]))))
                records[base] += 1
                hosts[base].add(ip)
                host_reports[ip].add(base)
                for it in items:
                    vals[base][it][ip] += 1
                    nets[base][it].add(e.get("asn") or "")
                    host_items[ip][base].add(it)
                combos[base][items] += 1
                combo_hosts[base][items][ip] += 1
        infected = collections.defaultdict(set)                                   # host -> infection names
        sink_rep = collections.defaultdict(lambda: collections.defaultdict(set))  # host -> sinkhole report -> names
        labels = self.ctx["labels"]() if self.ctx.get("labels") else {}
        for d in comms:
            for e in d.events:
                if e.get("src_ip") and e.get("infection"):
                    infected[e["src_ip"]].add(e["infection"])
                    sink_rep[e["src_ip"]][labels.get(e.get("source"), e.get("source") or "Sinkhole")].add(e["infection"])
        # an item may be shown when MIN_HOSTS hosts share it, and (free text) when they sit in MIN_NETWORKS networks
        template_labels = {b: {f["label"] for f in fs if f["kind"] == "template"} for b, fs in fields.items()}
        showable = {b: {it for it, h in v.items() if len(h) >= MIN_HOSTS and
                        (it[0] not in template_labels.get(b, ()) or len(nets[b][it] - {""}) >= MIN_NETWORKS)}
                    for b, v in vals.items()}
        data = {"fields": fields, "vals": vals, "showable": showable, "combos": combos, "combo_hosts": combo_hosts, "hosts": hosts,
                "host_reports": host_reports, "host_items": host_items, "infected": infected, "sink_rep": sink_rep, "records": records,
                "days": sorted({d.start.date().isoformat() for d in svc})}
        with self.lock:
            self.cache.update(key=key, at=time.time(), data=data)
        return data

    # ---------------------------------------------------------------- the sinkholes of a report's hosts
    @staticmethod
    def sink_code(base, name):
        return cross_code(SECTION, base, [(base, []), (SINK, [f"Infection: {name}"])])

    def sinkholes_of(self, base, data=None):
        data = data or self.index()
        hs = data["hosts"].get(base, set())
        inf_hosts = [h for h in hs if h in data["infected"]]
        names = collections.Counter(n for h in inf_hosts for n in data["infected"][h])
        where = collections.defaultdict(collections.Counter)                       # infection -> sinkhole report -> hosts
        for h in inf_hosts:
            for r, ns in (data["sink_rep"].get(h) or {}).items():
                for n in ns:
                    where[n][r] += 1
        return {"hosts": len(inf_hosts), "share": round(len(inf_hosts) / max(1, len(hs)), 4),
                "reports": [{"report": r, "hosts": c} for r, c in collections.Counter(
                    r for h in inf_hosts for r in (data["sink_rep"].get(h) or {})).most_common()],
                "names": [{"name": n, "hosts": c, "code": self.sink_code(base, n),
                           "reports": [{"report": r, "hosts": k} for r, k in where[n].most_common()],
                           # every report that led to it: the sinkhole reports, and the services / vulnerability reports
                           # these hosts are in, grouped by kind
                           "seen_in": grouped(collections.Counter(r for h in inf_hosts if n in data["infected"][h] for r in data["host_reports"].get(h, ())),
                                              self.title_of, self.kind_of, dict(where[n]))}
                          for n, c in names.most_common(12)]}

    def gathered(self, report):
        data = self.index()
        base = sibling(report)
        hs = data["hosts"].get(base, set())
        fields = data["fields"].get(base) or self.ctx["patterns"].fields_for(base)
        # patterns: values shared by MIN_HOSTS hosts or more, per pattern field
        by = collections.defaultdict(list)
        hidden = collections.Counter()
        show = data["showable"].get(base, set())
        for (lbl, v), h in data["vals"].get(base, {}).items():
            if (lbl, v) in show:
                by[lbl].append({"value": v, "hosts": len(h), "records": sum(h.values()), "repeat_hosts": _repeat(h),
                                "share": round(len(h) / max(1, len(hs)), 4)})
            else:
                hidden[lbl] += 1
        patterns = []
        for f in fields:
            lbl = f["label"] if f["kind"] != "tags" else "Tag"
            if any(p["label"] == lbl for p in patterns):
                continue
            rows = sorted(by.get(lbl, []), key=lambda r: -r["hosts"])
            patterns.append({"label": lbl, "field": f["field"], "kind": f["kind"], "values": rows[:TOP], "shown": len(rows),
                             "hidden": hidden.get(lbl, 0)})
        # exact combinations of the items that may be shown (an item that may not be shown is left out of the set),
        # shared by MIN_HOSTS hosts or more
        proj_n, proj_h = collections.Counter(), collections.defaultdict(collections.Counter)
        for items, n in data["combos"].get(base, collections.Counter()).items():
            p = tuple(i for i in items if i in show)
            proj_n[p] += n
            proj_h[p].update(data["combo_hosts"][base][items])
        combos = []
        for items, n in proj_n.most_common():
            ch = proj_h[items]
            if len(ch) < MIN_HOSTS or not items:
                continue
            labels = [_label(i) for i in items]
            combos.append({"items": labels, "records": n, "hosts": len(ch), "repeat_hosts": _repeat(ch),
                           "share": round(len(ch) / max(1, len(hs)), 4), "code": combo_code(SECTION, base, base, labels)})
            if len(combos) >= 12:
                break
        small = sum(1 for items, ch in proj_h.items() if items and len(ch) < MIN_HOSTS)
        # across reports: the sets of reports these hosts are in (services reports, and the network communications
        # sinkhole reports they call), and the exact cross-report patterns
        sets = collections.Counter(tuple(sorted(set(data["host_reports"][h]) | set(data["sink_rep"].get(h, {})))) for h in hs)
        multi = sum(n for s, n in sets.items() if len(s) > 1)
        report_sets = [{"reports": list(s), "hosts": n} for s, n in sets.most_common() if len(s) > 1 and n >= MIN_HOSTS][:10]
        xp = collections.Counter()
        for h in hs:
            pat = host_pattern(data, h)
            if len(pat) > 1:
                xp[pat] += 1
        cross = []
        for pattern, n in xp.most_common():
            if n < MIN_HOSTS:
                break
            parts = [{"report": r, "items": list(items)} for r, items in pattern]
            cross.append({"parts": parts, "hosts": n, "code": cross_code(SECTION, base, [(p["report"], p["items"]) for p in parts])})
            if len(cross) >= 8:
                break
        sinkholes = self.sinkholes_of(base, data)
        hook = self.ctx.get("on_codes")
        if hook:
            try:
                hook(SECTION, base, base, [c["items"] for c in combos])
                hook(SECTION, base, None, [[(p["report"], p["items"]) for p in x["parts"]] for x in cross]
                     + [[(base, []), (SINK, [f"Infection: {n['name']}"])] for n in sinkholes["names"]])
            except Exception:                              # noqa: BLE001  (bookkeeping never breaks the window)
                pass
        return {"report": base, "hosts": len(hs), "records": data["records"].get(base, 0), "days": data["days"],
                "fields": fields, "patterns": patterns, "combinations": combos, "combinations_small": small,
                "across": {"hosts_in_other_reports": multi, "report_sets": report_sets, "cross_patterns": cross},
                "sinkholes": sinkholes, "min_hosts": MIN_HOSTS}

    def intel_view(self, report, title_of=None, asks=(), kind_of=None):
        """gathered() in the shape of /api/intel (intel.py): one report (the IPv6 twin folded in), its pattern fields as
        the indicator kinds, its exact combinations, the services reports the same hosts are in, and the sinkholes."""
        title_of = title_of or (lambda n: n)
        g = self.gathered(report)
        base, recs = g["report"], max(1, g["records"])
        kinds = []
        for p in g["patterns"]:
            if not p["values"] and not p["hidden"]:
                continue
            kinds.append({"kind": p["label"], "distinct": p["shown"], "hidden": p["hidden"], "field": p["field"], "how": p["kind"],
                          "values": [{"value": v["value"], "count": v["records"], "share": round(v["records"] / recs, 4),
                                      "hosts": v["hosts"], "repeat_hosts": v["repeat_hosts"]} for v in p["values"]]})
        combos = [{"items": c["items"], "count": c["records"], "share": round(c["records"] / recs, 4), "hosts": c["hosts"],
                   "repeat_hosts": c["repeat_hosts"], "code": c["code"]} for c in g["combinations"]]
        a = g["across"]
        multi = max(1, a["hosts_in_other_reports"])
        reports_seen = {base} | {r for s in a["report_sets"] for r in s["reports"]} | {p["report"] for x in a["cross_patterns"] for p in x["parts"]}
        return {
            "name": base, "title": title_of(base), "section": SECTION, "days": g["days"], "leads": [], "asks": list(asks),
            "labels": {r: title_of(r) for r in reports_seen}, "across_always": True, "min_hosts": g["min_hosts"],
            "reports": [{"report": base, "label": title_of(base), "records": g["records"], "hosts": g["hosts"], "indicators": kinds,
                         "combinations": combos, "combinations_total": len(combos) + g["combinations_small"],
                         "combinations_small": g["combinations_small"], "combo_of": "pattern items",
                         "single": None}],
            "across": {"devices": g["hosts"], "multi_devices": a["hosts_in_other_reports"],
                       "cross_combos": [{"parts": x["parts"], "devices": x["hosts"], "share": round(x["hosts"] / multi, 4), "code": x["code"]}
                                        for x in a["cross_patterns"]],
                       "cross_combos_total": len(a["cross_patterns"]),
                       "report_sets": [{"reports": s["reports"], "devices": s["hosts"], "share": round(s["hosts"] / max(1, g["hosts"]), 4)}
                                       for s in a["report_sets"]],
                       "report_sets_total": len(a["report_sets"]), "shared": [], "shared_total": 0},
            "sinkholes": g["sinkholes"],
            # the same hosts in every other category (the window leaves out this report and the sinkholes it shows above)
            "cross": self.for_hosts(self.index()["hosts"].get(base, set()), title_of, kind_of=kind_of, hold_small=True)}

    def new_code(self, report, items):
        """A researcher builds a combination for a note from the pattern items Intel gathered shows (MIN_HOSTS hosts or
        more): (entry facts, error). Records / hosts: those carrying exactly these items (of the ones that may be shown)."""
        data = self.index()
        base = sibling(report)
        if base not in data["hosts"]:
            return None, "This report is not in the days in memory."
        show = data["showable"].get(base, set())
        allowed = {_label(i): i for i in show}
        bad = [x for x in items if x not in allowed]
        if bad:
            return None, f"Not a pattern item shown for this report: {', '.join(bad[:3])}"
        want = tuple(sorted(allowed[x] for x in items))
        n, ch = 0, collections.Counter()
        for its, c in data["combos"].get(base, collections.Counter()).items():
            if tuple(i for i in its if i in show) == want:
                n += c
                ch.update(data["combo_hosts"][base][its])
        return {"report": base, "items": sorted(items), "records": n, "devices": len(ch), "repeat_devices": _repeat(ch),
                "days": data["days"]}, None

    def for_hosts(self, hosts, title_of=None, top=8, kind_of=None, with_hosts=False, hold_small=False):
        """An analyst's selection (acodes.py) across every category, for a set of host addresses that never leaves this
        module: the services reports the hosts are in, with their exact pattern combinations and codes; the CVEs and
        issues on them; the infections they call sinkholes as, with the sinkhole code per services report. Counts and
        codes only; pattern values only those MIN_HOSTS hosts share (as Intel gathered)."""
        title_of = title_of or self.title_of
        kind_of = kind_of or self.kind_of
        hosts = {h for h in hosts if h}
        data = self.index()
        # hold_small (Intel gathered): a researcher browsing gets no lasting code for a pattern fewer than MIN_HOSTS hosts
        # carry (small_codes.py). An analyst's code page keeps every code: there the analyst handed the selection over.
        full = not hold_small or small_codes.viewer_sees_hosts()
        services = []
        for base, hs in data["hosts"].items():
            mine = hs & hosts
            if not mine:
                continue
            show = data["showable"].get(base, set())
            pn, ph = collections.Counter(), collections.defaultdict(collections.Counter)
            for items, per in data["combo_hosts"][base].items():
                p = tuple(i for i in items if i in show)
                for ip, n in per.items():
                    if ip in mine:
                        pn[p] += n
                        ph[p][ip] += n
            combos = []
            for items, n in pn.most_common(top):
                labels = [_label(i) for i in items]
                combos.append({"items": labels, "records": n, "hosts": len(ph[items]), "repeat": _repeat(ph[items]),
                               "code": small_codes.code_for(combo_code(SECTION, base, base, labels), len(ph[items]), full)})
            services.append({"report": base, "title": title_of(base), "kind": kind_of(base), "hosts": len(mine), "records": sum(pn.values()),
                             "combinations": combos, "combinations_total": len(pn)})
        services.sort(key=lambda s: -s["hosts"])
        issues = collections.defaultdict(set)
        issue_reps = collections.defaultdict(lambda: collections.defaultdict(set))   # issue -> report -> hosts
        for d in list(self.ctx["svc_store"].days.values()):
            for e in d.events:
                if e.get("ip") in hosts:
                    for i in e.get("issues") or []:
                        issues[i].add(e["ip"])
                        issue_reps[i][sibling(e.get("report") or "")].add(e["ip"])
        names = collections.defaultdict(set)
        for h in hosts:
            for n in data["infected"].get(h, ()):
                names[n].add(h)
        infections = []
        for n, hs in sorted(names.items(), key=lambda kv: -len(kv[1])):
            reps = [{"report": s["report"], "title": s["title"], "hosts": len(hs & data["hosts"][s["report"]]),
                     "code": self.sink_code(s["report"], n)} for s in services if hs & data["hosts"][s["report"]]]
            infections.append({"name": n, "hosts": len(hs), "reports": sorted(reps, key=lambda r: -r["hosts"])[:6]})
        # across reports: the exact pattern of each host over every report it is in (services reports with their pattern
        # items, sinkhole reports with the infections), counted; LG-X codes keyed on the pattern's first report
        by_pat = collections.defaultdict(list)
        for h in hosts:
            p = host_pattern(data, h)
            if len(p) > 1:
                by_pat[p].append(h)
        xp = collections.Counter({p: len(hs) for p, hs in by_pat.items()})
        cross = []
        for pat, n in xp.most_common(top * 2):
            name = pat[0][0]
            x = {"parts": [{"report": r, "title": title_of(r), "items": list(i)} for r, i in pat], "hosts": n,
                 "code": small_codes.code_for(cross_code(SECTION, name, [(r, list(i)) for r, i in pat]), n, full), "name": name}
            if with_hosts:                                 # only for the analysts (combo_review.py): the addresses
                x["ips"] = sorted(by_pat[pat])
            cross.append(x)
        hook = self.ctx.get("on_codes")
        if hook and cross:
            try:
                for x in cross:
                    hook(SECTION, x["name"], None, [[(p["report"], p["items"]) for p in x["parts"]]])
            except Exception:                              # noqa: BLE001
                pass
        if hook:
            try:
                for s in services:
                    hook(SECTION, s["report"], s["report"], [c["items"] for c in s["combinations"]])
            except Exception:                              # noqa: BLE001
                pass
            try:
                for x in infections:
                    for r in x["reports"]:
                        hook(SECTION, r["report"], None, [[(r["report"], []), (SINK, [f"Infection: {x['name']}"])]])
            except Exception:                              # noqa: BLE001
                pass
        # where these hosts were seen, by kind of report: the sinkhole reports they call, the vulnerability reports, the
        # services reports, and the other categories, each report named with its hosts
        by_kind = collections.defaultdict(list)
        sink_hosts = collections.defaultdict(set)
        for h in hosts:
            for r in (data["sink_rep"].get(h) or {}):
                sink_hosts[r].add(h)
        for r, hs in sorted(sink_hosts.items(), key=lambda kv: -len(kv[1])):
            by_kind["Sinkhole reports"].append({"title": r, "hosts": len(hs)})
        for s in services:
            by_kind[kind_of(s["report"])].append({"title": s["title"], "hosts": s["hosts"]})
        order = ["Sinkhole reports", "Vulnerability reports", "Services reports"]
        sources = [{"kind": k, "reports": by_kind[k]} for k in order if by_kind.get(k)]
        sources += [{"kind": k, "reports": v} for k, v in sorted(by_kind.items()) if k not in order]
        return {"days": data["days"], "sources": sources, "services": services[:20], "services_total": len(services),
                "cross": cross, "cross_total": len(xp), "multi_hosts": sum(xp.values()),
                "issues": [{"name": i, "hosts": len(h),
                            "reports": [{"report": r, "title": title_of(r), "hosts": len(rh)}
                                        for r, rh in sorted(issue_reps[i].items(), key=lambda kv: -len(kv[1]))],
                            # every report that led to it, grouped by kind (its hosts' sinkhole reports too)
                            "seen_in": grouped({r: len(rh) for r, rh in issue_reps[i].items()}, title_of, kind_of,
                                               dict(collections.Counter(r for x in h for r in (data["sink_rep"].get(x) or {}))))}
                           for i, h in sorted(issues.items(), key=lambda kv: -len(kv[1]))][:40],
                "issues_total": len(issues), "infections": infections[:20], "infections_hosts": len({h for hs in names.values() for h in hs})}

    def matcher(self, entry):
        return Matcher(self, entry)

    def infections_of(self, hosts, n=10):
        """[(infection / category, hosts)] these hosts call botnet sinkholes as (network communications, days in memory)."""
        inf = self.index()["infected"]
        c = collections.Counter(name for h in hosts for name in inf.get(h, ()))
        return c.most_common(n)

    def patterns_of(self, events, m):
        """(records with a host, {host: its exact cross-report pattern}) for a list of events, computed once and shared by
        every cross-report code matched against the same list (the Executive portal filters by several at a time)."""
        key = (id(events), len(events), id(events[0]) if events else 0, id(events[-1]) if events else 0, id(self.index()))
        with self.lock:
            hit = self.cache.get("patterns_of")
            if not (hit and hit["key"] == key):
                hit = None
        if hit is None:
            # once per list: each host's records and set of reports (cheap); patterns are worked out only when asked
            mine, evs, reps = [], collections.defaultdict(list), collections.defaultdict(set)
            for e in events:
                h = m.host(e)
                if h:
                    mine.append(e); evs[h].append(e); reps[h].add(m.report(e))
            for h in reps:                                 # the sinkhole reports each host calls (the days in memory)
                reps[h] |= set(m.sink_rep.get(h) or {})
            hit = {"key": key, "mine": mine, "evs": evs, "reps": {h: frozenset(r) for h, r in reps.items()}, "pat": {}}
            with self.lock:
                self.cache["patterns_of"] = hit
        want_reps = frozenset(r for r, _ in m.e.get("parts") or [])
        pat = hit["pat"]
        for h, rs in hit["reps"].items():
            if rs != want_reps or h in pat:
                continue                                   # another set of reports: never this pattern
            per = collections.defaultdict(set)
            for e in hit["evs"][h]:
                per[m.report(e)].update(m.items(e))
            for r, names in (m.sink_rep.get(h) or {}).items():
                per[r] = {f"Infection: {n}" for n in names}
            pat[h] = tuple(sorted((r, tuple(sorted(i))) for r, i in per.items()))
        return hit["mine"], {h: p for h, p in pat.items() if hit["reps"][h] == want_reps}

    def records_of(self, report, limit=20000):
        """The records of a report (and its twin) in memory, for the field suggestions (never sent out)."""
        base, out = sibling(report), []
        for d in list(self.ctx["svc_store"].days.values()):
            for e in d.events:
                if sibling(e.get("report") or "") == base:
                    out.append(e)
                    if len(out) >= limit:
                        return out
        return out


class Matcher:
    """The records of a services code (combos.py's search): the same items and the same "may be shown" projection as
    the counts above (the projection of the days in memory). A sinkhole code: the report's records of the hosts that
    call a sinkhole as that infection in the network communications reports of the days in memory."""

    def __init__(self, sv, entry):
        self.sv, self.e = sv, entry
        self.section, self.name = SECTION, entry["name"]
        self.me, self.lname = "", ""
        data = sv.index()
        self.show = data["showable"]
        self.fields = {}
        parts = entry.get("parts") or []
        self.sink = [i for r, items in parts if r == SINK for i in items]
        self.reports = {entry["report"]} if entry["kind"] == "r" else {r for r, _ in parts if r != SINK}
        self.infected = data["infected"]
        self.sink_rep = data["sink_rep"]

    def host(self, e):
        return e.get("ip") or ""

    def report(self, e):
        return sibling(e.get("report") or "")

    def of_name(self, e):
        return True                                        # a services code is about hosts, in whichever report they are

    def items(self, e):
        base = self.report(e)
        if base not in self.fields:
            self.fields[base] = self.sv.ctx["patterns"].fields_for(base)
        show = self.show.get(base, ())
        return tuple(sorted(_label(i) for i in set(self.sv.ctx["patterns"].items(base, e, self.fields[base])) if i in show))

    def collections(self, labels):
        """The database collections of the code's reports (and their IPv6 twins), for a history search."""
        return {c for c in labels if sibling(c) in self.reports}

    def match(self, events):
        if self.sink:
            names = {s.split(": ", 1)[-1].lower() for s in self.sink}
            return [e for e in events if self.report(e) in self.reports and self.host(e)
                    and names & {n.lower() for n in self.infected.get(self.host(e), ())}]
        if self.e["kind"] == "r":
            want = tuple(sorted(self.e["items"]))
            return [e for e in events if self.host(e) and self.report(e) in self.reports and self.items(e) == want]
        want = tuple(sorted((r, tuple(sorted(i))) for r, i in self.e["parts"]))
        mine, pat = self.sv.patterns_of(events, self)
        hit = {h for h, p in pat.items() if p == want}
        return [e for e in mine if self.host(e) in hit]
