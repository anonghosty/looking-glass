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
  device that is already infected), and the infection names there (the threat's names, not constituent data).

The host sets never leave this module: answers hold counts, codes, and values shared by at least MIN_HOSTS hosts.
ServicesIntel(ctx): ctx svc_store, comms_store, patterns (svc_patterns.Patterns), load_day(), on_codes(section, name,
report, combos) (combos.py records the codes a researcher was shown).
"""
import collections
import threading
import time

from intel import combo_code, cross_code
from report_map import sibling
from svc_patterns import MIN_HOSTS

SECTION = "services"
TOP = 15
MIN_NETWORKS = 2      # free text (templates) must also be seen in two networks: one organisation's own wording is not shown


def _label(item):
    return f"{item[0]}: {item[1]}"


class ServicesIntel:
    def __init__(self, ctx):
        self.ctx = ctx
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
        vals = collections.defaultdict(lambda: collections.defaultdict(set))       # base -> (label, value) -> hosts
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
                    vals[base][it].add(ip)
                    nets[base][it].add(e.get("asn") or "")
                    host_items[ip][base].add(it)
                combos[base][items] += 1
                combo_hosts[base][items][ip] += 1
        infected = collections.defaultdict(set)                                   # host -> infection names
        for d in comms:
            for e in d.events:
                if e.get("src_ip") and e.get("infection"):
                    infected[e["src_ip"]].add(e["infection"])
        # an item may be shown when MIN_HOSTS hosts share it, and (free text) when they sit in MIN_NETWORKS networks
        template_labels = {b: {f["label"] for f in fs if f["kind"] == "template"} for b, fs in fields.items()}
        showable = {b: {it for it, h in v.items() if len(h) >= MIN_HOSTS and
                        (it[0] not in template_labels.get(b, ()) or len(nets[b][it] - {""}) >= MIN_NETWORKS)}
                    for b, v in vals.items()}
        data = {"fields": fields, "vals": vals, "showable": showable, "combos": combos, "combo_hosts": combo_hosts, "hosts": hosts,
                "host_reports": host_reports, "host_items": host_items, "infected": infected, "records": records,
                "days": sorted({d.start.date().isoformat() for d in svc})}
        with self.lock:
            self.cache.update(key=key, at=time.time(), data=data)
        return data

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
                by[lbl].append({"value": v, "hosts": len(h), "share": round(len(h) / max(1, len(hs)), 4)})
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
            combos.append({"items": labels, "records": n, "hosts": len(ch), "repeat_hosts": sum(1 for c in ch.values() if c > 1),
                           "share": round(len(ch) / max(1, len(hs)), 4), "code": combo_code(SECTION, base, base, labels)})
            if len(combos) >= 12:
                break
        small = sum(1 for items, ch in proj_h.items() if items and len(ch) < MIN_HOSTS)
        # across reports: the sets of services reports these hosts are in, and the exact cross-report patterns
        sets = collections.Counter(tuple(sorted(data["host_reports"][h])) for h in hs)
        multi = sum(n for s, n in sets.items() if len(s) > 1)
        report_sets = [{"reports": list(s), "hosts": n} for s, n in sets.most_common() if len(s) > 1 and n >= MIN_HOSTS][:10]
        xp = collections.Counter()
        for h in hs:
            per = data["host_items"].get(h) or {}
            if len(data["host_reports"][h]) > 1:
                xp[tuple(sorted((r, tuple(sorted(_label(i) for i in per.get(r, ()) if i in data["showable"].get(r, ()))))
                                for r in data["host_reports"][h]))] += 1
        cross = []
        for pattern, n in xp.most_common():
            if n < MIN_HOSTS:
                break
            parts = [{"report": r, "items": list(items)} for r, items in pattern]
            cross.append({"parts": parts, "hosts": n, "code": cross_code(SECTION, base, [(p["report"], p["items"]) for p in parts])})
            if len(cross) >= 8:
                break
        # sinkholes: these hosts in the network communications reports
        inf_hosts = [h for h in hs if h in data["infected"]]
        names = collections.Counter(n for h in inf_hosts for n in data["infected"][h])
        sinkholes = {"hosts": len(inf_hosts), "share": round(len(inf_hosts) / max(1, len(hs)), 4),
                     "names": [{"name": n, "hosts": c} for n, c in names.most_common(12)]}
        hook = self.ctx.get("on_codes")
        if hook:
            try:
                hook(SECTION, base, base, [c["items"] for c in combos])
                hook(SECTION, base, None, [[(p["report"], p["items"]) for p in x["parts"]] for x in cross])
            except Exception:                              # noqa: BLE001  (bookkeeping never breaks the window)
                pass
        return {"report": base, "hosts": len(hs), "records": data["records"].get(base, 0), "days": data["days"],
                "fields": fields, "patterns": patterns, "combinations": combos, "combinations_small": small,
                "across": {"hosts_in_other_reports": multi, "report_sets": report_sets, "cross_patterns": cross},
                "sinkholes": sinkholes, "min_hosts": MIN_HOSTS}

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
