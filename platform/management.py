"""The management portal (/management): aggregated statistics of both platforms for managers and executives.

Only aggregates leave the server here: counts, shares, trends, regions, sectors, networks, infections and issues.
No IP address, host name or host reference is ever part of an answer (tests/check_management.py checks it).
Permission 'management': the management role (exclusive, see auth.py) and admins (preview).
"""
import gc
import hashlib
import json
import os
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from datetime import timedelta

from flask import Response, jsonify, render_template, request

from security import public_error

# icombo / rcombo / scombo: one row of the "Top findings" lists (devices or hosts with exactly that combination)
# code: a researcher's combination code (combos.py): the portal shows exactly the devices / hosts that carry it, counted
COMMS_FILTERS = ("attack", "infection", "report", "region", "sector", "network", "severity", "icombo", "rcombo", "code")
SVC_FILTERS = ("family", "service", "issue", "region", "sector", "network", "severity", "icombo", "scombo", "code")
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}


def register(app, ctx):
    AUTH = ctx["AUTH"]

    def allowed():
        return AUTH["has_perm"]("management")

    def deny():
        return jsonify(error="The management portal is for the management role."), 403

    def demo():
        return bool(ctx["public_demo"]() or request.args.get("demo") == "1")

    title = lambda s: " ".join(w.capitalize() if not w.isupper() or len(w) > 3 else w for w in str(s or "").lower().split()) if s else ""

    def net_of(asn, d):
        return ctx["asn_registry"].company(asn, d) if asn else ""

    def sector_of(asn):
        v = (ctx["asn_registry"].all().get(str(asn)) or {}) if asn else {}
        return ctx["type_labels"]().get(v.get("type") or "unknown", "Unknown")

    def combo_scope(ev, ip_key, wanted, skip_empty=True):
        """Keep the devices / hosts whose items in the selection form exactly the combination clicked in a "Top findings"
        list, with all their records; wanted = [(items of one record, the combination 'a + b + c'), ...]. The same rule the
        lists count with, so the page then shows exactly the number on the row."""
        for items_of, want in wanted:
            if not want:
                continue
            sets = defaultdict(set)
            for e in ev:
                if e[ip_key] or not skip_empty:
                    sets[e[ip_key]].update(items_of(e))
            ips = {ip for ip, s in sets.items() if " + ".join(sorted(s)) == want}
            ev = [e for e in ev if (e[ip_key] or not skip_empty) and e[ip_key] in ips]
        return ev

    def lookups():
        """title / sector_of / net_of for one request, each worked out once per distinct value. The same functions as
        above, but a day has hundreds of thousands of records and only a few hundred networks, regions and cities:
        sector_of alone used to read the network-type list (a file check) once per record."""
        tl, reg = ctx["type_labels"](), ctx["asn_registry"].all()
        t_c, s_c, n_c = {}, {}, {}

        def t(s):
            r = t_c.get(s)
            if r is None:
                r = t_c[s] = title(s)
            return r

        def sec(asn):
            r = s_c.get(asn)
            if r is None:
                v = (reg.get(str(asn)) or {}) if asn else {}
                r = s_c[asn] = tl.get(v.get("type") or "unknown", "Unknown")
            return r

        def net(asn, d):
            k = (asn, d)
            r = n_c.get(k)
            if r is None:
                r = n_c[k] = net_of(asn, d)
            return r
        return t, sec, net

    def top(counter, hosts=None, n=10, total=None, label=None):
        tot = total or sum(counter.values()) or 1
        return [{"value": k, "label": label(k) if label else k, "count": c, "share": c / tot,
                 **({"hosts": len(hosts[k])} if hosts is not None else {})} for k, c in counter.most_common(n) if k not in (None, "")]

    def day_of(store):
        days = sorted(store.days)
        want = request.args.get("day")
        start = next((d for d in days if d.date().isoformat() == want), None) if want else None
        if start is None:
            d = store.get(ctx["replay_now"]())
            return d, [x.date().isoformat() for x in days]
        return store.days[start], [x.date().isoformat() for x in days]

    # ------------------------------------------------------------------ network communications
    def comms(args, d_mask, combos_n=12, day=None):
        title, sector_of, net_of = lookups()     # per-request memos of the functions above (same results)
        if day is None:
            day, days = day_of(ctx["store"])
        else:
            days = []
        labels = {s["name"]: s["label"] for s in ctx["registry"].get()}
        f = {k: args.get(k, "") for k in COMMS_FILTERS}
        def keep(e):
            return ((not f["attack"] or e["attack_class"] == f["attack"]) and (not f["infection"] or (e["infection"] or "unknown") == f["infection"])
                    and (not f["report"] or e["source"] == f["report"]) and (not f["region"] or title(e["src_region"]) == f["region"])
                    and (not f["severity"] or (e["severity"] or "") == f["severity"])
                    and (not f["sector"] or sector_of(e["src_asn"]) == f["sector"]) and (not f["network"] or net_of(e["src_asn"], d_mask) == f["network"]))
        all_ev = day.events
        if f["code"]:                     # the records of a combination code, with the same rule as the analysts' search
            all_ev = ctx["combo_filter"](f["code"], "infections", all_ev, day) or []
        ev = [e for e in all_ev if keep(e)]
        ev = combo_scope(ev, "src_ip", [(lambda e: (e["infection"] or "unknown",), f["icombo"]),
                                        (lambda e: (labels.get(e["source"], e["source"]),), f["rcombo"])])
        hosts = {}
        inf, att, rep, reg, city, net, sec, sev, dst = (Counter() for _ in range(9))
        inf_h, reg_h, net_h, sec_h, rep_h, c2_h = (defaultdict(set) for _ in range(6))
        c2, dst_ips = Counter(), set()
        rd_city, rd_top, rd_net = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
        cpts = {}                                       # city -> events, devices, position, region (for the map)
        rd_ch = defaultdict(lambda: defaultdict(set))   # region -> city -> devices
        hours = [0] * 24
        t0 = day.start.timestamp()
        for e in ev:
            ip = e["src_ip"]
            i = e["infection"] or "unknown"
            inf[i] += 1; att[e["attack_class"]] += 1; rep[e["source"]] += 1; sev[e["severity"] or "unrated"] += 1
            r = title(e["src_region"]) or "Unknown region"; reg[r] += 1
            if e["src_city"]:
                city[title(e["src_city"])] += 1
                rd_city[r][title(e["src_city"])] += 1
                if ip:
                    rd_ch[r][title(e["src_city"])].add(ip)
                if e.get("src_coords"):
                    cp = cpts.setdefault(title(e["src_city"]), {"events": 0, "hosts": set(), "at": e["src_coords"], "region": r})
                    cp["events"] += 1
                    if ip:
                        cp["hosts"].add(ip)
            n = net_of(e["src_asn"], d_mask) or "Unknown network"; net[n] += 1
            rd_top[r][i] += 1; rd_net[r][n] += 1
            s = sector_of(e["src_asn"]); sec[s] += 1
            if e["dst_geo"]:
                dst[e["dst_geo"]] += 1
            hours[int((e["_t"] - t0) // 3600) % 24] += 1
            if e["http_host"]:
                c2[e["http_host"]] += 1
                if ip:
                    c2_h[e["http_host"]].add(ip)
            if e["dst_ip"]:
                dst_ips.add(e["dst_ip"])
            if ip:
                h = hosts.setdefault(ip, {"inf": set(), "rep": set(), "ts": []})
                h["inf"].add(i); h["rep"].add(e["source"]); h["ts"].append(e["_t"])
                inf_h[i].add(ip); reg_h[r].add(ip); net_h[n].add(ip); sec_h[s].add(ip); rep_h[e["source"]].add(ip)
        multi_inf = sum(1 for h in hosts.values() if len(h["inf"]) > 1)
        cross = sum(1 for h in hosts.values() if len(h["rep"]) > 1)
        pairs = Counter()
        for h in hosts.values():
            if len(h["rep"]) > 1:
                rs = sorted(labels.get(x, x) for x in h["rep"])
                for a_i in range(len(rs)):
                    for b_i in range(a_i + 1, len(rs)):
                        pairs[f"{rs[a_i]} + {rs[b_i]}"] += 1
        # devices with several infections: how many infections, and which combinations
        n_inf = Counter(min(len(h["inf"]), 5) for h in hosts.values() if len(h["inf"]) > 1)
        combos = Counter(" + ".join(sorted(h["inf"])) for h in hosts.values() if len(h["inf"]) > 1)          # every exact combination
        rcombos = Counter(" + ".join(sorted(labels.get(x, x) for x in h["rep"])) for h in hosts.values() if len(h["rep"]) > 1)
        n_rep = Counter(min(len(h["rep"]), 4) for h in hosts.values() if len(h["rep"]) > 1)
        # repeat behaviour (beaconing): devices seen three times or more, regular rhythm, typical interval
        gaps_med, regular = [], 0
        for h in hosts.values():
            ts = sorted(h["ts"])
            if len(ts) >= 3:
                gp = [b - a for a, b in zip(ts, ts[1:]) if b > a]
                if len(gp) >= 2:
                    gp_sorted = sorted(gp); med = gp_sorted[len(gp) // 2]; gaps_med.append(med)
                    mean = sum(gp) / len(gp); sd = (sum((x - mean) ** 2 for x in gp) / len(gp)) ** .5
                    regular += bool(mean and sd / mean < .5)
        typical = sorted(gaps_med)[len(gaps_med) // 2] if gaps_med else None
        dur = (lambda s: "" if s is None else f"{s / 3600:.1f} h" if s >= 3600 else f"{s / 60:.0f} min" if s >= 60 else f"{s:.0f} s")
        names = ctx["read_names"](); kb = ctx["knowledge_base"]()
        def friendly(i):
            e = kb.get(i.lower()) or {}
            fam = (names.get(i.lower()) or {}).get("family", "")
            return {"title": e.get("title") or (fam.replace("actor:", "") if fam else ""), "family": fam, "type": e.get("type", "")}
        infections = []
        for row in top(inf, inf_h, 40, len(ev)):
            infections.append({**row, **friendly(row["value"])})
        infections = sorted(infections, key=lambda r: (-r["hosts"], -r["count"]))[:15]     # ranked by devices, as shown
        n_ev, n_hosts = len(ev), len(hosts)
        peak = max(range(24), key=lambda x: hours[x]) if n_ev else None
        findings = []
        if n_ev:
            findings.append(f"{n_hosts:,} devices in the constituency were seen infected or attacking on {day.start.date()}, "
                            f"in {n_ev:,} events across {len(rep)} report{'s' if len(rep) != 1 else ''}.")
            if infections:
                t = infections[0]
                findings.append(f"The most common infection is {t['title'] or t['value']} ({t['hosts']:,} devices, "
                                f"{t['hosts'] / max(1, n_hosts):.0%} of the affected devices).")
            if reg:
                r0, c0 = reg.most_common(1)[0]
                findings.append(f"{r0} accounts for {c0 / n_ev:.0%} of the activity.")
            if net:
                n0 = top(net, net_h, 1, n_ev)[0]
                findings.append(f"Most affected network: {n0['label']} ({n0['hosts']:,} devices).")
            if multi_inf:
                findings.append(f"{multi_inf:,} devices carry more than one infection: they are the priority for clean-up.")
            if peak is not None:
                findings.append(f"Activity peaked between {peak:02d}:00 and {(peak + 1) % 24:02d}:00 UTC.")
        facets = {
            "attack": sorted({e["attack_class"] for e in all_ev}),
            "infection": [k for k, _ in Counter((e["infection"] or "unknown") for e in all_ev).most_common(80)],
            "report": [{"value": k, "label": labels.get(k, k)} for k, _ in Counter(e["source"] for e in all_ev).most_common()],
            "region": [k for k, _ in Counter(title(e["src_region"]) for e in all_ev if e["src_region"]).most_common()],
            "sector": [k for k, _ in Counter(sector_of(e["src_asn"]) for e in all_ev).most_common()],
            "network": [k for k, _ in Counter(net_of(e["src_asn"], d_mask) for e in all_ev if e["src_asn"]).most_common(40)],
            "severity": sorted({e["severity"] or "" for e in all_ev} - {""}, key=lambda s: SEV_ORDER.get(s, 9)),
        }
        return {
            "platform": "comms", "day": day.start.date().isoformat(), "days": days, "filters": f, "facets": facets,
            "kpis": {"events": n_ev, "devices": n_hosts, "infections": len(inf), "reports": len(rep), "regions": len([r for r in reg if r != "Unknown region"]),
                     "networks": len(net), "multi_infected": multi_inf, "cross_report": cross,
                     "critical": sev.get("critical", 0), "share_of_day": n_ev / max(1, len(all_ev)), "day_events": len(all_ev)},
            "hours": hours, "peak_hour": peak, "findings": findings,
            "item_counts": {k: len(v) for k, v in inf_h.items()},       # devices per infection (all of them: the baseline)
            "infections": infections, "attack": top(att, None, 10, n_ev),
            "reports": top(rep, rep_h, 12, n_ev, label=lambda k: labels.get(k, k)),
            "regions": top(reg, reg_h, 30, n_ev), "cities": top(city, None, 10, n_ev),
            "networks": top(net, net_h, 12, n_ev), "sectors": top(sec, sec_h, 15, n_ev),
            "severity": sorted(top(sev, None, 10, n_ev), key=lambda r: SEV_ORDER.get(r["value"], 9)),
            "destinations": top(dst, None, 10, n_ev), "report_pairs": top(pairs, None, 8, cross or 1),
            "cities_map": [{"name": n, "region": v["region"], "events": v["events"], "devices": len(v["hosts"]), "lon": v["at"][0], "lat": v["at"][1]}
                           for n, v in sorted(cpts.items(), key=lambda kv: -len(kv[1]["hosts"]))[:40]],
            "region_details": {r: {"cities": rd_city[r].most_common(3), "top": [(friendly(k)["title"] or k, v) for k, v in rd_top[r].most_common(3)],
                                   "networks": rd_net[r].most_common(2), "devices": len(reg_h[r]), "events": reg[r],
                                   "city_devices": sorted(((n, len(h)) for n, h in rd_ch[r].items()), key=lambda x: -x[1])[:6]} for r in reg},
            "multi": {"devices": multi_inf, "share": multi_inf / max(1, n_hosts),
                      "by_count": [{"value": str(c), "label": f"{c}{'+' if c == 5 else ''} infections", "count": n_inf.get(c, 0)} for c in range(2, 6)],
                      "combos": top(combos, None, combos_n, multi_inf or 1), "combinations": len(combos)},
            "cross": {"devices": cross, "share": cross / max(1, n_hosts),
                      "by_count": [{"value": str(c), "label": f"{c}{'+' if c == 4 else ''} reports", "count": n_rep.get(c, 0)} for c in range(2, 5)],
                      "combos": top(rcombos, None, combos_n, cross or 1), "combinations": len(rcombos)},
            "beacon": {"repeating": len(gaps_med), "regular": regular, "typical": dur(typical),
                       "share": regular / max(1, len(gaps_med))},
            "c2": {"domains": len(c2), "destinations": len(dst_ips),
                   "top": [{"value": k, "label": ("Domain " + str(i + 1)) if d_mask else k, "count": v, "hosts": len(c2_h[k]), "share": v / max(1, n_ev)}
                           for i, (k, v) in enumerate(c2.most_common(8))]},
        }

    # ------------------------------------------------------------------ publicly accessible / vulnerable services
    def services(args, d_mask, combos_n=12, day=None):
        title, sector_of, net_of = lookups()     # per-request memos of the functions above (same results)
        if day is None:
            day, days = day_of(ctx["svc_store"])
        else:
            days = []
        f = {k: args.get(k, "") for k in SVC_FILTERS}
        def keep(e):
            return ((not f["family"] or e["family"] == f["family"]) and (not f["service"] or e["service"] == f["service"])
                    and (not f["issue"] or f["issue"] in e["issues"]) and (not f["region"] or (title(e["region"]) or "Unknown region") == f["region"])
                    and (not f["severity"] or (e["severity"] or "") == f["severity"])
                    and (not f["sector"] or sector_of(e["asn"]) == f["sector"]) and (not f["network"] or net_of(e["asn"], d_mask) == f["network"]))
        all_ev = day.events
        if f["code"]:
            all_ev = ctx["combo_filter"](f["code"], "issues", all_ev, day) or []
        ev = [e for e in all_ev if keep(e)]
        # services hosts are counted by address as written (an empty address too), so the combination rule is the same
        ev = combo_scope(ev, "ip", [(lambda e: e["issues"], f["icombo"]), (lambda e: (e["service"],), f["scombo"])], skip_empty=False)
        kev = ctx["cve_intel"].kev()
        hosts = {}
        svc, fam, iss, reg, net, sec, sev, ind, vend = (Counter() for _ in range(9))
        iss_h, reg_h, net_h, sec_h, svc_h = (defaultdict(set) for _ in range(5))
        rd_city, rd_top, rd_net, rd_svc = defaultdict(Counter), defaultdict(Counter), defaultdict(Counter), defaultdict(Counter)
        cpts = {}
        rd_ch = defaultdict(lambda: defaultdict(set))
        hours = [0] * 24
        t0 = day.start.timestamp()
        for e in ev:
            ip = e["ip"]
            svc[e["service"]] += 1; fam[e["family"]] += 1; sev[e["severity"] or "unrated"] += 1
            r = title(e["region"]) or "Unknown region"; reg[r] += 1
            n = net_of(e["asn"], d_mask) or "Unknown network"; net[n] += 1
            if e.get("city"):
                rd_city[r][title(e["city"])] += 1
                rd_ch[r][title(e["city"])].add(ip)
                cp = cpts.setdefault(title(e["city"]), {"events": 0, "hosts": set(), "key": (e.get("geo") or "", e.get("region") or "", e["city"]), "region": r})
                cp["events"] += 1; cp["hosts"].add(ip)
            rd_net[r][n] += 1; rd_svc[r][e["service"]] += 1
            for i in e["issues"]:
                rd_top[r][i] += 1
            s = sector_of(e["asn"]); sec[s] += 1
            if e.get("sector"):
                ind[e["sector"]] += 1
            if e.get("vendor"):
                vend[e["vendor"]] += 1
            hours[int((e["_t"] - t0) // 3600) % 24] += 1
            h = hosts.setdefault(ip, {"iss": set(), "svc": set(), "kev": False, "dev": ""})
            if e.get("vendor") or e.get("device_type"):
                h["dev"] = h["dev"] or " · ".join(x for x in (e.get("vendor"), e.get("device_type")) if x)
            h["svc"].add(e["service"]); svc_h[e["service"]].add(ip); reg_h[r].add(ip); net_h[n].add(ip); sec_h[s].add(ip)
            for i in e["issues"]:
                iss[i] += 1; iss_h[i].add(ip); h["iss"].add(i)
                if i.upper() in kev:
                    h["kev"] = True
        n_ev, n_hosts = len(ev), len(hosts)
        n_iss = Counter(min(len(h["iss"]), 5) for h in hosts.values() if len(h["iss"]) > 1)
        icombos = Counter(" + ".join(sorted(h["iss"])) for h in hosts.values() if len(h["iss"]) > 1)          # every exact combination
        scombos = Counter(" + ".join(sorted(h["svc"])) for h in hosts.values() if len(h["svc"]) > 1)
        n_svc = Counter(min(len(h["svc"]), 4) for h in hosts.values() if len(h["svc"]) > 1)
        spairs = Counter()
        for h in hosts.values():
            if len(h["svc"]) > 1:
                ss = sorted(h["svc"])
                for a_i in range(len(ss)):
                    for b_i in range(a_i + 1, len(ss)):
                        spairs[f"{ss[a_i]} + {ss[b_i]}"] += 1
        devices = Counter(h["dev"] for h in hosts.values() if h["dev"])
        vuln = sum(1 for h in hosts.values() if h["iss"])
        multi = sum(1 for h in hosts.values() if len(h["iss"]) > 1)
        cross = sum(1 for h in hosts.values() if len(h["svc"]) > 1)
        kev_hosts = sum(1 for h in hosts.values() if h["kev"])
        cve_ids = [i for i in iss if re.match(r"^CVE-\d{4}-\d+$", i, re.I)]
        cards = {i: ctx["cve_intel"].card(i, fetch=False) for i in cve_ids}
        ikb = ctx["issues_kb"]()
        issues = []
        for row in top(iss, iss_h, 25, n_ev):
            i = row["value"]
            c = cards.get(i) or {}
            d = ikb.get(i.lower()) or {}
            issues.append({**row, "cve": i in cards, "exploited": bool(c.get("exploited")), "cvss": (c.get("cvss") or {}).get("score"),
                           "severity": (c.get("cvss") or {}).get("severity", ""), "epss": c.get("epss"),
                           "title": (c.get("kev") or {}).get("name") or d.get("title") or (c.get("description") or "")[:90]})
        kev_list = [i for i in cve_ids if (cards[i] or {}).get("exploited")]
        crit = [i for i in cve_ids if ((cards[i] or {}).get("cvss") or {}).get("score", 0) and cards[i]["cvss"]["score"] >= 9]
        peak = max(range(24), key=lambda x: hours[x]) if n_ev else None
        findings = []
        if n_ev:
            findings.append(f"{n_hosts:,} internet-facing hosts in the constituency were reported on {day.start.date()}; "
                            f"{vuln:,} of them ({vuln / max(1, n_hosts):.0%}) have a concrete issue.")
            if kev_hosts:
                findings.append(f"{kev_hosts:,} hosts run software with vulnerabilities that attackers are actively exploiting "
                                f"(CISA KEV: {len(kev_list)} CVE{'s' if len(kev_list) != 1 else ''}). These come first.")
            if crit:
                findings.append(f"{len(crit)} critical CVE{'s' if len(crit) != 1 else ''} (CVSS 9 or more) were found.")
            if multi:
                findings.append(f"{multi:,} hosts carry more than one issue: the largest attack surface.")
            if svc:
                s0, c0 = svc.most_common(1)[0]
                findings.append(f"Most visible: {s0} ({len(svc_h[s0]):,} hosts).")
            if reg:
                r0, c0 = reg.most_common(1)[0]
                findings.append(f"{r0} accounts for {c0 / n_ev:.0%} of the records.")
        facets = {
            "family": sorted({e["family"] for e in all_ev}),
            "service": [k for k, _ in Counter(e["service"] for e in all_ev).most_common(80)],
            "issue": [k for k, _ in Counter(i for e in all_ev for i in e["issues"]).most_common(80)],
            "region": [k for k, _ in Counter(title(e["region"]) for e in all_ev if e["region"]).most_common()],
            "sector": [k for k, _ in Counter(sector_of(e["asn"]) for e in all_ev).most_common()],
            "network": [k for k, _ in Counter(net_of(e["asn"], d_mask) for e in all_ev if e["asn"]).most_common(40)],
            "severity": sorted({e["severity"] or "" for e in all_ev} - {""}, key=lambda s: SEV_ORDER.get(s, 9)),
        }
        return {
            "platform": "services", "day": day.start.date().isoformat(), "days": days, "filters": f, "facets": facets,
            "kpis": {"records": n_ev, "hosts": n_hosts, "vulnerable_hosts": vuln, "multi_issue": multi, "cross_report": cross,
                     "kev_hosts": kev_hosts, "kev_cves": len(kev_list), "critical_cves": len(crit), "cves": len(cve_ids),
                     "issues": len(iss), "services": len(svc), "regions": len([r for r in reg if r != "Unknown region"]),
                     "critical": sev.get("critical", 0), "share_of_day": n_ev / max(1, len(all_ev)), "day_records": len(all_ev)},
            "hours": hours, "peak_hour": peak, "findings": findings, "issues": issues,
            "item_counts": {k: len(v) for k, v in iss_h.items()},       # hosts per issue (all of them: the baseline)
            "services": top(svc, svc_h, 12, n_ev), "families": top(fam, None, 8, n_ev),
            "regions": top(reg, reg_h, 30, n_ev), "networks": top(net, net_h, 12, n_ev), "sectors": top(sec, sec_h, 15, n_ev),
            "industries": top(ind, None, 10, n_ev), "vendors": top(vend, None, 10, n_ev),
            "severity": sorted(top(sev, None, 10, n_ev), key=lambda r: SEV_ORDER.get(r["value"], 9)),
            "cities_map": [p for p in ({"name": n, "region": v["region"], "events": v["events"], "devices": len(v["hosts"]),
                                        **dict(zip(("lon", "lat"), ctx["geocode"](*v["key"]) or (None, None)))}
                                       for n, v in sorted(cpts.items(), key=lambda kv: -len(kv[1]["hosts"]))[:40]) if p["lon"] is not None],
            "region_details": {r: {"cities": rd_city[r].most_common(3), "top": rd_top[r].most_common(3), "services": rd_svc[r].most_common(2),
                                   "networks": rd_net[r].most_common(2), "devices": len(reg_h[r]), "events": reg[r],
                                   "city_devices": sorted(((n, len(h)) for n, h in rd_ch[r].items()), key=lambda x: -x[1])[:6]} for r in reg},
            "multi": {"hosts": multi, "share": multi / max(1, vuln),
                      "by_count": [{"value": str(c), "label": f"{c}{'+' if c == 5 else ''} issues", "count": n_iss.get(c, 0)} for c in range(2, 6)],
                      "combos": top(icombos, None, combos_n, multi or 1), "combinations": len(icombos)},
            "cross": {"hosts": cross, "share": cross / max(1, n_hosts),
                      "by_count": [{"value": str(c), "label": f"{c}{'+' if c == 4 else ''} reports", "count": n_svc.get(c, 0)} for c in range(2, 5)],
                      "pairs": top(spairs, None, 8, cross or 1),
                      "combos": top(scombos, None, combos_n, cross or 1), "combinations": len(scombos)},
            "issue_kinds": [{"value": "cve", "label": "Vulnerabilities (CVE)", "count": sum(iss[i] for i in cve_ids)},
                            {"value": "other", "label": "Configuration / exposure", "count": sum(v for i, v in iss.items() if i not in cards)}],
            "devices": top(devices, None, 10, n_hosts or 1),
        }

    # ------------------------------------------------------------------ 7-day baseline
    # Each figure of the selected day is compared with the 7 days before it. A past day is loaded on its own (outside
    # the replay store, one at a time), analysed with exactly the same code and filters, and only its summary is kept
    # (memory and data/mgmt_baseline.json). A summary is redone when that day's reports change (row counts).
    BASE_N = 7
    KPI_KEYS = {"comms": ("devices", "events", "infections", "multi_infected", "cross_report", "regions", "networks", "critical"),
                "services": ("hosts", "records", "vulnerable_hosts", "kev_hosts", "critical_cves", "multi_issue", "cross_report",
                             "services", "issues", "regions", "critical")}
    FILTERS = {"comms": COMMS_FILTERS, "services": SVC_FILTERS}
    base_path = os.path.join(ctx["data_dir"], "mgmt_baseline.json") if ctx.get("data_dir") else None
    bl = {"mem": {}, "jobs": {}, "sig": {}}
    base_lock, build_lock = threading.Lock(), threading.Lock()

    def _base_load():
        try:
            with open(base_path, encoding="utf-8") as fh:
                bl["mem"] = json.load(fh).get("days", {})
        except (OSError, ValueError, TypeError):
            bl["mem"] = {}
    def _base_save():
        if not base_path:
            return
        # several baselines can be built at once (past days come from memory): new days are added under base_lock (see
        # build) and the file is written from a frozen copy, so a day added meanwhile can never break the write
        with base_lock:
            cut = (time.time() - 30 * 86400)
            keep = {k: v for k, v in list(bl["mem"].items()) if v.get("at", 0) > cut}
            bl["mem"] = keep
            frozen = dict(keep)
            tmp = base_path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump({"about": "Executive portal: 7-day baseline summaries (aggregates only)", "days": frozen}, fh)
                os.replace(tmp, base_path)
            except OSError:
                pass
    if base_path:
        _base_load()

    def store_of(platform):
        return ctx["store"] if platform == "comms" else ctx["svc_store"]

    def fkey(platform, args, d_mask):
        sel = {k: args.get(k, "") for k in FILTERS[platform] if args.get(k)}
        raw = json.dumps([sel, bool(d_mask), ctx["scope_text"]()], sort_keys=True)
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def sig_of(platform, start):
        """Rows per report of a day in MongoDB (cheap indexed counts), cached for 10 minutes."""
        k = f"{platform}|{start.date()}"
        hit = bl["sig"].get(k)
        if hit and time.time() - hit[0] < 600:
            return hit[1]
        try:
            s = store_of(platform).signature(start)
        except Exception:      # noqa: BLE001  (MongoDB unreachable: try again later)
            return None
        bl["sig"][k] = (time.time(), s)
        return s

    def summarise(platform, d):
        items = sorted(d.get("item_counts", {}).items(), key=lambda kv: -kv[1])[:80]
        return {"kpis": {k: d["kpis"].get(k, 0) for k in KPI_KEYS[platform]}, "items": dict(items)}

    # ------------------------------------------------------------------ compact past days
    # A selection's baseline needs the 7 previous days under the same filters. Loading a past day from MongoDB reads its
    # own files and the next day's, so each new selection (a filter, a clicked combination) used to cost 14 day loads, one
    # at a time behind a shared lock: a new filter waited minutes for its baseline. Instead each past day is loaded once
    # and kept in a compact form: only the fields comms() and services() read, as fixed slots, repeated text stored once.
    # Any selection is then worked out from memory in seconds, with exactly the same functions. A day is loaded again when
    # MongoDB has other rows for it (its signature changes) or the constituency changes; above MGMT_PAST_RECORDS records
    # in all, days are not kept and are loaded as before.
    PAST_FIELDS = {"comms": ("src_ip", "infection", "attack_class", "source", "severity", "src_region", "src_city", "src_coords",
                             "src_asn", "dst_geo", "http_host", "dst_ip", "_t"),
                   "services": ("ip", "service", "family", "severity", "region", "city", "geo", "asn", "issues", "sector",
                                "vendor", "device_type", "_t")}
    PAST_LIMIT = int(os.environ.get("MGMT_PAST_RECORDS", "3000000"))
    past, past_lock = {}, threading.Lock()

    def _rec_class(fields):
        idx = {f: i for i, f in enumerate(fields)}

        class Rec:                      # reads like the record dict for the fields the Executive figures use
            __slots__ = ("_v",)

            def __init__(self, v):
                self._v = v

            def __getitem__(self, k):
                return self._v[idx[k]]

            def get(self, k, default=None):
                i = idx.get(k)
                return default if i is None else self._v[i]
        return Rec
    REC = {p: _rec_class(f) for p, f in PAST_FIELDS.items()}

    class PastDay:
        def __init__(self, start, events):
            self.start, self.events = start, events

    def past_key(platform, start):
        return (platform, start, ctx["scope_text"]())

    def past_ready(platform, start):
        """True when this past day needs no MongoDB load: nothing was sent that day, or its compact copy is current."""
        sig = sig_of(platform, start)
        if not sig:
            return True
        hit = past.get(past_key(platform, start))
        return bool(hit and hit["sig"] == sig)

    def past_day(platform, start, sig):
        key = past_key(platform, start)
        hit = past.get(key)
        if hit and hit["sig"] == sig:
            return hit["day"]
        with build_lock:                                  # one full past day in memory at a time, while it is compacted
            hit = past.get(key)
            if hit and hit["sig"] == sig:
                return hit["day"]
            full = store_of(platform)._load(start)
            try:
                F, R, it = PAST_FIELDS[platform], REC[platform], sys.intern
                day = PastDay(full.start, [R(tuple(it(v) if type(v) is str else v for v in (e.get(f) for f in F)))
                                           for e in full.events])
            finally:
                del full
                gc.collect()
            with past_lock:
                past[key] = {"sig": sig, "day": day}
                # only the days a baseline can still ask for, and never more records than the limit allows
                cut = max(k[1] for k in past) - timedelta(days=BASE_N + 1)
                for k in [k for k in past if k[1] < cut or (k[0] == platform and k[1] == start and k != key)]:
                    del past[k]
                while sum(len(v["day"].events) for v in past.values()) > PAST_LIMIT and len(past) > 0:
                    del past[min(past, key=lambda k: k[1])]
            return day

    def compute_day(platform, start, args, d_mask):
        """Analyse one past day with the selection's filters; None when Shadowserver sent nothing for it."""
        sig = sig_of(platform, start)
        if not sig:
            return {"sig": sig or {}, "none": True, "at": time.time()}
        day = past_day(platform, start, sig)
        d = (comms if platform == "comms" else services)(args, d_mask, combos_n=1, day=day)
        return {"sig": sig, "at": time.time(), **summarise(platform, d)}

    def past_days(platform, d):
        sel = next((s for s in store_of(platform).days if s.date().isoformat() == d["day"]), None)
        if sel is None:
            from datetime import datetime, timezone
            sel = datetime.fromisoformat(d["day"]).replace(tzinfo=timezone.utc)
        return [sel - timedelta(days=i) for i in range(BASE_N, 0, -1)]

    def build(platform, starts, args, d_mask, fk, job):
        try:
            for start in starts:
                key = f"{platform}|{start.date()}|{fk}"
                e = bl["mem"].get(key)
                if not (e and e.get("sig") == sig_of(platform, start)):
                    result = compute_day(platform, start, args, d_mask)
                    with base_lock:                       # never while _base_save is reading the same dictionary
                        bl["mem"][key] = result
                    _base_save()
                job["done"] += 1
        except Exception:                                 # noqa: BLE001  (logged by Flask's logger below)
            import logging
            logging.getLogger(__name__).exception("Executive baseline build failed")
        finally:
            with base_lock:
                bl["jobs"].pop(f"{platform}|{fk}", None)

    def baseline(platform, d, args, d_mask, wait=False):
        """The 7 days before the selected day for this selection: each figure per day and each top item per day.
        Missing days are built in the background (or now, with wait=True, for the PDF report)."""
        fk = fkey(platform, args, d_mask)
        starts = past_days(platform, d)
        todo = []
        for start in starts:
            e = bl["mem"].get(f"{platform}|{start.date()}|{fk}")
            if not (e and e.get("sig") == sig_of(platform, start)):
                todo.append(start)
        jk = f"{platform}|{fk}"
        if todo and not wait and all(past_ready(platform, s) for s in todo):
            wait = True                 # every past day is already in memory: seconds, so the page gets it at once
        if todo:
            if wait:
                build(platform, todo, dict(args), d_mask, fk, {"done": 0})
                todo = []
            else:
                with base_lock:
                    if jk not in bl["jobs"]:
                        bl["jobs"][jk] = {"done": 0, "total": len(todo)}
                        threading.Thread(target=build, args=(platform, todo, dict(args), d_mask, fk, bl["jobs"][jk]),
                                         daemon=True, name="mgmt-baseline").start()
        entries = [bl["mem"].get(f"{platform}|{s.date()}|{fk}") for s in starts]
        names = [r["value"] for r in (d.get("infections") if platform == "comms" else d.get("issues")) or []]
        kpis = {k: [None if not e or e.get("none") else e["kpis"].get(k, 0) for e in entries] for k in KPI_KEYS[platform]}
        items = {n: [None if not e or e.get("none") else e["items"].get(n, 0) for e in entries] for n in names}
        job = bl["jobs"].get(jk)
        unit = "devices" if platform == "comms" else "hosts"
        rows = {r["value"]: r for r in ((d.get("infections") if platform == "comms" else d.get("issues")) or [])}
        grade = {"kpis": {k: assess(d["kpis"].get(k, 0), v, unit) for k, v in kpis.items()},
                 "items": {n: assess(rows[n]["hosts"], v, unit) for n, v in items.items()}}
        return {"days": [s.date().isoformat() for s in starts], "kpis": kpis, "items": items, "assess": grade, "scale": SCALE,
                "available": sum(1 for e in entries if e and not e.get("none")),
                "building": bool(todo), "progress": {"done": job["done"], "total": job["total"]} if job else None}

    def avg(vals):
        v = [x for x in vals if x is not None]
        return sum(v) / len(v) if v else None

    # How a day compares with its 7-day average, in levels that mean something: a few percent is day-to-day noise
    # (grey); amber and red are kept for changes worth acting on, so the colours are not learned to be ignored.
    #   normal  under 10 %, or numbers too small to read anything into      grey
    #   info    up 10-25 % (keep an eye on it) / down 10-25 %                blue
    #   good    down 25-50 %                                                 green
    #   watch   up 25-50 %; down 50 % or more; gone quiet (0 today)          amber  (look into it: also a reporting change?)
    #   high    up 50 % or more; new this week with 20 or more               red    (investigate now)
    # the scale, as shown on the page and in the report (one source for both)
    SCALE = [
        {"level": "normal", "name": "Normal", "range": "within ±10%",
         "meaning": "The usual day-to-day change. Also used when the numbers are too small to read anything into "
                    "(under 20, or fewer than 10 apart)."},
        {"level": "info", "name": "Slight rise / Slight drop", "range": "10% to 25% up or down",
         "meaning": "A small change: keep an eye on it."},
        {"level": "watch", "name": "Caution", "range": "25% to 50% up",
         "meaning": "Clearly above the usual level: look into it today."},
        {"level": "high", "name": "Danger", "range": "50% or more up, or new this week (20 or more)",
         "meaning": "Extreme: investigate now — a new campaign, newly affected hosts, or a network reported for the first time."},
        {"level": "good", "name": "Clear drop", "range": "25% to 50% down",
         "meaning": "Clearly below the usual level: often clean-up working."},
        {"level": "watch", "name": "Unusual drop / Went quiet", "range": "50% or more down, or none today (after 10 or more a day)",
         "meaning": "Check before reading it as good news: a takedown, a sinkhole change or a report that did not arrive."},
    ]

    def assess(today, vals, unit="devices"):
        seen = [v for v in vals if v is not None]
        if len(seen) < 3:
            return None
        a = sum(seen) / len(seen)
        r = lambda level, label, note: {"level": level, "label": label, "note": note, "avg": round(a, 1),
                                        "change": None if not a else round((today - a) / a, 4)}
        if a == 0:
            if not today:
                return r("normal", "None this week", "Not seen in the previous 7 days either.")
            return r("high" if today >= 20 else "watch", "New this week",
                     f"Not seen at all in the previous 7 days: find out what it is, which {unit} and where, before it spreads.")
        ch = (today - a) / a
        # cut, not rounded: 9.96 % shows as 9.9 % (Normal), never as "10.0 %", which would look like a slight change
        p = f"{int(abs(ch) * 100)}%" if abs(ch) >= .1 else f"{int(abs(ch) * 1000) / 10:.1f}%"
        sign = "+" if ch >= 0 else "-"
        if today == 0 and a >= 10:
            return r("watch", "Went quiet", "Seen every day this week but not today: a takedown, a sinkhole change or a report "
                                            "that did not arrive? Check before reading it as good news.")
        if abs(ch) >= .10 and (max(today, a) < 20 or abs(today - a) < 10):
            return r("normal", f"Normal {sign}{p} (small numbers)", f"Only {abs(today - a):,.0f} {unit} apart: too few to read "
                                                                   f"anything into, nothing to do.")
        if abs(ch) < .10:
            return r("normal", f"Normal {sign}{p}", "Nothing to do.")
        if ch > 0:
            if ch >= .5:
                return r("high", f"Danger +{p}", f"Investigate now: a new campaign, newly affected {unit} or a network "
                                                 f"reported for the first time.")
            if ch >= .25:
                return r("watch", f"Caution +{p}", "Look into it today.")
            return r("info", f"Slight rise +{p}", "Keep an eye on it.")
        if ch <= -.5:
            return r("watch", f"Unusual drop -{p}", "Clean-up working, or a report that did not arrive? Check before reading "
                                                    "it as good news.")
        if ch <= -.25:
            return r("good", f"Clear drop -{p}", "Often clean-up working.")
        return r("info", f"Slight drop -{p}", "Keep an eye on it.")

    def trend_findings(platform, d, b):
        """Plain sentences comparing the day with its 7-day baseline (only when there are at least 3 past days)."""
        if b["available"] < 3:
            if b.get("building"):
                pr = b.get("progress") or {}
                return [f"The 7-day comparison is being prepared ({pr.get('done', 0)} of {pr.get('total', 7)} days); "
                        f"it appears here by itself."]
            return [f"Only {b['available']} of the 7 previous days had reports: too few for a 7-day comparison."]
        out, k, A = [], d["kpis"], b["assess"]
        unit = "devices" if platform == "comms" else "hosts"
        figs = ([("devices", "affected devices"), ("multi_infected", "devices with several infections")] if platform == "comms" else
                [("hosts", "internet-facing hosts"), ("vulnerable_hosts", "hosts with an issue"), ("kev_hosts", "hosts with actively exploited vulnerabilities")])
        BAND = {"normal": "a normal day-to-day change", "info": "a slight change", "good": "a clear drop",
                "watch": "a change that needs attention", "high": "an extreme change"}

        def compare(today, g, u=""):
            """'1,700 hosts today; over the last 7 days the average was 1,850 a day, so today is 8% lower'."""
            n = f"{today:,}{' ' + u if u else ''}"
            if g["change"] is None:
                return f"{n} today; none at all in the previous 7 days"
            ch = g["change"]
            # cut like the grade's label (9.96 % reads 9.9 %, matching "Normal +9.9%")
            pc = f"{int(abs(ch) * 100)}%" if abs(ch) >= .1 else f"{int(abs(ch) * 1000) / 10:.1f}%"
            how = "about the same" if abs(ch) < .005 else f"{pc} {'higher' if ch > 0 else 'lower'}"
            return f"{n} today; over the last 7 days the average was {g['avg']:,.0f} a day, so today is {how}"

        for key, label in figs:
            g = A["kpis"].get(key)
            if not g:
                continue
            Label = label[0].upper() + label[1:]
            what = g["note"][0].lower() + g["note"][1:].rstrip(".")
            out.append(f"{Label}: {compare(k[key], g)}. That is {BAND[g['level']]} ({g['label']}): {what}.")
        rows = d.get("infections") if platform == "comms" else d.get("issues")
        name = lambda r: (r.get("title") or r["value"]) if platform == "comms" else r["value"]
        order = {"high": 0, "watch": 1}
        flagged = sorted([(r, A["items"][r["value"]]) for r in rows or [] if (A["items"].get(r["value"]) or {}).get("level") in order],
                         key=lambda x: (order[x[1]["level"]], -x[0]["hosts"]))
        for r, g in flagged[:3]:
            out.append(f"{name(r)}: {compare(r['hosts'], g, unit)}. That is {BAND[g['level']]} ({g['label']}): "
                       f"{g['note'][0].lower() + g['note'][1:]}")
        if not flagged:
            out.append(f"None of the top {'infections' if platform == 'comms' else 'issues'} changed by more than usual compared "
                       f"with the last 7 days (no Caution or Danger).")
        return out

    def with_baseline(platform, d, args, d_mask, wait=False):
        if args.get("code"):
            # past days keep only the fields the portal counts, not the indicators a combination is made of: no
            # 7-day comparison for a combination code (the page and the PDF say "no baseline for this selection")
            d["baseline"] = None
            return d
        b = baseline(platform, d, args, d_mask, wait=wait)
        d["baseline"] = b
        extra = trend_findings(platform, d, b)
        if extra:
            d["findings"] = d["findings"][:1] + extra + d["findings"][1:]
        return d

    def prewarm():
        """Background: the whole-constituency baseline of both platforms, so the portal opens with it ready."""
        time.sleep(90)                                     # let the replay day load first
        while True:
            for platform in ("comms", "services"):
                try:
                    with app.test_request_context("/"):
                        d = (comms if platform == "comms" else services)({}, False, combos_n=1)
                        if d.get("day"):
                            baseline(platform, d, {}, False, wait=True)
                except Exception:                         # noqa: BLE001
                    import logging
                    logging.getLogger(__name__).exception("Executive baseline pre-build failed")
            time.sleep(1800)

    # ------------------------------------------------------------------ routes
    @app.route("/management")
    def management_page():
        if not allowed():
            return render_template("denied.html", message="The management portal is for the management role."), 403
        return render_template("management.html")

    @app.route("/api/mgmt/<platform>")
    def mgmt_data(platform):
        if not allowed():
            return deny()
        if platform not in ("comms", "services"):
            return jsonify(error="unknown platform"), 400
        t = time.time()
        out = (comms if platform == "comms" else services)(request.args, demo())
        with_baseline(platform, out, request.args, demo())
        out.update(scope=ctx["scope_text"](), country=ctx["country"](), demo=demo(), took=round(time.time() - t, 2))
        return jsonify(out)

    @app.route("/api/mgmt/explain")
    def mgmt_explain():
        """What one infection or issue is (Malpedia / threat actor / definition; CVE: CISA KEV, EPSS, CVE.org, NVD)."""
        if not allowed():
            return deny()
        kind, name = request.args.get("kind"), (request.args.get("name") or "").strip()
        if kind not in ("infection", "issue") or not name or len(name) > 100:
            return jsonify(error="kind (infection or issue) and name expected"), 400
        try:
            if kind == "issue":
                return jsonify(ctx["issues_resolve"]([name]).get(name) or {})
            return jsonify(ctx["mp_resolve"](name)[0])
        except ValueError as exc:
            return jsonify(error=public_error(exc)), 400
        except RuntimeError as exc:
            return jsonify(found=False, pending=True,
                           reason=f"Not checked yet: {public_error(exc, 'the look-up service did not answer')}. Try again in a minute."), 200

    @app.route("/api/mgmt/report")
    def mgmt_report():
        """An executive PDF of the dashboard as filtered: aggregated figures, findings, charts and explanations."""
        if not allowed():
            return deny()
        platform = request.args.get("platform", "comms")
        if platform not in ("comms", "services"):
            return jsonify(error="unknown platform"), 400
        d = (comms if platform == "comms" else services)(request.args, demo(), combos_n=None)    # every combination, for the CSVs
        with_baseline(platform, d, request.args, demo(), wait=True)          # the report always has its 7-day trend
        k = d["kpis"]
        combo_names = {"icombo": "Infections on the same device" if platform == "comms" else "Issues on the same host",
                       "rcombo": "Reports seeing the same device", "scombo": "Services on the same host"}
        fl = [f"{combo_names.get(n, n)}: {v}" for n, v in d["filters"].items() if v]
        sel = ", ".join(fl) if fl else "Everything in the constituency"
        pct = lambda r: f"{r['share']:.1%}"
        if platform == "comms":
            kpis = [(f"{k['devices']:,}", "affected devices"), (f"{k['events']:,}", "events"), (f"{k['infections']:,}", "infections / categories"),
                    (f"{k['multi_infected']:,}", "devices with several infections"), (f"{k['cross_report']:,}", "devices in several reports"),
                    (f"{k['regions']:,}", "regions affected"), (f"{k['networks']:,}", "networks affected"),
                    (f"{k['critical']:,}", "critical events"), (f"{k['share_of_day']:.1%}", "of the day's events")]
            names = [r["value"] for r in d["infections"][:15]]
            enr = {}
            for n in names:
                try:
                    enr[n] = ctx["mp_resolve"](n)[0]
                except (ValueError, RuntimeError):
                    pass
            stats = {r["value"]: f"{r['hosts']:,} devices, {r['count']:,} events ({r['share']:.1%})" for r in d["infections"][:15]}
            bds = [("Infections / categories", ["Infection / category", "Devices", "Events", "Share"],
                    [[(r["title"] + f" ({r['value']})") if r["title"] else r["value"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["infections"]]),
                   ("Regions", ["Region", "Devices", "Events", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["regions"]]),
                   ("Sectors", ["Sector", "Devices", "Events", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["sectors"]]),
                   ("Networks", ["Network", "Devices", "Events", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["networks"]]),
                   ("Reports", ["Report", "Devices", "Events", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["reports"]]),
                   ("Devices seen in two reports", ["Reports", "Devices"], [[r["label"], f"{r['count']:,}"] for r in d["report_pairs"]]),
                   ("Cross-report analysis", ["Seen in", "Devices"], [[r["label"], f"{r['count']:,}"] for r in d["cross"]["by_count"]]),
                   ("Devices with several infections", ["Infections per device", "Devices"], [[r["label"], f"{r['count']:,}"] for r in d["multi"]["by_count"]]),
                   ("Top findings: infections on the same device", ["Infections on the same device", "Devices"], [[r["label"], f"{r['count']:,}"] for r in d["multi"]["combos"][:25]]),
                   ("Repeat behaviour (beaconing)", ["Measure", "Value"], [["devices seen three times or more", f"{d['beacon']['repeating']:,}"],
                     ["of which at a regular rhythm (automated check-ins)", f"{d['beacon']['regular']:,}"], ["typical repeat interval", d["beacon"]["typical"] or "–"]]),
                   ("C2 / sinkhole domains contacted", ["Domain", "Devices", "Events"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}"] for r in d["c2"]["top"]]),
                   ("Attack types", ["Attack type", "Events", "Share"], [[r["label"], f"{r['count']:,}", pct(r)] for r in d["attack"]]),
                   ("Where infected devices connect to", ["Country", "Events", "Share"], [[r["label"], f"{r['count']:,}", pct(r)] for r in d["destinations"]])]
            charts = [("Infections / categories", [{**r, "label": r["title"] or r["value"]} for r in d["infections"]]), ("Regions", d["regions"]),
                      ("Sectors", d["sectors"]), ("Attack types", d["attack"])]
            et, plat = "Infections and categories explained", "Network communications"
        else:
            kpis = [(f"{k['hosts']:,}", "internet-facing hosts"), (f"{k['vulnerable_hosts']:,}", "hosts with an issue"), (f"{k['kev_hosts']:,}", "hosts with actively exploited CVEs"),
                    (f"{k['kev_cves']:,}", "actively exploited CVEs"), (f"{k['critical_cves']:,}", "critical CVEs (CVSS 9+)"), (f"{k['multi_issue']:,}", "hosts with several issues"),
                    (f"{k['cross_report']:,}", "hosts in several reports"), (f"{k['services']:,}", "exposed services"), (f"{k['regions']:,}", "regions"),
                    (f"{k['records']:,}", "records")]
            names = [r["value"] for r in sorted(d["issues"], key=lambda r: (not r["exploited"], -(r["cvss"] or 0)))[:20]]
            enr = ctx["issues_resolve"](names)
            stats = {r["value"]: f"{r['hosts']:,} hosts, {r['count']:,} records" for r in d["issues"]}
            bds = [("Issues", ["Issue", "Hosts", "Actively exploited", "CVSS", "Share"],
                    [[r["value"] + (f": {r['title']}" if r["title"] else ""), f"{r['hosts']:,}", "YES" if r["exploited"] else "", r["cvss"] or "", pct(r)] for r in d["issues"]]),
                   ("Exposed services", ["Service", "Hosts", "Records", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["services"]]),
                   ("Hosts with several issues", ["Issues per host", "Hosts"], [[r["label"], f"{r['count']:,}"] for r in d["multi"]["by_count"]]),
                   ("Top findings: issues on the same host", ["Issues on the same host", "Hosts"], [[r["label"], f"{r['count']:,}"] for r in d["multi"]["combos"][:25]]),
                   ("Cross-report analysis", ["Seen in", "Hosts"], [[r["label"], f"{r['count']:,}"] for r in d["cross"]["by_count"]]),
                   ("Services found together on the same host", ["Services", "Hosts"], [[r["label"], f"{r['count']:,}"] for r in d["cross"]["pairs"]]),
                   ("Devices", ["Vendor · type", "Hosts"], [[r["label"], f"{r['count']:,}"] for r in d["devices"]]),
                   ("Regions", ["Region", "Hosts", "Records", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["regions"]]),
                   ("Sectors (network type)", ["Sector", "Hosts", "Records", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["sectors"]]),
                   ("Networks", ["Network", "Hosts", "Records", "Share"], [[r["label"], f"{r['hosts']:,}", f"{r['count']:,}", pct(r)] for r in d["networks"]]),
                   ("Industries (Shadowserver)", ["Industry", "Records", "Share"], [[r["label"], f"{r['count']:,}", pct(r)] for r in d["industries"]]),
                   ("Report families", ["Family", "Records", "Share"], [[r["label"], f"{r['count']:,}", pct(r)] for r in d["families"]])]
            charts = [("Exposed services", d["services"]), ("Regions", d["regions"]), ("Sectors", d["sectors"]),
                      ("Issues", [{**r, "label": r["value"]} for r in d["issues"]])]
            et, plat = "Issues explained", "Publicly accessible / vulnerable services"
        who = (ctx["user"]() or {}).get("user", "")
        spec = {"platform_label": plat, "title": f"Executive report · {plat}", "selection": sel, "day": d["day"], "generated_by": who,
                "scope": ctx["scope_text"](), "demo": demo(), "executive": True,
                "intro": "Aggregated figures for the constituency, as filtered in the management portal. No individual addresses are included.",
                "summary_points": d["findings"], "kpis": kpis, "hours": d["hours"], "peak_hour": d["peak_hour"],
                "enrichment": enr, "enrichment_stats": stats, "enrichment_title": et,
                "enrichment_note": "Infections are explained from Malpedia (malware families and threat actors) and the Looking Glass definitions; "
                                   "vulnerabilities from CISA's Known Exploited Vulnerabilities catalog, EPSS, CVE.org and NVD.",
                "breakdowns": [b for b in bds if b[2]], "charts": [c for c in charts if c[1]], "glossary": [],
                "sources": ctx["sources_text"]}
        # drawn like the dashboard (executive_pdf.py); the plain report layout only if that fails
        try:
            import json as _json, os as _os
            import executive_pdf
            shapes = None
            nomap = request.args.get("map") == "0"     # chosen on the page when the reports' regions are not on this map
            sp = _os.path.join(app.static_folder, "data", "adm1", f"{ctx['country']()}.json")
            if not nomap and _os.path.exists(sp):
                with open(sp, encoding="utf-8") as f:
                    shapes = _json.load(f)
            pdf = executive_pdf.build(d, enr, {"platform_label": plat, "scope": ctx["scope_text"](), "selection": sel, "generated_by": who,
                                               "demo": demo(), "shapes": shapes, "nomap": nomap, "stats": stats})
        except Exception as exc:                       # never leave the manager without a report
            app.logger.warning("Executive PDF (dashboard design) failed, plain layout used: %s", exc)
            pdf = ctx["build_pdf"](spec)
        AUTH["audit"].add("report_pdf", user=who, target=f"management:{platform}", detail=sel[:120])
        base = "looking-glass_executive_" + re.sub(r"[^\w.-]+", "-", f"{d['day']}_{plat}_{sel}")[:110].strip("-")
        if request.args.get("format") == "pdf":
            return Response(pdf, mimetype="application/pdf",
                            headers={"Content-Disposition": f'attachment; filename="{base}.pdf"', "Cache-Control": "no-store"})
        import csvsafe as _csv, io as _io, zipfile   # every cell spreadsheet-safe (no formulas)
        unit = "Devices" if platform == "comms" else "Hosts"
        def table(rows, what, total):
            buf = _io.StringIO(); w = _csv.writer(buf)
            w.writerow([what, f"Number of {what.split()[0].lower()}", f"{unit} with exactly this combination", f"Share of the {unit.lower()} concerned"])
            for r in rows:
                lbl = r["label"]
                w.writerow([lbl, len(lbl.split(" + ")), r["count"], f"{100 * r['share']:.1f}%"])
            return "\ufeff" + buf.getvalue()
        files = ({"infection-combinations": table(d["multi"]["combos"], "Infections on the same device", d["multi"]["devices"]),
                  "report-combinations": table(d["cross"]["combos"], "Reports seeing the same device", d["cross"]["devices"])} if platform == "comms" else
                 {"issue-combinations": table(d["multi"]["combos"], "Issues on the same host", d["multi"]["hosts"]),
                  "service-combinations": table(d["cross"]["combos"], "Services (reports) on the same host", d["cross"]["hosts"])})
        # the 7-day baseline: every figure per day, the selected day last
        b = d.get("baseline") or {}
        if b.get("days"):
            buf = _io.StringIO(); w = _csv.writer(buf)
            keys = list(b["kpis"])
            w.writerow(["Day"] + [k.replace("_", " ") for k in keys])
            for i, day_ in enumerate(b["days"]):
                w.writerow([day_] + ["" if b["kpis"][k][i] is None else b["kpis"][k][i] for k in keys])
            w.writerow([d["day"] + " (report day)"] + [d["kpis"].get(k, "") for k in keys])
            w.writerow([])
            w.writerow(["Infection / category" if platform == "comms" else "Issue"] + b["days"] + [d["day"]])
            for r in (d["infections"] if platform == "comms" else d["issues"]):
                lbl = r.get("title") or r["value"]
                w.writerow([lbl] +["" if v is None else v for v in b["items"].get(r["value"], [])] + [r["hosts"]])
            files["seven-day-trend"] = "﻿" + buf.getvalue()
        z = _io.BytesIO()
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{base}.pdf", pdf)
            for name, text in files.items():
                zf.writestr(f"{base}_{name}.csv", text)
        return Response(z.getvalue(), mimetype="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{base}.zip"', "Cache-Control": "no-store"})

    # internals for the checks (tests/check_past_days.py): not reachable over HTTP
    return {"prewarm": prewarm, "internals": {"comms": comms, "services": services, "summarise": summarise,
                                              "compact": lambda platform, full: PastDay(full.start, [
                                                  REC[platform](tuple(sys.intern(v) if type(v) is str else v
                                                                      for v in (e.get(f) for f in PAST_FIELDS[platform])))
                                                  for e in full.events]),
                                              "past": past, "past_day": past_day, "sig_of": sig_of}}
