# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Explore a match of "Looking Glass asks" (the user, 2026-11-15): exactly what Looking Glass stated, nothing around it.

A match says "the domain X was seen for avalanche-generic in Sinkhole HTTP and for qsnatch in Sinkhole DNS". Explore
used to open Intel gathered for the first name only, with X typed into the search box: the search narrows the lists by
text, but the lists are worked out over every record of the name, so the tags and patterns shown were not those of the
records that carry X. This module works out, for each name and report of the match, only the records that carry the
indicator: their other indicators, their tags and the exact sets that travel together, side by side.

Only a match Looking Glass is asking about right now can be explored (it must be in Intel.leads()), so this is never a
free search over the reports. The same rules as Intel gathered apply: no host is returned (devices are counted only),
values are masked exactly as there, a services value is shown only when MIN_HOSTS devices share it, and a combination
gets a lasting code only under small_codes' rule.

API (researchers and admins, the Definitions permission): GET /api/intel/match?kind=...&value=...
Installed from app.py: intel_match.install(app, INTEL, ctx).
"""
import collections
import threading
import time

from flask import jsonify, request

import intel as I
import small_codes


def _slot():
    return {"records": 0, "kinds": collections.defaultdict(collections.Counter), "combos": collections.Counter(),
            "vh": collections.defaultdict(collections.Counter), "ch": collections.defaultdict(collections.Counter)}


def _wanted(lead):
    """(section, name as the index keys it, report) for every place of the match."""
    return {(w["section"], w["name"] if w["section"] == "issues" else w["name"].lower(), w["report"]) for w in lead.get("where") or ()}


def _match_key(lead):
    return ("domain", lead["value"].lower()) if lead["kind"] == "domain" else (lead["kind"], lead["value"])


class MatchView:
    def __init__(self, intel, ctx):
        self.intel, self.ctx = intel, ctx
        self.lock = threading.Lock()
        self.cache = {}                              # (days key, kind, value) -> answer; a few, an hour at most

    def lead(self, kind, value):
        for x in self.intel.leads()["leads"]:
            if x["kind"] == kind and x["value"] == value:
                return x
        return None

    def _scan(self, lead):
        comms, svc = self.intel._days()
        want, mk = _wanted(lead), _match_key(lead)
        labels = self.ctx["labels"]()
        slots = collections.defaultdict(_slot)

        def add(place, vals, kinds_together, me, host):
            s = slots[place]
            s["records"] += 1
            together = []
            for kind, v in vals:
                s["kinds"][kind][v] += 1
                if host:
                    s["vh"][(kind, v)][host] += 1
                if kind in kinds_together:
                    together.append(v)
            items = tuple(sorted({v for v in together if I._norm(v) != me}))
            s["combos"][items] += 1
            if host:
                s["ch"][items][host] += 1

        if any(p[0] == "infections" for p in want):
            for d in comms:
                for e in d.events:
                    n = (e.get("infection") or "").lower()
                    rep = labels.get(e.get("source"), e.get("source") or "")
                    place = ("infections", n, rep)
                    if place not in want:
                        continue
                    fields, masked = I._comms(e)
                    vals = [(k, v) for k, f in fields for v in I._values(e, f, k, svc=masked)]
                    # the same test as the match index (Intel.index): the record carries the indicator itself
                    if not any(k not in I.NO_LEADS and I._match_key(k, v) == mk for k, v in vals):
                        continue
                    add(place, vals, I.COMMS_COMBO_KINDS, I._norm(n), e.get("src_ip") or "")
        if any(p[0] == "issues" for p in want):
            for d in svc:
                for e in d.events:
                    rep = e.get("report_label") or e.get("report") or ""
                    for issue in (e.get("issues") or []):
                        place = ("issues", issue, rep)
                        if place not in want:
                            continue
                        # services match on the certificate name as it is (the index does the same), shown masked
                        if not any(I._match_key(k, v) == mk for k, f in I.SVC_FIELDS if k in I.DOMAIN_KINDS
                                   for v in I._values(e, f, k, svc=True, raw=True)):
                            continue
                        vals = [(k, v) for k, f in I.SVC_FIELDS for v in I._values(e, f, k, svc=True)]
                        add(place, vals, I.COMBO_KINDS, I._norm(issue), e.get("ip") or "")
        return slots

    def _place(self, w, slot, value):
        section, name = w["section"], w["name"]
        full = small_codes.viewer_sees_hosts()
        me = I._norm(name)
        total = slot["records"] or 1
        kinds = []
        for k, c in slot["kinds"].items():
            c = collections.Counter({v: n for v, n in c.items() if I._norm(v) != me})
            # services, and decoded beacons for viewers who do not see hosts: shown only when MIN_HOSTS devices share it
            rare = I.held(section, k, c, slot, full)
            hidden = len(rare)
            if rare:
                c = collections.Counter({v: n for v, n in c.items() if v not in rare})
            if c or hidden:
                kinds.append({"kind": k, "distinct": len(c), "hidden": hidden,
                              "values": [{"value": v, "count": n, "share": round(n / total, 4), **I.hosts(slot["vh"].get((k, v)))}
                                         for v, n in c.most_common(I.TOP)]})
        kinds.sort(key=lambda k: (k["kind"] in I.NO_LEADS, -k["distinct"]))
        key_name = name if section == "issues" else name.lower()
        combos = [{"items": list(items), "count": n, "share": round(n / total, 4), **I.hosts(slot["ch"].get(items)),
                   "code": small_codes.code_for(I.combo_code(section, key_name, w["report"], items),
                                                len(slot["ch"].get(items) or ()), full)}
                  for items, n in slot["combos"].most_common(12)]
        self.intel._shown(section, key_name, w["report"], [c["items"] for c in combos])
        single = None
        if len(slot["combos"]) < 2:
            single, combos = (combos[0] if combos else None), []
        dev = len(set().union(*[set(h) for h in slot["ch"].values()]) - {""}) if slot["ch"] else 0
        return {"section": section, "name": name, "report": w["report"], "defined": w.get("defined", False),
                "records": slot["records"], "devices": dev, "indicators": kinds, "combinations": combos, "single": single,
                "combinations_total": len(slot["combos"]),
                "combo_of": "C2 domain, DNS lookup, TLS name, user agent and tags" if section == "infections" else "associated tags and CVEs"}

    def view(self, kind, value):
        lead = self.lead(kind, value)
        if lead is None:
            return None
        comms, svc = self.intel._days()
        days_key = (tuple((d.start, getattr(d, "serial", 0), len(d.events)) for d in comms)
                    + tuple((d.start, getattr(d, "serial", 0), len(d.events)) for d in svc))
        # only the scan is kept, never a finished answer: what a viewer may see (combination codes under small_codes'
        # rule) is worked out for each request, as Intel.gathered does (review of 6da6a80: an admin's answer reached
        # a researcher from the cache)
        ck = (days_key, kind, value)
        with self.lock:
            hit = self.cache.get(ck)
            slots = hit[1] if hit and time.time() - hit[0] < 3600 else None
        if slots is None:
            slots = self._scan(lead)
            with self.lock:
                if len(self.cache) > 64:
                    self.cache.clear()
                self.cache[ck] = (time.time(), slots)
        places = []
        for w in lead.get("where") or ():
            pk = (w["section"], w["name"] if w["section"] == "issues" else w["name"].lower(), w["report"])
            if pk in slots:
                places.append(self._place(w, slots[pk], value))
        out = {"kind": lead["kind"], "value": lead["value"], "verdict": lead.get("verdict", ""), "text": lead.get("text", ""),
               "priority": lead.get("priority"), "count": lead.get("count", 0), "days": self.intel.index()["days"],
               "places": places}
        return out


def install(app, intel, ctx):
    """ctx: allowed() -> may this request see the researchers' work; labels() as for intel.install."""
    mv = MatchView(intel, ctx)

    @app.route("/api/intel/match")
    def api_intel_match():
        if not ctx["allowed"]():
            return jsonify(error="Intel gathered is for researchers and admins."), 403
        kind = (request.args.get("kind") or "").strip()[:80]
        value = (request.args.get("value") or "").strip()[:300]
        if not kind or not value:
            return jsonify(error="kind= and value= are needed"), 400
        v = mv.view(kind, value)
        if v is None:
            return jsonify(error="Looking Glass is not asking about this match now (the days in memory changed)."), 404
        return jsonify(v)

    return mv
