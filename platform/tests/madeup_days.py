# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Made-up replay days for in-process tests (nothing here is real, nothing is read from or written to a database).

install(A, comms=[...], svc=[...]) puts one made-up day of each platform into the app's day stores in memory, with
the two report registries holding the made-up reports only. Each record is a plain dict of raw report fields; the
platforms' own normalisers (sources.normalise, services.normalise_service) turn them into records, as the loaders do.
Addresses are documentation addresses (192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32), networks private AS numbers,
names end in .example. Returns {"start", "comms", "svc"} (the records as stored)."""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DIAG = {"checks": [], "compatible": True, "layout": "standard", "missing": [], "missing_fields": [], "required_ok": 5,
        "required_total": 5, "warnings": []}


def comms_source(name, label, klass="Botnet / infection"):
    return {"name": name, "label": label, "class": klass, "layout": "standard", "filename_index": True}


def svc_source(name, label, family="Accessible"):
    return {"name": name, "label": label, "family": family, "filename_index": True}


def install(A, comms=(), svc=()):
    """comms: [(source entry, raw doc)], svc: [(source entry, raw doc)]; every record gets a time in the replay day
    before the replay position."""
    import sources
    import services as SV
    rn = A.replay_now()
    start = A.day_start(rn)
    span = max(60.0, (rn - start).total_seconds() - 5)

    def times(n):
        return [start + timedelta(seconds=span * (i + 1) / (n + 1)) for i in range(n)]

    events = []
    for i, ((src, doc), t) in enumerate(zip(comms, times(len(comms)))):
        doc = dict(doc, timestamp=t, extracted_date=t, _id=f"mc{i}",
                   filename=f"{start:%Y-%m-%d}-{src['name']}-made-up-asn.csv")
        n = sources.normalise(doc, src)
        n["id"] = f"{src['name']}:mc{i}"
        n["_t"] = t.timestamp()
        n["extracted_date"] = A.iso(t)
        for f, v in list(n.items()):
            if hasattr(v, "isoformat"):
                n[f] = A.iso(v)
        n["src_coords"], n["dst_coords"] = [-0.19, 5.6], [-77.49, 39.04]
        n["src_ref"] = A.host_refs.ref(n["src_ip"])
        n["request"] = A._request_path(n["http_url"]) if n.get("http_url") else ""
        events.append(n)
    day = A.Day(start, events)
    csrc = {s["name"]: s for s, _ in comms}
    day.per_source = {k: sum(1 for e in events if e["source"] == k) for k in csrc}
    day.arrived, day.sig = {}, None
    day.by_src = {k: {"raw": day.per_source[k], "asn": {}, "blocks": {}, "rows": [e for e in events if e["source"] == k],
                      "last": None} for k in csrc}
    day.gen, day.settings_version, day.raw_total = A.store.gen, A.settings.version, len(events)
    A.store.get = lambda dt=None: day
    A.store.days = {start: day}

    sevents = []
    for i, ((src, doc), t) in enumerate(zip(svc, times(len(svc)))):
        doc = dict(doc, timestamp=t, extracted_date=t, _id=f"ms{i}",
                   filename=f"{start:%Y-%m-%d}-{src['name']}-made-up-asn.csv")
        n = SV.normalise_service(doc, src)
        n["id"] = f"{src['name']}:ms{i}"
        n["_t"] = t.timestamp()
        n["extracted_date"] = SV._s(t)
        n["ip_ref"] = A.host_refs.ref(n["ip"])
        sevents.append(n)
    sday = SV.Day(start, sevents)
    ssrc = {s["name"]: s for s, _ in svc}
    sday.per_source = {k: sum(1 for e in sevents if e["report"] == k) for k in ssrc}
    sday.arrived, sday.sig = {}, None
    sday.by_src = {k: {"raw": sday.per_source[k], "asn": {}, "region": {}, "blocks": {},
                       "rows": [e for e in sevents if e["report"] == k], "last": None} for k in ssrc}
    sday.gen, sday.settings_version, sday.raw_total = getattr(A.svc["store"], "gen", 0), A.settings.version, len(sevents)
    A.svc["store"].get = lambda dt=None: sday
    A.svc["store"].days = {start: sday}

    centries = [dict(s, diagnostic=DIAG, latest="") for s in csrc.values()]
    sentries = [dict(s, diagnostic=dict(DIAG, layout="single-host"), layout="single-host", fields=[], **{"class": s["family"]})
                for s in ssrc.values()]
    for reg_, entries in ((A.registry, centries), (A.svc["registry"], sentries)):
        reg_.get = lambda *a, _e=entries, **k: list(_e)
        reg_.items, reg_.unsupported, reg_.names = list(entries), [], [e["name"] for e in entries]
    return {"start": start, "comms": events, "svc": sevents}
