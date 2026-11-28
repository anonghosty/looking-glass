# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Beacons on the analyst's map: the Beacon filter, the "Decoded beacons" figure and its Details list.

Each record's beacon label ("CLogin check-in, Android") comes from beacon_decode.field(), which caches per request line,
and is kept on the record as "_bc" so a loaded day is decoded once. Analysts and admins only: app.py leaves all of this
out for masked viewers (is_demo()).

label(e)          -> "" or "<format title>, <OS>"; a family seen but not decoded says what its value is, e.g.
                     "ttyunos API request (encrypted)" (beacon_decode.STATUS); state(e) -> its STATUS key
decoded(e)        -> True when the record carries a beacon that decoded
facet_rows(evs)   -> [{"value", "count"}] for the Beacon filter, most common first
counts(evs)       -> {"decoded_beacons": records, "beacon_devices": source hosts}
drill(evs, mt)    -> the Details list (app.py's /api/insight/drill, metric "beacons")
ready(day)        -> True once every record of a loaded day has its label; the first call starts labelling it in the
                     background (a decodable check-in takes ~14 ms, so a day with thousands of them is never labelled
                     inside a request: the options, figure and list wait until it is done)
"""
import threading
import time
import weakref
from collections import Counter

import beacon_decode

_done = weakref.WeakKeyDictionary()       # day -> True when every record is labelled
_busy = weakref.WeakKeyDictionary()       # day -> True while its labelling runs
_lock = threading.Lock()
_one_at_a_time = threading.Lock()         # one day labelled at a time, beside the requests


def _label_all(day):
    try:
        with _one_at_a_time:
            for i, e in enumerate(list(day.events)):
                label(e)
                if i % 200 == 199:
                    time.sleep(0.005)     # leave the requests their share
        with _lock:
            _done[day] = True
    finally:
        with _lock:
            _busy.pop(day, None)


def ready(day):
    with _lock:
        if day in _done:
            return True
        if day in _busy:
            return False
        _busy[day] = True
    threading.Thread(target=_label_all, args=(day,), name="beacon-labels", daemon=True).start()
    return False


def _read(e):
    got = e.get("_bc")
    if got is not None:
        return got
    out = ("", "")
    if e.get("http_url"):
        title = beacon_decode.field(e, "format")
        if title:
            st = beacon_decode.field(e, "state") or "unknown"
            fam = beacon_decode.field(e, "os_family")
            os_name = beacon_decode.OS_TITLE.get(fam, fam)
            out = (f"{title}, {os_name}" if os_name and st == "decoded" else title, st)
    try:
        e["_bc"] = out                    # (label, state), kept on the record: a loaded day is decoded once
    except TypeError:                     # a read-only mapping: no cache, the answer is the same
        pass
    return out


def label(e):
    return _read(e)[0]


def state(e):
    return _read(e)[1]


def decoded(e):
    return state(e) == "decoded"


def facet_rows(events, limit=300):
    c = Counter(lb for lb in map(label, events) if lb)
    return [{"value": v, "count": n} for v, n in c.most_common(limit)]


def counts(events):
    n, hosts = 0, set()
    for e in events:
        if decoded(e):
            n += 1
            if e.get("src_ip"):
                hosts.add(e["src_ip"])
    return {"decoded_beacons": n, "beacon_devices": len(hosts)}


def _when(t):
    import datetime
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%H:%M:%S") if t else ""


def drill(events, mt=lambda s: s):
    """Every beacon kind in the selection with its operators, versions, records, devices, the names Shadowserver filed
    it under and the C2 domains it called. Rows are clickable: their value is the Beacon filter's."""
    g = {}
    for e in events:
        lb, st = _read(e)
        if not lb:
            continue
        x = g.get(lb)
        if x is None:
            x = g[lb] = {"state": st, "events": 0, "hosts": set(), "ops": Counter(), "vers": Counter(), "inf": set(), "dom": set(),
                         "t0": e.get("_t"), "t1": e.get("_t")}
        x["events"] += 1
        if e.get("src_ip"):
            x["hosts"].add(e["src_ip"])
        op, ver = beacon_decode.field(e, "operator"), beacon_decode.field(e, "version")
        if op:
            x["ops"][op] += 1
        if ver:
            x["vers"][ver] += 1
        x["inf"].add(e.get("infection") or "unknown")
        if e.get("http_host"):
            x["dom"].add(mt(e["http_host"]))
        t = e.get("_t")
        if t is not None:
            x["t0"] = t if x["t0"] is None else min(x["t0"], t)
            x["t1"] = t if x["t1"] is None else max(x["t1"], t)
    rows = []
    for lb, x in sorted(g.items(), key=lambda kv: (kv[1]["state"] != "decoded", -kv[1]["events"])):
        rows.append({"value": lb, "beacon": lb, "decoded": "Yes" if x["state"] == "decoded" else "No",
                     "status": beacon_decode.status_text(x["state"], long=True)
                     + (". Ask to send it for decoding on the Findings page (Requests Looking Glass could not decode)"
                        if x["state"] in beacon_decode.SENDABLE_STATES else ""),
                     # every operator, version and C2 domain (the complete-list CSV is made from these rows), the most
                     # records first; no cut
                     "operators": [k for k, _ in x["ops"].most_common()], "versions": [k for k, _ in x["vers"].most_common()],
                     "events": x["events"], "hosts": len(x["hosts"]), "infections": sorted(x["inf"]),
                     "domains": sorted(x["dom"]), "first": _when(x["t0"]), "last": _when(x["t1"])})
    n_dec = sum(r["events"] for r in rows if r["decoded"] == "Yes")
    devs = len({e["src_ip"] for e in events if e.get("src_ip") and decoded(e)})
    return dict(
        title="Decoded beacons", row_kind="beacon",
        intro=(f"{n_dec:,} records in this selection carry a beacon Looking Glass decoded, from {devs:,} devices. "
               "Each row is one kind of beacon and the system it reports; open a row to show only those beacons on the map. "
               "Status says what each value is: decoded, encoded but not decodable (and why), or not encoded at all."),
        columns=[["beacon", "Beacon"], ["status", "Status"], ["operators", "Operators"], ["versions", "Versions"],
                 ["events", "Records"], ["hosts", "Devices"], ["infections", "Filed by Shadowserver as"],
                 ["domains", "C2 domains"], ["first", "First seen"], ["last", "Last seen"]],
        rows=rows, empty="No record in this selection carries a beacon Looking Glass can read.")
