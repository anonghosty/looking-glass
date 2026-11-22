#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A constituency change is never overtaken by a day load already running (external review, 2026-11-12): the load that
began before the change is not stored; it loads again, so the day kept is the new constituency's. Both platforms'
stores. No database: the loads are stand-ins.  Run: .venv/bin/python tests/check_scope_reload.py"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


def race(store, label, day_cls):
    calls = []

    def fake_load(start, old=None):          # old: the copy in memory (unchanged reports are taken over from it)
        n = len(calls)
        calls.append(n)
        if n == 0:
            time.sleep(0.6)                      # the old constituency's load, still running when Settings change
        d = day_cls(start, [])
        d.marker = n
        d.per_source, d.arrived, d.sig = {}, {}, None
        return d
    saved = (store.days, store.loading, store.changes, store.__dict__.get("_load"))
    store.days, store.loading, store.changes = {}, {}, {}
    store._load = fake_load
    try:
        now = A.utcnow()
        t = threading.Thread(target=lambda: store.get(now))
        t.start()
        time.sleep(0.15)
        store.reset()                            # Settings saved: a new constituency
        t.join(10)
        kept = [d for d in store.days.values()]
        ok(f"{label}: the day kept is the one loaded after the change, not the load that was running",
           len(calls) == 2 and kept and kept[0].marker == 1, f"loads {calls}, kept {[d.marker for d in kept]}")
    finally:
        store.days, store.loading, store.changes = saved[0], saved[1], saved[2]
        if saved[3] is None:
            del store._load
        else:
            store._load = saved[3]


race(A.store, "map platform", A.Day)
import services  # noqa: E402
race(A.svc["store"], "services platform", services.Day if hasattr(services, "Day") else A.Day)


def partial_same_as_full():
    """The map platform's partial reload (review of d82a436): only the reports whose count changed are read again,
    and the day is exactly the one a full load gives."""
    from datetime import datetime, timezone
    start = datetime(2026, 11, 14, tzinfo=timezone.utc)
    counts = {"event4_sinkhole": 3, "event4_sinkhole_http": 2, "event4_honeypot_brute_force": 2}
    read = []
    srcs = [{"name": n, "label": n, "class": "c", "filename_index": True} for n in counts]

    def fetch(src, a, b):
        read.append(src["name"])
        rows = []
        for i in range(counts[src["name"]]):
            rows.append({"source": src["name"], "_t": start.timestamp() + i * 60 + len(src["name"]), "id": f"{src['name']}:{i}",
                         "src_ip": f"192.0.2.{i}", "dst_ip": "", "src_asn": 64512 + i, "dst_asn": None, "src_geo": "GH", "dst_geo": "",
                         "src_region": "ACCRA", "dst_region": "", "src_city": "ACCRA", "dst_city": "", "http_url": "", "infection": "x"})
        return rows, None
    saved = (A.registry.get, A.store._fetch_collection, A.store.signature, A.geocoder.lookup, A.geocoder.flush, A._STAMPS.of)
    A.registry.get = lambda: srcs
    A.store._fetch_collection = fetch
    A.store.signature = lambda s: dict(counts)
    A.geocoder.lookup = lambda *p: None
    A.geocoder.flush = lambda: None
    A._STAMPS.of = lambda days: None
    try:
        d0 = A.store._load(start)
        read.clear(); counts["event4_sinkhole_http"] = 4
        d1 = A.store._load(start, old=d0)
        ok("map platform: one report grew, only it is read again", read == ["event4_sinkhole_http"], str(read))
        full = A.store._load(start)
        key = lambda d: [(e["source"], e["_t"], e["src_ip"]) for e in d.events]  # noqa: E731
        ok("map platform: the partial reload is exactly the full one (rows, order, per report, totals, networks, version)",
           key(d1) == key(full) and d1.per_source == full.per_source and d1.raw_total == full.raw_total
           and d1.asn_raw == full.asn_raw and d1.version == full.version and d1.sig == full.sig)
        ok("map platform: …and a new copy, with a new cache key", A.day_key(d1) != A.day_key(d0))
    finally:
        (A.registry.get, A.store._fetch_collection, A.store.signature, A.geocoder.lookup, A.geocoder.flush, A._STAMPS.of) = saved


partial_same_as_full()
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
