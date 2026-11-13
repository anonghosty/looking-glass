#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The Executive 7-day baseline from compact past days gives exactly what the full days give. Read-only.

management.py keeps each past day in a compact form (only the fields the Executive figures read) so a new filter's
baseline does not reload 7 days from MongoDB. This loads each of the 7 days before the replay day once, on both
platforms, and works out the complete Executive answer twice, from the full day and from its compact copy, for a set
of selections (no filter, single filters, combinations, demo mode). Every answer must be identical.

Runs in a temporary copy of the project, so the service's own data files are never written.
Usage: tests/check_past_days.py [days]   (default 7)
"""
import os
import shutil
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import needs_db  # noqa: E402
needs_db.require()   # no reachable MongoDB (a fresh clone, CI): skipped, not crashed
import tempfile
import time
from datetime import timedelta

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 7
tmp = tempfile.mkdtemp(prefix="lg_pastcheck_")
try:
    shutil.copytree(SRC, os.path.join(tmp, "p"), ignore=shutil.ignore_patterns(".venv", "__pycache__", "backups", "*.log", "mgmt_baseline.json"))
    P = os.path.join(tmp, "p")
    sys.path.insert(0, P); os.chdir(P)
    import app as tm  # noqa: E402
    from werkzeug.datastructures import MultiDict
    M = tm._mgmt["internals"]
    fails, checks = [], 0
    rn = tm.replay_now()
    with tm.app.test_request_context("/"):
        cur = {"comms": M["comms"]({}, False), "services": M["services"]({}, False)}
    start = tm.day_start(rn)
    for plat, store in (("comms", tm.store), ("services", tm.svc["store"])):
        d0 = cur[plat]
        fv = lambda k, i=0: (lambda x: x["value"] if isinstance(x, dict) else x)(d0["facets"][k][min(i, len(d0["facets"][k]) - 1)]) if d0["facets"].get(k) else ""
        if plat == "comms":
            sels = [{}, {"infection": fv("infection")}, {"region": fv("region")}, {"network": fv("network")}, {"sector": fv("sector")},
                    {"report": fv("report"), "severity": fv("severity")}, {"attack": fv("attack")}]
            sels += [{"icombo": r["label"]} for r in d0["multi"]["combos"][:2]] + [{"rcombo": r["label"]} for r in d0["cross"]["combos"][:1]]
        else:
            sels = [{}, {"family": fv("family")}, {"service": fv("service")}, {"issue": fv("issue")}, {"region": fv("region")},
                    {"network": fv("network")}, {"sector": fv("sector")}]
            sels += [{"icombo": r["label"]} for r in d0["multi"]["combos"][:2]] + [{"scombo": r["label"]} for r in d0["cross"]["combos"][:1]]
        fn = M[plat]
        for i in range(DAYS, 0, -1):
            s = start - timedelta(days=i)
            t = time.time()
            full = store._load(s)
            if not full.events:
                print(f"  {plat} {s.date()}: no records, skipped"); continue
            comp = M["compact"](plat, full)
            with tm.app.test_request_context("/"):
                for sel in sels:
                    for demo in (False, True) if not sel else (False,):
                        checks += 1
                        a = fn(MultiDict(sel), demo, combos_n=1, day=full)
                        b = fn(MultiDict(sel), demo, combos_n=1, day=comp)
                        if a != b:
                            diff = [k for k in a if a.get(k) != b.get(k)]
                            fails.append(f"{plat} {s.date()} {sel} demo={demo}: {diff[:5]}")
            print(f"  {plat} {s.date()}: {len(full.events):,} records, {len(sels) + 1} selections compared ({time.time() - t:.0f}s)", flush=True)
            del full, comp
    print(f"\n{checks - len(fails)} of {checks} complete Executive answers identical (full day vs compact past day)")
    for f in fails[:10]:
        print("  DIFFERENT:", f)
    sys.exit(1 if fails else 0)
finally:
    os.chdir("/")
    shutil.rmtree(tmp, ignore_errors=True)
