#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Many Executive 7-day baselines built at the same time must all succeed (no "Executive baseline build failed").

Past days come from memory, so several baselines can be built and saved at once. This runs in a temporary copy of the
project (the service's own data files are never written): it loads the past days once, then asks for many new
selections at the same moment from several threads, and checks that every one gets its full baseline and that nothing
was logged as failed. Read-only against the database. Usage: tests/check_baseline_concurrency.py
"""
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(HERE)
tmp = tempfile.mkdtemp(prefix="lg_blcheck_")
failed_logs = []


class Catch(logging.Handler):
    def emit(self, record):
        if "baseline build failed" in record.getMessage() or record.exc_info:
            failed_logs.append(record.getMessage())


try:
    shutil.copytree(SRC, os.path.join(tmp, "p"), ignore=shutil.ignore_patterns(".venv", "__pycache__", "backups", "*.log", "mgmt_baseline.json"))
    P = os.path.join(tmp, "p")
    sys.path.insert(0, P); os.chdir(P)
    os.environ["TRUST_PROXY"] = "0"     # called in-process, not through a reverse proxy (proxy_guard.py)
    import app as tm  # noqa: E402
    logging.getLogger().addHandler(Catch())
    tm.app.logger.addHandler(Catch())
    key = open(os.path.join(tm.BASE_DIR, "data", "automation.key")).read().strip()

    def get(u):
        c = tm.app.test_client(); c.environ_base["HTTP_X_LG_AUTOMATION"] = key
        return c.get(u).get_json()

    def wait_full(u, limit=900):
        t0 = time.time()
        while time.time() - t0 < limit:
            b = get(u)["baseline"]
            if not b["building"] and not b.get("progress"):
                return b, time.time() - t0
            time.sleep(1)
        return None, limit

    t = time.time()
    b0, _ = wait_full("/api/mgmt/comms"); s0, _ = wait_full("/api/mgmt/services")
    print(f"past days loaded: communications {b0['available']} days, services {s0['available']} days ({time.time() - t:.0f}s)")
    d, s = get("/api/mgmt/comms"), get("/api/mgmt/services")
    fac = lambda x, k: [(o["value"] if isinstance(o, dict) else o) for o in x["facets"].get(k, [])]
    sels = ([("comms", [("icombo", r["label"])]) for r in d["multi"]["combos"][:6]]
            + [("comms", [("region", v)]) for v in fac(d, "region")[:4]]
            + [("comms", [("network", v)]) for v in fac(d, "network")[:3]]
            + [("services", [("icombo", r["label"])]) for r in s["multi"]["combos"][:5]]
            + [("services", [("service", v)]) for v in fac(s, "service")[:4]]
            + [("services", [("region", v)]) for v in fac(s, "region")[:2]])
    urls = [f"/api/mgmt/{p}?" + urllib.parse.urlencode(q) for p, q in sels]
    results = {}

    def run(u):
        results[u] = wait_full(u)

    t = time.time()
    threads = [threading.Thread(target=run, args=(u,)) for u in urls]
    for th in threads: th.start()
    for th in threads: th.join()
    complete = [u for u, (b, _) in results.items() if b and b["available"] == (b0["available"] if "/comms" in u else s0["available"])]
    slow = max(dt for _, dt in results.values())
    print(f"{len(urls)} new selections at once: {len(complete)} complete baselines, slowest {slow:.1f}s, all in {time.time() - t:.1f}s")
    print(f"failures logged: {len(failed_logs)}" + (f" — {failed_logs[:2]}" if failed_logs else ""))
    ok = len(complete) == len(urls) and not failed_logs
    print("ALL PASSED" if ok else "FAILED")
    sys.exit(0 if ok else 1)
finally:
    os.chdir("/")
    shutil.rmtree(tmp, ignore_errors=True)
