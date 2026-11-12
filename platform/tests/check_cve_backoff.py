#!/usr/bin/env python3
"""CVE look-ups cannot hold the server up (external review, 2026-11-12): a failed CISA KEV download waits KEV_RETRY
before the next try (it used to try again, waiting up to 60 s, for every CVE), and a look-up with a time budget stops
fetching CVE.org records once it is spent. No network: the fetches are stand-ins.
Run: .venv/bin/python tests/check_cve_backoff.py"""
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cves  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


with tempfile.TemporaryDirectory() as d:
    c = cves.CveIntel(os.path.join(d, "cve_cache.json"))
    tries = []

    def unreachable(url, headers=None, timeout=30):
        tries.append(url)
        raise RuntimeError("CISA unreachable")
    c._get = unreachable
    for _ in range(5):
        c.kev()
    ok("CISA unreachable: one try, then no more until KEV_RETRY has passed (not one per CVE)", len(tries) == 1, f"{len(tries)} tries")
    c._kev_failed = time.time() - cves.KEV_RETRY - 1
    c.kev()
    ok("…and it tries again after KEV_RETRY", len(tries) == 2, f"{len(tries)} tries")

    fetched = []

    def slow_cveorg(cve, fetch=True):
        fetched.append(cve)
        time.sleep(0.4)
        return {"missing": True}
    c.cveorg = slow_cveorg
    c.epss = lambda ids: None
    c.card = lambda cve, fetch=False: {"id": cve}
    ids = [f"CVE-2026-{1000 + i}" for i in range(40)]
    t0 = time.monotonic()
    out = c.lookup_many(ids, budget=1.0)
    took = time.monotonic() - t0
    ok("a look-up with a 1 s budget stops fetching once it is spent (40 CVEs at 0.4 s each, 4 at a time)",
       took < 3 and len(fetched) < len(ids), f"{took:.1f} s, {len(fetched)} of {len(ids)} fetched")
    ok("…every CVE is still answered (from what is known)", len(out) == len(ids))
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
