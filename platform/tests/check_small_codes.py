#!/usr/bin/env python3
"""Intel gathered gives a researcher no lasting code for a pattern fewer than 5 hosts carry (small_codes.py; external
review 2026-11-11, option 2). The pattern itself and its device count are still shown, so a single odd device is still
noticed; the drill-down is the analyst's, who keeps every code. An analyst's code page (a selection the analyst handed
to a researcher) keeps every code, so the researcher can still answer with them.
Uses the services data in memory; prints no host.  Run: .venv/bin/python tests/check_small_codes.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
import app as A  # noqa: E402
import small_codes  # noqa: E402
from flask import g  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


MIN = small_codes.MIN_HOSTS
RESEARCHER, ANALYST = {"definitions", "networks"}, {"view", "unmasked", "export"}


def as_viewer(perms, fn, query=""):
    with A.app.test_request_context("/api/intel" + query):
        g.user = {"user": "lg-check", "role": "x", "perms": set(perms), "csrf": None, "automation": True}
        return fn()


def patterns(x):
    """(code, hosts) of every combination and across-report pattern in a for_hosts answer."""
    out = [(k["code"], k["hosts"]) for s in x["services"] for k in s["combinations"]]
    return out + [(c["code"], c["hosts"]) for c in x["cross"]]


print("The rule")
ok("below 5 hosts, a researcher gets no code", small_codes.code_for("LG-C-X", MIN - 1, False) is None)
ok("at 5 hosts, the code", small_codes.code_for("LG-C-X", MIN, False) == "LG-C-X")
ok("a viewer who sees hosts always gets it", small_codes.code_for("LG-C-X", 1, True) == "LG-C-X")

A.svc["store"].get(A.replay_now())
SI = A.SVC_INTEL
idx = SI.index()
picked = None
for base, hs in sorted(idx["hosts"].items(), key=lambda kv: -len(kv[1])):
    full = as_viewer(ANALYST, lambda: SI.for_hosts(hs, hold_small=True))
    if any(n < MIN for _, n in patterns(full)) and any(n >= MIN for _, n in patterns(full)):
        picked = (base, hs, full); break
if not picked:
    print("SKIPPED: no services report in memory with both small and large patterns")
    sys.exit(77)
base, hs, full = picked

print("Intel gathered, every category (hold_small)")
res = as_viewer(RESEARCHER, lambda: SI.for_hosts(hs, hold_small=True))
small_r = [c for c, n in patterns(res) if n < MIN]
big_r = [c for c, n in patterns(res) if n >= MIN]
ok("researcher: a pattern under 5 hosts has no code", small_r and all(c is None for c in small_r), f"{len(small_r)} small patterns")
ok("researcher: patterns of 5 hosts or more keep their codes", big_r and all(c for c in big_r), f"{len(big_r)} patterns")
ok("researcher: the small patterns are still listed, with their device counts", len(patterns(res)) == len(patterns(full)))
ok("analyst: every pattern keeps its code", all(c for c, _ in patterns(full)))
dem = as_viewer(ANALYST, lambda: SI.for_hosts(hs, hold_small=True), "?demo=1")
ok("demo mode: small patterns lose their codes too", all(c is None for c, n in patterns(dem) if n < MIN))
ok("the codes that stay are the same for everyone", [c for c, n in patterns(res) if n >= MIN] == [c for c, n in patterns(full) if n >= MIN])
view = as_viewer(RESEARCHER, lambda: SI.intel_view(base))
ok("a services report's window (Intel gathered) holds small codes back as well",
   all(c is None for c, n in patterns(view["cross"]) if n < MIN), base)

print("An analyst's code page (handed over in a channel)")
handed = as_viewer(RESEARCHER, lambda: SI.for_hosts(hs))
ok("without hold_small every code stays, for the researcher answering", all(c for c, _ in patterns(handed)))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
