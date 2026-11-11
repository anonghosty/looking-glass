#!/usr/bin/env python3
"""The failed-login counter clears out old records (throttle_prune.py, external review 2026-11-11) and the locks
still work exactly as before: 5 wrong tries for one name in 15 minutes, 20 from one address in an hour.
Uses a clock it controls; touches no file, account or service.
Run: .venv/bin/python tests/check_login_throttle.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


clock = [1_000_000.0]
real_now = auth._now
auth._now = lambda: clock[0]
try:
    print("The locks are unchanged")
    t = auth.Throttle()
    for _ in range(4):
        t.failed("10.0.0.1", "grace")
    ok("4 wrong tries: not locked, 1 left", not t.locked("10.0.0.1", "grace") and t.left("10.0.0.1", "grace") == 1)
    t.failed("10.0.0.1", "grace")
    ok("5th wrong try locks the name from that address", t.locked("10.0.0.1", "grace"))
    ok("…not the same name from another address", not t.locked("10.0.0.2", "grace"))
    clock[0] += 901
    ok("the name lock ends after 15 minutes", not t.locked("10.0.0.1", "grace"))
    t2 = auth.Throttle()
    for i in range(20):
        t2.failed("10.0.0.3", f"name{i}")
    ok("20 wrong tries from one address in an hour lock the address", t2.locked("10.0.0.3", "someone-else"))
    clock[0] += 3601
    ok("…and the address lock ends after an hour", not t2.locked("10.0.0.3", "someone-else"))
    t.failed("10.0.0.4", "rachel"); t.ok("10.0.0.4", "rachel")
    ok("a good login clears that name's count", t.left("10.0.0.4", "rachel") == 5)

    print("Old records are cleared out")
    t = auth.Throttle()
    for i in range(500):                          # one-off guessed names from many addresses, never seen again
        t.failed(f"10.1.{i // 250}.{i % 250}", f"guess{i}")
    t.count(("register", "10.2.0.1"), 3600, add=True)
    before = len(t.fail)
    clock[0] += 3601                              # more than an hour later, one new failure
    t.failed("10.9.9.9", "daniel")
    ok("records older than an hour are dropped on the next failure", len(t.fail) == 2, f"{before} -> {len(t.fail)}")
    ok("the new failure is kept", t.left("10.9.9.9", "daniel") == 4)
    clock[0] += 10
    t.failed("10.9.9.8", "sarah")
    ok("it sweeps at most once a minute (a second failure 10 s later adds, no sweep needed)", len(t.fail) == 4)
    clock[0] += 120
    t.locked("10.8.8.8", "nobody"); t.left("10.8.8.7", "nobody"); t.count(("setup", "10.8.8.6"), 3600)
    ok("look-ups alone leave no empty records behind", not any(k[0].startswith("10.8.") or k[1] == "10.8.8.6" for k in t.fail))
    ok("a registration count still adds up", t.count(("register", "10.7.0.1"), 3600, add=True) == 1
       and t.count(("register", "10.7.0.1"), 3600, add=True) == 2 and t.count(("register", "10.7.0.1"), 3600) == 2)
    clock[0] += 1000
    ok("a name failure from 18 minutes ago no longer counts, the address one still does",
       t.left("10.9.9.9", "daniel") == 5 and len(t.fail.get(("10.9.9.9", None), [])) == 1)
finally:
    auth._now = real_now

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
