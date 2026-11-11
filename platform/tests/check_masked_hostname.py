#!/usr/bin/env python3
"""A masked viewer (external role, demo mode) cannot use the services host-name filter to find out whether a host is in
the data (external review, 2026-11-11). Masked views show no host name ("hidden"), so in a masked request the filter
matches nothing; an unmasked viewer filters on host names as before. The IP filter already refused raw addresses.
Uses a real host name from the services day in memory; prints none of them.
Run: .venv/bin/python tests/check_masked_hostname.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)
import app as A  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


day = A.svc["store"].get(A.replay_now())
named = [e for e in day.events if e.get("hostname")]
if not named:
    print("SKIPPED: no services record with a host name in the replay day")
    sys.exit(77)
host = named[0]["hostname"]
ip = named[0]["ip"]

users, roles = A.AUTH["users"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
EXT, ANA, UA = auth.TEST_PREFIX + "masked-viewer", auth.TEST_PREFIX + "unmasked-viewer", "lg-check-hostname"
ROLE = {EXT: "lg-masked", ANA: "lg-unmasked"}
users.get = lambda n: {"status": "active", "role": ROLE[n], "changed": 0} if n in ROLE else real_get(n)
roles.perms = lambda r: {"view"} if r == "lg-masked" else {"view", "unmasked"} if r == "lg-unmasked" else real_perms(r)
tokens = []


def client(user):
    t = A.AUTH["sessions"].create(user, "127.0.0.1", UA); tokens.append(t)
    c = A.app.test_client(); c.set_cookie("lg_session", t)
    return c


def stats(c, **q):
    r = c.get("/api/svc/stats", query_string=q, headers={"User-Agent": UA})
    return r.status_code, (r.json or {})


try:
    print("Unmasked viewer (an analyst)")
    ana = client(ANA)
    st, d = stats(ana, hostname=host)
    ok("the host-name filter finds the host", st == 200 and d.get("total", 0) >= 1 and d.get("hosts") == 1, f"{st} {d.get('total')} records")

    print("Masked viewer (external role)")
    ext = client(EXT)
    st, d = stats(ext)
    ok("the services figures answer", st == 200 and d.get("total", 0) > 0, str(st))
    st, d = stats(ext, hostname=host)
    ok("a real host name typed into the request matches nothing", st == 200 and d.get("total") == 0 and d.get("hosts") == 0, f"{d.get('total')} records")
    st, d = stats(ext, hostname="hidden")
    ok("…nor does the 'hidden' shown in masked views", st == 200 and d.get("total") == 0)
    st, d = stats(ext, ip=ip)
    ok("the IP filter refuses a raw address too (as before)", st == 200 and d.get("total") == 0)

    print("Demo mode (the Demo button) on an unmasked account")
    st, d = stats(ana, hostname=host, demo="1")
    ok("a real host name matches nothing in demo mode", st == 200 and d.get("total") == 0, f"{d.get('total')} records")
    st, d = stats(ana, hostname=host)
    ok("…and outside demo mode it still works", st == 200 and d.get("total", 0) >= 1)
finally:
    users.get, roles.perms = real_get, real_perms
    for t in tokens:
        A.AUTH["sessions"].end(token=t)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
