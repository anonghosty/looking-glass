#!/usr/bin/env python3
"""A time in a request (?at=) with its own time-zone offset must not load another copy of the day (external review,
2026-11-11: ?at=…+05:37, +05:38, … each kept a shifted day in memory that was never dropped). Every request time is
turned into UTC, and both day caches start a day at 00:00 UTC whatever time they are given.
Run: .venv/bin/python tests/check_time_offsets.py"""
import os, sys
from datetime import datetime, timedelta, timezone
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)
import needs_db  # noqa: E402
needs_db.require()   # no reachable MongoDB (a fresh clone, CI): skipped, not crashed
import app as A  # noqa: E402
import auth  # noqa: E402
import services  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


UTC = timezone.utc
rn = A.replay_now()
day = A.day_start(rn)
noon = (day + timedelta(hours=12)).strftime("%Y-%m-%dT%H:%M:%S")

print("Request times become UTC")
for off in ("+05:37", "-11:59", "+14:00", "Z", ""):
    t = A.parse_iso(noon + off, rn)
    ok(f"at={noon}{off or ' (no offset)'} -> UTC", t.utcoffset() == timedelta(0) and t.tzinfo is not None, t.isoformat())
t = A.parse_iso(noon + "+05:37", rn)
ok("the moment is kept (12:00+05:37 is 06:23 UTC)", t == datetime.fromisoformat(noon + "+05:37"), t.strftime("%H:%M"))

print("A day always starts at 00:00 UTC (both caches)")
odd = datetime.fromisoformat(noon + "+05:37")
for name, f in (("communications", A.day_start), ("services", services.ServiceStore.day_start)):
    s = f(odd)
    ok(f"{name}: a +05:37 time gives the UTC day start", s == day and s.utcoffset() == timedelta(0), s.isoformat())
    ok(f"{name}: a UTC time is unchanged", f(day + timedelta(hours=5)) == day)

print("Many offsets in requests load the day once")
users, roles = A.AUTH["users"], A.AUTH["roles"]
real_get, real_perms = users.get, roles.perms
VIEWER, UA = auth.TEST_PREFIX + "offset-viewer", "lg-check-offsets"
users.get = lambda n: {"status": "active", "role": "lg-offset", "changed": 0} if n == VIEWER else real_get(n)
roles.perms = lambda r: {"view", "unmasked"} if r == "lg-offset" else real_perms(r)
token = None
try:
    token = A.AUTH["sessions"].create(VIEWER, "127.0.0.1", UA)
    c = A.app.test_client(); c.set_cookie("lg_session", token)
    H = {"User-Agent": UA}
    r = c.get("/api/sources", headers=H)
    ok("the replay day answers", r.status_code == 200, str(r.status_code))
    before = sorted(A.store.days)
    codes = set()
    for m in range(0, 24 * 60, 37):              # 39 different offsets, -12:00 … +11:57
        sign, mm = ("-" if m < 720 else "+"), abs(m - 720)
        codes.add(c.get("/api/sources", query_string={"at": f"{noon}{sign}{mm // 60:02d}:{mm % 60:02d}"}, headers=H).status_code)
    after = sorted(A.store.days)
    ok("39 different offsets: still answered", codes == {200}, str(codes))
    ok("no extra copy of any day in memory", after == before, f"{len(before)} -> {len(after)} days")
    ok("every day in memory starts at 00:00 UTC", all(k.utcoffset() == timedelta(0) and (k.hour, k.minute) == (0, 0) for k in after),
       ", ".join(k.isoformat() for k in after))
finally:
    users.get, roles.perms = real_get, real_perms
    if token:
        A.AUTH["sessions"].end(token=token)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
