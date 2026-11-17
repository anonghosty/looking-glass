#!/usr/bin/env python3
"""Intel gathered counts the report day (report_day.py; the user, 2026-11-17: "across reports is supposed to count 16
Nov only ie yesterday"). A services pattern counted 53 devices across 15 and 16 Nov while the Executive portal, on 16
Nov, counted 50 (43 on 16 Nov alone). Made-up records only (documentation addresses), no database needed:
1. report_day.select: the report day (the replay day), the newest day when it is not in memory, a named day, or
   every day in memory for the analysts' search
2. services Intel gathered: a host that is a router on one day and calls a sinkhole on the other is NOT counted on the
   report day; one that does both on the report day is
3. the analysts' combination search keeps its range (both days); the Executive portal's code filter matches on the day
   it shows
4. infections Intel gathered: the report day only, the search scope every day
Run: .venv/bin/python tests/check_report_day.py"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import report_day  # noqa: E402
import services_intel as SI  # noqa: E402
import intel as I  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


D15 = datetime(2026, 11, 15, tzinfo=timezone.utc)
D16 = D15 + timedelta(days=1)


class Day:
    def __init__(self, start, events):
        self.start, self.events, self.serial = start, events, 1


class Store:
    def __init__(self, days):
        self.days = {d.start: d for d in days}

    def get(self, _t):
        return None


print("1. Which day")
days = [Day(D15, []), Day(D16, [])]
now16 = lambda: D16 + timedelta(hours=7)                       # noqa: E731  (replaying 16 Nov)
now17 = lambda: D16 + timedelta(days=1, hours=1)               # noqa: E731  (17 Nov not in memory)
ok("the report day: the day being replayed", [d.start for d in report_day.select(days, None, now16)] == [D16])
ok("... the newest day in memory when the replay day is not there", [d.start for d in report_day.select(days, None, now17)] == [D16])
ok("a named day (the Executive portal's)", [d.start for d in report_day.select(days, "2026-11-15", now16)] == [D15])
ok("... every day in memory when the named day is not there", len(report_day.select(days, "2026-11-01", now16)) == 2)
ok("every day in memory for the analysts' search", len(report_day.select(days, "memory", now16)) == 2)


def svc(ip, day, report="scan_mikrotik_service"):
    return {"ip": ip, "report": report, "report_label": "Accessible MikroTik Service", "asn": "64500", "issues": [],
            "_t": (day + timedelta(hours=3)).timestamp()}


def sink(ip, day, name="m0yv"):
    return {"src_ip": ip, "infection": name, "source": "event4_sinkhole_http", "_t": (day + timedelta(hours=4)).timestamp()}


# A: router and sinkhole on 16 Nov. B: router on 15 Nov only, sinkhole on 16 Nov. C: router on 16 Nov, sinkhole on 15 Nov only
svc_days = [Day(D15, [svc("192.0.2.2", D15)]), Day(D16, [svc("192.0.2.1", D16), svc("192.0.2.3", D16)])]
comms_days = [Day(D15, [sink("192.0.2.3", D15)]), Day(D16, [sink("192.0.2.1", D16), sink("192.0.2.2", D16)])]


class Patterns:
    def fields_for(self, base):
        return []

    def items(self, base, e, fields):
        return []


ctx = {"svc_store": Store(svc_days), "comms_store": Store(comms_days), "patterns": Patterns(), "replay_now": now16,
       "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}}
sv = SI.ServicesIntel(ctx)

print("2. Services Intel gathered: the report day only")
rep = sv.index()
ok("counted from 16 Nov only", rep["days"] == ["2026-11-16"], str(rep["days"]))
s = sv.sinkholes_of("scan_mikrotik_service", rep, full=True)
ok("routers also calling a sinkhole on 16 Nov: only the one that does both that day (A), not B or C",
   s["hosts"] == 1 and [n["name"] for n in s["names"]] == ["m0yv"], str(s["hosts"]))

print("3. The analysts' search keeps its range; the Executive portal matches its day")
mem = sv.index("memory")
ok("the search scope counts both days", mem["days"] == ["2026-11-15", "2026-11-16"], str(mem["days"]))
ok("... where a router and a sinkhole on different days are linked (A, B and C)",
   sv.sinkholes_of("scan_mikrotik_service", mem, full=True)["hosts"] == 3)
entry = {"name": "scan_mikrotik_service", "kind": "x", "report": "scan_mikrotik_service",
         "parts": [["scan_mikrotik_service", []], [SI.SINK, ["Infection: m0yv"]]]}
ex = sv.matcher(entry, "2026-11-16").match(svc_days[1].events)
ok("Executive portal on 16 Nov: the 16 Nov router records whose host calls a sinkhole that day (A only)",
   [e["ip"] for e in ex] == ["192.0.2.1"], str([e["ip"] for e in ex]))
srch = sv.matcher(entry).match(svc_days[0].events + svc_days[1].events)
ok("the analysts' search (its range): every router record whose host calls a sinkhole on any day in memory",
   sorted(e["ip"] for e in srch) == ["192.0.2.1", "192.0.2.2", "192.0.2.3"], str(sorted(e["ip"] for e in srch)))
ok("each scope keeps its own cache (the report day is not worked out again by a search)", sv.index() is rep and sv.index("memory") is mem)

print("4. Infections Intel gathered")
ictx = {"store": Store(comms_days), "svc_store": Store(svc_days), "replay_now": now16, "labels": lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}}
iv = I.Intel(ictx)
ok("the report day only", I.Intel._days(iv)[0][0].start == D16 and len(I.Intel._days(iv)[0]) == 1)
ok("every day in memory for a code look-up or search", len(I.Intel._days(iv, "memory")[0]) == 2)
ictx.update(labels=lambda: {"event4_sinkhole_http": "Sinkhole HTTP"}, defined=lambda: {})
first = iv.index()
ok("the report day's counts are kept (2026-11-17: they were worked out again for every answer, ~3 s each)",
   iv.index() is first and iv.cache["key"] is not None)
ok("... and each scope keeps its own", iv.index("memory") is iv.index("memory") and iv.index("memory") is not first)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
