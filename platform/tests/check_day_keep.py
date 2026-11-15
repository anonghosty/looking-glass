#!/usr/bin/env python3
"""A loaded day is kept, with every cached answer, while MongoDB holds the same rows (speed review, 2026-11-15): when
its 10 minutes are up the rows per report are counted again, and only a change, a forced reload (a report arrived, the
schedule moved on) or a copy older than DAY_MAX_AGE_SECONDS loads it again. The cache key of a kept copy stays the
same; a reloaded copy gets a new one. No database needed (the services store, with its loading faked).
Run: .venv/bin/python tests/check_day_keep.py"""
import os
import sys
import time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import services as S  # noqa: E402
from respcache import day_key  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


class Store(S.ServiceStore):
    def __init__(self):
        super().__init__(db=None, registry=None, refs=None, logger=None, reload_seconds=600)
        self.counts = {"scan_http": 10}
        self.loads = 0
        self.sig_calls = 0

    def signature(self, start):
        self.sig_calls += 1
        return dict(self.counts)

    def _record_changes(self, start, old, new):       # the "new report data" log needs the report registry
        pass

    def _load(self, start, old=None):
        self.loads += 1
        d = S.Day(start, [{"_t": start.timestamp() + i} for i in range(self.counts.get("scan_http", 0))])
        d.sig = dict(self.counts)
        return d


start = datetime(2026, 11, 14, tzinfo=timezone.utc)
st = Store()
d1 = st.get(start)
ok("the first get loads the day", st.loads == 1 and len(d1.events) == 10)
ok("within its 10 minutes, nothing is counted or loaded", st.get(start) is d1 and st.sig_calls == 0 and st.loads == 1)
k1 = day_key(d1)
d1.checked_at -= 601
d2 = st.get(start)
ok("after 10 minutes with the same rows: counted once, not loaded, the same copy", d2 is d1 and st.sig_calls == 1 and st.loads == 1)
ok("…and its cache key is unchanged, so cached answers stay", day_key(d2) == k1)
ok("…and the next 10 minutes start from that check", time.time() - d2.checked_at < 5)
d2.checked_at -= 601
st.counts = {"scan_http": 12}
d3 = st.get(start)
ok("after 10 minutes with more rows: loaded again", st.loads == 2 and d3 is not d1 and len(d3.events) == 12)
ok("…with a new cache key", day_key(d3) != k1)
st.check(start)                                   # same counts: nothing to do
ok("the 15-second check with the same rows loads nothing", st.loads == 2)
st.counts = {"scan_http": 13}
st.check(start)
ok("new rows: the first check waits (the pipeline may still be adding)", st.loads == 2)
st.counts = {"scan_http": 14}
st.check(start)
ok("…still changing at the next check: still waits", st.loads == 2)
st.check(start)
ok("…the same counts twice in a row: loaded", st.loads == 3 and len(st.days[start].events) == 14)
st.days[start].pending = {"sig": {"scan_http": 1}, "since": time.time() - S.settled.__globals__["SETTLE_MAX_SECONDS"] - 1}
st.counts = {"scan_http": 15}
st.check(start)
ok("a run that keeps adding rows is loaded at least every SETTLE_MAX_SECONDS", st.loads == 4)
d4 = st.days[start]
d4.loaded_at -= S.DAY_MAX_AGE_SECONDS + 1
d4.checked_at -= 601
n = st.loads; st.get(start)
ok("a copy older than DAY_MAX_AGE_SECONDS is loaded again even with the same rows", st.loads == n + 1)
d5 = st.days[start]
d5.force = True
n = st.loads; st.get(start)
ok("a forced reload (report arrived, schedule moved) loads it", st.loads == n + 1)
st.days[start].sig = None
st.days[start].checked_at -= 601
n = st.loads; st.get(start)
ok("a copy whose counts are not known is loaded again (never kept blindly)", st.loads == n + 1)
empty = Store(); empty.counts = {}
e1 = empty.get(start); e1.checked_at -= 61
empty.get(start)
ok("an empty day (report not in yet) is still tried every minute", empty.loads == 2)

print("Only the reports that changed are read again")


class Reg:
    def __init__(self, names):
        self.items = [{"name": n} for n in names]

    def get(self):
        return self.items


class Partial(S.ServiceStore):
    """the real _load, with the database reads faked: _fetch counts which reports are read"""
    def __init__(self):
        super().__init__(db=None, registry=Reg(["scan_http", "scan_rdp", "scan_ssh"]), refs=None, logger=None)
        self.counts = {"scan_http": 3, "scan_rdp": 2, "scan_ssh": 4}
        self.read = []

    def signature(self, start):
        return dict(self.counts)

    def _fetch(self, src, start, end):
        self.read.append(src["name"])
        n = self.counts.get(src["name"], 0)
        return [{"_t": start.timestamp() + i, "asn": 64512, "region": "ACCRA", "ip": f"192.0.2.{i}", "report": src["name"]}
                for i in range(n)], None


p = Partial()
d0 = p._load(start)
ok("a first load reads every report", sorted(p.read) == ["scan_http", "scan_rdp", "scan_ssh"] and len(d0.events) == 9)
p.read.clear(); p.counts["scan_rdp"] = 5
d1 = p._load(start, old=d0)
ok("one report grew: only it is read again", p.read == ["scan_rdp"], str(p.read))
ok("…and the day holds every report's rows, the new ones included", len(d1.events) == 12 and d1.per_source == {"scan_http": 3, "scan_rdp": 5, "scan_ssh": 4})
ok("…the kept reports' rows are the very same (not read or prepared again)",
   all(e in d0.events for e in d1.events if e["report"] != "scan_rdp"))
ok("…totals before the constituency add up (rows, networks, regions)", d1.raw_total == 12 and d1.asn_raw["64512"] == 12 and d1.region_raw["ACCRA"] == 12)
ok("…in time order", [e["_t"] for e in d1.events] == sorted(e["_t"] for e in d1.events))
p.read.clear(); p.gen = 1
p._load(start, old=d1)
ok("the constituency changed since: everything is read again", len(p.read) == 3)
p.read.clear(); p.gen = 0; p.counts.pop("scan_ssh")
d2 = p._load(start, old=d1)
ok("a report that is gone is gone from the day", "scan_ssh" not in d2.per_source and len(d2.events) == 8)

print("The settle rule")
from respcache import settled  # noqa: E402


class D:
    pass


x = D(); now = 1000.0
ok("first change: wait", settled(x, {"a": 1}, now) is False and x.pending["sig"] == {"a": 1})
ok("same counts at the next check: go", settled(x, {"a": 1}, now + 15) is True and x.pending is None)
y = D()
settled(y, {"a": 1}, now)
ok("changed again: wait, keeping when it started", settled(y, {"a": 2}, now + 15) is False and y.pending["since"] == now)
ok("still changing after the limit: go anyway", settled(y, {"a": 3}, now + 200) is True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
