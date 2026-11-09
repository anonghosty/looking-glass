"""Simulated days for the replay schedule (no MongoDB needed).  Run: .venv/bin/python tests/test_schedule.py"""
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from schedule import ReplaySchedule  # noqa: E402

UTC = timezone.utc
d = lambda s: datetime.fromisoformat(s).replace(tzinfo=UTC)
clock = {"now": d("2026-11-06T19:00:00")}
arrived = {}                                    # day -> wall time its report lands in MongoDB
has = lambda day: 1000 if day.date().isoformat() in arrived and clock["now"] >= arrived[day.date().isoformat()] else 0
path = os.path.join(tempfile.mkdtemp(), "schedule.json")
fails = 0


def mk():
    return ReplaySchedule(path, 24, 600, has, now=lambda: clock["now"])


def check(label, s, want_state, want_pos=None):
    global fails
    s.tick()
    pos, st = s.position()
    ok = st == want_state and (want_pos is None or pos.strftime("%Y-%m-%d %H:%M") == want_pos)
    fails += not ok
    print(f"{'ok ' if ok else 'FAIL'} {clock['now']:%m-%d %H:%M}  {label:62} -> {st:8} {pos:%Y-%m-%d %H:%M}"
          + ("" if ok else f"   (wanted {want_state} {want_pos})"))


def at(s):
    clock["now"] = d(s)


# invented arrival times: day 05 arrives on the 6th at 14:10, 06 on the 7th at 14:10, 07 at 02:20 on the 8th
arrived.update({"2026-11-05": d("2026-11-06T14:10:00"), "2026-11-06": d("2026-11-07T14:10:00"),
                "2026-11-07": d("2026-11-08T02:20:00"), "2026-11-08": d("2026-11-09T04:00:00")})
s = mk()
check("first start, yesterday's report is in: normal 24 h schedule", s, "playing", "2026-11-05 19:00")
at("2026-11-06T23:59:00"); check("end of the replayed day", s, "playing", "2026-11-05 23:59")
at("2026-11-07T00:00:30"); check("midnight: 06 report not in yet", s, "waiting", "2026-11-06 00:00")
at("2026-11-07T09:00:00"); check("still no report in the morning", s, "waiting", "2026-11-06 00:00")
at("2026-11-07T14:11:00"); check("report arrived 14:10: settling (10 min)", s, "settling", "2026-11-06 00:00")
s2 = mk(); check("service restart while settling keeps the state", s2, "settling", "2026-11-06 00:00"); s = s2
at("2026-11-07T14:21:00"); check("settled: replay of 06 starts from 00:00", s, "playing", "2026-11-06 00:00")
at("2026-11-07T20:21:00"); check("6 h later: 06:00 of the 6th", s, "playing", "2026-11-06 06:00")
s2 = mk(); check("service restart while playing continues at the same point", s2, "playing", "2026-11-06 06:00"); s = s2
at("2026-11-08T14:20:00"); check("near the end of the 6th (07 report already in since 02:20)", s, "playing", "2026-11-06 23:59")
at("2026-11-08T14:21:10"); check("06 finished: 07 starts at once, no gap", s, "playing", "2026-11-07 00:00")
at("2026-11-09T14:21:10"); check("07 finished: 08 already in (04:00): continues", s, "playing", "2026-11-08 00:00")

# outage: service off for three days, the newest report is in -> skip to it
arrived["2026-11-11"] = d("2026-11-12T02:00:00")
at("2026-11-12T12:00:00"); s = mk(); check("after a 3-day outage: stale state ignored, normal start", s, "playing", "2026-11-11 12:00")

# no saved state and yesterday's report missing at start -> waiting, then starts from 00:00
os.remove(path); arrived.pop("2026-11-12", None)
at("2026-11-13T08:00:00"); s = mk(); check("fresh start, yesterday's report missing", s, "waiting", "2026-11-12 00:00")
arrived["2026-11-12"] = d("2026-11-13T09:00:00")
at("2026-11-13T09:00:30"); check("report arrives", s, "settling", "2026-11-12 00:00")
at("2026-11-13T09:11:00"); check("starts from 00:00 after settling", s, "playing", "2026-11-12 00:00")

# reports trickling in: each new one during the settle time restarts the wait
extra = {"rows": 0}
has_base = has
has = lambda day: has_base(day) + (extra["rows"] if day.date().isoformat() == "2026-11-13" and has_base(day) else 0)
arrived["2026-11-13"] = d("2026-11-14T07:31:00")
os.remove(path)
at("2026-11-14T06:00:00"); s = mk(); check("fresh start on the 14th: waiting for the 13 report", s, "waiting", "2026-11-13 00:00")
at("2026-11-14T07:31:30"); check("first reports of 13 arrive", s, "settling", "2026-11-13 00:00")
extra["rows"] = 78
at("2026-11-14T07:38:00"); check("another report arrives 7 min later: settle restarts", s, "settling", "2026-11-13 00:00")
at("2026-11-14T07:42:00"); check("10 min after the FIRST report: still settling", s, "settling", "2026-11-13 00:00")
at("2026-11-14T07:48:30"); check("10 min after the LAST report: replay starts", s, "playing", "2026-11-13 00:00")

print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
