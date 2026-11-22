#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The heavy scheduled jobs never overlap (r91; timing analysis, no load test: a CSIRT team is 10 to 15 people, the risk
is jobs colliding on large data, not many users).

1. The table (job_schedule.JOBS): every job named once, with a rule, a duration, and its locks.
2. A minute-by-minute simulation of the next 400 days and of every day of 2026 to 2029 (every shape of quarter): two
   heavy jobs whose windows (start + longest duration) overlap must be kept apart by a lock (one both take, not both
   shared), or be listed in job_schedule.ALLOWED_TOGETHER with the reason; the quarterly report and the purge never
   fall on one day; no heavy job other than the pipeline's own runs falls in the working hours (AUDIT_WORK_HOURS); the
   tripwire and the weekly names refresh sit in a quiet slot between two pipeline runs. Every schedule
   bin/shadowserver schedule accepts is tried for the purge.
3. The locks really work, with temporary folders: while the platform holds the pipeline's run lock (making a report), a
   run started like run.sh exits; while a run holds it, the platform does not start a report (it waits for the next
   check and says so in the log; "Make it again" is refused with a plain sentence).
4. The code takes the locks the table names (read from the files): quarterly.py, the pipeline's run.sh, its
   quarterly_purge.py (the deletes inside quiet()), and the purge inside a pipeline run.
5. The numbers in the table are the code's: the report's day and check interval, the names refresh's crontab line,
   the installer's recommended pipeline schedule.
No database. Run from the platform's folder: .venv/bin/python tests/check_job_overlap.py
(LG_PIPELINE_DIR: a held copy of the pipeline's changed files; else ../database or ../shadowserver)."""
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.chdir(HERE)
import job_schedule as js  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def read(path):
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def hm(minute):
    d, m = divmod(minute, 1440)
    return f"day {d} {m // 60:02d}:{m % 60:02d}"


# ------------------------------------------------------------------ 1. the table
print("The job table (job_schedule.py)")
for line in js.table():
    print("    " + line)
names = [j["name"] for j in js.JOBS]
ok("every job is named once", len(names) == len(set(names)), str(names))
ok("every job has a label, a time in words, a rule and a duration",
   all(j["label"] and j["when"] and j["rule"] and j["max_min"] > 0 for j in js.JOBS))
ok("every lock is exclusive or shared, on a known lock",
   all(set(j["locks"].values()) <= {"EX", "SH"} and set(j["locks"]) <= {"pipeline", "quarterly", "cve", "malpedia", "report_map"}
       for j in js.JOBS))
heavy = [j for j in js.JOBS if j["heavy"]]
ok("every heavy job runs on a clock or a rule of its own (never 'after a start' or by hand, where no schedule can keep it apart)",
   all(set(j["rule"]) & {"cron", "quarterly_make", "quarterly_purge", "anytime"} for j in heavy), str([j["name"] for j in heavy]))
ok("the heavy jobs are the pipeline's runs, the purge, the quarterly report and the day switch",
   {j["name"] for j in heavy} == {"pipeline_run", "quarterly_purge", "quarterly_make", "day_switch"})
ok("a job inside another (the purge inside a pipeline run) takes that job's lock too",
   all(js.BY_NAME[j["part_of"]]["locks"].items() <= j["locks"].items() for j in js.JOBS if j["part_of"]))
ok("the cron lines parse", all(js.parse_cron(j["rule"]["cron"]) for j in js.JOBS if "cron" in j["rule"])
   and all(js.parse_cron(c) for c in js.PIPELINE_CHOICES))
ok("cron arithmetic: */30 fires at 00:00 and 00:30 ... 23:30 (48 a day); Mondays 04:17 only on a Monday",
   js.cron_starts("*/30 * * * *", date(2026, 11, 23)) == list(range(0, 1440, 30))
   and js.cron_starts(js.NAMES_CRON, date(2026, 11, 23)) == [257] and js.cron_starts(js.NAMES_CRON, date(2026, 11, 24)) == [])
ok("the tripwire's time is kept here, for its module to read (TRIPWIRE_CRON and TRIPWIRE_TIME agree)",
   js.cron_starts(js.TRIPWIRE_CRON, date(2026, 11, 23)) == [int(js.TRIPWIRE_TIME[:2]) * 60 + int(js.TRIPWIRE_TIME[3:])])


# ------------------------------------------------------------------ 2. the simulation
def simulate(first, days, pipeline_cron=js.PIPELINE_CRON):
    """{job: [(start, end)]} for the clock jobs; the jobs that may start at any minute are None."""
    return {j["name"]: js.windows(j, first, days, pipeline_cron) for j in js.JOBS}


def collisions(W):
    """[(a, b, start)] heavy pairs whose windows overlap and that nothing keeps apart."""
    out = []
    hv = [j["name"] for j in heavy]
    for i, a in enumerate(hv):
        for b in hv[i + 1:]:
            if js.BY_NAME[a]["part_of"] == b or js.BY_NAME[b]["part_of"] == a:
                continue
            if js.exclusive(a, b) or frozenset((a, b)) in js.ALLOWED_TOGETHER:
                continue
            wa, wb = W[a], W[b]
            if wa is None or wb is None:                 # any minute: it can meet the other whenever that one runs
                if (wa or wb):
                    out.append((a, b, (wa or wb)[0][0]))
                continue
            k = 0
            for s, e in wa:                              # both sorted by start
                while k < len(wb) and wb[k][1] <= s:
                    k += 1
                if k < len(wb) and wb[k][0] < e:
                    out.append((a, b, max(s, wb[k][0])))
                    break
    return out


today = datetime.now(timezone.utc).date()
print(f"\nThe next 400 days from {today}, and every day of 2026 to 2029, minute by minute")
spans = [(today, 400), (date(2026, 1, 1), (date(2030, 1, 1) - date(2026, 1, 1)).days)]
for first, days in spans:
    W = simulate(first, days)
    c = collisions(W)
    ok(f"{first} + {days} days: no two heavy jobs overlap unless a lock keeps them apart or a reason is written",
       not c, "; ".join(f"{a} and {b} at {hm(s)}" for a, b, s in c[:3]))
    mk, pg = W["quarterly_make"], W["quarterly_purge"]
    ok(f"{first} + {days} days: a quarterly report and a purge in every quarter it covers",
       len(mk) >= days // 92 and len(pg) >= days // 92, f"{len(mk)} reports, {len(pg)} purges")
    ok(f"{first} + {days} days: the report and the purge never on one day (the purge 14 days or more after the report)",
       all(min(abs(p[0] - m[0]) for m in mk) >= 14 * 1440 for p in pg), "")
    # the report and the purge DO meet pipeline runs on the clock: the locks are what keeps them apart (part 3)
    pl = W["pipeline_run"]
    met = sum(1 for s, e in mk if any(ps < e and s < pe for ps, pe in pl))
    ok(f"{first} + {days} days: every report's window meets a pipeline run on the clock ({met} of {len(mk)}), so the "
       "pipeline lock is required, and the table says the report takes it", met == len(mk) and js.exclusive("quarterly_make", "pipeline_run"))
    wh = js.work_hours()
    inside = [(n, s) for n in ("quarterly_make", "quarterly_purge") for s, e in W[n]
              if any(max(s, d * 1440 + wh[0] * 60) < min(e, d * 1440 + wh[1] * 60) for d in range(s // 1440, e // 1440 + 1))]
    ok(f"{first} + {days} days: no report or purge in the working hours ({wh[0]:02d}:00 to {wh[1]:02d}:00 UTC, AUDIT_WORK_HOURS)",
       not inside, "; ".join(f"{n} at {hm(s)}" for n, s in inside[:3]))
    quiet_bad = [(j["name"], s) for j in js.JOBS if j["quiet"] for s, e in W[j["name"]]
                 if any(ps < e and s < pe for ps, pe in pl)
                 or any(max(s, d * 1440 + wh[0] * 60) < min(e, d * 1440 + wh[1] * 60) for d in range(s // 1440, e // 1440 + 1))]
    ok(f"{first} + {days} days: the tripwire and the names refresh sit between two pipeline runs, outside working hours",
       not quiet_bad, "; ".join(f"{n} at {hm(s)}" for n, s in quiet_bad[:3]))

print("\nEvery pipeline schedule bin/shadowserver accepts (the purge runs inside the first run of its day)")
first, days = date(2026, 1, 1), 4 * 365 + 1
for cron in js.PIPELINE_CHOICES:
    W = simulate(first, days, cron)
    c = collisions(W)
    pg = W["quarterly_purge"]
    starts = sorted({s % 1440 for s, _ in pg})
    wh = js.work_hours()
    # the recommended schedule: the whole window before the working hours; a daily run the administrator chose: the
    # purge starts with it, outside working hours (a long purge after a daily 06:30 run can reach into them)
    end = max(e % 1440 if e % 1440 else 1440 for _, e in pg) if pg else 0
    whole = cron != js.PIPELINE_CRON or end <= wh[0] * 60
    ok(f"pipeline '{cron}': no collision; the purge starts at {', '.join(f'{m // 60:02d}:{m % 60:02d}' for m in starts)}, "
       "outside working hours" + ("" if cron != js.PIPELINE_CRON else f", and is over by {end // 60:02d}:{end % 60:02d}"),
       not c and pg and whole and all(wh[1] * 60 <= m or m < wh[0] * 60 for m in starts),
       "; ".join(f"{a} and {b} at {hm(s)}" for a, b, s in c[:3]) or str(starts))
ok("the work hours setting is read as the platform reads it (07-19 when unset or unreadable)",
   js.work_hours("07-19") == (7, 19) and js.work_hours("nonsense") == (7, 19) and js.work_hours("08-17") == (8, 17))


# ------------------------------------------------------------------ 3. the locks, with temporary folders
print("\nThe locks, with temporary folders (a made-up pipeline beside a made-up platform)")
import fcntl  # noqa: E402

tmp = tempfile.mkdtemp(prefix="lg-jobs-")
keep_env = os.environ.get("PIPELINE_DIR")
FLOCK = shutil.which("flock")


def runsh_starts(lock):
    """Would a pipeline run start now? Exactly run.sh's two lines (exec 9>.pipeline.lock; flock -n 9)."""
    r = subprocess.run(["bash", "-c", 'exec 9>"$1"; flock -n 9', "_", lock], capture_output=True, timeout=30)
    return r.returncode == 0


def hold_ex(path):
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


try:
    base = os.path.join(tmp, "platform")
    pipe = os.path.join(tmp, "pipeline")
    os.makedirs(os.path.join(base, "data", "quarterly")); os.makedirs(pipe)
    with open(os.path.join(pipe, "shadowserver_pipeline.py"), "w") as fh:
        fh.write("# made-up stand-in\n")
    os.environ["PIPELINE_DIR"] = pipe
    lock = os.path.join(pipe, js.PIPELINE_LOCK)
    ok("the platform finds the pipeline's run lock beside it", js.pipeline_lock_path(base) == lock, str(js.pipeline_lock_path(base)))
    with js.pipeline_paused(base) as held:
        ok("before the pipeline's first run (no lock file yet): nothing to wait for, and it says it is not held", held is None)
    open(lock, "w").close()
    if FLOCK:
        ok("a run started like run.sh starts when nothing holds the lock", runsh_starts(lock))
        with js.pipeline_paused(base) as held:
            ok("the platform holds the run lock shared while it makes a report ...", held is True)
            ok("... and a run started like run.sh meanwhile exits at once (flock -n)", not runsh_starts(lock))
        ok("let go after the report: the next run starts", runsh_starts(lock))
    else:
        print("  (flock is not installed here: the run.sh part is checked by the CI)")
    fd = hold_ex(lock)                                   # a pipeline run in progress
    try:
        try:
            with js.pipeline_paused(base):
                busy = False
        except js.PipelineBusy as e:
            busy = str(e) == js.BUSY_TEXT
        ok("while a run holds the lock the platform does not start a report (PipelineBusy, a plain sentence)", busy)
        ok("pipeline_running() says so", js.pipeline_running(base) is True)
    finally:
        os.close(fd)
    ok("...and not once the run has ended", js.pipeline_running(base) is False)
    os.symlink(lock, os.path.join(tmp, "elsewhere.lock"))
    with js.pipeline_paused(base, os.path.join(tmp, "elsewhere.lock")) as held:
        ok("a lock reached through a symbolic link is never opened", held is None)

    # the platform's quarterly background check and Make it again, with the build replaced by a probe
    import json  # noqa: E402

    from flask import Flask  # noqa: E402

    import quarterly as qq  # noqa: E402
    with open(os.path.join(base, "data", "quarterly", "state.json"), "w") as fh:
        json.dump({"since": "2026-01-01", "oldest_day": ""}, fh)
    probe = {"calls": 0, "pipeline_could_start": None, "quarterly_lock_free": None}

    def fake_build(db, b, quarter, made, **kw):
        probe["calls"] += 1
        probe["pipeline_could_start"] = runsh_starts(lock) if FLOCK else False
        fd2 = os.open(os.path.join(b, "data", "quarterly", ".lock"), os.O_RDONLY)
        try:
            fcntl.flock(fd2, fcntl.LOCK_SH | fcntl.LOCK_NB)
            probe["quarterly_lock_free"] = True
        except OSError:
            probe["quarterly_lock_free"] = False
        finally:
            os.close(fd2)
        return {"status": "VALID", "valid": True, "permit": False, "why": ""}

    class Audit:
        def __init__(self):
            self.rows = []

        def add(self, event, **kw):
            self.rows.append((event, kw))

    class Lines(logging.Handler):
        def __init__(self):
            super().__init__()
            self.lines = []

        def emit(self, record):
            self.lines.append(record.getMessage())

    qlog = logging.getLogger("lg-jobs-quarterly")
    qlog.propagate = False
    qlog.setLevel(logging.INFO)
    lines = Lines()
    qlog.addHandler(lines)
    real_build = qq.build
    qq.build = fake_build
    try:
        audit = Audit()
        api = qq.install(Flask("lg_jobs_check"), {"base_dir": base, "db": None, "has_perm": lambda p: True,
                                                   "csrf_ok": lambda: True, "audit": audit, "logger": qlog,
                                                   "serving": False, "findings": None, "settings": None})
        day3 = datetime(2027, 1, 3, 0, 5, tzinfo=timezone.utc).timestamp()
        fd = hold_ex(lock)                               # the 00:00 pipeline run is loading
        try:
            api["tick"](now=day3)
        finally:
            os.close(fd)
        ok("on the report's day, while the 00:00 run loads: the report is not started", probe["calls"] == 0, str(probe))
        ok("...the log says it waits, in plain words, and when it tries again",
           any("2026Q4 waits: the database pipeline is loading reports; tried again at the next check (in 10 minutes)" in x
               for x in lines.lines), str(lines.lines))
        ok("...nothing is recorded as made", not audit.rows and not os.path.exists(os.path.join(base, "data", "quarterly", "2026Q4")))
        api["tick"](now=day3 + 600)                      # the next check: the run has ended
        ok("the next check, the run over: the report is made", probe["calls"] == 1 and audit.rows
           and audit.rows[0][0] == "quarterly_made", str(audit.rows))
        if FLOCK:
            ok("...and while it is made a pipeline run cannot start (run.sh exits)", probe["pipeline_could_start"] is False, str(probe))
        ok("...with the quarterly lock held (the purge cannot start its deletes)", probe["quarterly_lock_free"] is False, str(probe))
        ok("let go afterwards: the next pipeline run starts", (runsh_starts(lock) if FLOCK else True) and not js.pipeline_running(base))
        fd = hold_ex(lock)
        try:
            try:
                api["make"]("2026Q3", "made again on request", "ada.admin")
                refused = ""
            except qq.Refused as e:
                refused = str(e)
        finally:
            os.close(fd)
        ok("Make it again while a run loads: refused with a plain sentence, not made", refused == js.BUSY_TEXT
           and probe["calls"] == 1 and api["busy"]["error"] == js.BUSY_TEXT, refused)
        os.environ["PIPELINE_DIR"] = os.path.join(tmp, "nowhere")
        lines.lines.clear()
        api["make"]("2026Q3", "made again on request", "ada.admin")
        ok("no pipeline beside the platform (another computer): the report is made, and the log says it could not wait",
           probe["calls"] == 2 and any("could not be read here" in x for x in lines.lines), str(lines.lines))
    finally:
        qq.build = real_build
finally:
    if keep_env is None:
        os.environ.pop("PIPELINE_DIR", None)
    else:
        os.environ["PIPELINE_DIR"] = keep_env
    shutil.rmtree(tmp, ignore_errors=True)


# ------------------------------------------------------------------ 4. the code takes the locks the table names
print("\nThe code takes the locks the table names")
src = read(os.path.join(HERE, "quarterly.py")) or ""
m = re.search(r"\n    def make_now\(.*?\n    def ", src, re.S)
body = m.group(0) if m else ""
i_p, i_q, i_b = body.find("job_schedule.pipeline_paused("), body.find("fcntl.LOCK_EX"), body.find("st = build(")
ok("quarterly.py: a report is made with the pipeline's run lock, then data/quarterly/.lock (exclusive), then built",
   0 < i_p < i_q < i_b, f"{i_p} {i_q} {i_b}")
ok("quarterly.py: Make it again asks whether a run is loading before it starts", "job_schedule.pipeline_running(base)" in src)
ok("quarterly.py: the background check logs the wait (Waiting) apart from the other refusals",
   re.search(r"except Waiting:\s+if log:\s+log\.info\(", src) is not None)
TOP = os.path.dirname(HERE)
CANDS = [p for p in (os.environ.get("LG_PIPELINE_DIR"), os.path.join(TOP, "database"), os.path.join(TOP, "shadowserver")) if p]


def pipeline_file(name):
    for c in CANDS:
        t = read(os.path.join(c, name))
        if t is not None:
            return t, c
    return None, None


qpsrc, where = pipeline_file("quarterly_purge.py")
runsh, _ = pipeline_file("run.sh")
pipesrc, _ = pipeline_file("shadowserver_pipeline.py")
if qpsrc is None:
    print("  (the database pipeline is not beside this platform: its part is checked where it is)")
else:
    rb = (re.search(r"\ndef run\(.*?\ndef ", qpsrc, re.S) or re.search(r"\ndef run\(.*", qpsrc, re.S)).group(0)
    ok("the pipeline's quarterly_purge.py: the deletes run inside quiet() (the platform's quarterly lock shared, the run lock)",
       0 < rb.find("with quiet(") < rb.find("delete_many(") and "fcntl.LOCK_SH" in qpsrc and 'PLATFORM_LOCK = ".lock"' in qpsrc
       and 'RUN_LOCK = os.path.join(HERE, ".pipeline.lock")' in qpsrc, where)
    ok("...and a purge that meets a report being made waits, and says so", "except Busy:" in rb and "outcome=\"waiting\"" in rb)
if runsh is not None:
    ok("the pipeline's run.sh: one run at a time, on .pipeline.lock (flock -n)",
       "exec 9>.pipeline.lock" in runsh and "flock -n 9" in runsh and js.PIPELINE_LOCK == ".pipeline.lock")
if pipesrc is not None:
    mi = re.search(r"\ndef main\(.*?\n(?=def )", pipesrc, re.S)
    mb = mi.group(0) if mi else ""
    ok("the pipeline: the purge is part of a run (after loading, in main), so under run.sh's lock",
       0 < mb.find("load_into_mongo(") < mb.find("quarterly_purge.run_safely("))


# ------------------------------------------------------------------ 5. the table's numbers are the code's
print("\nThe table's numbers are the code's")
ok("the report's day and its check interval (quarterly.MAKE_ON_DAY, CHECK_EVERY)",
   qq.MAKE_ON_DAY == js.QUARTERLY_MAKE_ON_DAY and qq.CHECK_EVERY == js.QUARTERLY_CHECK_EVERY_S,
   f"{qq.MAKE_ON_DAY} {qq.CHECK_EVERY}")
fon = read(os.path.join(HERE, "manage", "fetch_offline_names.py")) or ""
ok("the weekly names refresh's crontab line (manage/fetch_offline_names.py)", f'line = f"{js.NAMES_CRON}  ' in fon)
inst = read(os.path.join(HERE, "tools", "release_root", "install.sh"))
if inst is not None:
    ok("the installer recommends 'every 30m', which bin/shadowserver writes as */30 (the table's pipeline schedule)",
       '"every 30m" "Every 30 minutes (recommended)"' in inst and js.PIPELINE_CRON == "*/30 * * * *")
bsh, _ = pipeline_file(os.path.join("bin", "shadowserver"))
if bsh is not None:
    ok("bin/shadowserver accepts exactly the minutes and hours the table tries",
       "5|10|15|20|30)" in bsh and "2|3|4|6|8|12)" in bsh)
cfg = read(os.path.join(HERE, "config_page.py")) or ""
ok("the working hours default is the platform's (AUDIT_WORK_HOURS)", f'"AUDIT_WORK_HOURS", "Audit", "Working hours (UTC)", "{js.WORK_HOURS_DEFAULT}"' in cfg)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
