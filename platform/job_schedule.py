# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every scheduled job of Looking Glass and its database pipeline, in one table: when it runs, how long it may take,
whether it is heavy, and which lock it takes (r91: the heavy jobs never overlap).

A CSIRT team is 10 to 15 people, so the risk is not many users at once: it is two heavy jobs working on the same large
data at the same time. tests/check_job_overlap.py reads this table, simulates the schedule minute by minute, and fails
when two heavy jobs could overlap without a lock that keeps them apart (or a written reason why they may), when a lock
the table names is not taken in the code, or when a heavy job falls in the team's working hours.

The locks (flock, advisory; every attempt is non-blocking, so nothing ever waits for ever):
  pipeline    the pipeline folder's .pipeline.lock. run.sh holds it EXCLUSIVE for a whole run (flock -n: a second run
              exits at once). The quarterly purge runs inside a run, so it is under it. The platform takes it SHARED
              while it makes a quarterly report (pipeline_paused below): no run can start then, and the report is not
              started while a run is loading (it waits for the next check, 10 minutes later).
  quarterly   the platform's data/quarterly/.lock. Making a report holds it EXCLUSIVE; the purge holds it SHARED
              (read only, from the pipeline's side) while it deletes, and does not start while a report is being made.
  cve, malpedia, report_map   data/.cve_check.lock, data/.malpedia_check.lock, data/report_map/.report_map.lock:
              one background check at a time (they only reach outside services and write small caches).

Times are UTC unless a job says otherwise. The pipeline's cron line uses the computer's own clock (bin/shadowserver
schedule): on a computer that is not on UTC the runs move, which is why the locks, not the clock, keep the heavy jobs
apart.
"""
import contextlib
import fcntl
import os
from datetime import date, datetime, timedelta, timezone

PIPELINE_LOCK = ".pipeline.lock"                  # in the pipeline's folder (run.sh, bin/shadowserver, uninstall.sh)
QUARTERLY_LOCK = os.path.join("data", "quarterly", ".lock")
PIPELINE_CRON = "*/30 * * * *"                    # the installer's recommended schedule ("every 30m", install.sh)
# every schedule bin/shadowserver schedule accepts (schedule_cron), and its daily default (install.sh: 06:30)
PIPELINE_CHOICES = ("*/5 * * * *", "*/10 * * * *", "*/15 * * * *", "*/20 * * * *", "*/30 * * * *", "0 * * * *",
                    "0 */2 * * *", "0 */3 * * *", "0 */4 * * *", "0 */6 * * *", "0 */8 * * *", "0 */12 * * *",
                    "30 6 * * *")
PIPELINE_TYPICAL_MAX_MIN = 15                     # 683 runs (live, 6-21 Nov 2026): median 3 s, longest 8 min
NAMES_CRON = "17 4 * * 1"                         # manage/fetch_offline_names.py --schedule (Mondays 04:17)
# the daily code-integrity check (the r91 tripwire): its time is set here, in a quiet slot between two pipeline runs
# and outside working hours; the tripwire's own module reads TRIPWIRE_CRON (or TRIPWIRE_TIME) from here
TRIPWIRE_CRON = "45 3 * * *"
TRIPWIRE_TIME = "03:45"
QUARTERLY_MAKE_ON_DAY = 3                         # quarterly.MAKE_ON_DAY: the next quarter's 3rd day
QUARTERLY_CHECK_EVERY_S = 600                     # quarterly.CHECK_EVERY: its background check
WORK_HOURS_DEFAULT = "07-19"                      # AUDIT_WORK_HOURS (Settings → Configuration): the team's working hours

BUSY_TEXT = "The database pipeline is loading reports now: try again in a few minutes."


def _job(name, label, where, when, rule, max_min, heavy, locks=None, part_of=None, quiet=False, notes=""):
    return {"name": name, "label": label, "where": where, "when": when, "rule": rule, "max_min": max_min,
            "heavy": heavy, "locks": locks or {}, "part_of": part_of, "quiet": quiet, "notes": notes}


# rule: {"cron": "m h dom mon dow"} | {"quarterly_make": True} | {"quarterly_purge": True} | {"anytime": True}
#       | {"every_s": N, "after_start_s": M} | {"once_after_start_s": N} | {"manual": True} | {"system": True}
JOBS = [
    _job("pipeline_run", "Pipeline run (e-mail or API, unzip, sort, load into MongoDB)", "pipeline (user crontab)",
         "every 30 minutes, at :00 and :30 (the computer's clock)", {"cron": PIPELINE_CRON}, PIPELINE_TYPICAL_MAX_MIN,
         True, {"pipeline": "EX"}, notes="a run longer than 30 minutes makes the next one exit at once (flock -n)"),
    _job("quarterly_purge", "Quarterly purge (raw report rows before the cutoff)", "pipeline (inside a run)",
         "the purge day (16th working day after the quarter), the first run from 00:00 UTC, after loading",
         {"quarterly_purge": True}, 60, True, {"pipeline": "EX", "quarterly": "SH"}, part_of="pipeline_run",
         notes="skipped (tried again at the next run) while the platform makes a quarterly report"),
    _job("quarterly_make", "Quarterly report (counts, PDFs, CSVs, purge permit)", "platform service",
         "the next quarter's 3rd day, the first check from 00:00 UTC (checks every 10 minutes)",
         {"quarterly_make": True}, 60, True, {"pipeline": "SH", "quarterly": "EX"},
         notes="waits for a pipeline run that is loading; Make it again (an administrator) takes the same locks"),
    _job("day_switch", "Replay day switch (the next day loaded in full)", "platform service",
         "when the next day's reports have settled (about 31 hours after that day began; live: about 07:45 UTC)",
         {"anytime": True}, 10, True, notes="driven by the reports' arrival, not by the clock"),
    _job("tripwire", "Code-integrity check (r91 tripwire)", "platform", f"daily at {TRIPWIRE_TIME} UTC",
         {"cron": TRIPWIRE_CRON}, 10, False, quiet=True, notes="reads the code files only; time kept here"),
    _job("names_refresh", "Offline name sources and ATT&CK refresh", "platform (user crontab)", "Mondays 04:17",
         {"cron": NAMES_CRON}, 10, False, quiet=True, notes="downloads and small JSON files; no database (a full one: 23 s)"),
    _job("day_reload", "Days in memory checked / reloaded", "platform service",
         "checked every 10 minutes, reloaded in full at least hourly (DAY_RELOAD_SECONDS, DAY_MAX_AGE_SECONDS)",
         {"every_s": 600, "after_start_s": 0}, 5, False, notes="reads; made to run beside loads"),
    _job("replay_tick", "Replay schedule and new rows", "platform service", "every 15 seconds",
         {"every_s": 15, "after_start_s": 0}, 1, False),
    _job("registry_refresh", "Report registry full re-check", "platform service", "hourly (REGISTRY_REFRESH_SECONDS)",
         {"every_s": 3600, "after_start_s": 0}, 1, False),
    _job("mgmt_prewarm", "Executive 7-day baseline worked out ahead", "platform service",
         "90 s after start, then every 30 minutes", {"every_s": 1800, "after_start_s": 90}, 5, False,
         notes="reads the last 8 days"),
    _job("finding_watch", "Findings: reported days, repeats, time to act", "platform service",
         "120 s after start, then every 30 minutes", {"every_s": 1800, "after_start_s": 120}, 5, False),
    _job("warmup", "Definitions page warm-up", "platform service", "checked every 30 s, runs when the days change",
         {"every_s": 30, "after_start_s": 20}, 2, False),
    _job("cve_lookups", "CVE look-ups (NVD, EPSS) and the daily CISA KEV refresh", "platform service",
         "120 s after start, then every 10 minutes", {"every_s": 600, "after_start_s": 120}, 10, False,
         {"cve": "EX"}, notes="outside services at their pace; small cache file"),
    _job("malpedia_check", "Malpedia: new names", "platform service", "90 s after start, then every 30 minutes",
         {"every_s": 1800, "after_start_s": 90}, 15, False, {"malpedia": "EX"}),
    _job("report_map", "Report map: feed (daily) and arrivals", "platform service",
         "150 s after start, then every 30 minutes", {"every_s": 1800, "after_start_s": 150}, 2, False,
         {"report_map": "EX"}),
    _job("audit_checkpoint", "Audit log checkpoint (signed)", "platform service",
         "checked hourly, made every 24 hours (AUDIT_CHECKPOINT_HOURS)", {"every_s": 3600, "after_start_s": 300}, 1,
         False, notes="its own folder lock"),
    _job("session_prune", "Expired sessions removed", "platform service", "every 5 minutes",
         {"every_s": 300, "after_start_s": 300}, 1, False),
    _job("spike_notice", "Spike notice refresh", "platform service", "on a page view, at most every 10 minutes",
         {"every_s": 600, "after_start_s": 0}, 1, False),
    _job("quarterly_check", "Quarterly background check (due report, purge results)", "platform service",
         "90 s after start, then every 10 minutes", {"every_s": QUARTERLY_CHECK_EVERY_S, "after_start_s": 90}, 1,
         False, notes="starts quarterly_make on its day"),
    _job("acode_warm", "Analyst code counts worked out ahead", "platform service", "once, 30 s after start",
         {"once_after_start_s": 30}, 2, False),
    _job("name_levels", "Name levels learned from every report", "platform service",
         "once per installation, 120 s after a start, until done", {"once_after_start_s": 120}, 30, False,
         notes="reads every report collection once, in batches with pauses"),
    _job("library_supply", "Refused library files into the audit log", "platform service", "once, 60 s after start",
         {"once_after_start_s": 60}, 1, False),
    _job("backup", "Backup (manage/backup.sh)", "manual", "when an administrator runs it (no schedule)",
         {"manual": True}, 10, False, notes="the platform folder only, not MongoDB"),
    _job("library_update", "Library update (deploy/update_libraries.sh)", "manual", "with an update (no schedule)",
         {"manual": True}, 10, False),
    _job("lookups", "Look-up jobs and Identify networks", "platform service", "when someone starts one",
         {"manual": True}, 30, False, notes="one person's request; bounded (bounded_jobs.py)"),
    _job("logrotate", "Log rotation (the system's logrotate, MongoDB's log)", "system timer",
         "daily, 00:00 plus up to 1 hour (RandomizedDelaySec)", {"system": True}, 5, False),
]
ALLOWED_TOGETHER = {
    frozenset(("day_switch", "pipeline_run")):
        "by design: a day starts after its reports have settled; later reports are added to it while it plays",
    frozenset(("day_switch", "quarterly_make")):
        "both only read, and different rows: the ended quarter's, not the replay day's (the days in memory are the last 3)",
    frozenset(("day_switch", "quarterly_purge")):
        "the purge deletes only rows older than 31 days; the days in memory are the last 3, the baseline the last 8",
}
BY_NAME = {j["name"]: j for j in JOBS}


# ------------------------------------------------------------------ cron
def _field(text, lo, hi):
    out = set()
    for part in text.split(","):
        step = 1
        if "/" in part:
            part, s = part.split("/", 1)
            step = int(s)
        if part == "*":
            a, b = lo, hi
        elif "-" in part:
            a, b = (int(x) for x in part.split("-", 1))
        else:
            a = b = int(part)
        if not (lo <= a <= b <= hi) or step < 1:
            raise ValueError(f"cron field {text!r} outside {lo}-{hi}")
        out.update(range(a, b + 1, step))
    return out


def parse_cron(line):
    """(minutes, hours, days of month, months, days of week 0=Sunday) as sets; standard cron, no names."""
    f = line.split()
    if len(f) != 5:
        raise ValueError(f"a cron line has 5 fields: {line!r}")
    dow = _field(f[4], 0, 7)
    return (_field(f[0], 0, 59), _field(f[1], 0, 23), _field(f[2], 1, 31), _field(f[3], 1, 12),
            {0 if d == 7 else d for d in dow}, f[2] == "*", f[4] == "*")


def cron_starts(line, day):
    """The minutes of `day` (0..1439) at which the cron line fires."""
    mi, hr, dom, mon, dow, dom_any, dow_any = parse_cron(line)
    wd = (day.weekday() + 1) % 7
    if day.month not in mon:
        return []
    d_ok, w_ok = day.day in dom, wd in dow
    if not ((d_ok and w_ok) if (dom_any or dow_any) else (d_ok or w_ok)):
        return []
    return sorted(h * 60 + m for h in hr for m in mi)


# ------------------------------------------------------------------ windows
def windows(job, first_day, days, pipeline_cron=PIPELINE_CRON):
    """[(start, end)] in minutes from first_day 00:00 for a job with a clock rule; [] for the others (intervals after a
    start, one-offs, manual, system); None for a job that may start at any minute ({"anytime"})."""
    r, out = job["rule"], []
    if r.get("anytime"):
        return None
    for i in range(days):
        day = first_day + timedelta(days=i)
        base = i * 1440
        if "cron" in r:
            out += [(base + m, base + m + job["max_min"]) for m in cron_starts(r["cron"], day)]
        elif r.get("quarterly_make") and day.day == QUARTERLY_MAKE_ON_DAY and day.month in (1, 4, 7, 10):
            out.append((base, base + QUARTERLY_CHECK_EVERY_S // 60 + job["max_min"]))
        elif r.get("quarterly_purge") and day == purge_day_of(day):
            runs = cron_starts(pipeline_cron, day)
            if runs:
                start = base + runs[0]
                out.append((start, start + BY_NAME["pipeline_run"]["max_min"] + job["max_min"]))
    return out


def purge_day_of(day):
    """The purge day of the quarter before day's quarter (quarterly.purge_dates, the one rule), or None."""
    import quarterly
    y, q = quarterly.prev_quarter(*quarterly.quarter_of(day))
    return quarterly.purge_dates(y, q)["purge_day"]


def exclusive(a, b):
    """Do two jobs' locks keep them apart? (a lock both take, not both shared)"""
    la, lb = BY_NAME[a]["locks"], BY_NAME[b]["locks"]
    return any(k in lb and "EX" in (la[k], lb[k]) for k in la)


def work_hours(text=None):
    """(first hour, end hour) of AUDIT_WORK_HOURS ("07-19"), the default when unreadable."""
    t = text if text is not None else os.environ.get("AUDIT_WORK_HOURS", WORK_HOURS_DEFAULT)
    try:
        a, b = (int(x) for x in str(t).split("-", 1))
        if 0 <= a < b <= 24:
            return a, b
    except ValueError:
        pass
    a, b = WORK_HOURS_DEFAULT.split("-")
    return int(a), int(b)


# ------------------------------------------------------------------ the pipeline's run lock, from the platform
class PipelineBusy(Exception):
    """A pipeline run holds its lock now."""


def pipeline_lock_path(base_dir):
    """The pipeline's run lock beside this platform, or None (no pipeline found: it runs on another computer)."""
    import pipeline_link
    pdir = pipeline_link.find_dir(base_dir)
    return os.path.join(str(pdir), PIPELINE_LOCK) if pdir else None


@contextlib.contextmanager
def pipeline_paused(base_dir, path=None):
    """Hold the pipeline's run lock SHARED for the block: no pipeline run can start meanwhile (run.sh's flock -n exits
    at once, and cron tries again 30 minutes later). Raises PipelineBusy at once when a run holds it. The file is only
    opened for reading (the platform never writes the pipeline's folder). Yields True when held; None when it cannot
    be held (no pipeline beside the platform, it never ran, or the file cannot be read): the caller goes on and says so."""
    p = path or pipeline_lock_path(base_dir)
    fd = None
    if p:
        try:
            fd = os.open(p, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError:
            fd = None
    if fd is None:
        yield None
        return
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except OSError:
            raise PipelineBusy(BUSY_TEXT) from None
        yield True
    finally:
        os.close(fd)                                # closing the only descriptor releases the lock


def pipeline_running(base_dir, path=None):
    """True while a pipeline run holds its lock (a quick look: taken and let go at once)."""
    try:
        with pipeline_paused(base_dir, path):
            return False
    except PipelineBusy:
        return True


def table(first=None):
    """The table as text lines (the check prints it; plain words for people)."""
    first = first or datetime.now(timezone.utc).date()
    rows = []
    for j in JOBS:
        locks = ", ".join(f"{k} {'exclusive' if v == 'EX' else 'shared'}" for k, v in j["locks"].items()) or "-"
        rows.append(f"{j['name']:<17} {'HEAVY' if j['heavy'] else 'light':<5} max {j['max_min']:>3} min  "
                    f"lock: {locks:<34} {j['when']}")
    return rows


if __name__ == "__main__":
    for line in table(date.today()):
        print(line)
