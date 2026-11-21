"""The quarterly purge: the raw Shadowserver report rows older than the cutoff are deleted, once per quarter, after the
quarter's report was made and the people who need it had time to download it.

Looking Glass makes the quarterly report once a quarter has ended (the platform's quarterly.py). When every accuracy
check passed (VALID), it writes a PURGE PERMIT into its OWN data folder: data/quarterly/<YYYYQn>/purge_permit.json. It
never writes here, and this module never trusts the permit on its own:

  * The dates are worked out HERE, again, by the same rule: 15 working days (Monday to Friday; public holidays are
    not counted) after the quarter's last day, the purge runs on the next working day; it always keeps the last 31
    days, so the cutoff is the purge day minus 31 days. A permit whose quarter, purge day or cutoff differ from these is
    refused. Nobody can change the timing: there is no setting for it.
  * The purge is OFF until an administrator turns it on in Settings → Quarterly (with their own password). Looking Glass
    then keeps data/quarterly/purge_confirmed.json with "enabled": true; this module reads it read-only, like the
    permit, and refuses unless it says exactly that: missing, unreadable, malformed or "enabled" anything but true is
    refused ("the purge is not turned on in Settings → Quarterly").
  * Nothing happens before the purge day, nor twice for one quarter (this pipeline's own record, below), nor when the
    permit is missing, is not VALID, was made after the purge day, or names a cutoff within 31 days of today.
  * Only report collections are touched: a name the pipeline itself loads reports into (report_names.valid: never
    files_* or discovered_fields_*, never lg_* or system.*), with the row index that starts with filename. Rows are
    chosen by their file name, which starts with the report day (YYYY-MM-DD): filename before the cutoff, through that
    index, one collection at a time. Findings, cases, advisories and everything of the platform's are never touched.
  * What was deleted is recorded per collection in <DATA_DIR>/quarterly_purge_status.json, which the platform reads
    (its admin page, the bell, the audit log). A purge that fails is recorded too and never stops the pipeline's run.
    A refusal names the next quarter and its purge day; when the latest quarter whose purge day has passed had no
    report row before its cutoff at all, the record says "nothing to purge" instead of a refusal.
  * Files dated before the cutoff are not loaded again afterwards (the sorted copies, a mailbox fetched again): the
    loader asks purged_before() and leaves them out.

A forged permit (the platform's data folder is the web service's, which a fault or a break-in could write) can
therefore only start the purge the rules already allow, on the day they allow it: never earlier, never more.

    run(db, platform_data_dir, base_dir, log, today=None)   one check (the pipeline, after loading)
    purged_before(base_dir)                                  "YYYY-MM-DD" or "": rows before it were purged
"""
import datetime as dt
import json
import os
import re
import secrets
import time

import report_names
import worker_settings

KEEP_DAYS = 31                    # the last 31 days are always kept
WORKING_DAYS = 15                 # the grace period after the quarter, in working days (Monday to Friday)
STATUS_FILE = "quarterly_purge_status.json"
CONFIRM_FILE = "purge_confirmed.json"   # in the platform's data/quarterly/: the purge's switch (Settings → Quarterly)
NOT_ON = "the purge is not turned on in Settings → Quarterly"
NO_PERMIT = "no purge permit from Looking Glass for this quarter (its report was not made, or was NOT VALID)"
DATE_PREFIX = re.compile(r"^\d{4}-\d{2}-\d{2}")
NOT_REPORTS = ("files_", "discovered_fields_", "lg_", "system.")


# ------------------------------------------------------------------ the dates (the platform's quarterly.py has the
# same rule; tests/test_quarterly_purge.py checks both agree for every quarter of 2026 to 2029)
def quarter_name(y, q):
    return f"{y}Q{q}"


def parse_quarter(text):
    m = re.fullmatch(r"(\d{4})Q([1-4])", str(text or "").strip().upper())
    if not m:
        raise ValueError("not a quarter (like 2026Q4)")
    return int(m.group(1)), int(m.group(2))


def quarter_end(y, q):
    """The quarter's last day."""
    first_next = dt.date(y + 1, 1, 1) if q == 4 else dt.date(y, 3 * q + 1, 1)
    return first_next - dt.timedelta(days=1)


def working_days_after(d, n):
    k = d
    while n > 0:
        k += dt.timedelta(days=1)
        if k.weekday() < 5:
            n -= 1
    return k


def dates(y, q):
    last = quarter_end(y, q)
    day15 = working_days_after(last, WORKING_DAYS)
    purge = working_days_after(day15, 1)
    return {"last_day": last, "working_day_15": day15, "purge_day": purge, "cutoff": purge - dt.timedelta(days=KEEP_DAYS)}


def due_quarter(today):
    """The latest quarter whose purge day has come (on or before today)."""
    y, q = today.year, (today.month - 1) // 3 + 1
    for _ in range(8):
        y, q = (y - 1, 4) if q == 1 else (y, q - 1)
        if dates(y, q)["purge_day"] <= today:
            return y, q
    return None


def next_quarter(y, q):
    return (y + 1, 1) if q == 4 else (y, q + 1)


def say_day(d):
    """Friday 22 January 2027."""
    return f"{d:%A} {d.day} {d:%B %Y}"


def next_purge_text(due):
    """The quarter after the due one and its purge day, in words: what is waiting next."""
    ny, nq = next_quarter(*due)
    return (f"{quarter_name(ny, nq)} is purged on {say_day(dates(ny, nq)['purge_day'])} if its report is VALID "
            "and the purge is on")


def has_rows_before(db, cutoff_iso):
    """True when a report collection holds a row dated before the cutoff, False when none does, None when that could
    not be read (no database here, or a read failed). Read only, through the filename index; used only for the
    wording of a refusal, never to decide what is deleted."""
    if db is None:
        return None
    try:
        flt = purge_filter(cutoff_iso)
        for name, no in report_collections(db).items():
            if not no and db[name].find_one(flt, {"_id": 1}) is not None:
                return True
        return False
    except Exception:  # noqa: BLE001  (the wording falls back to the plain refusal)
        return None


def purge_filter(cutoff_iso):
    """The rows a purge deletes: the file name starts with a report day before the cutoff (the indexed range; the
    pattern keeps out a name that does not start with a date)."""
    return {"filename": {"$gte": "0000-00-00", "$lt": cutoff_iso, "$regex": "^[0-9]{4}-[0-9]{2}-[0-9]{2}"}}


def report_collections(db):
    """{name: why not} for every collection: "" for a report collection the purge may touch."""
    out = {}
    for n in sorted(db.list_collection_names()):
        if n.startswith(NOT_REPORTS) or not report_names.valid(n):
            out[n] = "not a report collection"
            continue
        try:
            idx = db[n].index_information()
        except Exception as exc:  # noqa: BLE001
            out[n] = f"its indexes could not be read ({exc.__class__.__name__})"
            continue
        if not any((v.get("key") or [("", 0)])[0][0] == "filename" for v in idx.values()):
            out[n] = "no index on filename (never deleted from without one)"
            continue
        out[n] = ""
    return out


# ------------------------------------------------------------------ this pipeline's own record
def _status_path(base_dir):
    return os.path.join(str(base_dir), STATUS_FILE)


def read_status(base_dir):
    try:
        with open(_status_path(base_dir), encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write_status(base_dir, d):
    p = _status_path(base_dir)
    tmp = f"{p}.{secrets.token_hex(4)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=1)
    os.replace(tmp, p)


def purged_before(base_dir):
    """"YYYY-MM-DD": the rows dated before it were purged (files dated before it are not loaded again); "" if none."""
    v = str(read_status(base_dir).get("purged_before") or "")
    return v if DATE_PREFIX.fullmatch(v) else ""


def is_purged(filename, before):
    return bool(before) and bool(DATE_PREFIX.match(filename or "")) and filename[:10] < before


# ------------------------------------------------------------------ the permit (read from the platform's data folder)
def read_permit(platform_data_dir, quarter):
    """The permit as written by the platform, or None. Read like Settings → Workers' requests: never through a
    symbolic link, a plain file only, 64 KB at most (worker_settings.open_dir / read_request)."""
    if not platform_data_dir or not re.fullmatch(r"\d{4}Q[1-4]", quarter):
        return None
    try:
        top = worker_settings.open_dir(os.path.join(str(platform_data_dir), "quarterly"))
    except OSError:
        return None
    try:
        try:
            qfd = worker_settings.open_dir(quarter, dir_fd=top)
        except OSError:
            return None
        try:
            _raw, permit = worker_settings.read_request(qfd, "purge_permit.json")
        finally:
            os.close(qfd)
    finally:
        os.close(top)
    return permit or None


def read_confirmation(platform_data_dir):
    """The purge's switch as written by the platform (data/quarterly/purge_confirmed.json), or None. Read like the
    permit: never through a symbolic link, a plain file only, 64 KB at most; untrusted."""
    if not platform_data_dir:
        return None
    try:
        top = worker_settings.open_dir(os.path.join(str(platform_data_dir), "quarterly"))
    except OSError:
        return None
    try:
        _raw, conf = worker_settings.read_request(top, CONFIRM_FILE)
    finally:
        os.close(top)
    return conf or None


def check_confirmation(conf):
    """"" when an administrator turned the purge on; else why not (anything but "enabled": true is off)."""
    return "" if isinstance(conf, dict) and conf.get("enabled") is True else NOT_ON


def check_permit(permit, quarter, d, today):
    """"" when the permit allows this quarter's purge today; else why not."""
    if not permit:
        return NO_PERMIT
    if permit.get("quarter") != quarter:
        return "the permit names another quarter"
    if permit.get("valid") is not True or permit.get("status") != "VALID":
        return "the permit does not say the report is VALID"
    if permit.get("purge_day") != d["purge_day"].isoformat() or permit.get("cutoff") != d["cutoff"].isoformat():
        return (f"the permit's dates ({permit.get('purge_day')}, cutoff {permit.get('cutoff')}) are not the rule's "
                f"({d['purge_day']}, cutoff {d['cutoff']})")
    made = str(permit.get("generated_at") or "")[:10]
    if not DATE_PREFIX.fullmatch(made) or made > d["purge_day"].isoformat():
        return "the report was not made before the purge day"
    if today < d["purge_day"]:
        return f"before the purge day ({d['purge_day']})"
    if (today - d["cutoff"]).days < KEEP_DAYS:
        return f"the cutoff {d['cutoff']} is within {KEEP_DAYS} days of today: the last {KEEP_DAYS} days are always kept"
    return ""


# ------------------------------------------------------------------ the run
def run(db, platform_data_dir, base_dir, log, today=None, now=None):
    """One check, at the end of a pipeline run. Returns the result written (or {} when nothing was due)."""
    today = today or dt.datetime.now(dt.timezone.utc).date()
    due = due_quarter(today)
    if not due:
        return {}
    quarter = quarter_name(*due)
    d = dates(*due)
    st = read_status(base_dir)
    done = st.get("done") if isinstance(st.get("done"), dict) else {}
    base = {"quarter": quarter, "at": dt.datetime.fromtimestamp(now or time.time(), dt.timezone.utc).isoformat(timespec="seconds"),
            "purge_day": d["purge_day"].isoformat(), "cutoff": d["cutoff"].isoformat(), "keep_days": KEEP_DAYS}
    if quarter in done:
        return dict(base, outcome="already done", why=f"{quarter} was purged on {done[quarter].get('at', '')[:10]}")
    why = (check_confirmation(read_confirmation(platform_data_dir))
           or check_permit(read_permit(platform_data_dir, quarter), quarter, d, today))
    if why:
        # the wording only (what is deleted, and when, is decided above): the latest quarter whose purge day has passed
        # may have had nothing to purge at all (no report row dated before its cutoff: the reports start later), and
        # the quarter actually waiting is the next one; say so, and name it with its purge day
        outcome, nxt = "refused", next_quarter(*due)
        if why == NO_PERMIT and has_rows_before(db, d["cutoff"].isoformat()) is False:
            outcome = "nothing to purge"
            why = (f"Nothing to purge now: no report rows are dated before {say_day(d['cutoff'])}, the cutoff of {quarter}; "
                   f"{next_purge_text(due)}")
        elif why == NO_PERMIT:
            why = f"{NO_PERMIT}; its rows are kept. Next: {next_purge_text(due)}"
        res = dict(base, outcome=outcome, why=why, next_quarter=quarter_name(*nxt),
                   next_purge_day=dates(*nxt)["purge_day"].isoformat())
        last = st.get("last") or {}
        if (last.get("quarter"), last.get("outcome"), last.get("why")) != (quarter, outcome, why):
            log.info("[PURGE] %s: not purged: %s", quarter, why)
        st["last"] = res
        _write_status(base_dir, st)
        return res
    flt = purge_filter(d["cutoff"].isoformat())
    colls, skipped, total = {}, {}, 0
    failed = []
    for name, no in report_collections(db).items():
        if no:
            if not name.startswith(NOT_REPORTS):
                skipped[name] = no
            continue
        try:
            before = db[name].count_documents(flt)
            if not before:
                continue
            n = db[name].delete_many(flt).deleted_count
            colls[name] = {"matched": before, "deleted": n}
            total += n
        except Exception as exc:  # noqa: BLE001  (recorded; the others carry on)
            failed.append(name)
            colls[name] = {"error": exc.__class__.__name__}
    res = dict(base, outcome="failed" if failed else "done", rows_deleted=total, collections=colls,
               collections_touched=sum(1 for v in colls.values() if v.get("deleted")), skipped=skipped,
               why=("could not delete from: " + ", ".join(failed)) if failed else "")
    st["last"] = res
    if not failed:
        done[quarter] = res
        st["done"] = done
        st["purged_before"] = max(str(st.get("purged_before") or ""), d["cutoff"].isoformat())
    _write_status(base_dir, st)
    log.info("[PURGE] %s: %s rows deleted from %d collections, rows dated before %s%s", quarter, f"{total:,}",
             res["collections_touched"], d["cutoff"], f"; FAILED: {', '.join(failed)}" if failed else "")
    return res


def run_safely(make_db, platform_data_dir, base_dir, log, today=None):
    """run(), never raising: a purge that cannot run is recorded and logged, and the pipeline's run goes on."""
    try:
        return run(make_db(), platform_data_dir, base_dir, log, today)
    except Exception as exc:  # noqa: BLE001
        log.warning("[PURGE] the quarterly purge check could not run this time: %s", exc.__class__.__name__)
        try:
            st = read_status(base_dir)
            st["last"] = {"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "outcome": "failed",
                          "why": f"the check could not run ({exc.__class__.__name__})"}
            _write_status(base_dir, st)
        except OSError:
            pass
        return {}
