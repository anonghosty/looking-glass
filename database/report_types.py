"""New Shadowserver report types: noticed the first time one arrives, whether by e-mail or through the report API.

Every report file is sorted into sorting_backup/<type>/ by its name (for example 2026-11-11-scan_http-example-geo.csv
goes to scan_http/). After each run's sorting, the types present are compared with those seen before (table
report_types in .mail_state.sqlite): a type never seen before is logged as a WARNING ("new report type") and recorded
with the day it first arrived. The platform's Audit portal (Sender check) lists the new ones and says whether its report
map (the definitions, kept current from Shadowserver's schema through the feed on GitHub) knows them yet. Nothing is
held back: a new report is loaded like any other, it only has no definition until the feed carries it.

The first run on an installation records what is there without calling it new (the starting point).
"""
import datetime as dt
import sqlite3
from pathlib import Path


class Types:
    def __init__(self, path: Path):
        self.db = sqlite3.connect(str(path))
        self.db.execute("CREATE TABLE IF NOT EXISTS report_types (name TEXT PRIMARY KEY, first_seen TEXT, baseline INTEGER)")
        self.db.commit()

    def note(self, names) -> list:
        """Record the types present; returns those never seen before (none on the very first run: the baseline)."""
        names = sorted({n for n in names if n})
        known = {r[0] for r in self.db.execute("SELECT name FROM report_types")}
        first_run = not known
        new = [n for n in names if n not in known]
        now = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        self.db.executemany("INSERT OR IGNORE INTO report_types VALUES (?, ?, ?)", [(n, now, 1 if first_run else 0) for n in new])
        self.db.commit()
        return [] if first_run else new

    def close(self) -> None:
        self.db.close()


def note_new(base_dir: Path, names, log) -> list:
    """Called after sorting with the report types present; logs and returns the new ones. Never stops a run."""
    try:
        t = Types(Path(base_dir) / ".mail_state.sqlite")
        try:
            first = not t.db.execute("SELECT 1 FROM report_types LIMIT 1").fetchone()
            new = t.note(names)
        finally:
            t.close()
    except Exception as exc:  # noqa: BLE001
        log.warning("Report types could not be recorded: %s", exc)
        return []
    if first:
        log.info("Report types: %d recorded as the starting point (new ones are reported from now on)", len(set(names)))
    for n in new:
        log.warning("NEW REPORT TYPE from Shadowserver: %s (first time it arrived here; it is loaded like any other; "
                    "the Audit portal's Sender check says whether the report definitions know it yet)", n)
    return new
