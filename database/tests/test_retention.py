#!/usr/bin/env python3
"""Sorted copies are removed only when old, in MongoDB, and not waiting to load; folders, other files and symlinks stay;
every removal is noted; the status file says how the run went and warns on low disk (retention.py). No database.
Run: .venv/bin/python tests/test_retention.py"""
import json, logging, os, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import retention  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


log = logging.getLogger("t"); log.addHandler(logging.NullHandler())
base = tempfile.mkdtemp(prefix="lg-retention-")
try:
    srt = os.path.join(base, "sorting_backup"); now = time.time(); old = now - 100 * 86400
    files = {("scan_http", "old-loaded.csv"): old, ("scan_http", "old-not-loaded.csv"): old, ("scan_http", "new-loaded.csv"): now,
             ("scan_http", "old-pending.csv"): old, ("event4_sinkhole", "old-db-error.csv"): old,
             ("scan_ssh", "old-loaded2.csv"): old}
    for (r, f), t in files.items():
        os.makedirs(os.path.join(srt, r), exist_ok=True)
        p = os.path.join(srt, r, f); open(p, "w").write("a,b\n" * 50); os.utime(p, (t, t))
    outside = os.path.join(base, "outside.csv"); open(outside, "w").write("keep"); os.utime(outside, (old, old))
    os.symlink(outside, os.path.join(srt, "scan_http", "old-link.csv"))

    def loaded_of(report):
        if report == "event4_sinkhole":
            raise RuntimeError("MongoDB gone")
        return {"scan_http": {"old-loaded.csv", "new-loaded.csv", "old-pending.csv", "old-link.csv"},
                "scan_ssh": {"old-loaded2.csv"}}.get(report, set())

    print("Off by default")
    ok("SORTED_KEEP_DAYS unset: keep everything", retention.keep_days(lambda k, d="": d) == 0)
    ok("…a bad value too", retention.keep_days(lambda k, d="": "lots") == 0)
    ok("days 0 removes nothing", retention.prune_sorted(srt, base, 0, loaded_of, set(), log) == (0, 0))
    print("90 days")
    n, size = retention.prune_sorted(srt, base, 90, loaded_of, {("scan_http", "old-pending.csv")}, log, now=now)
    there = lambda r, f: os.path.lexists(os.path.join(srt, r, f))  # noqa: E731
    ok("an old file whose rows are in MongoDB is removed", not there("scan_http", "old-loaded.csv") and not there("scan_ssh", "old-loaded2.csv"))
    ok("an old file not in MongoDB stays", there("scan_http", "old-not-loaded.csv"))
    ok("a recent file stays", there("scan_http", "new-loaded.csv"))
    ok("a file waiting in the load journal stays", there("scan_http", "old-pending.csv"))
    ok("when MongoDB cannot say, the report's files stay", there("event4_sinkhole", "old-db-error.csv"))
    ok("a symlink is never followed or removed, its target untouched", there("scan_http", "old-link.csv") and os.path.exists(outside))
    ok("the folders stay", all(os.path.isdir(os.path.join(srt, r)) for r in ("scan_http", "scan_ssh", "event4_sinkhole")))
    ok("the count and size are returned", n == 2 and size == 2 * len("a,b\n" * 50), f"{n} {size}")
    notes = [json.loads(x) for x in open(os.path.join(base, "retention_removed.jsonl"))]
    ok("every removal is noted with report, file and size", {(x["report"], x["file"]) for x in notes} == {("scan_http", "old-loaded.csv"), ("scan_ssh", "old-loaded2.csv")}
       and all(x["bytes"] > 0 and x["t"] for x in notes))
    ok("the note file is private (600)", oct(os.stat(os.path.join(base, "retention_removed.jsonl")).st_mode & 0o777) == "0o600")
    print("The run's status")
    st = retention.status(base, True, {"rows_inserted": 15, "retention_files": 2, "retention_bytes": 3 * 1048576}, 5, now=now)
    got = json.load(open(os.path.join(base, "pipeline_status.json")))
    ok("written with when, how it went, counts and free disk", got == st and got["ok"] and got["rows_inserted"] == 15
       and got["pruned_files"] == 2 and got["pruned_mb"] == 3.0 and got["free_gb"] >= 0)
    ok("plenty of disk: no warning", not got["disk_low"])
    st = retention.status(base, False, {"file_errors": 1}, 10 ** 9)
    ok("a failed run and low disk are both said", not st["ok"] and st["file_errors"] == 1 and st["disk_low"])
    ok("DISK_MIN_FREE_GB defaults to 5", retention.min_free_gb(lambda k, d="": d) == 5.0)
    ok("the status file is private (600)", oct(os.stat(os.path.join(base, "pipeline_status.json")).st_mode & 0o777) == "0o600")
finally:
    shutil.rmtree(base, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
