"""How long the pipeline keeps its own copies of report files, and how much disk is left (2026-11-14: sorting_backup
had grown to 954 MB on a live server and only grew).

Every report's rows are in MongoDB once loaded; the sorted CSV in sorting_backup/<report>/ is a second copy. With
SORTED_KEEP_DAYS set (.env; 0 = keep everything, the default, so nobody's evidence goes away on an upgrade), after each
load a sorted file older than that many days is removed, but only when:
  - MongoDB already has rows from that file (by its name, as the loader itself checks), and
  - the file is not waiting in the journal of an interrupted load.
Folders stay (they name the reports). Every removal is one line in data's retention log (retention_removed.jsonl: when,
report, file, size), and the run's summary says how many files and MB went.

status() writes pipeline_status.json after every run: when it finished, whether it went well, the counts, and the free
disk, with a warning below DISK_MIN_FREE_GB (default 5). The platform shows it in the bell (notifications).
"""
import json
import os
import shutil
import time


def keep_days(env):
    try:
        return max(0, int(env("SORTED_KEEP_DAYS", "0") or 0))
    except ValueError:
        return 0


def min_free_gb(env):
    try:
        return max(0.0, float(env("DISK_MIN_FREE_GB", "5") or 0))
    except ValueError:
        return 5.0


def prune_sorted(sorting_dir, base_dir, days, loaded_of, pending, log, now=None):
    """Remove sorted files older than `days` whose rows are in MongoDB. loaded_of(report) -> set of loaded file names
    (None when it cannot be read: nothing of that report is removed). pending: {(report, file)} of the journal.
    Returns (files removed, bytes removed)."""
    if days <= 0 or not os.path.isdir(sorting_dir):
        return 0, 0
    now = now or time.time()
    cutoff = now - days * 86400
    n = size = 0
    note_path = os.path.join(base_dir, "retention_removed.jsonl")
    for report in sorted(os.listdir(sorting_dir)):
        rdir = os.path.join(sorting_dir, report)
        if not os.path.isdir(rdir) or os.path.islink(rdir):
            continue
        old = []
        for root, _dirs, files in os.walk(rdir):
            for fn in files:
                p = os.path.join(root, fn)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if os.path.islink(p) or st.st_mtime >= cutoff:
                    continue
                old.append((p, fn, st.st_size))
        if not old:
            continue
        try:
            loaded = loaded_of(report)
        except Exception as exc:  # noqa: BLE001  (the database could not say: keep everything of this report)
            log.warning("[RETENTION] %s: kept, MongoDB could not list its loaded files (%s)", report, exc.__class__.__name__)
            continue
        if loaded is None:
            continue
        for p, fn, sz in old:
            if fn not in loaded or (report, fn) in pending:
                continue
            try:
                os.remove(p)
            except OSError as exc:
                log.warning("[RETENTION] %s/%s not removed: %s", report, fn, exc.strerror or exc.__class__.__name__)
                continue
            n += 1; size += sz
            try:
                fd = os.open(note_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(json.dumps({"t": round(now), "report": report, "file": fn, "bytes": sz}) + "\n")
            except OSError:
                pass
    if n:
        log.info("[RETENTION] removed %d sorted file(s) older than %d days, %.1f MB (their rows stay in MongoDB)",
                 n, days, size / 1048576)
    return n, size


def free_gb(path):
    try:
        return shutil.disk_usage(path).free / 1024 ** 3
    except OSError:
        return -1.0


def status(base_dir, ok, stats, min_gb, now=None):
    """Write pipeline_status.json (read by the platform's bell). Returns the dict written."""
    now = now or time.time()
    free = free_gb(base_dir)
    st = {"finished": round(now), "ok": bool(ok), "file_errors": int(stats.get("file_errors", 0)),
          "email_failed": int(stats.get("email_failed", 0)), "rows_inserted": int(stats.get("rows_inserted", 0)),
          "pruned_files": int(stats.get("retention_files", 0)), "pruned_mb": round(stats.get("retention_bytes", 0) / 1048576, 1),
          "free_gb": round(free, 1), "min_free_gb": min_gb, "disk_low": bool(min_gb and 0 <= free < min_gb)}
    p = os.path.join(base_dir, "pipeline_status.json")
    tmp = p + ".tmp"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(st, f)
        os.replace(tmp, p)
    except OSError:
        pass
    return st
