"""Report names that may become a folder and a MongoDB collection (external review, 2026-11-11).

A report's name is cut out of its file name (2026-11-10-scan_http-ghana-geo.csv -> scan_http) and becomes the folder
sorting_backup/<name>/ and the collection <name>. Before, any characters were taken: a file named
2026-11-10-scan$x-ghana-geo.csv (by accident, or sent on purpose to the mailbox) made MongoDB refuse the collection
name, the load stopped there, and stopped again on every later run until someone removed the file by hand.

Shadowserver's report names are lowercase letters, digits and underscores (scan_http, event4_sinkhole_http,
device_id6). A file whose name is anything else is moved to quarantine/report-names/ with a note of why, never
loaded, and never met again on the next run.
"""
import re
import shutil
import time
from pathlib import Path

VALID = re.compile(r"^[a-z0-9][a-z0-9_]{0,63}$")
FOLDER = "report-names"


def valid(name: str) -> bool:
    return bool(VALID.match(name or ""))


def why(name: str) -> str:
    return (f"its report name {name!r} is not a Shadowserver report name (lowercase letters, digits and underscores, "
            "at most 64 characters), so it cannot become a folder and a MongoDB collection")


def quarantine(path, base_dir, name: str) -> Path:
    """Move a file (or a whole sorting folder) with an unusable report name to quarantine/report-names/, with a note."""
    path = Path(path)
    q = Path(base_dir) / "quarantine" / FOLDER
    q.mkdir(parents=True, exist_ok=True)
    dst = q / path.name
    if dst.exists():
        dst = q / f"{int(time.time())}-{path.name}"
    shutil.move(str(path), str(dst))
    dst.with_name(dst.name + ".reason.txt").write_text(
        f"{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}  not loaded: {why(name)}.\n"
        "If it is a genuine report, rename the file to its Shadowserver report name and move it back into "
        "attachments_backup/.\n", encoding="utf-8")
    return dst
