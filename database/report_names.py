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
# The pipeline's own bookkeeping collections: files_<report> (the files loaded) and discovered_fields_<report> (the
# columns seen). A report named like them would be loaded on top of them and mistaken for them (external review,
# 2026-11-11), so such a name is refused too. No Shadowserver report is named like that.
RESERVED = ("files_", "discovered_fields_")
FOLDER = "report-names"


def canonical(name: str) -> str:
    """The collection name for a report name from a file name. Shadowserver's one-off Special Reports come as
    "YYYY-MM-DD-special[-<name>]-...": "special-<name>" becomes "special_<name>" (hyphens are not allowed in a report
    name), so a Special Report is loaded into its own collection instead of quarantined. The platform keeps every
    "special*" collection out of the daily replay and lists it apart (special_reports.py). Others are unchanged."""
    n = name or ""
    if n.lower().startswith("special-"):
        return re.sub(r"[^a-z0-9_]", "_", n.lower())[:64]
    return n


def learn_tails(sorting_dir, limit: int = 400) -> set:
    """The country parts of the ordinary reports already sorted (a few files of each report folder)."""
    import os
    out = set()
    try:
        for d in os.scandir(sorting_dir):
            if not d.is_dir() or d.name.startswith("special"):
                continue
            for i, f in enumerate(os.scandir(d.path)):
                if i >= 3 or len(out) >= limit:
                    break
                t = country_tail(f.name, d.name)
                if t:
                    out.add(t)
    except OSError:
        pass
    return out


_CORE = re.compile(r"^\d{4}-\d{2}-\d{2}-(.+?)(?:_as\d+)?\.csv$")


def country_tail(filename: str, service: str):
    """The part after the report name in an ordinary report's file name ("2026-11-10-scan_http-123-ghana-geo.csv",
    "scan_http" -> "ghana-geo"), or None. An ordinary report name has no hyphen, so this split is exact; it tells
    where the name of a Special Report ends (special_name)."""
    m = _CORE.match(filename or "")
    if not m or not service or service.startswith("special") or not m.group(1).startswith(service + "-"):
        return None
    rest = re.sub(r"^\d+-", "", m.group(1)[len(service) + 1:])      # Shadowserver's number for the recipient
    return rest or None


def special_name(filename: str, first: str, tails=()) -> str:
    """The collection name of a report, from its file name and the name the file pattern found (`first`).
    For a Special Report the pattern stops at the first word ("special-badbox-ghana-geo" -> "special"), because the
    country part may hold hyphens too (south-africa-geo), so every Special Report landed in one "special" collection
    (review 2026-11-13). Its name is cut where the country part begins: one learnt from the ordinary reports (`tails`,
    longest first), or else the last word before "-geo". Others: canonical(first)."""
    if not (first or "").lower().startswith("special"):
        return canonical(first)
    m = _CORE.match(filename or "")
    core = m.group(1).lower() if m else ""
    head = None
    for t in sorted({t.lower() for t in tails if t}, key=len, reverse=True):
        if core.endswith("-" + t) and len(core) > len(t) + 1:
            head = core[:-len(t) - 1]
            break
    if head is None and core.endswith("-geo"):
        head = re.sub(r"-[a-z0-9_]+-geo$", "", core)
    if not head or not head.startswith("special"):
        return canonical(first)
    head = re.sub(r"-\d+$", "", head)                               # Shadowserver's number for the recipient
    return canonical(head) if head != "special" else "special"


def valid(name: str) -> bool:
    return bool(VALID.match(name or "")) and not (name or "").startswith(RESERVED)


def why(name: str) -> str:
    if (name or "").startswith(RESERVED):
        return (f"its report name {name!r} starts with {next(p for p in RESERVED if name.startswith(p))!r}, the name of "
                "the pipeline's own bookkeeping collections, so loading it would mix with them")
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
