#!/usr/bin/env python3
"""New report types (report_types.py): the first run records the starting point without calling anything new; a type
that arrives later for the first time is returned and logged once as new; the same type is never new twice; a broken
state file never stops a run.
Run: .venv/bin/python tests/test_report_types.py"""
import logging, sqlite3, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import report_types as RT  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class Catch(logging.Handler):
    def __init__(self):
        super().__init__(); self.lines = []
    def emit(self, r):
        self.lines.append((r.levelname, r.getMessage()))


log = logging.getLogger("rt"); log.setLevel(logging.INFO); h = Catch(); log.addHandler(h); log.propagate = False
with tempfile.TemporaryDirectory() as d:
    base = Path(d)
    new = RT.note_new(base, ["scan_http", "scan_ssh", "event4_sinkhole"], log)
    ok("the first run records the starting point and calls nothing new", new == [] and any("starting point" in m for _, m in h.lines)
       and not any(l == "WARNING" for l, _ in h.lines), str(h.lines))
    h.lines.clear()
    new = RT.note_new(base, ["scan_http", "scan_ssh", "event4_sinkhole"], log)
    ok("the same types again: nothing new, nothing logged", new == [] and not h.lines, str(h.lines))
    new = RT.note_new(base, ["scan_http", "scan_brandnew", "event4_sinkhole"], log)
    ok("a type arriving for the first time is new, logged as a warning", new == ["scan_brandnew"]
       and any(l == "WARNING" and "NEW REPORT TYPE" in m and "scan_brandnew" in m for l, m in h.lines), str(h.lines))
    h.lines.clear()
    ok("…and never new twice", RT.note_new(base, ["scan_brandnew"], log) == [] and not h.lines)
    rows = dict(sqlite3.connect(str(base / ".mail_state.sqlite")).execute("SELECT name, baseline FROM report_types"))
    ok("recorded with whether it was part of the starting point", rows == {"scan_http": 1, "scan_ssh": 1, "event4_sinkhole": 1, "scan_brandnew": 0}, str(rows))
with tempfile.TemporaryDirectory() as d:
    (Path(d) / ".mail_state.sqlite").write_bytes(b"not a database at all")
    h.lines.clear()
    ok("a broken state file: a warning, an empty answer, no exception", RT.note_new(Path(d), ["scan_x"], log) == []
       and any("could not be recorded" in m for _, m in h.lines))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
