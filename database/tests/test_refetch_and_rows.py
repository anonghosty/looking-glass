#!/usr/bin/env python3
"""Two pipeline fixes of the 2026-11-13 review, without MongoDB or a mailbox:
- a downloaded file that is broken every time is fetched again at most MailState.REFETCH_MAX times, then left alone
  (it was deleted and fetched again on every run, for ever)
- a CSV that has a non-UTF-8 byte after the first batches is read again with the bytes replaced: its rows are counted
  once, and the rows this run already inserted are not counted as "already in DB" (they were counted twice)
Run: .venv/bin/python tests/test_refetch_and_rows.py"""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import mail_sources  # noqa: E402
import shadowserver_pipeline as P  # noqa: E402
from pymongo.errors import BulkWriteError  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


with tempfile.TemporaryDirectory() as t:
    print("A file broken every time is fetched again a few times, then left alone")
    st = mail_sources.MailState(Path(t, "state.sqlite"))
    for k in range(5):
        st.mark_messages(["msg-1"]); st.mark_files([("report.zip", "msg-1")])
        n = st.forget_file("report.zip")
        if k < mail_sources.MailState.REFETCH_MAX:
            ok(f"broken time {k + 1}: its e-mail is reopened (fetched again next run)", n > 0 and "msg-1" not in st.done_messages(), str(n))
        else:
            ok(f"broken time {k + 1}: given up, its e-mail stays done (no endless re-downloads)", n == -1 and "msg-1" in st.done_messages(), str(n))
    other = st.forget_file("never-saved.zip")
    ok("a file the record never saw: nothing to reopen", other == 0, str(other))
    st.close()

    print("A CSV read again after a bad byte: every row counted once")
    csv_path = Path(t, "2026-11-13-scan_x-gh.csv")
    rows = [f"2026-11-13 10:{i // 60:02d}:{i % 60:02d},192.0.2.{i % 250},{'x' * 40},{i}" for i in range(600)]
    data = ("timestamp,ip,pad,n\n" + "\n".join(rows[:500]) + "\n").encode() + b"\xff\xfe broken\n" + ("\n".join(rows[500:]) + "\n").encode()
    csv_path.write_bytes(data)

    class Coll:
        name = "scan_x"

        def __init__(self):
            self.keys = set()

        def insert_many(self, docs, ordered=False):
            new = [d for d in docs if d["line_hash"] not in self.keys]
            self.keys.update(d["line_hash"] for d in new)
            dup = len(docs) - len(new)
            if dup:
                raise BulkWriteError({"writeErrors": [{"code": 11000}] * dup, "nInserted": len(new)})
            return type("R", (), {"inserted_ids": [0] * len(new)})()

    P._WORKER_DB = {"scan_x": Coll()}
    res = P.load_file("scan_x", str(csv_path), csv_path.name, 50)
    total = 600                                     # the broken line has no readable timestamp: skipped, as always
    ok("the bad byte was met after some rows were inserted (the case of the review)", "non-UTF-8 bytes replaced" in res["notes"], str(res["notes"]))
    ok(f"rows counted once: {res['rows']} (the file has {total})", res["rows"] == total, str(res))
    ok("inserted: every row once", res["inserted"] == len(P._WORKER_DB["scan_x"].keys) == total, str(res))
    ok("no row of this run counted as 'already in DB'", res["duplicates"] == 0, str(res))
    res2 = P.load_file("scan_x", str(csv_path), csv_path.name, 50)
    ok("loading the same file again: every row 'already in DB', counted once", res2["rows"] == total and res2["duplicates"] == total
       and res2["inserted"] == 0, str(res2))

print("Retry-After from the mailbox's server: seconds or a date, never a crash (review 2026-11-13)")
import datetime as _dt  # noqa: E402
from email.utils import format_datetime  # noqa: E402
soon = format_datetime(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=20), usegmt=True)
for v, want in (("30", 30), ("0", 4), ("900", 60), (None, 4), ("", 4), ("soon", 4), ("Wed, 21 Oct 2015 07:28:00 GMT", 4), (soon, None)):
    try:
        got = mail_sources._retry_after(v, 4)
        good = (1 <= got <= 60 and abs(got - 20) <= 2) if want is None else got == want
        ok(f"Retry-After {v!r} -> wait {got}s", good, str(got))
    except Exception as e:      # noqa: BLE001
        ok(f"Retry-After {v!r}", False, f"{type(e).__name__}: {e}")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
