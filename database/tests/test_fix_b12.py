#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The pipeline fixes of the whole-codebase audit, batch 12 (2026-11-27). Each check fails on the code before the fix.

  12-1  a CSV field over 128 KB no longer stops the rest of the report; a row that cannot be read is counted
  12-2  Block mode with the sender check unavailable: the mailbox is not read (with its reason), the run goes on
  12-3  a purge that fails part way records its cutoff first, so the loader does not put the deleted rows back
  12-4  the pipeline takes the run lock itself (a second run exits), and uses run.sh's when it inherited it
  12-5  an inline logo (any non-report attachment) no longer stops the report link being fetched
  12-6  IMAP messages are fetched by UID (an expunge cannot shift contents to another key); refused batches counted
  12-7  a file that stops its worker process is loaded alone, then quarantined (on its second such run, review r2); the
        others load; less memory per row
  12-8  the defaults the pipeline uses are the ones Settings → Workers shows (EMAIL_DAYS 7)
  12-9  store_mongo_admin.sh signs in through db_connect.py (TLS, no plaintext to another computer)
  12-10 the pipeline's MongoDB account gets a role of its own without drop/rename, and running installs can switch
  12-11 rows written before a dropped connection are counted as inserted, not "already in the database"
  12-12 a zip with a password-protected file is quarantined, not retried for ever
  12-13 CSV columns named like the loader's own fields (_id, filename ...) are kept under another name
  12-14 a file with no row to store (only a header) is not read again on every run
  12-15 the unused IMAP helpers are gone from the pipeline
Made-up files in temporary folders, an in-memory stand-in for MongoDB, a fake mail server and a fake pymongo for the
sign-in check: no database, no mailbox, no network.
Run: .venv/bin/python tests/test_fix_b12.py"""
import argparse
import csv
import email
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tracemalloc
import types
import zipfile
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from concurrent.futures.process import BrokenProcessPool
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import mail_sources  # noqa: E402
import quarterly_purge as qp  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402
import worker_settings  # noqa: E402
import zip_limits  # noqa: E402
from pymongo.errors import AutoReconnect, BulkWriteError  # noqa: E402

checks, fails = 0, []
TMP = tempfile.mkdtemp(prefix="lg-fix-b12-")
log = logging.getLogger("t-b12")
log.addHandler(logging.NullHandler())
log.propagate = False


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def attempt(label, fn):
    """Run one group of checks; an exception (the old code's crash) is a failed check, not the end of the test."""
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        ok(f"{label}: ran without an error", False, f"{exc.__class__.__name__}: {str(exc)[:200]}")


def tmpdir(name):
    d = os.path.join(TMP, name)
    os.makedirs(d, exist_ok=True)
    return d


HEAD = '"timestamp","ip","port","asn"\n'


def rows_of(text, name="2026-11-20-scan_x-kenya-geo.csv"):
    d = tempfile.mkdtemp(prefix="rows-", dir=TMP)
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(text.encode("utf-8") if isinstance(text, str) else text)
    info = {}
    out = list(sp.iter_csv_docs(p, name, "scan_x", info=info))
    return out, info


# ------------------------------------------------------------------ an in-memory MongoDB, just what the loader uses
class Coll:
    def __init__(self, name):
        self.name, self.docs, self.keys = name, [], set()

    def create_index(self, *a, **k):
        return "ix"

    def distinct(self, field):
        return sorted({d.get(field) for d in self.docs})

    def find(self, flt=None, proj=None):
        return [dict(d) for d in self.docs]

    def count_documents(self, flt):
        ids = set(map(str, (flt.get("_id") or {}).get("$in", [])))
        return sum(1 for d in self.docs if str(d.get("_id")) in ids)

    def insert_many(self, docs, ordered=False):
        errs, n = [], 0
        ids = {str(x.get("_id")) for x in self.docs}
        for i, d in enumerate(docs):
            d.setdefault("_id", f"oid-{id(d)}")                      # pymongo gives each row its _id, in place
            key = (d.get("filename"), d.get("category"), d.get("line_hash"))
            if ("line_hash" in d and key in self.keys) or str(d["_id"]) in ids:     # the row index, and _id's own
                errs.append({"index": i, "code": 11000, "errmsg": "duplicate"})
            else:
                ids.add(str(d["_id"]))
                self.keys.add(key)
                self.docs.append(dict(d))
                n += 1
        if errs:
            raise BulkWriteError({"writeErrors": errs, "nInserted": n})
        return type("R", (), {"inserted_ids": [0] * n})()

    def update_one(self, *a, **k):
        return None

    def bulk_write(self, ops, ordered=False):
        return None


class DB(dict):
    def __missing__(self, name):
        c = self[name] = Coll(name)
        return c


class Client:
    def __init__(self, db):
        self.db = db
        self.admin = type("A", (), {"command": staticmethod(lambda *a, **k: {"ok": 1})})()

    def __getitem__(self, name):
        return self.db

    def close(self):
        pass


def settings(base, workers=1):
    return sp.Settings(env_file=Path(base) / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                       imap_verify_tls=True, mongo={}, mongo_db="x", mongo_cache_gb=0.25, base_dir=Path(base),
                       workers=workers, insert_chunk=3, download_threads=1, fetch_batch=5, days=1)


def run_load(s, db, executor=ThreadPoolExecutor):
    """load_into_mongo with the stand-in database, in threads (no worker processes)."""
    stats = Counter()

    def init(*_a):
        sp._WORKER_DB = db
    with mock.patch.object(sp, "mongo_client", lambda *a, **k: Client(db)), \
            mock.patch.object(sp, "ProcessPoolExecutor", executor), \
            mock.patch.object(sp, "_init_worker", init):
        sp.load_into_mongo(s, stats)
    return stats


# ================================================================== 12-1
def t_12_1():
    print("12-1: a CSV field over 128 KB")
    big = "A" * (200 * 1024)
    out, info = rows_of(HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n'
                        + f'"2026-11-20 01:00:01","192.0.2.2",23,"{big}"\n'
                        + '"2026-11-20 01:00:02","192.0.2.3",23,64500\n')
    ok("a 200 KB field is read: all three rows, the big value whole", len(out) == 3 and out[1]["asn"] == big,
       f"{len(out)} rows")
    before = csv.field_size_limit()
    old_max = getattr(sp, "CSV_FIELD_MAX", None)
    try:
        csv.field_size_limit(1000)
        sp.CSV_FIELD_MAX = 1000
        out, info = rows_of(HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n'
                            + f'"2026-11-20 01:00:01","192.0.2.2",23,"{"B" * 2000}"\n'
                            + '"2026-11-20 01:00:02","192.0.2.3",23,64500\n')
        ok("a row over the field limit is counted (bad_csv) and the rows after it are still read",
           [r["ip"] for r in out] == ["192.0.2.1", "192.0.2.3"] and info.get("bad_csv") == 1 and info.get("rows_read") == 3,
           str({k: info.get(k) for k in ("bad_csv", "rows_read")}))
        base = tmpdir("b12-1-load")
        s = settings(base)
        d = s.sorting_dir / "scan_x"
        d.mkdir(parents=True)
        (d / "2026-11-20-scan_x-kenya-geo.csv").write_text(
            HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n' + f'"2026-11-20 01:00:01","192.0.2.2",23,"{"B" * 2000}"\n'
            + '"2026-11-20 01:00:02","192.0.2.3",23,64500\n', encoding="utf-8")
        st = run_load(s, DB())
        ok("...through the loader: the file is loaded (not a file error retried for ever), its two good rows stored",
           st["file_errors"] == 0 and st["files_loaded"] == 1 and st["rows_inserted"] == 2 and st["rows_bad_csv"] == 1,
           str({k: st[k] for k in ("file_errors", "files_loaded", "rows_inserted", "rows_bad_csv")}))
        ok("...and the run says so (a warning in words)",
           any(w["key"] == "rows_bad_csv" for w in sp.run_problems(st)[1]))
    finally:
        csv.field_size_limit(before)
        if old_max is not None:
            sp.CSV_FIELD_MAX = old_max


# ================================================================== 12-2
class FakeSrc:
    listed = closed = False
    failed = 0

    def list(self, days):
        FakeSrc.listed = True
        return []

    def close(self):
        FakeSrc.closed = True

    def describe(self):
        return "a fake mailbox"

    def fetch(self, items):
        return iter(())


def t_12_2():
    print("12-2: Block mode with the sender check unavailable")
    keep = {k: os.environ.get(k) for k in ("MAIL_AUTH", "REPORT_SOURCE", "SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET")}

    def broken_log(*a, **k):
        raise OSError("database is locked")
    base = Path(tmpdir("b12-2"))
    s = types.SimpleNamespace(attachments_dir=base / "att", base_dir=base, days=1, download_threads=1,
                              zip_limits=zip_limits.Limits())
    try:
        os.environ["MAIL_AUTH"] = "enforce"
        for k in ("REPORT_SOURCE", "SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET"):
            os.environ.pop(k, None)
        with mock.patch.object(sp.mail_sources, "make_source", lambda env=None: FakeSrc()), \
                mock.patch.object(sp.mail_auth, "Log", broken_log):
            stats = Counter()
            try:
                sp.fetch_reports(s, stats)
                raised = None
            except Exception as exc:  # noqa: BLE001
                raised = f"{exc.__class__.__name__}: {exc}"
            ok("the run goes on (the files already on disk are still loaded): no exception out of fetch_reports",
               raised is None, raised or "")
            ok("...no e-mail is read, and the mailbox counts as not read, with the reason for the bell",
               not FakeSrc.listed and stats["email_failed"] == 1 and "Block mode" in str(stats.get("email_error")),
               str(dict(stats)))
            errs = sp.run_problems(stats)[0]
            ok("...the run's error names the reason", any(e["key"] == "email_failed" and "sender check" in e["text"]
                                                         for e in errs), str(errs))
            try:
                sp.pull_emails(s, Counter())
                kinds = None
            except Exception as exc:  # noqa: BLE001
                kinds = (isinstance(exc, mail_sources.MailSourceError), isinstance(exc, RuntimeError),
                         "no e-mail is read" in str(exc))
            ok("...pull_emails itself still refuses to read unchecked mail (a MailSourceError, still a RuntimeError)",
               kinds == (True, True, True), str(kinds))
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ================================================================== 12-3
class PColl:
    def __init__(self, rows, fail=False):
        self.rows, self.fail = list(rows), fail

    def index_information(self):
        return {"_id_": {"key": [("_id", 1)]},
                "row": {"key": [("filename", 1), ("category", 1), ("line_hash", 1)], "unique": True}}

    @staticmethod
    def _match(r, flt):
        f = flt["filename"]
        return f["$gte"] <= r["filename"] < f["$lt"] and re.match(f["$regex"], r["filename"])

    def count_documents(self, flt):
        return sum(1 for r in self.rows if self._match(r, flt))

    def delete_many(self, flt):
        if self.fail:
            raise RuntimeError("simulated: the connection dropped")
        keep = [r for r in self.rows if not self._match(r, flt)]
        n = len(self.rows) - len(keep)
        self.rows = keep
        return types.SimpleNamespace(deleted_count=n)

    def find_one(self, flt, proj=None):
        return next((r for r in self.rows if self._match(r, flt)), None)


class PDB(dict):
    def list_collection_names(self):
        return list(self)


def t_12_3():
    print("12-3: a purge that fails part way")
    root = tmpdir("b12-3")
    data, base = os.path.join(root, "platform", "data"), os.path.join(root, "pipeline")
    os.makedirs(os.path.join(data, "quarterly", "2026Q4"))
    os.makedirs(base)
    with open(os.path.join(data, "quarterly", "2026Q4", "purge_permit.json"), "w", encoding="utf-8") as fh:
        json.dump({"quarter": "2026Q4", "valid": True, "status": "VALID", "purge_day": "2027-01-22", "cutoff": "2026-12-22",
                   "generated_at": "2027-01-01T00:10:00+00:00"}, fh)
    with open(os.path.join(data, "quarterly", qp.CONFIRM_FILE), "w", encoding="utf-8") as fh:
        json.dump({"enabled": True}, fh)
    lock = os.path.join(root, ".pipeline.lock")
    open(lock, "w").close()
    old_rows = [{"filename": "2026-12-01-scan_a-kenya-geo.csv"}, {"filename": "2026-12-02-scan_a-kenya-geo.csv"}]
    db = PDB(scan_a=PColl(old_rows), scan_b=PColl([{"filename": "2026-12-01-scan_b-kenya-geo.csv"}], fail=True))
    res = qp.run(db, data, base, log, today=qp.dates(2026, 4)["purge_day"], run_lock=lock)
    ok("the purge ran and failed on one collection (scan_b), deleted from the other (scan_a)",
       res.get("outcome") == "failed" and not db["scan_a"].rows and db["scan_b"].rows, str(res)[:200])
    ok("...its cutoff is recorded all the same, so files dated before it are not loaded again (scan_a's rows stay gone)",
       qp.purged_before(base) == "2026-12-22" and qp.is_purged("2026-12-01-scan_a-kenya-geo.csv", qp.purged_before(base)),
       repr(qp.purged_before(base)))
    ok("...the quarter is not marked done: it is tried again", "2026Q4" not in (qp.read_status(base).get("done") or {}))
    db["scan_b"].fail = False
    res = qp.run(db, data, base, log, today=qp.dates(2026, 4)["purge_day"], run_lock=lock)
    ok("...and the next run finishes it", res.get("outcome") == "done" and not db["scan_b"].rows
       and "2026Q4" in (qp.read_status(base).get("done") or {}), str(res)[:200])


# ================================================================== 12-4
def t_12_4():
    print("12-4: one run at a time, also without run.sh")
    root = tmpdir("b12-4")
    lock = os.path.join(root, ".pipeline.lock")
    envf = os.path.join(root, ".env")
    with open(envf, "w", encoding="utf-8") as fh:
        fh.write(f"DATA_DIR={root}\n")
    holder = subprocess.Popen([sys.executable, "-c", "import fcntl, os, sys, time\n"
                               f"fd = os.open({lock!r}, os.O_WRONLY | os.O_CREAT, 0o600)\n"
                               "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(60)\n"],
                              stdout=subprocess.PIPE, text=True)
    calls = []
    keep_env = os.environ.get("DATA_DIR")
    try:
        ok("(another run holds the lock)", holder.stdout.readline().strip() == "held")
        with mock.patch.object(qp, "RUN_LOCK", lock), \
                mock.patch.object(sp, "load_into_mongo", lambda s, st: calls.append("load")), \
                mock.patch.object(sp, "prune_sorted_backup", lambda s, st: None), \
                mock.patch.object(sp.quarterly_purge, "run_safely", lambda *a, **k: {}):
            rc = sp.main(["--stage", "load", "--env-file", envf, "-q"])
            ok("a second run started without run.sh exits (code 1) and loads nothing", rc == 1 and not calls,
               f"rc={rc}, calls={calls}")
            holder.kill()
            holder.wait(10)
            rc = sp.main(["--stage", "load", "--env-file", envf, "-q"])
            ok("...once the other run is over, it runs", rc == 0 and calls == ["load"], f"rc={rc}, calls={calls}")
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(10)
        if keep_env is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = keep_env
    # run.sh's way: the lock taken in the shell (exec 9>.pipeline.lock; flock -n 9), the script inherits it
    lock2 = os.path.join(root, "inherited.lock")
    code = ("import sys; sys.path.insert(0, %r); import shadowserver_pipeline as sp; "
            "print(sp.hold_run_lock(%r) is not None)" % (HERE, lock2))
    try:
        sh = subprocess.run(["bash", "-c", 'exec 9>"$1"; flock -n 9 || exit 9; "$2" -c "$3"', "_", lock2, sys.executable, code],
                            capture_output=True, text=True, timeout=60)
        ok("started by run.sh (the lock inherited): the script uses it and runs", sh.stdout.strip() == "True",
           (sh.stdout + sh.stderr)[-300:])
        sh = subprocess.run(["bash", "-c", 'flock "$1" sleep 20 & sleep 1; "$2" -c "$3"; kill $! 2>/dev/null; wait',
                             "_", lock2, sys.executable, code], capture_output=True, text=True, timeout=60)
        ok("...while another process holds it (not inherited): refused", sh.stdout.strip() == "False",
           (sh.stdout + sh.stderr)[-300:])
    except Exception as exc:  # noqa: BLE001
        ok("the inherited lock checks ran", False, str(exc))


# ================================================================== 12-5
def t_12_5():
    print("12-5: an inline logo and the report link")
    msg = MIMEMultipart("related")
    msg["Subject"] = "Shadowserver report"
    msg.attach(MIMEText('<p>Your report: <a href="https://dl.shadowserver.org/AbCdEf012345">download</a></p>', "html"))
    img = MIMEImage(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32, "png")
    img.add_header("Content-Disposition", "inline", filename="logo.png")
    msg.attach(img)
    links, names = set(), []
    d = Path(tmpdir("b12-5"))
    sp._handle_message(email.message_from_bytes(msg.as_bytes()), d, Counter(), links, "1/1", names)
    ok("the e-mail's report link is collected although it carries an inline logo",
       links == {"https://dl.shadowserver.org/AbCdEf012345"}, str(links))
    msg2 = MIMEMultipart()
    msg2.attach(MIMEText("Report attached; also at https://dl.shadowserver.org/XyZ987", "plain"))
    part = email.message.Message()
    part.set_payload(b"PK\x05\x06" + b"\x00" * 18)
    part.add_header("Content-Type", "application/zip")
    part.add_header("Content-Disposition", "attachment", filename="2026-11-20-scan_x-kenya-geo.zip")
    msg2.attach(part)
    links2 = set()
    sp._handle_message(email.message_from_bytes(msg2.as_bytes()), d, Counter(), links2, "2/2", [])
    ok("...an e-mail with the report attached still needs no link download (unchanged)", links2 == set(), str(links2))


# ================================================================== 12-6
def t_12_6():
    print("12-6: IMAP by UID")
    raw102 = b"Subject: report 102\r\n\r\nbody of 102\r\n"

    class FakeImap:
        """Message 101 was expunged by another client after the listing: sequence number 1 is now UID 102."""
        def __init__(self, refuse=False):
            self.refuse = refuse

        def fetch(self, ids, what):
            return "OK", [(b"1 (UID 102 BODY[] {30}", raw102), b")"]

        def uid(self, cmd, ids, what):
            assert cmd.upper() == "FETCH"
            if self.refuse:
                return "NO", [b"server busy"]
            wanted = ids.split(",")
            return "OK", [(b"1 (UID 102 BODY[] {30}", raw102), b")"] if "102" in wanted else []

    src = mail_sources.ImapSource({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "u", "IMAP_PASSWORD": "p"})
    src.imap, src.uidvalidity = FakeImap(), "7"
    # the keys list() found with their UID (review r2: a flag from list(), never parsed from the key's text)
    src.uids = {"imap:7:101": b"101", "imap:7:102": b"102", "imap:7:103": b"103"}
    got = list(src.fetch([("imap:7:101", b"1"), ("imap:7:102", b"2")]))
    ok("each content comes under its own message's key (102's content never under 101's)",
       got == [("imap:7:102", raw102)], str([k for k, _ in got]))
    # review r2: a message deleted meanwhile is gone (a warning), not one to try again (an error)
    ok("...the message gone meanwhile is counted as gone, not as not fetched",
       getattr(src, "gone", None) == 1 and getattr(src, "failed", None) == 0,
       str((getattr(src, "gone", None), getattr(src, "failed", None))))
    uids = src.uids
    src = mail_sources.ImapSource({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "u", "IMAP_PASSWORD": "p",
                                   "IMAP_FETCH_BATCH": "2"})
    src.uids = uids
    src.imap, src.uidvalidity = FakeImap(refuse=True), "7"
    got = list(src.fetch([("imap:7:101", b"1"), ("imap:7:102", b"2"), ("imap:7:103", b"3")]))
    ok("a batch the server refuses is counted (3 not fetched), not skipped in silence",
       got == [] and getattr(src, "failed", None) == 3, str(getattr(src, "failed", None)))
    st = Counter({"emails_not_fetched": 3})
    ok("...and it is an error of the run, in words",
       any(e["key"] == "emails_not_fetched" and "could not be fetched" in e["text"] for e in sp.run_problems(st)[0]))


# ================================================================== 12-7
class CrashPool(ThreadPoolExecutor):
    """A pool whose worker 'dies' on any file with 'bomb' in its name (as the kernel ends one out of memory). The other
    files are loaded before submit returns, so the test does not depend on thread timing."""
    def __init__(self, max_workers=None, initializer=None, initargs=()):
        self.initializer, self.initargs = initializer, initargs

    def submit(self, fn, *args, **kw):
        f = Future()
        if "bomb" in str(args[2] if len(args) > 2 else ""):
            f.set_exception(BrokenProcessPool("A process in the process pool was terminated abruptly"))
            return f
        if self.initializer:
            self.initializer(*self.initargs)
        try:
            f.set_result(fn(*args, **kw))
        except Exception as exc:  # noqa: BLE001
            f.set_exception(exc)
        return f

    def shutdown(self, wait=True, cancel_futures=False):
        pass


def t_12_7():
    print("12-7: a file that stops its worker process; memory per row")
    base = tmpdir("b12-7")
    s = settings(base, workers=2)
    d = s.sorting_dir / "scan_x"
    d.mkdir(parents=True)
    good = ["2026-11-20-scan_x-kenya-geo.csv", "2026-11-21-scan_x-kenya-geo.csv"]
    for i, fn in enumerate(good):
        (d / fn).write_text(HEAD + f'"2026-11-2{i} 01:00:00","192.0.2.{i + 1}",23,64500\n', encoding="utf-8")
    bomb = "2026-11-22-scan_x-bomb-kenya-geo.csv"
    (d / bomb).write_text(HEAD + '"2026-11-22 01:00:00","192.0.2.9",23,64500\n', encoding="utf-8")
    db = DB()
    try:
        st = run_load(s, db, CrashPool)
        raised = None
    except BrokenProcessPool as exc:
        st, raised = Counter(), str(exc)
    ok("the load is not stopped by the worker that died", raised is None, raised or "")
    ok("...the other files are loaded", st["files_loaded"] == 2 and st["rows_inserted"] == 2, str(dict(st))[:300])
    # review r2: quarantined only once it stopped its worker alone on a second run (a file error on the first)
    ok("...on the first run it is a file error, tried again next run (not quarantined yet)",
       st["file_errors"] == 1 and st["files_crashed"] == 0 and (d / bomb).exists(), str(dict(st))[:300])
    st = run_load(s, db, CrashPool)
    q = Path(base) / "quarantine" / "loader" / "scan_x" / bomb
    ok("...the file that stops its worker even alone is moved to quarantine/loader/ with a note, and counted",
       st["files_crashed"] == 1 and q.exists() and q.with_name(q.name + ".reason.txt").exists() and not (d / bomb).exists())
    errs = sp.run_problems(st)[0]
    ok("...an error of the run that names it", any(e["key"] == "files_crashed" and bomb in e["text"] for e in errs),
       str(errs)[:300])
    j = sp.Journal(s.journal_path)
    pend = j.pending()
    j.close()
    ok("...and it is not left in the journal to stop the next run again", ("scan_x", bomb) not in pend, str(pend))
    st2 = run_load(s, db, CrashPool)
    ok("...the next run has nothing left that stops it", st2["files_crashed"] == 0 and st2["file_errors"] == 0,
       str(dict(st2))[:200])


def t_12_7_memory():
    # memory: the rows of a file are remembered while it is read (to tell repeats); per row, measured
    n = 60000
    p = os.path.join(tmpdir("b12-7-mem"), "2026-11-20-scan_x-kenya-geo.csv")
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(HEAD)
        for i in range(n):
            fh.write(f'"2026-11-20 01:00:00","10.{i >> 16}.{(i >> 8) & 255}.{i & 255}",{i},64500\n')
    tracemalloc.start()
    for _ in sp.iter_csv_docs(p, "2026-11-20-scan_x-kenya-geo.csv", "scan_x"):
        pass
    _cur, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    per_row = peak / n
    ok(f"less memory per row while a file is read: {per_row:.0f} bytes (with the 64-character key: about 175)",
       per_row < 155, f"{per_row:.0f} bytes per row")


# ================================================================== 12-8
def t_12_8():
    print("12-8: the defaults are the ones Settings shows")
    keys = ("EMAIL_DAYS", "INSERT_CHUNK", "DOWNLOAD_THREADS", "IMAP_FETCH_BATCH", "MAIL_TIMEOUT", "WORKERS",
            "ZIP_MAX_UNPACKED_MB", "ZIP_MAX_RATIO", "ZIP_MAX_FILES", "ZIP_KEEP_FREE_MB", "DATA_DIR")
    keep = {k: os.environ.pop(k, None) for k in keys}
    try:
        root = tmpdir("b12-8")
        envf = os.path.join(root, ".env")
        open(envf, "w").close()
        s = sp.load_settings(argparse.Namespace(env_file=envf, workers=None, days=None))
        spec = {k: worker_settings.SPEC[k][4] for k in keys if k in worker_settings.SPEC}
        src = mail_sources.ImapSource({"IMAP_SERVER": "mail.example.org", "IMAP_USER": "u", "IMAP_PASSWORD": "p"})
        have = {"EMAIL_DAYS": s.days, "INSERT_CHUNK": s.insert_chunk, "DOWNLOAD_THREADS": s.download_threads,
                "IMAP_FETCH_BATCH": src.batch, "MAIL_TIMEOUT": src.timeout,
                "ZIP_MAX_UNPACKED_MB": s.zip_limits.max_unpacked // zip_limits.MB, "ZIP_MAX_RATIO": int(s.zip_limits.max_ratio),
                "ZIP_MAX_FILES": s.zip_limits.max_files, "ZIP_KEEP_FREE_MB": s.zip_limits.keep_free // zip_limits.MB}
        diff = {k: (have[k], spec[k]) for k in have if str(have[k]) != str(spec[k])}
        ok("with nothing set, the pipeline uses what Settings → Workers shows (EMAIL_DAYS 7, ...)", not diff, str(diff))
        ok("...WORKERS: 6, or the processor cores when fewer, as its help in Settings now says",
           s.workers == min(6, os.cpu_count() or 2) and "fewer" in worker_settings.SPEC["WORKERS"][7],
           f"{s.workers}; {worker_settings.SPEC['WORKERS'][7]}")
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


# ================================================================== 12-9
def t_12_9():
    print("12-9: the administrator's sign-in check goes through db_connect.py")
    sh = open(os.path.join(HERE, "store_mongo_admin.sh"), encoding="utf-8").read()
    m = re.search(r"login_check\(\) \{.*?\"\$PY\" -c '(.*?)'\n\}", sh, re.S)
    ok("(the sign-in check found in store_mongo_admin.sh)", bool(m))
    if not m:
        return
    snippet = m.group(1)
    fake = tmpdir("b12-9-fake")
    os.makedirs(os.path.join(fake, "pymongo"), exist_ok=True)
    with open(os.path.join(fake, "pymongo", "__init__.py"), "w", encoding="utf-8") as fh:
        fh.write("import json, os\nclass MongoClient:\n    def __init__(self, **kw):\n"
                 "        kw.pop('password', None)\n"
                 "        open(os.environ['FAKE_OUT'], 'w').write(json.dumps(kw))\n"
                 "        raise SystemExit(3)\n")

    def sign_in(lines):
        out = os.path.join(fake, "called.json")
        if os.path.exists(out):
            os.remove(out)
        # the fake pymongo first; anything already on PYTHONPATH (the suite's no-outside-connection guard) kept
        env = dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in (fake, os.environ.get("PYTHONPATH", "")) if p),
                   FAKE_OUT=out)
        r = subprocess.run([sys.executable, "-c", snippet], input=lines, capture_output=True, text=True, cwd=HERE,
                           env=env, timeout=60)
        called = json.load(open(out)) if os.path.exists(out) else None
        return r, called
    r, called = sign_in("MONGO_HOST=10.0.0.5\nMONGO_USER=admin\nMONGO_PASSWORD=x\n")
    ok("a MongoDB on another computer without TLS: refused before anything is sent (no plaintext sign-in)",
       called is None and r.returncode != 0 and "MONGO_TLS" in (r.stdout + r.stderr),
       f"rc={r.returncode} called={called} {(r.stdout + r.stderr)[-200:]}")
    r, called = sign_in("MONGO_HOST=10.0.0.5\nMONGO_TLS=1\nMONGO_USER=admin\nMONGO_PASSWORD=x\n")
    ok("...with MONGO_TLS=1: signs in over TLS", bool(called) and called.get("tls") is True and called.get("host") == "10.0.0.5",
       str(called))
    r, called = sign_in("MONGO_USER=admin\nMONGO_PASSWORD=x\n")
    ok("...this computer: as before (127.0.0.1)", bool(called) and called.get("host") == "127.0.0.1", str(called))
    grep = next((ln for ln in sh.splitlines() if "grep -E" in ln and "MONGO_(" in ln and "$SRC" in ln), "")
    ok("the TLS settings are stored with the account, so --check signs in the same way later (source check of the grep)",
       all(k in grep for k in ("TLS", "TLS_CA_FILE", "TLS_CERT_KEY_FILE", "ALLOW_PLAINTEXT")), grep)


# ================================================================== 12-10
def t_12_10():
    print("12-10: the pipeline's MongoDB account cannot drop collections")
    import importlib
    cp = importlib.import_module("create_pipeline_db_user")
    roles = cp.roles("shadowserver")
    ok("no readWrite (it may drop and rename collections)", not any(r["role"] in ("readWrite", "dbOwner", "root") for r in roles),
       str(roles))
    privs = getattr(cp, "privileges", lambda db: [])("shadowserver")
    acts = set().union(*[set(p["actions"]) for p in privs]) if privs else set()
    ok("...its own role: everything the pipeline does, nothing that drops or renames",
       cp.WRITE_ACTIONS <= acts and not acts & {"dropCollection", "dropDatabase", "dropIndex", "renameCollectionSameDB"}
       and all(p["resource"] == {"db": "shadowserver", "collection": ""} for p in privs), str(sorted(acts)))
    per_rw = {("shadowserver", ""): cp.WRITE_ACTIONS | {"dropCollection", "dropIndex"}}
    check = getattr(cp, "check_rights", None)
    ok("the rights check refuses an account that may still drop (readWrite)",
       bool(check) and "drop" in check(per_rw, set(), "shadowserver"))
    ok("...and accepts the role's rights", bool(check) and check({("shadowserver", ""): acts}, {"serverStatus"}, "shadowserver") == "")
    # a running installation: --update-rights, with the administrator account on standard input
    sent = []

    class FakeAdmin:
        def __init__(self, user):
            self.user = user

        def command(self, name, *a, **k):
            if self.user == "admin":
                sent.append((name, a, k))
                return {"ok": 1}
            if name == "connectionStatus":
                return {"authInfo": {"authenticatedUserPrivileges": [
                    {"resource": p["resource"], "actions": p["actions"]} for p in privs]
                    + [{"resource": {"cluster": True}, "actions": ["serverStatus"]}]}}
            return {"ok": 1}

    def fake_client(e, user, pw, source):
        return types.SimpleNamespace(admin=FakeAdmin(user))
    upd = getattr(cp, "update_rights", None)
    ok("(--update-rights exists for running installations)", bool(upd))
    if not upd:
        return
    with mock.patch.object(cp, "client", fake_client):
        rc = upd({"MONGO_USER": cp.NEW_USER, "MONGO_PASSWORD": "pw", "MONGO_DB": "shadowserver"}, "shadowserver",
                 "MONGO_USER=admin\nMONGO_PASSWORD=secret\n")
    names = [n for n, _, _ in sent]
    upd_user = next((k for n, _, k in sent if n == "updateUser"), {})
    ok("...creates the role, then gives the account the role in place of readWrite, its password unchanged",
       rc == 0 and names[:1] == ["createRole"] and "updateUser" in names and "pwd" not in upd_user
       and upd_user.get("roles") == roles, str(sent)[:300])


# ================================================================== 12-11
def t_12_11():
    print("12-11: counts after a dropped connection")

    class Flaky(Coll):
        """Writes the first 2 rows of the chunk, then the connection drops (AutoReconnect)."""
        tries = 0

        def insert_many(self, docs, ordered=False):
            Flaky.tries += 1
            if Flaky.tries == 1:
                for d in docs:
                    d.setdefault("_id", f"oid-{id(d)}")
                for d in docs[:2]:
                    self.keys.add((d.get("filename"), d.get("category"), d.get("line_hash")))
                    self.docs.append(dict(d))
                raise AutoReconnect("connection reset")
            return super().insert_many(docs, ordered)
    coll = Flaky("scan_x")
    coll.docs.append({"_id": "older", "filename": "f.csv", "category": "scan_x", "line_hash": "h9"})   # stored earlier
    coll.keys.add(("f.csv", "scan_x", "h9"))
    docs = [{"filename": "f.csv", "category": "scan_x", "line_hash": f"h{i}"} for i in range(5)]
    docs.append({"filename": "f.csv", "category": "scan_x", "line_hash": "h9"})
    with mock.patch("time.sleep", lambda s: None):
        res = sp._insert_docs(coll, docs)
    ok("the rows written before the drop count as inserted (5), the one stored earlier as already there (1)",
       res == (5, 1, 0), str(res))


# ================================================================== 12-12
def t_12_12():
    print("12-12: a zip with a password-protected file")
    root = Path(tmpdir("b12-12"))
    att, unz, srt = root / "attachments_backup", root / "unzipped_backup", root / "sorting_backup"
    for x in (att, unz, srt):
        x.mkdir()
    z = att / "2026-11-20-scan_x-kenya-geo.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("2026-11-20-scan_x-kenya-geo.csv", HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n')
    # mark the member "encrypted" (a password is needed to read it): bit 0 of the general-purpose flags, in the local
    # header (offset 6) and the central directory entry (offset 8); zipfile cannot write an encrypted zip itself
    b = bytearray(z.read_bytes())
    lo, ce = b.find(b"PK\x03\x04"), b.find(b"PK\x01\x02")
    b[lo + 6] |= 0x1
    b[ce + 8] |= 0x1
    z.write_bytes(bytes(b))
    result, items = sp._extract_zip(z, unz, srt)
    ok("it is quarantined (zips_refused), not left to fail again on every run (zips_failed)",
       result == "zips_refused" and not z.exists() and (root / "quarantine" / z.name).exists(), f"{result} {items}")
    ok("...the reason says why", bool(items) and "password" in items[0], str(items))


# ================================================================== 12-13
def t_12_13():
    print("12-13: a CSV column named _id")
    out, info = rows_of('"timestamp","ip","_id"\n'
                        '"2026-11-20 01:00:00","192.0.2.1","42"\n'
                        '"2026-11-20 01:00:01","192.0.2.2","42"\n')
    r = out[0] if out else {}
    ok("no row gets its MongoDB id from the file (rows with the same value, or of other files, no longer collide)",
       len(out) == 2 and all("_id" not in x for x in out), str(r)[:200])
    ok("...the file's value is kept as csv_id, and the file's header says so",
       r.get("csv_id") == "42" and ("_id", "csv_id") in (info.get("renamed") or []) and "csv_id" in (info.get("headers") or []),
       str(info.get("renamed")))
    base = tmpdir("b12-13-load")
    s = settings(base)
    d = s.sorting_dir / "scan_x"
    d.mkdir(parents=True)
    for i in (1, 2):
        (d / f"2026-11-2{i}-scan_x-kenya-geo.csv").write_text(
            f'"timestamp","ip","_id"\n"2026-11-2{i} 01:00:00","192.0.2.{i}","42"\n', encoding="utf-8")
    db = DB()
    st = run_load(s, db)
    ok("...through the loader: two files with the same _id value, both rows stored",
       st["rows_inserted"] == 2 and len(db["scan_x"].docs) == 2, str({k: st[k] for k in ("rows_inserted", "rows_duplicates")}))


# ================================================================== 12-14
def t_12_14():
    print("12-14: a file with only a header")
    base = tmpdir("b12-14")
    s = settings(base)
    d = s.sorting_dir / "scan_x"
    d.mkdir(parents=True)
    fn = "2026-11-20-scan_x-kenya-geo.csv"
    (d / fn).write_text(HEAD, encoding="utf-8")
    db = DB()
    st1 = run_load(s, db)
    st2 = run_load(s, db)
    ok("loaded once; the next run does not read it again", st1["files_loaded"] == 1 and st2["files_loaded"] == 0
       and st2["files_already_loaded"] == 1, f"first {st1['files_loaded']}, second {st2['files_loaded']}")
    time.sleep(0.01)
    (d / fn).write_text(HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n', encoding="utf-8")
    st3 = run_load(s, db)
    ok("...once it changes (rows arrived), it is loaded", st3["files_loaded"] == 1 and st3["rows_inserted"] == 1,
       str(dict(st3))[:200])


# ================================================================== 12-15
def t_12_15():
    print("12-15: the unused IMAP code")
    ok("the pipeline's own IMAP helpers are gone (mail_sources.py reads the mailbox)",
       not hasattr(sp, "_fetch_messages") and not hasattr(sp, "_imap_since"))


try:
    for name, fn in (("12-1", t_12_1), ("12-2", t_12_2), ("12-3", t_12_3), ("12-4", t_12_4), ("12-5", t_12_5),
                     ("12-6", t_12_6), ("12-7", t_12_7), ("12-7 memory", t_12_7_memory), ("12-8", t_12_8), ("12-9", t_12_9), ("12-10", t_12_10),
                     ("12-11", t_12_11), ("12-12", t_12_12), ("12-13", t_12_13), ("12-14", t_12_14), ("12-15", t_12_15)):
        attempt(name, fn)
finally:
    shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
