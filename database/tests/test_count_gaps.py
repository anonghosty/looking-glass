# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Nothing goes missing between the mailbox and MongoDB without being counted (count audit, 2026-11-26).

  - a run that left whole reports out (a report that could not be read, a zip refused or failed, a broken zip deleted,
    a link or an attachment not saved, the API unusable with no other way, an API download failed, a full API list,
    a file quarantined for its report name) is an error of the run, not "ok"; the status file says each in words
  - CSV files whose name is not a report file name are counted and listed; ".CSV", "-Kenya-geo" and "_as64500_2.csv"
    are report files and are sorted
  - every row read lands in exactly one count: read = inserted + already in the database + repeated in the file + same
    row hash + bad timestamp + failed; rows without a timestamp are counted
  - a byte-order mark no longer hides the timestamp column; U+2028, NEL and \\x1c-\\x1e no longer cut a row in two
  - a report sent again under the same name with other content is loaded again; unchanged files are not
Made-up files in temporary folders and an in-memory stand-in for MongoDB: no database, no mailbox.
Run: python3 tests/test_count_gaps.py"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import retention  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402
from pymongo.errors import BulkWriteError  # noqa: E402

HEAD = '"timestamp","ip","port","asn"\n'


def rows_of(text, name="2026-11-20-scan_x-kenya-geo.csv"):
    d = tempfile.mkdtemp(prefix="countgaps-")
    p = os.path.join(d, name)
    with open(p, "wb") as fh:
        fh.write(text.encode("utf-8") if isinstance(text, str) else text)
    info = {}
    out = list(sp.iter_csv_docs(p, name, "scan_x", info=info))
    shutil.rmtree(d, ignore_errors=True)
    return out, info


# ------------------------------------------------------------------ an in-memory MongoDB, just what the loader uses
class Coll:
    def __init__(self, name, fail_ip=None):
        self.name, self.docs, self.keys, self.fail_ip = name, [], set(), fail_ip

    def create_index(self, *a, **k):
        return "ix"

    def distinct(self, field):
        return sorted({d.get(field) for d in self.docs})

    def find(self, flt=None, proj=None):
        return [dict(d) for d in self.docs]

    def insert_many(self, docs, ordered=False):
        errs, n = [], 0
        for i, d in enumerate(docs):
            key = (d.get("filename"), d.get("category"), d.get("line_hash"))
            if self.fail_ip and d.get("ip") == self.fail_ip:
                errs.append({"index": i, "code": 2, "errmsg": "simulated write error"})
            elif "line_hash" in d and key in self.keys:
                errs.append({"index": i, "code": 11000, "errmsg": "duplicate"})
            else:
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
    def __init__(self, fail_ip=None):
        super().__init__()
        self.fail_ip = fail_ip

    def __missing__(self, name):
        c = self[name] = Coll(name, self.fail_ip if not name.startswith(("files_", "discovered_", "lg_")) else None)
        return c


class Client:
    def __init__(self, db):
        self.db = db
        self.admin = type("A", (), {"command": staticmethod(lambda *a, **k: {"ok": 1})})()

    def __getitem__(self, name):
        return self.db

    def close(self):
        pass


def settings(base):
    return sp.Settings(env_file=Path(base) / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                       imap_verify_tls=True, mongo={}, mongo_db="x", mongo_cache_gb=0.25, base_dir=Path(base), workers=1,
                       insert_chunk=3, download_threads=1, fetch_batch=5, days=1)


def run_load(s, db):
    """load_into_mongo with the stand-in database, in threads (no worker processes)."""
    stats = Counter()

    def init(*_a):
        sp._WORKER_DB = db
    with mock.patch.object(sp, "mongo_client", lambda *a, **k: Client(db)), \
            mock.patch.object(sp, "ProcessPoolExecutor", ThreadPoolExecutor), \
            mock.patch.object(sp, "_init_worker", init):
        sp.load_into_mongo(s, stats)
    return stats


def identity(stats):
    return (stats["rows_inserted"] + stats["rows_duplicates"] + stats["rows_same_in_file"] + stats["rows_same_hash"]
            + stats["rows_bad_timestamp"] + stats["rows_failed"])


# ------------------------------------------------------------------ rows
class Rows(unittest.TestCase):
    def test_bom_keeps_the_timestamp_column(self):
        out, info = rows_of(b"\xef\xbb\xbf" + (HEAD + '"2026-11-20 01:02:03","192.0.2.1",23,64500\n').encode())
        self.assertEqual(info["headers"][0], "timestamp", "the byte-order mark is not part of the first column's name")
        self.assertIn("extracted_date", out[0], "the row has its date, so the pages show it")
        self.assertTrue(info.get("bom"))

    def test_same_row_twice_in_a_file_is_counted(self):
        r = '"2026-11-20 01:02:03","192.0.2.1",23,64500\n'
        out, info = rows_of(HEAD + r * 3 + '"2026-11-20 01:02:04","192.0.2.2",23,64500\n')
        self.assertEqual(len(out), 2)
        self.assertEqual(info.get("same_in_file"), 2, "two repeats, stored once")
        self.assertEqual(info.get("rows_read"), 4)

    def test_rows_without_a_timestamp_are_counted(self):
        out, info = rows_of(HEAD + '"","192.0.2.1",23,64500\n"2026-11-20 01:02:03","192.0.2.2",23,64500\n')
        self.assertEqual(len(out), 2, "still stored, as before")
        self.assertEqual(info.get("no_time"), 1)

    def test_odd_line_break_characters_do_not_cut_a_row(self):
        for ch in (" ", "\x85", "\x1c", "\x1d", "\x1e", "\x0b", "\x0c"):
            out, info = rows_of(HEAD + f'2026-11-20 01:02:03,192.0.2.1,23,645{ch}00\n2026-11-20 01:02:04,192.0.2.2,23,64500\n')
            self.assertEqual(len(out), 2, f"{ch!r}: two rows stay two rows")
            self.assertEqual(out[0]["asn"], f"645{ch}00", f"{ch!r}: the value is kept whole")
            self.assertEqual(info.get("bad_timestamp", 0), 0)

    def test_ordinary_line_ends_and_hash_unchanged(self):
        import hashlib
        out, _ = rows_of('"ip","port"\r\n"192.0.2.1","23"\r\n"192.0.2.2","24"\r"192.0.2.3","25"\n')
        self.assertEqual([r["ip"] for r in out], ["192.0.2.1", "192.0.2.2", "192.0.2.3"], "\\r\\n, \\r and \\n end a line")
        self.assertEqual(out[0]["line_hash"], hashlib.sha256("192.0.2.1,23".encode()).hexdigest(), "line_hash as before")

    def test_same_hash_other_row_is_told_apart(self):
        out, info = rows_of('"a","b"\n"x,y","z"\n"x","y,z"\n"x,y","z"\n')
        self.assertEqual(len(out), 1, "documented limit kept: the pair has one line_hash")
        self.assertEqual((info.get("same_hash"), info.get("same_in_file")), (1, 1), "the other row is counted apart")

    def test_every_row_read_is_in_one_count(self):
        base = tempfile.mkdtemp(prefix="countgaps-load-")
        try:
            s = settings(base)
            d = s.sorting_dir / "scan_x"
            d.mkdir(parents=True)
            (d / "2026-11-20-scan_x-kenya-geo.csv").write_text(
                HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n' * 2      # one repeat
                + '"2026-11-20 01:00:01","192.0.2.2",23,64500\n'
                + '"not a time","192.0.2.3",23,64500\n'                         # bad timestamp
                + '"2026-11-20 01:00:02","192.0.2.66",23,64500\n'               # a write error
                + '"","192.0.2.4",23,64500\n', encoding="utf-8")               # no timestamp (stored)
            db = DB(fail_ip="192.0.2.66")
            st = run_load(s, db)
            self.assertEqual(st["rows_read"], 6)
            self.assertEqual((st["rows_inserted"], st["rows_same_in_file"], st["rows_bad_timestamp"], st["rows_failed"],
                              st["rows_no_time"]), (3, 1, 1, 1, 1), str(st))
            self.assertEqual(identity(st), st["rows_read"], "the parts add up to the rows read")
            st2 = run_load(s, db)                    # the failed row's file is tried again: the rest are already stored
            self.assertEqual(st2["rows_duplicates"], 3, str(st2))
            self.assertEqual((st2["rows_read"], identity(st2)), (6, 6), str(st2))
        finally:
            shutil.rmtree(base, ignore_errors=True)


# ------------------------------------------------------------------ the run's errors and warnings
class RunProblems(unittest.TestCase):
    LEFT_OUT = ("reports_failed", "zips_refused", "csv_quarantined", "reports_quarantined", "zips_failed",
                "zips_bad_deleted", "links_failed", "attachments_failed", "api_unusable", "api_failed", "api_list_full")

    def test_reports_left_out_fail_the_run(self):
        for k in self.LEFT_OUT:
            self.assertGreater(sp.run_errors(Counter({k: 1})), 0, f"{k} alone: the run did not go well")
        self.assertEqual(sp.run_errors(Counter()), 0)
        self.assertEqual(sp.run_errors(Counter(file_errors=1, email_failed=1)), 2, "as before")

    def test_api_with_a_working_fallback_is_a_warning(self):
        errs, warns = sp.run_problems(Counter(api_unusable=1, fallback_used=1))
        self.assertEqual(errs, [])
        self.assertEqual([w["key"] for w in warns], ["api_fallback"])

    def test_status_file_says_each_one(self):
        base = tempfile.mkdtemp(prefix="countgaps-status-")
        try:
            stats = Counter(zips_refused=2, rows_read=10, rows_inserted=7, rows_same_in_file=2, rows_bad_timestamp=1,
                            rows_no_time=3, csv_not_matched=25)
            stats["not_matched_names"] = [f"unzipped_backup/r.zip/2026-11-20-scan_x-{i}-kenya.csv" for i in range(25)]
            errs, warns = sp.run_problems(stats)
            st = retention.status(base, not errs, stats, 0, problems=(errs, warns))
            with open(os.path.join(base, "pipeline_status.json"), encoding="utf-8") as fh:
                saved = json.load(fh)
            self.assertFalse(saved["ok"])
            self.assertEqual(saved, st)
            self.assertTrue(any("2 zip file(s)" in e["text"] and "quarantine" in e["text"] for e in saved["errors"]), saved["errors"])
            nm = next(w for w in saved["warnings"] if w["key"] == "csv_not_matched")
            self.assertIn("the first 20 of 25 files", nm["text"], "a cut list says it is cut")
            self.assertEqual(saved["not_matched"]["count"], 25)
            self.assertEqual(len(saved["not_matched"]["names"]), 25)
            self.assertTrue(any(w["key"] == "rows_no_time" and "3 row(s)" in w["text"] for w in saved["warnings"]))
            self.assertEqual((saved["rows_read"], saved["rows_same_in_file"]), (10, 2))
        finally:
            shutil.rmtree(base, ignore_errors=True)


# ------------------------------------------------------------------ file names
class FileNames(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="countgaps-names-"))
        self.s = settings(self.base)
        for d in (self.s.attachments_dir, self.s.unzipped_dir, self.s.sorting_dir):
            d.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_variants_are_sorted_the_rest_counted(self):
        csv_text = HEAD + '"2026-11-20 01:02:03","192.0.2.1",23,64500\n'
        good = ["2026-11-20-scan_x-123-Kenya-geo.csv", "2026-11-20-scan_x-kenya-geo.CSV",
                "2026-11-20-scan_x-kenya-geo_as64500_2.csv"]
        odd = ["2026-11-20-scan_x-ke-cidr.csv", "2026-11-20-scan_x-kenya.csv"]
        for fn in good + odd:
            (self.s.attachments_dir / fn).write_text(csv_text)
        with zipfile.ZipFile(self.s.attachments_dir / "reports.zip", "w") as zf:
            zf.writestr("2026-11-20-scan$x-kenya-geo.csv", csv_text)          # a name that cannot be a report name
            zf.writestr("2026-11-20-scan_y-kenya-geo.csv", csv_text)
            zf.writestr("2026-11-20-scan_y-Kenya.csv", csv_text)              # not a report file name
            zf.writestr("readme.txt", "not a report")
        stats = Counter()
        sp.unzip_and_sort(self.s, stats)
        got = sorted(os.listdir(self.s.sorting_dir / "scan_x"))
        self.assertEqual(got, sorted(["2026-11-20-scan_x-123-Kenya-geo.csv", "2026-11-20-scan_x-kenya-geo.csv",
                                      "2026-11-20-scan_x-kenya-geo_as64500_2.csv"]), "variants sorted, '.CSV' as '.csv'")
        self.assertTrue((self.s.sorting_dir / "scan_y" / "2026-11-20-scan_y-kenya-geo.csv").exists())
        self.assertEqual(stats["csv_not_matched"], 3, str(stats))
        names = stats["not_matched_names"]
        self.assertTrue(all(any(n.endswith(o) for n in names) for o in odd + ["2026-11-20-scan_y-Kenya.csv"]), names)
        self.assertEqual(stats["csv_quarantined"], 1, "the bad report name is counted, not only logged")
        errs, warns = sp.run_problems(stats)
        self.assertTrue(any(e["key"] == "reports_quarantined" for e in errs))
        self.assertTrue(any(w["key"] == "csv_not_matched" for w in warns))


# ------------------------------------------------------------------ a report sent again under the same name
class SentAgain(unittest.TestCase):
    def test_changed_file_is_loaded_again(self):
        base = tempfile.mkdtemp(prefix="countgaps-again-")
        try:
            s = settings(base)
            d = s.sorting_dir / "scan_x"
            d.mkdir(parents=True)
            p = d / "2026-11-20-scan_x-kenya-geo.csv"
            one = '"2026-11-20 01:00:00","192.0.2.1",23,64500\n'
            two = '"2026-11-20 01:00:01","192.0.2.2",23,64500\n'
            p.write_text(HEAD + one + two, encoding="utf-8")
            db = DB()
            st = run_load(s, db)
            self.assertEqual(st["rows_inserted"], 2)
            st = run_load(s, db)
            self.assertEqual((st["files_already_loaded"], st["rows_read"]), (1, 0), "unchanged: not read again")
            os.utime(p, ns=(time.time_ns(), time.time_ns() + 5_000_000_000))      # touched, same content
            st = run_load(s, db)
            self.assertEqual((st["files_reloaded"], st["rows_read"]), (0, 0), "same content: not loaded again")
            p.write_text(HEAD + one + two + '"2026-11-20 01:00:02","192.0.2.3",23,64500\n', encoding="utf-8")
            os.utime(p, ns=(time.time_ns(), time.time_ns() + 10_000_000_000))
            st = run_load(s, db)
            self.assertEqual(st["files_reloaded"], 1, "the report sent again is loaded again")
            self.assertEqual((st["rows_inserted"], st["rows_duplicates"]), (1, 2), str(st))
            self.assertEqual(len(db["scan_x"].docs), 3)
            self.assertTrue(any(w["key"] == "files_reloaded" and "scan_x/2026-11-20-scan_x-kenya-geo.csv" in w["text"]
                                for w in sp.run_problems(st)[1]))
            st = run_load(s, db)
            self.assertEqual((st["files_reloaded"], st["rows_read"]), (0, 0), "and only once")
        finally:
            shutil.rmtree(base, ignore_errors=True)

    def test_file_loaded_before_fingerprints_is_not_reloaded(self):
        base = tempfile.mkdtemp(prefix="countgaps-legacy-")
        try:
            s = settings(base)
            d = s.sorting_dir / "scan_x"
            d.mkdir(parents=True)
            fn = "2026-11-20-scan_x-kenya-geo.csv"
            (d / fn).write_text(HEAD + '"2026-11-20 01:00:00","192.0.2.1",23,64500\n', encoding="utf-8")
            db = DB()
            db["scan_x"].docs.append({"filename": fn, "category": "scan_x", "line_hash": "x"})   # loaded by an older version
            st = run_load(s, db)
            self.assertEqual((st["files_already_loaded"], st["files_reloaded"], st["rows_read"]), (1, 0, 0), str(st))
        finally:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
