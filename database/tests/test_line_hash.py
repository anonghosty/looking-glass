# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The row hash (line_hash) and failed rows (external review, 2026-11-14).

line_hash stays exactly as the original loader made it, so its two known limits are pinned here (documented in
shadowserver_pipeline.iter_csv_docs): values beyond the header are not in it, and fields are joined without the CSV
quoting. Rows that could not be written make the run an error (exit code, the platform's bell), and their file is
tried again. Made-up data only. Run: python3 tests/test_line_hash.py"""
import hashlib
import json
import os
import re
import sys
import tempfile
import unittest
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import retention  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402


def docs(text):
    d = tempfile.mkdtemp()
    p = os.path.join(d, "r.csv")
    with open(p, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    info = {}
    return list(sp.iter_csv_docs(p, "r.csv", "scan_example", info=info)), info


class LineHash(unittest.TestCase):
    def test_hash_is_the_original_loaders(self):
        out, _ = docs('"ip","port"\n"192.0.2.1","23"\n')
        self.assertEqual(out[0]["line_hash"], hashlib.sha256("192.0.2.1,23".encode()).hexdigest())

    def test_values_beyond_the_header_are_not_in_the_hash(self):
        out, info = docs('"ip","port"\n"192.0.2.1","23","extra-a"\n"192.0.2.1","23","extra-b"\n')
        self.assertEqual(len(out), 1, "two rows differing only beyond the header are one row")
        self.assertNotIn(None, out[0], "the extra values are dropped")
        self.assertEqual(info.get("extra_columns"), 1)

    def test_fields_are_joined_without_quoting(self):
        out, _ = docs('"a","b"\n"x,y","z"\n"x","y,z"\n')
        self.assertEqual(len(out), 1, "documented limit: the second row of such a pair is taken for a duplicate")
        self.assertEqual(out[0]["a"], "x,y")

    def test_different_rows_stay_apart(self):
        out, _ = docs('"a","b"\n"x","y"\n"x","z"\n"x","y"\n')
        self.assertEqual([r["b"] for r in out], ["y", "z"])


class FailedRows(unittest.TestCase):
    def test_failed_rows_fail_the_run(self):
        self.assertEqual(sp.run_errors(Counter()), 0)
        self.assertEqual(sp.run_errors(Counter(files_rows_failed=1)), 1)
        self.assertEqual(sp.run_errors(Counter(file_errors=1, email_failed=1)), 2)

    def test_the_bell_hears_of_them(self):
        d = tempfile.mkdtemp()
        stats = Counter(rows_failed=7, files_rows_failed=2)
        st = retention.status(d, not sp.run_errors(stats), stats, 0)
        self.assertFalse(st["ok"])
        self.assertEqual((st["rows_failed"], st["files_rows_failed"]), (7, 2))
        with open(os.path.join(d, "pipeline_status.json"), encoding="utf-8") as fh:
            self.assertEqual(json.load(fh)["files_rows_failed"], 2)

    def test_a_file_with_failed_rows_is_not_marked_done(self):
        with open(sp.__file__, encoding="utf-8") as fh:
            src = fh.read()
        i = re.search(r'if res\["failed"\]:\n\s+stats\["files_rows_failed"\] \+= 1', src).start()   # any indentation
        self.assertIn("journal.done(category, fn)", src[i:i + 200].split("record_fields")[0].split("else:")[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
