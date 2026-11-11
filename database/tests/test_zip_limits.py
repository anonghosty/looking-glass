"""Unpacking limits (zip_limits.py, used by shadowserver_pipeline._extract_zip): a normal Shadowserver-sized report
goes through; a zip bomb, too many files, a zip that lies about its size, and file names that try to leave the
folder are refused and quarantined with nothing left behind; a nearly full disk is retried later, not quarantined.
Made-up data only. Run: python3 tests/test_zip_limits.py"""
import io
import os
import random
import shutil
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shadowserver_pipeline as sp  # noqa: E402
import zip_limits as zl  # noqa: E402

REPORT = "2026-11-10-scan_example-example-geo.csv"
MB = 1 << 20


def csv_text(size):
    """Report-like CSV: varied rows, so it compresses like a real report (a few times, not a thousand)."""
    rnd, rows, n = random.Random(7), ['"timestamp","ip","port","asn","geo","region","city","hostname","tag"\n'], 0
    while n < size:
        r = (f'"2026-11-10 {rnd.randrange(24):02d}:{rnd.randrange(60):02d}:{rnd.randrange(60):02d}","198.51.{rnd.randrange(256)}'
             f'.{rnd.randrange(256)}",{rnd.randrange(65536)},{rnd.randrange(64496, 65535)},"XX","REGION {rnd.randrange(50)}",'
             f'"CITY {rnd.randrange(900)}","host-{rnd.getrandbits(40):x}.example.net","tag-{rnd.randrange(30)}"\n')
        rows.append(r); n += len(r)
    return "".join(rows)


class ZipLimits(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="ziplimits-"))
        self.att, self.unz, self.srt = (self.base / d for d in ("attachments_backup", "unzipped_backup", "sorting_backup"))
        for d in (self.att, self.unz, self.srt):
            d.mkdir()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def make(self, name, members):
        p = self.att / name
        with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
            for fn, data in members:
                z.writestr(fn, data)
        return p

    def run_zip(self, p, limits=zl.Limits()):
        return sp._extract_zip(p, self.unz, self.srt, limits)

    def nothing_left(self, p):
        self.assertFalse(any(self.srt.rglob("*.csv")), "no report reached sorting_backup")
        self.assertFalse(list(self.unz.glob("*.partial")), "no half-unpacked folder left")
        self.assertFalse(p.exists(), "the zip left attachments_backup")
        q = self.base / "quarantine" / p.name
        self.assertTrue(q.exists(), "the zip is in quarantine/")
        self.assertIn("refused:", (q.parent / (q.name + ".reason.txt")).read_text())

    def test_normal_report_goes_through(self):
        p = self.make("2026-11-10-scan_example.zip", [(REPORT, csv_text(3 * MB))])
        result, routed = self.run_zip(p)
        self.assertEqual(result, "zips_extracted")
        self.assertEqual(routed[0][:2], (REPORT, "scan_example"))
        self.assertGreater((self.srt / "scan_example" / REPORT).stat().st_size, 3 * MB)
        self.assertTrue(p.exists(), "a good zip stays where it is")

    def test_zip_bomb_refused(self):
        p = self.make("bomb.zip", [(REPORT, b"\0" * (60 * MB))])          # ~60 KB packed, about 1000x
        self.assertLess(p.stat().st_size, MB)
        result, info = self.run_zip(p)
        self.assertEqual(result, "zips_refused")
        self.assertIn("zip bomb", info[0])
        self.nothing_left(p)

    def test_bomb_after_a_good_report_leaves_nothing(self):
        p = self.make("mixed.zip", [(REPORT, csv_text(MB)), ("2026-11-10-scan_other-example-geo.csv", b"\0" * (60 * MB))])
        self.assertEqual(self.run_zip(p)[0], "zips_refused")
        self.nothing_left(p)

    def test_too_many_files(self):
        p = self.make("many.zip", [(f"note-{i}.txt", "x") for i in range(101)])
        result, info = self.run_zip(p)
        self.assertEqual(result, "zips_refused")
        self.assertIn("101 files", info[0])
        self.nothing_left(p)

    def test_stated_size_over_the_limit(self):
        p = self.make("big.zip", [(REPORT, csv_text(3 * MB))])
        result, info = self.run_zip(p, zl.Limits(max_unpacked=2 * MB))
        self.assertEqual(result, "zips_refused")
        self.assertIn("says it unpacks to", info[0])

    def test_real_bytes_counted_when_the_zip_lies(self):
        # the listing check is skipped, as if the zip stated tiny sizes: the bytes counted while unpacking still stop it
        p = self.make("liar.zip", [(REPORT, csv_text(3 * MB))])
        with mock.patch.object(zl, "check_listing", lambda infos, limits: None):
            result, info = self.run_zip(p, zl.Limits(max_unpacked=2 * MB))
        self.assertEqual(result, "zips_refused")
        self.assertIn("unpacks to more than 2 MB", info[0])
        self.nothing_left(p)

    def test_names_cannot_leave_the_folder(self):
        p = self.make("paths.zip", [("../../escape.txt", "x"), ("/abs/escape2.txt", "y"), ("C:\\win\\escape3.txt", "z")])
        self.assertEqual(self.run_zip(p)[0], "zips_extracted")
        self.assertFalse((self.base / "escape.txt").exists() or (self.base.parent / "escape.txt").exists())
        inside = {f.name for f in (self.unz / "paths.zip").rglob("*") if f.is_file()}
        self.assertEqual(inside, {"escape.txt", "escape2.txt", "escape3.txt"})
        for f in (self.unz / "paths.zip").rglob("*"):
            self.assertTrue(str(f.resolve()).startswith(str((self.unz / "paths.zip").resolve())))

    def test_low_disk_is_retried_not_quarantined(self):
        p = self.make("ok.zip", [(REPORT, csv_text(MB))])
        result, _ = self.run_zip(p, zl.Limits(keep_free=1 << 62))
        self.assertEqual(result, "zips_failed")
        self.assertTrue(p.exists(), "the zip stays for the next run")
        self.assertFalse((self.base / "quarantine").exists())
        self.assertFalse(list(self.unz.glob("*.partial")))

    def test_settings_from_env(self):
        env = {"ZIP_MAX_UNPACKED_MB": "4096", "ZIP_MAX_RATIO": "350.5", "ZIP_MAX_FILES": "abc", "ZIP_KEEP_FREE_MB": "-5"}
        lim = zl.Limits.from_env(env.get)
        self.assertEqual((lim.max_unpacked, lim.max_ratio, lim.max_files, lim.keep_free), (4096 * MB, 350.5, 100, 1024 * MB))
        d = zl.Limits.from_env({}.get)
        self.assertEqual((d.max_unpacked, d.max_ratio, d.max_files, d.keep_free), (2048 * MB, 200.0, 100, 1024 * MB))


if __name__ == "__main__":
    unittest.main(verbosity=2)
