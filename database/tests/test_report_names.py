"""Report names (report_names.py, external review 2026-11-11): a file whose report name could not be a folder and a
MongoDB collection (scan$x, system., too long, capitals) is quarantined at unpacking, never loaded, and never met
again; the good reports beside it load as usual; one report that fails while loading no longer stops the others.
Made-up data in temporary folders and a throwaway database that is dropped afterwards (the real database is not
touched). Run: python3 tests/test_report_names.py"""
import argparse
import dataclasses
import os
import shutil
import sys
import tempfile
import unittest
import uuid
import zipfile
from collections import Counter
from pathlib import Path
from unittest import mock

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import report_names as rn  # noqa: E402
import shadowserver_pipeline as sp  # noqa: E402

CSV = ('"timestamp","ip","port","asn","geo","region","city","hostname","tag"\n'
       '"2026-11-10 01:02:03","198.51.100.7",443,64500,"XX","REGION 1","CITY 1","host-1.example.net","tag-1"\n'
       '"2026-11-10 04:05:06","198.51.100.8",22,64501,"XX","REGION 2","CITY 2","host-2.example.net","tag-2"\n')
GOOD = "2026-11-10-scan_example-example-geo.csv"
BAD = ["2026-11-10-scan$x-example-geo.csv", "2026-11-10-system.users-example-geo.csv",
       "2026-11-10-Scan_Http-example-geo.csv", f"2026-11-10-{'a' * 70}-example-geo.csv"]


class Names(unittest.TestCase):
    def test_rule(self):
        for ok in ("scan_http", "event4_sinkhole_http", "device_id6", "blocklist", "scan6_ssl"):
            self.assertTrue(rn.valid(ok), ok)
        for bad in ("scan$x", "system.users", "", "a" * 65, "Scan_Http", "scan-http", "../x", "_x", "x y"):
            self.assertFalse(rn.valid(bad), bad)


class Folders(unittest.TestCase):
    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="reportnames-"))
        self.att, self.unz, self.srt = (self.base / d for d in ("attachments_backup", "unzipped_backup", "sorting_backup"))
        for d in (self.att, self.unz, self.srt):
            d.mkdir()
        self.q = self.base / "quarantine" / rn.FOLDER

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def settings(self, **kw):
        return sp.Settings(env_file=self.base / ".env", imap_server="", imap_user="", imap_password="", imap_folder="inbox",
                           imap_verify_tls=False, mongo={}, mongo_db="x", mongo_cache_gb=0.25, base_dir=self.base, workers=2,
                           insert_chunk=500, download_threads=1, fetch_batch=5, days=1, **kw)

    def test_zip_with_bad_names(self):
        z = self.att / "reports.zip"
        with zipfile.ZipFile(z, "w") as zf:
            zf.writestr(GOOD, CSV)
            for b in BAD:
                zf.writestr(b, CSV)
        result, items = sp._extract_zip(z, self.unz, self.srt)
        self.assertEqual(result, "zips_extracted")
        self.assertEqual([i[1] for i in items], ["scan_example"], "only the good report is sorted")
        self.assertTrue((self.srt / "scan_example" / GOOD).exists())
        self.assertEqual(sorted(p.name for p in self.srt.iterdir()), ["scan_example"], "no folder with a bad name")
        for b in BAD:
            self.assertTrue((self.q / b).exists(), f"{b} is in quarantine/{rn.FOLDER}/")
            self.assertIn("not loaded", (self.q / (b + ".reason.txt")).read_text())
        self.assertEqual(sp._extract_zip(z, self.unz, self.srt)[0], "zips_skipped", "the zip is not unpacked again")

    def test_loose_csv_with_bad_name(self):
        (self.att / GOOD).write_text(CSV)
        (self.att / BAD[0]).write_text(CSV)
        sp.unzip_and_sort(self.settings(), Counter())
        self.assertTrue((self.srt / "scan_example" / GOOD).exists())
        self.assertTrue((self.q / BAD[0]).exists())
        self.assertFalse((self.att / BAD[0]).exists(), "it is not met again next run")
        self.assertFalse(any(p.name.startswith("scan$") for p in self.srt.iterdir()))


def _may_create_db(mongo):
    try:
        c = sp.mongo_client(mongo, serverSelectionTimeoutMS=4000)
        c["lg_write_probe"]["probe"].insert_one({"probe": 1})
        c.drop_database("lg_write_probe")
        return c
    except Exception:              # noqa: BLE001
        return None


def throwaway_db():
    """The real .env's MongoDB, with a database of its own (dropped afterwards). The pipeline's own account may only
    write its database, so an administrator account is looked for: the file named by LG_MONGO_ADMIN_FILE (the
    platform's tests/run_admin_db_tests.sh hands it over), /etc/looking-glass/mongo-admin.env when sudo works without a
    password, or a copy left in .env.before-pipeline-account (older set-ups).
    (None, None) when no account may create a database, or MongoDB is not reachable."""
    try:
        s = sp.load_settings(argparse.Namespace(env_file=os.path.join(HERE, ".env"), workers=2, days=None))
    except Exception:              # noqa: BLE001
        return None, None
    c = _may_create_db(s.mongo)
    if c:
        return s, c
    texts = []
    given = os.environ.get("LG_MONGO_ADMIN_FILE")
    if given and os.path.isfile(given):
        texts.append(open(given, encoding="utf-8").read())
    try:
        import subprocess
        r = subprocess.run(["sudo", "-n", "cat", "/etc/looking-glass/mongo-admin.env"], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            texts.append(r.stdout)
    except (OSError, subprocess.SubprocessError):
        pass
    kept = os.path.join(HERE, ".env.before-pipeline-account")
    if os.path.isfile(kept):
        texts.append(open(kept, encoding="utf-8").read())
    for text in texts:
        e = {}
        for raw in text.splitlines():
            line = raw.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                v = v.strip()
                e[k.strip()] = v[1:-1] if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"" else v
        if e.get("MONGO_USER"):
            mongo = dict(s.mongo, username=e["MONGO_USER"], password=e.get("MONGO_PASSWORD", ""),
                         authSource=e.get("MONGO_AUTH_SOURCE") or "admin")
            c = _may_create_db(mongo)
            if c:
                return dataclasses.replace(s, mongo=mongo), c
    return None, None


class Loading(unittest.TestCase):
    def setUp(self):
        self.s0, self.client = throwaway_db()
        if not self.client:
            self.skipTest("MongoDB not reachable, or no account here may create a throwaway database")
        self.base = Path(tempfile.mkdtemp(prefix="reportnames-load-"))
        self.db = f"lg_test_reportnames_{uuid.uuid4().hex[:8]}"
        self.s = dataclasses.replace(self.s0, base_dir=self.base, mongo_db=self.db, workers=2)
        for name in ("scan_example", "scan_other"):
            (self.s.sorting_dir / name).mkdir(parents=True)
            (self.s.sorting_dir / name / f"2026-11-10-{name}-example-geo.csv").write_text(CSV)
        bad = self.s.sorting_dir / "scan$x"            # left by an older version, before names were checked
        bad.mkdir()
        (bad / BAD[0]).write_text(CSV)

    def tearDown(self):
        if self.client:
            self.client.drop_database(self.db)
            self.client.close()
            shutil.rmtree(self.base, ignore_errors=True)

    def test_bad_folder_and_failing_report(self):
        real = sp.loaded_filenames

        def flaky(coll):                                # one report fails while it is being read
            if coll.name == "scan_other":
                raise RuntimeError("simulated failure")
            return real(coll)
        stats = Counter()
        with mock.patch.object(sp, "loaded_filenames", flaky):
            sp.load_into_mongo(self.s, stats)           # must not raise
        db = self.client[self.db]
        self.assertEqual(db["scan_example"].count_documents({}), 2, "the good report loaded")
        self.assertNotIn("scan$x", self.client[self.db].list_collection_names())
        self.assertTrue((self.base / "quarantine" / rn.FOLDER / "scan$x").exists(), "the bad folder is in quarantine")
        self.assertFalse((self.s.sorting_dir / "scan$x").exists())
        self.assertEqual((stats["reports_quarantined"], stats["reports_failed"]), (1, 1))
        stats2 = Counter()
        sp.load_into_mongo(self.s, stats2)              # next run: the failed one loads, nothing trips again
        self.assertEqual(db["scan_other"].count_documents({}), 2)
        self.assertEqual((stats2["reports_quarantined"], stats2["reports_failed"]), (0, 0))


if __name__ == "__main__":
    unittest.main(verbosity=2)
