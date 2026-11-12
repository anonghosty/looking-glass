"""Proves the new loader builds exactly the same MongoDB documents as mongo_added_json.py.

Run:  .venv/bin/python -m unittest discover -s tests -v
(no MongoDB needed)
"""
import csv
import datetime
import hashlib
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shadowserver_pipeline as sp  # noqa: E402


# ---- original logic, copied from mongo_added_json.py (async/aiofiles removed) ----
def old_csv_docs(file_path, filename, category):
    with open(file_path, "r") as csvfile:
        file_contents = csvfile.read()
    file_contents_lines = file_contents.splitlines()
    reader = csv.DictReader(file_contents_lines)
    if reader.fieldnames is None:
        return None, []
    headers = reader.fieldnames
    lines_to_hash = set()
    file_docs = []
    for row in reader:
        line = ','.join([str(row.get(field, "")) for field in headers])
        line_hash = hashlib.sha256(line.encode()).hexdigest()
        if line_hash in lines_to_hash:
            continue
        row["filename"] = filename
        row["category"] = category
        row["line_hash"] = line_hash
        if "extracted_date" not in row:
            timestamp_str = row.get("timestamp")
            if timestamp_str:
                try:
                    date_entry = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                    row.setdefault("logged_date", date_entry.strftime("%Y-%m-%d %H:%M:%S"))
                    row["extracted_date"] = date_entry
                except ValueError:
                    continue
        file_docs.append(row)
        lines_to_hash.add(line_hash)
    return headers, file_docs


def old_json_doc(file_path, filename, category):
    with open(file_path, "r") as jsonfile:
        json_data = jsonfile.read()
    json_object = json.loads(json_data)
    line_hash = hashlib.sha256(json_data.encode()).hexdigest()
    doc = {"filename": filename, "category": category, "line_hash": line_hash, **json_object}
    if "extracted_date" not in doc:
        timestamp_str = json_object.get("timestamp")
        if timestamp_str:
            try:
                date_entry = datetime.datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                doc.setdefault("logged_date", date_entry.strftime("%Y-%m-%d %H:%M:%S"))
                doc["extracted_date"] = date_entry
            except ValueError:
                pass
    return doc


CSV_CASES = {
    "basic": "timestamp,ip,port\n2025-08-01 10:00:00,1.2.3.4,80\n2025-08-01 10:00:01,1.2.3.5,443\n",
    "crlf_dupes_blank": "timestamp,ip\r\n2025-08-01 10:00:00,1.1.1.1\r\n\r\n2025-08-01 10:00:00,1.1.1.1\r\n2025-08-01 10:00:00,1.1.1.2\r\n",
    "bom": "﻿timestamp,ip\n2025-08-01 10:00:00,1.1.1.1\n",
    "bad_and_odd_ts": ("timestamp,ip\n2025-13-01 10:00:00,a\n2025-1-5 3:4:5,b\n2025-08-01T10:00:00,c\n"
                       ",d\n2024-02-29 23:59:59,e\n2023-02-29 00:00:00,f\n0999-01-01 00:00:00,g\n"
                       " 2025-08-01 10:00:00,h\n2025-08-01 10:00:60,i\n"),
    "no_timestamp_col": "ip,asn\n1.1.1.1,13335\n8.8.8.8,15169\n",
    "missing_values": "timestamp,ip,port,extra\n2025-08-01 10:00:00,1.1.1.1\n2025-08-01 10:00:00,1.1.1.1,,\n",
    "logged_and_extracted_cols": ("timestamp,logged_date,ip\n2025-08-01 10:00:00,keep-me,1.1.1.1\n"
                                  "\n") + "extracted_date,timestamp\nX,2025-08-01 10:00:00\n",
    "quoted_multiline": 'timestamp,note\n2025-08-01 10:00:00,"line one\nline two"\n2025-08-01 10:00:00,"a,b"\n',
    "weird_line_breaks": "timestamp,ip\r2025-08-01 10:00:00,1.1.1.1\x0c2025-08-01 10:00:00,2.2.2.2 3\n",
    "dup_headers": "timestamp,ip,ip\n2025-08-01 10:00:00,1.1.1.1,2.2.2.2\n",
    "filename_col": "filename,category,timestamp\nmine,cat,2025-08-01 10:00:00\n",
    "header_only": "timestamp,ip\n",
    "empty": "",
}

JSON_CASES = {
    "j1": {"timestamp": "2025-08-01 10:00:00", "ip": "1.1.1.1"},
    "j2": {"timestamp": "bad", "ip": "1.1.1.1"},
    "j3": {"filename": "override", "extracted_date": "x", "timestamp": "2025-08-01 10:00:00"},
    "j4": {"ip": "no ts", "nested": {"a": [1, 2]}},
}


class EquivalenceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, name, text):
        path = os.path.join(self.tmp.name, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        return path

    def test_csv_documents_identical(self):
        for case, text in CSV_CASES.items():
            with self.subTest(case=case):
                fn = f"2025-08-01-{case}-ghana-geo.csv"
                path = self._write(fn, text)
                old_headers, old_docs = old_csv_docs(path, fn, "svc")
                info = {}
                new_docs = list(sp.iter_csv_docs(path, fn, "svc", info=info))
                self.assertEqual(info["headers"], old_headers)
                self.assertEqual(len(new_docs), len(old_docs))
                for o, n in zip(old_docs, new_docs):
                    self.assertEqual(list(o.items()), list(n.items()))  # same keys, order, values, types

    def test_extra_columns_dropped_not_crashing(self):
        fn = "2025-08-01-x-ghana-geo.csv"
        path = self._write(fn, "timestamp,ip\n2025-08-01 10:00:00,1.1.1.1,EXTRA\n")
        _, old_docs = old_csv_docs(path, fn, "svc")
        new_docs = list(sp.iter_csv_docs(path, fn, "svc"))
        self.assertIn(None, old_docs[0])  # original produced an un-insertable document
        old_docs[0].pop(None)
        self.assertEqual(list(old_docs[0].items()), list(new_docs[0].items()))

    def test_json_documents_identical(self):
        for case, obj in JSON_CASES.items():
            with self.subTest(case=case):
                path = self._write(f"{case}.json", json.dumps(obj, indent=2) + "\r\n")
                self.assertEqual(list(old_json_doc(path, f"{case}.json", "svc").items()),
                                 list(sp.json_doc(path, f"{case}.json", "svc").items()))

    def test_parse_ts_matches_strptime(self):
        samples = ["2025-08-01 10:00:00", "2025-1-5 3:4:5", "2025-02-30 00:00:00", "2025-08-01 24:00:00",
                   "0000-01-01 00:00:00", "0001-01-01 00:00:00", "2025-08-01 10:00:61", "2025-08-01 10:00",
                   "2025-08-01 10:00:00 ", "２０２５-08-01 10:00:00", "9999-12-31 23:59:59"]
        for ts in samples:
            with self.subTest(ts=ts):
                try:
                    expected = datetime.datetime.strptime(ts, sp.TS_FMT)
                except ValueError:
                    expected = None
                got = sp.parse_ts(ts)
                self.assertEqual(got, expected)
                if got is not None:
                    self.assertEqual(sp.format_logged(ts, got), got.strftime(sp.TS_FMT))

    def test_service_regex(self):
        cases = {
            "2025-08-01-scan_http-ghana-geo.csv": "scan_http",
            "2025-08-01-scan_http-001-ghana-geo.csv": "scan_http",
            "2025-08-01-event4_honeypot_brute_force-ghana-geo_as12345.csv": "event4_honeypot_brute_force",
            # other CSIRTs: recipient ids of any length, any country
            "2026-11-05-scan_http-1234567-ghana-geo.csv": "scan_http",
            "2026-11-05-scan6_http_vulnerable-7654321-ghana-geo_as64500.csv": "scan6_http_vulnerable",
            "2026-11-05-scan_ssh-77-kenya-geo.csv": "scan_ssh",
            "2026-11-05-event4_sinkhole_dns-1204-south-africa-geo.csv": "event4_sinkhole_dns",
            "2026-11-05-scan_ssh-nigeria.csv": None,
            "readme.txt": None,
        }
        for name, svc in cases.items():
            m = sp.SERVICE_RE.match(name)
            self.assertEqual(m.group(1) if m else None, svc)


if __name__ == "__main__":
    unittest.main()
