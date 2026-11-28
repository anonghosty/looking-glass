#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every downloaded CSV says who downloaded it and when (insider.stamp_csv / stamp_zip and the download seal,
2026-11-27): two columns, "Downloaded by" and "Downloaded at", on every row (the user's choice: a last stamp row made
the CSVs uneven, which imports refuse); every other cell stays as it was; every row as wide as the header; in each CSV
inside a ZIP, and with a list the page saves as a CSV (download_stamp: the column names and cells); the full name and
the person's code, never the sign-in name; a quarterly CSV (stamped already) is left as it is; a name that looks like
a formula is made harmless; Trace a leak finds the file with or without the two columns. In-process with a small Flask
app and temporary folders: no database, no network, no live file. Run: .venv/bin/python tests/check_csv_stamp.py"""
import csv as CSV
import io
import json
import os
import sys
import tempfile
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from flask import Flask, Response, g, jsonify  # noqa: E402

import insider as I  # noqa: E402
import person_code  # noqa: E402

person_code.configure(tempfile.mkdtemp(prefix="lg-csv-stamp-pc-"))   # the person codes' key: temporary, never data/
PC = person_code.code("ada")
WHO = f"Ada Lovelace ({PC})"

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


def rows_of(text):
    return list(CSV.reader(io.StringIO(text.lstrip("﻿"), newline="")))


print("1. The stamp itself")
src = 'Address,Port,Note\r\n198.51.100.7,443,"a note, with a comma"\r\n203.0.113.9,22,"two\r\nlines"\r\n'
out = I.stamp_csv(src.encode(), WHO, "2026-11-27 17:00 UTC").decode()
r = rows_of(out)
ok("the header gets 'Downloaded by' and 'Downloaded at' last", r[0] == ["Address", "Port", "Note", "Downloaded by", "Downloaded at"], r[0])
ok("every row carries who and when", all(x[-2:] == [WHO, "2026-11-27 17:00 UTC"] for x in r[1:]) and len(r) == 3, r)
ok("every row as wide as the header (an even CSV, as imports need)", len({len(x) for x in r}) == 1, [len(x) for x in r])
ok("every other cell as it was (commas, quotes and a line break in a cell too)",
   [x[:-2] for x in r] == rows_of(src), [x[:-2] for x in r])
ok("the line endings kept (\\r\\n)", out.count("\r\n") >= 3 and "\n" not in out.replace("\r\n", ""), repr(out[:60]))
ok("the person's code, never the sign-in name", "(ada)" not in out and ",ada," not in out and PC in out)
bom = I.stamp_csv("﻿a,b\n1,2\n".encode(), "x", "t").decode()
ok("a byte-order mark stays first", bom.startswith("﻿a,b,Downloaded by,Downloaded at\n1,2,x,t"), repr(bom))
ok("a file stamped already is left as it is", I.stamp_csv(out.encode(), "z", "t").decode() == out)
q = b"Quarter,2026Q4\nDownloaded,Grace (p-0123),2026-11-20 10:00 UTC\nx,y\n"
ok("a quarterly CSV, stamped already under its first line, is left as it is", I.stamp_csv(q, "z", "t") == q)
ok("a file that is not UTF-8 text is left as it is", I.stamp_csv(b"\xff\xfe\x00", "z", "t") == b"\xff\xfe\x00")
evil = rows_of(I.stamp_csv(b"a\n1\n", "=HYPERLINK(\"http://x\")", "t").decode())
ok("a name that looks like a formula is made harmless (csvsafe)", evil[1][1].startswith("'="), evil)
ok("the two columns come off again for the fingerprints (_unstamp)", I._unstamp(out) == src, repr(I._unstamp(out)[:80]))
# a file of several tables (the Executive's 7-day trend: figures, a blank row, items under their own header; review
# 2026-11-27: the second header got a name and a time, and a short row put the stamp under another column)
multi = "Day,devices,events\n2026-11-19,5,9\n\nInfection,Mon,Tue,Wed\nmirai,1\n"
mr = rows_of(I.stamp_csv(multi.encode(), "x", "t").decode())
ok("several tables: each table's header gets the two column names",
   mr[0][-2:] == ["Downloaded by", "Downloaded at"] and mr[3][-2:] == ["Downloaded by", "Downloaded at"], mr)
ok("...each row the stamp at its own table's width (a short row padded first)",
   mr[1] == ["2026-11-19", "5", "9", "x", "t"] and mr[4] == ["mirai", "1", "", "", "x", "t"], mr)
ok("...the blank row between them stays blank", mr[2] == [], mr)
ok("text without them is left as it is", I._unstamp(src) == src)

print("2. Inside a ZIP")
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("report.pdf", b"%PDF-1.7 made-up")
    z.writestr("devices.csv", "Address\n192.0.2.1\n")
zout = zipfile.ZipFile(io.BytesIO(I.stamp_zip(buf.getvalue(), WHO, "t")))
zr = rows_of(zout.read("devices.csv").decode())
ok("each CSV in it is stamped", zr == [["Address", "Downloaded by", "Downloaded at"], ["192.0.2.1", WHO, "t"]], zr)
ok("the other files are as they were", zout.read("report.pdf") == b"%PDF-1.7 made-up")
ok("a file that is not a ZIP is left as it is", I.stamp_zip(b"PKnot really", "x", "t") == b"PKnot really")

print("3. On the way out, for a person (the download seal)")
tmp = tempfile.mkdtemp(prefix="lg-csv-stamp-")
os.makedirs(os.path.join(tmp, "data"))
app = Flask(__name__)
app.secret_key = "made-up"


class _Audit:
    def add(self, *a, **k):
        pass


WHO_ON = {"user": "ada"}


@app.before_request
def _who():
    g.user = dict(WHO_ON) if WHO_ON.get("user") else None


@app.get("/file.csv")
def _f():
    return Response("Address,Port\n198.51.100.7,443\n", mimetype="text/csv", headers={"Content-Disposition": 'attachment; filename="file.csv"'})


@app.get("/file.zip")
def _z():
    return Response(buf.getvalue(), mimetype="application/zip", headers={"Content-Disposition": 'attachment; filename="file.zip"'})


@app.get("/proof.zip")
def _p():
    # like the audit proof package: its files are checked against its own MANIFEST.json, so it is never stamped
    return Response(buf.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="proof.zip"', "X-LG-No-Stamp": "1"})


@app.get("/list")
def _l():
    return jsonify(columns=[["ip", "Address"]], rows=[{"ip": "198.51.100.7"}])


I.install(app, {"base_dir": tmp, "has_perm": lambda p: True, "csrf_ok": lambda: True, "audit": _Audit(),
                "people_name": lambda u: {"ada": "Ada Lovelace"}.get(u, "")})
c = app.test_client()
body = c.get("/file.csv").get_data(as_text=True)
br = rows_of(body)
ok("a CSV download: who (full name and person code) and when on every row",
   br[0][-2:] == ["Downloaded by", "Downloaded at"] and br[1][-2] == WHO and br[1][-1].endswith("UTC"), br)
z = zipfile.ZipFile(io.BytesIO(c.get("/file.zip").get_data()))
ok("a ZIP download: its CSV stamped", rows_of(z.read("devices.csv").decode())[1][1] == WHO)
pr = c.get("/proof.zip")
ok("a package checked against its own SHA-256s (the audit proof): sent byte for byte as made, no stamp",
   pr.get_data() == buf.getvalue(), len(pr.get_data()))
ok("...the internal mark never reaches the browser", "X-LG-No-Stamp" not in pr.headers, dict(pr.headers))
lst = c.get("/list?download=1").get_json()
st = lst.get("download_stamp") or {}
ok("a list saved as a CSV in the browser carries the column names and cells (download_stamp)",
   st.get("columns") == ["Downloaded by", "Downloaded at"] and (st.get("cells") or [""])[0] == WHO, lst)
ok("...never the sign-in name", "(ada)" not in json.dumps(st) and '"ada"' not in json.dumps(st), st)
ok("...and the list itself is unchanged", lst.get("rows") == [{"ip": "198.51.100.7"}])
ok("a list shown on the page (no download) carries no stamp", "download_stamp" not in c.get("/list").get_json())
seals = [json.loads(x) for x in open(os.path.join(tmp, "data", "copy_seals.jsonl")) if x.strip()]
ok("the stamped files are still sealed (in Trace a leak)", sum(1 for s in seals if s.get("kind") == "download") >= 3, len(seals))
for label, f in (("with its two columns", body), ("with the two columns deleted", "Address,Port\n198.51.100.7,443\n")):
    tr = c.post("/api/audit/trace", data={"file": (io.BytesIO(f.encode()), "found.csv")}, headers={"X-CSRF-Token": "x"},
                content_type="multipart/form-data").get_json() or {}
    ok(f"Trace a leak: the downloaded CSV {label} is found as the exact file",
       any(m.get("kind") == "download" and m.get("exact") and m.get("what") == "file.csv" for m in tr.get("matches") or []), str(tr)[:200])
WHO_ON["user"] = ""
ok("no one signed in: nothing stamped", "Downloaded by" not in c.get("/file.csv").get_data(as_text=True))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
