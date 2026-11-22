#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Devices are matched by IP address (external review follow-up, 2026-11-14): the one sentence is the same on the pages
(static/js/loader.js) and in the PDFs (device_note.py), and every place that links reports by device shows it: Across
reports on Combinations and on an analyst code's page, the Executive portal's cross-report cards, and the Executive and
advisory PDFs. No database needed. Run: .venv/bin/python tests/check_device_note.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from device_note import DEVICE_IP_NOTE  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def src(*p):
    with open(os.path.join(HERE, *p), encoding="utf-8") as f:
        return f.read()


print("One sentence, the same everywhere")
ok("it says how devices are matched and why one address can be several devices",
   "IP address" in DEVICE_IP_NOTE and "NAT" in DEVICE_IP_NOTE and "shared mobile" in DEVICE_IP_NOTE)
m = re.search(r'window\.LG_DEVICE_NOTE = "([^"]+)"', src("static", "js", "loader.js"))
ok("the pages' copy (loader.js, on every page) is word for word the PDFs' copy", bool(m) and m.group(1) == DEVICE_IP_NOTE,
   m.group(1) if m else "not found")
ok("…and it is drawn as text, never as HTML", "p.textContent = window.LG_DEVICE_NOTE" in src("static", "js", "loader.js"))
ok("…in a style that wraps (never cut)", ".lg-device-note" in src("static", "css", "app.css")
   and "white-space: normal" in src("static", "css", "app.css").split(".lg-device-note", 1)[-1][:200])

print("Every place that links reports by device shows it")
ok("Combinations: a search's Across reports", "also seen in other reports`), window.lgDeviceNote()" in src("static", "js", "combos.js"))
ce = src("static", "js", "combos-enrich.js")
ok("Combinations: the researcher's and the analyst's Across reports", ce.count("window.lgDeviceNote()") >= 2)
ok("an analyst code's page: Across reports", "sec.append(window.lgDeviceNote())" in src("static", "js", "acode.js"))
mg = src("static", "js", "management.js")
ok("Executive portal: Devices in two reports and the cross-report card (both platforms)",
   'devNote("tX1", comms)' in mg and mg.count('devNote("tCross", true)') == 2)
ok("Executive PDF: the cross-report card", "DEVICE_IP_NOTE" in src("executive_pdf.py"))
ok("advisory and analyst PDFs: Across reports", "DEVICE_IP_NOTE" in src("combo_pdf.py"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
