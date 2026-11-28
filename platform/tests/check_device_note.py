#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Devices are matched by IP address (external review follow-up, 2026-11-14): the one sentence is the same on the pages
(static/js/loader.js) and in the PDFs (device_note.py), and every place that links reports by device shows it: Across
reports on Combinations and on an analyst code's page, the Executive portal's cross-report cards, and the Executive and
advisory PDFs. The page files are the ones that ship (the held copies in $LG_HELD_DIR when there are); node runs
loader.js's note and the Executive portal's devNote. No database needed. Run: .venv/bin/python tests/check_device_note.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
import page_harness as H  # noqa: E402
from device_note import DEVICE_IP_NOTE  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


def src(*p):
    """a platform file; a page file (static/, templates/) as the held copy that ships when there is one"""
    held = os.path.join(H.HELD, p[-1] + ".new") if H.HELD and p[0] in ("static", "templates") else ""
    with open(held if held and os.path.isfile(held) else os.path.join(HERE, *p), encoding="utf-8") as f:
        return f.read()


if not H.NODE:
    print("SKIPPED: no node to run the pages with"); sys.exit(77)

print("One sentence, the same everywhere")
ok("it says how devices are matched and why one address can be several devices",
   "IP address" in DEVICE_IP_NOTE and "NAT" in DEVICE_IP_NOTE and "shared mobile" in DEVICE_IP_NOTE)
loader = src("static", "js", "loader.js")
note_js = "\n".join(m.group(0) for m in re.finditer(r"^  window\.(?:LG_DEVICE_NOTE|lgDeviceNote) = .*$", loader, re.M))
mg = src("static", "js", "management.js")
R, raw = H.run(r"""
let html = 0; Object.defineProperty(N.prototype, "innerHTML", { set() { html++; }, get() { return ""; } });
""" + note_js + "\n" + H.extract(mg, ["$", "devNote"]) + r"""
const a = window.lgDeviceNote();
const card = document.createElement("div"), sub = document.createElement("p"); card.append(sub); IDS.tX1 = sub;
devNote("tX1", true); devNote("tX1", true);
const once = card.children.filter((n) => n._cls.has("lg-device-note")).length;
devNote("tX1", false); const hid = card.children[1] && card.children[1].hidden;
devNote("tX1", true); const back = card.children[1] && !card.children[1].hidden;
devNote("nowhere", true);
console.log(JSON.stringify({ note: window.LG_DEVICE_NOTE, text: a.textContent, tag: a.tag, cls: a.className, html, once, hid, back, errs: ERRS }));
""")
R = R or {}
ok("the pages' copy (loader.js, on every page) is word for word the PDFs' copy", R.get("note") == DEVICE_IP_NOTE, str(R.get("note")) or raw[-300:])
ok("...lgDeviceNote() draws it as the text of a paragraph, never as HTML",
   R.get("text") == DEVICE_IP_NOTE and R.get("tag") == "p" and R.get("cls") == "lg-device-note" and R.get("html") == 0, str(R))
ok("the Executive portal's devNote puts it under a card's subtitle once, however often it is called", R.get("once") == 1, str(R.get("once")))
ok("...hides it when the card does not link reports by device, and shows it again", R.get("hid") is True and R.get("back") is True, str(R))
ok("...and a card that is not there is no error", not R.get("errs"), str(R.get("errs")))
css = src("static", "css", "app.css")
ok("…in a style that wraps (never cut)", ".lg-device-note" in css and "white-space: normal" in css.split(".lg-device-note", 1)[-1][:200])

print("Every place that links reports by device shows it (the page files that ship)")
ok("Combinations: a search's Across reports", "also seen in other reports`), window.lgDeviceNote()" in src("static", "js", "combos.js"))
ce = src("static", "js", "combos-enrich.js")
ok("Combinations: the researcher's and the analyst's Across reports", ce.count("window.lgDeviceNote()") >= 2)
ok("an analyst code's page: Across reports", "sec.append(window.lgDeviceNote())" in src("static", "js", "acode.js"))
ok("Executive portal: Devices in two reports and the cross-report card (both platforms)",
   'devNote("tX1", comms)' in mg and mg.count('devNote("tCross", true)') == 2)
ok("Executive PDF: the cross-report card", "DEVICE_IP_NOTE" in src("executive_pdf.py"))
ok("advisory and analyst PDFs: Across reports", "DEVICE_IP_NOTE" in src("combo_pdf.py"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
