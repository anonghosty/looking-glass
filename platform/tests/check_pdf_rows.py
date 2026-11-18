#!/usr/bin/env python3
"""PDF tables: a row is as tall as its tallest cell (the user, 2026-11-18: in the analyst's devices PDF the "Other days"
column ran over the rows below it: cells stopped at three lines and squeezed the rest into the third). Made-up rows:
1. a long text cell keeps every word, on as many lines as it needs (no "…", nothing squeezed)
2. the row's height covers all of them, so the next row starts below the last line
3. the table's height (what decides the page breaks) is the sum of those rows
Run: .venv/bin/python tests/check_pdf_rows.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import combo_pdf as CP  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


doc = CP.AnalystDoc({"platform_label": "Services"})
cols = [("IP address", .1, "l", True), ("Infections, issues, CVEs", .15, "l", False), ("Other days", .2, "l", False)]
W = 760
long = ("2026-11-15: changed: in Accessible MikroTik Service with Tag: iot + Tag: mikrotik + Tag: mikrotik-btest; calls sinkholes "
        "as android.vo1d2; 2026-11-17: changed: in Accessible MikroTik Service with Tag: iot + Tag: mikrotik + Tag: mikrotik-btest; "
        "no sinkhole call; 2026-11-14: carried this same combination")
rows = [["192.0.2.1", "android.vo1d2, avalanche-andromeda, m0yv", long], ["192.0.2.2", "m0yv", "–"]]

print("1. Every word kept")
cells = doc.row_lines(cols, W, rows[0])
other = cells[2]
ok("the long cell is on more than three lines", len(other) > 3, f"{len(other)} lines")
ok("every line is plain text at the table's size (nothing squeezed smaller)", all(isinstance(t, str) for t in other))
ok("no word lost, no '…'", " ".join(other).split() == doc.s(long).split() and "…" not in " ".join(other))
ok("each line fits its column", all(doc.c.stringWidth(t, doc.F["r"], 8) <= W * .2 - 10 + .01 for t in other))

print("2. The row covers them")
rh = doc.row_height(cells)
ok("the row is at least 10 pt a line of its tallest cell", rh >= len(other) * 10, f"{rh} pt for {len(other)} lines")
y_end = doc.table(0, 1000, W, cols, rows)
ok("drawn: the table ends below every line", y_end <= 1000 - 14 - rh - doc.row_height(doc.row_lines(cols, W, rows[1])) + .01, f"{y_end}")

print("3. The page breaks use the same heights")
ok("table_height is the head plus each row", abs(doc.table_height(cols, W, rows) - (14 + rh + doc.row_height(doc.row_lines(cols, W, rows[1])))) < .01)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
