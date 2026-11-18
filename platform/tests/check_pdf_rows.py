#!/usr/bin/env python3
"""PDF tables (analysts' report and advisory): a row is as tall as its tallest cell; a long name breaks at its hyphen;
the advisory's table head and first row stay on one page with their heading.
Earlier note: a row is as tall as its tallest cell (the user, 2026-11-18: in the analyst's devices PDF the "Other days"
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

print("4. A long name breaks at its hyphen, never mid-word, never over the next column")
import executive_pdf as EX  # noqa: E402
lines = EX.hard_lines(doc, ["avalanche-andromeda,"], doc.F["r"], 8, doc.c.stringWidth("avalanche-androm", doc.F["r"], 8))
ok("'avalanche-andromeda,' becomes 'avalanche-' / 'andromeda,'", lines == ["avalanche-", "andromeda,"], str(lines))
wide = doc.row_lines([("Infections", .05, "l", False)], 760, ["lumma-stealer-beacon-with-a-very-long-name"])[0]
ok("in the analysts' table every line fits its column", all(doc.c.stringWidth(t, doc.F["r"], 8) <= 760 * .05 - 10 + .01 for t in wide), str(wide))

print("5. The advisory: a table's head and its first row on one page, the heading with them")
import advisory_pdf as APDF  # noqa: E402
reports = [{"title": f"Report number {i} with a long name"} for i in range(40)]
early = "2026-11-15: changed: in Accessible MikroTik Service with Tag: iot + Tag: mikrotik + Tag: mikrotik-btest; calls sinkholes as android.vo1d2"
devs = [{"ip": f"192.0.2.{i}", "ports": ["2000"], "reports": ["Accessible MikroTik Service"], "infections": ["android.vo1d2", "avalanche-andromeda"],
         "last": "2026-11-16 10:00", "earlier": [early, early]} for i in range(6)]
for n in range(0, 40, 3):                        # the table starting at every height down page 1
    seen = []
    orig = CP.AnalystDoc.text                     # every text drawn, with its page

    def rec(self, x, y, t, *a, **k):
        seen.append((self.page, str(t)))
        return orig(self, x, y, t, *a, **k)
    CP.AnalystDoc.text = rec
    try:
        APDF.alone({"logo": None, "title": "T", "ref": "ADV-T", "tlp": "TLP:AMBER", "reports": reports[:n], "devices": devs, "description": "d",
                    "actions": "a", "header": "h", "labels": [], "impact": [], "kinds_line": "", "recipients": []},
                   {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2026-11-16", "generated_by": "t"})
    finally:
        del CP.AnalystDoc.text                    # back to the inherited one
    pg = lambda s: next((p for p, t in seen if t.startswith(s)), None)       # noqa: E731
    if not (pg("Affected IP addresses") == pg("IP ADDRESS") == pg("192.0.2.0")):
        ok(f"with {n} report chips: heading, head and first row together", False,
           f"pages {pg('Affected IP addresses')}, {pg('IP ADDRESS')}, {pg('192.0.2.0')}")
        break
else:
    ok("wherever the table starts on page 1, its heading, head and first row are on one page", True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
