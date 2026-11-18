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

print("6. The advisory's own title is the large one (2026-11-18), the CSIRT's line small above it, nothing cut")
drawn = []
orig = CP.AnalystDoc.text


def rec2(self, x, y, t, size=10, *a, **k):
    drawn.append((str(t), size))
    return orig(self, x, y, t, size, *a, **k)


CP.AnalystDoc.text = rec2
try:
    long_title = "Void 2 Detected: " + " ".join(["MikroTik routers and Android TV boxes calling sinkholes"] * 4)
    APDF.alone({"logo": None, "title": "Example CSIRT Security Advisory", "subject": long_title, "ref": "ADV-T", "tlp": "TLP:AMBER",
                "reports": [], "devices": [], "description": "d", "actions": "a", "header": "h", "labels": [], "impact": [],
                "kinds_line": "", "recipients": []},
               {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2026-11-16", "generated_by": "t"})
finally:
    del CP.AnalystDoc.text
big = [t for t, s in drawn if s == 17]
ok("the advisor's title is printed large, every word of it (no line dropped)", " ".join(big).split() == long_title.split(), f"{len(big)} lines")
ok("... and the CSIRT's line small above it", ("EXAMPLE CSIRT SECURITY ADVISORY", 8.5) in drawn)

print("7. The Executive report: long names, long descriptions and long labels never overlap and are never cut (2026-11-18)")
import executive_pdf as EXP  # noqa: E402


def drawn_boxes(doc_cls, build):
    """Every text the page draws, as (x0, y0, x1, y1, text), and the doc."""
    seen, orig_t = [], doc_cls.text

    def rec(self, x, y, t, size=10, color=None, bold=False, anchor="start", mono=False):
        f = self.F["m"] if mono else self.F["b"] if bold else self.F["r"]
        s_ = getattr(t, "size", None) or size
        lines = getattr(t, "lines", None) or [str(t)]
        for i, ln in enumerate(lines):
            w_ = self.c.stringWidth(self.s(ln), f, s_)
            x0 = x if anchor == "start" else x - w_ if anchor == "end" else x - w_ / 2
            yy_ = y - i * s_ * 1.15
            seen.append((x0, yy_ - s_ * .22, x0 + w_, yy_ + s_ * .75, str(ln)))
        return orig_t(self, x, y, t, size, color if color is not None else EXP.TXT, bold, anchor, mono)
    doc_cls.text = rec
    try:
        d = build()
    finally:
        doc_cls.text = orig_t
    return seen, d


def overlaps(boxes):
    out = []
    for i in range(len(boxes)):
        a = boxes[i]
        for b in boxes[i + 1:]:
            w_ = min(a[2], b[2]) - max(a[0], b[0]); h_ = min(a[3], b[3]) - max(a[1], b[1])
            if w_ > 1 and h_ > 1.5:
                out.append((a[4][:30], b[4][:30]))
    return out


long_desc = ("The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows remote "
             "attackers to bypass integrity checks such that some packets are omitted (from the extension negotiation message), and a "
             "client and server may consequently end up with a connection for which some security features have been downgraded or "
             "disabled, aka a Terrapin attack.")
rows = [{"value": f"CVE-2023-4879{i}", "title": long_desc if i % 2 else "Exposed administration panel", "hosts": 200 - i, "count": 200 - i,
         "cve": True, "cvss": 5.9, "epss": .94, "exploited": i % 3 == 0} for i in range(8)]
rows.insert(2, {"value": "popcorntime", "title": "Popcorn Time (Time4Popcorn) with an abandoned updater (not malware)", "hosts": 150, "count": 150})


def build_rank():
    d_ = EXP.Doc({"platform_label": "Services", "scope": "s", "selection": "s", "day": "2026-11-17", "cities": [], "tz": None, "generated_by": "t"})
    y_ = d_.new_page("Top issues")
    d_.ranking(EXP.M + 14, y_ - 40, 470, rows, False, max_rows=13, bottom=38)
    d_.bars(560, y_ - 40, 230, [{"label": "Accessible GPRS Tunneling Protocol (GTP)", "hosts": 900}, {"label": "Accessible SSH", "hosts": 800}],
            n=8, bottom=40)
    return d_


boxes, _ = drawn_boxes(EXP.Doc, build_rank)
ov = overlaps([b for b in boxes if b[1] > 40 and b[3] < EXP.H - 80])          # the page's body, not the header and footer
ok("the top list and the bars: no text over another", not ov, str(ov[:4]))
words = " ".join(b[4] for b in boxes)
ok("... the long description is there in full", all(w_ in words for w_ in ("Terrapin", "disabled,", "consequently")))
ok("... the long name too", "(not malware)" in words and "Popcorn" in words)

lots = " ".join(["Researchers saw this family on many devices across several networks this week."] * 9) + " The very last words."


def build_expl():
    d_ = EXP.Doc({"platform_label": "Services", "scope": "s", "selection": "s", "day": "2026-11-17", "cities": [], "tz": None, "generated_by": "t"})
    y_ = d_.new_page("Explained")
    d_.explanation(EXP.M, y_ - 20, 380, "android.midnight-mimosa", {"curated": True, "title": "Midnight Mimosa (preinstalled Android malware)",
                   "description": lots, "notes": [{"role": "Researcher", "by": "Grace", "date": "2026-11-16", "text": lots}]}, "130 devices", True)
    return d_


boxes, _ = drawn_boxes(EXP.Doc, build_expl)
ok("an Explained card keeps every line of its text and notes (no sentence stops mid-way)",
   sum(b[4].count("The very last words.") for b in boxes) == 2, f"{sum(b[4].count('The very last words.') for b in boxes)} of 2 endings drawn")

print("8. An advisory's page names (2026-11-18)")
ok("the Technical Details pages are titled Definitions under the TECHNICAL DETAILS badge",
   CP.AnalystDoc.label_of("Definitions") == "TECHNICAL DETAILS" and CP.AnalystDoc.label_of("Ports · Definitions") == "INSIGHTS · TECHNICAL DETAILS"
   and "EXPL = \"Definitions\" if adv" in open(CP.__file__, encoding="utf-8").read())
ok("the map page is Geographic Location, the address table IP addresses",
   'new_page("Geographic Location")' in open(CP.__file__, encoding="utf-8").read() and 'new_page("IP addresses")' in open(CP.__file__, encoding="utf-8").read())

said = []
orig = CP.AnalystDoc.text
CP.AnalystDoc.text = lambda self, x, y, t, *a, **k: (said.append((self.meta.get("advisory") is not None, str(t))), orig(self, x, y, t, *a, **k))[1]
try:
    for adv_meta in ({"x": 1}, None):
        d_ = CP.AnalystDoc({"platform_label": "Publicly accessible services", "scope": "Ghana · whole country", "header": "h",
                            **({"advisory": adv_meta} if adv_meta else {})})
        for sec in ("Advisory", "Overview", "Definitions", "Shadowserver Report References"):
            d_.new_page(sec)
finally:
    del CP.AnalystDoc.text
line = "Publicly accessible services · Ghana · whole country"
ok("no page of an advisory prints the platform and scope line (2026-11-18: taken out entirely)",
   not any(a and t == line for a, t in said) and any((not a) and t == line for a, t in said))

print("9. More than 10 affected IP addresses: the advisory points to the CSV instead of listing them (2026-11-18)")


def adv_text(n, csv):
    said_ = []
    orig_ = CP.AnalystDoc.text
    CP.AnalystDoc.text = lambda self, x, y, t, *a, **k: (said_.append(str(t)), orig_(self, x, y, t, *a, **k))[1]
    try:
        APDF.alone({"logo": None, "title": "T", "ref": "ADV-T", "tlp": "TLP:AMBER", "reports": [], "description": "d", "actions": "a",
                    "header": "h", "labels": [], "impact": [], "kinds_line": "", "recipients": [], **({"devices_csv": csv} if csv else {}),
                    "devices": [{"ip": f"192.0.2.{i}", "ports": ["2000"], "reports": ["R"], "last": "2026-11-16 10:00"} for i in range(n)]},
                   {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2026-11-16", "generated_by": "t"})
    finally:
        del CP.AnalystDoc.text
    return " ".join(said_)


many, few, alone_ = adv_text(14, "X_devices.csv"), adv_text(10, "X_devices.csv"), adv_text(14, None)
ok("14 addresses with a CSV: no address listed, the CSV named", "192.0.2.3" not in many and "X_devices.csv" in many and "(14)" in many)
ok("10 addresses: the table, as before", "192.0.2.9" in few and "refer to the" not in few)
ok("no CSV goes with it (the advisory alone): the table stays, nothing points to a file that is not sent", "192.0.2.13" in alone_)
import combos as CB  # noqa: E402
src_ = open(CB.__file__, encoding="utf-8").read()
ok("the devices CSV carries the host name and ports the table showed", '"ip", "host_name", "ports"' in src_)
import advisory as ADV  # noqa: E402
gen = open(ADV.__file__, encoding="utf-8").read().split('def api_advisory_generate', 1)[1].split("@app.route", 1)[0]
ok("RULE: Generate report always gives the advisory AND its devices CSV (never a PDF alone)",
   "if not kept(x):" in gen and "if not zbytes:" in gen and gen.index("if not kept(x):") < gen.index("build(x, adv, network)"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
