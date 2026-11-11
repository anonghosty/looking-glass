"""The advisory's own pages in the report (advisory.py): drawn first, before the analyst's report, which follows
unchanged (combo_pdf.build calls front() and references()).

front: the organisation's logo section and title, the reference, the affected CVEs, issues and categories (only the
kinds that hold something), the reports with their impact flags, the Description (the advisor's text, then a line
pointing to Technical Details), the impact, the Recommended Actions, and "See below for further insight into the
activity" when the report follows. references: Shadowserver Report References, every report the advisory names, with
its address on shadowserver.org (a link).

alone(adv, meta): the advisory's pages on their own, for a finding without a kept search (no report to put below).
"""
import io

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.utils import ImageReader, simpleSplit

from executive_pdf import AMBER, BLUE, DIM, H, M, MUTE, RED, SLATE, TXT, VIOLET, W

LEVEL = {"critical": RED, "high": AMBER, "medium": BLUE, "low": SLATE}
LEVEL_WORD = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
ACCENT = HexColor("#a9b8ff")
BOTTOM = 40                                   # nothing below this line: the footer's room


class Flow:
    """A cursor down the advisory's pages: a new page when the next line would not fit."""

    def __init__(self, doc, title):
        self.doc, self.title = doc, title
        self.y = doc.new_page(title)

    def need(self, h):
        if self.y - h < BOTTOM:
            self.y = self.doc.new_page(f"{self.title} (continued)")

    def heading(self, text):
        self.need(52)
        d = self.doc
        self.y -= 8
        d.c.setFillColor(VIOLET); d.c.rect(M, self.y - 13, 3, 15, stroke=0, fill=1)
        d.text(M + 10, self.y - 10, text, 12.5, TXT, True)
        self.y -= 24

    def para(self, text, size=9.6, color=TXT, bold=False, x=M, width=None):
        d = self.doc
        width = width or (W - M - x)
        lead = size * 1.42
        for block in str(text or "").replace("\r", "").split("\n"):
            lines = simpleSplit(d.s(block), d.F["b"] if bold else d.F["r"], size, width) or [""]
            for ln in lines:                  # wrapped, never cut
                self.need(lead + 2)
                d.text(x, self.y - size, ln, size, color, bold)
                self.y -= lead
        self.y -= 4

    def chips(self, label, items, color=ACCENT):
        """A label and its values as chips, wrapping onto as many lines (and pages) as they need."""
        d = self.doc
        size, x0, w = 8.4, M + 130, W - 2 * M - 130
        lines, cur, cw = [], [], 0
        for it in items:
            iw = d.c.stringWidth(d.s(it), d.F["b"], size) + 14
            if cur and cw + iw > w:
                lines.append(cur); cur, cw = [], 0
            cur.append(it); cw += iw
        if cur:
            lines.append(cur)
        for i, ln in enumerate(lines):
            self.need(18)
            if i == 0:
                d.text(M, self.y - 9, label, 9, DIM, True)
            x = x0
            for it in ln:
                x = d.pill(x, self.y - 9, it, color, size)
            self.y -= 18
        self.y -= 4


def _logo_section(doc, a, y):
    """The logo section, top left: the organisation's logo (or its initial), its name and the advisory's title."""
    c = doc.c
    bw, bh = 132, 74
    c.setFillColor(Color(1, 1, 1, .96)); c.setStrokeColor(Color(1, 1, 1, .2))
    c.roundRect(M, y - bh, bw, bh, 10, stroke=1, fill=1)
    drawn = False
    if a.get("logo"):
        try:
            img = ImageReader(io.BytesIO(a["logo"]))
            iw, ih = img.getSize()
            s = min((bw - 16) / iw, (bh - 16) / ih)
            c.drawImage(img, M + (bw - iw * s) / 2, y - bh + (bh - ih * s) / 2, iw * s, ih * s, mask="auto")
            drawn = True
        except Exception:                     # noqa: BLE001  (an unreadable logo: the initial instead)
            drawn = False
    if not drawn:
        doc.text(M + bw / 2, y - bh / 2 - 9, (a.get("org") or "?")[:1].upper(), 28, HexColor("#1b2140"), True, "middle")
    x = M + bw + 18
    tw = W - M - x
    yy = y - 4
    doc.text(x, yy - 8, "SECURITY ADVISORY", 8.5, ACCENT, True)
    yy -= 14
    for ln in simpleSplit(doc.s(a["title"]), doc.F["b"], 17, tw)[:3]:
        doc.text(x, yy - 16, ln, 17, TXT, True); yy -= 21
    for ln in simpleSplit(doc.s(a.get("subject") or ""), doc.F["r"], 11, tw)[:3]:
        doc.text(x, yy - 12, ln, 11, DIM); yy -= 15
    return min(y - bh, yy) - 12


def front(doc, a):
    """The advisory's pages: everything that holds something, in an advisory's order."""
    f = Flow(doc, "Advisory")
    f.y = _logo_section(doc, a, f.y)
    # the reference line
    x = M
    for label, val in (("Reference", a["ref"]), ("Date", a.get("date") or ""), ("Status", a.get("status_label") or ""),
                       ("Prepared by", a.get("by") or ""), ("Finding", a.get("finding") or "")):
        if not val:
            continue
        w = max(doc.c.stringWidth(doc.s(val), doc.F["b"], 10), doc.c.stringWidth(label, doc.F["r"], 7.6)) + 26
        if x + w > W - M:
            f.y -= 30; x = M
        doc.text(x, f.y - 8, label.upper(), 7.6, MUTE)
        doc.text(x, f.y - 21, val, 10, TXT, True, mono=(label == "Reference"))
        x += w
    f.y -= 32
    if a.get("recipients"):
        f.para("Distribution: " + ", ".join(a["recipients"]), 9, DIM)

    # affected: only the kinds that hold something
    rows = [(k, a.get(key) or []) for k, key in (("CVEs", "cves"), ("Issues", "issues"), ("Categories", "categories"))]
    if any(v for _, v in rows) or a.get("reports"):
        f.heading("Affected")
        for label, vals in rows:
            if vals:
                f.chips(label, vals)
        if a.get("reports"):
            f.chips("Reports", [r["title"] for r in a["reports"]], SLATE)

    f.heading("Description")
    f.para(a.get("description") or "(The advisor has not written the description yet.)",
           color=TXT if a.get("description") else MUTE)
    if a.get("kinds_line"):
        f.para(a["kinds_line"], 9.2, ACCENT, True)

    # impact: the flags of every report in the advisory, the most severe first, and which reports carry them
    if a.get("impact"):
        f.heading("Impact")
        f.para("What the exposures and events in this advisory can lead to, by the reports that found them.", 8.8, DIM)
        for fl in a["impact"]:
            body = simpleSplit(doc.s(fl["text"]), doc.F["r"], 9, W - 2 * M - 70)
            reps = simpleSplit(doc.s("Reports: " + ", ".join(fl["reports"])), doc.F["r"], 8, W - 2 * M - 70)
            f.need(18 + 12.5 * len(body) + 11 * len(reps))
            col = LEVEL.get(fl["level"], SLATE)
            doc.pill(M, f.y - 10, LEVEL_WORD.get(fl["level"], fl["level"]).upper(), col, 7.4)
            doc.text(M + 70, f.y - 10, fl["label"], 10, TXT, True)
            yy = f.y - 10
            for ln in body:                   # under the label, wrapped, never cut
                yy -= 12.5; doc.text(M + 70, yy, ln, 9, TXT)
            for ln in reps:
                yy -= 11; doc.text(M + 70, yy, ln, 8, MUTE)
            f.y = yy - 9

    f.heading("Recommended Actions")
    f.para(a.get("actions") or "(The advisor has not written the recommended actions yet.)",
           color=TXT if a.get("actions") else MUTE)
    if a.get("has_report"):
        f.y -= 6
        f.para("See below for further insight into the activity.", 10.5, ACCENT, True)


def references(doc, a):
    """Shadowserver Report References: every report the advisory names, with its page on shadowserver.org."""
    if not a.get("reports"):
        return
    f = Flow(doc, "Shadowserver Report References")
    f.para("The Shadowserver Foundation's reports this advisory draws on. Each page explains the report, its fields and how "
           "to remediate what it finds.", 9.2, DIM)
    for i, r in enumerate(a["reports"], 1):
        url_lines = simpleSplit(doc.s(r.get("url") or ""), doc.F["m"], 8.4, W - 2 * M - 30)
        f.need(34 + 11 * len(url_lines))
        doc.text(M, f.y - 10, f"{i}.", 10, DIM, True)
        doc.text(M + 22, f.y - 10, r["title"], 10.5, TXT, True)
        where = " · ".join(x for x in (r.get("section"), r.get("group")) if x)
        if r.get("note"):
            where = f"{where} · {r['note']}" if where else r["note"]
        yy = f.y - 23
        if where:
            for ln in simpleSplit(doc.s(where), doc.F["r"], 8.2, W - 2 * M - 30):
                doc.text(M + 22, yy, ln, 8.2, MUTE); yy -= 11
        for ln in url_lines:
            doc.text(M + 22, yy, ln, 8.4, HexColor("#8fb4ff"), mono=True)
            if r.get("url"):
                lw = doc.c.stringWidth(ln, doc.F["m"], 8.4)
                doc.c.linkURL(r["url"], (M + 22, yy - 2, M + 22 + lw, yy + 9), relative=0)
            yy -= 11
        f.y = yy - 8


def alone(a, meta):
    """The advisory's pages on their own (no report below them)."""
    import combo_pdf

    class Doc(combo_pdf.AnalystDoc):
        def footer(self):
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            self.text(M, 14, f"Advisory {a['ref']}. Share only according to your organisation's information-sharing policy. "
                             f"Generated {now}. Data: Shadowserver Foundation.", 7.2, MUTE)
            self.text(W - M, 14, f"Page {self.page}", 7.2, MUTE, anchor="end")

    doc = Doc(dict(meta, advisory=a))
    doc.c.setTitle(f"{a['title']} · {a['ref']}")
    front(doc, a)
    references(doc, a)
    return doc.done()
