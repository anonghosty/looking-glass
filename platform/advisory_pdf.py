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
import re

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.utils import ImageReader, simpleSplit

from executive_pdf import AMBER, BLUE, DIM, M, MUTE, RED, SLATE, TXT, VIOLET, W, hard_lines as _hard

LEVEL = {"critical": RED, "high": AMBER, "medium": BLUE, "low": SLATE}
LEVEL_WORD = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
ACCENT = HexColor("#a9b8ff")
BOTTOM = 40                                   # nothing below this line: the footer's room
LIST_MAX = 10                                 # above this many affected IP addresses, the CSV holds them (not the PDF)
KEEP_MAX = 300                               # a block kept on one page is at most this tall (about half a landscape page)
# Observed / Possible as on the app's cards (app.css .mp-cert-observed / -possible / -known)
CERT_COLOUR = {"observed": HexColor("#f6c27a"), "possible": HexColor("#9fdbe6"), "known for this malware": HexColor("#c4b5fd")}


class Flow:
    """A cursor down the advisory's pages: a new page when the next line would not fit."""

    def __init__(self, doc, title):
        self.doc, self.title = doc, title
        self.y = doc.new_page(title)

    def need(self, h):
        if self.y - h < BOTTOM:
            self.y = self.doc.new_page(f"{self.title} (continued)")

    def heading(self, text, keep=0):
        """keep: the height of what must follow on the same page (a table's head and first row): a heading never
        stands alone at the foot of a page (2026-11-18)."""
        self.need(52 + keep)
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

    def para_cert(self, text, size, cert, x=M):
        """A bold line ending in the certainty with the cards' look (app.css .mp-cert, the user's choice 2026-11-18):
        the word in its colour inside a thin faded outline of the same colour, no fill. Observed amber, Possible teal."""
        d = self.doc
        col = CERT_COLOUR.get(cert.lower())
        if not col:
            return self.para(f"{text} · {cert}" if cert else text, size, TXT, True, x=x)
        lead = size * 1.42
        bs = size * .82                                  # the badge's text, a little smaller, as on the cards
        bw = d.c.stringWidth(d.s(cert), d.F["b"], bs) + 10
        lines = simpleSplit(d.s(text + " ·"), d.F["b"], size, W - M - x) or [""]
        last_w = d.c.stringWidth(lines[-1], d.F["b"], size)
        own_line = x + last_w + 6 + bw > W - M           # no room after the last line: the badge on a line of its own
        for i, ln in enumerate(lines):
            self.need(lead + 2)
            d.text(x, self.y - size, ln, size, TXT, True)
            if i == len(lines) - 1 and not own_line:
                self._badge(x + last_w + 6, self.y - size, cert, bs, col)
            self.y -= lead
        if own_line:
            self.need(lead + 2)
            self._badge(x, self.y - size, cert, bs, col)
            self.y -= lead
        self.y -= 4

    def _badge(self, x, base, word, size, col):
        c = self.doc.c
        w = c.stringWidth(self.doc.s(word), self.doc.F["b"], size) + 10
        c.setStrokeColor(Color(col.red, col.green, col.blue, .5)); c.setLineWidth(.7)
        c.roundRect(x, base - 3.2, w, size + 5.6, 3.5, stroke=1, fill=0)
        self.doc.text(x + 5, base, word, size, col, True)

    def height(self, text, size=9.6, bold=False, x=M, width=None):
        """How much room para() would take for this text (to keep a block together before drawing it)."""
        d = self.doc
        width = width or (W - M - x)
        n = sum(len(simpleSplit(d.s(b), d.F["b"] if bold else d.F["r"], size, width) or [""])
                for b in str(text or "").replace("\r", "").split("\n"))
        return n * size * 1.42 + 4

    def rich(self, text, size=9.6, color=TXT):
        """The advisor's text with its light markup: "- " bullets, "1. " numbers, **bold**; wrapped, never cut."""
        d = self.doc
        lead = size * 1.42
        for raw in str(text or "").replace("\r", "").split("\n"):
            if not raw.strip():
                self.y -= lead * .5
                continue
            mb = re.match(r"^\s*[-*•]\s+(.*)$", raw)
            mn = re.match(r"^\s*(\d{1,3})[.)]\s+(.*)$", raw)
            mark, body = ("•", mb.group(1)) if mb else (f"{mn.group(1)}.", mn.group(2)) if mn else ("", raw.strip())
            x0 = M + (16 if mark else 0)
            width = W - M - x0
            words = []                                   # (word, bold), the ** pairs switching bold on and off
            for i, seg in enumerate(body.split("**")):
                words += [(w, i % 2 == 1) for w in seg.split()]
            lines, cur, cw = [], [], 0
            for w, b in words:
                ww = d.c.stringWidth(d.s(w), d.F["b"] if b else d.F["r"], size)
                sp = d.c.stringWidth(" ", d.F["r"], size) if cur else 0
                if cur and cw + sp + ww > width:
                    lines.append(cur); cur, cw, sp = [], 0, 0
                cur.append((w, b, ww)); cw += sp + ww
            lines.append(cur)
            for li, ln in enumerate(lines):
                self.need(lead + 2)
                if li == 0 and mark:
                    d.text(M + 2, self.y - size, mark, size, ACCENT, True)
                x = x0
                for w, b, ww in ln:
                    d.text(x, self.y - size, w, size, color, b)
                    x += ww + d.c.stringWidth(" ", d.F["r"], size)
                self.y -= lead
        self.y -= 4

    def cells(self, cols, r, size=8.2):
        """Each cell's lines: wrapped at spaces, a long word broken after a hyphen (_hard); never cut."""
        d, w = self.doc, W - 2 * M
        return [_hard(d, simpleSplit(d.s(str(v)), d.F["m"] if mono else d.F["r"], size, w * fr - 10) or [""],
                      d.F["m"] if mono else d.F["r"], size, w * fr - 10)
                for v, (_, fr, mono) in zip(r, cols)]

    def row_height(self, cols, r, size=8.2):
        return max(len(c) for c in self.cells(cols, r, size)) * (size + 2.2) + 5

    def table(self, cols, rows, size=8.2):
        """A table that wraps every cell (never cut) and carries on over pages, its head on each.
        cols [(label, fraction, mono)]."""
        d = self.doc
        w = W - 2 * M
        xs, acc = [], M
        for _, fr, _ in cols:
            xs.append(acc); acc += w * fr
        lead = size + 2.2

        def head():
            for (lbl, fr, _), cx in zip(cols, xs):
                d.text(cx + 4, self.y - 9, lbl.upper(), 6.8, MUTE, True)
            d.c.setStrokeColor(Color(1, 1, 1, .1)); d.c.setLineWidth(.6); d.c.line(M, self.y - 14, M + w, self.y - 14)
            self.y -= 14
        # the head goes on the page its first row goes on (2026-11-18: a tall first row moved on and left the head
        # alone over half an empty page)
        self.need(14 + (self.row_height(cols, rows[0], size) if rows else 26))
        head()
        for i, r in enumerate(rows):
            cells = self.cells(cols, r, size)
            rh = max(len(c) for c in cells) * lead + 5
            if self.y - rh < BOTTOM:
                self.y = self.doc.new_page(f"{self.title} (continued)")
                head()
            if i % 2:
                d.c.setFillColor(Color(1, 1, 1, .025)); d.c.rect(M, self.y - rh, w, rh, stroke=0, fill=1)
            for (lbl, fr, mono), cx, lines in zip(cols, xs, cells):
                for j, t in enumerate(lines):
                    d.text(cx + 4, self.y - 10 - lead * j, t, size, HexColor("#e3e9ff") if mono else HexColor("#d6ddee"), False, "start", mono)
            self.y -= rh
        self.y -= 8

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
    # the advisor's own title large (the user, 2026-11-18: "Void 2 Detected" is the heading); the CSIRT's line
    # ("Meridian CSIRT Security Advisory", or an older advisory's typed heading) small above it. Every line kept.
    eyebrow = (a.get("title") or "Security Advisory").upper()
    for ln in simpleSplit(doc.s(eyebrow), doc.F["b"], 8.5, tw):
        doc.text(x, yy - 8, ln, 8.5, ACCENT, True); yy -= 12
    yy -= 2
    for ln in simpleSplit(doc.s(a.get("subject") or a.get("title") or ""), doc.F["b"], 17, tw):
        doc.text(x, yy - 16, ln, 17, TXT, True); yy -= 21
    return min(y - bh, yy) - 12


def front(doc, a):
    """The advisory's pages: everything that holds something, in an advisory's order."""
    f = Flow(doc, "Advisory")
    f.y = _logo_section(doc, a, f.y)
    # the reference line
    x = M
    # no workflow status in the report: what the organisation receives is the advisory, not "Draft"
    for label, val in (("Organisation", a.get("network") or ""), ("TLP", a.get("tlp") or ""), ("Reference", a["ref"]), ("Date", a.get("date") or ""),
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
    if a.get("tlp"):                              # how far it may go (TLP 2.0), in words, under the label
        f.para(f"{a['tlp']} ({a.get('tlp_short', '')}): {a.get('tlp_text', '')} Traffic Light Protocol 2.0, FIRST.", 8.8,
               HexColor(a.get("tlp_colour") or "#FFC000"))

    # affected: only the kinds that hold something
    rows = [(k, a.get(key) or []) for k, key in (("CVEs", "cves"), ("Issues", "issues"), ("Categories", "categories"))]
    if any(v for _, v in rows) or a.get("reports"):
        f.heading("Affected")
        for label, vals in rows:
            if vals:
                f.chips(label, vals)
        if a.get("labels"):                      # what the devices are (product / protocol tags): context, not issues
            f.chips("Seen as", a["labels"], SLATE)
        if a.get("reports"):
            f.chips("Reports", [r["title"] for r in a["reports"]], SLATE)

    # the organisation's IP addresses: what the advisory is about
    devs = a.get("devices") or []
    if devs:
        # infections apart from CVEs and issues (2026-11-14): what the device calls botnet sinkholes as
        # the other days in memory (2026-11-17): the same combination there too, or what the device carried instead
        other = any(d.get("earlier") for d in devs)
        # with Other days, its long text gets the room (2026-11-18: at 15 % each row was a column of words, too tall to
        # start under the report chips); an IPv6 address still fits its column on two lines
        cols = ([("IP address", .12 if other else .13, True), ("Host name", .09 if other else .12, False), ("Ports", .05 if other else .06, True),
                 ("Reports", .12 if other else .2, False), ("CVEs and issues", .13 if other else .23, False),
                 ("Infections", .12 if other else .14, False), ("Last seen (UTC)", .09 if other else .12, True)]
                + ([("Other days", .28, False)] if other else []))
        trows = [[d["ip"], d.get("hostname") or "–", ", ".join(d.get("ports") or []) or "–", ", ".join(d.get("reports") or []) or "–",
                  ", ".join((d.get("cves") or []) + (d.get("issues") or [])) or "–",
                  ", ".join(d.get("infections") or d.get("categories") or []) or "–", d.get("last") or "–"]
                 + (["; ".join(d.get("earlier") or []) or "–"] if other else []) for d in devs]
        if len(devs) > LIST_MAX and a.get("devices_csv"):
            # many addresses: said, not listed (the user, 2026-11-18: "this will save space and prevent too much
            # information"); the devices CSV sent with the PDF holds every one, with all these columns
            f.heading(f"Affected IP addresses ({len(devs):,})")
            f.para(f"Due to the number of affected IP addresses ({len(devs):,}), they are not listed here. Kindly refer to the "
                   f"attached CSV file, {a['devices_csv']}: it lists every IP address with its host name, ports, network and "
                   "location, the reports that found it, its infections, issues and CVEs, when it was first and last seen, and "
                   "what it carried on the other days.", 9.6, TXT)
        else:
            # the heading keeps the table's head and first row with it on one page
            f.heading(f"Affected IP addresses ({len(devs):,})", keep=14 + f.row_height(cols, trows[0]))
            f.table(cols, trows)

    f.heading("Description")
    if a.get("description"):
        f.rich(a["description"])
    else:
        f.para("(The advisor has not written the description yet.)", color=MUTE)
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

    # MITRE ATT&CK techniques: the mappings of the reports in the advisory, with the ATT&CK version this advisory was
    # generated with (kept with the advisory: a sent one keeps what the recipient got; attack_map.py)
    att = a.get("attack") or {}                   # reviewed mappings only (advisory_attack.for_recipients)
    if att.get("techniques"):
        f.heading("MITRE ATT&CK techniques")
        f.para(f"MITRE ATT&CK v{att.get('version') or '?'}. Observed: the report saw it; Possible: an exposure an attacker "
               "could use. \"What it is\" and \"How to defend\" are MITRE's words; \"Why it is in this advisory\" is ours. "
               "© The MITRE Corporation, reproduced and distributed with its permission.", 8.8, DIM)
        if any(t.get("cve") for t in att["techniques"]):
            f.para("CVE techniques: MITRE Center for Threat-Informed Defense, Mappings Explorer (KEV to ATT&CK). © MITRE, "
                   "Apache License 2.0.", 8.8, DIM)
        seen = set()
        for t in att["techniques"]:
            if (t["id"], t.get("report"), t.get("category"), t.get("cve"), t.get("kind")) in seen:
                continue
            seen.add((t["id"], t.get("report"), t.get("category"), t.get("cve"), t.get("kind")))
            cert = (t.get("certainty_label") or "").split(" (")[0] or str(t.get("certainty") or "").capitalize()
            # the technique's lines as (text, size, colour, bold, x), measured first so the whole block is kept on one
            # page (a technique split from its "How to defend" was seen in a render, 2026-11-13); a block taller than
            # KEEP_MAX still flows over pages rather than leaving a page empty
            # the first line ends in Observed / Possible only, with the cards' look (the user, 2026-11-18); the
            # device's part is in "Why it is in this advisory"
            head = f"{t['id']} {t['name']} · {', '.join(t.get('tactics') or [])}"
            rows = []
            if t.get("desc"):
                rows.append((f"What it is (MITRE): {t['desc']}", 9, TXT, False, M + 10))
            if t.get("why_here"):
                rows.append((f"Why it is in this advisory (Looking Glass): {t['why_here']}", 9, TXT, False, M + 10))
            if t.get("comment"):                      # CTID's own words on how the CVE maps (KEV mappings, Apache 2.0)
                rows.append((f"How {t.get('cve') or 'the vulnerability'} maps (MITRE CTID): {t['comment']}", 9, TXT, False, M + 10))
            if t.get("note"):                         # the ATT&CK version CTID mapped with differs: renamed / revoked
                rows.append((f"ATT&CK version: {t['note']}.", 8.8, DIM, False, M + 10))
            if t.get("defend"):
                rows.append(("How to defend (MITRE mitigations):", 9, TXT, False, M + 10))
                for m in t["defend"]:
                    rows.append((f"• {m['id']} {m['name']}" + (f": {m['text']}" if m.get("text") else ""), 8.8, DIM, False, M + 20))
            rows.append((f"MITRE ATT&CK: {t.get('url') or ''}", 8.4, ACCENT, False, M + 10))
            f.y -= 4
            f.need(min(f.height(head + " · " + cert + " xx", 9.6, True) + sum(f.height(s, z, b, x) for s, z, _, b, x in rows), KEEP_MAX))
            f.para_cert(head, 9.6, cert)
            for s, z, c, b, x in rows:
                f.para(s, z, c, b, x=x)

    f.heading("Recommended Actions")
    if a.get("actions"):
        f.rich(a["actions"])
    else:
        f.para("(The advisor has not written the recommended actions yet.)", color=MUTE)
    if a.get("has_report"):
        f.y -= 6
        f.para("See below for further insight into the activity.", 10.5, ACCENT, True)


def references(doc, a, cards=(), levels=None):
    """References (the user, 2026-11-18): every defined name's references, then every Shadowserver report the advisory
    names with its page on shadowserver.org, all ordered by criticality and flagged with it (pdf_refs.py)."""
    import pdf_refs
    reps = [{"title": r["title"], "url": r.get("url") or "", "severity": pdf_refs.severity_by_url(r.get("url")),
             "where": " · ".join(x for x in (r.get("section"), r.get("group"), r.get("note")) if x)}
            for r in a.get("reports") or []]
    pdf_refs.draw(doc, pdf_refs.groups(cards, levels or {}, reps),
                  "The sources behind this advisory: each defined name with its references, then the Shadowserver "
                  "Foundation's reports it draws on (each page explains the report, its fields and how to remediate what "
                  "it finds), the most critical first.")


def alone(a, meta):
    """The advisory's pages on their own (no report below them)."""
    import combo_pdf

    class Doc(combo_pdf.AnalystDoc):
        def footer(self):
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
            page = f"Page {self.page}"
            self.text(W - M, 14, page, 7.2, MUTE, anchor="end")
            self.tlp_mark(14, W - M - self.c.stringWidth(page, self.F["r"], 7.2) - 10)
            if self.preview_text():                # a preview: who and when (combo_pdf.AnalystDoc.preview_marks)
                self.text(M, 14, self.preview_text(), 7.2, HexColor("#f5b54a"), True)
                return
            self.text(M, 14, f"Advisory {a['ref']}. Generated {now} by {a.get('org') or 'the CSIRT'}.", 7.2, MUTE)

    doc = Doc(dict(meta, advisory=a))
    doc.c.setTitle(f"{a.get('subject') or a['title']} · {a['ref']}")     # the advisor's title, as on the page
    front(doc, a)
    references(doc, a)
    return doc.done()
