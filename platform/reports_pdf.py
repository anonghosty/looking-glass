"""PDF reports of an analysis figure (a "card") on either platform: an executive summary, key figures, activity charts,
the infections / categories explained (Malpedia, threat actors, or the Looking Glass definitions written by researchers),
breakdowns, the complete list and the report definitions.

build(spec) -> bytes. Everything printed comes from the same server-side analysis as the page (and is masked the same
way in Demo mode). All text is escaped before it reaches reportlab's markup parser.
"""
import io
import os
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import HorizontalBarChart, VerticalBarChart
from reportlab.graphics.shapes import Drawing, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (CondPageBreak, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

# the dashboard's colours (dark pages, like the management portal and its executive report)
NAVY = colors.HexColor("#eef2fb")          # headings
ACCENT = colors.HexColor("#9fbaff")        # links
MUTED = colors.HexColor("#9aa6bf")
LINE = colors.HexColor("#222a3f")
SOFT = colors.HexColor("#151b2d")          # zebra rows
PAGE_BG = colors.HexColor("#070a12")
CARD_BG = colors.HexColor("#111627")
HEAD_BG = colors.HexColor("#1b2238")
BODY = colors.HexColor("#d6ddee")
KINDS = {"found": colors.HexColor("#2e7d5b"), "actor": colors.HexColor("#b7791f"), "curated": colors.HexColor("#6d4fc4"),
         "none": colors.HexColor("#8a93a3"), "kev": colors.HexColor("#c0392b"), "cve": colors.HexColor("#2f5fb3")}
MAX_ROWS = 5000                     # rows printed in the complete list (the CSV has every row)

# ------------------------------------------------------------------ fonts: Unicode where the server has DejaVu
_FONT = {"r": "Helvetica", "b": "Helvetica-Bold", "i": "Helvetica-Oblique", "m": "Courier"}


def _fonts():
    if _FONT.get("done"):
        return
    _FONT["done"] = True
    # fonts-dejavu-core (installed by install.sh) has regular and bold; italic and mono are used when present
    for base in ("/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu", "/usr/share/fonts/TTF"):
        files = {"r": "DejaVuSans.ttf", "b": "DejaVuSans-Bold.ttf", "i": "DejaVuSans-Oblique.ttf", "m": "DejaVuSansMono.ttf"}
        if all(os.path.exists(os.path.join(base, files[k])) for k in ("r", "b")):
            try:
                got = {}
                for k, f in files.items():
                    if os.path.exists(os.path.join(base, f)):
                        pdfmetrics.registerFont(TTFont(f"LG-{k}", os.path.join(base, f)))
                        got[k] = f"LG-{k}"
                got.setdefault("i", got["r"]); got.setdefault("m", "Courier")
                pdfmetrics.registerFontFamily("LG-r", normal=got["r"], bold=got["b"], italic=got["i"], boldItalic=got["b"])
                _FONT.update(unicode=True, **got)
            except Exception:                               # a broken font file: the built-in fonts still work
                pass
            return


_ASCII = str.maketrans({"→": "->", "←": "<-", "“": '"', "”": '"', "‘": "'", "’": "'", "…": "...", "≥": ">=", "≤": "<=",
                        "✓": "v", "•": "-", "−": "-", " ": " "})


def t(x):
    """Any value as safe paragraph text."""
    if x is None:
        return ""
    if isinstance(x, (list, tuple, set)):
        x = ", ".join(str(v) for v in x)
    s = str(x)
    if not _FONT.get("unicode"):
        s = s.translate(_ASCII).encode("latin-1", "replace").decode("latin-1")
    return escape(s)


def styles():
    _fonts()
    r, b, i = _FONT["r"], _FONT["b"], _FONT["i"]
    S = {
        "title": ParagraphStyle("title", fontName=b, fontSize=22, leading=27, textColor=NAVY, spaceAfter=4),
        "subtitle": ParagraphStyle("subtitle", fontName=r, fontSize=12, leading=16, textColor=colors.HexColor("#a9b8ff"), spaceAfter=10),
        "h1": ParagraphStyle("h1", fontName=b, fontSize=15, leading=19, textColor=NAVY, spaceBefore=10, spaceAfter=6),
        "h2": ParagraphStyle("h2", fontName=b, fontSize=11.5, leading=15, textColor=colors.HexColor("#c9d6ff"), spaceBefore=8, spaceAfter=3),
        "body": ParagraphStyle("body", fontName=r, fontSize=9.5, leading=13.5, alignment=TA_LEFT, spaceAfter=4, textColor=BODY),
        "bullet": ParagraphStyle("bullet", fontName=r, fontSize=9.5, leading=13.5, leftIndent=12, bulletIndent=2, spaceAfter=2, textColor=BODY,
                                 bulletColor=colors.HexColor("#8fb0ff")),
        "small": ParagraphStyle("small", fontName=r, fontSize=8, leading=10.5, textColor=MUTED),
        "cell": ParagraphStyle("cell", fontName=r, fontSize=7.2, leading=9, textColor=BODY),
        "cellb": ParagraphStyle("cellb", fontName=b, fontSize=7.4, leading=9, textColor=colors.HexColor("#a9c3ff")),
        "meta": ParagraphStyle("meta", fontName=r, fontSize=8.6, leading=12, textColor=MUTED),
        "link": ParagraphStyle("link", fontName=r, fontSize=8, leading=10.5, textColor=ACCENT, leftIndent=12),
        "kpiv": ParagraphStyle("kpiv", fontName=b, fontSize=15, leading=18, textColor=NAVY),
        "kpil": ParagraphStyle("kpil", fontName=r, fontSize=7.8, leading=10, textColor=MUTED),
        "badge": ParagraphStyle("badge", fontName=b, fontSize=7.5, leading=9, textColor=colors.white),
        "italic": ParagraphStyle("italic", fontName=i, fontSize=9, leading=12.5, textColor=MUTED),
    }
    return S


def P(text, st, **kw):
    return Paragraph(text, st, **kw)


def link(url, st):
    u = str(url or "")
    if not u.startswith(("http://", "https://")):
        return P(t(u), st)
    return P(f'<link href="{escape(u, {chr(34): "&quot;"})}">{t(u)}</link>', st)


# ------------------------------------------------------------------ building blocks
def kpi_grid(items, S, width):
    """Key figures as tiles: [(value, label), ...]."""
    items = [x for x in items if x and x[0] not in (None, "")]
    if not items:
        return Spacer(1, 1)
    per = 5
    rows = []
    for i in range(0, len(items), per):
        chunk = items[i:i + per] + [("", "")] * (per - len(items[i:i + per]))
        rows.append([[P(t(v), S["kpiv"]), P(t(l), S["kpil"])] if (v != "" or l) else "" for v, l in chunk])
    tb = Table(rows, colWidths=[width / per] * per)
    tb.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), SOFT), ("BOX", (0, 0), (-1, -1), 0.4, LINE),
                            ("INNERGRID", (0, 0), (-1, -1), 2.5, colors.white), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                            ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
    return tb


MAX_CELL = 900                      # characters in one table cell (a row must fit on a page)


def _cell(c):
    s = ", ".join(str(v) for v in c) if isinstance(c, (list, tuple, set)) else ("" if c is None else str(c))
    return s if len(s) <= MAX_CELL else s[:MAX_CELL].rsplit(" ", 1)[0] + " … (more in the CSV)"


def data_table(head, rows, S, widths, zebra=True, repeat=1):
    data = [[P(t(h), S["cellb"]) for h in head]]
    for r in rows:
        data.append([c if isinstance(c, Paragraph) else P(t(_cell(c)), S["cell"]) for c in r])
    try:                                    # reportlab >= 4: a very tall row may continue on the next page
        tb = Table(data, colWidths=widths, repeatRows=repeat, splitInRow=1)
    except TypeError:
        tb = Table(data, colWidths=widths, repeatRows=repeat)
    style = [("BACKGROUND", (0, 0), (-1, 0), HEAD_BG), ("BACKGROUND", (0, 1), (-1, -1), CARD_BG), ("VALIGN", (0, 0), (-1, -1), "TOP"),
             ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("TOPPADDING", (0, 0), (-1, -1), 3),
             ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if zebra:
        for i in range(2, len(data), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), SOFT))
    tb.setStyle(TableStyle(style))
    return tb


def bar_hours(hours, S, width, title, peak=None):
    if not hours or not any(hours):
        return None
    d = Drawing(width, 150)
    c = VerticalBarChart()
    c.x, c.y, c.width, c.height = 34, 26, width - 50, 100
    c.data = [list(hours)]
    c.categoryAxis.categoryNames = [f"{h:02d}" for h in range(len(hours))]
    c.categoryAxis.labels.fontName = _FONT["r"]; c.categoryAxis.labels.fontSize = 6.5
    c.valueAxis.labels.fontName = _FONT["r"]; c.valueAxis.labels.fontSize = 6.5
    c.valueAxis.valueMin = 0
    c.bars[0].fillColor = ACCENT; c.bars[0].strokeColor = None
    if peak is not None and 0 <= peak < len(hours):
        c.bars[(0, peak)].fillColor = NAVY
    c.barSpacing = 1
    d.add(c)
    d.add(String(34, 136, title, fontName=_FONT["b"], fontSize=8.5, fillColor=NAVY))
    d.add(String(width - 16, 8, "hour (UTC)", fontName=_FONT["r"], fontSize=6.5, fillColor=MUTED, textAnchor="end"))
    return d


def bar_top(rows, width, title):
    """Horizontal bars of a breakdown ([{label, count}])."""
    rows = [r for r in rows if r.get("count")][:10]
    if len(rows) < 2:
        return None
    h = 28 + 15 * len(rows)
    d = Drawing(width, h)
    c = HorizontalBarChart()
    c.x, c.y, c.width, c.height = 170, 8, width - 200, h - 30
    c.data = [[r["count"] for r in reversed(rows)]]
    names = [str(r.get("label") or r.get("value") or "")[:34] for r in reversed(rows)]
    if not _FONT.get("unicode"):
        names = [n.translate(_ASCII).encode("latin-1", "replace").decode("latin-1") for n in names]
    c.categoryAxis.categoryNames = names
    c.categoryAxis.labels.fontName = _FONT["r"]; c.categoryAxis.labels.fontSize = 7; c.categoryAxis.labels.dx = -4
    c.valueAxis.labels.fontName = _FONT["r"]; c.valueAxis.labels.fontSize = 6.5; c.valueAxis.valueMin = 0
    c.bars[0].fillColor = ACCENT; c.bars[0].strokeColor = None
    d.add(c)
    d.add(String(0, h - 12, title, fontName=_FONT["b"], fontSize=8.5, fillColor=NAVY))
    return d


from reportlab.platypus import Flowable  # noqa: E402

TONES = None


class Painted(Flowable):
    """A block drawn with the dashboard's parts (executive_pdf.Doc): tiles, the activity chart, chart cards."""

    def __init__(self, width, height, fn):
        super().__init__()
        self.width, self.height, self.fn = width, height, fn

    def wrap(self, aw, ah):
        return self.width, self.height

    def draw(self):
        import executive_pdf
        self.fn(executive_pdf.Doc.painter(self.canv), self.width, self.height)


def dash_tiles(items, width):
    """Key figures as the dashboard's coloured tiles, four per row."""
    import executive_pdf as ex
    tones = [ex.BLUE, ex.VIOLET, ex.AMBER, ex.RED, ex.TEAL, ex.SLATE]
    items = [x for x in items if x and x[0] not in (None, "")]
    per = 4                                   # four wide tiles a row: the analysts' labels are long
    rows = [items[i:i + per] for i in range(0, len(items), per)]
    def draw(p, w, h):
        y = h
        for r_i, row in enumerate(rows):
            p.kpis(y, [(v, l, "", tones[(r_i * per + i) % 6]) for i, (v, l) in enumerate(row)], x0=0, total=w * len(row) / per if len(row) < per else w)
            y -= 78
    return Painted(width, 78 * len(rows), draw)


def dash_activity(hours, peak, width, unit="Events"):
    if not hours or not any(hours):
        return None
    return Painted(width, 210, lambda p, w, h: p.area(0, h, w, h, hours, peak, unit))


def dash_chart_pair(pair, width):
    """Two breakdowns side by side as dashboard cards with bars."""
    n = max(min(10, len([r for r in rows if r.get("count")])) for _, rows in pair)
    h = 56 + 17 * n
    def draw(p, w, hh):
        cw = (w - 12) / 2
        for i, (title, rows) in enumerate(pair):
            x = i * (cw + 12)
            top = p.card(x, hh, cw, hh, title, "Events / records")
            p.bars(x + 14, top, cw - 28, rows, metric="count", n=10, label=lambda r: str(r.get("label") or r.get("value") or ""))
    return Painted(width, h, draw)


# ------------------------------------------------------------------ the infections / categories, explained
def _kind(x):
    if x.get("kind") == "cve":
        if x.get("exploited"):
            return "kev", "CVE · actively exploited"
        if x.get("found"):
            return "cve", "CVE"
        return "none", "CVE · not looked up yet" if x.get("pending") else "CVE · no public record"
    if x.get("found") and x.get("kind") == "actor":
        return "actor", "Malpedia · threat actor"
    if x.get("found"):
        return "found", "Malpedia"
    if x.get("curated"):
        return "curated", "Looking Glass definition"
    if x.get("pending"):
        return "none", "Not checked yet"
    return "none", "No definition yet" if x.get("offline") else "Not in Malpedia"


def enrichment_block(name, x, stat, S, width):
    """One infection / category: what it is, from Malpedia or the researchers' definitions, with references."""
    k, badge = _kind(x)
    shown = (x.get("kev") or {}).get("name", "") if x.get("kind") == "cve" else (x.get("name") or x.get("title") or "")
    head = Table([[P(t(badge), S["badge"]), P(f"<b>{t(name)}</b>" + (f"  =  {t(shown)}" if shown and shown != name else ""), S["h2"])]],
                 colWidths=[46 * mm, width - 46 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), KINDS[k]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (0, 0), 5), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    out = [head]
    facts = []
    if stat:
        facts.append(f"In this selection: {stat}.")
    if k == "found":
        facts.append(f"Malpedia family {x.get('family')}" + (f", matched by {x['matched_by']}" if x.get("matched_by") else "") + ".")
    if k == "actor":
        facts.append(f'"{name}" is a threat actor (a group of attackers), not a malware program'
                     + (f"; matched by {x['matched_by']}" if x.get("matched_by") else "") + ".")
    if x.get("type"):
        facts.append(f"Type: {x['type']}.")
    if x.get("kind") == "cve":
        cv = x.get("cvss") or {}
        if cv.get("score") is not None:
            facts.append(f"CVSS {cv.get('version', '')} base score {cv['score']} ({str(cv.get('severity', '')).title()}"
                         + (f", from {cv['source']}" if cv.get("source") else "") + ").")
        if x.get("sources"):
            facts.append("Sources: " + ", ".join(x["sources"] + ["CISA KEV", "EPSS"])
                         + ("" if x.get("nvd") else " (NVD's own analysis is added within minutes by the background check)") + ".")
        if x.get("epss") is not None:
            facts.append(f"EPSS: {x['epss']:.1%} probability of exploitation in the next 30 days"
                         + (f" (more likely than {int(x['epss_percentile'] * 1000) / 10:.1f}% of all CVEs)" if x.get("epss_percentile") is not None else "") + ".")
        if x.get("published"):
            facts.append(f"Published {x['published']}.")
    if facts:
        out.append(P(t(" ".join(facts)), S["meta"]))
    desc = x.get("description") or x.get("text") or x.get("reason") or ""
    if desc:
        out.append(P(t(desc), S["body"]))
    if x.get("kind") == "cve":
        kv = x.get("kev")
        if kv:
            rw = {"Known": "Yes, used in ransomware campaigns", "Unknown": "Not known"}.get(kv.get("ransomware"), kv.get("ransomware") or "Not known")
            out.append(P(t(f"Actively exploited: CISA added it to the Known Exploited Vulnerabilities catalog on {kv.get('date_added')}"
                           f" ({kv.get('vendor')} {kv.get('product')}). Ransomware use: {rw}."), S["body"]))
            if kv.get("action"):
                out.append(P(f"<b>CISA's required action:</b> {t(kv['action'])}" + (f" (due {t(kv['due'])} for US federal agencies)" if kv.get("due") else ""), S["meta"]))
        elif x.get("found"):
            out.append(P(t("Not in CISA's Known Exploited Vulnerabilities catalog: no confirmed active exploitation reported to CISA "
                           "(this does not mean it is safe)."), S["meta"]))
        if x.get("note"):
            out.append(P(f"<b>Note by {t(x.get('note_by') or 'a researcher')}:</b> {t(x['note'])}", S["meta"]))
    extra = []
    if x.get("alt_names"):
        extra.append(("Also known as", x["alt_names"]))
    if x.get("attribution"):
        extra.append(("Attributed to", x["attribution"]))
    if x.get("country") or x.get("sponsor"):
        extra.append(("Suspected origin", " · ".join(v for v in (x.get("country"), x.get("sponsor") and f"sponsor: {x['sponsor']}") if v)))
    if x.get("targets"):
        extra.append(("Targets", x["targets"]))
    if x.get("sectors"):
        extra.append(("Sectors", x["sectors"]))
    if x.get("families") and k == "actor":
        extra.append(("Malware it uses", x["families"]))
    if x.get("seen_in"):
        extra.append(("Seen in reports", x["seen_in"]))
    if x.get("near"):
        extra.append(("Similar names in Malpedia", x["near"]))
    if x.get("cwes"):
        extra.append(("Weakness", x["cwes"]))
    if x.get("updated") and k != "none" and x.get("kind") != "cve":
        extra.append(("Updated", f"{x['updated']}" + (f" by {x['by']}" if x.get("by") else "")))
    for lbl, v in extra:
        out.append(P(f"<b>{t(lbl)}:</b> {t(v)}", S["meta"]))
    refs = list(x.get("references") or [])
    if x.get("cveorg_url") and not x.get("nvd"):
        refs = [x["cveorg_url"]] + refs
    if x.get("kev_url"):
        refs = [x["kev_url"]] + refs
    if x.get("url"):
        refs = [x["url"]] + [u for u in refs if u != x["url"]]
    refs += [u for u in (x.get("curated_references") or []) if u not in refs]
    if refs:
        out.append(P(f"<b>{'Evidence / references' if k == 'curated' else 'References'}"
                     + (f" ({x.get('reference_count')} in {x.get('ref_source') or 'NVD' if x.get('kind') == 'cve' else 'Malpedia'}, {len(refs)} shown)"
                        if x.get("reference_count", 0) > len(refs) else "")
                     + ":</b>", S["meta"]))
        out += [link(u, S["link"]) for u in refs[:10]]
    out.append(Spacer(1, 7))
    return KeepTogether(out[:4]), out[4:]


# ------------------------------------------------------------------ the document
def build(spec):
    """spec: platform, platform_label, title (card), selection, day, generated_by, scope, demo, intro,
    summary_points [str], kpis [(value, label)], hours [24], peak_hour, charts [(title, rows)], enrichment {name: card},
    enrichment_stats {name: str}, enrichment_note, columns [[key, label]], rows [dict], total, breakdowns [(title, head, rows)],
    glossary [(title, def, url)], sources [str]."""
    S = styles()
    buf = io.BytesIO()
    page = landscape(A4)
    W = page[0] - 30 * mm
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def frame(canv, doc):
        import executive_pdf as ex
        canv.saveState()
        canv.setFillColor(PAGE_BG); canv.rect(0, 0, page[0], page[1], stroke=0, fill=1)
        canv.setFillColor(colors.Color(.36, .55, .94, .10)); canv.circle(page[0] * .18, page[1] + 40, 260, stroke=0, fill=1)
        canv.setFillColor(colors.Color(.55, .36, .96, .08)); canv.circle(page[0] * .85, page[1] + 60, 230, stroke=0, fill=1)
        p = ex.Doc.painter(canv)
        p.text(15 * mm, page[1] - 32, "Looking Glass", 13, ex.TXT, True)
        lw = canv.stringWidth("Looking Glass", _FONT["b"], 13)
        p.pill(15 * mm + lw + 8, page[1] - 31, "EXECUTIVE" if spec.get("executive") else "ANALYSIS REPORT", ex.VIOLET if spec.get("executive") else ex.BLUE, 7)
        p.text(15 * mm, page[1] - 46, p.fit(f"{spec.get('platform_label', '')} · {spec.get('scope', '')}", 420, 8.5), 8.5, ex.DIM)
        p.text(page[0] - 15 * mm, page[1] - 32, p.fit(spec.get("title") or "", 380, 11, True), 11, colors.HexColor("#a9b8ff"), True, "end")
        p.text(page[0] - 15 * mm, page[1] - 46, p.fit(f"Report day {spec.get('day', '')} · {spec.get('selection', '')}", 380, 8.5), 8.5, ex.DIM, anchor="end")
        canv.setStrokeColor(colors.Color(1, 1, 1, .08)); canv.setLineWidth(.6); canv.line(15 * mm, page[1] - 56, page[0] - 15 * mm, page[1] - 56)
        canv.setFillColor(colors.HexColor("#6b7690")); canv.setFont(_FONT["r"], 7.5)
        canv.drawString(15 * mm, 8 * mm, ("Demo mode: addresses, networks and names are concealed. " if spec.get("demo") else
                                          "Aggregated figures only: no individual addresses. " if spec.get("executive") else
                                          "Contains information about affected hosts: share only according to your organisation's information-sharing policy. ")
                        + f"Generated {now}" + (f" by {spec['generated_by']}" if spec.get("generated_by") else ""))
        canv.drawRightString(page[0] - 15 * mm, 8 * mm, f"Page {doc.page}")
        canv.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=page, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=24 * mm, bottomMargin=15 * mm,
                            title=f"Looking Glass · {spec.get('title', '')}", author="Looking Glass",
                            subject=spec.get("selection", ""), creator="Looking Glass")
    st = []

    # ---- cover block
    st.append(P(t(spec.get("title") or "Analysis report"), S["title"]))
    st.append(P(t(f"{spec.get('platform_label', '')} · {spec.get('selection', '')}"), S["subtitle"]))
    meta = [("Report day", spec.get("day")), ("Selection", spec.get("selection")), ("Figure", spec.get("title")),
            ("Constituency", spec.get("scope")), ("Generated", now + (f" by {spec['generated_by']}" if spec.get("generated_by") else "")),
            ("Data", "Shadowserver Foundation daily reports" + (" · Demo mode (masked)" if spec.get("demo") else ""))]
    mt = Table([[P(f"<b>{t(k)}</b>", S["meta"]), P(t(v), S["meta"])] for k, v in meta if v], colWidths=[34 * mm, W - 34 * mm])
    mt.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), CARD_BG), ("BOX", (0, 0), (-1, -1), 0.5, LINE), ("LINEBELOW", (0, 0), (-1, -1), 0.3, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3), ("LEFTPADDING", (0, 0), (-1, -1), 8)]))
    st += [mt, Spacer(1, 8)]

    # ---- executive summary
    st.append(P("Executive summary", S["h1"]))
    if spec.get("intro"):
        st.append(P(t(spec["intro"]), S["body"]))
    for s in spec.get("summary_points") or []:
        st.append(P(t(s), S["bullet"], bulletText="•" if _FONT.get("unicode") else "-"))
    st.append(Spacer(1, 8))
    st.append(dash_tiles(spec.get("kpis") or [], W))
    st.append(Spacer(1, 6))
    h = dash_activity(spec.get("hours"), spec.get("peak_hour"), W, "Records" if "services" in str(spec.get("platform_label", "")).lower() else "Events")
    if h:
        st.append(CondPageBreak(80 * mm))
        st.append(h)

    # ---- priorities (hosts to act on first)
    if spec.get("priorities"):
        st.append(CondPageBreak(60 * mm))
        st.append(P("Priorities", S["h1"]))
        st.append(P(t(spec.get("priorities_intro") or "The entries with the strongest signs, to be followed up first."), S["body"]))
        ph, prows, pw = spec["priorities"]
        st.append(data_table(ph, prows, S, [W * x for x in pw]))

    # ---- infections / categories explained
    enr = spec.get("enrichment") or {}
    if enr:
        st.append(CondPageBreak(70 * mm))
        st.append(P(t(spec.get("enrichment_title") or "Infections and categories explained"), S["h1"]))
        if spec.get("enrichment_note"):
            st.append(P(t(spec["enrichment_note"]), S["body"]))
        counts = {}
        for x in enr.values():
            counts[_kind(x)[1]] = counts.get(_kind(x)[1], 0) + 1
        st.append(P(t(" · ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))), S["meta"]))
        st.append(Spacer(1, 6))
        stats = spec.get("enrichment_stats") or {}
        for name, x in sorted(enr.items(), key=lambda kv: not kv[1].get("exploited")):
            first, rest = enrichment_block(name, x, stats.get(name), S, W)
            st.append(first); st += rest

    # ---- breakdowns
    charts = [(title, rows) for title, rows in (spec.get("charts") or []) if len([r for r in rows if r.get("count")]) >= 2]
    bds = spec.get("breakdowns") or []
    if charts or bds:
        st.append(CondPageBreak(70 * mm))
        st.append(P("Breakdowns", S["h1"]))
        for i in range(0, len(charts), 2):
            st += [dash_chart_pair(charts[i:i + 2], W), Spacer(1, 10)]
        for title, head, rows in bds:
            if not rows:
                continue
            n = len(head)
            widths = [W * 0.34] + [W * 0.66 / (n - 1)] * (n - 1) if n > 1 else [W]
            st.append(KeepTogether([P(t(title), S["h2"]), data_table(head, rows, S, widths)]))
            st.append(Spacer(1, 4))

    # ---- the complete list: in the CSV delivered with the report (or, for a PDF alone, printed here)
    cols, rows = spec.get("columns") or [], spec.get("rows") or []
    if cols and spec.get("csv_name"):
        total = spec.get("total", len(rows))
        st.append(CondPageBreak(45 * mm))
        st.append(P("The complete list", S["h1"]))
        st.append(P(t(f"The complete list behind this figure ({total:,} entr{'y' if total == 1 else 'ies'}: {spec.get('title', '')}) "
                      f"is in the CSV file delivered with this report, {spec['csv_name']}. Open it in a spreadsheet program "
                      "(Excel, LibreOffice Calc, Google Sheets). It has the same columns as the list on the platform"
                      + (", plus what each infection / issue is" if any(k == "_explained" for k, _ in cols) else "")
                      + ". The Priorities section above shows the entries to follow up first."), S["body"]))
        st.append(P(t("Columns: " + ", ".join(lbl for _, lbl in cols) + "."), S["meta"]))
    elif cols:
        st.append(CondPageBreak(70 * mm))
        st.append(P(t(f"The complete list: {spec.get('title', '')}"), S["h1"]))
        total = spec.get("total", len(rows))
        st.append(P(t(f"{total:,} entr{'y' if total == 1 else 'ies'}"
                      + (f"; the first {MAX_ROWS:,} are printed here (the CSV download has all of them)" if total > MAX_ROWS else "")
                      + (". The last column gives what each infection / category is." if any(k == "_explained" for k, _ in cols) else ".")),
                      S["meta"]))
        st.append(Spacer(1, 4))
        weights = {"ip": 1.1, "dst": 1.1, "followup": 1.5, "infections": 1.7, "infection": 1.4, "reports": 1.7, "issues": 1.8,
                   "services": 1.6, "network": 1.5, "kinds": 1.2, "domains": 1.5, "domain": 1.6, "name": 1.6, "report": 1.4,
                   "_explained": 2.6, "device": 1.4, "events": 0.6, "hosts": 0.6, "critical": 0.6, "share": 0.7, "first": 0.8,
                   "last": 0.8, "interval": 0.8, "rhythm": 0.7, "city": 0.9, "region": 0.9, "country": 0.7, "ports": 0.8}
        wsum = sum(weights.get(k, 1.0) for k, _ in cols)
        widths = [W * weights.get(k, 1.0) / wsum for k, _ in cols]
        body = [[r.get(k, "") for k, _ in cols] for r in rows[:MAX_ROWS]]
        st.append(data_table([lbl for _, lbl in cols], body, S, widths))

    # ---- report definitions and sources
    gl = spec.get("glossary") or []
    st.append(CondPageBreak(70 * mm))
    if gl:
        st.append(P("The reports in this selection", S["h1"]))
        for title, d, url in gl:
            st.append(P(f"<b>{t(title)}</b>", S["body"]))
            if d:
                st.append(P(t(d), S["meta"]))
            if url:
                st.append(link(url, S["link"]))
            st.append(Spacer(1, 4))
    st.append(P("About this report", S["h1"]))
    for s in spec.get("sources") or []:
        st.append(P(t(s), S["bullet"], bulletText="•" if _FONT.get("unicode") else "-"))

    doc.build(st, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()
