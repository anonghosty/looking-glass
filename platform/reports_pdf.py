# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""PDF reports of an analysis figure (a "card") on either platform: an executive summary, key figures, activity charts,
the infections / categories explained (Malpedia, threat actors, or the Looking Glass definitions written by researchers),
breakdowns, the complete list and the report definitions.

build(spec) -> bytes. Everything printed comes from the same server-side analysis as the page (and is masked the same
way in Demo mode). All text is escaped before it reaches reportlab's markup parser.
"""
import io
import os
import re
from datetime import datetime, timezone
from xml.sax.saxutils import escape

import attack_map
import name_sources
import pdf_refs
from shares import pct

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (CondPageBreak, KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table,
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
         "reference": colors.HexColor("#3b7a8c"), "none": colors.HexColor("#8a93a3"), "kev": colors.HexColor("#c0392b"), "cve": colors.HexColor("#2f5fb3")}
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


CERT_HEX = {"Observed": "#f6c27a", "Possible": "#9fdbe6"}     # as on the app's cards (app.css .mp-cert-*)


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
        # a heading never ends a page: it moves on with what it heads (keepWithNext)
        "h1": ParagraphStyle("h1", fontName=b, fontSize=15, leading=19, textColor=NAVY, spaceBefore=10, spaceAfter=6, keepWithNext=1),
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
# (the older tiles and bar charts, kpi_grid, bar_hours and bar_top, were removed: nothing used them since the
# dashboard's own parts below took their place; audit 2026-11-27)
def _cell(c):
    """A cell's text, whole: a row taller than a page continues on the next one (splitInRow, reportlab 4 and later,
    which requirements.txt asks for). Audit 2026-11-27: cells over 900 characters were cut with "… (more in the CSV)",
    also in a PDF downloaded without its CSV."""
    return ", ".join(str(v) for v in c) if isinstance(c, (list, tuple, set)) else ("" if c is None else str(c))


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


def dash_geo(geo, width, height=92 * mm):
    """The Executive report's region map (the country's first-level regions, coloured by devices) with each region and
    its cities beside it. Without a map for the country, the regions and cities alone."""
    import executive_pdf as ex

    def fn(p, w, h):
        c = p.c
        c.setFillColor(ex.CARD); c.setStrokeColor(colors.Color(1, 1, 1, .06)); c.roundRect(0, 0, w, h, 8, stroke=1, fill=1)
        if geo.get("shapes"):
            p.region_map(8, h - 8, w * .55, h - 16, geo["shapes"], geo["regions"], geo.get("details") or {}, True)
            p.region_tree(w * .59, h - 10, w * .39, 10, geo["regions"], geo.get("details") or {}, True)
        else:
            p.region_tree(14, h - 10, w - 28, 10, geo["regions"], geo.get("details") or {}, True)
    return Painted(width, height, fn)


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
    # every row given is drawn (up to 14: a top 12 and its Other row), so an "Other" row is never cut off (2026-11-26)
    n = max(min(14, len([r for r in rows if r.get("count")])) for _, rows in pair)
    h = 56 + 17 * n
    def draw(p, w, hh):
        cw = (w - 12) / 2
        for i, (title, rows) in enumerate(pair):
            x = i * (cw + 12)
            top = p.card(x, hh, cw, hh, title, "Events / records")
            p.bars(x + 14, top, cw - 28, rows, metric="count", n=14, label=lambda r: str(r.get("label") or r.get("value") or ""))
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
    if x.get("reference"):                          # MISP Galaxy / MITRE ATT&CK, from the copies in data/ (offline_names.py)
        return "reference", x.get("source_label") or "Reference"
    if x.get("pending"):
        return "none", "Not checked yet"
    return "none", "No source knows this name"


def _shared_lines(name, x):
    """(label, text) of the lines a card prints that another card can print word for word: the description, Also
    described by, each researcher's note and its combinations, CISA's required action (2026-11-26: the same note was
    printed under three names, the same required action under several CVEs)."""
    out = []
    desc = x.get("description") or x.get("text") or x.get("reason") or ""
    if desc:
        out.append(("Description", desc))
    if x.get("kind") != "cve":
        also = name_sources.also_text(x)
        if also:
            out.append(("Also described by", also))
    for n in x.get("notes") or []:
        out.append(("Note", f"{n.get('role')}|{n.get('by')}|{n.get('date')}|{n.get('text', '')}"))
        if n.get("codes"):
            out.append(("Combinations", "; ".join(f"{c.get('code')}|{c.get('text')}" for c in n["codes"])))
    kv = x.get("kev") if x.get("kind") == "cve" else None
    if kv and kv.get("action"):
        # the action alone: CVEs with one action and different due dates print it once, each with its own due date
        # (2026-11-27)
        out.append(("CISA's required action", kv["action"]))
    return out


class Once:
    """Lines several cards share are printed once, under the first card, with the names they apply to; the other cards
    point to it (the user, 2026-11-26: no definition, note or required action printed twice in a PDF)."""

    def __init__(self, cards):
        self.owners = {}
        for name, x in cards:
            for key in _shared_lines(name, x):
                names = self.owners.setdefault(key, [])
                if name not in names:
                    names.append(name)

    def lines(self, name, label, text, para, S, extra=""):
        """The paragraphs to print for this card's line: the line itself (with the names it applies to), or a pointer.
        extra: what the pointer adds that is this card's own (a CVE's due date)."""
        names = self.owners.get((label, text)) or [name]
        if len(names) < 2:
            return [para()]
        if names[0] == name:
            return [para(), P(f"<i>{t(label)}: the same for {t(', '.join(names[1:]))}.</i>", S["meta"])]
        return [P(f"<i>{t(label)}: the same as for {t(names[0])}, above{t(extra)}.</i>", S["meta"])]


def enrichment_block(name, x, stat, S, width, attack=True, once=None):
    """One infection / category: what it is, from Malpedia or the researchers' definitions, with references.
    attack=False: no ATT&CK lines (the PDF lists each technique once, in its own section: attack_section).
    once (Once): lines shared with other cards printed once."""
    k, badge = _kind(x)
    # para: a function making the paragraph, called only when it is printed
    printed = set()      # a line this card already printed (the same note saved twice, 2026-11-27): not again

    def share(label, text, para, extra=""):
        if (label, text) in printed:
            return []
        printed.add((label, text))
        return once.lines(name, label, text, para, S, extra) if once else [para()]
    shown = (x.get("kev") or {}).get("name", "") if x.get("kind") == "cve" else (x.get("name") or x.get("title") or "")
    # the name as reported is the card's heading, then the source's badge with what that source calls it
    title = P(f"<b>{t(name)}</b>", S["h2"])
    head = Table([[P(t(badge), S["badge"]), P(t(shown) if shown and shown != name else "", S["meta"])]],
                 colWidths=[46 * mm, width - 46 * mm])
    head.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), KINDS[k]), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                              ("LEFTPADDING", (0, 0), (0, 0), 5), ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 2)]))
    out = [title, head]
    facts = []
    if stat:
        facts.append(f"In this selection: {stat}.")
    if k == "found":
        facts.append(f"Malpedia family {x.get('family')}" + (f", matched by {x['matched_by']}" if x.get("matched_by") else "") + ".")
    if k == "reference":
        facts.append(f"Answered by {x.get('source_label')}" + (f" ({x['id']})" if x.get("id") else "")
                     + (f", matched by {x['matched_by']}" if x.get("matched_by") else "") + ".")
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
            facts.append(f"EPSS: {pct(x['epss'], 1)} probability of exploitation in the next 30 days"
                         + (f" (more likely than {int(x['epss_percentile'] * 1000) / 10:.1f}% of all CVEs)" if x.get("epss_percentile") is not None else "") + ".")
        if x.get("published"):
            facts.append(f"Published {x['published']}.")
    if facts:
        out.append(P(t(" ".join(facts)), S["meta"]))
    desc = x.get("description") or x.get("text") or x.get("reason") or ""
    if desc:
        out += share("Description", desc, lambda: P(t(desc), S["body"]))
    for n in x.get("notes") or []:                 # researchers' notes on this name, newest first (notes.py)
        out += share("Note", f"{n.get('role')}|{n.get('by')}|{n.get('date')}|{n.get('text', '')}",
                     lambda n=n: P(f"<b>Notes shared by {t(n.get('role') or 'Researcher/TI')}: {t(n.get('by') or 'a researcher')}</b>"
                                   f"{' (' + t(n['date']) + ')' if n.get('date') else ''}: {t(n.get('text', ''))}", S["meta"]))
        if n.get("codes"):                         # the combinations the note points at (combos.py): an analyst pulls them
            out += share("Combinations", "; ".join(f"{c.get('code')}|{c.get('text')}" for c in n["codes"]),
                         lambda n=n: P("<b>Combinations:</b> " + "; ".join(f"{t(c['code'])}" + (f" ({t(c['text'])})" if c.get("text") else "")
                                                                           for c in n["codes"]), S["meta"]))
    if x.get("kind") == "cve":
        kv = x.get("kev")
        if kv:
            rw = {"Known": "Yes, used in ransomware campaigns", "Unknown": "Not known"}.get(kv.get("ransomware"), kv.get("ransomware") or "Not known")
            # the CVE named: two CVEs of one product added on one day read alike otherwise (2026-11-26)
            out.append(P(t(f"Actively exploited: CISA added {name} to the Known Exploited Vulnerabilities catalog on {kv.get('date_added')}"
                           f" ({kv.get('vendor')} {kv.get('product')}). Ransomware use: {rw}."), S["body"]))
            if kv.get("action"):
                due = f" (due {kv['due']} for US federal agencies)" if kv.get("due") else ""
                out += share("CISA's required action", kv["action"],
                             lambda: P(f"<b>CISA's required action:</b> {t(kv['action'])}{t(due)}", S["meta"]), extra=due)
        elif x.get("found"):
            out.append(P(t(f"Not in CISA's Known Exploited Vulnerabilities catalog: no confirmed active exploitation of {name} reported "
                           "to CISA (this does not mean it is safe)."), S["meta"]))
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
    # its references: in the References section at the end, grouped by name (pdf_refs.py, the user 2026-11-18)
    if x.get("kind") != "cve":                     # the source and its licence travel with its text (name_sources.py)
        src = name_sources.source_text(x)
        if src:
            out.append(P(f"<b>Source:</b> {t(src[len('Source: '):])}", S["meta"]))
        also = name_sources.also_text(x)
        if also:
            out += share("Also described by", also, lambda: P(f"<b>Also described by:</b> {t(also[len('Also described by: '):])}", S["meta"]))
    if not attack and (x.get("attack") or {}).get("techniques"):
        out.append(P("<b>MITRE ATT&amp;CK:</b> see MITRE ATT&amp;CK techniques, after these cards.", S["meta"]))
    for ln in attack_map.attack_lines(x.get("attack")):   # MITRE ATT&CK, with the version this PDF was made with
        if not attack and not ln.startswith("Groups MITRE"):   # the techniques: once, in the ATT&CK section
            continue
        head_, _, rest_ = ln.partition(": ")
        # Observed / Possible in the cards' colours (app.css .mp-cert, the user's choice 2026-11-18)
        rest_ = re.sub(r"· (Observed|Possible)\b", lambda m: f'· <font color="{CERT_HEX[m.group(1)]}"><b>{m.group(1)}</b></font>', t(rest_))
        out.append(P(f"<b>{t(head_)}:</b> {rest_}", S["meta"]))
    out.append(Spacer(1, 7))
    return KeepTogether(out[:5]), out[5:]


_CERT = {"observed": 0, "possible": 1, "known": 2}


def attack_groups(cards):
    """Each ATT&CK technique of the cards once, in code order: [(id, text, [names])], the version, and the source lines
    (CTID licence) once each. The text is the technique's line as attack_lines writes it, from the card where its
    certainty is strongest (Observed before Possible before Known for the malware)."""
    by, version, sources_ = {}, None, []
    for name, x in cards:
        att = x.get("attack") or {}
        techs = att.get("techniques") or []
        version = version or att.get("version")
        for tid in dict.fromkeys(tt.get("id") for tt in techs):
            sub = [tt for tt in techs if tt.get("id") == tid]
            lines = attack_map.attack_lines(dict(att, techniques=sub, cves=False, groups=None, source=None))
            bits = []
            for ln in lines:
                head_, _, rest_ = ln.partition(": ")
                rest_ = rest_.rstrip(".")
                if head_.startswith("Known for this malware"):
                    ta, _, what = rest_.partition(": ")
                    bits.append(f"{what} · {ta} · Known for this malware")
                else:
                    bits.append(rest_)
            rank = min(_CERT.get(tt.get("certainty"), 3) for tt in sub)
            g = by.get(tid)
            if g is None:
                by[tid] = {"text": "; ".join(bits), "rank": rank, "names": [name]}
            else:
                if rank < g["rank"]:
                    g["text"], g["rank"] = "; ".join(bits), rank
                if name not in g["names"]:
                    g["names"].append(name)
        if att.get("source"):
            s = f"Source: {att.get('licence') or att['source']}" + (f" Mapped with ATT&CK v{att['mapped_with']}." if att.get("mapped_with") else "")
            if s not in sources_:
                sources_.append(s)
    key = getattr(attack_map, "_code_key", lambda c: str(c))
    return [(tid, g["text"], g["names"]) for tid, g in sorted(by.items(), key=lambda kv: key(kv[0]))], version, sources_


def attack_section(cards, S, issues=False):
    """The PDF's one MITRE ATT&CK part: each technique once, with the infections / categories (or issues) it is mapped
    to (the user, 2026-11-26: the same technique was printed under each of seven cards)."""
    groups, version, sources_ = attack_groups(cards)
    if not groups:
        return []
    what = "issues" if issues else "infections / categories"
    out = [CondPageBreak(40 * mm), P("MITRE ATT&amp;CK techniques", S["h1"]),
           P(t(f"Each technique once (MITRE ATT&CK v{version}), in code order, with the {what} explained above that it is "
               "mapped to."), S["body"])]
    for tid, text, names in groups:
        text = re.sub(r"· (Observed|Possible)\b", lambda m: f'· <font color="{CERT_HEX[m.group(1)]}"><b>{m.group(1)}</b></font>', t(text))
        out.append(P(f"{text}. <b>Mapped for:</b> {t(', '.join(names))}.", S["meta"]))
    for s in sources_:
        out.append(P(t(s), S["meta"]))
    out.append(Spacer(1, 6))
    return out


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
        # who made it and when only (the user, 2026-11-28): no address notice in a footer; the cover table says the data
        canv.drawString(15 * mm, 8 * mm, ("Demo mode (masked). " if spec.get("demo") else "")
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

    # ---- where: the region map and the cities (the analyst's combination report, combos.py)
    geo = spec.get("geo")
    if geo and geo.get("regions"):
        gh = (84 if geo.get("shapes") else max(30, min(84, 14 + 6 * len(geo["regions"])))) * mm
        st.append(CondPageBreak(gh + 22 * mm))
        st.append(P(t(geo.get("title") or "Where"), S["h1"]))
        if geo.get("note"):
            st.append(P(t(geo["note"]), S["body"]))
        st.append(Spacer(1, 4))
        st.append(dash_geo(geo, W, gh))
        st.append(Spacer(1, 6))

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
        cards = sorted(enr.items(), key=lambda kv: not kv[1].get("exploited"))
        once = Once(cards)                 # a note, definition or required action shared by several cards: printed once
        for name, x in cards:
            first, rest = enrichment_block(name, x, stats.get(name), S, W, attack=False, once=once)
            st.append(first); st += rest
        st += attack_section(cards, S, issues=spec.get("enrichment_title") == "Issues explained")

    # ---- breakdowns
    charts = [(title, rows) for title, rows in (spec.get("charts") or []) if len([r for r in rows if r.get("count")]) >= 2]
    bds = spec.get("breakdowns") or []
    if charts or bds:
        st.append(CondPageBreak(70 * mm))
        st.append(P("Breakdowns", S["h1"]))
        for i in range(0, len(charts), 2):
            st += [dash_chart_pair(charts[i:i + 2], W), Spacer(1, 10)]
        for b in bds:
            title, head, rows = b[:3]
            if not rows:
                continue
            n = len(head)
            widths = ([W * f for f in b[3]] if len(b) > 3 and b[3] else
                      [W * 0.34] + [W * 0.66 / (n - 1)] * (n - 1) if n > 1 else [W])
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
                      + (f"; the first {MAX_ROWS:,} are printed here. Download the report as a ZIP (this PDF with a CSV "
                         f"file) for all {total:,}" if total > MAX_ROWS else "")
                      + (". The last columns give what each infection / category is and which sources know it."
                         if any(k == "_source" for k, _ in cols) else
                         ". The last column gives what each infection / category is." if any(k == "_explained" for k, _ in cols) else ".")),
                      S["meta"]))
        st.append(Spacer(1, 4))
        weights = {"ip": 1.1, "dst": 1.1, "followup": 1.5, "infections": 1.7, "infection": 1.4, "reports": 1.7, "issues": 1.8,
                   "services": 1.6, "network": 1.5, "kinds": 1.2, "domains": 1.5, "domain": 1.6, "name": 1.6, "report": 1.4,
                   "_explained": 2.6, "_source": 1.3, "_attack": 1.4, "device": 1.4, "events": 0.6, "hosts": 0.6, "critical": 0.6, "share": 0.7, "first": 0.8,
                   "last": 0.8, "interval": 0.8, "rhythm": 0.7, "city": 0.9, "region": 0.9, "country": 0.7, "ports": 0.8}
        wsum = sum(weights.get(k, 1.0) for k, _ in cols)
        widths = [W * weights.get(k, 1.0) / wsum for k, _ in cols]
        body = [[r.get(k, "") for k, _ in cols] for r in rows[:MAX_ROWS]]
        st.append(data_table([lbl for _, lbl in cols], body, S, widths))

    # ---- References (pdf_refs.py, the user 2026-11-18): each explained name's references, then the reports in this
    # selection with what each is and its page, all ordered by criticality and flagged with it
    gl = spec.get("glossary") or []
    st.append(CondPageBreak(70 * mm))
    gs = pdf_refs.groups(list((spec.get("enrichment") or {}).items()),
                         spec.get("ref_levels") or pdf_refs.platform_levels(spec.get("platform_label")),
                         [{"title": ti, "url": u, "severity": pdf_refs.severity_by_url(u), "where": d} for ti, d, u in gl if u], shown=10)
    pill = {"critical": "#ef5d6c", "high": "#f5b54a", "medium": "#5b8def", "low": "#7d8aa8", "info": "#7d8aa8", "": "#7d8aa8"}

    def flags_html(lv, flags):
        bits = [f'<font color="{pill[lv]}"><b>{pdf_refs.WORD[lv].upper()}</b></font>']
        bits += [f'<font color="#ef5d6c"><b>{t(f)}</b></font>' if f == "Actively exploited" else t(f) for f in flags]
        return " · ".join(bits)
    for i, g_ in enumerate(gs):
        head = [P("References", S["h1"]), P(t("The sources behind this report: each explained name with its references, then "
                                                "the Shadowserver reports in this selection, the most critical first."), S["meta"])] if i == 0 else []
        if g_["kind"] == "name":
            e = [P(f"<b>{t(g_['title'])}</b> · {flags_html(g_['level'], g_['flags'])}", S["body"])]
            e += [link(u, S["link"]) for u in g_["refs"]]
            if g_.get("more"):
                e.append(P(t(f"and {g_['more']} more on the {g_.get('more_where') or 'source'} page"), S["meta"]))
            st.append(KeepTogether(head + e + [Spacer(1, 4)]))
        else:
            for j, r in enumerate(g_["items"]):               # the group's heading never alone at a page's foot
                e = [P(f"<b>{t(r['title'])}</b> · {flags_html(r['level'], [])}", S["body"])]
                e += ([P(t(r["where"]), S["meta"])] if r.get("where") else []) + [link(r["url"], S["link"]), Spacer(1, 4)]
                st.append(KeepTogether((head + [P("Shadowserver reports", S["h2"])] if j == 0 else []) + e))
    st.append(P("About this report", S["h1"]))
    for s in spec.get("sources") or []:
        st.append(P(t(s), S["bullet"], bulletText="•" if _FONT.get("unicode") else "-"))

    doc.build(st, onFirstPage=frame, onLaterPages=frame)
    return buf.getvalue()
