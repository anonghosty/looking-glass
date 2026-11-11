"""The Audit portal's evidence report (PDF): what an auditor files as evidence for a period. Read from audit_portal.py.

Page 1: the period, who generated it and when, the key figures, and the log's integrity with its head hash (the
auditor notes it: next time it proves nothing was removed from the end in between). Then the control checks with
their evidence, the accounts (access review), the privileged changes and failed sign-ins by address. Every cell wraps:
nothing is cut off.
"""
import io

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from xml.sax.saxutils import escape

INK, MUTED, LINE, OK, BAD, ACCENT = (colors.HexColor(c) for c in ("#16161a", "#5f5f69", "#d9d9df", "#1f7a4d", "#b42318", "#3b6fd8"))


def _styles():
    s = getSampleStyleSheet()
    base = ParagraphStyle("b", parent=s["Normal"], fontName="Helvetica", fontSize=8.6, leading=11.2, textColor=INK, alignment=TA_LEFT)
    return {
        "title": ParagraphStyle("t", parent=base, fontName="Helvetica-Bold", fontSize=18, leading=22),
        "sub": ParagraphStyle("s", parent=base, textColor=MUTED, fontSize=9.5, leading=13),
        "h": ParagraphStyle("h", parent=base, fontName="Helvetica-Bold", fontSize=11.5, leading=15, spaceBefore=10, spaceAfter=5),
        "b": base, "small": ParagraphStyle("sm", parent=base, fontSize=7.6, leading=9.8, textColor=MUTED),
        "mono": ParagraphStyle("m", parent=base, fontName="Courier", fontSize=7.8, leading=10),
        "cellb": ParagraphStyle("cb", parent=base, fontName="Helvetica-Bold"),
        "ok": ParagraphStyle("ok", parent=base, fontName="Helvetica-Bold", textColor=OK),
        "bad": ParagraphStyle("bad", parent=base, fontName="Helvetica-Bold", textColor=BAD),
    }


def _p(text, st):
    return Paragraph(escape(str(text if text is not None else "")).replace("\n", "<br/>"), st)


def _table(rows, widths, head=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
    style = [("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
             ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
             ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
    if head:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f1f4")), ("LINEBELOW", (0, 0), (-1, 0), 0.8, MUTED)]
    t.setStyle(TableStyle(style))
    return t


def build(d):
    st = _styles()
    buf = io.BytesIO()
    W = landscape(A4)[0] - 30 * mm

    def foot(c, doc):
        c.saveState()
        c.setFont("Helvetica", 7.5); c.setFillColor(MUTED)
        c.drawString(15 * mm, 9 * mm, f"Looking Glass · Audit evidence {d['from']} to {d['to']} · generated {d['generated']} by {d['by']}")
        c.drawRightString(landscape(A4)[0] - 15 * mm, 9 * mm, f"Page {doc.page}")
        c.restoreState()

    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=15 * mm, rightMargin=15 * mm, topMargin=14 * mm, bottomMargin=16 * mm,
                            title=f"Audit evidence {d['from']} to {d['to']}", author="Looking Glass")
    v, k = d["integrity"], d["kpis"]
    out = [_p("Audit evidence", st["title"]),
           _p(f"Period {d['from']} to {d['to']} (UTC, both days included) · generated {d['generated']} by {d['by']} · read only", st["sub"]),
           Spacer(1, 6),
           _p("Scope and method", st["h"]),
           _p(f"Automated checks of Looking Glass's own controls (the web application: accounts, roles, sign-in, sessions and the audit "
              f"log), computed from its records when this report was generated. Each check (LG-01 to LG-15) is mapped to the "
              f"{d.get('nist_release', 'NIST SP 800-53 Rev. 5')} controls it supports, cited by their official titles; the LG "
              "identifiers are Looking Glass's own, not NIST control numbers. A passed check supports, but does not on its own "
              "establish, that a control is implemented and operating effectively: corroborate it with independent testing (for "
              "example, try to sign in without a second factor) and review what lies outside the application: the server's "
              "operating system, its clock synchronisation, backups and network. "
              + (f"The system started on {d['started']}. " if d.get("started") else "") + "All times are UTC.", st["b"]),
           Spacer(1, 8)]
    figs = [("Events", k["events"]), ("Sign-ins", k["signins"]), ("Failed sign-ins", f"{k['failed']} ({k['failure_rate']} %)"),
            ("Lockouts", k["lockouts"]), ("Privileged changes", k["privileged"]), ("Exports", k["exports"]),
            ("People signed in", k["people"]), ("Sign-ins outside working hours", k["after_hours"])]
    cells = [[_p(n, st["small"]) for n, _ in figs], [_p(x, st["cellb"]) for _, x in figs]]
    out += [_table(cells, [W / len(figs)] * len(figs), head=False), Spacer(1, 8)]
    out.append(_p("Integrity of the audit log", st["h"]))
    state = "Chain whole: no entry was changed, inserted or removed." if v["ok"] else \
        f"BROKEN at entry {v['break']['entry']}: {v['break']['what']}."
    rows = [[_p("Result", st["cellb"]), _p(state, st["ok"] if v["ok"] else st["bad"])],
            [_p("Entries", st["cellb"]), _p(f"{v['entries']} kept ({v['chained']} chained, {v['before_chain']} written before the chain started), "
                                            f"from {d['first']} to {d['last']}; {v['archives']} archive file(s); "
                                            f"{v['removed_archives']} removed by the retention of {v['retention_days']} days", st["b"])],
            [_p("Head hash", st["cellb"]), _p(v["head"], st["mono"])],
            *([[_p("Before the chain", st["cellb"]),
                _p(f"{v['seal']['entries']} entries written before the chain started were sealed on "
                   f"{d.get('sealed_at', '')} with SHA-256 {v['seal']['sha256']} (the seal is recorded in the chain). State: "
                   f"{v['seal']['state']}. Changes after the seal are detected; nothing can prove these entries were unchanged before it.",
                   st["b"])]] if v.get("seal") else []),
            [_p("How to use it", st["cellb"]), _p("Note the head hash with this report. At the next audit, the chain must still lead to it: "
                                                  "that proves nothing was removed from the end of the log in between.", st["b"])]]
    out += [_table(rows, [38 * mm, W - 38 * mm], head=False)]
    out.append(_p("Control checks", st["h"]))
    rows = [[_p(h, st["cellb"]) for h in ("Check", "Control", f"NIST SP 800-53 Rev. 5 (5.2.0)", "Result", "Evidence")]]
    for c in d["checks"]:
        nist = Paragraph("<br/>".join(f"<b>{escape(n['id'])}</b> {escape(n['title'])}" for n in c.get("nist") or []) or "–", st["small"])
        rows.append([_p(c["id"], st["mono"]), Paragraph(f"{escape(c['control'])}<br/><font size='7' color='#5f5f69'>{escape(c['area'])}</font>", st["b"]),
                     nist, _p("Passed" if c["ok"] else "Attention", st["ok"] if c["ok"] else st["bad"]), _p(c["evidence"], st["b"])])
    out.append(_table(rows, [16 * mm, 60 * mm, 58 * mm, 19 * mm, W - 153 * mm]))
    out += [PageBreak(), _p("Access review: every account", st["h"]),
            _p("Role, permissions, authenticator, last sign-in and who approved the account. Flags show what needs attention.", st["small"])]
    rows = [[_p(h, st["cellb"]) for h in ("Account", "Role", "Permissions", "Status", "Two factors", "Last sign-in", "Approved", "Flags")]]
    for a in d["accounts"]:
        who = f"{a['full_name']} ({a['name']})" if a["full_name"] else a["name"]
        rows.append([_p(who, st["b"]), _p(a["role"], st["b"]), _p(", ".join(a["permissions"]), st["small"]), _p(a["status"], st["b"]),
                     _p("yes" if a["mfa"] else "NO", st["b"] if a["mfa"] else st["bad"]),
                     _p(f"{a['last_login'] or 'never'} {a['last_login_location']}".strip(), st["small"]),
                     _p(f"{a['approved_by']} {a['approved_at']}".strip() or "–", st["small"]), _p("; ".join(a["flags"]) or "–", st["small"])])
    out.append(_table(rows, [46 * mm, 24 * mm, 56 * mm, 16 * mm, 20 * mm, 40 * mm, 34 * mm, W - 236 * mm]))
    out.append(_p("Privileged changes (most recent first)", st["h"]))
    if d["privileged"]:
        rows = [[_p(h, st["cellb"]) for h in ("Time", "Change", "By", "Account", "Detail")]]
        for r in d["privileged"]:
            rows.append([_p(r["when"], st["small"]), _p(r["label"], st["b"]), _p(r["user_label"], st["b"]), _p(r["target_label"] or "–", st["b"]),
                         _p(r["detail"], st["small"])])
        out.append(_table(rows, [34 * mm, 40 * mm, 46 * mm, 46 * mm, W - 166 * mm]))
    else:
        out.append(_p("None in the period.", st["b"]))
    out.append(KeepTogether([_p("Failed sign-ins by address", st["h"]),
                             _table([[_p(h, st["cellb"]) for h in ("Address", "Location", "Failed sign-ins and lockouts")]] +
                                    [[_p(s["ip"], st["mono"]), _p(s["location"], st["b"]), _p(s["n"], st["b"])] for s in d["fail_sources"]]
                                    or [[_p("None", st["b"]), _p("", st["b"]), _p("", st["b"])]], [50 * mm, 80 * mm, W - 130 * mm])]))
    doc.build(out, onFirstPage=foot, onLaterPages=foot)
    return buf.getvalue()
