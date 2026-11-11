"""The executive report of the management portal, drawn like the dashboard: dark pages, coloured key-figure tiles, the
activity chart, the regions map, donuts, ranked threats, deeper insight and the explanations as cards.

build(d, enr, meta) -> PDF bytes. d is the dashboard's own answer (management.comms / services); enr the explanations
({name: card}); meta {platform_label, scope, selection, generated_by, demo, country_shapes}. Aggregated figures only.
"""
import io
import math
import re
from datetime import datetime, timezone

from reportlab.lib.colors import Color, HexColor
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.utils import simpleSplit
from reportlab.pdfgen import canvas as rl_canvas

import reports_pdf as rp

W, H = landscape(A4)
M = 26                                         # page margin
BG, CARD, EDGE = HexColor("#070a12"), HexColor("#111627"), HexColor("#222a3f")
TXT, DIM, MUTE = HexColor("#eef2fb"), HexColor("#9aa6bf"), HexColor("#6b7690")
BLUE, VIOLET, TEAL, AMBER, RED, SLATE = (HexColor(x) for x in ("#5b8def", "#8b5cf6", "#22c3a6", "#f5b54a", "#ef5d6c", "#7d8aa8"))
PALETTE = [HexColor(x) for x in ("#5b8def", "#8b5cf6", "#22c3a6", "#f5b54a", "#ef6f8a", "#38bdf8", "#a3e635", "#f97316", "#c084fc", "#94a3b8")]
fmt = lambda n: f"{int(round(n or 0)):,}"
pct = lambda x, d=0: f"{100 * (x or 0):.{d}f}%"


class Doc:
    def __init__(self, meta):
        rp._fonts()
        self.F = rp._FONT
        self.buf = io.BytesIO()
        self.c = rl_canvas.Canvas(self.buf, pagesize=(W, H))
        self.c.setTitle(f"Looking Glass · Executive report · {meta['platform_label']}")
        self.c.setAuthor("Looking Glass")
        self.meta, self.page = meta, 0

    @classmethod
    def painter(cls, canvas, meta=None):
        """The drawing parts on an existing canvas (a flowable of the analysts' reports)."""
        rp._fonts()
        obj = cls.__new__(cls)
        obj.F, obj.c, obj.meta, obj.page, obj.buf = rp._FONT, canvas, meta or {}, 0, None
        return obj

    # ---------------- text helpers
    def s(self, text):
        text = str(text if text is not None else "")
        if not self.F.get("unicode"):
            text = text.translate(rp._ASCII).encode("latin-1", "replace").decode("latin-1")
        return text

    def text(self, x, y, text, size=10, color=TXT, bold=False, anchor="start", mono=False):
        c = self.c
        c.setFillColor(color)
        c.setFont(self.F["m"] if mono else self.F["b"] if bold else self.F["r"], size)
        t = self.s(text)
        (c.drawString if anchor == "start" else c.drawRightString if anchor == "end" else c.drawCentredString)(x, y, t)

    def wrap(self, x, y, text, width, size=9.5, color=TXT, bold=False, leading=None, max_lines=None):
        """Draws wrapped text downward from y (baseline of the first line); returns the y below the last line."""
        leading = leading or size * 1.38
        lines = simpleSplit(self.s(text), self.F["b"] if bold else self.F["r"], size, width)
        if max_lines and len(lines) > max_lines:
            lines = lines[:max_lines]
            lines[-1] = lines[-1].rstrip()[:-1] + "…"
        for ln in lines:
            self.text(x, y, ln, size, color, bold)
            y -= leading
        return y

    def fit(self, text, width, size, bold=False):
        t = self.s(text)
        font = self.F["b"] if bold else self.F["r"]
        while t and self.c.stringWidth(t, font, size) > width:
            t = t[:-2] + "…" if len(t) > 2 else ""
        return t

    # ---------------- shapes
    def card(self, x, y, w, h, title=None, sub=None, tone=None):
        """A dashboard card; (x, y) is the top-left corner. Returns the y where the content starts."""
        c = self.c
        c.setFillColor(CARD); c.setStrokeColor(EDGE); c.setLineWidth(.7)
        c.roundRect(x, y - h, w, h, 10, stroke=1, fill=1)
        if tone is not None:
            c.saveState(); p = c.beginPath(); p.roundRect(x, y - h, w, h, 10); c.clipPath(p, stroke=0, fill=0)
            c.setFillColor(tone); c.rect(x, y - 3, w, 3, stroke=0, fill=1); c.restoreState()
        top = y - 18
        if title:
            self.text(x + 14, top, title, 11.5, TXT, True); top -= 13
        if sub:
            self.text(x + 14, top, self.fit(sub, w - 28, 8.2), 8.2, MUTE); top -= 12
        return top - 4

    def bar(self, x, y, w, h, frac, colors=(BLUE, VIOLET)):
        c = self.c
        c.setFillColor(Color(1, 1, 1, .07)); c.roundRect(x, y, w, h, h / 2, stroke=0, fill=1)
        fw = max(h, w * max(0, min(1, frac)))
        c.setFillColor(colors[0]); c.roundRect(x, y, fw, h, h / 2, stroke=0, fill=1)
        if fw > 3 * h:                                  # a violet tip, like the dashboard's gradient
            c.setFillColor(Color(colors[1].red, colors[1].green, colors[1].blue, .85)); c.roundRect(x + fw * .55, y, fw * .45, h, h / 2, stroke=0, fill=1)
            c.setFillColor(Color((colors[0].red + colors[1].red) / 2, (colors[0].green + colors[1].green) / 2, (colors[0].blue + colors[1].blue) / 2, .9))
            c.rect(x + fw * .5, y, fw * .12, h, stroke=0, fill=1)

    def pill(self, x, y, text, color, size=7.2):
        t = self.s(text); w = self.c.stringWidth(t, self.F["b"], size) + 10
        c = self.c
        c.setFillColor(Color(color.red, color.green, color.blue, .16)); c.setStrokeColor(Color(color.red, color.green, color.blue, .6)); c.setLineWidth(.6)
        c.roundRect(x, y - 3, w, size + 6, (size + 6) / 2, stroke=1, fill=1)
        self.text(x + 5, y, t, size, Color(min(1, color.red + .35), min(1, color.green + .35), min(1, color.blue + .35)), True)
        return x + w + 4

    # ---------------- pages
    def new_page(self, section):
        if self.page:
            self.footer(); self.c.showPage()
        self.page += 1
        c = self.c
        c.setFillColor(BG); c.rect(0, 0, W, H, stroke=0, fill=1)
        # soft glow, like the portal
        c.saveState(); c.setFillColor(Color(.36, .55, .94, .10)); c.circle(W * .18, H + 40, 260, stroke=0, fill=1)
        c.setFillColor(Color(.55, .36, .96, .08)); c.circle(W * .85, H + 60, 230, stroke=0, fill=1); c.restoreState()
        self.text(M, H - M - 6, "Looking Glass", 13, TXT, True)
        lw = self.c.stringWidth("Looking Glass", self.F["b"], 13)
        self.pill(M + lw + 8, H - M - 5, "EXECUTIVE", VIOLET, 7)
        self.text(M, H - M - 20, f"{self.meta['platform_label']} · {self.meta['scope']}", 8.5, DIM)
        self.text(W - M, H - M - 6, section, 11, HexColor("#a9b8ff"), True, "end")
        self.text(W - M, H - M - 20, self.fit(f"Report day {self.meta['day']} · {self.meta['selection']}", 380, 8.5), 8.5, DIM, anchor="end")
        c.setStrokeColor(Color(1, 1, 1, .08)); c.setLineWidth(.6); c.line(M, H - M - 30, W - M, H - M - 30)
        return H - M - 44

    def footer(self):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        who = f" by {self.meta['generated_by']}" if self.meta.get("generated_by") else ""
        note = "Demo mode: network names are aliases. " if self.meta.get("demo") else ""
        self.text(M, 14, f"{note}Aggregated figures only: no individual addresses. Generated {now}{who}. Data: Shadowserver Foundation.", 7.2, MUTE)
        self.text(W - M, 14, f"Page {self.page}", 7.2, MUTE, anchor="end")

    def done(self):
        self.footer(); self.c.save()
        return self.buf.getvalue()

    # ---------------- 7-day baseline
    def spark(self, x, y, w, h, vals, today, avg=None):
        """A small trend line: the 7 days before the report day and the day itself (dot); dashed: the 7-day average.
        (x, y) is the bottom-left corner."""
        pts = list(vals) + [today]
        nums = [v for v in pts if v is not None]
        if len(nums) < 2:
            self.text(x, y + h / 2 - 3, "not enough days yet", 7.4, MUTE); return
        lo, hi = min(nums + [0]), max(nums + [1])
        X = lambda i: x + 2 + i * (w - 4) / (len(pts) - 1)
        Y = lambda v: y + 2 + (v - lo) / ((hi - lo) or 1) * (h - 4)
        c = self.c
        if avg is not None:
            c.setStrokeColor(Color(1, 1, 1, .3)); c.setLineWidth(.6); c.setDash(2, 2); c.line(x, Y(avg), x + w, Y(avg)); c.setDash()
        seg = [(X(i), Y(v)) for i, v in enumerate(pts) if v is not None]
        p = c.beginPath(); p.moveTo(seg[0][0], y)
        for a, b_ in seg:
            p.lineTo(a, b_)
        p.lineTo(seg[-1][0], y); p.close()
        c.setFillColor(Color(.36, .55, .94, .16)); c.drawPath(p, stroke=0, fill=1)
        c.setStrokeColor(HexColor("#8fb0f5")); c.setLineWidth(1.3)
        p = c.beginPath(); p.moveTo(*seg[0])
        for a, b_ in seg[1:]:
            p.lineTo(a, b_)
        c.drawPath(p, stroke=1, fill=0)
        c.setFillColor(TXT); c.setStrokeColor(BLUE); c.setLineWidth(1.2); c.circle(seg[-1][0], seg[-1][1], 2.4, stroke=1, fill=1)

    LEVEL = {"normal": SLATE, "info": BLUE, "good": TEAL, "watch": AMBER, "high": RED}

    @classmethod
    def change(cls, today, vals, grade=None):
        """(7-day average, (label, colour)) from the server's grade (management.py assess)."""
        v = [x for x in vals if x is not None]
        a = sum(v) / len(v) if v else None
        if not grade:
            return a, None
        return a, (grade["label"], cls.LEVEL.get(grade["level"], SLATE))

    def baseline_page(self, y, d, b, comms):
        figs = ([("devices", "Affected devices"), ("multi_infected", "Several infections"),
                 ("infections", "Infections"), ("cross_report", "In several reports"), ("critical", "Critical events"),
                 ("regions", "Regions affected"), ("events", "Events")] if comms else
                [("hosts", "Internet-facing hosts"), ("vulnerable_hosts", "Hosts with an issue"), ("kev_hosts", "Actively exploited"),
                 ("critical_cves", "Critical CVEs"), ("multi_issue", "Several issues"), ("cross_report", "In several reports"),
                 ("issues", "Kinds of issue"), ("records", "Records")])
        enough = b.get("available", 0) >= 3
        days = b["days"]
        self.text(M, y - 4, f"THE REPORT DAY AGAINST THE 7 DAYS BEFORE IT · {days[0]} TO {days[-1]} · {b.get('available', 0)} OF 7 DAYS WITH REPORTS",
                  8, HexColor("#a9b8ff"), True)
        y -= 16
        gap, cols, ch = 9, 4, 104
        cw = (W - 2 * M - gap * (cols - 1)) / cols
        for i, (key, label) in enumerate(figs):
            x = M + (i % cols) * (cw + gap); top = y - (i // cols) * (ch + gap)
            self.card(x, top, cw, ch)
            vals, today = b["kpis"].get(key, []), d["kpis"].get(key, 0)
            a, chg = self.change(today, vals, ((b.get("assess") or {}).get("kpis") or {}).get(key))
            self.text(x + 12, top - 16, label, 8.6, DIM, True)
            self.text(x + cw - 12, top - 17, fmt(today), 15, TXT, True, "end")
            self.spark(x + 12, top - ch + 28, cw - 24, 46, vals, today, a)
            if enough and chg:
                self.pill(x + 12, top - ch + 11, chg[0], chg[1], 6.8)
            else:
                self.text(x + 12, top - ch + 11, "not enough days yet", 7.2, MUTE)
            if a is not None:
                self.text(x + cw - 12, top - ch + 11, f"avg {fmt(a)}", 7.4, MUTE, anchor="end")
        y -= 2 * (ch + gap) + 4
        # how the changes are graded (the thresholds and what each grade means), as on the platform
        scale = b.get("scale") or []
        if scale:
            top = self.card(M, y, W - 2 * M, min(y - 30, 60 + 27 * len(scale)), "How changes are graded",
                            "Each figure against its own average over the 7 days before the report day: change = (today - 7-day average) / 7-day average")
            yy = top - 4
            for s_ in scale:
                self.pill(M + 14, yy, s_["name"], self.LEVEL.get(s_["level"], SLATE), 7)
                y1 = self.wrap(M + 170, yy, s_["range"], 220, 8.2, TXT, True, leading=10.5)
                y2 = self.wrap(M + 410, yy, s_["meaning"], W - 2 * M - 420, 8.2, HexColor("#cfd6e6"), leading=10.5)
                yy = min(y1, y2) - 6
            # the top list's trend table follows on its own page
        y = self.new_page("7-day trend: " + ("top infections" if comms else "top issues"))
        # the top infections / issues over the 7 days
        rows = (d["infections"] if comms else sorted(d["issues"], key=lambda r: -r["hosts"]))
        unit = "devices" if comms else "hosts"
        top = self.card(M, y, W - 2 * M, y - 30, ("Top infections" if comms else "Top issues") + " over the 7 days",
                        f"{unit.capitalize()} per day for each of the day's top {'infections' if comms else 'issues'} · new, rising or falling against its 7-day average")
        cx = [M + 14, M + 330, M + 460, M + 530, M + 640]
        for xx, h_, an in zip(cx, ("Name", "7 days and the report day", "7-day avg", "Report day", "Change"), ("start", "start", "end", "end", "start")):
            if h_:
                self.text(xx + (60 if an == "end" else 0), top - 2, h_, 7.6, MUTE, True, an)
        yy = top - 18
        for r in rows:
            if yy < 44:
                break
            vals = b["items"].get(r["value"], [])
            today = r["hosts"]
            g = ((b.get("assess") or {}).get("items") or {}).get(r["value"])
            a, chg = self.change(today, vals, g)
            name = (r.get("title") or r["value"]) if comms else r["value"]
            self.text(cx[0], yy, self.fit(name, 300, 8.6, True), 8.6, TXT, True)
            self.spark(cx[1], yy - 4, 120, 14, vals, today, a)
            self.text(cx[2] + 60, yy, fmt(a) if a is not None else "-", 8.4, DIM, anchor="end")
            self.text(cx[3] + 60, yy, fmt(today), 8.4, TXT, True, "end")
            if enough and chg:
                self.pill(cx[4], yy, chg[0], chg[1], 6.6)
            if enough and g and g["level"] in ("watch", "high"):        # what to do about it, under the row
                yy -= 11
                self.text(cx[0] + 8, yy, self.fit(g["note"], W - 2 * M - 40, 7.4), 7.4, HexColor("#ffd38a") if g["level"] == "watch" else HexColor("#ff9aa4"))
            self.c.setStrokeColor(Color(1, 1, 1, .05)); self.c.setLineWidth(.5); self.c.line(M + 14, yy - 7, W - M - 14, yy - 7)
            yy -= 21

    # ---------------- components
    def kpis(self, y, tiles, x0=M, total=None):
        n, gap = len(tiles), 9
        w = ((total or (W - 2 * M)) - gap * (n - 1)) / n
        for i, (v, label, sub, tone) in enumerate(tiles):
            x = x0 + i * (w + gap)
            self.card(x, y, w, 66, tone=tone)
            c = self.c
            c.saveState(); clip = c.beginPath(); clip.roundRect(x, y - 66, w, 66, 10); c.clipPath(clip, stroke=0, fill=0)
            c.setFillColor(Color(tone.red, tone.green, tone.blue, .10)); c.circle(x + w - 10, y - 12, 26, stroke=0, fill=1); c.restoreState()
            self.text(x + 12, y - 17, self.fit(label, w - 20, 8.6, True), 8.6, DIM, True)
            col = HexColor("#ff9aa4") if tone == RED else HexColor("#ffd38a") if tone == AMBER else TXT
            self.text(x + 12, y - 41, v, 21, col, True)
            self.text(x + 12, y - 56, self.fit(sub, w - 20, 7.6), 7.6, MUTE)
        return y - 66 - 12

    def area(self, x, y, w, h, hours, peak, unit):
        top = self.card(x, y, w, h, "Activity across the day", f"{unit} per hour (UTC)" + (f" · peak {peak:02d}:00" if peak is not None else ""))
        c = self.c
        L, B, R = x + 40, y - h + 26, x + w - 16
        T = top - 6
        mx = max(1, max(hours or [0]))
        X = lambda i: L + i * (R - L) / 23
        Y = lambda v: B + (T - B) * v / mx
        c.setLineWidth(.5)
        for k in range(5):
            v = mx * k / 4; yy = Y(v)
            c.setStrokeColor(Color(1, 1, 1, .06)); c.line(L, yy, R, yy)
            self.text(L - 6, yy - 3, fmt(v), 7, MUTE, anchor="end")
        for i in range(0, 24, 3):
            self.text(X(i), B - 13, f"{i:02d}:00", 7, MUTE, anchor="middle")
        pts = [(X(i), Y(v)) for i, v in enumerate(hours)]
        # filled area with a vertical gradient
        p = c.beginPath(); p.moveTo(pts[0][0], B)
        for px, py in pts:
            p.lineTo(px, py)
        p.lineTo(pts[-1][0], B); p.close()
        c.setFillColor(Color(.36, .55, .94, .26)); c.drawPath(p, stroke=0, fill=1)
        c.setStrokeColor(HexColor("#7ea6ff")); c.setLineWidth(1.8); c.setLineJoin(1)
        p = c.beginPath(); p.moveTo(*pts[0])
        for pt in pts[1:]:
            p.lineTo(*pt)
        c.drawPath(p, stroke=1, fill=0)
        if peak is not None:
            px, py = pts[peak]
            c.setDash(2, 2); c.setStrokeColor(Color(1, 1, 1, .3)); c.setLineWidth(.6); c.line(px, py, px, B); c.setDash()
            c.setFillColor(TXT); c.setStrokeColor(BLUE); c.setLineWidth(2); c.circle(px, py, 3.6, stroke=1, fill=1)
            anchor = "start" if px < L + 60 else "end" if px > R - 60 else "middle"
            self.text(px + (6 if anchor == "start" else -6 if anchor == "end" else 0), min(py + 7, T + 2), f"Peak {peak:02d}:00 · {fmt(hours[peak])}", 7.6, TXT, True, anchor)

    def findings(self, x, y, w, h, items):
        top = self.card(x, y, w, h, "Key findings", "For this selection")
        yy = top - 4
        for i, t in enumerate(items[:7], 1):
            if yy < y - h + 24:
                break
            c = self.c
            c.setFillColor(Color(.36, .55, .94, .18)); c.roundRect(x + 14, yy - 4, 14, 14, 4, stroke=0, fill=1)
            self.text(x + 21, yy, str(i), 7.6, HexColor("#a9c3ff"), True, "middle")
            yy = self.wrap(x + 36, yy, t, w - 52, 8.8, HexColor("#d6ddee"), leading=12, max_lines=3) - 6

    def bars(self, x, y, w, rows, metric="hosts", n=8, label=lambda r: r["label"], stack=False, row_h=None):
        rows = [r for r in rows if (r.get(metric) if r.get(metric) is not None else r.get("count"))][:n]
        if not rows:
            self.text(x, y - 10, "Nothing for this selection.", 8.5, MUTE); return y - 20
        mx = max(r.get(metric) if r.get(metric) is not None else r["count"] for r in rows) or 1
        yy = y
        for r in rows:
            v = r.get(metric) if r.get(metric) is not None else r["count"]
            if stack:
                yy = self.wrap(x, yy - 9, label(r), w - 50, 8.4, HexColor("#d6ddee"), max_lines=2, leading=10.5) + 10.5
                self.bar(x, yy - 16, w - 50, 5.5, v / mx)
                self.text(x + w, yy - 16, fmt(v), 8.6, TXT, True, "end")
                yy -= (row_h or 26)
            else:
                lw = w * .44
                self.text(x, yy - 9, self.fit(label(r), lw - 6, 8.4), 8.4, HexColor("#d6ddee"))
                self.bar(x + lw, yy - 10, w - lw - 46, 5.5, v / mx)
                self.text(x + w, yy - 9, fmt(v), 8.6, TXT, True, "end")
                yy -= (row_h or 17)
        return yy

    def donut(self, x, y, size, rows, unit, w=300, severity=False):
        rows = [r for r in rows if r.get("count")]
        sevc = {"critical": HexColor("#ef4444"), "high": HexColor("#f97316"), "medium": HexColor("#f5b54a"), "low": HexColor("#38bdf8"),
                "info": HexColor("#94a3b8"), "unrated": HexColor("#64748b")}
        col = lambda i, p: (sevc.get(p.get("value"), HexColor("#64748b")) if severity else
                            HexColor("#3a3f4d") if p.get("other") else PALETTE[i % len(PALETTE)])
        if not rows:
            self.text(x, y - 10, "Nothing for this selection.", 8.5, MUTE); return
        top, rest = rows[:7], sum(r["count"] for r in rows[7:])
        parts = top + ([{"label": "Other", "count": rest, "other": True}] if rest else [])
        tot = sum(p["count"] for p in parts)
        c = self.c
        cx, cy, R, r0 = x + size / 2, y - size / 2, size / 2, size / 2 * .64
        a0 = 90.0
        for i, p in enumerate(parts):
            ext = -360.0 * p["count"] / tot
            c.setFillColor(col(i, p)); c.setStrokeColor(BG); c.setLineWidth(1.2)
            path = c.beginPath(); path.moveTo(cx, cy); path.arcTo(cx - R, cy - R, cx + R, cy + R, a0, ext); path.close()
            c.drawPath(path, stroke=1, fill=1); a0 += ext
        c.setFillColor(CARD); c.circle(cx, cy, r0, stroke=0, fill=1)
        self.text(cx, cy, fmt(tot), 12.5, TXT, True, "middle")
        self.text(cx, cy - 11, unit.upper(), 6.2, MUTE, True, "middle")
        lx, ly = x + size + 16, y - 6
        for i, p in enumerate(parts):
            c.setFillColor(col(i, p)); c.roundRect(lx, ly - 7, 7, 7, 2, stroke=0, fill=1)
            right = x + w
            self.text(lx + 12, ly - 6.5, self.fit(p["label"], right - lx - 52, 8.2), 8.2, HexColor("#d6ddee"))
            self.text(right, ly - 6.5, pct(p["count"] / tot), 8.2, TXT, True, "end")
            ly -= 13.5

    def region_map(self, x, y, w, h, shapes, rows, details, comms):
        """The country's first-level regions, coloured by activity, with their names."""
        if not shapes:
            self.text(x, y - 12, "No region map for this country.", 8.5, MUTE); return
        norm = lambda s: re.sub(r"[^A-Z]", "", re.sub(r"\b(REGION|PROVINCE|STATE|COUNTY|DISTRICT|GOVERNORATE)\b", "", str(s).upper()))
        keys = {norm(v["name"]): k for k, v in shapes["regions"].items()}
        byk = {}
        for r in rows:
            k = keys.get(norm(r["value"])) or next((kk for nn, kk in keys.items() if nn and (nn in norm(r["value"]) or norm(r["value"]) in nn)), None)
            if k:
                byk[k] = r
        mx = max([r.get("hosts") or r["count"] for r in byk.values()] or [1])
        x0, y0, x1, y1 = shapes["bbox"]
        kx = math.cos(math.radians((y0 + y1) / 2)); s = min((w - 10) / ((x1 - x0) * kx), (h - 10) / (y1 - y0))
        ox, oy = x + (w - (x1 - x0) * kx * s) / 2, y - h + (h - (y1 - y0) * s) / 2
        P = lambda lo, la: (ox + (lo - x0) * kx * s, oy + (la - y0) * s)
        c = self.c
        labels = []
        for k, reg in shapes["regions"].items():
            r = byk.get(k); v = (r.get("hosts") or r["count"]) if r else 0; t = v / mx
            c.setFillColor(Color((91 + 148 * t) / 255, (141 - 70 * t) / 255, (239 - 162 * t) / 255, .28 + .65 * t) if r else Color(1, 1, 1, .05))
            c.setStrokeColor(BG); c.setLineWidth(.8)
            path = c.beginPath(); xs, ys = [], []
            for poly in reg["polys"]:
                for ring in poly:
                    for i, (lo, la) in enumerate(ring):
                        px, py = P(lo, la); xs.append(px); ys.append(py)
                        (path.lineTo if i else path.moveTo)(px, py)
                    path.close()
            c.drawPath(path, stroke=1, fill=1, fillMode=0)
            lx, ly = P(*reg["label"]) if reg.get("label") else ((min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2)
            name = re.sub(r"\s+(Region|Province|State)$", "", reg["name"])
            labels.append((v, lx, ly, name, r))
        placed = []
        for v, lx, ly, name, r in sorted(labels, key=lambda z: -z[0]):        # busiest first; skip overlapping names
            tw = c.stringWidth(self.s(name), self.F["b"], 6.6)
            box = (lx - tw / 2 - 2, ly - 8, lx + tw / 2 + 2, ly + 8)
            if any(not (box[2] < b[0] or box[0] > b[2] or box[3] < b[1] or box[1] > b[3]) for b in placed):
                continue
            placed.append(box)
            c.saveState(); c.setFillColor(TXT); c.setStrokeColor(Color(.03, .04, .07, .9)); c.setLineWidth(2.2)
            t = c.beginText(); t.setTextRenderMode(2); t.setFont(self.F["b"], 6.6); tw = c.stringWidth(self.s(name), self.F["b"], 6.6)
            t.setTextOrigin(lx - tw / 2, ly + 1); t.textOut(self.s(name)); c.drawText(t)
            c.restoreState()
            self.text(lx - tw / 2, ly + 1, name, 6.6, TXT, True)
            if r:
                self.text(lx, ly - 7, fmt(v), 6.2, HexColor("#c9d6ff"), True, "middle")

    def region_tree(self, x, y, w, bottom, regions, details, comms):
        """Each region with its total, and its cities with theirs underneath, before the next region."""
        unit = "devices" if comms else "hosts"
        mx = max([r.get("hosts") or r["count"] for r in regions] or [1]) or 1
        yy, shown = y, 0
        regions = [r for r in regions if r["value"] != "Unknown region"]
        for r in regions:
            cities = [c for c in (details.get(r["value"]) or {}).get("city_devices", []) if c[1]]
            cities = [c for c in cities if c[0].lower() != r["value"].lower() or len(cities) == 1][:4]
            need = 17 + 12 * len(cities)
            if yy - need < bottom:
                break
            v = r.get("hosts") or r["count"]
            self.text(x, yy - 9, self.fit(r["label"], w * .48, 9.2, True), 9.2, TXT, True)
            self.bar(x + w * .5, yy - 10, w * .5 - 52, 5.5, v / mx)
            self.text(x + w, yy - 9, fmt(v), 9.4, TXT, True, "end")
            yy -= 15
            for name, n in cities:
                self.c.setFillColor(HexColor("#ffd38a")); self.c.circle(x + 7, yy - 6.4, 1.8, stroke=0, fill=1)
                self.text(x + 14, yy - 9, self.fit(name, w * .6, 8), 8, HexColor("#c3cbe0"))
                self.text(x + w, yy - 9, f"{fmt(n)} {unit}", 7.8, DIM, anchor="end")
                yy -= 12
            yy -= 4
            self.c.setStrokeColor(Color(1, 1, 1, .05)); self.c.setLineWidth(.5); self.c.line(x, yy + 2, x + w, yy + 2)
            shown += 1
        if shown < len(regions):
            rest = regions[shown:]
            self.text(x, yy - 9, f"+ {len(rest)} more region{'s' if len(rest) != 1 else ''} with {fmt(sum((r.get('hosts') or r['count']) for r in rest))} {unit}", 7.8, MUTE)
        return yy

    def ranking(self, x, y, w, rows, comms, max_rows=10):
        mx = max([r.get("hosts") or r["count"] for r in rows] or [1])
        yy = y
        for i, r in enumerate(rows[:max_rows], 1):
            c = self.c
            c.setFillColor(Color(1, 1, 1, .05)); c.roundRect(x, yy - 18, 17, 17, 4, stroke=0, fill=1)
            self.text(x + 8.5, yy - 12, str(i), 8, DIM, True, "middle")
            name = (r.get("title") or r["value"]) if comms else r["value"]
            self.text(x + 26, yy - 9, self.fit(name, w * .55, 9.6, True), 9.6, TXT, True)
            sub = r["value"] if comms and r.get("title") and r["title"] != r["value"] else (r.get("title") if not comms else "")
            nx = x + 26 + min(w * .55, c.stringWidth(self.s(self.fit(name, w * .55, 9.6, True)), self.F["b"], 9.6)) + 8
            if sub:
                self.text(nx, yy - 9, self.fit(sub, x + w - 90 - nx, 7.8), 7.8, MUTE, mono=comms)
            tx = x + 26
            if not comms:
                if r.get("exploited"):
                    tx = self.pill(tx, yy - 21, "Actively exploited", RED)
                if r.get("cvss") is not None:
                    tx = self.pill(tx, yy - 21, f"CVSS {r['cvss']}", RED if r["cvss"] >= 9 else AMBER if r["cvss"] >= 7 else BLUE)
                if r.get("epss") is not None and r["epss"] >= .1:
                    tx = self.pill(tx, yy - 21, f"EPSS {pct(r['epss'])}", AMBER)
                if r.get("infection"):
                    tx = self.pill(tx, yy - 21, "Infection / category · calling botnet sinkholes", RED)
                elif not r.get("cve"):
                    tx = self.pill(tx, yy - 21, "Configuration / exposure", SLATE)
            elif r.get("family"):
                tx = self.pill(tx, yy - 21, "Threat actor" if r["family"].startswith("actor:") else "Malpedia", BLUE)
            elif r.get("title"):
                tx = self.pill(tx, yy - 21, "Looking Glass definition", VIOLET)
            self.bar(tx + 4, yy - 20, x + w - 80 - tx, 5.5, (r.get("hosts") or r["count"]) / mx)
            self.text(x + w, yy - 10, fmt(r.get("hosts") or r["count"]), 13, TXT, True, "end")
            self.text(x + w, yy - 20, "devices" if comms else "hosts", 6.8, MUTE, anchor="end")
            yy -= 33
        return yy

    def hero(self, x, y, w, items):
        n = len(items); gw = (w - 8 * (n - 1)) / n
        for i, (v, label, col) in enumerate(items):
            xx = x + i * (gw + 8)
            self.c.setFillColor(Color(1, 1, 1, .035)); self.c.setStrokeColor(Color(1, 1, 1, .06)); self.c.roundRect(xx, y - 40, gw, 40, 8, stroke=1, fill=1)
            self.text(xx + 10, y - 20, v, 16, col, True)
            self.text(xx + 10, y - 32, self.fit(label, gw - 16, 7.4), 7.4, MUTE)
        return y - 48

    def steps(self, x, y, w, h, rows, unit):
        n = len(rows); gw = (w - 8 * (n - 1)) / max(1, n); mx = max([r["count"] for r in rows] or [1]) or 1
        for i, r in enumerate(rows):
            xx = x + i * (gw + 8)
            self.text(xx + gw / 2, y - 9, fmt(r["count"]), 8.6, TXT, True, "middle")
            colh = h - 32
            self.c.setFillColor(Color(1, 1, 1, .03)); self.c.roundRect(xx, y - 14 - colh, gw, colh, 5, stroke=0, fill=1)
            bh = max(3, colh * r["count"] / mx)
            c = self.c
            c.setFillColor(BLUE); c.roundRect(xx, y - 14 - colh, gw, bh, 5, stroke=0, fill=1)
            if bh > 12:
                c.setFillColor(Color(VIOLET.red, VIOLET.green, VIOLET.blue, .9)); c.roundRect(xx, y - 14 - colh + bh * .5, gw, bh * .5, 5, stroke=0, fill=1)
            self.text(xx + gw / 2, y - h + 6, self.fit(r["label"], gw, 7.2), 7.2, MUTE, anchor="middle")
        return y - h - 6

    def explanation(self, x, y, w, name, x_, stat, comms):
        """One explanation card; returns its height (drawn only when y is given)."""
        lines = []
        kind = x_.get("kind")
        if kind == "cve":
            tags = ([("Actively exploited · CISA KEV", RED)] if x_.get("exploited") else []) + \
                   ([(f"CVSS {x_['cvss']['score']} {str(x_['cvss'].get('severity', '')).lower()}", RED if x_["cvss"]["score"] >= 9 else AMBER if x_["cvss"]["score"] >= 7 else BLUE)] if x_.get("cvss") else []) + \
                   ([(f"EPSS {pct(x_['epss'], 1)}", AMBER if x_["epss"] >= .1 else SLATE)] if x_.get("epss") is not None else [])
            title = (x_.get("kev") or {}).get("name") or ""
        elif x_.get("found") and kind == "actor":
            tags, title = [("Threat actor · Malpedia", AMBER)], x_.get("name", "")
        elif x_.get("found"):
            tags, title = [("Malware family · Malpedia", BLUE)], x_.get("name", "")
        elif x_.get("curated"):
            tags, title = [("Looking Glass definition", VIOLET)], x_.get("title", "")
        else:
            tags, title = [(x_.get("title") or "Not in Malpedia", SLATE)], ""
        desc = x_.get("description") or x_.get("text") or x_.get("reason") or ""
        alert = ""
        if kind == "cve" and x_.get("kev"):
            kv = x_["kev"]
            alert = (f"Actively exploited since {kv.get('date_added')}" + ("; used in ransomware" if kv.get("ransomware") == "Known" else "") + ". "
                     + (f"Required action: {kv['action']}" if kv.get("action") else ""))
        dl = simpleSplit(self.s(desc), self.F["r"], 8.2, w - 24)[:6]
        # researchers' notes on this name (notes.py), the newest first, up to three lines
        nt = " ".join(f"Notes shared by {n.get('role') or 'Researcher'}: {n.get('by') or 'a researcher'}"
                      f"{' (' + n['date'] + ')' if n.get('date') else ''}: {n.get('text', '')}"
                      + (f" Combinations: {', '.join(c['code'] for c in n['codes'])}." if n.get("codes") else "")
                      for n in (x_.get("notes") or [])[:2])
        if nt:
            dl += simpleSplit(self.s(nt), self.F["r"], 8.2, w - 24)[:3]
        al = simpleSplit(self.s(alert), self.F["r"], 7.8, w - 36)[:3] if alert else []
        h = 46 + 11 * len(dl) + (20 + 10 * len(al) if al else 0) + (12 if title and title != name else 0)
        if y is None:
            return h
        self.card(x, y, w, h)
        tx = x + 12
        for t, col in tags:
            tx = self.pill(tx, y - 17, t, col)
        self.text(x + 12, y - 33, self.fit(name, w * .6, 10.5, True), 10.5, TXT, True)
        if stat:
            self.text(x + w - 12, y - 33, self.fit(stat, w * .38, 7.6), 7.6, HexColor("#a9c3ff"), anchor="end")
        yy = y - 45
        if title and title != name:
            self.text(x + 12, yy, self.fit(title, w - 24, 8.6, True), 8.6, HexColor("#c9d6ff"), True); yy -= 12
        for ln in dl:
            self.text(x + 12, yy, ln, 8.2, HexColor("#d6ddee")); yy -= 11
        if al:
            yy -= 8
            self.c.setFillColor(Color(.94, .36, .42, .12)); self.c.setStrokeColor(Color(.94, .36, .42, .5))
            self.c.roundRect(x + 10, yy - 10 * (len(al) - 1) - 5, w - 20, 10 * len(al) + 6, 6, stroke=1, fill=1)
            for ln in al:
                self.text(x + 18, yy, ln, 7.8, HexColor("#f6c6cb")); yy -= 10
        return h


def build(d, enr, meta):
    comms = d["platform"] == "comms"
    k = d["kpis"]
    doc = Doc({**meta, "day": d["day"], "cities": d.get("cities_map") or []})
    unit = "Events" if comms else "Records"

    # ---------------- page 1: overview
    y = doc.new_page("Overview")
    doc.text(M, y - 4, (("Infections & attacks" if comms else "Exposure & vulnerabilities") + f" · {d['day']}").upper(), 8, HexColor("#a9b8ff"), True)
    y = doc.wrap(M, y - 22, d["findings"][0] if d["findings"] else "Nothing was reported for this selection.", W - 2 * M - 120, 17, TXT, True, 21, 2) - 4
    tiles = [(fmt(k["devices"]), "Affected devices", "infected or attacking", BLUE), (fmt(k["infections"]), "Infections", "families and categories", VIOLET),
             (fmt(k["multi_infected"]), "Several infections", "devices to clean up first", AMBER), (fmt(k["cross_report"]), "In several reports", "devices seen by more than one report", RED),
             (fmt(k["regions"]), "Regions affected", f"{fmt(k['networks'])} networks", TEAL), (fmt(k["events"]), "Events", f"{pct(k['share_of_day'], 1)} of the day", SLATE)] if comms else \
            [(fmt(k["hosts"]), "Internet-facing hosts", f"{fmt(k['services'])} services exposed", BLUE), (fmt(k["vulnerable_hosts"]), "Hosts with an issue", f"{pct(k['vulnerable_hosts'] / max(1, k['hosts']))} of the hosts", AMBER),
             (fmt(k["kev_hosts"]), "Actively exploited", f"{fmt(k['kev_cves'])} CVEs in CISA KEV", RED), (fmt(k["critical_cves"]), "Critical CVEs", "CVSS 9 or more", VIOLET),
             (fmt(k["multi_issue"]), "Several issues", "largest attack surface", TEAL), (fmt(k["records"]), "Records", f"{pct(k['share_of_day'], 1)} of the day", SLATE)]
    y = doc.kpis(y, tiles)
    hgt = y - 30
    cw = (W - 2 * M - 12) * .62
    doc.area(M, y, cw, hgt, d["hours"], d["peak_hour"], unit)
    doc.findings(M + cw + 12, y, W - 2 * M - cw - 12, hgt, d["findings"][1:] or ["No further findings for this selection."])

    # ---------------- 7-day baseline (the report day against the 7 days before it)
    if (d.get("baseline") or {}).get("days"):
        doc.baseline_page(doc.new_page("7-day baseline"), d, d["baseline"], comms)

    # ---------------- page 2: where and who
    y = doc.new_page("Where and who")
    hh = (y - 30) / 1
    mw = (W - 2 * M - 12) * .62
    if meta.get("nomap"):
        # generated without the map (the reports' regions are not on the selected country's map): the list takes the card
        top = doc.card(M, y, mw, hh, "Regions and cities", "Each region's total, with its cities beneath")
        doc.text(M + 14, top - 2, ("Devices" if comms else "Hosts") + " per region and city", 8, DIM, True)
        doc.text(M + mw - 14, top - 2, "Map left out: these regions are not on the selected country's map", 7.5, MUTE, anchor="end")
        doc.region_tree(M + 14, top - 10, mw - 28, y - hh + 16, d["regions"], d.get("region_details", {}), comms)
    else:
        top = doc.card(M, y, mw, hh, "Regions and cities", "Regions coloured by activity (red is most), with each region's cities beside the map")
        doc.region_map(M + 10, top, mw * .56, hh - (y - top) - 12, meta.get("shapes"), d["regions"], d.get("region_details", {}), comms)
        doc.text(M + mw * .56 + 22, top - 2, ("Devices" if comms else "Hosts") + " per region and city", 8, DIM, True)
        doc.region_tree(M + mw * .56 + 22, top - 10, mw * .44 - 36, y - hh + 16, d["regions"], d.get("region_details", {}), comms)
    x2, w2 = M + mw + 12, W - 2 * M - mw - 12
    h2 = (hh - 12) / 2
    top = doc.card(x2, y, w2, h2, "Sectors", "By the type of network")
    doc.donut(x2 + 14, top - 2, min(110, h2 - 50), d["sectors"], unit, w2 - 28)
    top = doc.card(x2, y - h2 - 12, w2, h2, "Attack types" if comms else "Report families", f"Share of the {unit.lower()}")
    doc.donut(x2 + 14, top - 2, min(110, h2 - 50), d["attack"] if comms else d["families"], unit, w2 - 28)

    # ---------------- page 3: top threats
    y = doc.new_page("Top infections" if comms else "Top issues")
    rw = (W - 2 * M - 12) * .6
    rows = d["infections"] if comms else sorted(d["issues"] + (d.get("infections_on") or []),        # with the hosts' infections
                                                key=lambda r: (-r["hosts"], not r["exploited"], -(r["cvss"] or 0)))
    top = doc.card(M, y, rw, y - 30, "Top infections" if comms else "Top issues",
                   "Devices per infection" if comms else "Hosts per issue, most hosts first")
    doc.ranking(M + 14, top, rw - 28, rows, comms, max_rows=int((top - 40) // 33))
    x2, w2 = M + rw + 12, W - 2 * M - rw - 12
    h3 = (y - 30 - 12) / 2
    top = doc.card(x2, y, w2, h3, "Most affected networks", ("Devices" if comms else "Hosts") + " per network")
    doc.bars(x2 + 14, top, w2 - 28, [r for r in d["networks"] if r["value"] != "Unknown network"], n=int((h3 - 50) // 17))
    if comms:
        top = doc.card(x2, y - h3 - 12, w2, h3, "Where infected devices connect to", "Events per country of the server contacted")
        doc.bars(x2 + 14, top, w2 - 28, d["destinations"], metric="count", n=int((h3 - 50) // 17), label=lambda r: _country(r["label"]))
    else:
        top = doc.card(x2, y - h3 - 12, w2, h3, "Exposed services", "Hosts per service")
        doc.bars(x2 + 14, top, w2 - 28, d["services"], n=int((h3 - 50) // 17))

    # ---------------- page 4: deeper insight
    y = doc.new_page("Deeper insight")
    cw3 = (W - 2 * M - 24) / 3
    hh = y - 30
    top = doc.card(M, y, cw3, hh, "Devices with several infections" if comms else "Hosts with several issues",
                   "The clean-up priority" if comms else "The largest attack surface")
    mlt = d["multi"]
    yy = doc.hero(M + 14, top, cw3 - 28, [(fmt(mlt["devices"] if comms else mlt["hosts"]), "devices" if comms else "hosts", HexColor("#ffd38a")),
                                          (pct(mlt["share"]), "of the affected devices" if comms else "of the hosts with an issue", TXT)])
    yy = doc.steps(M + 14, yy, cw3 - 28, 92, mlt["by_count"], "devices")
    doc.text(M + 14, yy - 4, f"Top findings · {fmt(mlt.get('combinations', len(mlt['combos'])))} combinations in all (CSV)", 8.4, DIM, True)
    doc.bars(M + 14, yy - 10, cw3 - 28, mlt["combos"], metric="count", n=5, stack=True)
    x2 = M + cw3 + 12
    top = doc.card(x2, y, cw3, hh, "Cross-report analysis", "The same " + ("device seen by different sensors" if comms else "host in several reports"))
    cr = d["cross"]
    yy = doc.hero(x2 + 14, top, cw3 - 28, [(fmt(cr["devices"] if comms else cr["hosts"]), ("devices" if comms else "hosts") + " in several reports", HexColor("#a9c3ff")),
                                           (pct(cr["share"]), "of the devices" if comms else "of the hosts", TXT)])
    yy = doc.steps(x2 + 14, yy, cw3 - 28, 92, cr["by_count"], "devices")
    doc.text(x2 + 14, yy - 4, f"Top findings · {fmt(cr.get('combinations', 0))} combinations in all (CSV)", 8.4, DIM, True)
    doc.bars(x2 + 14, yy - 10, cw3 - 28, cr.get("combos") or (d["report_pairs"] if comms else cr["pairs"]), metric="count", n=5, stack=True)
    x3 = M + 2 * (cw3 + 12)
    h4 = (hh - 12) / 2
    if comms:
        top = doc.card(x3, y, cw3, h4, "Repeat behaviour", "Devices that call home again and again")
        b = d["beacon"]
        yy = doc.hero(x3 + 14, top, cw3 - 28, [(fmt(b["repeating"]), "seen three times or more", HexColor("#cdb9ff")), (fmt(b["regular"]), "at a regular rhythm", HexColor("#ffd38a"))])
        doc.wrap(x3 + 14, yy - 6, f"Typical repeat interval: {b['typical']}. A regular rhythm points to automated malware check-ins." if b["typical"] else
                 "Not enough repeated contacts to measure a rhythm.", cw3 - 28, 8.4, HexColor("#d6ddee"))
    else:
        top = doc.card(x3, y, cw3, h4, "Kinds of issue", "Vulnerabilities versus configuration and exposure")
        yy = doc.hero(x3 + 14, top, cw3 - 28, [(fmt(k["cves"]), "different CVEs", HexColor("#cdb9ff")), (fmt(k["issues"] - k["cves"]), "other issues", TXT)])
        doc.bars(x3 + 14, yy, cw3 - 28, d["issue_kinds"], metric="count", n=2)
    top = doc.card(x3, y - h4 - 12, cw3, h4, "Severity", "As rated by Shadowserver")
    doc.donut(x3 + 14, top - 2, min(96, h4 - 50), d["severity"], unit, cw3 - 28, severity=True)

    # ---------------- explanations
    if enr:
        y = doc.new_page("Explained")
        doc.text(M, y - 4, ("WHAT THE TOP INFECTIONS ARE" if comms else "WHAT THE TOP ISSUES ARE"), 8, HexColor("#a9b8ff"), True)
        y -= 14
        col_w, gap = (W - 2 * M - 12) / 2, 12
        cols = [y, y]
        stats = meta.get("stats", {})
        order = sorted(enr.items(), key=lambda kv: (not kv[1].get("exploited"),)) if not comms else list(enr.items())
        for name, x_ in order:
            h = doc.explanation(0, None, col_w, name, x_, stats.get(name), comms)
            ci = 0 if cols[0] >= cols[1] else 1
            if cols[ci] - h < 30:
                if cols[1 - ci] - h >= 30:
                    ci = 1 - ci
                else:
                    y = doc.new_page("Explained"); cols = [y, y]; ci = 0
            doc.explanation(M + ci * (col_w + gap), cols[ci], col_w, name, x_, stats.get(name), comms)
            cols[ci] -= h + 10
    return doc.done()


_COUNTRIES = {
    "NL": "Netherlands", "US": "United States", "DE": "Germany", "GB": "United Kingdom", "UK": "United Kingdom", "FR": "France",
    "IE": "Ireland", "DK": "Denmark", "IL": "Israel", "EU": "Europe (EU)", "CA": "Canada", "SG": "Singapore", "RU": "Russia",
    "CN": "China", "HK": "Hong Kong", "JP": "Japan", "KR": "South Korea", "IN": "India", "AU": "Australia", "BR": "Brazil",
    "SE": "Sweden", "NO": "Norway", "FI": "Finland", "PL": "Poland", "CZ": "Czechia", "AT": "Austria", "CH": "Switzerland",
    "BE": "Belgium", "LU": "Luxembourg", "IT": "Italy", "ES": "Spain", "PT": "Portugal", "RO": "Romania", "BG": "Bulgaria",
    "UA": "Ukraine", "TR": "Türkiye", "AE": "United Arab Emirates", "SA": "Saudi Arabia", "ZA": "South Africa", "NG": "Nigeria",
    "GH": "Ghana", "KE": "Kenya", "EG": "Egypt", "MA": "Morocco", "CI": "Côte d'Ivoire", "SN": "Senegal", "TG": "Togo",
    "BF": "Burkina Faso", "LT": "Lithuania", "LV": "Latvia", "EE": "Estonia", "MD": "Moldova", "SC": "Seychelles", "PA": "Panama",
    "VN": "Vietnam", "TH": "Thailand", "ID": "Indonesia", "MY": "Malaysia", "TW": "Taiwan", "MX": "Mexico", "AR": "Argentina"}


def _country(code):
    return _COUNTRIES.get(str(code or "").upper(), code)
