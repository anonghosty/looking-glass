# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The quarterly reports' two PDFs (quarterly.py), in the Executive report's look (executive_pdf.Doc):

  write_management(path, ...)  the management role: the quarter at a glance, reports and networks, regions, sectors,
                               infections and CISA KEV, over time with the cases and management's decisions (each with
                               its full reason and date, no person's name), advisories in summary, data quality and
                               the retention dates
  write_advisor(path, ...)     the advisor role: a short overview, advisories (per month, impacts, per organisation
                               with the follow-up), the cases that matter for advising, the top issues and CVEs per
                               network, and the accuracy checks. No management decisions.

Both say VALID or NOT VALID at the top of every page, and a quarter with no report rows says so on every page (r89).
The retention dates and the purge are as they were when the report was made (a record); the cards say what is true now. Every text is drawn whole (rows grow with wrapped text, tables
carry on over pages; never "…"). Counts only: no address. Each returns every text it drew, for the address check.
"""
from datetime import date, datetime, timedelta, timezone

from reportlab.lib.colors import HexColor
from reportlab.lib.utils import simpleSplit

import executive_pdf as xp

M, Wd, H = xp.M, xp.W, xp.H
fmt = xp.fmt
GOOD, BAD = HexColor("#22c3a6"), HexColor("#ef5d6c")


def _shown(rows, n, csv="management_summary", metric="unique"):
    """A card's subtitle tail for a list cut to n: " · 7 of 47; all in the management_summary CSV", or "" when every
    one is drawn (the bars skip rows with 0, so those are not counted as drawn)."""
    total = len(rows or [])
    drawn = min(n, sum(1 for r in rows or [] if r.get(metric)))
    return f" · {drawn:,} of {total:,}; all in the {csv} CSV" if total > drawn else ""


def month_name(m):
    return datetime.strptime(m, "%Y-%m").strftime("%B %Y")


def long_day(d):
    return (d if isinstance(d, date) else date.fromisoformat(str(d))).strftime("%A %d %B %Y")


class QDoc(xp.Doc):
    """The Executive report's page, with the quarterly header: the audience, the status (VALID / NOT VALID) on every page."""

    def __init__(self, meta):
        super().__init__(meta)
        self.c.setTitle(f"Looking Glass · Quarterly report for {meta['audience']} · {meta['quarter']}")
        self.drawn = []

    def text(self, x, y, text, size=10, color=xp.TXT, bold=False, anchor="start", mono=False):
        self.drawn.append(" ".join(text.lines) if isinstance(text, xp._Fit) and text.lines else str(text))
        return super().text(x, y, text, size, color, bold, anchor, mono)

    def new_page(self, section):
        if self.page:
            self.footer(); self.c.showPage()
        self.page += 1
        c = self.c
        c.setFillColor(xp.BG); c.rect(0, 0, Wd, H, stroke=0, fill=1)
        c.saveState(); c.setFillColor(xp.Color(.36, .55, .94, .10)); c.circle(Wd * .18, H + 40, 260, stroke=0, fill=1)
        c.setFillColor(xp.Color(.55, .36, .96, .08)); c.circle(Wd * .85, H + 60, 230, stroke=0, fill=1); c.restoreState()
        self.text(M, H - M - 6, "Looking Glass", 13, xp.TXT, True)
        x = M + c.stringWidth("Looking Glass", self.F["b"], 13) + 8
        x = self.pill(x, H - M - 5, "QUARTERLY", xp.VIOLET, 7)
        valid = self.meta["status"][0] == "VALID"
        self.pill(x, H - M - 5, self.meta["status"][0], GOOD if valid else BAD, 7)
        self.text(M, H - M - 20, f"Quarterly report for {self.meta['audience']} · {self.meta['quarter']}", 8.5, xp.DIM)
        self.text(Wd - M, H - M - 6, section, 11, HexColor("#a9b8ff"), True, "end")
        self.text(Wd - M, H - M - 20, self.fit(self.meta["selection"], 420, 8.5), 8.5, xp.DIM, anchor="end")
        c.setStrokeColor(xp.Color(1, 1, 1, .08)); c.setLineWidth(.6); c.line(M, H - M - 30, Wd - M, H - M - 30)
        y = H - M - 44
        if not valid:
            y = self.wrap(M, y - 2, f"NOT VALID: {self.meta['status'][1]}. Do not rely on these figures until the report is "
                                    "made again and says VALID.", Wd - 2 * M, 9.5, HexColor("#ff9aa4"), True) - 4
        if self.meta.get("empty"):                   # every page, so no zero-filled chart stands without it (r89)
            y = self.wrap(M, y - 2, self.meta["empty"], Wd - 2 * M, 9.5, HexColor("#ffd27a"), True) - 4
        return y

    def footer(self):
        self.text(M, 22, "Addresses are counted by IP address, as Shadowserver reports them: one address can stand for several "
                         "devices (shared connections), and one device can use several addresses.", 6.6, xp.MUTE)
        # who made it and when only (the user, 2026-11-28): no address notice, no "Data: Shadowserver Foundation" in a footer
        self.text(M, 12, f"{self.meta['made'][:1].upper()}{self.meta['made'][1:]}, {self.meta['generated']}.", 7.2, xp.MUTE)
        self.text(Wd - M, 14, f"Page {self.page}", 7.2, xp.MUTE, anchor="end")

    def table(self, y, section, title, sub, cols, rows, bottom=44, size=8.2, group=None):
        """A card with a table; rows grow when a cell wraps; it carries on over pages, never cuts text.
        group: a column whose value is drawn once for rows that follow each other with the same value (the network of
        its five issues: audit 2026-11-27, 6-9), and again at the top of every continued card, so no card starts blank."""
        lead = size * 1.32
        gap = 10
        inner = Wd - 2 * M - 28
        fixed = sum(w for _, w, _ in cols if w)
        flex = [i for i, (_, w, _) in enumerate(cols) if not w]
        widths = [w or (inner - fixed - gap * (len(cols) - 1)) / max(1, len(flex)) for _, w, _ in cols]

        def cell(v, w, bold=False):
            font = self.F["b"] if bold else self.F["r"]
            return xp.hard_lines(self, simpleSplit(self.s(v), font, size, w), font, size, w) or [""]
        measured = [[cell(v, w) for v, w in zip(r, widths)] for r in rows]
        same = [group is not None and k > 0 and rows[k][group] == rows[k - 1][group] for k in range(len(rows))]
        blank = [[[""] if j == group else c for j, c in enumerate(m)] if s else m for m, s in zip(measured, same)]
        hdr = [cell(lab, w, True) for (lab, _, _), w in zip(cols, widths)]
        hh = max(len(c) for c in hdr) * lead + 6
        i, first = 0, True
        while True:
            sub_now = sub if first else None             # a continued table: its title "(continued)", the subtitle once
            head_h = 18 + (13 if title else 0) + (12 if sub_now else 0) + 4
            room = y - bottom - head_h - hh - 10
            chunk, used = [], 0
            fresh = y > H - M - 140                  # at the top of a page: a row taller than the page is drawn anyway
            while i < len(measured):
                row = blank[i] if chunk else measured[i]     # the first row of a card always names its group
                rh = max(len(c) for c in row) * lead + 6
                if used + rh > room and (chunk or not fresh):
                    break
                chunk.append(row); used += rh; i += 1
            if not chunk and i < len(measured):          # not even one row here: the whole table starts on the next page
                y = self.new_page(section)
                continue
            h = head_h + hh + used + 10
            top = self.card(M, y, Wd - 2 * M, h, (title + ("" if first else " (continued)")) if title else None, sub_now)
            yy, x = top - 2, M + 14
            for lines, w, (_, _, al) in zip(hdr, widths, cols):
                for k, ln in enumerate(lines):
                    self.text(x + (w if al == "end" else 0), yy - k * lead, ln, 7.6, xp.MUTE, True, al)
                x += w + gap
            yy -= hh
            for r in chunk:
                rh = max(len(c) for c in r) * lead + 6
                x = M + 14
                for lines, w, (_, _, al) in zip(r, widths, cols):
                    for k, ln in enumerate(lines):
                        self.text(x + (w if al == "end" else 0), yy - k * lead, ln, size, xp.TXT, False, al)
                    x += w + gap
                self.c.setStrokeColor(xp.Color(1, 1, 1, .05)); self.c.setLineWidth(.5)
                self.c.line(M + 14, yy - rh + size + 1, Wd - M - 14, yy - rh + size + 1)
                yy -= rh
            y = y - h - 10
            first = False
            if i >= len(measured):
                return y
            y = self.new_page(section)

    def notes(self, y, title, lines, section=None, bottom=44):
        """A card of plain sentences, each wrapped whole (a long word broken, never cut); its height is measured first.
        What does not fit above the footer carries on in a "(continued)" card on the next page (audit 2026-11-27, 6-8:
        a long "Read me" ran off the page)."""
        w = Wd - 2 * M - 28
        size, lead = 8.4, 11
        measured = [xp.hard_lines(self, simpleSplit(self.s(t), self.F["r"], size, w), self.F["r"], size, w) or [""]
                    for t in lines]
        i, first = 0, True
        while i < len(measured):
            room = y - bottom - 38
            chunk, used = [], 0
            fresh = y > H - M - 140                  # at the top of a page: a sentence taller than the page is drawn anyway
            while i < len(measured):
                h = len(measured[i]) * lead + 2
                if used + h > room and (chunk or not fresh):
                    break
                chunk.append(measured[i]); used += h; i += 1
            if not chunk:
                y = self.new_page(section or title)
                continue
            top = self.card(M, y, Wd - 2 * M, 30 + used + 8, title if first else f"{title} (continued)")
            yy = top
            for ls in chunk:
                for ln in ls:
                    self.text(M + 14, yy, ln, size, HexColor("#cfd6e6"))
                    yy -= lead
                yy -= 2
            y = y - (30 + used + 8) - 10
            first = False
            if i < len(measured):
                y = self.new_page(section or title)
        return y


def _doc(R, status, made, audience):
    lo, last = R["lo"], R["hi"] - timedelta(days=1)
    upto = min(R["today"], last)
    meta = {"quarter": R["quarter"], "platform_label": "Quarterly report", "audience": audience, "status": status,
            "made": made or "made by Looking Glass",
            "generated": (datetime.fromtimestamp(R["now_ts"], timezone.utc) if R.get("now_ts") else
                          datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M UTC"),
            "selection": f"{lo:%d %b %Y} to {last:%d %b %Y}" + (f" (to date: {upto:%d %b %Y})" if upto < last else ""),
            "empty": "" if sum(R["rep_total"].values()) else _empty(R)}
    return QDoc(meta), upto < last


def _empty(R):
    import quarterly                                 # the one sentence (the cards and the CSVs say the same)
    return quarterly.empty_text(R["quarter"], R.get("oldest_day"))


def _no_purge_made_late(R):
    """The report was made after its purge day: no purge for this quarter (what was true when it was made)."""
    pd = R["purge"]
    return R["today"] > pd["purge_day"], (f"No purge for this quarter: its purge day ({long_day(pd['purge_day'])}) had "
                                          "passed when this report was made. Nothing is deleted for it; the next quarter's "
                                          "purge covers its rows if the purge is on then")


def _month_chart(d, R, X, x, y, w, h):
    top = d.card(x, y, w, h, "Month by month", "Records and unique addresses per month")
    mx = {k: max([X["totals"][m][k] for m in R["months"]] + [1]) for k in ("records", "unique")}   # each against its highest month
    bw = (w - 60) / len(R["months"])
    base_y = y - h + 34
    for i, m in enumerate(R["months"]):
        t = X["totals"][m]
        mid = x + 30 + i * bw + bw / 2                   # each month's pair and its name centred in its slot (2026-11-28:
        for j, (k, col) in enumerate((("records", xp.BLUE), ("unique", xp.VIOLET))):   # drawn 10 pt from its left)
            hgt = (top - base_y - 26) * t[k] / mx[k]
            bx = mid - 41 + j * 52                        # two bars of 30 with 22 between: 82 wide
            d.c.setFillColor(col); d.c.rect(bx, base_y, 30, max(hgt, .5), stroke=0, fill=1)
            d.text(bx + 15, base_y + max(hgt, .5) + 4, fmt(t[k]), 7.4, xp.TXT, True, "middle")
        d.text(mid, base_y - 12, month_name(m), 8, xp.DIM, anchor="middle")
    # the legend at the card's right padding (14 pt, as its title on the left), the pills 4 pt apart like every pill row
    pw = lambda s: d.c.stringWidth(d.s(s), d.F["b"], 6.8) + 10 + 4               # noqa: E731
    lx = x + w - 14 - pw("records") - pw("unique addresses") + 4
    d.pill(d.pill(lx, y - 18, "records", xp.BLUE, 6.8), y - 18, "unique addresses", xp.VIOLET, 6.8)


def _read_me(R, X, W, running):
    un = X.get("unknown_network") or {}
    notes = [f"Months so far: {', '.join(month_name(m) for m in X['elapsed'])}." + (" The quarter is still running." if running else ""),
             f"Records without an address: {fmt(X['noaddr'])}. Records without a network ({fmt(un.get('records', 0))}) are "
             "shown as \"Unknown network\" and are not counted as a network. Networks are counted by company: two AS "
             "numbers of one company are one network.",
             "Unique addresses across reports count each address once, so they are lower than the sum over reports. An "
             "address seen in two regions, or in networks of two types, counts in each of them.",
             "Sectors are the network types of the addresses' networks (as the portal shows them). Shadowserver's own "
             "sector column is listed apart as Industry (Shadowserver).",
             "The quarter holds the reports sent in it (by the date in the file name)"
             + (f"; their events are dated {X['event_span'][0]} to {X['event_span'][1]}" if X.get("event_span") else "")
             + (f"; {fmt(X['undated'])} rows have no time and are counted by their file's date" if X.get("undated") else "")
             + "."]
    if X.get("duplicates"):
        notes.append(f"{fmt(X['duplicates'])} rows were also in another file of the same day (a country file and a "
                     "network file): each is counted once.")
    if X.get("not_on_portal"):
        notes.append("Counted here but not shown on the portal (reports its pages cannot read in full): "
                     + ", ".join(f"{r['label']} ({fmt(r['records'])} records)" for r in X["not_on_portal"]) + ".")
    # the findings note stays the last one (the advisor's report leaves it out: _read_me(...)[:-1])
    notes.append(f"Findings count each finding or case once ({fmt(W['opened'])} opened, {fmt(W['cases'])} of them cases). "
                 f"Management decides once per organisation of a case, so there can be more decisions ({fmt(W['reviews'])}) "
                 "than findings.")
    if R["failed"]:
        notes.insert(0, "Collections that could not be read: " + ", ".join(sorted(R["failed"])) + ".")
    notes.insert(0, f"Counted for: {(R.get('constituency') or {}).get('label') or 'the whole country'}. Every figure in this "
                    "report follows the constituency set in Settings → Constituency.")
    return notes


def _accuracy(d, y, section, R):
    return d.table(y, section, "Accuracy checks", "Run every time the report is made; any failure marks it NOT VALID",
                   [("Check", 0, "start"), ("Result", 70, "start"), ("Detail", 260, "start")],
                   [[g[0], "passed" if g[1] else "FAILED", g[2] or "-"] for g in R["_guards"]]
                   + [["8 no address in any output", "after writing", "checked on every file once written; a file with an "
                       "address is deleted and the run fails"]])


def _advisory_tables(d, y, section, R, A, with_orgs):
    rows = [[month_name(m), fmt(A["per_month"].get(m, 0))] for m in R["months"]]
    rows.append(["The quarter", f"{fmt(A['sends'])} sends of {fmt(len(A['advisories']))} advisories to {fmt(len(A['to']))} recipients"])
    y = d.table(y, section, "Advisories sent per month", None, [("Month", 0, "start"), ("Sent", 330, "end")], rows)
    if A["impact"]:
        y = d.table(y, section, "Impacts most seen", "In the advisories sent this quarter",
                    [("Impact", 0, "start"), ("Level", 120, "start"), ("Advisories", 90, "end")],
                    [[lab, lv or "-", fmt(n)] for (lab, lv), n in sorted(A["impact"].items(), key=lambda kv: (-kv[1], str(kv[0])))[:10]])
    if with_orgs and A["orgs"]:
        y = d.table(y, section, "Per organisation: advisories, open cases and follow-up",
                    "Follow-up: of the devices named in an advisory, how many were still seen in the reports after it was sent",
                    [("Organisation", 0, "start"), ("Advisories sent", 90, "end"), ("Devices named", 90, "end"),
                     ("Still seen after", 90, "end"), ("Not seen since", 90, "end"), ("Cases open", 80, "end")],
                    [[o, fmt(c["advisories"]), fmt(c["devices"]), fmt(c["still_seen"]), fmt(c["devices"] - c["still_seen"]),
                      fmt(c["cases_open"])] for o, c in sorted(A["orgs"].items())])
    return y


def write_management(path, R, X, W, A, status, made):
    d, running = _doc(R, status, made, "management")
    T = X["totals"]["quarter"]
    cw = (Wd - 2 * M - 10) / 2
    x2 = M + cw + 10
    # 1 at a glance
    y = d.new_page("The quarter at a glance")
    y = d.kpis(y, [(fmt(T["records"]), "Records", "rows in the quarter's reports", xp.BLUE),
                   (fmt(T["unique"]), "Unique addresses", "each counted once, across every report", xp.VIOLET),
                   (fmt(T["networks"]), "Networks", "companies with records (Unknown network not counted)", xp.TEAL),
                   (fmt(T["reports"]), "Reports with data", "of the Shadowserver reports received", xp.SLATE),
                   (fmt(A["sends"]), "Advisories sent", f"to {fmt(len(A['to']))} recipients", xp.AMBER),
                   (fmt(W["opened"]), "Findings opened", f"{fmt(W['still_open'])} still open · {fmt(W['reviews'])} decisions "
                                                          "(one per organisation of a case)", xp.RED)])
    ch = 200
    _month_chart(d, R, X, M, y, cw, ch)
    top2 = d.card(x2, y, cw, ch, "Report families", "Unique addresses per family (an address in two families counts in each)")
    d.bars(x2 + 14, top2, cw - 28, X["families"], metric="unique", n=7, bottom=y - ch + 8)
    y -= ch + 10
    d.notes(y, "Read me", _read_me(R, X, W, running), "The quarter at a glance")
    # 2 reports and networks
    y = d.new_page("Reports and networks")
    hgt = y - 50
    top = d.card(M, y, cw, hgt, "Top reports", "Unique addresses in the quarter")
    d.bars(M + 14, top, cw - 28, X["reports"], metric="unique", n=14, bottom=y - hgt + 8)
    top = d.card(x2, y, cw, hgt, "Top networks", "Unique addresses across every report, by network name")
    d.bars(x2 + 14, top, cw - 28, X["networks"], metric="unique", n=14, bottom=y - hgt + 8)
    # 3 regions, sectors, infections, KEV
    y = d.new_page("Where and what")
    hgt = (y - 60) / 2
    top = d.card(M, y, cw, hgt, "Regions", "Unique addresses per region" + _shown(X["regions"], 7))
    d.bars(M + 14, top, cw - 28, X["regions"], metric="unique", n=7, bottom=y - hgt + 8)
    top = d.card(x2, y, cw, hgt, "Sectors (network type)", "Unique addresses per network type" + _shown(X["sectors"], 7))
    d.bars(x2 + 14, top, cw - 28, X["sectors"], metric="unique", n=7, bottom=y - hgt + 8)
    y2 = y - hgt - 10
    cut = _shown(X["infections"], 7)                   # a cut card says so on one line: the shorter subtitle then
    top = d.card(M, y2, cw, hgt, "Infections", ("Sinkhole and compromised reports, unique addresses" + cut) if cut else
                 "Top infection families (sinkhole and compromised reports), unique addresses")
    d.bars(M + 14, top, cw - 28, X["infections"], metric="unique", n=7, bottom=y2 - hgt + 8)
    cut = _shown(X["kev"]["top"], 6)
    top = d.card(x2, y2, cw, hgt, "Actively exploited (CISA KEV)",
                 f"{fmt(X['kev']['hosts'])} addresses, {fmt(X['kev']['records'])} records"
                 + (f" with a KEV CVE{cut}" if cut else " with a CVE in the KEV catalogue"))
    if X["kev"]["top"]:
        d.bars(x2 + 14, top, cw - 28, X["kev"]["top"], metric="unique", n=6, bottom=y2 - hgt + 8)
    else:
        d.text(x2 + 14, top - 10, "No address with a CVE in the KEV catalogue this quarter.", 8.5, xp.MUTE)
    # 4 over time, cases and management's decisions (one section: the over-time figures alone left a page nearly empty)
    sec = "Over time, cases and decisions"
    y = d.new_page(sec)
    bw_ = X["better_worse"]
    rows = [["Networks with records in every month so far", fmt(len(X["recurring"])),
             "months so far: " + ", ".join(month_name(m) for m in X["elapsed"])]]
    if bw_:
        src = (X.get("prev") or {}).get("source", "")
        rows += [[k[:1].upper() + k[1:], f"{v:+,}" if k.startswith("change") else fmt(v), f"against the previous quarter ({src})"]
                 for k, v in bw_.items()]
    else:
        rows.append(["Better or worse than the previous quarter", "-", "No data for the previous quarter: nothing to compare yet."])
    rows += [["Findings expired unanswered (time to act passed)", fmt(W["expired"]), ""],
             ["Median days from opening to the decision", "-" if W["median_to_decision"] is None else str(W["median_to_decision"]),
              f"{len(W['to_decision'])} decided in the quarter"],
             ["Median days from opening to the advisory sent", "-" if W["median_to_advisory"] is None else str(W["median_to_advisory"]),
              f"{len(W['to_advisory'])} sent in the quarter"]]
    y = d.table(y, sec, "Recurring networks, better or worse, time to act", None,
                [("Figure", 300, "start"), ("Value", 80, "end"), ("Note", 0, "start")], rows)
    rows = [["Findings opened (each finding or case once)", fmt(W["opened"])], ["Of them cases", fmt(W["cases"])],
            ["Closed", fmt(W["closed"])], ["Advisory sent", fmt(W["advisory_sent"])], ["Still open", fmt(W["still_open"])],
            ["Expired (time to act)", fmt(W["expired"])],
            ["Decisions (one per organisation of a case): approved", fmt(W["approved"])],
            ["Decisions (one per organisation of a case): rejected", fmt(W["rejected"])],
            ["Decisions (one per organisation of a case): waiting", fmt(W["waiting"])]]
    rows += [[f"Opened in {month_name(m)}", fmt(W["opened_month"].get(m, 0))] for m in R["months"]]
    y = d.table(y, sec, "Cases and findings in the quarter", None, [("Figure", 0, "start"), ("Count", 90, "end")], rows)
    if W["decisions"]:
        y = d.table(y, sec, "Management's decisions", "One per organisation of a case, each with its deciding comment in full",
                    [("Finding", 170, "start"), ("Organisation", 120, "start"), ("Decision", 60, "start"), ("Date", 62, "start"),
                     ("Reason", 0, "start")],
                    [[f"{r['finding']} {r['title']}", r["organisation"] or "-", r["decision"], r["date"], r["reason"] or "-"]
                     for r in W["decisions"]])
    if X["recurring"]:
        y = d.table(y, sec, "Recurring networks", "Records in every month of the quarter so far"
                    + _shown(X["recurring"], 12, metric="label"),
                    [("Network", 0, "start"), ("Unique addresses", 110, "end"), ("Records", 90, "end")],
                    [[r["label"], fmt(r["unique"]), fmt(r["records"])] for r in X["recurring"][:12]])
    if X.get("industries"):
        # Shadowserver's own sector column, never under Sectors (the user, 2026-11-26)
        y = d.table(y, sec, "Industry (Shadowserver)", "Shadowserver's own sector column, not the network type"
                    + _shown(X["industries"], 12, metric="label"),
                    [("Industry", 0, "start"), ("Unique addresses", 110, "end"), ("Records", 90, "end")],
                    [[r["label"], fmt(r["unique"]), fmt(r["records"])] for r in X["industries"][:12]])
    # 5 advisories in summary
    y = d.new_page("Advisories")
    _advisory_tables(d, y, "Advisories", R, A, with_orgs=False)
    # 6 data quality and retention
    sec = "Data quality and retention"
    y = d.new_page(sec)
    pd = R["purge"]
    late, late_text = _no_purge_made_late(R)
    if late:
        rows = [["The quarterly purge", late_text],
                ["Quarter ends", long_day(pd["last_day"])],
                ["Purge day for this quarter (passed when this report was made)", long_day(pd["purge_day"])],
                ["Never deleted", "these reports, their statistics, findings, cases and advisories"],
                ["Collections that could not be read", ", ".join(sorted(R["failed"])) or "none"]]
    elif R.get("purge_on"):
        rows = [["The quarterly purge", "On when this report was made (turned on in Settings → Quarterly): it runs on the purge "
                 "day unless an administrator turns it off before then"],
                ["Quarter ends", long_day(pd["last_day"])],
                ["Download these reports before the end of (the 15th working day after, Mon-Fri)", long_day(pd["working_day_15"])],
                ["Purge day (the next working day)", long_day(pd["purge_day"])],
                ["Cutoff: report rows dated before it are deleted (the last 31 days are kept)", long_day(pd["cutoff"])],
                ["Raw report rows the purge deletes (all quarters, all networks in the database, not only the constituency; counted when this report was made)", fmt(sum(R["purge_all"].values()))],
                ["Kept after the purge", "these reports, their statistics, findings, cases and advisories"],
                ["Collections that could not be read", ", ".join(sorted(R["failed"])) or "none"]]
    else:
        rows = [["The quarterly purge", "Off on this installation when this report was made: nothing will be deleted. An "
                 "administrator can turn it on in Settings → Quarterly; until then every report row is kept"],
                ["Quarter ends", long_day(pd["last_day"])],
                ["If the purge is turned on before then: the purge day (16th working day after, Mon-Fri)", long_day(pd["purge_day"])],
                ["If it is turned on: report rows dated before this day would be deleted (the last 31 days are kept)", long_day(pd["cutoff"])],
                ["Raw report rows the purge would delete if turned on (all quarters, all networks in the database, not only the constituency; counted when this report was made)",
                 fmt(sum(R["purge_all"].values()))],
                ["Never deleted", "these reports, their statistics, findings, cases and advisories"],
                ["Collections that could not be read", ", ".join(sorted(R["failed"])) or "none"]]
    y = d.table(y, sec, "Retention", "As it was when this report was made: the Executive portal's card says what is true now",
                [("Figure", 420, "start"), ("Value", 0, "start")], rows)
    _accuracy(d, y, sec, R)
    pdf = d.done()
    with open(path, "wb") as f:
        f.write(pdf)
    return d.drawn


def write_advisor(path, R, X, W, A, status, made):
    d, running = _doc(R, status, made, "advisors")
    T = X["totals"]["quarter"]
    netname = X["netname"]
    # 1 overview
    y = d.new_page("The quarter for advisors")
    y = d.kpis(y, [(fmt(T["records"]), "Records", "rows in the quarter's reports", xp.BLUE),
                   (fmt(T["unique"]), "Unique addresses", "each counted once, across every report", xp.VIOLET),
                   (fmt(T["networks"]), "Networks", "companies with records (Unknown network not counted)", xp.TEAL),
                   (fmt(A["sends"]), "Advisories sent", f"{fmt(len(A['advisories']))} advisories to {fmt(len(A['to']))} recipients", xp.AMBER),
                   (fmt(W["opened"]), "Findings opened", f"{fmt(W['cases'])} of them cases", xp.SLATE),
                   (fmt(W["still_open"]), "Still open", f"{fmt(W['advisory_sent'])} with an advisory sent this quarter", xp.RED)])
    cw = (Wd - 2 * M - 10) / 2
    _month_chart(d, R, X, M, y, cw, 200)
    top2 = d.card(M + cw + 10, y, cw, 200, "Top networks", "Unique addresses across every report, by network name")
    d.bars(M + cw + 24, top2, cw - 28, X["networks"], metric="unique", n=7, bottom=y - 200 + 8)
    y -= 210
    notes = _read_me(R, X, W, running)[:-1] + [
        # the files named as the issues card names them ("the advisor_network_issues CSV"; the user, 2026-11-28)
        "The networks, reports and months are in the advisor_networks CSV; the follow-up per organisation in the "
        "advisor_organisations CSV; every issue and CVE per network, with the CVE's full description, in the "
        "advisor_network_issues CSV."]
    d.notes(y, "Read me", notes, "The quarter for advisors")
    # 2 advisories
    y = d.new_page("Advisories")
    _advisory_tables(d, y, "Advisories", R, A, with_orgs=True)
    # 3 the cases that matter for advising
    sec = "Cases for advising"
    y = d.new_page(sec)
    rows = [["Findings opened (each finding or case once)", fmt(W["opened"])], ["Of them cases", fmt(W["cases"])],
            ["With an advisory sent this quarter", fmt(W["advisory_sent"])], ["Still open", fmt(W["still_open"])],
            ["Closed", fmt(W["closed"])], ["Expired (time to act passed)", fmt(W["expired"])],
            ["Median days from opening to the advisory sent", "-" if W["median_to_advisory"] is None else str(W["median_to_advisory"])]]
    rows += [[f"Opened in {month_name(m)}", fmt(W["opened_month"].get(m, 0))] for m in R["months"]]
    y = d.table(y, sec, "Cases and findings in the quarter", None, [("Figure", 0, "start"), ("Count", 90, "end")], rows)
    # 4 issues per network
    sec = "Issues per network"
    y = d.new_page(sec)
    all_nets = sorted(X["net_issues"].items(), key=lambda kv: (-len(R["net_hosts"].get(kv[0], {})), kv[0]))
    top_nets = all_nets[:12]
    rows = []
    for asn, lst in top_nets:                           # X holds every issue; the PDF draws 5 per network and says "5 of M"
        for r in lst[:5]:
            rows.append([netname(asn) + (f" (AS{asn})" if asn else "") + (f": 5 of {len(lst):,} issues" if len(lst) > 5 else ""),
                         X["cve_label"](r["issue"]) if r["issue"].upper().startswith("CVE-") else r["issue"],
                         "yes" if r["kev"] else "no", fmt(r["unique"])])
    if rows:
        nets = (f"the {len(top_nets)} largest of {len(all_nets):,} networks" if len(all_nets) > len(top_nets)
                else f"every network ({len(all_nets):,})")
        d.table(y, sec, f"Top issues and CVEs of {nets}",
                "Up to five per network; every issue of every network, with each CVE's full description, is in the "
                "advisor_network_issues CSV",
                [("Network", 190, "start"), ("Issue or CVE", 0, "start"), ("CISA KEV", 60, "start"), ("Unique addresses", 100, "end")], rows,
                group=0)
    else:
        d.text(M, y - 10, "No issue or CVE was reported for a network this quarter.", 9, xp.MUTE)
    # 5 accuracy
    sec = "Accuracy checks"
    y = d.new_page(sec)
    pd = R["purge"]
    late, late_text = _no_purge_made_late(R)
    keep = [["The quarterly purge", late_text]] if late else ([["Download these reports before the end of (the 15th working day after the quarter, Mon-Fri)", long_day(pd["working_day_15"])],
             ["The raw report rows dated before this day are deleted on the purge day", f"{long_day(pd['cutoff'])} (purge on {long_day(pd['purge_day'])})"],
             ["The quarterly purge", "On when this report was made: it runs on the purge day unless an administrator turns it off before then"]]
            if R.get("purge_on") else
            [["The quarterly purge", "Off on this installation when this report was made: no report rows will be deleted"],
             ["If an administrator turns it on before the purge day", f"the raw report rows dated before {long_day(pd['cutoff'])} would be "
              f"deleted on {long_day(pd['purge_day'])}: download your copy before the end of {long_day(pd['working_day_15'])}"]])
    y = d.table(y, sec, "Keep your copy", "As it was when this report was made: the advisory portal's card says what is true now",
                [("Figure", 420, "start"), ("Value", 0, "start")], keep)
    _accuracy(d, y, sec, R)
    pdf = d.done()
    with open(path, "wb") as f:
        f.write(pdf)
    return d.drawn
