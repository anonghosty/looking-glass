"""The quarterly reports' two PDFs (quarterly.py), in the Executive report's look (executive_pdf.Doc):

  write_management(path, ...)  management and admins: the quarter at a glance, reports and networks, regions, sectors,
                               infections and CISA KEV, over time with the cases and management's decisions (each with
                               its full reason and date, no person's name), advisories in summary, data quality and
                               the retention dates
  write_advisor(path, ...)     advisors and admins: a short overview, advisories (per month, impacts, per organisation
                               with the follow-up), the cases that matter for advising, the top issues and CVEs per
                               network, and the accuracy checks. No management decisions.

Both say VALID or NOT VALID at the top of every page. Every text is drawn whole (rows grow with wrapped text, tables
carry on over pages; never "…"). Counts only: no address. Each returns every text it drew, for the address check.
"""
from datetime import date, datetime, timedelta, timezone

from reportlab.lib.colors import HexColor
from reportlab.lib.utils import simpleSplit

import executive_pdf as xp

M, Wd, H = xp.M, xp.W, xp.H
fmt = xp.fmt
GOOD, BAD = HexColor("#22c3a6"), HexColor("#ef5d6c")


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
        return y

    def footer(self):
        self.text(M, 22, "Addresses are counted by IP address, as Shadowserver reports them: one address can stand for several "
                         "devices (shared connections), and one device can use several addresses.", 6.6, xp.MUTE)
        self.text(M, 12, f"Aggregated figures only: no individual addresses. {self.meta['made'][:1].upper()}{self.meta['made'][1:]}, "
                         f"{self.meta['generated']}. Data: Shadowserver Foundation.", 7.2, xp.MUTE)
        self.text(Wd - M, 14, f"Page {self.page}", 7.2, xp.MUTE, anchor="end")

    def table(self, y, section, title, sub, cols, rows, bottom=44, size=8.2):
        """A card with a table; rows grow when a cell wraps; it carries on over pages, never cuts text."""
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
        hdr = [cell(lab, w, True) for (lab, _, _), w in zip(cols, widths)]
        hh = max(len(c) for c in hdr) * lead + 6
        i, first = 0, True
        while True:
            head_h = 18 + (13 if title else 0) + (12 if sub else 0) + 4
            room = y - bottom - head_h - hh - 10
            chunk, used = [], 0
            fresh = y > H - M - 140                  # at the top of a page: a row taller than the page is drawn anyway
            while i < len(measured):
                rh = max(len(c) for c in measured[i]) * lead + 6
                if used + rh > room and (chunk or not fresh):
                    break
                chunk.append(measured[i]); used += rh; i += 1
            if not chunk and i < len(measured):          # not even one row here: the whole table starts on the next page
                y = self.new_page(section)
                continue
            h = head_h + hh + used + 10
            top = self.card(M, y, Wd - 2 * M, h, (title + ("" if first else " (continued)")) if title else None, sub)
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

    def notes(self, y, title, lines):
        """A card of plain sentences, each wrapped whole; its height is measured first."""
        w = Wd - 2 * M - 28
        need = sum(len(simpleSplit(self.s(t), self.F["r"], 8.4, w)) * 11 + 2 for t in lines)
        top = self.card(M, y, Wd - 2 * M, 30 + need + 8, title)
        yy = top
        for t in lines:
            yy = self.wrap(M + 14, yy, t, w, 8.4, HexColor("#cfd6e6"), leading=11) - 2
        return y - (30 + need + 8) - 10


def _doc(R, status, made, audience):
    lo, last = R["lo"], R["hi"] - timedelta(days=1)
    upto = min(R["today"], last)
    meta = {"quarter": R["quarter"], "platform_label": "Quarterly report", "audience": audience, "status": status,
            "made": made or "made by Looking Glass",
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "selection": f"{lo:%d %b %Y} to {last:%d %b %Y}" + (f" (to date: {upto:%d %b %Y})" if upto < last else "")}
    return QDoc(meta), upto < last


def _month_chart(d, R, X, x, y, w, h):
    top = d.card(x, y, w, h, "Month by month", "Records and unique addresses per month")
    mx = {k: max([X["totals"][m][k] for m in R["months"]] + [1]) for k in ("records", "unique")}   # each against its highest month
    bw = (w - 60) / len(R["months"])
    base_y = y - h + 34
    for i, m in enumerate(R["months"]):
        t = X["totals"][m]
        x0 = x + 30 + i * bw
        for j, (k, col) in enumerate((("records", xp.BLUE), ("unique", xp.VIOLET))):
            hgt = (top - base_y - 26) * t[k] / mx[k]
            d.c.setFillColor(col); d.c.rect(x0 + 10 + j * 52, base_y, 30, max(hgt, .5), stroke=0, fill=1)
            d.text(x0 + 25 + j * 52, base_y + max(hgt, .5) + 4, fmt(t[k]), 7.4, xp.TXT, True, "middle")
        d.text(x0 + 51, base_y - 12, month_name(m), 8, xp.DIM, anchor="middle")
    d.pill(x + w - 150, y - 18, "records", xp.BLUE, 6.8); d.pill(x + w - 100, y - 18, "unique addresses", xp.VIOLET, 6.8)


def _read_me(R, X, W, running):
    notes = [f"Months so far: {', '.join(month_name(m) for m in X['elapsed'])}." + (" The quarter is still running." if running else ""),
             f"Records without an address: {fmt(X['noaddr'])}. Records without a network are counted under \"Unknown network\".",
             "Unique addresses across reports count each address once, so they are lower than the sum over reports.",
             f"Findings count each finding or case once ({fmt(W['opened'])} opened, {fmt(W['cases'])} of them cases). Management "
             f"decides once per organisation of a case, so there can be more decisions ({fmt(W['reviews'])}) than findings."]
    if R["failed"]:
        notes.insert(0, "Collections that could not be read: " + ", ".join(sorted(R["failed"])) + ".")
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
                   (fmt(T["networks"]), "Networks", "with records (unknown network included)", xp.TEAL),
                   (fmt(T["reports"]), "Reports with data", "of the Shadowserver reports received", xp.SLATE),
                   (fmt(A["sends"]), "Advisories sent", f"to {fmt(len(A['to']))} recipients", xp.AMBER),
                   (fmt(W["opened"]), "Findings opened", f"{fmt(W['still_open'])} still open · {fmt(W['reviews'])} decisions "
                                                          "(one per organisation of a case)", xp.RED)])
    ch = 200
    _month_chart(d, R, X, M, y, cw, ch)
    top2 = d.card(x2, y, cw, ch, "Report families", "Unique addresses per family (an address in two families counts in each)")
    d.bars(x2 + 14, top2, cw - 28, X["families"], metric="unique", n=7, bottom=y - ch + 8)
    y -= ch + 10
    d.notes(y, "Read me", _read_me(R, X, W, running))
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
    top = d.card(M, y, cw, hgt, "Regions", "Unique addresses per region")
    d.bars(M + 14, top, cw - 28, X["regions"], metric="unique", n=7, bottom=y - hgt + 8)
    top = d.card(x2, y, cw, hgt, "Sectors", "Unique addresses per sector")
    d.bars(x2 + 14, top, cw - 28, X["sectors"], metric="unique", n=7, bottom=y - hgt + 8)
    y2 = y - hgt - 10
    top = d.card(M, y2, cw, hgt, "Infections", "Top infection families (sinkhole and compromised reports), unique addresses")
    d.bars(M + 14, top, cw - 28, X["infections"], metric="unique", n=7, bottom=y2 - hgt + 8)
    top = d.card(x2, y2, cw, hgt, "Actively exploited (CISA KEV)",
                 f"{fmt(X['kev']['hosts'])} addresses, {fmt(X['kev']['records'])} records with a CVE in the KEV catalogue")
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
        y = d.table(y, sec, "Recurring networks", "Records in every month of the quarter so far",
                    [("Network", 0, "start"), ("Unique addresses", 110, "end"), ("Records", 90, "end")],
                    [[r["label"], fmt(r["unique"]), fmt(r["records"])] for r in X["recurring"][:12]])
    # 5 advisories in summary
    y = d.new_page("Advisories")
    _advisory_tables(d, y, "Advisories", R, A, with_orgs=False)
    # 6 data quality and retention
    sec = "Data quality and retention"
    y = d.new_page(sec)
    pd = R["purge"]
    rows = [["Quarter ends", long_day(pd["last_day"])],
            ["Download these reports before the end of (the 15th working day after, Mon-Fri)", long_day(pd["working_day_15"])],
            ["Purge day (the next working day)", long_day(pd["purge_day"])],
            ["Cutoff: report rows dated before it are deleted (the last 31 days are kept)", long_day(pd["cutoff"])],
            ["Raw report rows the purge deletes (all quarters, counted now)", fmt(sum(R["purge_all"].values()))],
            ["Kept after the purge", "these reports, their statistics, findings, cases and advisories"],
            ["Collections that could not be read", ", ".join(sorted(R["failed"])) or "none"]]
    y = d.table(y, sec, "Retention", None, [("Figure", 420, "start"), ("Value", 0, "start")], rows)
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
                   (fmt(T["networks"]), "Networks", "with records (unknown network included)", xp.TEAL),
                   (fmt(A["sends"]), "Advisories sent", f"{fmt(len(A['advisories']))} advisories to {fmt(len(A['to']))} recipients", xp.AMBER),
                   (fmt(W["opened"]), "Findings opened", f"{fmt(W['cases'])} of them cases", xp.SLATE),
                   (fmt(W["still_open"]), "Still open", f"{fmt(W['advisory_sent'])} with an advisory sent this quarter", xp.RED)])
    cw = (Wd - 2 * M - 10) / 2
    _month_chart(d, R, X, M, y, cw, 200)
    top2 = d.card(M + cw + 10, y, cw, 200, "Top networks", "Unique addresses across every report, by network name")
    d.bars(M + cw + 24, top2, cw - 28, X["networks"], metric="unique", n=7, bottom=y - 200 + 8)
    y -= 210
    notes = _read_me(R, X, W, running)[:-1] + [
        "The networks, reports and months are in advisor_networks; the follow-up per organisation in advisor_organisations; "
        "every issue and CVE per network, with the CVE's full description, in advisor_network_issues."]
    d.notes(y, "Read me", notes)
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
    top_nets = sorted(X["net_issues"].items(), key=lambda kv: (-len(R["net_hosts"].get(kv[0], {})), kv[0]))[:12]
    rows = []
    for asn, lst in top_nets:
        for r in lst[:5]:
            rows.append([netname(asn) + (f" (AS{asn})" if asn else ""), X["cve_label"](r["issue"]) if r["issue"].upper().startswith("CVE-") else r["issue"],
                         "yes" if r["kev"] else "no", fmt(r["unique"])])
    if rows:
        d.table(y, sec, "Top issues and CVEs of the 12 largest networks",
                "Up to five per network; every one, with each CVE's full description, is in the advisor_network_issues CSV",
                [("Network", 190, "start"), ("Issue or CVE", 0, "start"), ("CISA KEV", 60, "start"), ("Unique addresses", 100, "end")], rows)
    else:
        d.text(M, y - 10, "No issue or CVE was reported for a network this quarter.", 9, xp.MUTE)
    # 5 accuracy
    sec = "Accuracy checks"
    y = d.new_page(sec)
    pd = R["purge"]
    y = d.table(y, sec, "Keep your copy", None, [("Figure", 420, "start"), ("Value", 0, "start")],
                [["Download these reports before the end of (the 15th working day after the quarter, Mon-Fri)", long_day(pd["working_day_15"])],
                 ["The raw report rows dated before this day are deleted on the purge day", f"{long_day(pd['cutoff'])} (purge on {long_day(pd['purge_day'])})"]])
    _accuracy(d, y, sec, R)
    pdf = d.done()
    with open(path, "wb") as f:
        f.write(pdf)
    return d.drawn
