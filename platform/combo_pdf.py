"""The analyst's combination report (combos.py), drawn like the Executive report: dark pages, coloured key-figure tiles,
the activity chart and key findings, the region map with each region's cities, ranked bars, and the explanations as
cards. Unlike the Executive report it lists the devices' addresses: it is for analysts only, and every page says so.

Pages: Overview (what the combination is, the key figures, activity, key findings) · Where (the region map and
cities, networks, cities) · The devices (the busiest devices with their network, place, records and the other reports
they were seen in) · Across reports and the devices (cross-report patterns with their codes, what the devices are,
ports, records per day) · Explained (the name and every CVE in the combination, from Malpedia / NVD / CISA KEV / EPSS
and the Looking Glass definitions, and the researchers' notes).

build(data, meta) -> PDF bytes. data is assembled by combos.package; meta {platform_label, scope, selection, day,
generated_by, shapes}.
"""
from reportlab.lib.colors import Color, HexColor

import executive_pdf as ex
from executive_pdf import AMBER, BLUE, DIM, H, M, MUTE, RED, SLATE, TEAL, TXT, VIOLET, W, fmt, pct

def _share(n, total):
    """A share people read correctly: "<0.1%" rather than "0%" when there is at least one."""
    s = (n or 0) / max(1, total or 0)
    return "0%" if not n else "<0.1%" if s < .001 else f"{100 * s:.1f}%" if s < .1 else pct(s)


DEVICE_ROWS = 28                   # devices per page on "The devices" (two pages at most; the CSV has all of them)


class AnalystDoc(ex.Doc):
    def new_page(self, section):
        if self.page:
            self.footer(); self.c.showPage()
        self.page += 1
        c = self.c
        c.setFillColor(ex.BG); c.rect(0, 0, W, H, stroke=0, fill=1)
        c.saveState(); c.setFillColor(Color(.36, .55, .94, .10)); c.circle(W * .18, H + 40, 260, stroke=0, fill=1)
        c.setFillColor(Color(.96, .7, .29, .06)); c.circle(W * .85, H + 60, 230, stroke=0, fill=1); c.restoreState()
        self.text(M, H - M - 6, "Looking Glass", 13, TXT, True)
        lw = self.c.stringWidth("Looking Glass", self.F["b"], 13)
        self.pill(M + lw + 8, H - M - 5, "ANALYST · " + ("SELECTION" if str(self.meta.get("header", "")).find("LG-A-") >= 0 else "COMBINATION"), AMBER, 7)
        self.text(M, H - M - 20, f"{self.meta['platform_label']} · {self.meta['scope']}", 8.5, DIM)
        self.text(W - M, H - M - 6, section, 11, HexColor("#a9b8ff"), True, "end")
        self.text(W - M, H - M - 20, self.fit(self.meta["header"], 420, 8.5), 8.5, DIM, anchor="end")
        c.setStrokeColor(Color(1, 1, 1, .08)); c.setLineWidth(.6); c.line(M, H - M - 30, W - M, H - M - 30)
        return H - M - 44

    def footer(self):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        who = f" by {self.meta['generated_by']}" if self.meta.get("generated_by") else ""
        self.text(M, 14, f"Contains the addresses of affected devices: share only according to your organisation's information-sharing policy. "
                         f"Generated {now}{who}. Data: Shadowserver Foundation.", 7.2, MUTE)
        self.text(W - M, 14, f"Page {self.page}", 7.2, MUTE, anchor="end")

    # ---------------- parts of this report
    def chips(self, x, y, w, items, size=8.2):
        """The combination's indicators as chips joined with +, wrapping; returns the y below them."""
        c = self.c
        xx, yy = x, y
        if not items:
            self.text(x, y - 9, "the name only (no other indicator)", 8.2, MUTE); return y - 18
        for i, it in enumerate(items):
            t = self.fit(it, w - 20, size, True)
            tw = c.stringWidth(t, self.F["b"], size) + 14
            plus = 12 if i else 0
            if xx + plus + tw > x + w and xx > x:
                xx, yy = x, yy - 20
                plus = 0
            if plus:
                self.text(xx + 3, yy - 9, "+", 8, MUTE); xx += plus
            c.setFillColor(Color(1, 1, 1, .06)); c.setStrokeColor(Color(1, 1, 1, .14)); c.setLineWidth(.6)
            c.roundRect(xx, yy - 14, tw, 16, 5, stroke=1, fill=1)
            self.text(xx + 7, yy - 9, t, size, TXT, True)
            xx += tw + 4
        return yy - 22

    def row_lines(self, cols, w, r):
        """Each cell's lines: text columns wrap (at most three lines), numbers and addresses stay on one."""
        out = []
        for (lbl, f, al, mono), v in zip(cols, r):
            if al == "r" or mono:
                out.append([self.fit(str(v), w * f - 10, 8)])
            else:
                ls = ex.simpleSplit(self.s(str(v)), self.F["r"], 8, w * f - 10) or [""]
                out.append(ls[:3] if len(ls) <= 3 else ls[:2] + [self.fit(" ".join(ls[2:]), w * f - 10, 8)])
        return out

    def table_height(self, cols, w, rows):
        return 14 + sum(max(len(c) for c in self.row_lines(cols, w, r)) * 10 + 5.5 for r in rows)

    def table(self, x, y, w, cols, rows):
        """cols [(label, fraction of w, "l"|"r", mono)]; long text wraps within its column. Returns the y below it."""
        c = self.c
        xs, acc = [], x
        for _, f, _, _ in cols:
            xs.append(acc); acc += w * f
        for (lbl, f, al, _), cx in zip(cols, xs):
            self.text(cx + (w * f - 6 if al == "r" else 4), y - 9, lbl.upper(), 6.8, MUTE, True, "end" if al == "r" else "start")
        c.setStrokeColor(Color(1, 1, 1, .1)); c.setLineWidth(.6); c.line(x, y - 14, x + w, y - 14)
        yy = y - 14
        for i, r in enumerate(rows):
            cells = self.row_lines(cols, w, r)
            rh = max(len(cl) for cl in cells) * 10 + 5.5
            if i % 2:
                c.setFillColor(Color(1, 1, 1, .025)); c.rect(x, yy - rh, w, rh, stroke=0, fill=1)
            for (lbl, f, al, mono), cx, lines in zip(cols, xs, cells):
                for j, t in enumerate(lines):
                    if al == "r":
                        self.text(cx + w * f - 6, yy - 10.5 - 10 * j, t, 8, TXT, False, "end")
                    else:
                        self.text(cx + 4, yy - 10.5 - 10 * j, t, 8, HexColor("#e3e9ff") if mono else HexColor("#d6ddee"), False, "start", mono)
            yy -= rh
        return yy

    def explanation(self, x, y, w, name, x_, stat, comms):
        """As the Executive card, but nothing is cut: the full title and the whole description, wrapped."""
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
        tl = ex.simpleSplit(self.s(title), self.F["b"], 8.6, w - 24) if title and title != name else []
        dl = ex.simpleSplit(self.s(desc), self.F["r"], 8.2, w - 24)
        al = ex.simpleSplit(self.s(alert), self.F["r"], 7.8, w - 36) if alert else []
        sl = ex.simpleSplit(self.s(stat or ""), self.F["r"], 7.6, w - 24) if stat else []
        h = 46 + 11 * len(dl) + 11 * len(tl) + 10 * len(sl) + (20 + 10 * len(al) if al else 0)
        if y is None:
            return h
        self.card(x, y, w, h)
        tx = x + 12
        for t, col in tags:
            tx = self.pill(tx, y - 17, t, col)
        self.text(x + 12, y - 33, name, 10.5, TXT, True)
        yy = y - 45
        for ln in sl:
            self.text(x + 12, yy, ln, 7.6, HexColor("#a9c3ff")); yy -= 10
        for ln in tl:
            self.text(x + 12, yy, ln, 8.6, HexColor("#c9d6ff"), True); yy -= 11
        for ln in dl:
            self.text(x + 12, yy, ln, 8.2, HexColor("#d6ddee")); yy -= 11
        if al:
            yy -= 8
            self.c.setFillColor(Color(.94, .36, .42, .12)); self.c.setStrokeColor(Color(.94, .36, .42, .5))
            self.c.roundRect(x + 10, yy - 10 * (len(al) - 1) - 5, w - 20, 10 * len(al) + 6, 6, stroke=1, fill=1)
            for ln in al:
                self.text(x + 18, yy, ln, 7.8, HexColor("#f6c6cb")); yy -= 10
        return h

    def note_card(self, x, y, w, n, this_code):
        """One researcher's note; returns its height (drawn only when y is given)."""
        body = ex.simpleSplit(self.s(n.get("text", "")), self.F["r"], 8.4, w - 28)
        codes = ", ".join(cc["code"] for cc in n.get("codes") or [])
        cl = ex.simpleSplit(self.s(f"Combinations: {codes}"), self.F["r"], 7.6, w - 28) if codes else []
        who = ex.simpleSplit(self.s(f"Notes shared by {n.get('role') or 'Researcher'}: {n.get('by') or 'a researcher'}"), self.F["b"], 9.4, w - 28)
        h = 40 + 12 * len(who) + 11.5 * len(body) + 10 * len(cl)
        if y is None:
            return h
        on = any(cc["code"] == this_code for cc in n.get("codes") or [])
        self.card(x, y, w, h, tone=BLUE if on else AMBER)
        tx = self.pill(x + 12, y - 17, "Researcher's note", AMBER)
        if on:
            self.pill(tx, y - 17, "On this combination", BLUE)
        self.text(x + w - 14, y - 17, n.get("date") or "", 7.6, MUTE, anchor="end")
        yy = y - 33
        for ln in who:
            self.text(x + 14, yy, ln, 9.4, TXT, True); yy -= 12
        yy -= 1
        for ln in body:
            self.text(x + 14, yy, ln, 8.4, HexColor("#d6ddee")); yy -= 11.5
        for ln in cl:
            self.text(x + 14, yy - 1, ln, 7.6, HexColor("#c5d2ff")); yy -= 10
        return h


def build(d, meta):
    doc = AnalystDoc(meta)
    comms = d["section"] == "infections"
    unit = "Events" if comms else "Records"

    # ---------------- page 1: overview
    y = doc.new_page("Overview")
    is_a = d["code"].startswith("LG-A-")
    doc.text(M, y - 4, (f"ANALYST CODE {d['code']}" if is_a else f"COMBINATION {d['code']} · {d['name']}").upper(), 8, HexColor("#a9b8ff"), True)
    y = doc.wrap(M, y - 22, d["headline"], W - 2 * M - 40, 16, TXT, True, 20, 2) - 2
    # what the combination is: per report, its indicators
    for rep, items in d["parts"]:
        doc.text(M, y - 9, doc.fit(rep, 150, 8.6, True), 8.6, DIM, True)
        y = doc.chips(M + 160, y, W - 2 * M - 160, items) - 2
    y -= 4
    k = d["kpis"]
    tiles = [(fmt(k["devices"]), "Devices", "with exactly this", BLUE),
             (fmt(k["records"]), unit, f"{k['records'] / max(1, k['devices']):.1f} per device", VIOLET),
             (fmt(k["repeat"]), "Repeating it", f"{_share(k['repeat'], k['devices'])} of the devices", AMBER),
             (fmt(k["also"]), "In other reports", "of the same name", RED),
             (fmt(k["regions"]), "Regions", f"{fmt(k['cities'])} cit{'y' if k['cities'] == 1 else 'ies'}", TEAL),
             (fmt(k["networks"]), "Networks", "operators", SLATE)]
    y = doc.kpis(y, tiles)
    cols = [("IP address", .17, "l", True), ("Network", .25, "l", False), ("Region", .16, "l", False), ("City", .14, "l", False),
            (unit, .1, "r", False), ("Last seen (UTC)", .18, "l", True)]
    prev = lambda xs: [[x["ip"], x["network"], x["region"], x["city"], fmt(x["records"]), x["last"]] for x in xs]
    if d.get("hours"):
        hgt = max(150, y - 30)
        cw = (W - 2 * M - 12) * .58
        doc.area(M, y, cw, hgt, d["hours"], d["peak_hour"], unit)
        doc.findings(M + cw + 12, y, W - 2 * M - cw - 12, hgt, d["findings"])
    else:
        # no event times on this platform: the key findings at their own height, the busiest devices beneath
        need = 56 + sum(12 * min(3, len(ex.simpleSplit(doc.s(t), doc.F["r"], 8.8, W - 2 * M - 52))) + 6 for t in d["findings"][:7])
        doc.findings(M, y, W - 2 * M, need, d["findings"])
        y -= need + 12
        if y - 30 > 90 and d["devices"]:
            n = int((y - 30 - 62) // 15.5)
            while n > 1 and 48 + doc.table_height(cols, W - 2 * M - 28, prev(d["devices"][:n])) > y - 30:
                n -= 1
            top = doc.card(M, y, W - 2 * M, min(y - 30, 52 + doc.table_height(cols, W - 2 * M - 28, prev(d["devices"][:n]))), "The busiest devices",
                           f"The {min(n, len(d['devices']))} with the most records; all of them on the next pages and in {d['csv_devices']}")
            doc.table(M + 14, top, W - 2 * M - 28, cols, prev(d["devices"][:n]))

    # ---------------- page 2: where
    y = doc.new_page("Where")
    hh = y - 30
    mw = (W - 2 * M - 12) * .64
    if d.get("shapes"):
        top = doc.card(M, y, mw, hh, "Regions and cities", "Regions coloured by devices (red is most), with each region's cities beside the map")
        doc.region_map(M + 10, top, mw * .56, hh - (y - top) - 12, d["shapes"], d["regions"], d["region_details"], True)
        doc.text(M + mw * .56 + 22, top - 2, "Devices per region and city", 8, DIM, True)
        doc.region_tree(M + mw * .56 + 22, top - 10, mw * .44 - 36, y - hh + 16, d["regions"], d["region_details"], True)
    else:
        top = doc.card(M, y, mw, hh, "Regions and cities", "Devices per region, with its cities")
        doc.region_tree(M + 14, top - 10, mw - 28, y - hh + 16, d["regions"], d["region_details"], True)
    x2, w2 = M + mw + 12, W - 2 * M - mw - 12
    h2 = (hh - 12) / 2
    top = doc.card(x2, y, w2, h2, "Networks", "Devices per network (all of them in the devices CSV)")
    doc.bars(x2 + 14, top, w2 - 28, d["networks"], n=max(1, int((h2 - 56) // 37)), stack=True)
    top = doc.card(x2, y - h2 - 12, w2, h2, "Cities", "Devices per city")
    doc.bars(x2 + 14, top, w2 - 28, d["cities"], n=max(1, int((h2 - 56) // 37)), stack=True)

    # ---------------- page 3 (and 4): the devices
    cols = [("IP address", .13, "l", True), ("Network", .2, "l", False), ("AS", .06, "l", False), ("Region", .11, "l", False),
            ("City", .1, "l", False), (unit, .06, "r", False), ("Days", .05, "r", False), ("Last seen (UTC)", .12, "l", True),
            ("Also seen in", .17, "l", False)]
    devs = d["devices"][:2 * DEVICE_ROWS]
    row = lambda x: [x["ip"], x["network"], x["asn"], x["region"], x["city"], fmt(x["records"]), fmt(x["days"]), x["last"], x["also"] or "–"]
    tw = W - 2 * M - 28
    room = H - M - 44 - 30 - 56                      # the table's height on one page
    pages, cur = [], []
    for x in devs:                                   # as many rows as fit (long cells wrap, so rows differ in height)
        if cur and doc.table_height(cols, tw, [row(r) for r in cur + [x]]) > room:
            pages.append(cur); cur = []
            if len(pages) == 2:
                break
        cur.append(x)
    if cur and len(pages) < 2:
        pages.append(cur)
    pages = pages or [[]]
    shown = sum(len(p) for p in pages)
    for pi, chunk in enumerate(pages):
        y = doc.new_page("The devices")
        top = doc.card(M, y, W - 2 * M, min(y - 30, 56 + doc.table_height(cols, tw, [row(x) for x in chunk])),
                       "The devices with the most records" if pi == 0 else "The devices (continued)",
                       f"{fmt(shown)} of {fmt(d['kpis']['devices'])} shown, the most records first; every device is in {d['csv_devices']}, every record in {d['csv_records']}")
        doc.table(M + 14, top, tw, cols, [row(x) for x in chunk])

    # ---------------- across reports and what the devices are
    y = doc.new_page("Across reports")
    lw = (W - 2 * M - 12) * .6
    hh = y - 30
    top = doc.card(M, y, lw, hh, "Across reports", "What these devices carried in the name's other reports: each exact pattern, with its code to search next")
    yy = doc.hero(M + 14, top, lw - 28, [(fmt(d["across"]["multi"]), "devices also in other reports", HexColor("#a9c3ff")),
                                         (fmt(d["across"]["patterns_total"]), "exact patterns", TXT),
                                         (_share(d["across"]["multi"], k["devices"]), "of the devices", HexColor("#ffd38a"))])
    if not d["across"]["patterns"]:
        doc.wrap(M + 14, yy - 6, ("An analyst code covers the whole selection, with several names: the researchers' view of the code gives each "
                                  "name's cross-report patterns and their codes." if is_a else
                                  "None of these devices was seen in another report of this name in this period."), lw - 28, 8.8, DIM)
    for p in d["across"]["patterns"]:
        if yy < y - hh + 70:
            break
        yy -= 6
        head = f"{fmt(p['devices'])} device{'s' if p['devices'] != 1 else ''}"
        doc.text(M + 14, yy - 10, head, 9.6, TXT, True)
        doc.pill(M + 14 + doc.c.stringWidth(doc.s(head), doc.F["b"], 9.6) + 10, yy - 9.5, p["code"], VIOLET, 7.4)
        yy -= 22
        for part in p["parts"]:
            doc.text(M + 22, yy - 9.5, doc.fit(part["report"], 100, 8, True), 8, DIM, True)
            yy = doc.chips(M + 128, yy, lw - 142, part["items"], 7.6) - 2
        doc.c.setStrokeColor(Color(1, 1, 1, .05)); doc.c.line(M + 14, yy + 2, M + lw - 14, yy + 2)
    x2, w2 = M + lw + 12, W - 2 * M - lw - 12
    h3 = (hh - 24) / 3
    top = doc.card(x2, y, w2, h3, "Reports these devices were seen in", "Devices per set of reports")
    doc.bars(x2 + 14, top, w2 - 28, d["report_sets"], n=max(1, int((h3 - 56) // 47)), stack=True)
    top = doc.card(x2, y - h3 - 12, w2, h3, "What the devices are", f"{unit} per vendor / type, as the reports name them")
    doc.bars(x2 + 14, top, w2 - 28, d["kinds"], metric="count", n=max(1, int((h3 - 56) // 37)), stack=True)
    top = doc.card(x2, y - 2 * (h3 + 12), w2, h3, "Destination ports" if comms else "Ports", f"{unit} per port / protocol")
    doc.bars(x2 + 14, top, w2 - 28, d["ports"], metric="count", n=max(1, int((h3 - 50) // 17)))

    # ---------------- explained: the name and every CVE in the combination, then the researchers' notes
    if d["explained"] or d["notes"]:
        y = doc.new_page("Explained")
        doc.text(M, y - 4, "WHAT THE NAME AND ITS VULNERABILITIES ARE", 8, HexColor("#a9b8ff"), True)
        y -= 14
        col_w, gap = (W - 2 * M - 12) / 2, 12
        cols_y = [y, y]

        def place(height, draw):
            nonlocal cols_y
            ci = 0 if cols_y[0] >= cols_y[1] else 1
            if cols_y[ci] - height < 30:
                if cols_y[1 - ci] - height >= 30:
                    ci = 1 - ci
                else:
                    top_ = doc.new_page("Explained"); cols_y = [top_, top_]; ci = 0
            draw(M + ci * (col_w + gap), cols_y[ci])
            cols_y[ci] -= height + 10
        for name, card in d["explained"]:
            card = {kk: v for kk, v in card.items() if kk != "notes"}          # the notes have their own cards below
            hgt = doc.explanation(0, None, col_w, name, card, d["stats"].get(name), comms)
            place(hgt, lambda x, yy, n=name, c=card: doc.explanation(x, yy, col_w, n, c, d["stats"].get(n), comms))
        for n in d["notes"]:
            hgt = doc.note_card(0, None, col_w, n, d["code"])
            place(hgt, lambda x, yy, n=n: doc.note_card(x, yy, col_w, n, d["code"]))
    return doc.done()
