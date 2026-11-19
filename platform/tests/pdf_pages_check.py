#!/usr/bin/env python3
"""Every page of PDFs, checked as a reader sees them (the user, 2026-11-18: "tests always to be done"): text drawn over
other text, the "…" cut-off, and text beyond the page's edge; and, per PDF, no MITRE ATT&CK technique or mitigation
listed twice (a rule, 2026-11-19). Renders with pypdfium2; without it the check is skipped
(exit 77, SKIPPED) so an install without it still runs the rest of the suite.
    python tests/pdf_pages_check.py               made-up advisory and Executive pages, built here
    python tests/pdf_pages_check.py a.pdf b.pdf   those files (the release flow: every kind of PDF from a test system)
Exit 1 when a page has a problem."""
import os
import sys

try:
    import pypdfium2 as pdfium
except ImportError:
    print("SKIPPED: pypdfium2 is not installed (pip install pypdfium2) - the PDF layout check runs where it is")
    sys.exit(77)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def page_problems(page):
    W, H = page.get_size()
    tp = page.get_textpage()
    boxes, probs = [], []
    for i in range(tp.count_chars()):
        ch = tp.get_text_range(i, 1)
        if not ch.strip():
            continue
        l, b, r, t = tp.get_charbox(i)
        if r - l < .5 or t - b < .5:
            continue
        boxes.append((i, ch, l, b, r, t))
    if "…" in tp.get_text_range():
        probs.append("'…' on the page")
    off = sum(1 for _, _, l, b, r, t in boxes if l < -1 or r > W + 1 or b < -1 or t > H + 1)
    if off:
        probs.append(f"{off} characters beyond the page edge")
    boxes.sort(key=lambda x: x[2])
    hits = []
    for a in range(len(boxes)):
        ia, ca, la, ba, ra, ta = boxes[a]
        for bb in range(a + 1, len(boxes)):
            ib, cb, lb, b2, rb, tb = boxes[bb]
            if lb >= ra:
                break
            if abs(ia - ib) <= 2:                       # neighbours in the text: kerning, not an overlap
                continue
            w = min(ra, rb) - max(la, lb)
            h = min(ta, tb) - max(ba, b2)
            if w > 0 and h > 0 and w * h > .35 * min((ra - la) * (ta - ba), (rb - lb) * (tb - b2)):
                hits.append((round(la), round(H - ta), ca + cb))
    if hits:
        probs.append(f"{len(hits)} characters drawn over others, e.g. at {hits[:3]}")
    return probs


import re  # noqa: E402

HEAD = re.compile(r"^\s*((?:T\d{4}(?:\.\d{3})?)|(?:M\d{4})) \S.* · ")       # a technique's / a mitigation's title line
TID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def attack_duplicates(pdf):
    """RULE (the user, 2026-11-19: "duplicates need to be checked and guarded"): in one PDF, a MITRE ATT&CK technique
    or mitigation has its title line once, and no line names the same technique twice."""
    heads, probs = {}, []
    for i in range(len(pdf)):
        for line in pdf[i].get_textpage().get_text_range().splitlines():
            m = HEAD.match(line)
            if m:
                heads.setdefault(m.group(1), []).append(i + 1)
            ids = TID.findall(line)
            twice = sorted({t for t in ids if ids.count(t) > 1})
            if twice:
                probs.append(f"page {i + 1}: {', '.join(twice)} twice on one line")
    probs += [f"{k} listed {len(p)} times (pages {p})" for k, p in heads.items() if len(p) > 1]
    return probs


def made_up():
    """A made-up advisory with long names, many report chips and long Other days; the Executive top list and an
    Explained card with long texts. Returns [(name, pdf bytes)]."""
    import advisory_pdf as APDF
    import executive_pdf as EXP
    long_ = ("2026-11-15: changed: in Accessible MikroTik Service with Tag: iot + Tag: mikrotik + Tag: mikrotik-btest; calls sinkholes "
             "as android.vo1d2, avalanche-andromeda; 2026-11-17: changed: no sinkhole call")
    devs = [{"ip": f"192.0.2.{i}", "hostname": "very-long-hostname-without-spaces.example-telecom.example" if i == 3 else "",
             "ports": ["2000"], "reports": ["Accessible MikroTik Service"], "infections": ["android.vo1d2", "avalanche-andromeda", "m0yv"],
             "last": "2026-11-16 10:00", "earlier": [long_]} for i in range(8)]
    adv = {"logo": None, "title": "Example CSIRT Security Advisory", "subject": "Void 2 Detected: " + "MikroTik routers calling sinkholes " * 3,
           "ref": "ADV-T", "tlp": "TLP:AMBER", "network": "Example Telecom", "reports": [{"title": f"Report number {i} with a long name",
           "url": f"https://www.example.org/report-{i}/"} for i in range(30)], "devices": devs, "description": "d", "actions": "a",
           "header": "h", "labels": [],
           # the Impact section (advisory_pdf.draw_impact, shared with the analysts' PDF): long texts and many reports wrap
           "impact": [{"flag": f"f{i}", "label": f"Example impact {i}: remote code execution on an exposed management service",
                       "level": lvl, "text": "What this can lead to, in words long enough to wrap over several lines. " * 4,
                       "reports": [f"Report number {j} with a long name" for j in range(12)]}
                      for i, lvl in enumerate(["critical", "high", "medium", "low"])],
           "kinds_line": "", "recipients": [],
           # the same technique from several reports (the user's 2026-11-19 case): printed once, its mitigations once
           "attack": {"version": "18.1", "techniques": [
               {"id": tid, "name": nm, "tactics": ["Command and Control"], "certainty": "observed", "certainty_label": "Observed",
                "status": "reviewed", "report": rep, "desc": "Adversaries may communicate using an application layer protocol.",
                "why_here": f"Looking Glass maps the report “{rep}” to this technique.", "url": "https://attack.mitre.org/techniques/T1071/",
                "defend": [{"id": "M1031", "name": "Network Intrusion Prevention", "text": "Use network signatures."}]}
               for tid, nm in (("T1071.001", "Web Protocols"), ("T1071.004", "DNS"))
               for rep in ("Sinkhole Events", "Sinkhole DNS Events", "IPv6 Sinkhole Events")]}}
    out = [("made-up advisory", APDF.alone(adv, {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s",
                                                  "day": "2026-11-16", "generated_by": "t"}))]
    d = EXP.Doc({"platform_label": "Services", "scope": "s", "selection": "s", "day": "2026-11-17", "cities": [], "tz": None, "generated_by": "t"})
    y = d.new_page("Top issues")
    rows = [{"value": f"CVE-2023-4879{i}", "title": "The SSH transport protocol with certain OpenSSH extensions " * (1 + i % 3),
             "hosts": 200 - i, "count": 200 - i, "cve": True, "cvss": 5.9, "epss": .9, "exploited": i % 2 == 0} for i in range(12)]
    d.ranking(EXP.M + 14, y - 40, 470, rows, False, max_rows=13, bottom=38)
    d.bars(560, y - 40, 230, [{"label": "Accessible GPRS Tunneling Protocol (GTP)", "hosts": 900}, {"label": "Accessible SSH", "hosts": 800}], n=8, bottom=40)
    y = d.new_page("Explained")
    d.explanation(EXP.M, y - 20, 380, "android.midnight-mimosa", {"curated": True, "title": "Midnight Mimosa",
                  "description": "A long description of what this family does. " * 12}, "130 devices", True)
    out.append(("made-up Executive pages", d.done()))
    return out


files = sys.argv[1:]
docs = [(os.path.basename(f), open(f, "rb").read()) for f in files] if files else made_up()
bad = 0
pages = 0
for name, data in docs:
    pdf = pdfium.PdfDocument(data)
    dup = attack_duplicates(pdf)
    if dup:
        bad += 1
        print(f"  FAIL {name}: MITRE ATT&CK shown twice: " + "; ".join(dup[:6]))
    for i in range(len(pdf)):
        pages += 1
        pr = page_problems(pdf[i])
        if pr:
            bad += 1
            print(f"  FAIL {name} page {i + 1}: " + "; ".join(pr))
print(f"{pages - bad}/{pages} pages clean in {len(docs)} PDF(s)")
sys.exit(1 if bad else 0)
