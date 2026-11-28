#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Every page of PDFs, checked as a reader sees them (the user, 2026-11-18: "tests always to be done"): text drawn over
other text, the "…" cut-off, and text beyond the page's edge; and, per PDF, no MITRE ATT&CK technique or mitigation
listed twice (a rule, 2026-11-19). Renders with pypdfium2: without it in .venv the file runs itself again with
~/lg-shots/venv's Python when that is there; with neither the check is skipped (exit 77, SKIPPED) so an install
without it still runs the rest of the suite.
    python tests/pdf_pages_check.py               made-up advisory and Executive pages, built here
    python tests/pdf_pages_check.py a.pdf b.pdf   those files (the release flow: every kind of PDF from a test system)
Exit 1 when a page has a problem."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
try:
    import pypdfium2 as pdfium
except ImportError:
    # not in .venv: run again with the screenshot tools' Python, which has it, and the platform's libraries beside it
    # (as tests/check_cut_lists_data.py does), so the suite runs the check here instead of skipping it (2026-11-26)
    shots = os.path.expanduser("~/lg-shots/venv/bin/python")
    if os.path.exists(shots) and not os.environ.get("LG_PDF_REEXEC"):
        import glob
        site = glob.glob(os.path.join(ROOT, ".venv", "lib", "python3*", "site-packages"))
        env = dict(os.environ, LG_PDF_REEXEC="1", PYTHONPATH=os.pathsep.join(site + [os.environ.get("PYTHONPATH", "")]))
        os.execve(shots, [shots, os.path.abspath(__file__)] + sys.argv[1:], env)
    print("SKIPPED: pypdfium2 is not installed (pip install pypdfium2) - the PDF layout check runs where it is")
    sys.exit(77)

sys.path.insert(0, ROOT)


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


# "0%", "0.0%": a share of a part that has records (a change "+0.0%" / "-0.0%" is not a share)
ZERO = re.compile(r"(?<![\d.,<>+\-±])0(?:\.0+)? ?%")
OF = re.compile(r"\b(\d[\d,]*) of (\d[\d,]*)\b")
CONT = re.compile(r"\bof [\d,]+ shown\b|\(continued\)|continued from", re.I)    # a table's note repeated on its next page


def content_problems(pdf):
    """What the PDF SAYS (the user, 2026-11-26: "are they what they are, are there duplicate definitions, MITRE
    attacks, nothing missed"): no share reads "0%" (a part listed has records: "<1%"; shares.pct), no "N of M" with N
    above M, no definition, paragraph or MITRE ATT&CK line printed twice. Lines on most pages (the running head, the
    footer with its page number, the watermark), a table's header repeated on its next page and a source line under
    each item are not paragraphs."""
    pages = [pdf[i].get_textpage().get_text_range().splitlines() for i in range(len(pdf))]
    norm = lambda s: " ".join(s.split())
    shape = lambda s: re.sub(r"\d+", "#", s)
    on_pages = {}
    for i, lines in enumerate(pages):
        for ln in {shape(norm(x)) for x in lines}:
            on_pages.setdefault(ln, set()).add(i)
    running = {ln for ln, ps in on_pages.items() if len(pages) > 1 and len(ps) >= max(2, len(pages) // 2)}
    probs, seen = [], {}
    for i, lines in enumerate(pages):
        lines = [norm(x) for x in lines]
        facts = False      # inside an item's facts line ("In this selection: N records ... CVSS ... EPSS ..."): two CVEs
        prev = ""          # with the same counts and scores read alike, and that is data, not a repeated paragraph
        for j, ln in enumerate(lines):
            if not ln or shape(ln) in running:
                continue
            nxt = next((x for x in lines[j + 1:] if x), "")
            before, prev = prev, ln
            if ln.startswith("In this selection:") or facts:
                facts = not ln.endswith(".")
                continue
            if ": the same as for " in ln:     # a pointer to a line printed once above (reports_pdf.Once), not a repeat
                continue
            for m in ZERO.finditer(ln):
                probs.append(f"page {i + 1}: a share reads {m.group(0)!r}: {ln[:90]!r}")
            for a, b in OF.findall(ln):
                if int(a.replace(",", "")) > int(b.replace(",", "")):
                    probs.append(f"page {i + 1}: '{a} of {b}' (more shown than there are): {ln[:90]!r}")
            words = ln.split()
            header = not re.search(r"[.,:;]", ln) and sum(w[:1].isupper() for w in words) >= .6 * len(words)
            # a paragraph's line: long and made of words (not a table header, not one device's row, not a source line)
            if (len(ln) >= 70 and len(words) >= 10 and not header and not CONT.search(ln)
                    and not ln.startswith(("Source:", "(Source:")) and not re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", ln)):
                # counted as itself when it names an ATT&CK technique or ends a sentence; otherwise with the line after
                # it (two items whose wrapped first lines only start alike are not a repeat)
                # the end of a sentence wrapped from a long line above: that line was counted together with this one
                # (two CVEs of one product end their "Actively exploited" sentence alike, 2026-11-27)
                if ln.endswith(".") and not TID.search(ln) and len(before) >= 70 and not re.search(r"[.:;!?)]$", before):
                    continue
                key = ln if (TID.search(ln) or ln.endswith(".")) else (ln + " / " + nxt)
                seen.setdefault(key, []).append(i + 1)
    probs += [f"printed {len(p)} times (pages {p}): {ln[:90]!r}" for ln, p in seen.items() if len(p) > 1]
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
                       "level": lvl, "text": f"What impact {i} can lead to, in words long enough to wrap over several lines, part " + ", part ".join(map(str, range(9))) + ".",
                       "reports": [f"Report number {i}.{j} with a long name" for j in range(12)]}
                      for i, lvl in enumerate(["critical", "high", "medium", "low"])],
           "kinds_line": "", "recipients": [],
           # the same technique from several reports (the user's 2026-11-19 case): printed once, its mitigations once
           "attack": {"version": "18.1", "techniques": [
               {"id": tid, "name": nm, "tactics": ["Command and Control"], "certainty": "observed", "certainty_label": "Observed",
                "status": "reviewed", "report": rep, "desc": f"Adversaries may communicate using {nm} as an application layer protocol.",
                "why_here": f"Looking Glass maps the report “{rep}” to {nm}.", "url": "https://attack.mitre.org/techniques/T1071/",
                "defend": [{"id": "M1031", "name": "Network Intrusion Prevention", "text": "Use network signatures."}]}
               for tid, nm in (("T1071.001", "Web Protocols"), ("T1071.004", "DNS"))
               for rep in ("Sinkhole Events", "Sinkhole DNS Events", "IPv6 Sinkhole Events")]}}
    out = [("made-up advisory", APDF.alone(adv, {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s",
                                                  "day": "2026-11-16", "generated_by": "t"}))]
    d = EXP.Doc({"platform_label": "Services", "scope": "s", "selection": "s", "day": "2026-11-17", "cities": [], "tz": None, "generated_by": "t"})
    y = d.new_page("Top issues")
    rows = [{"value": f"CVE-2023-4879{i}", "title": f"Issue {i}: " + " ".join(f"The SSH transport protocol with certain OpenSSH extensions ({i}.{k})" for k in range(1 + i % 3)),
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
    said = content_problems(pdf)
    if said:
        bad += 1
        print(f"  FAIL {name}: what it says ({len(said)}): " + "; ".join(said[:8]))
    for i in range(len(pdf)):
        pages += 1
        pr = page_problems(pdf[i])
        if pr:
            bad += 1
            print(f"  FAIL {name} page {i + 1}: " + "; ".join(pr))
print(f"{pages - bad}/{pages} pages clean in {len(docs)} PDF(s)")
sys.exit(1 if bad else 0)
