"""Content checks for every PDF and CSV Looking Glass makes (the user, 2026-11-20: "a test to check for every pdf and csv
variation for issues ... so we dont get the errors like mitre again"). The layout check (tests/pdf_pages_check.py)
looks at how pages are drawn; this reads what they say.

PDF (the text of each page):
  templated     3+ sentences on one page the same but for a quoted name or a number (the ATT&CK repetition)
  order         a list of codes (T1071.001, M1031, CVE-2024-1234) not in code order
  leftover      None / nan / undefined / null / [object Object] / {'… / a Python or JS value left in the text
  cut           "…" (text cut short)
  pages         "Page n" numbers that skip or repeat
  tlp           an advisory page without its TLP label (when tlp= is given)
CSV:
  header        no header, an empty or repeated column name
  width         a row with a different number of cells than the header
  duplicate     the same row twice
  leftover      as above, in a cell
  formula       a cell starting with = + - @ (or a tab / CR) that is not made spreadsheet-safe (a leading ')
  order         a cell listing codes, not in code order

lint_pdf(pages: [str], tlp="") -> [problem]; lint_csv(text) -> [problem]; problems are short strings.
CLI: python output_lint.py FILE... (PDF, CSV or ZIP: every PDF and CSV inside); exit 1 on a problem.
"""
import csv
import io
import re
import sys
import zipfile

CODE = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|M\d{4}|CVE-\d{4}-\d{4,7})\b")
LIST = re.compile(r"(?:\b(?:T\d{4}(?:\.\d{3})?|M\d{4}|CVE-\d{4}-\d{4,7})\b(?:\s*(?:,|and)\s*)){1,}\b(?:T\d{4}(?:\.\d{3})?|M\d{4}|CVE-\d{4}-\d{4,7})\b")
# a value left in the text: "None" only where a value stands (after ": ", alone, before , ; ) ]), not the English
# "None of the top issues"; nan / undefined / null / [object Object] / a Python dict / an escaped character anywhere
LEFTOVER = re.compile(r"(?:(?<=:\s)|(?<=\()|(?<=^))None\b|\bNone(?=\s*[,;)\]]|\s*$)|(?<![\w./-])(?:nan|NaN|undefined|null)(?![\w./-])"
                      r"|\[object Object\]|<built-in|Traceback \(most|\{'[a-z_]+':|\\u[0-9a-f]{4}", re.M)
TECH = re.compile(r"\b(?:T\d{4}(?:\.\d{3})?|M\d{4})\b")       # code order is checked for ATT&CK codes (CVE lists are ranked)
SENT = re.compile(r"[^.!?\n]{60,}[.!?]")
PAGE_NO = re.compile(r"\bPage (\d+)\b")
SAFE_FORMULA = re.compile(r"^([+-]?\d+([.,]\d+)*%?|-+)$")      # a number or dashes may start with + or -


def code_key(c):
    m = re.match(r"^(T|M)(\d+)(?:\.(\d+))?$", c)
    if m:
        return (m.group(1), int(m.group(2)), int(m.group(3) or 0))
    m = re.match(r"^CVE-(\d{4})-(\d+)$", c)
    return ("CVE", int(m.group(1)), int(m.group(2))) if m else ("~", 0, 0)


def _lists(text):
    """The comma / 'and' separated lists of codes in a text."""
    for m in LIST.finditer(text):
        codes = TECH.findall(m.group(0))
        kinds = {code_key(c)[0] for c in codes}
        if len(codes) > 1 and len(kinds) == 1:
            yield codes


def _shape(s):
    """A sentence with its quoted names and numbers taken out: the same shape = the same sentence but for a name."""
    s = re.sub(r"“[^”]*”|\"[^\"]*\"|'[^']*'", "“·”", s)
    s = re.sub(r"\b(?:T\d{4}(?:\.\d{3})?|M\d{4}|CVE-\d{4}-\d{4,7})\b", "#", s)
    return re.sub(r"\d+", "#", s).strip()


def lint_pdf(pages, tlp="", log=False):
    """log=True for a PDF of log rows (the audit evidence): two identical rows can be two events."""
    out = []
    nums = []
    for i, t in enumerate(pages, 1):
        flat = re.sub(r"\s+", " ", t)
        sents = [s.strip() for s in SENT.findall(flat)]
        # (no "same line twice" rule: two cards side by side are read line by line in turn, so two different paragraphs'
        # wrapped endings look like one line twice; tried on the release PDFs 2026-11-20 and dropped)
        # the ATT&CK repetition: 3+ sentences naming a quoted thing, the same but for that name
        shapes = {}
        for s in set(sents):
            if "“" in s:
                shapes.setdefault(_shape(s), []).append(s)
        out += [f"page {i}: templated ({len(v)} sentences the same but for a name): {v[0][:90]}" for v in shapes.values() if len(v) >= 3]
        for codes in _lists(flat):
            if codes != sorted(codes, key=code_key):
                out.append(f"page {i}: order: {', '.join(codes)[:90]}")
        for m in LEFTOVER.finditer(flat):
            out.append(f"page {i}: leftover {m.group(0)!r}: …{flat[max(0, m.start() - 40):m.end() + 20]}…")
        if "…" in t:
            out.append(f"page {i}: cut (…)")
        pn = PAGE_NO.findall(t)
        if pn:
            nums.append(int(pn[-1]))
        if tlp and tlp not in t:
            out.append(f"page {i}: tlp: no {tlp} label")
    if nums and nums != list(range(nums[0], nums[0] + len(nums))):
        out.append(f"pages: numbers {nums[:12]}")
    return out


def lint_csv(text):
    out = []
    rows = list(csv.reader(io.StringIO(text.lstrip("﻿"))))
    if not rows:
        return ["header: empty file"]
    head, seen = None, set()
    # a file may hold several tables, each after a blank line with its own header (the Executive trend: the day's
    # figures, then one row per issue over the 7 days)
    for n, r in enumerate(rows, 1):
        if not r or not any(c.strip() for c in r):
            head = None
            continue
        if head is None:
            head = r
            if any(not h.strip() for h in head):
                out.append(f"row {n}: a header with an empty column name: {head[:8]}")
            dup = sorted({h for h in head if head.count(h) > 1})
            if dup:
                out.append(f"row {n}: a header with repeated column names {dup}")
            continue
        if len(r) != len(head):
            out.append(f"row {n}: width {len(r)} cells, the header has {len(head)}")
        key = tuple(r)
        if key in seen:
            out.append(f"row {n}: duplicate of an earlier row")
        seen.add(key)
        for c, v in enumerate(r):
            col = head[c] if c < len(head) else f"#{c + 1}"
            if LEFTOVER.search(v):
                out.append(f"row {n} {col}: leftover {LEFTOVER.search(v).group(0)!r}")
            if v[:1] in ("=", "+", "-", "@", "\t", "\r") and not SAFE_FORMULA.match(v):
                out.append(f"row {n} {col}: formula: starts with {v[:1]!r} and is not made safe")
            if "…" in v:
                out.append(f"row {n} {col}: cut (…)")
            for codes in _lists(v):
                if codes != sorted(codes, key=code_key):
                    out.append(f"row {n} {col}: order: {', '.join(codes)[:80]}")
    return out


def pdf_pages(data):
    import pypdfium2 as pdfium
    d = pdfium.PdfDocument(data)
    return [d[i].get_textpage().get_text_range() for i in range(len(d))]


def lint_file(name, data, tlp=""):
    """[(name, problem)] for a PDF, a CSV or every PDF / CSV inside a ZIP."""
    low = name.lower()
    if low.endswith(".zip") or data[:2] == b"PK":
        z = zipfile.ZipFile(io.BytesIO(data))
        return [x for n in z.namelist() if n.lower().endswith((".pdf", ".csv")) for x in lint_file(f"{name}/{n}", z.read(n), tlp)]
    if data[:4] == b"%PDF":
        return [(name, p) for p in lint_pdf(pdf_pages(data), tlp, log="audit" in low)]
    if low.endswith(".csv"):
        return [(name, p) for p in lint_csv(data.decode("utf-8", "replace"))]
    return []


if __name__ == "__main__":
    bad = []
    for f in sys.argv[1:]:
        bad += lint_file(f, open(f, "rb").read())
    for n, p in bad[:200]:
        print(f"  FAIL {n}: {p}")
    print(f"{len(sys.argv) - 1} file(s), {len(bad)} problem(s)")
    sys.exit(1 if bad else 0)
