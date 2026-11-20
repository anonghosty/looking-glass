#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The advisory PDF's options and contents (the user, 2026-11-19), on a made-up advisory (documentation addresses,
made-up names), no database:
1. References list every report the advisory names: its own, the ones its devices were also seen in (Device
   Identification was named in the advisory but missing from References);
1b. Add insights: the advisory alone, or with the analysis pages;
2. the pipeline's confirmation command has a Copy button that records the copy (Settings → Workers);
3. the advisory PDF's look (designed or plain white) and the name at the top of its pages (Settings → Organisation).
Usage: tests/check_advisory_options.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def pdf_text(data):
    try:
        import pypdfium2 as pdfium
    except ImportError:
        return None
    pdf = pdfium.PdfDocument(data)
    return "\n".join(pdf[i].get_textpage().get_text_range() for i in range(len(pdf)))


print("1. References: every report the advisory names")
import advisory_pdf as APDF  # noqa: E402
MT = "https://www.shadowserver.org/what-we-do/network-reporting/accessible-mikrotik-report/"
devs = [{"ip": f"192.0.2.{i}", "hostname": "", "ports": ["2000"], "reports": ["Accessible MikroTik Service", "Device Identification"],
         "infections": ["example-bot"], "last": "2099-01-01 10:00", "earlier": []} for i in range(3)]
adv = {"logo": None, "title": "Example CSIRT Security Advisory", "subject": "Example", "ref": "ADV-T", "tlp": "TLP:AMBER",
       "network": "Example Telecom", "reports": [{"title": "Accessible MikroTik Service", "url": MT}],
       "devices": devs, "description": "d", "actions": "a", "header": "h", "labels": [], "impact": [], "kinds_line": "", "recipients": []}
meta = {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2099-01-01", "generated_by": "t"}
import pdf_refs  # noqa: E402
drawn = []
real_draw = pdf_refs.draw
pdf_refs.draw = lambda doc, gs, intro, title="References": (drawn.append(gs), real_draw(doc, gs, intro, title))[1]
pdf = APDF.alone(adv, meta)
pdf_refs.draw = real_draw
items = [it for gs in drawn for g in gs if g.get("kind") == "reports" for it in g.get("items") or []]
titles = [it.get("title") for it in items]
ok("a report the devices were also seen in is listed (Device Identification)", "Device Identification" in titles, str(titles))
ok("…marked as such", any("the devices were also seen in this report" in (it.get("where") or "") for it in items if it.get("title") == "Device Identification"))
ok("…the advisory's own report is listed once", titles.count("Accessible MikroTik Service") == 1, str(titles))
ok("the advisory still renders", pdf[:4] == b"%PDF")
text = pdf_text(pdf)
if text is not None:                          # where a PDF reader is installed: the words on the page too
    ok("…and the page shows it", "Device Identification" in text[text.rfind("References"):])
src = open(os.path.join(HERE, "advisory_pdf.py"), encoding="utf-8").read()
ok("references() takes the other reports the pages name (also=) and the devices' reports",
   "def references(doc, a, cards=(), levels=None, also=())" in src and 'dv.get("reports")' in src)
csrc = open(os.path.join(HERE, "combo_pdf.py"), encoding="utf-8").read()
ok("the advisory with its report passes the package's reports (ref_reports)", 'also=d.get("ref_reports") or []' in csrc)

print("1b. Add insights: the advisory alone, or with the analysis pages (the user, 2026-11-19)")
import advisory as ADV  # noqa: E402
base = {"heading": "h", "subject": "s", "tlp": "TLP:AMBER", "description": "d", "actions": "a"}
ok("an advisory saved before the option keeps its fingerprint (its generated report stays current)",
   ADV.content_sig(dict(base)) == ADV.content_sig(dict(base)) and "insights" not in base)
ok("…turning the insights on or off makes the generated report out of date",
   ADV.content_sig(dict(base, insights=True)) != ADV.content_sig(dict(base, insights=False)))
asrc = open(os.path.join(HERE, "advisory.py"), encoding="utf-8").read()
ok("a new advisory starts without the insights (the user's choice)", '"insights": False}' in asrc)
ok("an advisory saved before the option keeps them", 'return bool(adv.get("insights", True))' in asrc)
ok("the choice is saved, and a change is in the advisory's history", 'adv["insights"] = bool(b.get("insights"))' in asrc
   and '"insights added" if adv["insights"] else "insights left out"' in asrc)
lines = csrc.split("\n")
i_if = next((i for i, ln in enumerate(lines) if ln.startswith("    if insights:")), -1)
i_p1 = next((i for i, ln in enumerate(lines) if "page 1: overview" in ln), -1)
i_ex = next((i for i, ln in enumerate(lines) if "---------------- explained" in ln), -1)
ok("the PDF: the insights pages (Overview .. Across reports) only when added", 0 < i_if < i_p1
   and lines[i_p1].startswith("        #") and 'insights = not adv or bool(adv.get("insights", True))' in csrc)
ok("…the Technical Details and References always stay (outside that block)", i_ex > i_p1 and lines[i_ex].startswith("    #"))
ok("…'See below for further insight' only when the insights follow", 'a.get("has_report") and a.get("insights", True)' in src)
js_adv = os.path.join(S_ := os.environ.get("LG_HELD_DIR", ""), "advisory.js.new") if os.environ.get("LG_HELD_DIR") \
    and os.path.exists(os.path.join(os.environ["LG_HELD_DIR"], "advisory.js.new")) else os.path.join(HERE, "static", "js", "advisory.js")
ajs = open(js_adv, encoding="utf-8").read()
ok("the advisory page: an Add insights checkbox, saved with the advisory", 'el("b", null, "Add insights")' in ajs and "insights: ins.checked" in ajs)

print("2. Settings → Workers: the confirmation command's Copy button")
S = os.environ.get("LG_HELD_DIR", "")
js_path = os.path.join(S, "pipeline-settings.js.new") if S and os.path.exists(os.path.join(S, "pipeline-settings.js.new")) \
    else os.path.join(HERE, "static", "js", "pipeline-settings.js")
js = open(js_path, encoding="utf-8").read()
ok("a Copy button beside the command", 'el("button", "pill-btn wk-copy", "Copy")' in js)
ok("…copying through the recorded path (LGCopy, audited), never straight to the clipboard",
   "window.LGCopy.copy({ text: r.confirm" in js and "navigator.clipboard" not in js)

print("3. The advisory PDF's look and the name on its pages (Settings → Organisation, the user 2026-11-19)")
import tempfile  # noqa: E402
import organisation as ORG  # noqa: E402
import combo_pdf as CP  # noqa: E402
from reportlab.lib.colors import Color, HexColor  # noqa: E402
with tempfile.TemporaryDirectory() as tmp:
    o = ORG.Organisation(os.path.join(tmp, "organisation.json"))
    g0 = o.get()
    ok("unset: today's look and Looking Glass at the top (nothing changes until an admin chooses)",
       g0["pdf_look"] == "designed" and g0["pdf_brand"] == "looking-glass" and o.brand_text() == "Looking Glass")
    o.save("Example CSIRT", None, "plain", "organisation")
    ok("plain + the organisation's name saved", o.get()["pdf_look"] == "plain" and o.brand_text() == "Example CSIRT")
    o.save("Example CSIRT", None, None, "none")
    ok("…no name: blank, and the look kept when not given", o.brand_text() == "" and o.get()["pdf_look"] == "plain")
    o.save("Example CSIRT", None, "pink", "everything")
    ok("…an unknown choice is ignored (the stored one stays)", o.get()["pdf_look"] == "plain" and o.get()["pdf_brand"] == "none")
osrc = open(os.path.join(HERE, "organisation.py"), encoding="utf-8").read()
ok("the API refuses an unknown look or name (400) and audits a change",
   'look not in LOOKS' in osrc and 'brand not in BRANDS' in osrc and 'advisory look: ' in osrc)


def lum(c):
    return CP._luminance(float(c.red), float(c.green), float(c.blue))


ok("plain: the dark page turns white", lum(CP._light(HexColor("#0b1020"))) > .9)
ok("…light text turns dark", lum(CP._light(HexColor("#e8ecf6"))) < .1)
ok("…a bright accent (amber) is darkened until it reads on white (4.5:1)", lum(CP._light(HexColor("#FFC000"))) <= .183)
ok("…transparency kept", abs(CP._light(Color(1, 1, 1, .08)).alpha - .08) < 1e-6)
for look, brand in (("plain", "Example CSIRT"), ("designed", "")):
    p = APDF.alone(dict(adv, look=look, brand=brand), meta)
    ok(f"{look} look, name {brand or 'none'}: renders", p[:4] == b"%PDF")
    t = pdf_text(p)
    if t is not None:
        ok(f"…the name at the top is {brand or 'left out'}", (brand in t) if brand else ("Looking Glass" not in t), "")
ok("the TLP label keeps its black box and colour on any look (raw)", "self._raw = True" in csrc and "def tlp_mark" in csrc)
ok("the logo's white card stays white on the plain look", "doc._raw = True" in src)
S = os.environ.get("LG_HELD_DIR", "")
pick = lambda name, live: os.path.join(S, name + ".new") if S and os.path.exists(os.path.join(S, name + ".new")) else live  # noqa: E731
ojs = open(pick("organisation.js", os.path.join(HERE, "static", "js", "organisation.js")), encoding="utf-8").read()
shtml = open(pick("settings.html", os.path.join(HERE, "templates", "settings.html")), encoding="utf-8").read()
ok("Settings → Organisation: the two choices, saved with the organisation",
   'id="orgPdfLook"' in shtml and 'id="orgPdfBrand"' in shtml and "body.pdf_look" in ojs and "body.pdf_brand" in ojs)

print("4. MITRE ATT&CK: each technique once (the user, 2026-11-19: the advisory repeated them)")
mk = lambda tid, cert, why, **k: dict({"id": tid, "name": "Exploit Public-Facing Application" if tid == "T1190" else "External Remote Services",  # noqa: E731
                                       "tactics": ["Initial Access"], "certainty": cert, "certainty_label": cert.capitalize(), "status": "reviewed",
                                       "desc": "Adversaries may exploit a weakness.", "why_here": why, "url": f"https://attack.mitre.org/techniques/{tid}/",
                                       "defend": [{"id": "M1050", "name": "Exploit Protection"}]}, **k)
techs = [mk("T1190", "possible", "Looking Glass maps the report A to this technique.", report="A"),
         mk("T1190", "possible", "Looking Glass maps the report B to this technique.", report="B"),
         mk("T1190", "observed", "MITRE CTID maps CVE-2099-0001 to this technique.", cve="CVE-2099-0001", kind="how attackers exploit it",
            comment="Fixture comment.", defend=[{"id": "M1050", "name": "Exploit Protection"}, {"id": "M1016", "name": "Vulnerability Scanning"}]),
         mk("T1190", "possible", "Looking Glass maps the report A to this technique.", report="A", category="c"),
         mk("T1133", "possible", "Looking Glass maps the report A to this technique.", report="A")]
g = APDF.group_techniques(techs)
ok("one entry per technique, in code order (2026-11-20)", [x["id"] for x in g] == ["T1133", "T1190"], str([x["id"] for x in g]))
g90 = next(x for x in g if x["id"] == "T1190")
ok("…every distinct reason kept, each once", len(g90["whys"]) == 3, g90["whys"])
ok("…the strongest certainty (Observed before Possible)", g90["certainty"] == "observed")
ok("…the CVE's CTID comment and the mitigations, each once, in code order", g90["comments"] == [("CVE-2099-0001", "Fixture comment.")]
   and [m["id"] for m in g90["defend"]] == ["M1016", "M1050"])
heads = []
real_pc = APDF.Flow.para_cert
APDF.Flow.para_cert = lambda self, head, *a, **k: (heads.append(head), real_pc(self, head, *a, **k))[1]
try:
    pdf = APDF.alone(dict(adv, attack={"version": "18.1", "techniques": techs}), meta)
finally:
    APDF.Flow.para_cert = real_pc
t1190 = [h for h in heads if h.startswith("T1190 ")]
ok("the advisory PDF prints T1190 once (it was printed for each report and CVE)", len(t1190) == 1 and pdf[:4] == b"%PDF", str(heads))
mits = APDF.group_mitigations(g)
ok("the mitigations grouped by code, in code order: each once, with the techniques it defends against",
   [m["id"] for m in mits] == ["M1016", "M1050"] and mits[1]["techs"] == ["T1133", "T1190"] and mits[0]["techs"] == ["T1190"], str(mits))
paras = []
real_para = APDF.Flow.para
APDF.Flow.para = lambda self, s, *a, **k: (paras.append(s), real_para(self, s, *a, **k))[1]
try:
    APDF.alone(dict(adv, attack={"version": "18.1", "techniques": techs}), meta)
finally:
    APDF.Flow.para = real_para
ok("…printed in one section after the techniques, M1050 once",
   sum(1 for s in paras if s.startswith("M1050 Exploit Protection")) == 1
   and not any(s.startswith("• M1050") for s in paras), str([s for s in paras if "M1050" in s]))
import attack_map as AM  # noqa: E402
lines = AM.attack_lines({"version": "18.1", "techniques": [dict(techs[0], certainty_label="Possible"), dict(techs[0], certainty_label="Possible")]})
ok("the plain-text lines (Technical Details, CSV) list a technique once", lines and lines[0].count("T1190") == 1, str(lines))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
