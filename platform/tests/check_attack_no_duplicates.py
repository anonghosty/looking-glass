#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""RULE (the user, 2026-11-19): a MITRE ATT&CK technique or mitigation is never listed twice, anywhere. "Duplicates
need to be checked and guarded": the same technique from several reports, categories or CVEs is one entry with every
reason; each mitigation is once, grouped by its code. Checked on made-up mappings, no database, wherever techniques are
listed: the advisory PDF (and its guard), the names' cards (Technical Details, Executive, services, management), the
plain-text lines (PDFs, CSV), the Executive's tactic view and short IDs, and the advisory page.
Usage: tests/check_attack_no_duplicates.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
import advisory_pdf as APDF  # noqa: E402
import attack_map as AM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def tech(tid, report="", cert="observed", **k):
    return dict({"id": tid, "name": {"T1071.001": "Web Protocols", "T1071.004": "DNS"}.get(tid, "Technique"),
                 "tactics": ["Command and Control"], "certainty": cert, "certainty_label": cert.capitalize(), "status": "reviewed",
                 "desc": "Adversaries may communicate using an application layer protocol.", "report": report,
                 "why_here": f"Looking Glass maps the report “{report}” to this technique.", "why": f"Seen in {report}.",
                 "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
                 "defend": [{"id": "M1031", "name": "Network Intrusion Prevention", "text": "Use network signatures."},
                            {"id": "M1037", "name": "Filter Network Traffic", "text": "Filter DNS requests." if tid == "T1071.004" else "Restrict outbound web traffic."}]}, **k)


# the case the user found (2026-11-19): Sinkhole Events, Sinkhole HTTP Referer, IPv6 Sinkhole, Sinkhole DNS Events
TECHS = [tech("T1071.001", "Sinkhole HTTP Referer Events"), tech("T1071.001", "IPv6 Sinkhole Events"),
         tech("T1071.001", "Sinkhole Events"), tech("T1071.004", "Sinkhole Events"), tech("T1071.004", "Sinkhole DNS Events"),
         tech("T1071.004", "Sinkhole DNS Events", category="m0yv")]

print("1. The advisory PDF")
groups = APDF.group_techniques(TECHS)
mits = APDF.group_mitigations(groups)
ok("each technique once", [g["id"] for g in groups] == ["T1071.001", "T1071.004"], str([g["id"] for g in groups]))
ok("…with every report's reason, each once", len(groups[0]["whys"]) == 3 and len(groups[1]["whys"]) == 2)
ok("each mitigation once, grouped and in code order", [m["id"] for m in mits] == ["M1031", "M1037"]
   and mits[0]["techs"] == ["T1071.001", "T1071.004"], str(mits))
ok("…MITRE's different words per technique both kept (M1037: web, DNS)", len(mits[1]["texts"]) == 2)
try:
    APDF.assert_no_duplicates(groups, mits)
    ok("the guard lets the merged list through", True)
except APDF.DuplicateAttack as e:
    ok("the guard lets the merged list through", False, str(e))
for bad, label in (([groups[0], groups[0]], "a technique twice"),
                   ([dict(groups[0], defend=groups[0]["defend"] * 2)], "a mitigation twice inside one technique")):
    try:
        APDF.assert_no_duplicates(bad, [])
        ok(f"the guard refuses {label}", False)
    except APDF.DuplicateAttack:
        ok(f"the guard refuses {label}", True)
try:
    APDF.assert_no_duplicates(groups, mits + mits[:1])
    ok("the guard refuses a mitigation listed twice", False)
except APDF.DuplicateAttack:
    ok("the guard refuses a mitigation listed twice", True)
heads, paras = [], []
real_pc, real_p = APDF.Flow.para_cert, APDF.Flow.para
APDF.Flow.para_cert = lambda self, h, *a, **k: (heads.append(h), real_pc(self, h, *a, **k))[1]
APDF.Flow.para = lambda self, s, *a, **k: (paras.append(s), real_p(self, s, *a, **k))[1]
adv = {"logo": None, "title": "Example CSIRT Security Advisory", "subject": "s", "ref": "ADV-T", "tlp": "TLP:AMBER", "network": "Example Telecom",
       "reports": [], "devices": [], "description": "d", "actions": "a", "header": "h", "labels": [], "impact": [], "kinds_line": "", "recipients": [],
       "attack": {"version": "18.1", "techniques": TECHS}}
meta = {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2099-01-01", "generated_by": "t"}
try:
    pdf = APDF.alone(adv, meta)
finally:
    APDF.Flow.para_cert, APDF.Flow.para = real_pc, real_p
ok("the PDF: each technique heading once", sorted(h.split(" ")[0] for h in heads) == ["T1071.001", "T1071.004"] and pdf[:4] == b"%PDF", str(heads))
ok("the PDF: each mitigation once, in its own section", [s.split(" ")[0] for s in paras if s.startswith(("M1031 ", "M1037 "))] == ["M1031", "M1037"]
   and not any(s.startswith("• M10") for s in paras))
asrc = open(os.path.join(HERE, "advisory.py"), encoding="utf-8").read()
ok("generating the report stops with a message if the guard ever fires", "except advisory_pdf.DuplicateAttack as e:" in asrc)

print("2. Names' cards (Technical Details, Executive, services, management) and the text lines")
merged = AM.merge_by_id([dict(t, report=t["report"]) for t in TECHS])
ok("a card's techniques: each once, every report named", [t["id"] for t in merged] == ["T1071.001", "T1071.004"]
   and merged[0]["reports"] == ["Sinkhole HTTP Referer Events", "IPv6 Sinkhole Events", "Sinkhole Events"], str(merged[0].get("reports")))
ok("…its mitigations once", [m["id"] for m in merged[0]["defend"]] == ["M1031", "M1037"])
ok("…the strongest certainty kept", AM.merge_by_id([tech("T1", cert="possible"), tech("T1", cert="observed")])[0]["certainty"] == "observed")
msrc = open(os.path.join(HERE, "attack_map.py"), encoding="utf-8").read()
ok("card_attack (every card's ATT&CK) merges them", '"techniques": merge_by_id(items) + merge_by_id(known)' in msrc)
att = {"version": "18.1", "techniques": TECHS}
lines = AM.attack_lines(att)
ok("plain-text lines (PDF cards, CSV): each technique once", lines and lines[0].count("T1071.001") == 1 and lines[0].count("T1071.004") == 1, str(lines))
ok("short IDs (CSV cells, Executive card): each once", AM.ids_text(att).count("T1071.001") == 1)
bt = AM.by_tactic(att)
ok("the Executive's tactic view: each once", [t["id"] for t in bt["Command and Control"]] == ["T1071.001", "T1071.004"])

print("3. The advisory page")
S = os.environ.get("LG_HELD_DIR", "")
p = os.path.join(S, "advisory.js.new") if S and os.path.exists(os.path.join(S, "advisory.js.new")) else os.path.join(HERE, "static", "js", "advisory.js")
js = open(p, encoding="utf-8").read()
ok("what goes to the recipients: one box per technique (mergeOut), every reason listed",
   "for (const t of mergeOut(A.techniques))" in js and "function mergeOut(list)" in js and "t.whys?.length > 1" in js)
ok("…each mapping keeps its own Undo", "for (const p of parts)" in js and "key: p.key, action: \"restore\"" in js)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
