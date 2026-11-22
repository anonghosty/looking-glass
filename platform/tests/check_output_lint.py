#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The content checks for every PDF and CSV (tests/output_lint.py; the user, 2026-11-20: "a test to check for every pdf
and csv variation for issues ... so we dont get the errors like mitre again"), no database:
1. each rule catches what it is for, on made-up bad samples (the ATT&CK repetition rebuilt, codes out of order, a
   leftover None, a cut, page numbers skipping, a CSV with a repeated column, a short row, a duplicate, a formula);
   and lets good samples through;
2. every advisory variation, rendered here: designed and plain, each page name, with and without ATT&CK techniques
   (several reports and CVEs on one technique), few and many devices: no problem in any of them.
The release run also gathers every PDF and CSV from the test system and checks them the same way (outputs_gather.py).
Usage: tests/check_output_lint.py"""
import itertools
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
os.environ.setdefault("LG_QUIET", "1")
import output_lint as L  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. Each rule catches what it is for")
tail = "this device was used for it. 14 IP addresses in this advisory have these affected devices (most often: x)."
mitre = "\n".join(f"Looking Glass maps the report “{r}” to this technique: {tail}" for r in ("A events", "B events", "C events"))
for label, pages, want in (
        ("the ATT&CK repetition (the same sentence but for a report's name)", [mitre], "templated"),
        ("mitigation codes out of order", ["How to defend: M1035, M1030, M1042 (MITRE mitigations, below)."], "order"),
        ("technique codes out of order", ["M1035 Limit Access · for T1133, T1021"], "order"),
        ("a value left as None", ["Organisation: None"], "leftover"),
        ("a value left as undefined / nan", ["Devices: undefined, records: nan"], "leftover"),
        ("text cut short", ["Accessible MikroTik Serv…"], "cut"),
        ("page numbers that skip", ["Page 1", "Page 3"], "pages"),
        ("an advisory page without its TLP label", ["TLP:AMBER Page 1", "Page 2"], "tlp")):
    got = L.lint_pdf(pages, tlp="TLP:AMBER" if want == "tlp" else "")
    ok(f"catches {label}", any(want in p for p in got), got[:1])
good = ["Looking Glass maps the 8 reports “A”, “B” and “C” to this technique: x. For each, 14 IP addresses in this advisory have them. Page 1",
        "How to defend: M1030, M1035, M1042. None of the top issues changed. Page 2"]
ok("a good page passes (merged reasons, codes in order, the English 'None of')", not L.lint_pdf(good), L.lint_pdf(good))
bad_csv = 'ip,ports,ip\n192.0.2.1,=cmd|x,1\n192.0.2.1,=cmd|x,1\n192.0.2.2,"T1133, T1021"\n'
c = L.lint_csv(bad_csv)
for want in ("repeated column", "width", "duplicate", "formula", "order"):
    ok(f"CSV: catches {want}", any(want in p for p in c))
good_csv = "ip,ports,note\n192.0.2.1,\"22, 80\",'=SUM(1)\n192.0.2.2,-,-5\n"
ok("CSV: a good one passes (a safe formula, numbers starting with - )", not L.lint_csv(good_csv), L.lint_csv(good_csv))
two = "Day,hosts,records\n2099-01-01,1,2\n\nIssue,2099-01-01,2099-01-02,2099-01-03\nExpired certificate,1,2,3\n"
ok("CSV: two tables after a blank line, each with its own header (the Executive trend) pass", not L.lint_csv(two), L.lint_csv(two))
ok("…a row narrower than its own table's header is still caught",
   any("width" in p for p in L.lint_csv(two + "Exposed panel,1,2\n")))

print("2. Every advisory variation, rendered here")
try:
    import pypdfium2  # noqa: F401
    import advisory_pdf as APDF
    have = True
except ImportError:
    have = False
    print("  SKIPPED: pypdfium2 is not installed - the rendered variations are checked where it is")
if have:
    reps = ["Sinkhole Events", "Sinkhole HTTP Events", "IPv6 Sinkhole Events"]
    techs = [{"id": tid, "name": n, "tactics": ["Command and Control"], "certainty": "observed", "certainty_label": "Observed",
              "status": "reviewed", "desc": "Adversaries may communicate using an application layer protocol.",
              "why_here": f"Looking Glass maps the report “{r}” to this technique: {tail}", "url": "https://attack.mitre.org/techniques/T1071/",
              "defend": [{"id": "M1037", "name": "Filter Network Traffic", "text": "Filter traffic."}, {"id": "M1031", "name": "Network Intrusion Prevention", "text": "Use signatures."}]}
             for tid, n in (("T1071.004", "DNS"), ("T1071.001", "Web Protocols")) for r in reps]
    bad = []
    n = 0
    for look, brand, attack, many in itertools.product(("designed", "plain"), ("Looking Glass", "Example CSIRT", ""), (False, True), (False, True)):
        devs = [{"ip": f"192.0.2.{i}", "hostname": "", "ports": ["8291", "443"], "reports": ["Accessible MikroTik Service", "Device Identification"],
                 "infections": ["example-bot"], "last": "2099-01-01 10:00", "earlier": []} for i in range(60 if many else 3)]
        adv = {"logo": None, "title": "Example CSIRT Security Advisory", "subject": "Example", "ref": "ADV-2099-9", "tlp": "TLP:AMBER",
               "tlp_colour": "#FFC000", "tlp_short": "Limited", "tlp_text": "Its organisation and clients.", "network": "Example Telecom",
               "reports": [{"title": "Accessible MikroTik Service", "url": "https://www.shadowserver.org/"}], "devices": devs,
               "description": "A made-up description of what was seen.", "actions": "1. Close the service.\n2. Clean the devices.",
               "header": "TLP:AMBER · ADV-2099-9 · Example Telecom", "labels": [], "kinds_line": "", "recipients": ["Example Telecom"],
               "impact": [], "look": look, "brand": brand, "attack": {"version": "18.1", "techniques": techs} if attack else {}}
        pdf = APDF.alone(adv, {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2099-01-01", "generated_by": "t"})
        n += 1
        bad += [(look, brand or "no name", attack, many, p) for p in L.lint_pdf(L.pdf_pages(pdf), tlp="TLP:AMBER")]
    ok(f"{n} advisory variations (look x page name x ATT&CK x devices): no content problem", not bad, bad[:3])

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
