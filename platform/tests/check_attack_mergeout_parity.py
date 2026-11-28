#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What goes to the recipients: one box per ATT&CK technique, on the advisory page (advisory.js mergeOut) exactly as in
the PDF (advisory_pdf.group_techniques). node runs the page's own mergeOut (the held copy $LG_HELD_DIR/advisory.js.new
when there is one) on a made-up mapping and Python runs group_techniques on the same one; the two must agree on every
technique: its name, link, description and tactics (taken from a later mapping when the first lacks them), the strongest
certainty, every reason once (reasons that differ only in a name merged into one sentence), each CTID comment and note
once, the mitigations once and in code order, and the techniques in code order.
Run: .venv/bin/python tests/check_attack_mergeout_parity.py"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import page_harness as H  # noqa: E402
from advisory_pdf import group_techniques  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info and not cond else ""))


if not H.NODE:
    print("SKIPPED: no node to run the page with"); sys.exit(77)

M = lambda i, n: {"id": i, "name": n, "url": f"https://attack.mitre.org/mitigations/{i}/"}       # noqa: E731
RDP = "Looking Glass maps the report “Accessible RDP” to this technique: the service answers on the internet. 12 IP addresses are in this advisory."
SMB = "Looking Glass maps the report “Accessible SMB” to this technique: the service answers on the internet. 12 IP addresses are in this advisory."
CVE1 = "MITRE CTID maps CVE-2023-11111 to this technique (exploitation technique): a made-up flaw. 2 IP addresses are in this advisory."
CVE2 = "MITRE CTID maps CVE-2024-22222 to this technique (exploitation technique): a made-up flaw. 2 IP addresses are in this advisory."
URL = "https://attack.mitre.org/techniques/"
TECHS = [
    {"key": "k1", "id": "T1190", "name": "Exploit Public-Facing Application", "url": URL + "T1190/", "desc": "Made-up description.",
     "tactics": ["Initial Access"], "certainty": "possible", "certainty_label": "Possible (made up)", "why_here": RDP,
     "defend": [M("M1035", "Limit Access"), M("M1030", "Segmentation")]},
    {"key": "k2", "id": "T1190", "name": "Exploit Public-Facing Application", "url": URL + "T1190/", "desc": "Made-up description.",
     "tactics": ["Initial Access"], "certainty": "observed", "certainty_label": "Observed (made up)", "why_here": SMB,
     "defend": [M("M1030", "Segmentation"), M("M1051", "Update Software")]},
    {"key": "k3", "id": "T1190", "certainty": "known", "certainty_label": "Known (made up)", "why_here": CVE1, "cve": "CVE-2023-11111",
     "comment": "A made-up CTID comment.", "defend": [M("M1016", "Vulnerability Scanning")]},
    {"key": "k4", "id": "T1190", "certainty": "known", "why_here": CVE2, "cve": "CVE-2024-22222", "comment": "A made-up CTID comment."},
    {"key": "k5", "id": "T1190", "why_here": RDP, "note": "Seen in version 17 (made up)."},
    # a first mapping without MITRE's name, link, text or tactics (not in the local ATT&CK copy yet): a later one has them
    {"key": "k6", "id": "T1071.004", "name": "", "url": "", "desc": "", "tactics": [], "certainty": "possible", "why_here": "Made-up reason one."},
    {"key": "k7", "id": "T1071.004", "name": "DNS", "url": URL + "T1071/004/", "desc": "Made-up DNS text.", "tactics": ["Command and Control"],
     "certainty": "possible", "why_here": "Made-up reason two.", "note": "A made-up note."},
    {"key": "k8", "id": "T1021", "name": "Remote Services", "url": URL + "T1021/", "tactics": ["Lateral Movement"], "certainty": "observed",
     "why_here": "Made-up reason.", "defend": [M("M1042", "Disable or Remove Feature"), M("M1032", "Multi-factor Authentication")]},
    {"key": "k9", "id": "T1071.001", "name": "Web Protocols", "url": URL + "T1071/001/", "certainty": "unknown-level", "why_here": "Another."},
    {"key": "k10", "id": "T1133", "name": "External Remote Services", "url": URL + "T1133/", "certainty": "possible", "why_here": "Made-up."},
]
FIELDS = ("id", "name", "url", "desc", "tactics", "certainty", "certainty_label", "whys", "comments", "notes")


def norm(g):
    out = {k: g.get(k) or ([] if k in ("tactics", "whys", "comments", "notes") else "") for k in FIELDS}
    out["comments"] = [list(c) for c in out["comments"]]
    out["defend"] = [m.get("id") for m in g.get("defend") or []]
    return out


src = H.page_src("advisory.js")
js = H.extract(src, ["CERT_RANK", "WHY_FORMS", "count", "names", "each", "codeKey", "codeCmp", "mergeWhys", "mergeOut"]) + r"""
const out = mergeOut(JSON.parse(process.argv[1]));
console.log(JSON.stringify(out.map((g) => ({ ...g, parts: g.parts.map((p) => p.key) }))));
"""
got, raw = H.run(js, TECHS)
want = [norm(g) for g in group_techniques(json.loads(json.dumps(TECHS)))]
ok("the page's mergeOut runs", isinstance(got, list), raw[-400:])
got = got or []
js_n = [norm(g) for g in got]
ok("one box per technique, in code order (T1021, T1071.001, T1071.004, T1133, T1190)",
   [g["id"] for g in js_n] == ["T1021", "T1071.001", "T1071.004", "T1133", "T1190"], [g["id"] for g in js_n])
ok("...the same techniques as the PDF", [g["id"] for g in js_n] == [g["id"] for g in want], f"{[g['id'] for g in js_n]} {[g['id'] for g in want]}")
by_js, by_py = {g["id"]: g for g in js_n}, {g["id"]: g for g in want}
for tid in [g["id"] for g in want]:
    a, b = by_js.get(tid) or {}, by_py[tid]
    diff = {k: (a.get(k), b[k]) for k in b if a.get(k) != b[k]}
    ok(f"{tid}: the page's box is the PDF's (name, link, text, tactics, certainty, reasons, comments, notes, mitigations)", not diff, diff)
t = by_py["T1190"]
ok("T1190: the strongest certainty (Observed before Possible and Known)", t["certainty"] == "observed")
ok("...the two report reasons in one sentence, the two CVE reasons in another, nothing twice", len(t["whys"]) == 2
   and t["whys"][0].startswith("Looking Glass maps the 2 reports “Accessible RDP” and “Accessible SMB”")
   and "For each, " in t["whys"][0] and t["whys"][1].startswith("MITRE CTID maps CVE-2023-11111 and CVE-2024-22222"), t["whys"])
ok("...each CTID comment once per CVE, the mitigations once and in code order", t["comments"] == [["CVE-2023-11111", "A made-up CTID comment."],
   ["CVE-2024-22222", "A made-up CTID comment."]] and t["defend"] == ["M1016", "M1030", "M1035", "M1051"], t)
d = by_js.get("T1071.004") or {}
ok("T1071.004 on the page: MITRE's name, link, text and tactics from the mapping that has them", d.get("name") == "DNS"
   and d.get("url") == URL + "T1071/004/" and d.get("desc") == "Made-up DNS text." and d.get("tactics") == ["Command and Control"], d)
ok("...every mapping kept under its box for Undo", [g.get("parts") for g in got if g.get("id") == "T1190"] == [["k1", "k2", "k3", "k4", "k5"]],
   [g.get("parts") for g in got if g.get("id") == "T1190"])
ok("...the mitigations of T1021 in code order", (by_js.get("T1021") or {}).get("defend") == ["M1032", "M1042"])

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
