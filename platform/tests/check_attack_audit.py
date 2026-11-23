#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""ATT&CK suggestions checked against each report's own Shadowserver page (2026-11-23), and how a revised suggestion
reaches mappings already made. No database, no network; temporary folders only.
- the shipped rules: every page-checked rule (id ss-<report>) names one report exactly, comes before the general rules,
  says where it was checked (source = a shadowserver.org report page), lists each technique once, uses only current
  techniques of the local ATT&CK copy (when present), and a "no technique fits" rule suggests none
- corrected general rules: databases are not "data from cloud storage" (T1530), the non-HTTP sinkhole is not web/DNS
- report_impact.json: every per-report flag is in the flag vocabulary
- sync(): a revised suggestion replaces a suggestion, a reviewed mapping goes to "please check" with the new offer and
  the reviewed one kept, a mapping already equal to the new rule is left alone, and confirming a "no technique fits"
  suggestion keeps it that way
Run: .venv/bin/python tests/check_attack_audit.py"""
import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import attack_map  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


D = os.path.join(HERE, "data")
R = json.load(open(os.path.join(D, "attack_rules.json"), encoding="utf-8"))["rules"]
ss = [r for r in R if r["id"].startswith("ss-")]
print("The page-checked rules")
ok("there are page-checked rules", len(ss) >= 80, len(ss))
first_general = next((i for i, r in enumerate(R) if not r["id"].startswith("ss-")), len(R))
ok("…all before the general rules (the first match wins)", all(R.index(r) < first_general for r in ss))
bad_match = [r["id"] for r in ss if r["match"].get("report") != "^" + re.escape(r["id"][3:]) + "$"]
ok("…each names exactly its own report", not bad_match, bad_match[:5])
ok("…each says which Shadowserver page it was checked against",
   all(str(r.get("source", "")).startswith("https://www.shadowserver.org/") for r in ss), [r["id"] for r in ss if not r.get("source")][:5])
ok("…no technique twice in a rule", all(len(r["techniques"]) == len(set(r["techniques"])) for r in R))
nofit = [r for r in ss if r.get("nofit")]
ok("…'no technique fits' rules suggest none, and say why", nofit and all(not r["techniques"] and r.get("why") for r in nofit))
ok("…every other page-checked rule suggests at least one technique, with certainty, role and why",
   all(r["techniques"] and r.get("certainty") in ("observed", "possible") and r.get("role") in ("used", "target", "host", "exposure")
       and r.get("why") for r in ss if not r.get("nofit")))
names_p = os.path.join(D, "names_attack.json")
if os.path.exists(names_p):
    techs = json.load(open(names_p, encoding="utf-8")).get("techniques", {})
    stale = sorted({t for r in R for t in r["techniques"] + r.get("shortlist", []) if (techs.get(t) or {}).get("state") in (None, "revoked", "deprecated")})
    ok("every technique in the rules is current in the local ATT&CK copy", not stale, stale)
else:
    print("  (no local ATT&CK copy here: technique currency checked where it is)")
gen = {r["id"]: r for r in R if not r["id"].startswith("ss-")}
ok("databases: 'data from cloud storage' (T1530) is no longer suggested", "T1530" not in (gen.get("open-database") or {}).get("techniques", [])
   and not any("T1530" in r["techniques"] for r in ss))
ok("the non-HTTP sinkhole is not suggested as web or DNS traffic", (gen.get("sinkhole") or {}).get("techniques") == ["T1095", "T1071"])
ok("blocklist (third-party lists of possibly malicious addresses) gets no technique", any(r["id"] == "ss-blocklist" and r.get("nofit") for r in ss))

print("Impact flags")
imp = json.load(open(os.path.join(D, "report_impact.json"), encoding="utf-8"))
badf = {k: v for k, v in imp["reports"].items() if not v or any(f not in imp["flags"] for f in v)}
ok("every per-report flag is in the vocabulary", not badf, badf)

print("A revised suggestion reaches mappings already made (sync)")
tmp = tempfile.mkdtemp(prefix="lg-attack-audit-")
try:
    rules = {"about": "", "version": 1, "names": [], "rules": [
        {"id": "r-a", "match": {"report": "^alpha$"}, "techniques": ["T1190"], "certainty": "possible", "role": "exposure", "why": "a"},
        {"id": "r-b", "match": {"report": "^beta$"}, "techniques": ["T1110"], "certainty": "possible", "role": "exposure", "why": "b"},
        {"id": "r-c", "match": {"report": "^gamma$"}, "techniques": ["T1133"], "certainty": "possible", "role": "exposure", "why": "c"},
        {"id": "r-d", "match": {"report": "^delta$"}, "techniques": [], "nofit": True, "certainty": "possible", "role": "exposure", "why": "d"}]}
    json.dump(rules, open(os.path.join(tmp, "attack_rules.json"), "w"))
    reports = {k: {"type": "t", "title": k.title(), "section": "s", "group": "g"} for k in ("alpha", "beta", "gamma", "delta")}
    am = attack_map.AttackMap(tmp, None, report_map=lambda: reports, report_defs=lambda: {})
    am.sync()
    d = json.load(open(os.path.join(tmp, "attack_mappings.json")))["reports"]
    ok("new reports: their suggestion, with the rule's fingerprint", d["alpha"]["status"] == "suggested" and d["alpha"].get("rule_sig"))
    ok("a 'no technique fits' rule: a suggestion of no technique", d["delta"]["status"] == "suggested" and d["delta"]["techniques"] == []
       and d["delta"].get("nofit") is True)
    d["beta"].update(status="reviewed", techniques=["T1110"], by="researcher")
    d["gamma"].update(status="reviewed", techniques=["T1021"], by="researcher")
    for k in ("beta", "gamma"):
        d[k].pop("rule_sig", None)                   # mappings made before fingerprints existed
    json.dump({"reports": d}, open(os.path.join(tmp, "attack_mappings.json"), "w"))
    rules["rules"][0]["techniques"] = ["T1133"]       # alpha's suggestion revised
    rules["rules"][2]["techniques"] = ["T1133", "T1190"]   # gamma's too (reviewed differently)
    os.utime(os.path.join(tmp, "attack_rules.json"))
    json.dump(rules, open(os.path.join(tmp, "attack_rules.json"), "w"))
    am2 = attack_map.AttackMap(tmp, None, report_map=lambda: reports, report_defs=lambda: {})
    am2.sync()
    d = json.load(open(os.path.join(tmp, "attack_mappings.json")))["reports"]
    ok("a suggestion takes the revised one", d["alpha"]["status"] == "suggested" and d["alpha"]["techniques"] == ["T1133"])
    ok("a reviewed mapping equal to the rule is left reviewed", d["beta"]["status"] == "reviewed" and d["beta"]["techniques"] == ["T1110"])
    ok("a reviewed mapping that differs goes to 'please check', the new offer attached, the reviewed one kept",
       d["gamma"]["status"] == "check" and d["gamma"]["check_suggest"] == ["T1133", "T1190"]
       and (d["gamma"].get("previous") or {}).get("techniques") == ["T1021"] and "Shadowserver" in d["gamma"].get("check_reason", ""))
    n = am2.sync()
    ok("…and a second sync changes nothing more", n == 0, n)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} ATT&CK audit checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
