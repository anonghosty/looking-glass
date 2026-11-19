#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""CVE and issue codes in "In every other category", and what a cross-report pattern's devices carry (the user,
2026-11-19: a researcher could not move a CVE or an issue to notes; each "Combinations across reports" card should say
which CVEs, issues and infections its devices carry). On made-up devices (documentation addresses), no database:
1. per report a CVE / issue was found in, a code for exactly the devices carrying it there; a group under MIN_HOSTS gets
   no lasting code for a viewer who does not see hosts, and one when the viewer does; the codes are registered (on_codes);
2. the code resolves to exactly those devices' records in that report (services_intel.Matcher), not the others, nor the
   same devices' records in another report; its description reads in words (combos.describe);
3. carried(): names and counts per group, most carried first, CVEs from tags counted too, never an address;
4. the infection / issue pages: a pattern's device set is taken out before the answer leaves (intel.py).
Usage: tests/check_issue_codes.py"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import services_intel as SI  # noqa: E402
import small_codes  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


REP, OTHER = "scan_example_service", "scan_example_other"
ips = [f"192.0.2.{n}" for n in range(1, 11)]                 # documentation addresses (RFC 5737)
CVE, SMALL = "CVE-2099-0101", "Expired certificate"
host_issues = {}
for ip in ips[:6]:                                           # 6 devices carry the CVE in REP
    host_issues.setdefault(ip, {})[CVE] = {REP}
for ip in ips[6:9]:                                          # 3 carry an issue in REP (below MIN_HOSTS)
    host_issues.setdefault(ip, {})[SMALL] = {REP}
host_issues[ips[9]] = {CVE: {OTHER}}                         # one carries the CVE in the other report only
data = {"hosts": {REP: set(ips[:9]), OTHER: {ips[0], ips[9]}}, "showable": {REP: set(), OTHER: set()},
        "combo_hosts": {REP: {(): {ip: 1 for ip in ips[:9]}}, OTHER: {(): {ips[0]: 1, ips[9]: 1}}},
        "host_issues": host_issues, "host_cves": {ips[1]: {"CVE-2099-0202"}},
        "infected": {ips[0]: {"example-bot"}, ips[1]: {"example-bot"}, ips[2]: {"other-bot"}},
        "sink_rep": {}, "host_reports": {ip: {REP} for ip in ips[:9]}, "host_items": {}, "host_levels": {}, "days": ["2099-01-01"]}
data["host_reports"][ips[0]] = {REP, OTHER}
data["host_reports"][ips[9]] = {OTHER}

shown = []
si = SI.ServicesIntel({"on_codes": lambda section, name, report, combos: shown.append((section, name, report, combos))})
si.index = lambda scope=None, load=True: data

print("1. a code per report a CVE / issue was found in")
small_codes.viewer_sees_hosts = lambda: False                # a researcher (no hosts)
x = si.for_hosts(set(ips), hold_small=True)
by = {i["name"]: i for i in x["issues"]}
cve_rep = {r["report"]: r for r in by[CVE]["reports"]}
ok("the CVE has a code for its 6 devices in the report", cve_rep[REP]["hosts"] == 6 and str(cve_rep[REP]["code"]).startswith("LG-X-"), cve_rep[REP])
ok("and one row for the other report (1 device): no lasting code there", cve_rep[OTHER]["hosts"] == 1 and cve_rep[OTHER]["code"] is None)
ok("an issue on 3 devices: no lasting code for a viewer without hosts", by[SMALL]["reports"][0]["code"] is None)
ok("the code is the shared rule's (issue_code)", cve_rep[REP]["code"] == SI.ServicesIntel.issue_code(REP, CVE))
reg = [c for s, n, r, cs in shown for c in cs if any(p[0] == SI.ISSUE for p in c)]
ok("the shown code is registered for the analysts (on_codes)", [[(REP, []), (SI.ISSUE, [f"Issue: {CVE}"])]] == reg, reg)
small_codes.viewer_sees_hosts = lambda: True                 # a viewer who sees hosts: every code
y = si.for_hosts(set(ips), hold_small=True)
ok("a viewer who sees hosts gets the small group's code", {i["name"]: i for i in y["issues"]}[SMALL]["reports"][0]["code"] is not None)
ok("no address in the answer for a researcher", not any(ip in json.dumps(x) for ip in ips))

print("2. the code resolves to exactly those devices")
entry = {"kind": "x", "section": "services", "name": REP, "parts": [[REP, []], [SI.ISSUE, [f"Issue: {CVE}"]]]}
m = SI.Matcher(si, entry)
events = [{"ip": ip, "report": REP} for ip in ips] + [{"ip": ip, "report": OTHER} for ip in (ips[0], ips[9])]
got = m.match(events)
ok("the 6 devices' records in the report", sorted(e["ip"] for e in got) == sorted(ips[:6]) and all(e["report"] == REP for e in got), len(got))
ok("not the device carrying it in another report only", ips[9] not in {e["ip"] for e in got})
ok("the code's reports leave out the part that is not a report", m.reports == {REP})
ok("what a device carried instead, in words", m.issues_in(ips[6], REP) == [SMALL] and m.issues_in(ips[0], OTHER) == [])
try:
    import combos  # noqa: E402
    combos._TITLE["of"] = lambda n: {REP: "Example Service"}.get(n, n)
    ok("the code's description", combos.describe(entry) == f"Example Service: hosts carrying {CVE} there", combos.describe(entry))
except ImportError as exc:
    ok("combos importable", False, exc)

print("3. what a pattern's devices carry")
c = si.carried(ips[:3])
ok("CVEs with how many devices (tags too)", c["cves"]["names"] == [{"name": CVE, "hosts": 3}, {"name": "CVE-2099-0202", "hosts": 1}], c["cves"])
ok("infections, most carried first", c["infections"]["names"] == [{"name": "example-bot", "hosts": 2}, {"name": "other-bot", "hosts": 1}], c["infections"])
ok("no issue on these: none", c["issues"] == {"names": [], "total": 0})
ok("names and counts only, never an address", not any(ip in json.dumps(c) for ip in ips))
many = si.carried(ips[:9], top=1)
ok("a cap with the total kept", len(many["cves"]["names"]) == 1 and many["issues"]["total"] == 1)

print("4. the infection / issue pages")
src = open(os.path.join(HERE, "intel.py"), encoding="utf-8").read()
ok("the pattern's device set is taken out before the answer leaves", 'x.pop("_hosts", None)' in src and '"carries"' in src)
ok("only the 12 shown patterns keep a device set", "c.most_common(12)" in src)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
