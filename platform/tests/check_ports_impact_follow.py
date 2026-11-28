#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Three asks of 2026-11-19, on made-up data in scratch folders (no database, nothing of this installation changed):
1. every port an address was seen open on, with the service, for the devices CSVs (services_intel.ports_text via
   host_flags; combos.py's all_ports_and_services column, also for a review kept before the ports were kept);
2. a researcher who answers an analyst's request follows it: the review / case the analyst sends to management on the
   researcher's code takes the researcher into its channel (seeing it, not holding it) and is linked to the request;
   a researcher who did not answer is not added; a researcher's own finding on the code still comes first;
3. the Impact section of the analysts' PDF: advisory.Impact.summary / of_names (one rule with the advisory), drawn by
   advisory_pdf.draw_impact (shared), placed by combo_pdf.py, fed by combos.py.
Usage: tests/check_ports_impact_follow.py"""
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import advisory  # noqa: E402
import findings as F  # noqa: E402
import services_intel as SI  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. every port per address, with the service")
si = SI.ServicesIntel({})
si.title_of = lambda r: {"scan_ssh": "Accessible SSH", "scan_ssl": "Accessible SSL", "scan_http_vulnerable": "Vulnerable HTTP"}.get(r, r)
ip = "192.0.2.10"                                            # a documentation address
data = {"host_ports": {ip: {"443/tcp": {"scan_ssl", "scan_http_vulnerable"}, "22/tcp": {"scan_ssh"}, "8443/tcp": {"scan_ssl"}, "161/udp": {"scan_snmp"}}},
        "host_issues": {}, "host_cves": {}, "infected": {}, "host_levels": {}}
txt = si.ports_text(data, ip)
ok("lowest port first, each with its services", txt == "22/tcp Accessible SSH; 161/udp scan_snmp; 443/tcp Accessible SSL, Vulnerable HTTP; 8443/tcp Accessible SSL", txt)
ok("an address with no open port: empty", si.ports_text(data, "192.0.2.99") == "")
si.index = lambda scope=None, load=True: data
ok("host_flags carries them (the devices table's one source)", si.host_flags([ip])[ip]["ports"] == txt)
src = open(os.path.join(HERE, "services_intel.py"), encoding="utf-8").read()
ok("the index records every record's port and protocol", 'host_ports[ip][f"{port}/{proto}" if proto else str(port)].add(base)' in src)
csrc = open(os.path.join(HERE, "combos.py"), encoding="utf-8").read()
ok("the devices CSV has the column, beside the selection's own ports", '"ports", "all_ports_and_services"' in csrc and 'd["flags"].get("ports") or ""' in csrc)
# 2026-11-26: the same step now also fills in a review's severities (levels, kept since 18 Nov); what it does is RUN by
# tests/check_ports_index_old_review.py on a made-up old review
ok("a review kept before the ports were kept gets them worked out",
   'missing = {h for h, v in kept_here.items() if "ports" not in v or "levels" not in v}' in csrc)
ok("the advisory's text names the column's content", "it was seen open on with the service running there" in open(os.path.join(HERE, "advisory_pdf.py"), encoding="utf-8").read())

print("2. a researcher who answered follows it")


class People:
    def name(self, u, default=""):
        return u or default


with tempfile.TemporaryDirectory() as tmp:
    f = F.Findings(os.path.join(tmp, "findings.json"), People())
    req = f.create_analyst("LG-A-00000001", "services", "Analyst selection", "Look", "t", "ana", "analyst", to="res")
    f.reply(req["id"], "Found this", ["LG-X-00000002"], "res", "researcher")
    other = f.create_analyst("LG-A-00000003", "services", "Another", "Look", "t", "ana", "analyst", to="res2")
    rv = f.create_review("LG-X-00000002", "services", "x", "Review", "t", "ana", "analyst", "man", {"codes": [], "source": "LG-X-00000002"})
    ok("the researcher who answered is in the review's channel", "res" in rv["participants"], rv["participants"])
    ok("…seeing it, not holding it (it is with the manager)", rv["assignee"] == "man" and rv["status"] == "management")
    ok("a researcher who did not answer is not added", "res2" not in rv["participants"])
    res_open = [x["id"] for x in f.list(True, user="res", admin=False, strict=True)]
    ok("the researcher's Findings page shows the request and the review", {req["id"], rv["id"]} <= set(res_open), res_open)
    ok("the review is linked to the request it came from", f.request_links(list(f.data["items"].values())).get(rv["id"]) == req["id"])
    case, kids = f.create_case("LG-X-00000002", "services", "x", "Case", "t", "ana", "analyst", "man", [("Example Org A", {"codes": []}), ("Example Org B", {"codes": []})])
    ok("a case on the code too, and each of its sub-findings", "res" in case["participants"] and all("res" in k["participants"] for k in kids))
    # a researcher's own finding on the same code comes first in the links
    g = F.Findings(os.path.join(tmp, "g.json"), People())
    own = g.create({"id": "n1", "codes": ["LG-X-0000000A"], "text": "t"}, "services", "x", "Mine", "res2", "researcher", to="man", kind="management")
    req2 = g.create_analyst("LG-A-0000000B", "services", "Sel", "Look", "t", "ana", "analyst", to="res")
    g.reply(req2["id"], "Same pattern", ["LG-X-0000000A"], "res", "researcher")
    rv2 = g.create_review("LG-X-0000000A", "services", "x", "Review", "t", "ana", "analyst", "man", {"codes": [], "source": "LG-X-0000000A"})
    ok("a researcher's own finding on the code still comes first in the links", g.request_links(list(g.data["items"].values())).get(rv2["id"]) == own["id"])
    ok("…and the researcher who answered still follows the review", "res" in rv2["participants"])
    # the external review of 15dc30a: only THE answer counts (the reply that sent the request back, by a researcher)
    h = F.Findings(os.path.join(tmp, "h.json"), People())
    rq = h.create_analyst("LG-A-0000000C", "services", "Sel", "Look", "t", "ana", "analyst", to="res")
    h.reply(rq["id"], "my answer", ["LG-X-0000000D"], "res", "researcher")                    # the answer: counts
    h.reply(rq["id"], "later, more codes", ["LG-X-0000000E"], "res", "researcher")           # a second reply: does not
    h.data["items"][rq["id"]]["participants"].append("ana2")
    h.reply(rq["id"], "someone else in the channel", ["LG-X-0000000F"], "ana2", "analyst")  # not the answer: does not
    rv_d = h.create_review("LG-X-0000000D", "services", "x", "R", "t", "ana", "analyst", "man", {"codes": []})
    rv_e = h.create_review("LG-X-0000000E", "services", "x", "R", "t", "ana", "analyst", "man", {"codes": []})
    rv_f = h.create_review("LG-X-0000000F", "services", "x", "R", "t", "ana", "analyst", "man", {"codes": []})
    ok("only the researcher's answer makes a follower", "res" in rv_d["participants"], rv_d["participants"])
    ok("…a later reply with other codes does not", "res" not in rv_e["participants"], rv_e["participants"])
    ok("…nor anyone else in the channel attaching codes", "ana2" not in rv_f["participants"], rv_f["participants"])
    links = h.request_links(list(h.data["items"].values()))
    ok("…and only the answer's codes link a review to the request", links.get(rv_d["id"]) == rq["id"]
       and rv_e["id"] not in links and rv_f["id"] not in links, str(links))
    shown = json.dumps(f.list(False, user="res", admin=False, strict=True))
    ok("nothing on the researcher's page holds an address", "192.0.2." not in shown and "sent" not in json.dumps([x.get("review") for x in f.list(False, user="res", admin=False, strict=True)]))

print("3. Impact in the analysts' PDF")
with tempfile.TemporaryDirectory() as base:
    os.makedirs(os.path.join(base, "data"))
    json.dump({"flags": {"rce": {"label": "Remote code execution", "level": "critical", "text": "An attacker can run code."},
                         "info": {"label": "Information disclosure", "level": "medium", "text": "Data can leak."}},
               "reports": {"scan_http_vulnerable": ["info", "rce"], "scan_ssh": ["info"]}, "groups": {}},
              open(os.path.join(base, "data", "report_impact.json"), "w"))
    json.dump({"reports": {"scan_http_vulnerable": {"title": "Vulnerable HTTP", "section": "Vulnerable"},
                           "scan_ssh": {"title": "Accessible SSH", "section": "Services"}}},
              open(os.path.join(base, "data", "report_map_snapshot.json"), "w"))
    imp = advisory.Impact(base)
    got = imp.of_names(["Vulnerable HTTP", "scan_ssh", "Not a report"])
    ok("by the reports' titles or names, the most severe first", [x["flag"] for x in got] == ["rce", "info"], [x["flag"] for x in got])
    ok("each flag with the reports carrying it", got[1]["reports"] == ["Vulnerable HTTP", "Accessible SSH"], got[1]["reports"])
    reports, impact = imp.summary({"scan_ssh": ({"title": "Accessible SSH"}, None)})
    ok("the advisory's rule is the same function", impact[0]["flag"] == "info" and reports[0]["flags"] == ["info"])
asrc = open(os.path.join(HERE, "advisory.py"), encoding="utf-8").read()
ok("the advisory builds its impact with it (no second copy)", "imp.summary(reps" in asrc and asrc.count("by_flag.setdefault") == 1)
psrc = open(os.path.join(HERE, "advisory_pdf.py"), encoding="utf-8").read()
ok("one drawing for both PDFs", psrc.count('f.heading("Impact")') == 1 and 'draw_impact(f, a.get("impact"), "this advisory")' in psrc)
cpsrc = open(os.path.join(HERE, "combo_pdf.py"), encoding="utf-8").read()
ok("the analysts' PDF draws it (an advisory has it on its own pages)", 'advisory_pdf.draw_impact(f, d["impact"], "this report")' in cpsrc and 'd.get("impact") and not adv' in cpsrc)
ok("the package is given it (the report's own and also-seen-in reports)", 'data["impact"] = ctx["impact_of"](data["ref_reports"])' in csrc)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
