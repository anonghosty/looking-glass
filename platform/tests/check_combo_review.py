#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Management decides which views an analyst's report carries (combo_review.py), end to end, in-process, on throwaway
files (the real code book and findings are untouched): an analyst searches a researcher's code whose devices turn up in
other reports; the download is locked; they tick across-report patterns and send them to a manager they name; the
download stays locked while it waits; the manager sees both views (counts only, no address) and adds the analyst's
views; it goes back to the analyst; the report then carries exactly the ticked patterns.
Usage: tests/check_combo_review.py"""
import csv, io, json, os, re, sys, tempfile, time, zipfile
from urllib.parse import quote
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ANALYST, MGMT, ADVISOR = {"view", "unmasked", "export", "malpedia"}, {"management"}, {"advisory"}


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms, method="GET", body=None, role="analyst", user="lg-check-analyst", raw=False):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return (code, r.get_data()) if raw and code == 200 else (code, json.loads(r.get_data(as_text=True) or "{}"))


tmp = tempfile.mkdtemp(prefix="lg-review-")
book, F = A.COMBOS, A.FINDINGS
saved = (book.path, book.data, book.loaded, F.path, F.mtime, F.data, F.people_of)
book.path, book.data, book.loaded = os.path.join(tmp, "codes.json"), {}, True
F.path, F.mtime, F.data = os.path.join(tmp, "findings.json"), None, {"seq": 0, "items": {}}
F.people_of = lambda kind: [{"user": f"lg-check-{kind}", "name": f"Check {kind}", "role": kind}]
real_store = book.review_paths["store"]; book.review_paths["store"] = os.path.join(tmp, "review_searches")
real_adv, real_org = A.ADVISORIES.dir, A.ORG.path
A.ADVISORIES.dir, A.ORG.path = os.path.join(tmp, "advisories"), os.path.join(tmp, "organisation.json")
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append(a[0] if a else "")
jids = []


def search(code, user="lg-check-analyst"):
    st, j = call("/api/combos/search", ANALYST, "POST", {"code": code}, user=user)
    jid = j.get("id"); jids.append(jid)
    for _ in range(600):
        st, s = call(f"/api/combos/search/{jid}", ANALYST, user=user)
        if s.get("state") != "running":
            return jid, s
        time.sleep(0.2)
    return jid, s


try:
    g0 = A.SVC_INTEL.gathered("scan_mikrotik_service")
    code = g0["combinations"][0]["code"]
    print(f"An analyst opens a researcher's code ({code}) whose devices turn up in other reports")
    jid, s = search(code)
    ok("the search finishes", s.get("state") == "done", s.get("error", ""))
    ok("…with the across-report views to tick", s.get("needs_review") and (s.get("preview") or {}).get("cross"), f"{len((s.get('preview') or {}).get('cross') or [])} patterns")
    ok("…each with its devices' IP addresses and networks, for the analyst", all(x.get("devices") and len(x["devices"]) == x["hosts"]
       and IP_RX.match(x["devices"][0]["ip"]) for x in s["preview"]["cross"]))
    st, d = call(f"/api/combos/search/{jid}/download", ANALYST)
    ok("the download is locked until management decides", st == 409 and d.get("needs_review"), d.get("error", ""))
    st, d = call(f"/api/combos/search/{jid}/enrich", ANALYST, "POST")
    ok("…and cannot be got round by adding the analysis", st == 409)
    pats = s["preview"]["cross"]
    tick = [pats[0]["code"]] + ([pats[1]["code"]] if len(pats) > 1 else [])
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", {"codes": [], "title": "t", "to": "lg-check-management"})
    ok("sending nothing ticked is refused", st == 400)
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", {"codes": tick, "title": "t"})
    ok("sending without the manager it goes to is refused", st == 400)
    st, d = call(f"/api/combos/search/{jid}/review", ANALYST, "POST", {"codes": tick, "title": "Same hosts, two reports", "text": "Worth the advisory?",
                                                                      "to": "lg-check-management"})
    ok("the analyst sends the ticked patterns to the manager named", st == 200 and d.get("finding") == "#1", d.get("error", ""))
    st, d = call(f"/api/combos/search/{jid}/download", ANALYST)
    ok("the download stays locked while management decides", st == 409 and "Waiting" in d.get("error", ""), d.get("error", ""))
    print("The manager sees both views and decides")
    st, fl = call("/api/findings", MGMT, role="management", user="lg-check-management")
    f = (fl.get("findings") or [{}])[0]
    rv = f.get("review") or {}
    ok("the manager sees the researcher's view with its figures", rv.get("researcher", {}).get("devices") == s["summary"]["devices"]
       and "top_networks" in rv["researcher"])
    ok("…and the analyst's view: each ticked pattern with the hosts that share it", [p["code"] for p in rv.get("analyst", {}).get("patterns", [])] == tick
       and all(p["hosts"] >= 1 and len(p["parts"]) >= 2 for p in rv["analyst"]["patterns"]))
    ok("…with no address anywhere", not IP_RX.search(json.dumps(fl)))
    st, fl2 = call("/api/findings", MGMT, role="management", user="lg-other-manager")
    ok("another manager does not see it", st == 200 and not fl2["findings"])
    st, d = call("/api/findings/1/review-decision", MGMT, "POST", {"choice": "both", "text": ""}, role="management", user="lg-check-management")
    ok("a decision needs the comment", st == 400)
    st, d = call("/api/findings/1/review-decision", MGMT, "POST", {"choice": "both", "text": "Add them: one advisory for both reports."},
                 role="management", user="lg-check-management")
    ok("a decision needs the advisor it goes to", st == 400)
    st, d = call("/api/findings/1/review-decision", MGMT, "POST", {"choice": "both", "text": "Add them: one advisory for both reports.",
                                                                    "to": "lg-check-advisor"}, role="management", user="lg-check-management")
    ok("the manager adds the analyst's views; it goes to the advisor named", st == 200 and d["finding"]["status"] == "advisor"
       and F.get("1").get("assignee") == "lg-check-advisor" and d["finding"]["review"]["decision"] == "both", d.get("error", ""))
    st, d = call("/api/findings/1/review-decision", MGMT, "POST", {"choice": "researcher", "text": "x", "to": "lg-check-advisor"},
                 role="management", user="lg-check-management")
    ok("…once", st == 400)
    st, d = call(f"/api/combos/search/{jid}/download", ANALYST)
    ok("the analyst's download stays closed: the advisor generates the report", st == 409 and "advisory" in d.get("error", ""), d.get("error", ""))
    print("The report the advisor generates carries what was sent")
    st, z = call("/review/1/report", ADVISOR, role="advisor", user="lg-check-advisor", raw=True)
    ok("the advisor gets the report", st == 200, str(z)[:120] if st != 200 else "")
    if st == 200:
        names = zipfile.ZipFile(io.BytesIO(z)).namelist()
        oc = next((n for n in names if n.endswith("_other_categories.csv")), None)
        ok("the report carries the analyst's views", bool(oc), ", ".join(names))
        if oc:
            rows = list(csv.reader(io.StringIO(zipfile.ZipFile(io.BytesIO(z)).read(oc).decode("utf-8-sig"))))
            across = sorted(r[5] for r in rows[1:] if r[0] == "across reports")
            ok("…exactly the ticked patterns", across == sorted(tick), f"{across}")
            sent_n = sum(x["hosts"] for x in pats if x["code"] in tick)
            devs = [r for r in rows[1:] if r[0] == "across reports device"]
            import ipaddress
            def is_ip(s):
                try: ipaddress.ip_address(s.split(" ")[0]); return True
                except ValueError: return False
            ok("…with exactly the devices that were sent (each with its address, IPv4 or IPv6)", len(devs) == sent_n and all(is_ip(r[2]) for r in devs),
               f"{len(devs)} of {sent_n}")
    st, s3 = call(f"/api/combos/search/{jid}", ANALYST)
    sent = (s3.get("review") or {}).get("sent") or []
    ok("the analyst's page shows what was sent, not a new look-up", sorted(x["code"] for x in sent) == sorted(tick)
       and all(len(x["devices"]) == x["hosts"] for x in sent))
    st, fl3 = call("/api/findings", MGMT, role="management", user="lg-check-management")
    ok("management never gets the sent devices", "sent" not in (fl3["findings"][0].get("review") or {}) and not IP_RX.search(json.dumps(fl3)))
    jid2, s2 = search(code, user="lg-other-analyst")
    st, d = call(f"/api/combos/search/{jid2}/download", ANALYST, user="lg-other-analyst")
    ok("an analyst outside the finding's channel is still locked", st == 409)
    print("The report from the review, without a new search")
    real_pkg = book.package; calls = []
    def pkg(*a, **k):
        calls.append(len(a[2])); return real_pkg(*a, **k)
    book.package = pkg
    import services_intel as SI, combos as CB
    real_m1, real_m2 = SI.Matcher.match, CB.Matcher.match
    def no_search(*a, **k):
        raise AssertionError("no new search")              # matching again would fail here
    SI.Matcher.match = CB.Matcher.match = no_search
    try:
        st, zz = call("/review/1/report", ADVISOR, role="advisor", user="lg-check-advisor", raw=True)
    finally:
        SI.Matcher.match, CB.Matcher.match = real_m1, real_m2; book.package = real_pkg
    ok("the review's report is made from the kept records (no new search)", st == 200 and calls and calls[0] == s["summary"]["records"],
       f"HTTP {st} · {calls[:1]} of {s['summary']['records']} records" if st == 200 else str(zz)[:150])
    if st == 200:
        zn = zipfile.ZipFile(io.BytesIO(zz)).namelist()
        oc2 = next((n for n in zn if n.endswith("_other_categories.csv")), None)
        rows2 = list(csv.reader(io.StringIO(zipfile.ZipFile(io.BytesIO(zz)).read(oc2).decode("utf-8-sig")))) if oc2 else []
        ok("…carrying exactly what was sent", sorted(r[5] for r in rows2[1:] if r[0] == "across reports") == sorted(tick))
    st, pdf = call("/review/1/report?as=pdf", ADVISOR, role="advisor", user="lg-check-advisor", raw=True)
    ok("…and its PDF to preview in the browser", st == 200 and pdf[:4] == b"%PDF")
    st, _ = call("/review/1/report", ANALYST)
    ok("the analyst no longer generates it", st == 403)
    st, _ = call("/review/1/report", MGMT, role="management", user="lg-check-management")
    ok("management cannot download the addresses", st == 403)
    st, _ = call("/api/review/1", MGMT, role="management", user="lg-check-management")
    ok("the manager opens the review page's data", st == 200)
    st, _ = call("/api/review/1", ANALYST)
    ok("the analyst does not (the review is management's)", st == 403)

    print("The advisor writes one advisory per organisation (network)")
    ADV = dict(role="advisor", user="lg-check-advisor")
    st, a = call("/api/advisory/1", ADVISOR, **ADV)
    nets = a.get("networks") or []
    ok("the advisor opens the decided finding: its organisations (networks) to pick from", st == 200 and nets and all(n["network"] and n["devices"] for n in nets),
       f"{len(nets)} networks" if st == 200 else a.get("error", ""))
    ok("…with no address on that list", not IP_RX.search(json.dumps(a)))
    NET = nets[0]["network"] if nets else ""
    st, a = call(f"/api/advisory/1/net?network={quote(NET)}", ADVISOR, **ADV)
    av = a.get("advisory") or {}
    devs = av.get("devices") or []
    ok("picking one shows its data: its IP addresses only", st == 200 and devs and all(d["network"] == NET for d in devs)
       and len(devs) == nets[0]["devices"], f"{len(devs)} of {nets[0]['devices'] if nets else 0} on {NET}")
    ok("…each with its ports, reports, and what the records say (CVEs, issues, what it is)", devs and all(d["reports"] for d in devs)
       and any(d["cves"] or d["issues"] or d["labels"] for d in devs))
    import issue_tags
    ok("…issues are weaknesses only: product and protocol tags are apart, as what the devices are",
       all(i.startswith(("End of life", "Exposed", "Device implant", "Badcandy", "Cpanel", "Open dir", "Vulnerable", "Expired", "POODLE", "FREAK", "Compromised"))
           for d in devs for i in d["issues"]) and not any(issue_tags.issue_of(lb) for d in devs for lb in d["labels"]),
       f"issues {sorted({i for d in devs for i in d['issues']})[:6]} · seen as {sorted({lb for d in devs for lb in d['labels']})[:6]}")
    ok("…the reports filled in on their own, each with its impact flags", av.get("reports") and all(r["flags"] and r["url"].startswith("https://")
       for r in av["reports"]), ", ".join(r["title"] for r in av.get("reports") or []))
    ok("…the impacts gathered, the most severe first", av.get("impact") and [f["level"] for f in av["impact"]] ==
       sorted([f["level"] for f in av["impact"]], key=["critical", "high", "medium", "low"].index))
    kinds = [w for w, k_ in (("CVEs", "cves"), ("issues", "issues"), ("categories", "categories")) if av.get("affected", {}).get(k_)]
    ok("…the Technical Details line naming only the kinds present, never their values",
       (all(w in av.get("kinds_line", "") for w in kinds) and av["kinds_line"].startswith("See Technical Details")) if kinds else not av.get("kinds_line"),
       av.get("kinds_line", "") or "(none: no CVE, issue or category on this organisation)")
    ok("…and the product / protocol tags listed apart as Seen as", isinstance(av.get("affected", {}).get("labels"), list))
    ok("…the recipients start with the organisation", av.get("recipients") == [NET])
    fb = a.get("file_base") or ""
    ok("…and its files named CSIRT_organisation_data-title_yyyymmdd", re.fullmatch(r"[A-Za-z0-9-]+_[A-Za-z0-9-]+_[A-Za-z0-9-]+_\d{8}", fb)
       and fb.endswith(time.strftime("%Y%m%d", time.gmtime())), fb)
    st, _ = call("/api/advisory/1/net?network=Not-a-network", ADVISOR, **ADV)
    ok("a network not in the finding is refused", st == 404)
    st, _ = call("/api/advisory/1", ADVISOR, role="advisor", user="lg-other-advisor")
    ok("an advisor outside the channel does not see it", st == 404)
    st, _ = call("/api/advisory/1", MGMT, role="management", user="lg-check-management")
    ok("management does not write advisories", st == 403)
    st, d = call("/api/advisory/1/net", ADVISOR, "POST", {"network": NET, "subject": ""}, **ADV)
    ok("an advisory needs a subject", st == 400)
    st, d = call("/api/advisory/1/net", ADVISOR, "POST", {"subject": "x"}, **ADV)
    ok("…and its organisation", st == 400)
    body = {"network": NET, "subject": "Exposed VMware ESXi hosts", "description": "", "actions": "", "recipients": f"{NET}, Team B"}
    st, d = call("/api/advisory/1/net", ADVISOR, "POST", body, **ADV)
    ref = (d.get("advisory") or {}).get("ref") or ""
    ok("the advisor saves it: it gets its reference", st == 200 and re.fullmatch(r"ADV-\d{4}-001", ref), d.get("error", ref))
    ok("…kept as JSON", os.path.exists(os.path.join(A.ADVISORIES.dir, f"{ref}.json")))
    ok("…at TLP:AMBER unless the advisor chooses (it lists the organisation's addresses)", (d.get("advisory") or {}).get("tlp") == "TLP:AMBER")
    st, _ = call("/api/advisory/1/net", ADVISOR, "POST", dict(body, tlp="TLP:PURPLE"), **ADV)
    ok("a TLP level that does not exist is refused", st == 400)
    st, a_ = call("/api/advisory/1", ADVISOR, **ADV)
    ok("the page gets the five TLP 2.0 levels with what each allows", [x["key"] for x in a_.get("tlp_levels") or []] ==
       ["TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER", "TLP:GREEN", "TLP:CLEAR"] and all(x["text"] for x in a_["tlp_levels"]))
    body["tlp"] = "TLP:RED"
    ok("the heading is the CSIRT's name + Security Advisory until the advisor writes one", (d.get("advisory") or {}).get("title", "").endswith("Security Advisory")
       and not d["advisory"]["heading"])
    body["heading"] = "Exposed MikroTik routers on Dimension Data"
    st, d = call("/api/advisory/1/generate", ADVISOR, "POST", {"network": NET}, **ADV)
    ok("no report without the Description and the Recommended Actions", st == 400)
    body.update(description="These hosts run an **end-of-life** hypervisor:\n- reachable from the internet\n- with known CVEs",
                actions="1. Patch to a supported version\n2. Close the management ports\n3. Check for signs of compromise")
    st, d = call("/api/advisory/1/net", ADVISOR, "POST", body, **ADV)
    ok("…saved again under the same reference", st == 200 and d["advisory"]["ref"] == ref)
    ok("…with the advisor's own heading and the TLP chosen", d["advisory"]["title"] == body["heading"] and d["advisory"]["tlp"] == "TLP:RED")
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {"network": NET}, **ADV)
    ok("it cannot be marked as sent before a report is generated", st == 400)
    st, pdf = call(f"/advisory/1/preview?network={quote(NET)}", ADVISOR, raw=True, **ADV)
    ok("the preview: its pages on top of the analyst's report on this organisation", st == 200 and pdf[:4] == b"%PDF" and len(pdf) > 20000,
       f"{len(pdf) if isinstance(pdf, bytes) else pdf}")
    if os.environ.get("LG_SAVE_PDF") and st == 200:      # to look at the pages
        with open(os.environ["LG_SAVE_PDF"], "wb") as fh:
            fh.write(pdf)
    import combo_pdf as _cp
    real_b, seen_b = _cp.build, []
    _cp.build = lambda d_, m_: (seen_b.append(d_), real_b(d_, m_))[1]
    try:
        st, d = call("/api/advisory/1/generate", ADVISOR, "POST", {"network": NET}, **ADV)
    finally:
        _cp.build = real_b
    fname = (d.get("file") or {}).get("name") or ""
    ok("the advisor generates the report: named as the CSIRT names it", st == 200 and fname == f"{fb}.zip", d.get("error", fname))
    words = json.dumps([seen_b[-1].get("findings"), seen_b[-1].get("headline")]) if seen_b else ""
    ok("…its words name no Looking Glass code (the patterns go by their devices' IP addresses)", seen_b and not re.search(r"LG-[ACX]-", words),
       (re.findall(r"[^.]*LG-[ACX]-[^.]*", words) or [""])[0][:160])
    st, zz = call(f"/advisory/1/file/{ref}/1", ADVISOR, raw=True, **ADV)
    zf_ = zipfile.ZipFile(io.BytesIO(zz)) if st == 200 else None
    zn = zf_.namelist() if zf_ else []
    ok("…kept with its download: just the PDF and the devices CSV, what is mailed to the organisation",
       sorted(zn) == sorted([f"{fb}.pdf", f"{fb}_devices.csv"]), ", ".join(zn))
    if zf_ and f"{fb}_devices.csv" in zn:
        rows = list(csv.reader(io.StringIO(zf_.read(f"{fb}_devices.csv").decode("utf-8-sig"))))
        ok("…its devices are this organisation's only", rows[1:] and all(r[2] == NET for r in rows[1:]), f"{len(rows) - 1} devices")
        ok("…and the devices CSV carries no Looking Glass code", not {"combination_code", "cross_report_code", "code"} & set(rows[0])
           and not re.search(r"LG-[ACX]-", zf_.read(f"{fb}_devices.csv").decode("utf-8", "replace")), ", ".join(h for h in rows[0] if "code" in h))
    st, d = call("/api/advisory/1/generate", ADVISOR, "POST", {"network": NET}, **ADV)
    gen = (d.get("advisory") or {}).get("generated") or []
    st2, _ = call(f"/advisory/1/file/{ref}/1", ADVISOR, raw=True, **ADV)
    st3, _ = call(f"/advisory/1/file/{ref}/2", ADVISOR, raw=True, **ADV)
    ok("generating again replaces the report: one download, the latest", st == 200 and len(gen) == 1 and gen[0]["n"] == 2 and st2 == 404 and st3 == 200,
       f"{len(gen)} kept, old link {st2}, new link {st3}")
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {"network": NET, "recipients": f"{NET}, Team B"}, **ADV)
    ok("it is not marked as sent before it is drafted", st == 400 and "drafted" in d.get("error", ""), d.get("error", ""))
    st, d = call("/api/advisory/1/drafted", ADVISOR, "POST", {"network": NET}, **ADV)
    ok("the advisor marks it as drafted on its page", st == 200 and d["advisory"]["status"] == "drafted" and d["advisory"]["status_label"] == "Drafted",
       d.get("error", ""))
    st, fl = call("/api/findings", ADVISOR, role="advisor", user="lg-check-advisor")
    f1 = next((f_ for f_ in fl.get("findings") or [] if f_["id"] == "1"), {})
    ok("the Findings page shows it drafted, with its organisation and TLP, to mark as sent there",
       [(a_["ref"], a_["network"], a_["status"], a_["tlp"]) for a_ in f1.get("advisories") or []] == [(ref, NET, "drafted", "TLP:RED")]
       and not IP_RX.search(json.dumps(f1.get("advisories"))))
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {"network": NET, "recipients": f"{NET}, Team B"}, **ADV)
    ok("the advisor marks it as sent", st == 200 and d["advisory"]["status"] == "sent", d.get("error", ""))
    ok("…and the finding closes, logged", F.get("1")["status"] == "closed" and F.get("1")["history"][-1].get("kind") == "advisory_sent"
       and ref in F.get("1")["history"][-1]["comment"])
    # a sent advisory is the record of what the organisation received: locked (external review, 2026-11-11)
    sent_adv = d["advisory"]
    ok("the send records exactly which file went out", (sent_adv.get("sends") or [{}])[-1].get("report") == f"{fb}.zip" and sent_adv.get("locked") is True,
       json.dumps(sent_adv.get("sends")))
    st_f, sent_bytes = call(f"/advisory/1/file/{ref}/2", ADVISOR, raw=True, **ADV)
    st, d = call("/api/advisory/1/net", ADVISOR, "POST", dict(body, subject="Changed after sending"), **ADV)
    ok("once sent, its text can no longer be changed", st == 409 and "can no longer be changed" in d.get("error", ""), f"{st} {d.get('error', '')}")
    st, d = call("/api/advisory/1/generate", ADVISOR, "POST", {"network": NET}, **ADV)
    ok("…and its report is not generated again", st == 409 and "can no longer be changed" in d.get("error", ""), f"{st} {d.get('error', '')}")
    st, again = call(f"/advisory/1/file/{ref}/2", ADVISOR, raw=True, **ADV)
    ok("…the file that was sent is still there, byte for byte", st_f == 200 and st == 200 and again == sent_bytes, f"{st_f} {st}")
    st, a3 = call(f"/api/advisory/1/net?network={quote(NET)}", ADVISOR, **ADV)
    ok("…and the advisory still reads as it was sent", st == 200 and a3["advisory"]["subject"] == body["subject"] and a3["advisory"]["status"] == "sent")
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {"network": NET, "recipients": "Team B"}, **ADV)
    ok("it can still be sent on to more people, with the same file", st == 200 and d["advisory"]["sends"][-1]["report"] == f"{fb}.zip"
       and len(d["advisory"]["sends"]) == 2, d.get("error", ""))
    st, a2 = call("/api/advisory/1", ADVISOR, **ADV)
    ok("the organisation shows as sent on the list, the others still to do", st == 200 and next(n for n in a2["networks"] if n["network"] == NET)["status"] == "sent")
    st, ex = call(f"/api/advisory/1/export?network={quote(NET)}", ADVISOR, raw=True, **ADV)
    exj = json.loads(ex) if st == 200 else {}
    ok("the JSON export describes itself, with the organisation, the reports and their impact", exj.get("schema") == "looking-glass/advisory"
       and exj.get("reference") == ref and exj.get("network") == NET and exj.get("shadowserver_reports") and exj.get("generated"))
    ok("…without any address", st == 200 and not IP_RX.search(ex.decode()))
    ok("…with its TLP level and what it means", (exj.get("tlp") or {}).get("level") == "TLP:RED" and exj["tlp"].get("meaning"))
    st, db = call("/api/advisory/dashboard", ADVISOR, **ADV)
    ok("the advisor's portal counts it: sent, to whom, reports generated, the finding closed", st == 200 and db["kpis"]["sent"] == 1
       and db["kpis"]["recipients"] == 2 and db["kpis"]["reports"] == 1 and db["kpis"]["drafted"] == 0 and db["kpis"]["closed_findings"] == 1
       and db["advisories"][0]["network"] == NET and db["impacts"], json.dumps(db.get("kpis")))
    st, db2 = call("/api/advisory/dashboard", ADVISOR, role="advisor", user="lg-other-advisor")
    ok("…another advisor's portal does not", st == 200 and db2["kpis"]["sent"] == 0 and not db2["advisories"])
    print("The organisation in Settings")
    png = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
    ADM = dict(role="admin", user="lg-check-admin")
    st, d = call("/api/organisation", {"settings"}, "POST", {"name": "Example CSIRT", "logo": "data:image/png;base64,AAAA"}, **ADM)
    ok("a logo that is not an image is refused", st == 400)
    st, d = call("/api/organisation", ADVISOR, "POST", {"name": "X"}, **ADV)
    ok("only admins set the organisation", st == 403)
    st, d = call("/api/organisation", {"settings"}, "POST", {"name": "Example CSIRT", "logo": png}, **ADM)
    ok("the admin sets the name and logo", st == 200 and d.get("has_logo"), d.get("error", ""))
    st, a = call(f"/api/advisory/1/net?network={quote(NET)}", ADVISOR, **ADV)
    ok("…the advisory's title carries the name, and its files start with it", st == 200 and a["advisory"]["heading_default"] == "Example CSIRT Security Advisory"
       and a["file_base"].startswith("Example-CSIRT_"), a.get("file_base", ""))
    import combo_pdf
    real_build, seen = combo_pdf.build, []
    combo_pdf.build = lambda d_, m_: (seen.append((d_, m_)), real_build(d_, m_))[1]
    try:
        st, pdf = call(f"/advisory/1/preview?network={quote(NET)}", ADVISOR, raw=True, **ADV)
    finally:
        combo_pdf.build = real_build
    ok("…the report with the logo is made", st == 200 and pdf[:4] == b"%PDF")
    d_, m_ = seen[-1] if seen else ({}, {})
    ok("it goes to an organisation: signed by the CSIRT (the person is in the audit log), without the team's notes",
       m_.get("generated_by") == "Example CSIRT" and d_.get("notes") == [] and not any("researcher note" in str(p_) for p_ in d_.get("findings") or [])
       and not any(c_.get("note") or c_.get("by") for _, c_ in d_.get("explained") or []), m_.get("generated_by", ""))
    ok("every step is in the audit log", {"combo_review_sent", "finding_review_decision", "advisory_saved", "advisory_report", "advisory_sent", "organisation_set"} <= set(audited),
       ", ".join(sorted(set(audited))))

    print("A combination without across-report data still goes to management for the advisory")
    def plain(jid_, user_):
        """The search as if its devices turned up in no other report."""
        with A.app.test_request_context("/"):
            g.user = {"user": user_, "role": "analyst", "perms": ANALYST}
            j_ = book.own_job(jid_)
            j_["preview"], j_["needs_review"], j_["review"] = {"cross": []}, False, None
    jid3, _ = search(code, user="lg-plain-analyst")
    plain(jid3, "lg-plain-analyst")
    PA = dict(user="lg-plain-analyst")
    st, z3 = call(f"/api/combos/search/{jid3}/download", ANALYST, raw=True, **PA)
    ok("before it is sent, the analyst's download is open", st == 200)
    st, d = call(f"/api/combos/search/{jid3}/review", ANALYST, "POST", {"codes": [], "title": "Exposed routers", "text": "Needs an advisory.",
                                                                       "to": "lg-check-management"}, **PA)
    fid3 = (d.get("finding") or "#0")[1:]
    ok("the analyst sends it to the manager named, without patterns", st == 200 and d.get("codes") == [], d.get("error", ""))
    st, d = call(f"/api/combos/search/{jid3}/review", ANALYST, "POST", {"codes": [], "title": "again", "to": "lg-check-management"}, **PA)
    ok("…once", st == 409)
    st, d = call(f"/api/combos/search/{jid3}/download", ANALYST, **PA)
    ok("…and the download closes while management decides", st == 409 and "Waiting" in d.get("error", ""), d.get("error", ""))
    st, d = call(f"/api/findings/{fid3}/review-decision", MGMT, "POST", {"choice": "both", "text": "Write it up.", "to": "lg-check-advisor"},
                 role="management", user="lg-check-management")
    ok("management approves it to the advisor named (the researcher's view: there is no analyst's view to add)", st == 200
       and d["finding"]["status"] == "advisor" and d["finding"]["review"]["decision"] == "researcher", d.get("error", ""))
    st, d = call(f"/api/combos/search/{jid3}/download", ANALYST, **PA)
    ok("…the analyst's download stays closed: the advisor generates it", st == 409 and "advisory" in d.get("error", ""))
    st, a = call(f"/api/advisory/{fid3}", ADVISOR, **ADV)
    ok("the advisor opens its advisory, with its organisations", st == 200 and a.get("networks"), a.get("error", ""))
    n3 = (a.get("networks") or [{}])[0].get("network", "")
    st, pdf = call(f"/advisory/{fid3}/preview?network={quote(n3)}", ADVISOR, raw=True, **ADV)
    ok("…and generates its report from the kept search", st == 200 and pdf[:4] == b"%PDF", str(pdf)[:120] if st != 200 else "")
    jid4, _ = search(code, user="lg-plain2-analyst")
    plain(jid4, "lg-plain2-analyst")
    P2 = dict(user="lg-plain2-analyst")
    st, d = call(f"/api/combos/search/{jid4}/review", ANALYST, "POST", {"codes": [], "title": "Maybe", "to": "lg-check-management"}, **P2)
    fid4 = (d.get("finding") or "#0")[1:]
    st, d = call(f"/api/findings/{fid4}/review-decision", MGMT, "POST", {"choice": "reject", "text": "Not for an advisory."},
                 role="management", user="lg-check-management")
    ok("management rejects one with the reason: it is closed", st == 200 and d["finding"]["status"] == "closed", d.get("error", ""))
    st, _ = call(f"/api/combos/search/{jid4}/download", ANALYST, raw=True, **P2)
    ok("…and the analyst's download opens again", st == 200)
    st, _ = call(f"/api/advisory/{fid4}", ADVISOR, **ADV)
    ok("…with no advisory to write", st in (404, 409))

    print("Several organisations: a case with one sub-finding each")
    jid5, s5 = search(code, user="lg-case-analyst")
    CA = dict(user="lg-case-analyst")
    nets5 = s5.get("networks") or []
    ok("the analyst sees the organisations (networks) of the search to pick from", len(nets5) >= 2 and all(n["network"] and n["devices"] for n in nets5),
       f"{len(nets5)} networks")
    pick = [n["network"] for n in nets5[:2]]
    st, sm = call(f"/api/combos/search/{jid5}/summary?network={quote(pick[0])}", ANALYST, **CA)
    ok("the page filters to one network: its own figures", st == 200 and sm["summary"]["devices"] == nets5[0]["devices"]
       and sm["summary"]["records"] == nets5[0]["records"] and all(n["label"] == pick[0] for n in sm["summary"]["networks_all"]),
       f"{sm.get('summary', {}).get('devices')} of {nets5[0]['devices']}" if st == 200 else sm.get("error", ""))
    st, _ = call(f"/api/combos/search/{jid5}/summary?network=Not-a-network", ANALYST, **CA)
    ok("…and says so for a network that is not in it", st == 404)
    tick5 = [s5["preview"]["cross"][0]["code"]]
    st, d = call(f"/api/combos/search/{jid5}/review", ANALYST, "POST", {"codes": tick5, "networks": ["Not a network"], "title": "x", "to": "lg-check-management"}, **CA)
    ok("a network not in the search is refused", st == 400)
    st, d = call(f"/api/combos/search/{jid5}/review", ANALYST, "POST", {"codes": tick5, "networks": pick, "title": "Two operators", "text": "One advisory each.",
                                                                       "to": "lg-check-management"}, **CA)
    ok("submitting several networks opens a case with one sub-finding each", st == 200 and d.get("case") and [s_["network"] for s_ in d.get("subs") or []] == pick,
       d.get("error", ""))
    cid = (d.get("finding") or "#0")[1:]
    sids = [s_["finding"][1:] for s_ in d.get("subs") or []]
    case = F.get(cid) or {}
    ok("…the case is the overview, its sub-findings under it", case.get("kind") == "case" and case.get("children") == sids
       and all(F.get(k)["parent"] == cid and F.get(k)["network"] == n for k, n in zip(sids, pick)))
    sub0 = F.get(sids[0]) if sids else {}
    p0 = {x["ip"] for x in sub0.get("review", {}).get("sent", []) for x in x.get("devices") or []}
    ok("…each carrying only its organisation's devices", sub0.get("review", {}).get("researcher", {}).get("devices") == nets5[0]["devices"]
       and all(any(dv["ip"] == ip and dv.get("network") == pick[0] for x in sub0["review"]["sent"] for dv in x["devices"]) for ip in p0))
    st, fl = call("/api/findings", MGMT, role="management", user="lg-check-management")
    ok("management sees the case and its sub-findings", st == 200 and {cid, *sids} <= {f_["id"] for f_ in fl["findings"]})
    st, d = call(f"/api/findings/{cid}/decision", MGMT, "POST", {"decision": "accept", "text": "x", "to": "lg-check-analyst"}, role="management", user="lg-check-management")
    ok("the case itself is not decided: each sub-finding is", st == 400)
    st, d = call(f"/api/findings/{sids[0]}/review-decision", MGMT, "POST", {"choice": "both", "text": "Go.", "to": "lg-check-advisor"},
                 role="management", user="lg-check-management")
    ok("management approves one organisation's sub-finding to the advisor", st == 200 and d["finding"]["status"] == "advisor", d.get("error", ""))
    ok("…the case still waits for the other", F.get(cid)["status"] == "management")
    st, d = call(f"/api/combos/search/{jid5}/download", ANALYST, **CA)
    ok("…and the analyst's download waits for it too", st == 409 and f"#{sids[1]}" in d.get("error", ""), d.get("error", ""))
    st, d = call(f"/api/findings/{sids[1]}/review-decision", MGMT, "POST", {"choice": "reject", "text": "Not this one."},
                 role="management", user="lg-check-management")
    ok("management rejects the other: the case follows (with the advisor)", st == 200 and F.get(cid)["status"] == "advisor", F.get(cid)["status"])
    st, d = call(f"/api/advisory/{cid}", ADVISOR, **ADV)
    ok("the advisor writes no advisory on the case itself", st == 409 and d.get("case"))
    st, d = call(f"/api/advisory/{sids[0]}", ADVISOR, **ADV)
    ok("…but on the approved sub-finding, for its organisation only", st == 200 and [n["network"] for n in d.get("networks") or []] == [pick[0]],
       json.dumps([n["network"] for n in d.get("networks") or []]))
    st, d = call(f"/api/combos/search/{jid5}/download", ANALYST, **CA)
    ok("…and the analyst's download stays the advisor's", st == 409 and "advisory" in d.get("error", ""), d.get("error", ""))
    s0 = sids[0]
    call(f"/api/advisory/{s0}/net", ADVISOR, "POST", {"network": pick[0], "subject": "Exposed routers", "description": "Exposed.", "actions": "- Close the port",
                                                     "recipients": pick[0]}, **ADV)
    st, d = call(f"/api/advisory/{s0}/generate", ADVISOR, "POST", {"network": pick[0]}, **ADV)
    st2, d2 = call(f"/api/advisory/{s0}/drafted", ADVISOR, "POST", {"network": pick[0]}, **ADV)
    ok("the advisor writes, generates and drafts the sub-finding's advisory", st == 200 and st2 == 200, d.get("error", "") or d2.get("error", ""))
    ok("…the case stays open meanwhile", F.get(cid)["status"] != "closed")
    st, d = call(f"/api/advisory/{s0}/send", ADVISOR, "POST", {"network": pick[0], "recipients": pick[0]}, **ADV)
    ok("marked as sent: the sub-finding closes", st == 200 and F.get(s0)["status"] == "closed", d.get("error", ""))
    ok("…and, its other sub-finding rejected, the case closes, logged", F.get(cid)["status"] == "closed"
       and "the case is closed" in F.get(cid)["history"][-1]["comment"], F.get(cid)["history"][-1]["comment"])
    st, db = call("/api/advisory/dashboard", ADVISOR, **ADV)
    ok("the advisor's portal counts the closed case", st == 200 and db["kpis"]["closed_cases"] >= 1, json.dumps(db.get("kpis")))
    jid6, s6 = search(code, user="lg-one-analyst")
    st, d = call(f"/api/combos/search/{jid6}/review", ANALYST, "POST", {"codes": [s6["preview"]["cross"][0]["code"]], "networks": [s6["networks"][0]["network"]],
                                                                       "title": "One operator", "to": "lg-check-management"}, user="lg-one-analyst")
    one = F.get((d.get("finding") or "#0")[1:]) or {}
    ok("one network: a finding for that organisation, no case", st == 200 and not d.get("case") and one.get("network") == s6["networks"][0]["network"]
       and not one.get("parent"), d.get("error", ""))
finally:
    for jid in jids:
        for s_ in (".zip", ".json"):
            try: os.remove(os.path.join(A.BASE_DIR, "data", "combo_exports", f"{jid}{s_}"))
            except OSError: pass
    audit.add = real_add
    book.review_paths["store"] = real_store
    A.ADVISORIES.dir, A.ORG.path = real_adv, real_org
    for n in (f"review{i}" for i in range(1, 10)):
        for s_ in (".zip", ".json"):
            try: os.remove(os.path.join(A.BASE_DIR, "data", "combo_exports", n + s_))
            except OSError: pass
    book.path, book.data, book.loaded, F.path, F.mtime, F.data, F.people_of = saved
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} review checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
