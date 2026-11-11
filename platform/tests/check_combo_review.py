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

    print("The advisor writes the advisory")
    ADV = dict(role="advisor", user="lg-check-advisor")
    st, a = call("/api/advisory/1", ADVISOR, **ADV)
    av = a.get("advisory") or {}
    ok("the advisor opens the advisory of the decided finding", st == 200 and av.get("title", "").endswith("Security Advisory"), a.get("error", ""))
    ok("…with the reports filled in on their own, each with its impact flags", av.get("reports") and all(r["flags"] and r["url"].startswith("https://")
       for r in av["reports"]), ", ".join(r["title"] for r in av.get("reports") or []))
    ok("…the impacts gathered, the most severe first", av.get("impact") and [f["level"] for f in av["impact"]] ==
       sorted([f["level"] for f in av["impact"]], key=["critical", "high", "medium", "low"].index))
    ok("…the Technical Details line naming only the kinds present, never their values",
       (av.get("kinds_line") or "").startswith("See Technical Details") if any(av.get("affected", {}).values()) else not av.get("kinds_line"),
       av.get("kinds_line", ""))
    ok("…and no address anywhere", not IP_RX.search(json.dumps(a)))
    st, _ = call("/api/advisory/1", ADVISOR, role="advisor", user="lg-other-advisor")
    ok("an advisor outside the channel does not see it", st == 404)
    st, _ = call("/api/advisory/1", MGMT, role="management", user="lg-check-management")
    ok("management does not write advisories", st == 403)
    st, d = call("/api/advisory/1", ADVISOR, "POST", {"subject": ""}, **ADV)
    ok("an advisory needs a subject", st == 400)
    st, d = call("/api/advisory/1", ADVISOR, "POST", {"subject": "Exposed MikroTik services", "description": "", "actions": "",
                                                       "recipients": "Team A, Team B"}, **ADV)
    ref = (d.get("advisory") or {}).get("ref") or ""
    ok("the advisor saves it: it gets its reference", st == 200 and re.fullmatch(r"ADV-\d{4}-001", ref), d.get("error", ref))
    ok("…kept as JSON", os.path.exists(os.path.join(A.ADVISORIES.dir, f"{ref}.json")))
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {}, **ADV)
    ok("it cannot be sent without the Description and the Recommended Actions", st == 400)
    st, d = call("/api/advisory/1", ADVISOR, "POST", {"subject": "Exposed MikroTik services", "description": "Routers answer on management ports.",
                                                       "actions": "Close the ports to the internet.", "recipients": "Team A, Team B"}, **ADV)
    ok("…saved again under the same reference", st == 200 and d["advisory"]["ref"] == ref)
    st, pdf = call("/advisory/1/report?as=pdf", ADVISOR, raw=True, **ADV)
    ok("the advisory's report: its pages on top of the analyst's report", st == 200 and pdf[:4] == b"%PDF" and len(pdf) > 20000,
       f"{len(pdf) if isinstance(pdf, bytes) else pdf}")
    st, zz = call("/advisory/1/report", ADVISOR, raw=True, **ADV)
    zn = zipfile.ZipFile(io.BytesIO(zz)).namelist() if st == 200 else []
    ok("…and its ZIP: the PDF, the CSV files and the advisory as JSON", f"{ref}.pdf" in zn and f"{ref}.json" in zn and any(n.endswith(".csv") for n in zn),
       ", ".join(zn))
    st, d = call("/api/advisory/1/send", ADVISOR, "POST", {"recipients": "Team A, Team B"}, **ADV)
    ok("the advisor marks it as sent", st == 200 and d["advisory"]["status"] == "sent", d.get("error", ""))
    ok("…and the finding moves to Advisory sent", F.get("1")["status"] == "advisory")
    st, ex = call("/api/advisory/1/export", ADVISOR, raw=True, **ADV)
    exj = json.loads(ex) if st == 200 else {}
    ok("the JSON export describes itself, with the reports and their impact", exj.get("schema") == "looking-glass/advisory"
       and exj.get("reference") == ref and exj.get("shadowserver_reports") and exj.get("recipients") == ["Team A", "Team B"])
    ok("…without any address", st == 200 and not IP_RX.search(ex.decode()))
    st, db = call("/api/advisory/dashboard", ADVISOR, **ADV)
    ok("the advisor's portal counts it: sent, to whom", st == 200 and db["kpis"]["sent"] == 1 and db["kpis"]["recipients"] == 2
       and {r["name"] for r in db["recipients"]} == {"Team A", "Team B"} and db["impacts"], json.dumps(db.get("kpis")))
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
    st, a = call("/api/advisory/1", ADVISOR, **ADV)
    ok("…and the advisory's title carries the name", st == 200 and a["advisory"]["title"] == "Example CSIRT Security Advisory" and a["has_logo"])
    st, pdf = call("/advisory/1/report?as=pdf", ADVISOR, raw=True, **ADV)
    ok("…the report with the logo is made", st == 200 and pdf[:4] == b"%PDF")
    if os.environ.get("LG_SAVE_PDF") and st == 200:      # to look at the pages
        with open(os.environ["LG_SAVE_PDF"], "wb") as fh:
            fh.write(pdf)
    ok("every step is in the audit log", {"combo_review_sent", "finding_review_decision", "advisory_saved", "advisory_sent", "organisation_set"} <= set(audited),
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
    ok("the advisor opens its advisory", st == 200, a.get("error", ""))
    st, pdf = call(f"/advisory/{fid3}/report?as=pdf", ADVISOR, raw=True, **ADV)
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
