#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Analyst codes (acodes.py) end to end, in-process, on throwaway files (the real code book, notes and findings are
never touched): an analyst makes an LG-A code from an analysis selection (a network and one host) and a finding; the
researchers open it without the host's address and with the names and codes of exactly those records; they reply on
the finding with a code; management filters the Executive portal by it (counts only); the analysts find it in their
list and report on it (PDF + CSV); other roles are refused. Usage: tests/check_acodes.py"""
import io, json, os, re, sys, tempfile, time, zipfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
ANALYST, RESEARCHER, MGMT = {"view", "unmasked", "export", "malpedia"}, {"definitions", "networks"}, {"management"}


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms, method="GET", body=None, role="analyst", raw=False, user="lg-check"):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return (code, r.get_data()) if raw else (code, json.loads(r.get_data(as_text=True) or "{}"))


tmp = tempfile.mkdtemp(prefix="lg-acodes-")
book, F = A.COMBOS, A.FINDINGS
saved = (book.path, book.data, book.loaded, F.path, F.mtime, F.data)
book.path, book.data, book.loaded = os.path.join(tmp, "codes.json"), {}, True
F.path, F.mtime, F.data = os.path.join(tmp, "findings.json"), None, {"seq": 0, "items": {}}
real_ids = A.ACODES.paths["ids"]; A.ACODES.paths["ids"] = os.path.join(tmp, "acodes")
real_exports = book.export_paths["dir"]; book.export_paths["dir"] = os.path.join(tmp, "combo_exports")   # not data/
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append(a[0] if a else "")
real_people = F.people_of        # the accounts that do each job: test accounts here (findings.py channels)
F.people_of = lambda kind: [{"user": f"lg-check-{kind}", "name": f"Check {kind}", "role": kind}]
jids = []
try:
    day = A.store.get(A.replay_now()); A.svc["store"].get(A.replay_now())
    # a host with an infection on a network: the kind of selection an analyst analyses
    e0 = next(e for e in day.events if e.get("src_ip") and e.get("src_asn") and e.get("infection"))
    ip, asn = e0["src_ip"], e0["src_asn"]
    value = f"src_asn={asn}&src_ip={ip}"
    want = [e for e in day.events if str(e.get("src_asn")) == str(asn) and e.get("src_ip") == ip]
    at = day.start.isoformat()
    print("The analyst makes a code")
    st, d = call("/api/analyst-codes", RESEARCHER, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "title": "t"}, role="researcher")
    ok("a researcher cannot make an analyst code", st == 403, f"HTTP {st}")
    st, d = call("/api/analyst-codes?demo=1", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "title": "t"})
    ok("demo mode: refused", st == 403)
    st, d = call("/api/analyst-codes", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "title": "no recipient"})
    ok("a code without the researcher it goes to is refused", st == 400 and "researcher" in d.get("error", ""), d.get("error", ""))
    st, d = call("/api/analyst-codes", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "title": "x", "to": "lg-nobody"})
    ok("…and one sent to someone who is not a researcher", st == 400)
    st, d = call("/api/analyst-codes", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "to": "lg-check-researcher",
                                                          "title": "Test host on two sinkholes", "text": "Which infections share a C2 here?"})
    ok("the analyst makes an LG-A code and a finding", st == 200 and re.match(r"^LG-A-[0-9A-F]{8}$", d.get("code", "")) and d.get("finding") == "#1",
       f"{d.get('code')} {d.get('finding')} · {d.get('records')} records")
    code = d["code"]
    ok("its records are exactly the analysis selection's", d["records"] == len(want) and d["hosts"] == 1, f"{d['records']} vs {len(want)}")
    ok("the code and its description carry no address", ip not in code and ip not in d["label"] and "held back" in d["label"], d["label"][:90])
    p_ids = os.path.join(A.ACODES.paths["ids"], f"{code}.json")
    ok("its exact records are kept (owner-only file), so every role sees the same records", os.path.exists(p_ids)
       and oct(os.stat(p_ids).st_mode & 0o777) == "0o600" and len(json.load(open(p_ids))) == len(want))
    st, d2 = call("/api/analyst-codes", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "title": "again", "to": "lg-check-researcher"})
    ok("the same selection on the same day gives the same code", d2.get("code") == code)
    print("The researcher opens it")
    st, v = call(f"/api/intel/acode/{code}", RESEARCHER, role="researcher")
    blob = json.dumps(v)
    ok("the researcher sees it", st == 200 and v["records"] == len(want) and v["finding"]["number"] == "#1", f"HTTP {st}")
    ok("…without the host's address anywhere", ip not in blob)
    names = sorted({(e.get("infection") or "").lower() for e in want if e.get("infection")})
    ok("…with every name in those records and its combinations' codes", sorted(n["name"] for n in v["names"]) == names
       and all(re.match(r"^LG-C-", c["code"]) for n in v["names"] for c in n["combinations"]), ", ".join(names))
    st, _ = call(f"/api/intel/acode/{code}", {"view"}, role="external")
    ok("external: refused", st == 403)
    st, _ = call(f"/api/intel/acode/{code}", RESEARCHER, role="researcher", user="lg-check-researcher")
    ok("the researcher it was sent to opens it", st == 200)
    st, _ = call(f"/api/intel/acode/{code}", RESEARCHER, role="researcher", user="lg-outsider")
    ok("a researcher outside its channel does not (as unknown)", st == 404)
    st, _ = call("/api/findings/1/reply", RESEARCHER, "POST", {"text": "sneaking in"}, role="researcher", user="lg-outsider")
    ok("…and cannot reply on its finding", st == 404)
    st, fl = call("/api/findings", RESEARCHER, role="researcher", user="lg-outsider")
    ok("…nor see it on the Findings page", st == 200 and not fl["findings"])
    st, _ = call(f"/api/combo-codes/{code}", ANALYST, user="lg-outsider")
    ok("an analyst outside the channel cannot look the code up", st == 404)
    reply_code = v["names"][0]["combinations"][0]["code"]
    st, r = call("/api/findings/1/reply", RESEARCHER, "POST", {"text": "Shares the C2 with another family.", "codes": [reply_code]},
                 role="researcher", user="lg-check-researcher")
    ok("the researcher replies on the finding with a code", st == 200 and r["finding"]["history"][-1]["kind"] == "reply"
       and r["finding"]["history"][-1]["codes"][0]["code"] == reply_code)
    ok("…and it goes back to the analyst who asked", r["finding"]["status"] == "analyst"
       and A.FINDINGS.get("1").get("assignee") == A.FINDINGS.get("1")["user"], r["finding"]["status"])
    st, r = call("/api/findings/1/reply", RESEARCHER, "POST", {"text": "x", "codes": ["LG-C-00000000"]}, role="researcher")
    ok("an unknown code in a reply is refused", st == 400)
    print("Management filters the Executive portal by it")
    st, m = call(f"/api/mgmt/comms?code={code}&day={day.start.date().isoformat()}", MGMT, role="management")
    ok("the Executive portal counts exactly the selection's devices, on its day", st == 200 and m["kpis"]["devices"] == 1 and m["kpis"]["events"] == len(want),
       f"{m.get('kpis', {}).get('devices')} devices, {m.get('kpis', {}).get('events')} events")
    ok("…with no address in the answer", ip not in json.dumps(m))
    st, m = call(f"/api/mgmt/services?code={code}", MGMT, role="management")
    ok("on the other platform it matches nothing", st == 200 and not m["kpis"]["hosts"])
    print("The analysts revisit it and report on it")
    st, lst = call("/api/analyst-codes", ANALYST)
    ok("the analysts' list holds it, with its finding", st == 200 and any(x["code"] == code and x["finding"]["number"] == "#1" for x in lst["codes"]))
    st, _ = call("/api/analyst-codes", RESEARCHER, role="researcher")
    ok("the list is for analysts only", st == 403)
    st, j = call("/api/combos/search", ANALYST, "POST", {"code": code})
    ok("the Combinations page searches an analyst code", st == 200, j.get("error", ""))
    jid = j["id"]; jids.append(jid)
    for _ in range(300):
        st, s = call(f"/api/combos/search/{jid}", ANALYST)
        if s.get("state") != "running":
            break
        time.sleep(0.2)
    ok("…and finds exactly its records again", s.get("state") == "done" and s["summary"]["records"] == len(want) and s["summary"]["devices"] == 1,
       f"{s.get('summary', {}).get('records')} records")
    st, z = call(f"/api/combos/search/{jid}/download", ANALYST, raw=True)
    names_in = zipfile.ZipFile(io.BytesIO(z)).namelist()
    ok("the report: PDF + devices CSV + records CSV", len(names_in) == 3 and any(n.endswith(".pdf") for n in names_in), ", ".join(names_in))
    ok("every step is in the audit log", {"analyst_code", "finding_reply", "combo_export"} <= set(audited), ", ".join(sorted(set(audited))))
    print("The finding says what the analyst asked for")
    st, fl = call("/api/findings", ANALYST)
    f1 = next((f for f in fl.get("findings") or [] if f["id"] == "1"), {})
    ok("a code made with “Everything”: the finding says so", (f1.get("codes") or [{}])[0].get("asked", "").startswith("Everything"),
       (f1.get("codes") or [{}])[0].get("asked", ""))
    st, d3 = call("/api/analyst-codes", ANALYST, "POST", {"platform": "comms", "kind": "filters", "value": value, "at": at, "focus": "across",
                                                          "to": "lg-check-researcher", "title": "Across reports only"})
    ok("the same selection asked across reports only is a code of its own", st == 200 and d3.get("code") not in (None, code), d3.get("code", ""))
    st, fl = call("/api/findings", ANALYST)
    f3 = next((f for f in fl.get("findings") or [] if f["number"] == d3.get("finding")), {})
    ok("…and its finding says “Just across-report combinations”", (f3.get("codes") or [{}])[0].get("asked", "").startswith("Just across-report"),
       (f3.get("codes") or [{}])[0].get("asked", ""))
    st, fr = call("/api/findings", RESEARCHER, role="researcher", user="lg-check-researcher")
    ok("the researcher it was sent to sees the same", any((f.get("codes") or [{}])[0].get("asked", "").startswith("Just across-report")
                                                          for f in fr.get("findings") or []))
finally:
    book.export_paths["dir"] = real_exports
    audit.add = real_add
    F.people_of = real_people
    A.ACODES.paths["ids"] = real_ids
    book.path, book.data, book.loaded, F.path, F.mtime, F.data = saved
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} analyst-code checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
