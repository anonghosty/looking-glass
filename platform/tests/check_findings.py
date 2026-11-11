#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Findings (findings.py) end to end, in-process, on throwaway files (data/notes.json and data/findings.json untouched):
a researcher tracks a note as a finding (with a combination code), it gets a number and the status New; management,
the analysts and the researchers all see it, without any address; each moves it on with a comment, every move is in the
history and the audit log; closed findings leave the Open list; removing the note keeps the finding; external is refused.
Usage: tests/check_findings.py"""
import json, os, re, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
import auth  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
ANALYST, RESEARCHER, MGMT = {"view", "unmasked", "export", "malpedia"}, {"definitions", "networks"}, {"management"}


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, perms, method="GET", body=None, role="researcher", user="lg-check"):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": user, "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, json.loads(r.get_data(as_text=True) or "{}")


tmp = tempfile.mkdtemp(prefix="lg-findings-")
saved = {o: (o.path, o.mtime, o.data) for o in (A.NOTES, A.FINDINGS)}
A.NOTES.path, A.NOTES.mtime, A.NOTES.data = os.path.join(tmp, "notes.json"), None, {"infections": {}, "issues": {}}
A.FINDINGS.path, A.FINDINGS.mtime, A.FINDINGS.data = os.path.join(tmp, "findings.json"), None, {"seq": 0, "items": {}}
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append(a[0] if a else k.get("event"))
real_people = A.FINDINGS.people_of           # the accounts that do each job: test accounts here
A.FINDINGS.people_of = lambda kind: [{"user": f"lg-check-{kind}", "name": f"Check {kind}", "role": kind}]
try:
    A.store.get(A.replay_now())
    gat = A.INTEL.gathered("infections", "android.badbox2")
    code0 = next((c["code"] for r in gat["reports"] for c in r["combinations"]), None)
    print("A researcher tracks a note as a finding, sent to a manager")
    st, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": "android.badbox2", "text": "No recipient.", "finding": {"title": "x"}})
    ok("a finding without the manager it goes to is refused (and no note is saved)", st == 400 and "manager" in d.get("error", "")
       and not any(n["text"] == "No recipient." for n in A.NOTES.list("infections", "android.badbox2")), d.get("error", ""))
    st, d = call("/api/findings/people?kind=management", RESEARCHER)
    ok("the managers to choose from are listed (names only)", st == 200 and d["people"] and set(d["people"][0]) == {"user", "name", "role"})
    st, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": "android.badbox2", "text": "Test: a new C2 cluster.",
                                                     "codes": [code0] if code0 else [], "finding": {"title": "Test cluster", "to": "lg-check-management"}})
    ok("the note is saved", st == 200, f"HTTP {st} {d.get('error', '')}")
    mine = next((n for n in d.get("notes", []) if n["id"] == d.get("note", {}).get("id")), {})
    ok("…and carries its finding number, with management", (mine.get("finding") or {}).get("number") == "#1" and mine["finding"]["status"] == "management", str(mine.get("finding")))
    print("Only the people in its channel see it")
    st, d = call("/api/findings", MGMT, role="management", user="lg-check-management")
    ok("the manager it was sent to sees it, held by them", st == 200 and d["findings"] and d["findings"][0]["assignee"] == "lg-check-management")
    st, d = call("/api/findings", MGMT, role="management", user="lg-other-manager")
    ok("another manager does not", st == 200 and not d["findings"])
    st, d = call("/api/findings/1/status", MGMT, "POST", {"status": "closed", "comment": "x"}, role="management", user="lg-other-manager")
    ok("…and cannot move it (as unknown)", st == 404)
    st, d = call("/api/findings", ANALYST, role="analyst", user="lg-check-analyst")
    ok("an analyst not yet in it does not see it", st == 200 and not d["findings"])
    st, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": "android.badbox2", "text": "Just a note."})
    ok("a note not tracked makes no finding", st == 200 and not any(n.get("finding") for n in d["notes"] if n["text"] == "Just a note."))
    print("Everyone who works on it sees it, without addresses")
    for role, perms in (("researcher", RESEARCHER), ("management", MGMT), ("analyst", ANALYST)):
        st, d = call("/api/findings", perms, role=role)
        f = (d.get("findings") or [{}])[0]
        ok(f"{role}: sees finding #1 with its title, name, note and code", st == 200 and f.get("number") == "#1" and f.get("title") == "Test cluster"
           and (not code0 or f["codes"][0]["code"] == code0), f"HTTP {st}")
        ok(f"{role}: no address anywhere in the answer", not IP_RX.search(json.dumps(d)))
    ok("only roles that see addresses get the Search button", call("/api/findings", ANALYST, role="analyst")[1]["can_search"]
       and not call("/api/findings", MGMT, role="management")[1]["can_search"])
    st, d = call("/api/findings", {"view"}, role="external", user="lg-check-external")
    ok("external opens the Findings page, but sees no finding it is not in (not even one made before channels)",
       st == 200 and d.get("findings") == [], f"HTTP {st} · {len(d.get('findings') or [])} findings")
    ok("researchers and management can open the page (their allowed paths)", "/findings".startswith(auth.DEFINITIONS_PATHS) and "/api/findings".startswith(auth.MANAGEMENT_PATHS))
    print("Moving it on")
    st, d = call("/api/findings/1/status", MGMT, "POST", {"status": "analyst", "comment": "x"}, role="management", user="lg-check-management")
    ok("a hand-over without the analyst it goes to is refused", st == 400)
    st, d = call("/api/findings/1/status", MGMT, "POST", {"status": "analyst", "comment": "Rising in the north: pull the devices.", "to": "lg-check-analyst"},
                 role="management", user="lg-check-management")
    ok("management moves it to the analyst they name, with a comment", st == 200 and d["finding"]["status"] == "analyst"
       and d["finding"]["history"][-1]["comment"].startswith("Rising") and d["finding"]["history"][-1]["to"] == "lg-check-analyst")
    st, d = call("/api/findings", ANALYST, role="analyst", user="lg-check-analyst")
    ok("…who now sees it, with its whole trail", st == 200 and d["findings"] and len(d["findings"][0]["history"]) == 2 and len(d["findings"][0]["channel"]) == 3)
    st, d = call("/api/findings/1/status", ANALYST, "POST", {"status": "advisory", "comment": "Advisory sent to the affected networks."}, role="analyst", user="lg-check-analyst")
    ok("the analyst marks the advisory sent", st == 200 and len(d["finding"]["history"]) == 3, f"{len(d.get('finding', {}).get('history', []))} steps")
    st, d = call("/api/findings/1/status", ANALYST, "POST", {"status": "nonsense"}, role="analyst")
    ok("an unknown status is refused", st == 400)
    st, d = call("/api/findings/99/status", ANALYST, "POST", {"status": "closed"}, role="analyst")
    ok("an unknown finding: 404", st == 404)
    st, d = call("/api/findings/1/status", {"view"}, "POST", {"status": "closed"}, role="external", user="lg-check-external")
    ok("external cannot move it (to them it does not exist)", st == 404)
    with A.FINDINGS.lock:                                 # a finding made before channels: open to the team, never to the others
        A.FINDINGS._load(); A.FINDINGS.data["items"]["900"] = {"id": "900", "note": None, "section": "infections", "name": "x", "title": "Old",
                                                               "text": "", "codes": [], "user": "someone", "role": "researcher", "at": 1.0,
                                                               "status": "new", "history": [{"status": "new", "user": "someone", "role": "researcher",
                                                                                             "at": 1.0, "comment": ""}]}
        A.FINDINGS._save()
    ok("an old finding without a channel: still open to the team", any(f_["id"] == "900" for f_ in call("/api/findings?state=all", MGMT, role="management")[1]["findings"]))
    ok("…never to the other roles", not call("/api/findings?state=all", {"view"}, role="external", user="lg-check-external")[1]["findings"]
       and call("/api/findings/900/status", {"view"}, "POST", {"status": "closed"}, role="external", user="lg-check-external")[0] == 404)
    with A.FINDINGS.lock:
        A.FINDINGS._load(); A.FINDINGS.data["items"].pop("900", None); A.FINDINGS._save()
    call("/api/findings/1/status", MGMT, "POST", {"status": "closed"}, role="management")
    ok("a closed finding leaves the Open list", not call("/api/findings?state=open", MGMT, role="management")[1]["findings"])
    ok("…and stays in All", len(call("/api/findings?state=all", MGMT, role="management")[1]["findings"]) == 1)
    nid = next(n["id"] for n in A.NOTES.list("infections", "android.badbox2") if n.get("finding"))
    A.NOTES.delete(nid, "lg-check", True)
    ok("removing the note keeps the finding (it holds its own copy)", call("/api/findings?state=all", MGMT, role="management")[1]["findings"][0]["text"].startswith("Test:"))
    print("Management decides first, then moves it on to the person it names")
    st, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": "android.badbox2", "text": "Test: second.",
                                                     "finding": {"title": "Second", "to": "lg-check-management"}})
    st, d = call("/api/findings/2/decision", MGMT, "POST", {"decision": "accept", "text": "Generate the advisory for the three operators."},
                 role="management", user="lg-check-management")
    ok("approving needs the analyst it goes to", st == 400, d.get("error", ""))
    st, d = call("/api/findings/2/decision", MGMT, "POST", {"decision": "accept", "text": "Generate the advisory for the three operators.",
                                                             "to": "lg-check-analyst"}, role="management", user="lg-check-management")
    ok("approving with a comment sends it straight to the analyst named", st == 200 and d["finding"]["status"] == "analyst"
       and A.FINDINGS.get("2").get("assignee") == "lg-check-analyst", d.get("error", ""))
    st, d = call("/api/findings/2/decision", MGMT, "POST", {"decision": "accept", "text": "again", "to": "lg-check-analyst"},
                 role="management", user="lg-check-management")
    ok("…once", st == 400)
    st, d = call("/api/findings/2/decision", MGMT, "POST", {"decision": "reject", "text": "x"}, role="management", user="lg-check-management")
    ok("once it is with the analyst there is nothing left to decide", st == 400 and "not with management" in d.get("error", ""), d.get("error", ""))
    st, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": "android.badbox2", "text": "Test: third.",
                                                     "finding": {"title": "Third", "to": "lg-check-management"}})
    st, d = call("/api/findings/3/decision", MGMT, "POST", {"decision": "reject", "text": "Not enough evidence."}, role="management", user="lg-check-management")
    ok("rejecting with the reason closes it", st == 200 and d["finding"]["status"] == "closed")
    ok("every step is in the audit log", {"finding_created", "finding_status", "finding_decision"} <= set(audited), ", ".join(sorted(set(audited))))
finally:
    audit.add = real_add
    A.FINDINGS.people_of = real_people
    for o, (p, m, dd) in saved.items():
        o.path, o.mtime, o.data = p, m, dd
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} findings checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
