#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Notifications (notifications.py) end to end, in-process, on throwaway files (data/findings.json and
data/notifications.json untouched): a researcher sends a finding to a manager, who is notified (waiting for them), the
researcher is not (their own step), nobody outside the channel is; management's decision notifies the researcher and the
analyst named (waiting for them); a reply notifies the others; opening one clears it for that person only; Clear all
clears theirs; a clear needs the page's CSRF token and never touches another finding or another person; the links stay
on this site; no address anywhere.
Usage: tests/check_notifications.py"""
import json, os, re, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RES, MGR, ANA, OUT = "lg-n-researcher", "lg-n-management", "lg-n-analyst", "lg-n-outsider"


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def call(path, user, perms=("definitions",), method="GET", body=None, automation=True, token=None):
    headers = {"X-CSRF-Token": token} if token else {}
    with A.app.test_request_context(path, method=method, json=body, headers=headers):
        g.user = {"user": user, "role": "x", "perms": set(perms), "csrf": "the-page-token", "automation": automation}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, json.loads(r.get_data(as_text=True) or "{}")


def notes(user, perms=("definitions",)):
    st, d = call("/api/notifications", user, perms)
    return d if st == 200 else {"count": -1, "items": [], "error": d.get("error", st)}


tmp = tempfile.mkdtemp(prefix="lg-notif-")
F = A.FINDINGS
saved = (F.path, F.mtime, F.data, F.people_of, A.NOTIFS.path)
F.path, F.mtime, F.data = os.path.join(tmp, "findings.json"), None, {"seq": 0, "items": {}}
A.NOTIFS.path = os.path.join(tmp, "notifications.json")
F.people_of = lambda kind: [{"user": {"management": MGR, "analyst": ANA, "researcher": RES}.get(kind, ""), "name": kind, "role": kind}]
try:
    print("A researcher sends a finding to a manager")
    f1 = F.create({"id": "n1", "text": "Same C2 in two reports.", "codes": []}, "infections", "android.badbox2", "Shared C2", RES, "researcher",
                  to=MGR, kind="management")
    d = notes(MGR, ("management",))
    ok("the manager is notified, the finding waiting for them", d["count"] == 1 and d["items"][0]["waiting"] and d["items"][0]["id"] == f1["id"],
       json.dumps(d)[:160])
    ok("…with a link to the finding, on this site", d["items"][0]["link"] == f"/findings#f{f1['id']}")
    ok("the researcher is not notified of their own step", notes(RES)["count"] == 0)
    ok("nobody outside the channel is", notes(OUT, ("management",))["count"] == 0)
    print("Management decides: the analyst named and the researcher are notified")
    F.decide(f1["id"], True, "Pull the devices.", MGR, "management", ANA)
    d = notes(ANA, ("view", "unmasked", "export"))
    ok("the analyst named is notified, waiting for them", d["count"] == 1 and d["items"][0]["waiting"] and "approved" in d["items"][0]["text"],
       json.dumps(d["items"][:1])[:160])
    d = notes(RES)
    ok("the researcher sees the decision (not waiting for them)", d["count"] == 1 and not d["items"][0]["waiting"] and "Pull the devices" in d["items"][0]["text"])
    ok("the manager has no new one from their own decision… only the earlier", notes(MGR, ("management",))["count"] == 1)
    print("Clearing")
    st, x = call("/api/notifications/clear", MGR, ("management",), "POST", {"all": True}, automation=False, token="forged")
    ok("a clear without the page's token is refused", st == 403)
    st, x = call("/api/notifications/clear", MGR, ("management",), "POST", {"all": True}, automation=False, token="the-page-token")
    ok("Clear all clears the manager's", st == 200 and x["count"] == 0 and notes(MGR, ("management",))["count"] == 0, json.dumps(x))
    ok("…and only theirs: the researcher's and the analyst's stay", notes(RES)["count"] == 1 and notes(ANA, ("view", "unmasked", "export"))["count"] == 1)
    st, x = call("/api/notifications/clear", RES, ("definitions",), "POST", {"ids": ["999", f1["id"]]})
    ok("opening one clears it; an unknown finding is ignored", st == 200 and x["cleared"] == 1 and x["count"] == 0)
    f2 = F.create({"id": "n2", "text": "Another.", "codes": []}, "infections", "android.badbox2", "Other", RES, "researcher", to=MGR, kind="management")
    st, x = call("/api/notifications/clear", OUT, ("management",), "POST", {"ids": [f2["id"]]})
    ok("someone outside a finding cannot clear it for anyone", st == 200 and x["cleared"] == 0 and notes(MGR, ("management",))["count"] == 1)
    print("Later updates come back")
    F.reply(f1["id"], "Found 12 devices on two networks.", [], ANA, "analyst")
    d = notes(RES)
    ok("a new reply notifies the researcher again", d["count"] == 1 and "replied" in d["items"][0]["text"])
    ok("…and the manager, who cleared before", any(n["id"] == f1["id"] for n in notes(MGR, ("management",))["items"]))
    every = json.dumps([notes(u)["items"] for u in (RES, MGR, ANA)])
    ok("no address in any notification", not IP_RX.search(every))
    ok("every link is this site's own path", all(n["link"].startswith("/") and not n["link"].startswith("//")
                                                 for u in (RES, MGR, ANA) for n in notes(u)["items"]))
    st, _ = call("/api/notifications", "", ())
    ok("signed out: refused", st == 401)
finally:
    F.path, F.mtime, F.data, F.people_of, A.NOTIFS.path = saved
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} notification checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
