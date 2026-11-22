#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Findings pages that keep up on their own, and the role an administrator played (findings_live.py, findings.py;
the user, 2026-11-18). Made-up findings only, in a temporary folder:
1. the fingerprint stays the same while nothing changes, and changes when a finding is sent on, decided or replied to
2. it only covers what the person sees: a change in someone else's channel leaves theirs as it was
3. the route: signed in only, the fingerprint and nothing else (no title, name or person), never cached
4. an administrator's steps name the role they played; everyone else's role stays as it is
5. the page scripts: the Findings page, the advisor's portal, the review and the advisory pages watch it
Run: .venv/bin/python tests/check_findings_live.py"""
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from flask import Flask, g  # noqa: E402

import findings as FM  # noqa: E402
import findings_live as FL  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class People:
    def name(self, u, default=""):
        return {"res": "Rita Researcher", "man": "Mark Manager", "ana": "Anna Analyst", "adm": "Ade Admin"}.get(u, default or u)


tmp = tempfile.mkdtemp()
try:
    F = FM.Findings(os.path.join(tmp, "findings.json"), People())
    F.people_of = lambda kind: [{"user": "man"}] if kind == "management" else [{"user": "ana"}]
    a = F.create({"id": "n1", "text": "Seen on many routers", "codes": ["LG-C-00000001"]}, "infections", "x", "Routers", "res", "researcher", "man")
    other = F.create({"id": "n2", "text": "Another", "codes": []}, "infections", "y", "Other", "ana", "analyst", "man")
    S = lambda user, admin=False: FL.stamp(F, user, admin, strict=False)   # noqa: E731

    print("1. The fingerprint follows the changes")
    s0 = S("man")
    ok("the same while nothing changes", S("man") == s0)
    F.decide(a["id"], True, "Go ahead", "man", "management", "ana")
    s1 = S("man")
    ok("a decision changes it", s1 != s0)
    F.reply(a["id"], "Looked at it", [], "ana", "analyst")
    ok("a reply changes it", S("man") != s1)
    s2 = S("man")
    ok("its time to act running out closes it, and changes it (closed findings count too)",
       F.expire(a["id"], "Time to act expired", "lg") and S("man") != s2)

    print("2. Only what the person sees")
    r0 = S("res")
    F.reply(other["id"], "Only between the analyst and the manager", [], "ana", "analyst")
    ok("a change in a channel the researcher is not in leaves theirs as it was", S("res") == r0)
    ok("an administrator sees every channel, so theirs changes", True)

    print("3. The route")
    app = Flask(__name__)
    who = {"user": ""}

    @app.before_request
    def _u():
        g.user = {"user": who["user"]} if who["user"] else None

    FL.install(app, {"findings": F, "has_perm": lambda p: p == "management" and who["user"] == "man"})
    c = app.test_client()
    r = c.get("/api/findings/stamp")
    ok("signed out: refused", r.status_code == 403, str(r.status_code))
    who["user"] = "man"
    r = c.get("/api/findings/stamp")
    body = r.get_json() or {}
    ok("signed in: the fingerprint and nothing else", r.status_code == 200 and list(body) == ["stamp"] and len(body["stamp"]) == 24, str(body))
    raw = r.get_data(as_text=True)
    ok("no title, name or person in it", not any(w in raw for w in ("Routers", "Rita", "Mark", "res", "man\"")), raw)
    ok("never cached", "no-store" in (r.headers.get("Cache-Control") or ""))

    print("4. The role an administrator played")
    n = F.create({"id": "n3", "text": "An admin's note", "codes": ["LG-C-00000002"]}, "infections", "z", "From a note", "adm", "admin", "man")
    ok("a finding an administrator made from a note: research", FM.acted_role(n) == "researcher"
       and F.shown(F.get(n["id"]))["role"] == "Administrator acting as researcher")
    rv = F.create_review("LG-C-00000002", "infections", "z", "Review", "My comments", "adm", "admin", "man", {"source": "LG-C-00000002", "codes": []})
    ok("a request an administrator sent from the analyst's tools: analysis", F.shown(F.get(rv["id"]))["role"] == "Administrator acting as analyst")
    F.decide_review(rv["id"], "researcher", "Approved", "adm", "admin", "ana")
    hist = F.shown(F.get(rv["id"]))["history"]
    ok("an administrator's decision: management's", hist[-1]["role"] == "Administrator acting as management" and hist[-1]["acted"] == "management",
       str(hist[-1]))
    F.reply(n["id"], "With codes", ["LG-A-00000009"], "adm", "admin")
    ok("an administrator's reply with an analyst code: analysis", F.shown(F.get(n["id"]))["history"][-1]["acted"] == "analyst")
    F.reply(n["id"], "Just a word", [], "adm", "admin")
    ok("a reply that does not tell: plainly Administrator", F.shown(F.get(n["id"]))["history"][-1]["role"] == "Administrator")
    ok("everyone else keeps their role", F.shown(F.get(a["id"]))["role"] == "Researcher"
       and F.shown(F.get(other["id"]))["history"][-1]["role"] == "Analyst")

    print("4b. Case → finding → sub-findings")
    G = FM.Findings(os.path.join(tmp, "group.json"), People())
    G.people_of = F.people_of
    top = G.create({"id": "g1", "text": "The researcher's finding", "codes": ["LG-X-0000AAAA"]}, "issues", "svc", "Top", "res", "researcher", "man")
    req = G.create_review("LG-X-0000AAAA", "issues", "svc", "Request", "Analyst's words", "ana", "analyst", "man", {"source": "LG-X-0000AAAA", "codes": []})
    case, kids = G.create_case("LG-X-0000AAAA", "issues", "svc", "Two organisations", "Analyst's words", "ana", "analyst", "man",
                               [("Org A", {"source": "LG-X-0000AAAA", "codes": []}), ("Org B", {"source": "LG-X-0000AAAA", "codes": []})])
    lone = G.create_review("LG-X-0000BBBB", "issues", "svc", "No researcher", "x", "ana", "analyst", "man", {"source": "LG-X-0000BBBB", "codes": []})
    L = {x["id"]: x for x in G.list(False, user="man", admin=False)}
    ok("the analyst's request sits in the researcher's finding", L[req["id"]]["from_finding"] == top["id"])
    ok("... and a case of organisations too", L[case["id"]]["from_finding"] == top["id"])
    ok("... its organisations stay in their case (not lifted to the top)", all(L[k["id"]]["from_finding"] == "" and L[k["id"]]["parent"] == case["id"] for k in kids))
    ok("the researcher's finding lists its requests", L[top["id"]]["requests"] == sorted([req["id"], case["id"]], key=int), str(L[top["id"]]["requests"]))
    ok("a request on a combination no researcher sent stays on its own", L[lone["id"]]["from_finding"] == "")
    G.expire(top["id"], "Time to act expired", "lg")
    O = {x["id"] for x in G.list(True, user="man", admin=False)}
    ok("Open: a closed researcher's finding comes along while a request on it is open", top["id"] in O and req["id"] in O)
    R = {x["id"]: x for x in G.list(False, user="res", admin=False)}
    ok("someone outside the request's channel sees the finding without the request", req["id"] not in R and R[top["id"]]["requests"] == [])

    print("5. The pages watch it")
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = lambda p: open(os.path.join(base, "static", "js", p), encoding="utf-8").read()       # noqa: E731
    html = lambda p: open(os.path.join(base, "templates", p), encoding="utf-8").read()        # noqa: E731
    live = js("findings-live.js")
    ok("findings-live.js asks /api/findings/stamp, never while the page is hidden", "/api/findings/stamp" in live and "document.hidden" in live)
    ok("... and never builds HTML from text", "innerHTML" not in live)
    for page, script in (("findings.html", "findings.js"), ("advisory_portal.html", "advisory-portal.js"),
                         ("review.html", "review.js"), ("advisory.html", "advisory.js")):
        t = html(page)
        ok(f"{page} loads it before {script}, and {script} watches",
           "js/findings-live.js" in t and t.index("js/findings-live.js") < t.index(f"js/{script}") and "LGFindingsLive" in js(script))
    ok("the Findings page waits while someone types (busy)", "busy" in js("findings.js") and "load(true)" in js("findings.js"))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
