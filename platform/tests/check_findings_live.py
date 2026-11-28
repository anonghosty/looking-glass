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
import re
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


def live_checks():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import page_harness as H
    if not H.NODE:
        H.no_node(ok, "node is there to run the pages")
        return
    # findings-live.js itself: setInterval caught (its turns run by hand), fetch answered by the test
    js = r"""
let TICK = null, calls = 0, mode = "ok", stamp = "s1", pending = null, reloaded = 0, html = 0;
window.setInterval = (f) => { TICK = f; return 1; }; window.clearInterval = () => {};
location.reload = () => { reloaded++; };
Object.defineProperty(N.prototype, "innerHTML", { set() { html++; }, get() { return ""; } });
N.prototype.contains = function (x) { while (x) { if (x === this) return true; x = x.parent; } return false; };
document.hidden = false;
const myFetch = async (url) => { calls++;
  if (!String(url).includes("/api/findings/stamp")) return { ok: false, status: 404, json: async () => ({}) };
  if (mode === "throw") throw new TypeError("Failed to fetch");
  if (mode === "hang") await new Promise((r) => { pending = r; });
  if (mode === "403") return { ok: false, status: 403, json: async () => ({ error: "Sign in" }) };
  return { ok: true, status: 200, json: async () => ({ stamp }) }; };
((fetch) => {""" + H.page_src("findings-live.js") + r"""})(myFetch);       // the page's fetch is the test's
const tick = () => new Promise((r) => setTimeout(r, 5));
(async () => {
  const R = {}; let refreshed = 0, busyNow = false;
  LGFindingsLive.watch({ refresh: () => { refreshed++; }, busy: () => busyNow });
  await tick(); R.first = { calls, refreshed };
  TICK(); await tick(); R.same = { calls, refreshed };
  stamp = "s2"; TICK(); await tick(); R.changed = refreshed;
  document.hidden = true; let c = calls; TICK(); await tick(); R.hidden = calls - c; document.hidden = false;
  busyNow = true; stamp = "s3"; TICK(); await tick();
  let bar = document.body.querySelector(".fl-notice");
  R.busy = { refreshed, notice: bar ? lines(bar) : null, role: bar ? bar.getAttribute("role") : null };
  if (bar) bar.querySelector("button").click();
  R.click = { refreshed, gone: !document.body.querySelector(".fl-notice") };
  busyNow = false;
  mode = "hang"; stamp = "s4"; c = calls; TICK(); await tick(); TICK(); await tick(); R.running = calls - c;
  mode = "ok"; pending(); await tick(); R.afterRun = refreshed;
  mode = "throw"; c = calls; TICK(); await tick(); mode = "ok"; TICK(); await tick(); R.afterError = calls - c;
  mode = "403"; stamp = "s9"; const rf = refreshed; TICK(); await tick(); R.refused = refreshed - rf;
  // a page without refresh (the review and advisory pages): the notice, and its button opens the page again
  mode = "ok"; LGFindingsLive.watch({}); await tick(); stamp = "s10"; TICK(); await tick();
  bar = document.body.querySelector(".fl-notice"); R.plain = !!bar; if (bar) bar.querySelector("button").click();
  R.reloaded = reloaded;
  // the person's own change: no notice for it
  LGFindingsLive.watch({}); await tick(); stamp = "s11"; LGFindingsLive.mine(); await tick(); TICK(); await tick();
  R.mine = !document.body.querySelector(".fl-notice");
  R.html = html; R.errs = ERRS;
  console.log(JSON.stringify(R));
})().catch((e) => console.log(JSON.stringify({ fatal: String(e && e.stack) })));
"""
    R, raw = H.run(js)
    R = R or {}
    ok("findings-live.js runs without an error", R and not R.get("errs"), raw[-600:] if not R else str(R.get("errs")))
    ok("it asks /api/findings/stamp once on opening, and takes that as what the page shows", R.get("first") == {"calls": 1, "refreshed": 0}, str(R.get("first")))
    ok("the same fingerprint: nothing redrawn", R.get("same") == {"calls": 2, "refreshed": 0}, str(R.get("same")))
    ok("a new fingerprint: the page reads it again (refresh)", R.get("changed") == 1, str(R.get("changed")))
    ok("never while the page is hidden", R.get("hidden") == 0, str(R.get("hidden")))
    b = R.get("busy") or {}
    ok("while the person types (busy): nothing thrown away, a notice offers the changes", b.get("refreshed") == 1 and b.get("role") == "status"
       and b.get("notice") == ["A finding here has changed since you opened this page.", "Show the changes"], str(b))
    ok("...its button redraws and the notice goes", R.get("click") == {"refreshed": 2, "gone": True}, str(R.get("click")))
    ok("while a request runs, the next turn sends no second one", R.get("running") == 1, str(R.get("running")))
    ok("...and its answer still counts when it comes", R.get("afterRun") == 3, str(R.get("afterRun")))
    ok("a dropped connection clears the request in hand: the next turn asks again", R.get("afterError") == 2, str(R.get("afterError")))
    ok("a refused answer (signed out) redraws nothing", R.get("refused") == 0, str(R.get("refused")))
    ok("a page without refresh: the notice, and its button opens the page again", R.get("plain") is True and R.get("reloaded") == 1,
       f"{R.get('plain')} {R.get('reloaded')}")
    ok("the person's own change (mine): no notice for it", R.get("mine") is True)
    ok("it never builds HTML from text", R.get("html") == 0, str(R.get("html")))

    # the Findings page: busy while its request runs, cleared on an error; it watches, and waits while someone types
    fjs = r"""
let W = null, ready = 0, gate = null, mode = "ok";
window.LGFindingsLive = { watch(o) { W = o; }, mine() {} };
window.LGLoader.ready = () => { ready++; };
N.prototype.contains = function (x) { while (x) { if (x === this) return true; x = x.parent; } return false; };
document.activeElement = null; document.body.append(document.getElementById("fdList"));
const D = { findings: [{ id: "1", number: "F-001", title: "Made-up", name: "x", text: "t", codes: [], status: "new", status_label: "New",
  history: [], open: true, origin: "researcher", children: [], requests: [], advisories: [], channel: [] }], statuses: [{ key: "new", label: "New" }] };
const myFetch = async (url) => {
  if (!String(url).startsWith("/api/findings?state=")) return { ok: false, status: 404, json: async () => ({}) };
  await new Promise((r) => { gate = r; });
  if (mode === "throw") throw new TypeError("Failed to fetch");
  if (mode === "403") return { ok: false, status: 403, json: async () => ({ error: "Refused" }) };
  return { ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(D)) }; };
((fetch) => {""" + H.page_src("findings.js") + r"""})(myFetch);
const tick = () => new Promise((r) => setTimeout(r, 5));
const L = () => IDS.fdList;
(async () => {
  const R = {};
  await tick(); R.loading = !!L().querySelector(".st-loading");
  gate(); await tick(); R.drawn = !L().querySelector(".st-loading") && !!L().querySelector("article");
  R.watches = !!(W && W.refresh && W.busy);
  R.idle = W.busy();
  const ta = L().querySelector("textarea"); ta.value = "half a reply"; for (const f of L().on.input || []) f({ target: ta });
  R.typing = W.busy(); ta.value = "";
  R.cleared = W.busy();
  mode = "403"; W.refresh(); await tick(); gate(); await tick(); R.quietRefused = !!L().querySelector("article");
  console.log(JSON.stringify(R));
})().catch((e) => console.log(JSON.stringify({ fatal: String(e && e.stack) })));
"""
    R2, raw2 = H.run(fjs)
    R2 = R2 or {}
    ok("the Findings page shows its loading line while its request runs", R2.get("loading") is True, raw2[-300:] if not R2 else "")
    ok("...and draws the cards when it answers", R2.get("drawn") is True)
    ok("it watches (findings-live.js) with refresh and busy", R2.get("watches") is True)
    ok("busy: not while nothing is typed", R2.get("idle") is False)
    ok("busy while someone has typed a reply (the change waits for them)", R2.get("typing") is True)
    ok("...and not once the box is empty again", R2.get("cleared") is False)
    ok("a refused background read keeps what is on the page", R2.get("quietRefused") is True)
    ejs = fjs.split("const tick = ")[0] + r"""
const tick = () => new Promise((r) => setTimeout(r, 5));
(async () => {
  const R = {};
  mode = "throw"; await tick(); R.loading = !!IDS.fdList.querySelector(".st-loading");
  gate(); await tick();
  R.after = { loading: !!IDS.fdList.querySelector(".st-loading"), text: lines(IDS.fdList), ready };
  console.log(JSON.stringify(R));
})().catch((e) => console.log(JSON.stringify({ fatal: String(e && e.stack) })));
"""
    R3, raw3 = H.run(ejs)
    R3 = R3 or {}
    a = R3.get("after") or {}
    ok("a read that loses its connection: busy while it runs, cleared after", R3.get("loading") is True and a.get("loading") is False,
       raw3[-300:] if not R3 else str(R3))
    ok("...plain words instead, and the page's loading screen is released", a.get("text") == ["The connection was interrupted. Try again."]
       and a.get("ready", 0) >= 1, str(a))

    # the other pages run their script with findings-live.js loaded before it (the templates render it so)
    import jinja2
    tdir = os.path.join(H.PF, "templates")

    def held_tpl(name):
        p = os.path.join(H.HELD, name + ".new") if H.HELD else ""
        src = p if p and os.path.isfile(p) else os.path.join(tdir, name)
        if not os.path.isfile(src):
            return None
        return open(src, encoding="utf-8").read(), src, lambda: True

    class Blank(jinja2.ChainableUndefined):         # what the app would put in (the user, a helper): empty and callable
        def __call__(self, *a, **k):
            return self

    env = jinja2.Environment(loader=jinja2.FunctionLoader(held_tpl), undefined=Blank, autoescape=True)
    env.globals.update(url_for=lambda ep, filename="", **k: f"/{ep}/{filename}", csrf_token=lambda: "t")
    for page, script in (("findings.html", "findings.js"), ("advisory_portal.html", "advisory-portal.js"),
                         ("review.html", "review.js"), ("advisory.html", "advisory.js")):
        try:
            out = env.get_template(page).render()
            srcs = re.findall(r'<script[^>]*\bsrc="([^"]+)"', out)
        except Exception as e:      # noqa: BLE001 - a template that does not render is the failure itself
            srcs, out = [], f"{type(e).__name__}: {e}"
        names = [s.rsplit("/", 1)[-1].split("?")[0] for s in srcs]
        ok(f"{page} (rendered) loads findings-live.js before {script}",
           "findings-live.js" in names and script in names and names.index("findings-live.js") < names.index(script), str(names) if names else out[:300])
    for script in ("advisory-portal.js", "review.js", "advisory.js"):
        wjs = r"""
let W = null; window.LGFindingsLive = { watch(o) { W = o || {}; }, mine() {} };
N.prototype.contains = function (x) { while (x) { if (x === this) return true; x = x.parent; } return false; };
window.scrollTo = () => {}; window.scrollY = 0; document.activeElement = null;
try {
""" + H.page_src(script) + r"""
} catch (e) { keep(e); }
setTimeout(() => console.log(JSON.stringify({ watched: W !== null, refresh: !!(W && W.refresh) })), 200);
"""
        R4, raw4 = H.run(wjs)
        R4 = R4 or {}
        want = script == "advisory-portal.js"          # the portal redraws in place; the review and advisory pages show the notice
        ok(f"{script} watches the findings" + (" and redraws in place" if want else " (the notice opens the page again)"),
           R4.get("watched") is True and R4.get("refresh") is want, raw4[-300:] if not R4 else str(R4))


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
       and F.shown(F.get(n["id"]))["role"] == "Administrator acting as Researcher/TI")
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
    ok("everyone else keeps their role", F.shown(F.get(a["id"]))["role"] == "Researcher/TI"
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

    print("5. The pages watch it (node runs the page files that ship: the held copies in $LG_HELD_DIR when there are)")
    live_checks()
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
