#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The page-script bugs the 2026-11-27 whole-codebase audit found (batch 10), each kept fixed. These are browser
scripts and the suite has no JavaScript engine, so each check reads the page file itself (the held copy
$LG_HELD_DIR/<name>.new when LG_HELD_DIR is set and holds it, else static/js/<name>) and checks the exact code of the fix:
  10-1  combos-enrich.js: the ticks of an earlier search are cleared when the next search's box is built;
  10-2  findings.js: a quiet refresh that loses the connection keeps the list (and a reply being written);
  10-3  findings.js: what is being written in a card is kept by finding and field and put back after a redraw;
  10-4  intelligence.js: only the newest read of a report's view draws;
  10-5  lg-select.js: Enter in the search picks the first match, passing over only the empty option;
  10-6  intel.js / kb-services.js: the keyboard focus stays in place when the pane or table is drawn again;
  10-7  intelligence.js: one Escape listener for the host box, removed however the box closes;
  10-8  config-page.js: "Use the default" clears the "outside its range" mark;
  10-9  kb-settings.js: the issues table draws the first 400 and says so;
  10-10 kb-notes.js: the always-hidden tabs and the code only they reached are gone;
  10-11 findings.js / findings-live.js: a person's own change is taken as known, not shown as someone else's;
  10-12 connectors-admin.js: no "..." in the address hints;
  10-13 combos-enrich.js: a refused read of the search's state is said, not read as a state;
  10-14 glossary.js: the services platform's heatmap is the chosen country's, not "Ghana";
  extra combos.js: the analyst-code picker says "The first 40 of N" when more match.
Run: .venv/bin/python tests/check_fix_b10.py   (LG_HELD_DIR=<folder>: check the held .new page files)"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELD = os.environ.get("LG_HELD_DIR", "")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


def page(name):
    held = os.path.join(HELD, f"{name}.new") if HELD else ""
    p = held if held and os.path.exists(held) else os.path.join(ROOT, "static", "js", name)
    try:
        return open(p, encoding="utf-8").read()
    except OSError as e:
        ok(f"{name} can be read", False, str(e))
        return ""


def body(src, head, end_marker="\n  }\n"):
    """the text of a function from its head to the end of its block (two-space indented closing brace)"""
    i = src.find(head)
    if i < 0:
        return ""
    j = src.find(end_marker, i)
    return src[i:j if j > 0 else len(src)]


print("10-1 combos-enrich.js: ticks belong to one search")
ce = page("combos-enrich.js")
tf = re.search(r"const ticksFor = \(job\) => \{(.*?)\};", ce, re.S)
ok("a function clears the three tick sets when the search changes",
   bool(tf) and all(f"{s}.clear()" in tf.group(1) for s in ("ticked", "tickedInf", "tickedIss")) and "tickJob !== job" in tf.group(1))
bx = body(ce, "  function box(job, s, entry) {")
ok("the box of a search starts by taking its own ticks", bool(bx) and bx.index("ticksFor(job)") < bx.index("fetch(`/api/combos/search/${job}`")
   if "ticksFor(job)" in bx else False)

print("10-13 combos-enrich.js: the search's state is read only from an answer that was accepted")
ok("the state read checks r.ok and throws on a refusal",
   bool(re.search(r"fetch\(`/api/combos/search/\$\{job\}`, \{ cache: \"no-store\" \}\)\.then\(async \(r\) => \{\s*const st = await r\.json\(\)\.catch\(\(\) => \(\{\}\)\);\s*if \(!r\.ok\) throw", ce)))
ok("no state is read straight from an unchecked answer", ".then((r) => r.json()).then((st)" not in ce)

fd = page("findings.js")
print("10-2 findings.js: a quiet refresh that loses the connection keeps the page")
ld = body(fd, "  async function load(quiet) {")
cat = ld[ld.find("} catch {"):ld.find("if (seq !== loadSeq) return;\n    if (!r.ok)")] if "} catch {" in ld else ""
ok("the catch returns for a quiet refresh before it replaces the list",
   "if (quiet) return;" in cat and cat.index("if (quiet) return;") < cat.index('$("fdList").replaceChildren') if '$("fdList").replaceChildren' in cat else False, cat[:200])

print("10-3 findings.js: what is being written survives a redraw")
ok("a drafts map, kept by finding and field", "const drafts = new Map();" in fd and "node.dataset.draft = `${f.id}|${key}`;" in fd
   and "if (v != null) node.value = v;" in fd)
ok("every input in the list records its draft", 'if (e.target.dataset?.draft) drafts.set(e.target.dataset.draft, e.target.value);' in fd)
for key, var in (("reply", "rta"), ("codes", "rcodes"), ("decide", "dta"), ("move", "com"), ("review", "ta")):
    ok(f"the {key} field is kept ({var})", f'keep(f, "{key}", {var})' in fd)
ok("the advisory's recipients are kept", "keep(f, `sent:${a.network || \"\"}`, rec);" in fd)
ok("a reply being written keeps its box open", "if (kept.some(Boolean)) rp.open = true;" in fd)
ok("a sent reply, decision or move forgets its draft (4 places)", fd.count("done(f); Object.assign(f, d.finding);") == 4, fd.count("done(f); Object.assign"))

print("10-11 findings.js / findings-live.js: a person's own change is theirs")
ok("findings.js tells the live watch after its own actions", "const done = (f) => { forget(f); window.LGFindingsLive?.mine(); };" in fd
   and "window.LGFindingsLive?.mine(); load();" in fd)
fl = page("findings-live.js")
ok("mine() during a check on its way takes the fingerprint again afterwards",
   "mine() { base = null; if (asking) again = true; else check(); }," in fl and "if (again) { again = false; base = null; check(); }" in fl)

print("10-4 intelligence.js: only the newest read draws")
it = page("intelligence.js")
fv = body(it, "  async function fetchView(scroll) {")
ok("a sequence number per read", "const seq = ++viewSeq;" in fv)
ok("an older answer stops before it draws (answer and failure)", fv.count("if (seq !== viewSeq) return;") == 2
   and fv.rindex("if (seq !== viewSeq) return;") < fv.index("drawView(pane, d);") if "drawView(pane, d);" in fv else False)

print("10-7 intelligence.js: one Escape listener for the host box")
hv = body(it, "  async function hostView(ip, from) {")
ok("the previous box's listener is removed when a new box opens",
   'if (hostKey) { document.removeEventListener("keydown", hostKey); hostKey = null; }' in hv)
ok("Close removes the listener too (one shut for Close and Escape)", 'x.addEventListener("click", shut);' in hv
   and 'document.removeEventListener("keydown", onKey)' in hv[hv.find("const shut"):hv.find("const onKey")])

print("10-5 lg-select.js: Enter picks the first match")
ls = page("lg-select.js")
ok("the empty option is passed over, nothing else", 'items.find((b) => b.dataset.value !== "") || items[0]' in ls)
ok("the old 'second item' rule is gone", "items[1] && search.value ? items[1] : items[0]" not in ls)

print("10-6 intel.js / kb-services.js: focus stays in place")
ig = page("intel.js")
pt = body(ig, "  function paint(scrollTop) {")
ok("intel.js paint() redraws through paintNow and puts the focus back", "paintNow(scrollTop);" in pt and "focus({ preventScroll: true })" in pt
   and "function paintNow(scrollTop) {" in ig)
ks = page("kb-services.js")
ok("kb-services.js: '+N more' / 'show fewer' gives the focus back to its row's button",
   "tr.dataset.report = x.name;" in ks and '$("svcTable").querySelector(`tr[data-report="${CSS.escape(x.name)}"] .svc-more`)?.focus();' in ks)

print("10-8 config-page.js: 'Use the default' clears the mark")
cp = page("config-page.js")
ok("the range check is one function, run when the row is drawn", "const check = () => {" in cp and "      check();\n      inp.addEventListener" in cp)
ok("Use the default runs it after clearing the value",
   'back.addEventListener("click", () => { edits.set(i.key, ""); inp.value = ""; inp.placeholder = `default ${fmt(i.default)}`; check(); state(); });' in cp)

print("10-9 kb-settings.js: the issues table is cut at 400, and says so")
kss = page("kb-settings.js")
ri = body(kss, "  function renderIss() {")
ok("the first 400 rows", "for (const x of rows.slice(0, 400))" in ri)
ok("'Showing 400 of N' when there are more", "if (rows.length > 400)" in ri and "Showing 400 of ${fmt(rows.length)}" in ri)

print("10-10 kb-notes.js: no dead tabs")
kn = page("kb-notes.js")
ok("only the Paste tab", '"Paste a code"' in kn and '"Seen in the reports"]' not in kn and '["build", "Build one"]' not in kn)
ok("the code only those tabs reached is gone", all(x not in kn for x in ("function seenPane", "function buildPane", "async function ensureIntel")))
ok("renderPane draws the paste pane", "function renderPane() { pastePane(); }" in kn)

print("10-12 connectors-admin.js: no '...' hint")
ca = page("connectors-admin.js")
ok('no "https://..." anywhere', "https://..." not in ca)

print("10-14 glossary.js: the heatmap is the chosen country's")
gl = page("glossary.js")
ok('no "Ghana regions heatmap"', "Ghana regions heatmap" not in gl)
ok("the services platform entry names the country chosen in Settings", "a heatmap of the regions of the country chosen in Settings." in gl)

print("extra combos.js: the analyst-code picker's cut is said")
cb = page("combos.js")
al = body(cb, "  function acList(show) {")
ok("the first 40 of all matches, and a line when more match", "const hits = found.slice(0, 40);" in al
   and "The first ${fmt(hits.length)} of ${fmt(found.length)}: type to narrow the list." in al)

# ---------------------------------------------------------------- the same, run: each page's own code under node, on
# the small stand-in for the browser's page (tests/page_harness.py), made-up data, no server
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import page_harness as H  # noqa: E402

print("Run under node (tests/page_harness.py)")
if not H.NODE:
    H.no_node(ok, "node runs the page scripts")
WAIT = "const wait = () => new Promise((r) => setTimeout(r, 30));\n"


def run(label, js, data=None):
    if not H.NODE:
        return None
    # the page's own errors (the stand-in keeps them) are printed when node ends, so a failure says why
    out, raw = H.run('process.on("exit", () => { for (const e of ERRS) console.error("page error:", e); });\n' + js, data)
    if out is None:
        ok(f"{label} runs", False, raw[-600:])
    return out


# 10-1 / 10-13: two searches one after the other; a refused state read
js = (r"""
const POSTS = [], STATE = {};
const F = async (url, o) => {
  if (o && o.method === "POST") { POSTS.push({ url, body: JSON.parse(o.body) }); return { ok: true, status: 200, json: async () => ({ finding: "F7", to: "M" }) }; }
  const m = /\/api\/combos\/search\/(\w+)$/.exec(String(url)), st = m && STATE[m[1]];
  if (!st) return { ok: false, status: 404, json: async () => ({}) };
  return { ok: st[0] < 400, status: st[0], json: async () => JSON.parse(JSON.stringify(st[1])) };
};
{ const fetch = F;
/*__SRC__*/
}
""" + WAIT + r"""
const pv = { infections: [{ name: "inf-A", hosts: 2, reports: [], devices: [] }], infections_hosts: 2, issues: [], issues_total: 0, days: ["2026-11-25"] };
(async () => {
  const out = {};
  STATE.j1 = [200, { needs_review: false, preview: pv, networks: [] }];
  STATE.j2 = [200, { needs_review: false, preview: pv, networks: [] }];
  STATE.j3 = [410, { error: "This search has expired: run it again." }];
  const tick = (b) => b.querySelectorAll("input").find((x) => x.type === "checkbox" && x.value === "inf-A");
  const b1 = window.LGEnrich.box("j1", { devices: 3 }, { code: "LG-C-00000001" }); await wait();
  const cb = tick(b1); out.tick_found = !!cb;
  if (cb) { cb.checked = true; cb.fire("change"); }
  const b2 = window.LGEnrich.box("j2", { devices: 3 }, { code: "LG-C-00000002" }); await wait();
  const cb2 = tick(b2); out.tick2_checked = cb2 ? !!cb2.checked : null;
  const w2 = b2.querySelector(".ce-plain");
  if (w2) {
    const t = w2.querySelectorAll("input.ac-in").find((x) => !x.classList.contains("ce-nets-find")); if (t) t.value = "a title";
    const send = w2.querySelectorAll("button.primary")[0]; if (send) { send.click(); await wait(); }
  }
  out.posted = POSTS.map((p) => ({ url: p.url, infections: p.body.infections }));
  const b3 = window.LGEnrich.box("j3", { devices: 3 }, { code: "LG-C-00000003" }); await wait();
  out.j3_said = lines(b3).some((x) => x.includes("Could not read this search's state"));
  out.j3_form = !!b3.querySelector(".ce-plain");
  console.log(JSON.stringify(out));
})();
""").replace("/*__SRC__*/", page("combos-enrich.js"))
o = run("combos-enrich.js", js)
if o:
    ok("10-1 run: the first search's tick is made", o["tick_found"], o)
    ok("10-1 run: the next search's box starts with nothing ticked", o["tick2_checked"] is False, o)
    ok("10-1 run: what the next search sends carries none of the earlier search's ticks",
       len(o["posted"]) == 1 and "/j2/" in o["posted"][0]["url"] and o["posted"][0]["infections"] == [], o["posted"])
    ok("10-13 run: a refused state read is said", o["j3_said"], o)
    ok("10-13 run: ...and no send form is drawn for it", o["j3_form"] is False, o)

# 10-2 / 10-3 / 10-11: the Findings page
fdata = {"findings": [{"id": "7", "number": "F7", "title": "Test finding", "name": "m0yv", "display_name": "m0yv", "text": "a note",
                       "codes": [], "status": "new", "status_label": "New", "history": [], "open": True, "kind": "", "origin": "researcher",
                       "role": "Researcher/TI", "by": "Ada", "created": "2026-11-20", "updated": "2026-11-21", "section": "infections",
                       "channel": [], "replies": 0}],
         "statuses": [{"key": "new", "label": "New"}], "can_research": False, "can_decide": False, "can_search": False,
         "can_advise": False, "can_portal": False}
js = (r"""
N.prototype.replaceWith = function (x) { this.before(x); this.remove(); };   // the stand-in lacks it
let W = null, MINE = 0, MODE = "ok";
window.LGFindingsLive = { watch(o) { W = o; }, mine() { MINE++; } };
const DATA = JSON.parse(process.argv[1]);
const F = async (url, o) => {
  if (MODE === "down") throw new TypeError("Failed to fetch");
  const u = String(url);
  if (o && o.method === "POST") return { ok: true, status: 200, json: async () => ({ finding: Object.assign(JSON.parse(JSON.stringify(DATA.findings[0])), { replies: 1 }) }) };
  if (u.startsWith("/api/findings?")) return { ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(DATA)) };
  if (u.startsWith("/api/findings/watch")) return { ok: true, status: 200, json: async () => ({ findings: {} }) };
  return { ok: false, status: 404, json: async () => ({}) };
};
{ const fetch = F;
/*__SRC__*/
}
""" + WAIT + r"""
const list = () => document.getElementById("fdList");
const replyBox = () => list().querySelector("details.fd-replybox textarea");
const typeIn = (node, v) => { node.value = v; for (const f of list().on.input || []) f({ target: node }); };
(async () => {
  const out = {};
  await wait();
  out.cards = list().querySelectorAll("article.fd-card").length;
  if (replyBox()) typeIn(replyBox(), "half a reply");
  const q = document.getElementById("fdQ"); q.value = "test"; q.fire("input");           // typing in the search
  out.after_search = replyBox() ? replyBox().value : null;
  out.open_after_search = replyBox() ? !!replyBox().parent.open : null;
  MODE = "down"; if (W) await W.refresh(); await wait(); MODE = "ok";                    // a quiet refresh, connection lost
  out.cards_after_drop = list().querySelectorAll("article.fd-card").length;
  out.after_drop = replyBox() ? replyBox().value : null;
  const send = list().querySelectorAll("button").find((b) => b.textContent === "Send the reply");
  if (send) { send.click(); await wait(); }
  out.mine = MINE;
  out.after_send = replyBox() ? replyBox().value : null;
  console.log(JSON.stringify(out));
})();
""").replace("/*__SRC__*/", page("findings.js"))
o = run("findings.js", js, fdata)
if o:
    ok("findings.js run: the card is drawn", o["cards"] == 1, o)
    ok("10-3 run: a reply being written is still there after typing in the search", o["after_search"] == "half a reply", o)
    ok("10-3 run: ...and its box stays open", o["open_after_search"] is True, o)
    ok("10-2 run: a quiet refresh that loses the connection keeps the list", o["cards_after_drop"] == 1, o)
    ok("10-2 run: ...and the reply being written", o["after_drop"] == "half a reply", o)
    ok("10-11 run: the person's own reply tells the live watch (no 'has changed' notice for it)", o["mine"] == 1, o)
    ok("10-3 run: a sent reply is not put back", o["after_send"] == "", o)

# 10-11: findings-live.js, the person's own change while a check is on its way
js = (r"""
let TICK = null, SLOW = false, STAMP = "A"; const Q = [];
const ans = (s) => ({ ok: true, status: 200, json: async () => ({ stamp: s }) });
const F = () => (SLOW ? new Promise((res) => Q.push(() => res(ans("A")))) : Promise.resolve(ans(STAMP)));
{ const fetch = F; const setInterval = (f) => { TICK = f; return 1; }; const clearInterval = () => {};
/*__SRC__*/
}
""" + WAIT + r"""
let REF = 0;
(async () => {
  window.LGFindingsLive.watch({ refresh: () => { REF++; } }); await wait();      // the page opened with A
  SLOW = true; TICK(); SLOW = false;                                              // a check on its way: it read A
  STAMP = "B"; window.LGFindingsLive.mine();                                      // the person's own change lands
  Q.shift()(); await wait();
  TICK(); await wait();                                                           // the next turn
  console.log(JSON.stringify({ refreshed: REF, notice: !!document.body.querySelector(".fl-notice") }));
})();
""").replace("/*__SRC__*/", page("findings-live.js"))
o = run("findings-live.js", js)
if o:
    ok("10-11 run: an own change during a check is not taken for someone else's", o["refreshed"] == 0 and not o["notice"], o)

# 10-4 / 10-7: intelligence.js
src = page("intelligence.js")
try:
    defs = H.extract(src, ["el", "viewSeq", "fetchView", "hostKey", "hostView"], optional=("viewSeq", "hostKey"))
except KeyError as e:
    defs = ""
    ok("intelligence.js: the functions are found", False, e)
js = r"""
const $ = (id) => document.getElementById(id);
const DRAWN = [], R = [], LIVE = new Set();
const drawView = (pane, d) => DRAWN.push(d.tag), body = () => ({});
let HOST = false;
const postJSON = (url) => (HOST ? Promise.resolve({ ok: true, status: 200, json: async () => ({ intelligence: [], services: [], issues: [], infections: [] }) })
  : new Promise((res) => R.push(res)));
Object.defineProperty(N.prototype, "lastChild", { get() { return this.children[this.children.length - 1] || null; } });
N.prototype.replaceWith = function (x) { this.before(x); this.remove(); };
document.addEventListener = (t, f) => { if (t === "keydown") LIVE.add(f); };
document.removeEventListener = (t, f) => { if (t === "keydown") LIVE.delete(f); };
""" + defs + r"""
(async () => {
  const p1 = fetchView(false), p2 = fetchView(false);
  R[1]({ ok: true, status: 200, json: async () => ({ tag: "newer" }) }); await p2;
  R[0]({ ok: true, status: 200, json: async () => ({ tag: "older" }) }); await p1;
  HOST = true;
  await hostView("192.0.2.1", null); const a = LIVE.size;
  await hostView("192.0.2.2", null); const b = LIVE.size;
  document.body.querySelector("aside.it-host").querySelector("button").click(); const c = LIVE.size;
  console.log(JSON.stringify({ drawn: DRAWN, a, b, c }));
})();
"""
o = run("intelligence.js", js) if defs else None
if o:
    ok("10-4 run: an older answer arriving last does not draw over the newer one", o["drawn"] == ["newer"], o["drawn"])
    ok("10-7 run: a second host box leaves one Escape listener, not two", o["a"] == 1 and o["b"] == 1, o)
    ok("10-7 run: Close removes it", o["c"] == 0, o)

# 10-5: lg-select.js, Enter in the search
src = page("lg-select.js")
defs = H.extract(src, ["el", "open", "label", "sync", "close", "choose", "openList"])
js = defs + r"""
const pickWith = (opts, q) => {
  const sel = document.createElement("select"); sel.options = opts.map(([v, t]) => new Option(t, v)); sel.value = "";
  sel._lgs = { wrap: el("span"), btn: el("button"), value: el("span") };
  openList(sel);
  const pop = document.body.querySelectorAll(".lgs-pop").pop(), search = pop.querySelector("input.lgs-search");
  search.value = q; search.fire("input"); document.activeElement = search; pop.fire("keydown");   // Enter
  close(false); return sel.value;
};
const C = [["NE", "Niger"], ["NG", "Nigeria"], ["ML", "Mali"], ["GH", "Ghana"], ["KE", "Kenya"], ["SN", "Senegal"], ["TG", "Togo"], ["BJ", "Benin"], ["CI", "Ivory Coast"]];
console.log(JSON.stringify({ plain: pickWith(C, "niger"), empty: pickWith([["", "Any country"], ...C], "niger") }));
"""
o = run("lg-select.js", js)
if o:
    ok("10-5 run: 'niger' + Enter in a list without an empty option picks Niger", o["plain"] == "NE", o)
    ok("10-5 run: ...and with one, still Niger", o["empty"] == "NE", o)

# 10-8: config-page.js, "Use the default"
src = page("config-page.js")
defs = H.extract(src, ["el", "fmt", "edits", "sourceText", "row"])
js = "const state = () => {};\n" + defs + r"""
const i = { key: "k", label: "K", editable: true, kind: "int", min: 1, max: 10, value: 5, saved: 7, default: 5, source: "this page" };
const r = row(i), inp = r.querySelector("input");
inp.value = "999"; inp.fire("input"); const bad1 = inp.classList.contains("bad");
r.querySelectorAll("button").find((b) => b.textContent === "Use the default").click(); const bad2 = inp.classList.contains("bad");
edits.set("k", "999"); const bad3 = row(i).querySelector("input").classList.contains("bad");
console.log(JSON.stringify({ bad1, bad2, bad3 }));
"""
o = run("config-page.js", js)
if o:
    ok("10-8 run: a value outside its range is marked", o["bad1"] is True, o)
    ok("10-8 run: 'Use the default' clears the mark", o["bad2"] is False, o)
    ok("10-8 run: a value kept from before a redraw is marked again", o["bad3"] is True, o)

print(f"{checks - len(fails)}/{checks} checks passed")
sys.exit(1 if fails else 0)
