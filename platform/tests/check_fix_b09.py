#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The page-script bugs the 2026-11-27 whole-codebase audit found (batch 09), each kept fixed. These are browser
scripts and the suite has no JavaScript engine, so each check reads the page file itself (the held copy
$LG_HELD_DIR/<name>.new when LG_HELD_DIR is set and holds it, else static/js/<name>) and checks the exact code of the fix:
  9-1  audit.js: "Signed in now" names people by full name or person code, never the sign-in name; the access review
       names each account exactly (audit evidence, like the audit trail: the owner, 2026-11-27);
  9-2  app.js: the flags come from Looking Glass itself (/static/img/flags), never flagcdn.com;
  9-3  app.js: one wait at a time for the Beacon filter; an answer for older filters is dropped;
  9-4  advisory.js: a dropped connection while opening an organisation keeps the page, with what went wrong;
  9-5  app.js: one Escape closes one layer (the Glossary, the intro, the insight, the details, the drawer);
  9-6  admin.js: the 30-second refresh does not redraw the users table while the admin uses it;
  9-7  beacon-handover.js: the people list belongs to the role picked last, and a refused answer is said;
  9-8  advisory.js, attack-map.js, beacon-unknown.js, code-integrity.js: the keyboard focus is kept on redraws;
  9-9  account.js: a passkey list that cannot be read stops its loading animation;
  9-10 attack-map.js: only the newest ATT&CK search draws its answer;
  (9-11 "..." in still-working lines and placeholders: kept by the owner's decision, nothing to check)
  9-12 advisory.js, attack-map.js: a change that worked is never reported as failed because the re-read failed;
  9-13 advisory.js: the logo and the "reported again" answer are asked once, not at every redraw;
  9-14 app.js: the whole-day arcs cache keeps only the connections drawn now;
  9-15 acode.js dead ".ax-issues" selector gone; account.js no extra GET when adding a passkey; advisory.js the
       "Choose" line and "All networks" no longer share the empty option value.
Run: .venv/bin/python tests/check_fix_b09.py   (LG_HELD_DIR=<folder>: check the held .new page files)"""
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


AUD, APP, ADV, ADM = page("audit.js"), page("app.js"), page("advisory.js"), page("admin.js")
AM, BH, BU, CI = page("attack-map.js"), page("beacon-handover.js"), page("beacon-unknown.js"), page("code-integrity.js")
ACC, ACODE = page("account.js"), page("acode.js")

print("9-1 audit.js: people by name or person code")
ses = body(AUD, "  async function loadSessions() {")
ok("Signed in now: the full name, else the person code (user_label / person_code), not s.user",
   "s.user_label || s.person_code" in ses and 'el("b", null, s.user)' not in ses, ses[:200])
acc = body(AUD, "  async function loadAccess() {")
# the owner, 2026-11-27: the access review is audit evidence like the audit trail, so it names each account exactly
ok("the access review's Account column: the exact sign-in name, with the full name when there is one (audit evidence)",
   "who(x.name, x.full_name)" in acc and "`${full} (${name})`" in acc and "x.user_label" not in acc)
ok("...and Approved by the approver in the audit form (full name and sign-in name)",
   "[x.approved_by, x.approved_at]" in acc and "x.approved_by_label" not in acc)

print("9-2 app.js: flags from Looking Glass itself")
ok("no flagcdn.com, the local /static/img/flags", "flagcdn" not in APP and "/static/img/flags/" in APP)

print("9-3 app.js: one Beacon-filter wait")
lf = body(APP, "  async function loadFacets() {")
lb = body(APP, "  async function loadBeaconFacet() {")
ok("loadFacets schedules through beaconLater and stops the wait when nothing is pending",
   "setTimeout(loadBeaconFacet" not in lf and "beaconLater(20000)" in lf and "clearTimeout(beaconTimer)" in lf)
ok("beaconLater replaces the wait (clearTimeout first), the only setTimeout(loadBeaconFacet in the file",
   bool(re.search(r"function beaconLater\(ms\) \{ clearTimeout\(beaconTimer\); beaconTimer = setTimeout\(loadBeaconFacet, ms\); \}", APP))
   and APP.count("setTimeout(loadBeaconFacet") == 1)
ok("an answer that comes after the filters were asked again is dropped",
   "const my = loadFacets.seq;" in lb and "if (my !== loadFacets.seq) return;" in lb and "beaconLater(30000)" in lb)
ok("beaconTimer is declared before loadFacets", 0 <= APP.find("let beaconTimer = 0;") < APP.find("async function loadFacets()"))

print("9-4 advisory.js: a dropped connection keeps the page")
on = body(ADV, "  async function openNet(n) {")
m = re.search(r"\} catch \(e\) \{(.*?)return;\s*\} finally \{ wait\.remove\(\); \}", on, re.S)
ok("the fetch's failure is caught: the page drawn again with the picker and the words of what went wrong",
   bool(m) and "if (my === SEQ) { draw();" in m.group(1) and "LGLoader.errorText(e)" in m.group(1), on[:400])

print("9-5 app.js: one Escape, one layer")
main = body(APP, '  document.addEventListener("keydown", (e) => {\n    if (e.key !== "Escape"', "\n  });\n")
ok("one handler closes the Glossary first and stops there", 'if (!$("glossaryDlg").hidden) { e.preventDefault(); closeGlossaryDlg(); return; }' in main)
ok("...an Escape already used by a drop-down or dialog closes nothing more", 'if (e.key !== "Escape" || e.defaultPrevented) return;' in main)
ok("...the intro page is left to its own handler", 'if ($("intro") && !$("intro").hidden) return;' in main)
ok("the Glossary's second Escape listener is gone",
   'if (e.key === "Escape" && !$("glossaryDlg").hidden) closeGlossaryDlg();' not in APP)
ok("the intro's handler skips an Escape already used", 'e.key === "Escape" && !e.defaultPrevented && !$("intro").hidden' in APP)

print("9-6 admin.js: the refresh waits while the admin works")
ok("the 30-second refresh asks usersBusy() before redrawing the users table",
   bool(re.search(r'if \(t === "users" && !usersBusy\(\)\) loadUsers\(\);', ADM)))
ub = body(ADM, "  const usersBusy = () => {", "\n  };\n")
ok("...busy while the focus or the pointer is in the table, a request runs, a role list is open or the page is hidden",
   all(s in ub for s in ("t.contains(document.activeElement)", 't.matches(":hover")', "button:disabled", ".lgs-pop", "document.hidden")))

print("9-7 beacon-handover.js: the people list")
pp = body(BH, "      const people = async () => {", "\n      };\n")
ok("an answer for a role changed meanwhile is dropped", "const my = ++pseq" in pp and pp.count("if (my !== pseq) return;") >= 2)
ok("a refused answer is said, not read as an empty list", "if (!r.ok) throw new Error(" in pp and pp.index("if (!r.ok)") < pp.index("who.replaceChildren(); msg"))

print("9-8 focus kept on redraws")
dr = body(ADV, "  function drawFocus() {" if "  function drawFocus() {" in ADV else "  function draw() {")   # draw() wraps it (typed words kept)
ok("advisory.js: draw() keeps the focus (same data-fk), else the card's heading; the drawing itself is drawNow()",
   "drawNow();" in dr and 'querySelectorAll("[data-fk]")' in dr and "back.focus(" in dr and "function drawNow() {" in ADV)
ok("advisory.js: the buttons carry their keys",
   all(s in ADV for s in ('b.dataset.fk = `tech|${t.key}|${action}`', 'b.dataset.fk = `undo|${p.key}`', 'all.dataset.fk = "confirm_all"',
                          'sv.dataset.fk = "save"', 'gen.dataset.fk = "generate"', 'dr.dataset.fk = "drafted"', 'b.dataset.fk = `net|${n.network}`')))
ok("advisory.js: a disabled button that lost the focus still counts (lastFocus), focus elsewhere is never taken",
   'main.addEventListener("focusin"' in ADV and "!main.contains(a)) { drawNow(); return; }" in dr)
rn = body(AM, "  function render() {")
ok("attack-map.js: render() keeps the focus, else the report now in its place, else the status line",
   "renderNow();" in rn and 'querySelectorAll("[data-fk]")' in rn and "near?.querySelector" in rn and "function renderNow() {" in AM)
ok("attack-map.js: Confirm, Change, Show more carry their keys",
   all(s in AM for s in ("ok.dataset.fk = `confirm|${x.report}`", "ch.dataset.fk = `change|${x.report}`", 'more.dataset.fk = "more"', "card.dataset.report = x.report")))
ok("attack-map.js: removing a chosen chip moves the focus to the next chip or the search",
   '(sel.querySelector(".am-chip-x") || q).focus()' in AM)
rd = body(BU, "    const redraw = async () => {", "\n    };\n")
ok("beacon-unknown.js: the redraw puts the focus back (same family, same action), keeps Sent or put away open",
   "await mount(holder);" in rd and '[data-fam]' in rd and '[data-fv]' in rd and "awayNow.open = true" in rd and ".focus(" in rd)
ok("beacon-unknown.js: the families and their buttons carry their keys",
   all(s in BU for s in ("c.dataset.fam = f.id", 'ok.dataset.fv = "approve"', 'tog.dataset.fv = "toggle"', "go.dataset.fv = button")))
act = body(CI, "  async function act(f, kind, btn) {")
ok("code-integrity.js: after a decision the focus goes back to the button used, else the status line",
   "keepFocus(draw, btn)" in act and " draw();" not in act and "msg.focus(" in body(CI, "  function keepFocus(build, from) {")
   and 'keep.dataset.fk = f.key' in CI and 'out.dataset.fk = f.key' in CI)

print("9-9 account.js: a failed list stops turning")
ld = body(ACC, "  async function load() {")
ok("the failure removes the loading animation's classes", 'classList.remove("st-loading", "lg-has-logo")' in ld.split("catch")[-1] if "catch" in ld else False, ld)

print("9-10 attack-map.js: the newest search draws")
pk = body(AM, "  async function picker(card, x, btn) {")
ok("each search has its number; an older answer is dropped",
   "my = ++qseq" in pk and "if (my !== qseq) return;" in pk and "if (my === qseq) found.replaceChildren(" in pk)

print("9-12 a change that worked is never reported as failed")
rq = body(ADV, "    const run = async (button, work) => {", "\n    };\n")
ok("advisory.js run(): the work's failure and the re-read's failure are kept apart",
   "try { done = await work(); }" in rq and "try { if (seq === SEQ) await reloadIndex(); } catch { stale = true; }" in rq)
sv = body(AM, "  async function save(x, ids, nofit, note, btn) {")
ok("attack-map.js save(): the re-read is outside the post's try (reread(), 'Saved' with a note when it failed)",
   "data = await get" not in sv and "await reread()" in sv and "STALE" in sv)
bulk = body(AM, "  function bulkBar(list) {") + body(AM, "  function checkBar(bar, list) {") + body(AM, "  function ctidLine() {")
ok("attack-map.js: the bulk confirmations and the CTID switch re-read with reread() too",
   bulk.count("await reread()") == 3 and "data = await get" not in bulk, bulk.count("await reread()"))

print("9-13 advisory.js: asked once")
ok("the logo's address is made once per page load (LOGO_T), not Date.now() at every redraw",
   "/organisation/logo?t=${LOGO_T}" in ADV and "logo?t=${Date.now()}" not in ADV)
ok("the 'reported again' answer is kept (againOnce), not fetched at every redraw",
   "AGAIN ||= fetch(" in ADV and "againOnce().then(" in ADV and ADV.count("/again`") == 1)

print("9-14 app.js: the arcs cache")
gl = body(APP, "  function buildGeoLayers(g) {")
ok("only the connections drawn now are kept", "flowPaths.clear();" in gl and "kept.set(k, p);" in gl)

print("9-15 dead selector, extra GET, shared empty option value")
ok("acode.js: no '.ax-issues' (no part of the page has it)", ".ax-issues" not in ACODE)
add = body(ACC, '  $("pkAdd")?.addEventListener("click", async () => {', "\n  });\n")
ok("account.js: adding a passkey draws its answer with the last list, no GET first",
   '...(await call("/api/passkeys")), ...(await call("/api/passkeys", {' not in add and "last.passkeys ? last :" in add)
pi = body(ADV, "  function picker() {")
ok("advisory.js: All networks has a value of its own; the Choose line alone is empty and opens nothing",
   "optVal(n.network)" in pi and 'n === "" ? ALL : n' in pi and 'if (BUSY || sel.value === "") { sel.value = optVal(NET); return; }' in pi
   and 'openNet(sel.value === ALL ? "" : sel.value)' in pi)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
