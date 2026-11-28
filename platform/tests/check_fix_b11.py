#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase audit of 2026-11-27, batch 11 (the page scripts management.js .. welcome.js), each finding kept
fixed. The page scripts cannot run in-process (no JavaScript here), so each fix is checked precisely in the page file:
the held copy <name>.new in LG_HELD_DIR when there is one, else static/js/<name>. The password policy's "by" is
checked by calling the server's own function.
  11-1  no sign-in name on the admin and auditor pages: the server's display name (by_name / user_label), else
        "an administrator" (quarterly.js, pipeline-settings.js, sender-audit.js; task-monitor.js "a signed-in person")
  11-2  management.js: a map drawing that waited for the shapes stops when a newer one started (no doubled map)
  11-3  management.js: the background refresh while the baseline builds keeps the keyboard focus
  11-4  services.js / task-monitor.js: periodic redraws keep the focus; the resize redraw is debounced
  11-5  services.js fit(): the "…" on the canvas bubble labels is kept (accepted by the owner; the name shows on hover)
  11-6  services.js: CVE descriptions in full (page and CSV), every reference ("the first 10 of N" and Show all)
  11-7  review.js: the researchers' notes say "12 of N"
  11-8  pdf.js: the button keeps its own label after a failure
  11-9  people-pick.js: a failed list is not kept as "no accounts"; it says so and can be tried again
  11-10 pipeline-settings.js: the unlock countdown stops at every redraw and asks again only once
  11-11 quarterly.js: "Make it again" asks for its confirm click again after a redraw
  11-12 services.js: no flag from flagcdn.com (the flags ship in /static/img/flags)
  11-13 links only to http(s) (services.js report pages, unusual.js)
  11-14 management.js: the drawer explain() that nothing called is gone
  11-15 "…" only where it cuts nothing: still-working statuses and placeholders keep theirs (the owner's decision,
        2026-11-27; tour.js "LG-C-…" is a placeholder); no value is cut with "…" apart from fit() (11-5)
Run: .venv/bin/python tests/check_fix_b11.py   (LG_HELD_DIR=<folder of the held copies> for the held page files)"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
HELD = os.environ.get("LG_HELD_DIR", "")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


def page(name):
    """The page script as it will ship: the held copy when there is one, else the one in static/js."""
    p = os.path.join(HELD, name + ".new") if HELD and os.path.exists(os.path.join(HELD, name + ".new")) else os.path.join(ROOT, "static", "js", name)
    with open(p, encoding="utf-8") as f:
        return f.read()


def body(src, head):
    """The text of the function (or block) that starts at `head`, up to its matching closing brace ("" if not found).
    Braces inside strings are rare in these scripts and balanced where they occur."""
    i = src.find(head)
    if i < 0:
        return ""
    j = src.find("{", i)
    depth = 0
    for k in range(j, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[i:k + 1]
    return ""


def code_lines(src):
    """The lines that are not comments."""
    return [ln for ln in src.split("\n") if not ln.strip().startswith(("//", "/*", "*"))]


Q, PS, SA, TM = page("quarterly.js"), page("pipeline-settings.js"), page("sender-audit.js"), page("task-monitor.js")
MG, SV, RV, PDF = page("management.js"), page("services.js"), page("review.js"), page("pdf.js")
PP, UN, TOUR = page("people-pick.js"), page("unusual.js"), page("tour.js")

print("11-1 no sign-in name on the admin and auditor pages")
ok("quarterly.js: the purge's switch names who by the server's by_name, else 'an administrator'",
   'confirmed by ${p.by_name || "an administrator"}' in Q and "p.by_name || p.by}" not in Q)
ok("pipeline-settings.js: the waiting and the done requests name who by by_name, else 'an administrator' (never r.by)",
   PS.count('${r.by_name || "an administrator"}') == 2 and "${r.by}" not in PS)
ok("sender-audit.js: the settings changes name who by by_name, else 'an administrator' (never x.user)",
   'x.by_name || "an administrator", x.detail' in SA and "x.user, x.detail" not in SA)
WHO = 'const who = (x) => x.user_label || (x.user && x.user !== "(signing in)" ? "a signed-in person" : "(signing in)");'
ok("task-monitor.js: requests and users by user_label, else 'a signed-in person' (never the account's name)",
   WHO in body(TM, "function drawProcesses(d)") and WHO in body(TM, "function drawUsers(d)") and "user: who(p)" in TM and "user: who(u)" in TM and "user: p.user," not in TM)
ok("task-monitor.js: the note no longer says 'Account names as on the Admin page'",
   "Account names as on the Admin page" not in TM and "no sign-in name" in TM)
try:
    import password_policy
    users = {"jdoe": {"profile": {"full_name": "Ada Admin"}}, "nofull": {"profile": {}}}
    a, b = password_policy.shown_name(users, "jdoe"), password_policy.shown_name(users, "nofull")
    ok("password-policy.js shows the server's 'by': the full name, else the person code, never the sign-in name",
       a == "Ada Admin" and b and b != "nofull" and "${P.by}" in page("password-policy.js"), (a, b))
except Exception as e:                   # noqa: BLE001  (the check fails, it never skips)
    ok("password-policy.js shows the server's 'by' (password_policy.shown_name)", False, repr(e))

print("11-2 management.js: one map, never a doubled one")
rm = body(MG, "async function regionMap(")
ok("regionMap numbers its own drawing and stops after the shapes arrive when a newer one started on the map",
   "const mine = String((state.drawN = (state.drawN || 0) + 1)); svg.dataset.draw = mine;" in rm
   and "if (svg.dataset.draw !== mine) return;" in rm and "String(state.drawN))" not in rm, rm[:200])
ok("...and the check comes after the only wait (the shapes) and before anything is drawn",
   0 < rm.find("await state.shapesP") < rm.find("if (svg.dataset.draw !== mine) return;") < rm.find("svg.append("))

print("11-3 management.js: the baseline's background refresh keeps the focus")
ld = body(MG, "async function load(big, quiet = false)")
ok("load(): the focused control is noted before render() in a quiet refresh and focused again after it",
   "const spot = quiet ? focusSpot() : null;\n      render();\n      refocus(spot);" in ld, ld[:300])
ok("focusSpot / refocus find the control again by its id or its place in the nearest part with an id",
   "function focusSpot()" in MG and "function refocus(spot)" in MG and "focus({ preventScroll: true })" in body(MG, "function refocus(spot)"))

print("11-4 periodic redraws keep the focus; the resize redraw is debounced")
ok("services.js: the Intel redraws (every 30 s, every 60 s, the lists' counts, on resize) go through keepIntelFocus",
   "const redrawIntel = (s) => keepIntelFocus(() => renderIntel(s));" in SV and "redrawIntel(s); stage.setData(s); loadRegions();" in SV
   and "setInterval(() => { if (state.stats) redrawIntel(state.stats); }, 60000);" in SV
   and "if (state.stats) { stage.setData(state.stats); redrawIntel(state.stats); }" in SV)
ok("services.js: the resize redraw waits until resizing settles (150 ms)",
   re.search(r'addEventListener\("resize", \(\) => \{ clearTimeout\(intelResize\); intelResize = setTimeout\(\(\) => \{ placeIntel\(\); '
             r'if \(state\.stats\) redrawIntel\(state\.stats\); \}, 150\); \}\);', SV) is not None
   and 'addEventListener("resize", () => { placeIntel(); if (state.stats) renderIntel(state.stats); });' not in SV)
rf = body(TM, "async function refresh()")
ok("task-monitor.js: each refresh (every 2 s / 5 s) and each sort click keeps the focus",
   "const spot = focusSpot(); draw(D); drawTab(D); refocus(spot);" in rf
   and "const spot = focusSpot(); drawTab(D); refocus(spot);" in TM and "drawPerformance(D); refocus(spot);" in TM, rf[:200])

print("11-5 services.js fit(): the bubble labels keep their \"…\" (accepted by the owner)")
ok("fit() is unchanged: a label too long for its bubble ends in \"…\", the full name on hover",
   'return t.slice(0, n) + "…"; };' in SV)

print("11-6 services.js: CVE texts and references in full")
ish = body(SV, "function issueShort(x)")
ok("issueShort (the issue line on the page and the CSV column): the whole description, never .slice(0, 70)",
   ish and ".slice(0, 70)" not in ish and "x.kev?.name || x.description || \"\"" in ish, ish[:300])
rl = body(SV, "function refList(card, refs, label)")
ok("refList: each address in full (no .slice(0, 90)), the first 10 then 'The first 10 of N references' and Show all",
   rl and ".slice(0, 90)" not in rl and "refs.slice(0, 10)" not in rl and "of ${refs.length} references" in rl
   and "Show all ${refs.length}" in rl and "put(refs.length)" in rl, rl[:300])
ok("the CVE card hands every reference to refList (no .slice(0, 6))",
   "...(x.references || []).slice(0, 6)" not in SV and "...(x.references || []), ...(x.curated_references || [])" in SV)

print("11-7 review.js: the researchers' notes never cut without a word")
ok("review.js reads notes_total and says 'The first 12 of N notes', with Show all for notes sent beyond 12",
   "d.researcher.notes_total" in RV and "of ${notesTotal} notes on this combination" in RV
   and "Show all ${notes.length}" in RV and "notes.slice(0, 12)" in RV)

print("11-8 pdf.js: the report button keeps its own label")
dl = body(PDF, "async function download(btn, url)")
ok("download(): the label is kept from the first click (data-lg-label), never re-read from a '(retry)' text",
   "const label = btn.dataset.lgLabel || (btn.dataset.lgLabel = btn.textContent);" in dl and "const label = btn.textContent;" not in dl, dl[:200])

print("11-9 people-pick.js: a failed list is not 'no accounts'")
ok("a refused or failed request is not cached (the cache entry is dropped) and not turned into an empty list",
   "delete cache[kind]; throw e;" in PP and ".catch(() => [])" not in PP and "r.ok ? r.json() : { people: [] }" not in PP)
ok("...the picker says the list could not be loaded, with Try again",
   "The list of people could not be loaded." in PP and '"Try again"' in PP and "fill();" in PP)

print("11-10 pipeline-settings.js: the unlock countdown")
dr = body(PS, "function draw()")
ok("draw() stops the countdown before anything else is drawn",
   dr.find("clearInterval(timer); timer = null;") > 0 and dr.find("clearInterval(timer); timer = null;") < dr.find("body.replaceChildren();"), dr[:200])
ok("at zero the countdown stops and asks again once, after a moment (never load() every second)",
   "if (s <= 0) { clearInterval(timer); timer = null; setTimeout(() => load(), 1500); }" in PS and "if (s <= 0) load();" not in PS)

print("11-11 quarterly.js: Make it again asks for its confirm click again after a redraw")
at = body(Q, "function adminTools(d)")
ok("the armed quarter belongs to the button drawn (let confirmQ inside adminTools), not to the whole page",
   "let confirmQ = null;" in at and not re.search(r"let timer = null, confirmQ", Q), at[:200])
ok("...and choosing another quarter asks again",
   'sel.addEventListener("change", () => { if (confirmQ) { confirmQ = null; btn.textContent = "Make it again"; } });' in at)

print("11-12 services.js: no flag from flagcdn.com")
ok("services.js loads no flag from flagcdn.com (/static/img/flags)", "flagcdn" not in SV and "/static/img/flags" in SV)

print("11-13 links only to http(s)")
ok("services.js: the report-page links only when httpUrl(…) (the Shadowserver report page, the definitions)",
   "function httpUrl(u)" in SV and "if (httpUrl(d.url))" in SV and "if (httpUrl(it.url))" in SV
   and "if (d.url) { const a" not in SV and "if (it.url) { const a" not in SV)
ok("unusual.js: a pattern's links only to this site or http(s); anything else is plain text",
   "new URL(l.href, location.origin)" in UN and '["http:", "https:"].includes(to.protocol)' in UN)

print("11-14 management.js: no dead code")
ok("the drawer explain() that nothing called is gone", "async function explain(" not in MG and not re.search(r"[^.\w]explain\(", MG))

print("11-15 \"…\": only where it does not cut text (the owner's decision, 2026-11-27)")
ok("tour.js: the combination step keeps its placeholder 'LG-C-…' / 'LG-X-…' (a placeholder, not a cut)",
   "Paste a combination code (LG-C-… one report, LG-X-… across reports)" in TOUR)
CUT = re.compile(r"""\.slice\([^()]*\)\s*\+\s*["'`]…|\.slice\([^()]*\)\}…""")   # a value cut and "…" put after it
left = []
for name in ("management.js", "net-editor.js", "notifications.js", "organisation.js", "overview.js", "password-policy.js", "pdf.js",
             "peace.js", "people-pick.js", "pipeline-settings.js", "platform-update.js", "portal-intel.js", "quarterly.js", "regions.js",
             "review.js", "sender-audit.js", "services.js", "settings.js", "severity-map.js", "spike-notice.js", "task-monitor.js",
             "tour.js", "unusual.js", "welcome.js"):
    for ln in code_lines(page(name)):
        if CUT.search(ln) and 'return t.slice(0, n) + "…"' not in ln:      # fit(): 11-5, accepted
            left.append(f"{name}: {ln.strip()[:80]}")
ok("no page script of the batch cuts a name or value with \"…\" (only fit()'s canvas labels, accepted)", not left, "; ".join(left[:6]))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
