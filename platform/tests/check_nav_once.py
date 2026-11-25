#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""RULE (the user, r90): each destination is offered once per page, per role. Static, no database:

1. The Overview screens (overview.html, the platforms' overview over the map in index.html) have no page buttons in
   their header: their "Your pages" cards offer each page; the bell, Tutorial and Log out stay.
2. A page with a labelled Overview button shows the logo as branding only: not a link, not a button, no data-go.
3. Rendered for every built-in role, no screen of the main pages offers one plain destination twice (a deep link with
   a #part or a ?query is another destination); index.html is two screens: its Overview dialog and the map.
4. Findings follow one rule (finding_rules.is_team): its buttons and cards are shown to exactly the roles that work the
   findings, the server refuses every other account, and the external role and the auditor get none.
5. The no-access page goes back to the role's own Overview; Settings has no second way to Definitions; the advisory
   portal's finding numbers open that finding; the map script no longer looks for the removed buttons.
The browser side (visible, uncovered navigation per page and role) is in browser_checks.py (nav_once).
Run from the platform's folder: python3 tests/check_nav_once.py (LG_HELD_DIR: held .new files).
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if not os.path.isdir(os.path.join(HERE, "templates")):
    HERE = os.getcwd()
sys.path.insert(0, HERE)
S = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(name, cond, detail=""):
    global checks
    checks += 1
    if cond:
        print(f"  ok   {name}")
    else:
        fails.append(name)
        print(f"  FAIL {name}  {str(detail)[:400]}")


def held(path):
    n = os.path.basename(path)
    return os.path.join(S, n + ".new") if S and os.path.exists(os.path.join(S, n + ".new")) else path


def read(path):
    p = held(path)
    return open(p, encoding="utf-8").read() if os.path.exists(p) else ""


from jinja2 import ChoiceLoader, Environment, FunctionLoader  # noqa: E402

import auth  # noqa: E402
import external_access  # noqa: E402
import finding_rules  # noqa: E402

TDIR = os.path.join(HERE, "templates")
JDIR = os.path.join(HERE, "static", "js")
env = Environment(loader=ChoiceLoader([FunctionLoader(lambda name: read(os.path.join(TDIR, name)) or None)]))
env.policies["json.dumps_kwargs"] = {"sort_keys": True, "default": lambda o: None}   # a value the stub context lacks
env.globals.update(url_for=lambda *a, **k: "/static/" + str(k.get("filename", "")),
                   lg_greeting=lambda: ("Good morning, ", "Grace", ". Welcome to Looking Glass."),
                   lg_findings_team=lambda perms: finding_rules.is_team(lambda p: p in (perms or ())),
                   lg_external=external_access.is_external)
ROLES = {k: sorted(v) for k, v in auth.DEFAULT_ROLES.items()}
TEAM = {r: finding_rules.is_team(lambda p, r=r: p in ROLES[r]) for r in ROLES}


def render(name, role, **kw):
    ctx = {"lg_perms": ROLES[role], "lg_role": role, "lg_user": f"lg-nav-{role}", "lg_name": "Grace", "lg_csrf": "t",
           "lg_peace": False, "message": "Not allowed here.", "statuses": []}
    ctx.update(kw)
    return env.get_template(name).render(**ctx)


def header_of(html):
    m = re.search(r'<header class="hud">(.*?)</header>', html, re.S)
    return m.group(1) if m else ""


def intro_of(html):
    """index.html: the Overview dialog (its own screen) and the rest (the map), apart."""
    i, j = html.find('<section class="intro"'), html.find('<div id="map"')
    return (html[i:j], html[:i] + html[j:]) if 0 <= i < j else ("", html)


def targets(html):
    """Every destination the markup offers: links and data-go buttons (no external, no file, no API)."""
    out = re.findall(r'<a\b[^>]*\bhref="(/[^"]*)"', html) + re.findall(r'\bdata-go="(/[^"]*)"', html)
    return [t for t in out if not re.match(r"^/(static|api|logout)(/|$)", t)]


def plain_dups(html):
    ts = [t for t in targets(html) if "#" not in t and "?" not in t]
    return sorted({t for t in ts if ts.count(t) > 1})


print("1. The Overview screens: no page buttons in their header")
nav = read(os.path.join(TDIR, "_page_nav.html"))
ok("_page_nav.html leaves the page items out on the Overview", 'nav_here != "overview"' in nav)
for role in ROLES:
    h = header_of(render("overview.html", role))
    ok(f"overview.html, {role}: the header has Log out and no page button", "nav-ic" not in h and 'action="/logout"' in h,
       re.findall(r'aria-label="([^"]+)"', h))
idx = read(os.path.join(TDIR, "index.html"))
ok("index.html: no page group over the map's Overview (.intro-nav, #introSettings)", 'class="intro-nav"' not in idx and 'id="introSettings"' not in idx)
for role in [r for r in ROLES if "view" in ROLES[r]]:
    intro, _ = intro_of(render("index.html", role))
    corner = re.search(r'<div class="intro-gear-wrap">(.*?)<span class="intro-scope"', intro, re.S)
    ok(f"index.html, {role}: the Overview's header keeps Log out only", corner and "<a " not in corner.group(1)
       and 'action="/logout"' in corner.group(1), corner.group(1)[:200] if corner else "no corner")

print("2. The logo beside an Overview button is branding only")
for f in sorted(os.listdir(TDIR)):
    if not f.endswith(".html"):
        continue
    src = read(os.path.join(TDIR, f))
    has_overview = 'id="btnOverview"' in src or ('_page_nav.html' in src and "nav_here" in src)
    if not has_overview:
        continue
    bad = re.findall(r'<(?:a|button)\b[^>]*>\s*<img class="brand-mark"', src) + re.findall(r'class="brand-btn"', src) + \
        re.findall(r'<img class="brand-mark"[^>]*(?:data-go|tabindex|href)', src)
    ok(f"{f}: the logo is not a link, a button or focusable", not bad, bad)

print("3. Rendered for every role: no plain destination twice on one screen")
MAIN = ["overview.html", "index.html", "services.html", "settings.html", "admin.html"]
for name in MAIN:
    for role in ROLES:
        try:
            html = render(name, role)
        except Exception as e:  # noqa: BLE001
            ok(f"{name}, {role}: renders with the stub context", False, e)
            continue
        if name == "index.html":
            intro, rest = intro_of(html)
            screens = [("Overview dialog", intro), ("map", rest)]
        else:
            screens = [("page", html)]
        for label, part in screens:
            d = plain_dups(part)
            ok(f"{name} ({label}), {role}: each destination once", not d, d)

print("4. Findings: one rule, for the buttons, the cards and the server")
ok("external and the auditor are not in the findings team", not TEAM["external"] and not TEAM.get("auditor", False))
ok("researchers, management, analysts, advisors and admins are",
   all(TEAM[r] for r in ("researcher", "management", "analyst", "advisor", "admin") if r in TEAM), TEAM)
for role in ROLES:
    for name in ("overview.html", "_page_nav.html") + (("index.html", "services.html") if "view" in ROLES[role] else ()):
        html = render(name, role, nav_here="x", nav_go=False, portal_skip=[]) if name == "_page_nav.html" else render(name, role)
        ok(f"{name}, {role}: Findings {'offered' if TEAM[role] else 'not offered'}", ('href="/findings"' in html) == TEAM[role])
for f in ("_page_nav.html", "_portal_cards.html", "index.html", "services.html"):
    src = read(os.path.join(TDIR, f))
    ok(f"{f}: the Findings button or card follows lg_findings_team(lg_perms)", "lg_findings_team(lg_perms)" in src
       and 'lg_role != "auditor"' not in src)
fsrc = open(os.path.join(HERE, "findings.py"), encoding="utf-8").read()
ok("findings.py: allowed() is the team rule (pages and API refuse anyone else)", "and team()" in fsrc
   and "finding_rules.is_team(hp)" in fsrc and 'jinja_env.globals["lg_findings_team"]' in fsrc)
for mod in ("findings_live.py", "finding_watch.py", "beacon_findings.py"):
    src = open(os.path.join(HERE, mod), encoding="utf-8").read()
    ok(f"{mod}: refuses a non-team account with the plain message", "finding_rules.is_team" in src and "finding_rules.REFUSED" in src)

print("5. The other single ways")
for role in ROLES:
    want = "/?intro=1" if "view" in ROLES[role] else "/overview"
    ok(f"denied.html, {role}: Back to the overview -> {want}", f'href="{want}"><span>Back to the overview' in render("denied.html", role))
st = render("settings.html", "admin", nav_go=True)
ok("settings.html: no Open Definitions card (the header's Definitions button is the way)", "Open Definitions" not in st
   and targets(st).count("/definitions") == 1, targets(st).count("/definitions"))
ap = read(os.path.join(JDIR, "advisory-portal.js"))
ok("advisory-portal.js: a finding's number opens that finding (/findings#f<id>)", 'link("/findings",' not in ap and "/findings#f${" in ap)
app_js = read(os.path.join(JDIR, "app.js"))
ok("app.js: no handler on the removed logo button or the intro's Settings button", '$("btnIntro")' not in app_js
   and '$("introSettings")' not in app_js, [s for s in ('$("btnIntro")', '$("introSettings")') if s in app_js])

print("6. External accounts: only the two platforms and Abused or Compromised are offered (r90, external_access.py)")
# by page (a ?query or #part is the same page); Your account too: on a public installation an external account
# registers its passkeys like everyone else (external_access.ACCOUNT, 2026-11-24)
EXT_OK = {"/", "/services", "/intelligence", "/overview", "/account"}
for name in ("index.html", "services.html", "intelligence.html"):
    html = render(name, "external")
    offered = sorted({re.split(r"[?#]", t)[0] for t in targets(html)} - EXT_OK - {""})
    ok(f"{name}, external: no button or card to a page refused to externals", not offered, offered)
intro, _ = intro_of(render("index.html", "external"))
ok("index.html, external: the Overview's Your pages offer Abused or Compromised once", targets(intro).count("/intelligence") == 1,
   targets(intro))
ok("index.html, analyst: Abused or Compromised offered too (unchanged)", targets(intro_of(render("index.html", "analyst"))[0]).count("/intelligence") == 1)
for role in ("researcher", "management", "advisor", "auditor"):
    ok(f"index/overview, {role}: no Abused or Compromised", 'href="/intelligence"' not in render("overview.html", role))
for name in ("index.html", "services.html"):
    ok(f"{name}, external: Copy JSON hidden (no copy for externals)", re.search(r'id="mCopy" hidden', render(name, "external"))
       and not re.search(r'id="mCopy" hidden', render(name, "analyst")))
ok("index.html: Look up buttons only with the 'malpedia' permission (data-lookups)", 'data-lookups="1"' not in render("index.html", "external")
   and 'data-lookups="1"' in render("index.html", "analyst"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
