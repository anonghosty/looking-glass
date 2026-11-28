#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Audit batch 13 fixes (2026-11-27): stylesheets and templates. Made-up data only.
Page files are read from the held copies ($LG_HELD_DIR/<name>.new) when there is one, else from the installed files.
1. 13-1: every view of the sign-in card (login.html data-v) has its display rule in auth.css; the passkey view
   renders (Jinja) and its rule shows it.
2. 13-2: no template puts the viewer's sign-in name (lg_user) in the page.
3. 13-3/4/5: Combinations, Intel and the Settings Apply bar: text wraps, never cut with an ellipsis or a line clamp.
4. 13-6/7: dimmed text by colour, not opacity; the colours used measure >= 4.5:1 on the darkest and the raised surfaces.
5. 13-8: every log-out form carries the CSRF token.
6. 13-9: no attribute glued to the one before it (id="x"maxlength).
7. 13-10: Log out is the last control of its header in the page's own order (keyboard order = what the eye sees).
8. 13-11: the KPI tiles' "Details" hint shows on keyboard focus too.
9. 13-12/13/14: .pill-btn.primary once; the dead and shadowed rules removed stay removed.
Source checks of page files: CSS and templates cannot be run in-process beyond the Jinja render.
Run: .venv/bin/python tests/check_fix_b13.py"""
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELD = os.environ.get("LG_HELD_DIR", "")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def page(name):
    """A page file: the held copy that ships next when LG_HELD_DIR names one, else the installed file."""
    held = os.path.join(HELD, name + ".new") if HELD else ""
    if held and os.path.exists(held):
        return open(held, encoding="utf-8").read()
    sub = "templates" if name.endswith(".html") else os.path.join("static", "css")
    return open(os.path.join(HERE, sub, name), encoding="utf-8").read()


def nocomments(css):
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def rule_bodies(css, selector):
    """The bodies of every rule whose selector list contains `selector` exactly."""
    out = []
    for m in re.finditer(r"([^{}]+)\{([^{}]*)\}", nocomments(css)):
        sels = [re.sub(r"\s+", " ", s.strip()) for s in m.group(1).split(",")]
        if selector in sels:
            out.append(m.group(2))
    return out


TEMPLATES = sorted(n for n in os.listdir(os.path.join(HERE, "templates")) if n.endswith(".html"))

print("1. 13-1: the sign-in card shows every view, the passkey one too")
login, auth = page("login.html"), nocomments(page("auth.css"))
views = sorted(set(re.findall(r'class="auth-view"[^>]*data-v="([a-z]+)"', login)))
ok("login.html has its views, passkey among them", "passkey" in views and len(views) >= 5, views)
for v in views:
    sel = f'.auth-card[data-view="{v}"] [data-v="{v}"]'
    bodies = rule_bodies(auth, sel)
    ok(f"auth.css shows the {v} view", any(re.search(r"display:\s*flex", b) for b in bodies), sel)
try:
    import jinja2
    tmp = tempfile.mkdtemp()
    for n in ("login.html", "auth_base.html", "_pw.html"):
        open(os.path.join(tmp, n), "w", encoding="utf-8").write(page(n))
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(tmp), autoescape=True)
    html = env.get_template("login.html").render(
        view="passkey", tls=True, no_admin=False, registration=False, next="/", username="", error=None, notice=None,
        invite=None, form={}, countries=[], default_country="", signin_org="Example CSIRT",
        url_for=lambda ep, filename="": f"/static/{filename}")
    card = re.search(r'<div class="auth-card" id="authCard" data-view="([a-z]+)"', html)
    ok("the passkey sign-in renders with data-view=passkey and its form", card and card.group(1) == "passkey"
       and 'data-v="passkey"' in html and 'id="pkGo"' in html)
except ImportError:
    ok("jinja2 importable for the render", False)

print("2. 13-2: no sign-in name in the pages")
for n in TEMPLATES:
    t = page(n)
    if "lg_user" in t or "data-me=" in t:
        ok(f"{n}: no lg_user / data-me", False)
ok("no template names lg_user or data-me", not any("lg_user" in page(n) or "data-me=" in page(n) for n in TEMPLATES))

print("3. 13-3/4/5: text wraps, never an ellipsis or a line clamp")
for n in ("combos.css", "intel.css", "settings.css"):
    css = nocomments(page(n))
    ok(f"{n}: no text-overflow: ellipsis", "text-overflow: ellipsis" not in css)
    ok(f"{n}: no line clamp", "line-clamp" not in css)
for n, sel in (("combos.css", ".cb-geo-n"), ("combos.css", ".cb-tree-row .l"), ("combos.css", ".cb-bar-r .n"),
               ("intel.css", ".ig-v code"), ("intel.css", ".kbn-code-t"), ("settings.css", ".st-apply-text .muted")):
    bodies = rule_bodies(page(n), sel)
    ok(f"{n} {sel} wraps (overflow-wrap) and is not cut", bodies and all("overflow-wrap: anywhere" in b and "nowrap" not in b
                                                                       and "overflow: hidden" not in b for b in bodies))


def hexrgb(h):
    h = h.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def lum(rgb):
    def c(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (c(x) for x in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def ratio(a, b):
    la, lb = sorted((lum(hexrgb(a)), lum(hexrgb(b))), reverse=True)
    return (la + 0.05) / (lb + 0.05)


print("4. 13-6/7: dimmed by colour, not opacity, at 4.5:1 or more")
app = page("app.css")
root = dict(re.findall(r"(--[\w-]+):\s*(#[0-9a-fA-F]{6})", re.search(r":root\s*\{([^}]*)\}", nocomments(app)).group(1)))
SURFACES = ("#0b0b0d", "#141417", "#1b1b1f")           # the page, the cards, the raised controls (app.css :root)


def colour_of(body):
    m = re.search(r"(?<![\w-])color:\s*(var\((--[\w-]+)\)|#[0-9a-fA-F]{6})", body)
    if not m:
        return None
    return root.get(m.group(2)) if m.group(2) else m.group(1)


for n, sel in (("app.css", ".adm-table tr.adm-selftest td"), ("services-kb.css", ".svp-off td"), ("services-kb.css", ".svp-noise td"),
               ("intel.css", ".ig-card.empty"), ("app.css", ".intro-reports li.off .ct"), ("app.css", ".m-sec dd.empty")):
    bodies = rule_bodies(page(n), sel)
    ok(f"{n} {sel}: no opacity on the text", bodies and not any(re.search(r"(?<![\w-])opacity:", b) for b in bodies))
for n, sel in (("app.css", ".adm-table tr.adm-selftest td"), ("services-kb.css", ".svp-off td"), ("services-kb.css", ".svp-noise td"),
               ("intel.css", ".ig-card.empty .ig-card-t b"), ("app.css", ".intro-reports li.off .ct"), ("app.css", ".m-sec dd.empty")):
    cols = [colour_of(b) for b in rule_bodies(page(n), sel)]
    cols = [c for c in cols if c]
    worst = min((ratio(c, s) for c in cols for s in SURFACES), default=0)
    ok(f"{n} {sel}: its colour is >= 4.5:1 on every surface", cols and worst >= 4.5, f"{cols} worst {worst:.2f}")
ok("app.css: the 2:1 grey #4a4a52 is gone", "#4a4a52" not in nocomments(app).lower())

print("5. 13-8: the log-out forms carry the CSRF token")
forms = []
for n in TEMPLATES:
    for m in re.finditer(r'<form[^>]*action="/logout"[^>]*>(.*?)</form>', page(n), flags=re.S):
        forms.append((n, m.group(1)))
ok("log-out forms found (header, overview, platforms, denied)", len(forms) >= 5, len(forms))
for n, body in forms:
    ok(f"{n}: the log-out form has the hidden csrf_token", re.search(
        r'<input type="hidden" name="csrf_token" value="\{\{ lg_csrf \}\}">', body) is not None)

print("6. 13-9: no attribute glued to the one before it")
glued = [(n, m.group(0)) for n in TEMPLATES for m in re.finditer(r'\s[\w-]+="[^"{}]*"[A-Za-z][\w-]*=', page(n))]
ok("every attribute has its space", not glued, glued[:3])

print("7. 13-10: Log out is the last control of its header")
FOCUSABLE = re.compile(r"<(button|a|select|textarea)\b|<input(?![^>]*type=\"hidden\")")
for n in TEMPLATES:
    t = page(n)
    for m in re.finditer(r'<form[^>]*action="/logout"[^>]*class="account-form"[^>]*>.*?</form>', t, flags=re.S):
        rest = t[m.end():]
        end = rest.find("</div>")
        after = rest if end < 0 else rest[:end]
        ok(f"{n}: nothing to tab to after Log out in its header", not FOCUSABLE.search(after), after.strip()[:80])

print("8. 13-11: the Details hint on keyboard focus")
ok("app.css shows .i-kpi .go on :focus-visible", re.search(r"\.i-kpi\.click:focus-visible \.go", app) is not None)

print("9. 13-12/13/14: one .pill-btn.primary; the dead and shadowed rules stay removed")
ok("app.css defines .pill-btn.primary once", len(re.findall(r"(?m)^\.pill-btn\.primary\s*\{", nocomments(app))) == 1)
# one rule of each removed family (203 rules in all: classes and ids no template, page script, Python file or test names)
REMOVED = [("app.css", ".login-card"), ("app.css", "#auditTable"), ("app.css", ".intro-track"), ("app.css", ".mp-list"),
           ("app.css", ".live-pill"), ("auth.css", ".auth-field"), ("auth.css", ".auth-hero-points .dot"), ("auth.css", ".auth-live"),
           ("services-kb.css", ".svp-tabs"), ("services-kb.css", ".svc-modal"), ("settings.css", ".kb-table"), ("settings.css", ".org-signin"),
           ("intelligence.css", ".it-chip"), ("findings.css", ".fd-flow"), ("intel.css", ".ig-sort"), ("intel.css", ".kbn-head"),
           ("acode.css", ".ax-xhead"), ("beacon.css", ".bh-handover"), ("review.css", ".rv-role"), ("combos.css", ".cb-geo-r")]
JS_DIR = os.path.join(HERE, "static", "js")
scripts = [open(os.path.join(JS_DIR, n), encoding="utf-8").read() for n in os.listdir(JS_DIR) if n.endswith(".js")]
if HELD and os.path.isdir(HELD):
    scripts += [open(os.path.join(HELD, n), encoding="utf-8").read() for n in os.listdir(HELD) if n.endswith(".js.new")]
markup = "\n".join(scripts + [page(n) for n in TEMPLATES])
for n, sel in REMOVED:
    ok(f"{n}: {sel} removed", not rule_bodies(page(n), sel))
    ok(f"{sel[1:]} is used by no template or page script (else it needs its rule back)", sel[1:] not in markup)
# near-copies: a rule wholly re-set later by the same selector is gone, one rule each is left
for n, sel in (("app.css", ".kpi.crit .kpi-value"),
               ("services-kb.css", ".svc-iss"), ("intel.css", ".kbn-body .kbn-list")):
    ok(f"{n}: {sel} defined once (its earlier near-copy removed)", len(rule_bodies(page(n), sel)) == 1, len(rule_bodies(page(n), sel)))
ok("intelligence.css: the shadowed ellipsis rule for .it-view .brk .bl span is gone",
   not any("ellipsis" in b for b in rule_bodies(page("intelligence.css"), ".it-view .brk .bl span")))

print(f"\n{checks - len(fails)}/{checks} checks passed")
sys.exit(1 if fails else 0)
