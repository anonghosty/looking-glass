#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The Overview of every role (overview.py, _portal_cards.html, _page_nav.html), in-process: each built-in role opens an
Overview whose buttons are its own pages, Findings among them for every role; the roles that see the platforms are sent
to the platforms' overview; every page header has the Overview icon and Findings; the restricted roles' path lists let
them open /overview and nothing more than before.
Usage: tests/check_overview.py"""
import os, re, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import app as A  # noqa: E402
import auth  # noqa: E402
from flask import g, render_template  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


ROLES = {k: set(v) for k, v in auth.DEFAULT_ROLES.items()}
WANT = {"researcher": {"/definitions", "/findings"}, "management": {"/management", "/findings"}, "advisor": {"/advisory", "/findings"}}


def render(template, role, **kw):
    with A.app.test_request_context("/overview"):
        g.user = {"user": f"lg-ov-{role}", "role": role, "perms": ROLES[role], "csrf": "t", "automation": True}
        ctx = {"lg_perms": ROLES[role], "lg_user": f"lg-ov-{role}", "lg_role": role, "lg_csrf": "t"}
        return render_template(template, **ctx, **kw)


def view(role):
    with A.app.test_request_context("/overview"):
        g.user = {"user": f"lg-ov-{role}", "role": role, "perms": ROLES[role], "csrf": "t", "automation": True}
        r = A.app.view_functions["overview_page"]()
        return (r.status_code, r.headers.get("Location", "")) if hasattr(r, "status_code") else (200, "")


print("Every role has an Overview, its buttons its own pages")
for role in ("researcher", "management", "advisor"):
    st, loc = view(role)
    html = render("overview.html", role)
    cards = set(re.findall(r'class="portal-card pc-\w+" href="([^"]+)"', html))
    ok(f"{role}: opens /overview, with {', '.join(sorted(WANT[role]))}", st == 200 and WANT[role] <= cards, ", ".join(sorted(cards)))
    ok(f"{role}: no platform button it cannot open", not ({"/", "/services"} & cards) and ("/management" not in cards or role == "management"))
    ok(f"{role}: /overview is on its allowed paths", "/overview".startswith({"researcher": auth.DEFINITIONS_PATHS, "management": auth.MANAGEMENT_PATHS,
                                                                              "advisor": auth.ADVISORY_PATHS}[role]))
for role in ("analyst", "external", "admin"):
    st, loc = view(role)
    ok(f"{role}: sent to the platforms' overview", st in (301, 302) and loc.endswith("/?intro=1"), f"{st} {loc}")
print("Every header has the Overview icon, and Findings for every role but the auditor")
for role in ROLES:
    nav = render("_page_nav.html", role, nav_here="x", nav_go=False)
    ov = re.search(r'href="([^"]+)"[^>]*aria-label="Overview"', nav)
    findings = role != "auditor"              # the auditor reads the Audit portal only: findings are not theirs
    ok(f"{role}: Overview icon → {ov.group(1) if ov else '-'}, Findings icon {'shown' if findings else 'not shown'}",
       ov and ov.group(1) == ("/?intro=1" if "view" in ROLES[role] else "/overview") and ('aria-label="Findings"' in nav) == findings)
print(f"\n{checks - len(fails)} of {checks} overview checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
