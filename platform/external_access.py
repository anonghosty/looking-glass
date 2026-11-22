# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""What an external account may open (the user, 2026-11-21): exactly three things, all masked, plus what every
signed-in account needs.

1. Network communications: the map (/) and the APIs it calls.
2. Publicly accessible / vulnerable services (/services) and the APIs it calls.
3. Abused or Compromised (/intelligence), in its masked view (intelligence.py, masked_fields.intelligence_row).
Plus: the Overview over the map (/?intro=1, its glossary included), the sign-in welcome, the account's own
details (/api/me), the tour's memory, the bell, the platform's files (/static/), signing in and out (public paths).

Everything else is refused on the server, pages and APIs alike, by auth.py's sign-in gate (_require_login), which
asks refused(path) on every request of such an account, before any page or API runs. The list is an allow-list of
exact paths: a route added tomorrow is closed to external accounts until someone adds it here on purpose.

Who counts as external: an account whose permissions are exactly {"view"} (is_external). The built-in "external" role
is fixed to ["view"] (auth.FIXED_ROLES), so it always matches; a custom role an administrator makes with only "view"
is the same masked viewer and gets the same three pages. The rule keys on the permissions, not on the role's name,
so renaming or copying the role cannot widen what such an account opens. A role with any other permission
(unmasked, export, malpedia, ...) is not external and keeps what its permissions give it.

is_external(perms) -> bool      refused(path) -> None (allowed) or the reason (refused)
install(app) registers the templates' lg_external(perms), the same test (features.py).
"""

EXTERNAL_PERMS = frozenset({"view"})

# the pages (GET): the map with its Overview, the services platform, Abused or Compromised; /overview sends a
# platform account to the map's Overview; /welcome is the page right after signing in
PAGES = frozenset({"/", "/services", "/intelligence", "/overview", "/welcome"})

# what every signed-in account needs on those pages: its own details, the tour's memory, the bell
COMMON_API = frozenset({"/api/me", "/api/tour", "/api/notifications", "/api/notifications/clear",
                        "/api/overview/spikes"})       # the Overview's platform cards: counts only

# 1. network communications (app.js): masked on the server for an account without 'unmasked' (app.is_demo)
MAP_API = frozenset({"/api/clock", "/api/events", "/api/facets", "/api/geo", "/api/infections", "/api/insight",
                     "/api/insight/drill", "/api/overview", "/api/related", "/api/replayed", "/api/report_glossary",
                     "/api/settings/public", "/api/stats",
                     "/api/svc/clock", "/api/svc/facets", "/api/svc/glossary"})   # the map's Overview shows both platforms

# 2. publicly accessible / vulnerable services (services.js): masked the same way (services_api.public)
SERVICES_API = frozenset({"/api/svc/clock", "/api/svc/detail", "/api/svc/drill", "/api/svc/events", "/api/svc/facets",
                          "/api/svc/glossary", "/api/svc/insight", "/api/svc/regions", "/api/svc/replayed",
                          "/api/svc/stats"})

# 3. Abused or Compromised (intelligence.js): the summary, a report's masked rows, and the Overview card's counts.
# Not the export, not a host's cross-view, not the reveal of leaked accounts (intelligence.py refuses those too)
INTELLIGENCE_API = frozenset({"/api/intelligence", "/api/intelligence/report", "/api/intelligence/totals"})

ALLOWED = PAGES | COMMON_API | MAP_API | SERVICES_API | INTELLIGENCE_API

REFUSED = "External accounts open the two platforms and Abused or Compromised only."


def is_external(perms):
    """An account that may only look, masked: its permissions are exactly 'view'."""
    try:
        return frozenset(perms or ()) == EXTERNAL_PERMS
    except TypeError:
        return False


def refused(path):
    """None when an external account may open this path, else the reason. Exact paths only: /api/insight is allowed,
    /api/insight/report (the PDF) is not. The platform's files are always served."""
    if path in ALLOWED or path.startswith("/static/"):
        return None
    return REFUSED


def install(app):
    """The templates ask the same question (_page_nav.html, _portal_cards.html): lg_external(lg_perms)."""
    app.jinja_env.globals["lg_external"] = is_external
    return {"is_external": is_external, "refused": refused, "allowed": ALLOWED}
