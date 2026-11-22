# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Right after signing in (the user, 2026-11-19): /welcome dives deep into the globe to pitch black, the Looking Glass
logo draws itself, and the loading screen opens the page the sign-in was for (templates/welcome.html, static/js/welcome.js).

auth.start_session sends a new session here with ?next=<the page>. The page is behind the sign-in (it is not one of
auth.PUBLIC_PATHS): someone not signed in is sent to the sign-in page and never sees the product's logo
(anti-fingerprinting). next is a path on this site only (auth._safe_next); anything else opens the Overview.
Installed from features.py."""
from flask import g, redirect, render_template, request


def install(app, ctx):
    """ctx: safe_next(str) -> a path on this site (auth._safe_next)."""
    safe_next = ctx["safe_next"]

    @app.route("/welcome")
    def signin_welcome():
        if not getattr(g, "user", None) or g.user.get("automation"):
            return redirect("/login")
        nxt = safe_next(request.args.get("next"))
        if nxt in ("", "/", "/welcome") or nxt.startswith("/welcome?"):
            nxt = "/overview"
        resp = app.make_response(render_template("welcome.html", next=nxt))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return {"route": "/welcome"}
