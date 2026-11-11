"""The Overview page of every role (/overview): Looking Glass's welcome and "Your pages", the portals this role opens,
Findings among them for every role (templates/overview.html, _portal_cards.html). Roles that see the platforms ('view')
have the platforms' own overview (/?intro=1), which shows the same "Your pages" under the two platforms; /overview sends
them there. Nothing but the page: no data, no address. Installed from app.py.
"""
from flask import redirect, render_template


def install(app, ctx):
    """ctx: has_perm(p)."""
    hp = ctx["has_perm"]

    @app.route("/overview")
    def overview_page():
        if hp("view"):
            return redirect("/?intro=1")
        return render_template("overview.html")
