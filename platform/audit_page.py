"""The audit log as a page of its own (/audit): apart from Admin (users, sessions, roles), for the roles with the
'audit' permission. The page is read only; its data comes from GET /api/admin/audit, which checks the permission again.
Installed from app.py.
"""
from flask import render_template


def install(app, ctx):
    """ctx: has_perm(p)."""
    hp = ctx["has_perm"]

    @app.route("/audit")
    def audit_page():
        if not hp("audit"):
            return render_template("denied.html", message="The audit log is for the roles that may read it (permission 'audit')."), 403
        return render_template("audit.html")
