"""Findings pages that keep up on their own (the user, 2026-11-18: "when I send to management and they are still on the
Findings page I have to manually refresh before it changes").

GET /api/findings/stamp answers with a short fingerprint of what this person sees of the findings: each finding in their
channel, where it stands, who holds it, its trail's length and last step, management's decision and its advisories'
states. The pages (static/js/findings-live.js) ask for it every 15 seconds while they are in front, and again the moment
they come back to the front; a different fingerprint means someone changed something, and the page reads it again
(the Findings page at once, unless the person is typing; the other pages offer "Show the changes").

Only a fingerprint: no title, name, code, person or date leaves here, and the same channel rule as the Findings page
decides what is in it (findings.Findings.sees), so it tells nobody about a finding they cannot open.
Installed from features.py: findings_live.install(app, ctx) with ctx: findings, has_perm.
"""
import hashlib
import json

from flask import g, jsonify

import finding_rules


def team(hp):
    """The roles that work the findings (finding_rules.is_team, the one rule)."""
    return finding_rules.is_team(hp)


def stamp(F, user, admin, strict):
    """The fingerprint of every finding this user sees, open and closed (a closing changes it too)."""
    parts = []
    for x in sorted(F.visible(user, admin, strict), key=lambda x: str(x.get("id"))):
        h = x.get("history") or []
        rv = x.get("review") or {}
        try:
            advs = [(a.get("ref"), a.get("status"), len(a.get("recipients") or [])) for a in F.advisories_of(x["id"])] if rv else []
        except Exception:                                    # an advisory store that cannot be read: the rest still counts
            advs = []
        parts.append([str(x.get("id")), x.get("status"), x.get("assignee") or "", len(h), (h[-1].get("at") if h else 0),
                      sorted(x.get("participants") or []), rv.get("decision") or "", advs, sorted(x.get("children") or []),
                      bool(x.get("expired")), (x.get("reported") or {}).get("last") or ""])
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()[:24]


def install(app, ctx):
    F, hp = ctx["findings"], ctx["has_perm"]

    @app.route("/api/findings/stamp")
    def api_findings_stamp():
        user = (getattr(g, "user", None) or {}).get("user", "")
        if not user:
            return jsonify(error="Sign in first."), 403
        if not team(hp):                                     # findings are the team's only (r90)
            return jsonify(error=finding_rules.REFUSED), 403
        resp = jsonify(stamp=stamp(F, user, bool(hp("settings")), strict=False))
        resp.headers["Cache-Control"] = "no-store"
        return resp

    return {"stamp": stamp}
