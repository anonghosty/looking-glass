# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Add a person: one-time sign-up links made on the Admin page (the user, 2026-11-19).

An administrator chooses the person's role (and, if they like, the name they expect) and gets a link to send them. The
person opens it, fills in their details and sets their own password and authenticator: nothing secret passes through
the administrator. The account is active at once, with that role, approved by the administrator who made the link.
It works when sign-up on the sign-in page is closed (REGISTRATION=0).

* The link holds a random token (256 bits); only its SHA-256 is kept (data/invites.json, owner-only), so the file does
  not hold working links. It works ONCE, until INVITE_HOURS (72) have passed, and an administrator can revoke it.
* Every link made, used and revoked is in the audit log (invite_made, invite_used, invite_revoked), never the link.
* At most INVITES_OPEN_MAX (50) links are open at a time.
* No link gives an administrator's or an auditor's role (any role holding NO_LINK_PERMS: users, settings, audit):
  those accounts sign up on the sign-in page and are approved. Checked again when the link is opened and used, so a
  role given those rights after the link was made does not slip through (external review, 2026-11-19).
API (permission 'users', CSRF, a recent sign-in for changes): GET /api/admin/invites · POST /api/admin/invites
{role, name} -> {link} (shown once) · POST /api/admin/invites/<id>/revoke.
auth.py reads the link at sign-up through INVITE (check, use), set here.
Installed from features.py: invites.install(app, ctx).
"""
import hashlib
import json
import os
import re
import secrets
import threading
import time

from flask import g, jsonify, request

INVITES_OPEN_MAX = 50


def hours():
    try:
        return max(1, min(24 * 30, int(os.environ.get("INVITE_HOURS", "72"))))
    except ValueError:
        return 72


class TooManyOpen(ValueError):
    """INVITES_OPEN_MAX sign-up links are open: the one refusal the Admin page shows in words."""


def h(token):
    return hashlib.sha256(str(token or "").encode()).hexdigest()


class Invites:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(d, fh)
        os.replace(tmp, self.path)

    def open_ones(self, now=None):
        now = now or time.time()
        return {k: v for k, v in self._load().items() if not v.get("used_at") and not v.get("revoked_at") and v.get("expires", 0) > now}

    def make(self, role, name, by):
        with self.lock:
            d = self._load()
            now = time.time()
            # links used, revoked or expired more than 90 days ago are forgotten
            d = {k: v for k, v in d.items() if max(v.get("used_at") or 0, v.get("revoked_at") or 0, v.get("expires", 0)) > now - 90 * 86400}
            if len([1 for v in d.values() if not v.get("used_at") and not v.get("revoked_at") and v.get("expires", 0) > now]) >= INVITES_OPEN_MAX:
                raise TooManyOpen(f"{INVITES_OPEN_MAX} sign-up links are open: revoke some first.")
            token = secrets.token_urlsafe(32)
            iid = secrets.token_hex(4)
            d[h(token)] = {"id": iid, "role": role, "name": name, "by": by, "at": now, "expires": now + hours() * 3600}
            self._save(d)
            return token, d[h(token)]

    def check(self, token):
        """The open invite a token stands for, or None."""
        if not token or len(str(token)) > 100:
            return None
        e = self._load().get(h(token))
        if not e or e.get("used_at") or e.get("revoked_at") or e.get("expires", 0) <= time.time():
            return None
        return dict(e)

    def use(self, token, user):
        """Mark it used by user (once): the invite, or None when it was used, revoked or expired meanwhile."""
        with self.lock:
            d = self._load()
            e = d.get(h(token))
            if not e or e.get("used_at") or e.get("revoked_at") or e.get("expires", 0) <= time.time():
                return None
            e.update(used_at=time.time(), used_by=user)
            self._save(d)
            return dict(e)

    def revoke(self, iid, by):
        with self.lock:
            d = self._load()
            for e in d.values():
                if e.get("id") == iid and not e.get("used_at") and not e.get("revoked_at"):
                    e.update(revoked_at=time.time(), revoked_by=by)
                    self._save(d)
                    return dict(e)
            return None


# roles a sign-up link never gives: one that holds any of these permissions (administrators, auditors, or a custom role
# made with their rights) goes through approval. A forwarded or leaked link must not make a working administrator with
# nobody approving it (external review, 2026-11-19)
NO_LINK_PERMS = ("users", "settings", "audit")


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, roles (() -> role names), perms_of (role -> permissions; when
    given, roles holding NO_LINK_PERMS get no link), hook (auth.INVITE), people_name."""
    inv = Invites(os.path.join(ctx["base_dir"], "data", "invites.json"))
    hp = ctx["has_perm"]
    perms_of = ctx.get("perms_of")

    def link_roles():
        """The roles a sign-up link may give; checked again when a link is opened and used (a role changed since)."""
        return [r for r in ctx["roles"]() if r != "admin" and not (perms_of and set(perms_of(r)) & set(NO_LINK_PERMS))]

    def check(token):
        e = inv.check(token)
        return e if e and e.get("role") in link_roles() else None

    def use(token, user):
        if not check(token):
            return None
        return inv.use(token, user)
    ctx["hook"].update(check=check, use=use)
    name_of = ctx.get("people_name") or (lambda u: u)

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def guard(change=False):
        if not hp("users"):
            return jsonify(error="Adding people is for administrators (permission 'users')."), 403
        if change and not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if change and not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        return None

    def shaped(e):
        return {"id": e["id"], "role": e["role"], "name": e.get("name", ""), "by": name_of(e.get("by", "")) or e.get("by", ""),
                "at": int(e["at"]), "expires": int(e["expires"])}

    @app.route("/api/admin/invites", methods=["GET", "POST"])
    def api_invites():
        # making a link changes something: the CSRF token and a recent sign-in (tests/check_csrf_routes.py reads this)
        bad = guard(change=True) if request.method == "POST" else guard()
        if bad:
            return bad
        if request.method == "GET":
            return jsonify(open=[shaped(e) for e in sorted(inv.open_ones().values(), key=lambda e: e["at"])],
                           roles=link_roles(), hours=hours())
        b = request.get_json(silent=True) or {}
        role = str(b.get("role") or "")
        if role in ctx["roles"]() and role not in link_roles():
            return jsonify(error="A sign-up link cannot give this role: administrators and auditors sign up on the sign-in "
                                 "page and are approved on Admin → Users."), 400
        if role not in link_roles():
            return jsonify(error="Choose one of the roles."), 400
        name = re.sub(r"\s+", " ", str(b.get("name") or "")).strip()
        if len(name) > 100 or re.search(r"[<>\x00-\x1f]", name):
            return jsonify(error="The name: at most 100 characters, without < or >."), 400
        try:
            token, e = inv.make(role, name, me())
        except TooManyOpen:
            # this one case only, with its own fixed words; anything else is the plain error page (no internal text in an
            # answer: CodeQL py/stack-trace-exposure, 2026-11-20)
            return jsonify(error=f"{INVITES_OPEN_MAX} sign-up links are open: revoke some first."), 400
        ctx["audit"].add("invite_made", user=me(), target=name or role,
                         detail=f"sign-up link for the role {role}, valid {hours()} h (link {e['id']})")
        link = request.host_url.rstrip("/") + "/register?invite=" + token
        return jsonify(ok=True, link=link, invite=shaped(e))

    @app.route("/api/admin/invites/<iid>/revoke", methods=["POST"])
    def api_invite_revoke(iid):
        bad = guard(change=True)
        if bad:
            return bad
        if not re.fullmatch(r"[0-9a-f]{8}", iid):
            return jsonify(error="No such link."), 404
        e = inv.revoke(iid, me())
        if not e:
            return jsonify(error="That link was used, revoked or has expired already."), 404
        ctx["audit"].add("invite_revoked", user=me(), target=e.get("name") or e["role"], detail=f"sign-up link {iid}")
        return jsonify(ok=True)

    return {"invites": inv}
