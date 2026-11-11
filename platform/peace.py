"""Peace of mind: an admin's own switch to step out of the platforms and the work on findings and keep only the admin
and audit duties and Settings. While it is on, their permissions are cut to those (auth.PEACE_PERMS) on every request,
the other pages and APIs are closed to them (auth.PEACE_PATHS), the Findings and the portals leave their header and
Overview, and no findings notification comes in. Only an account whose role can manage users (the admins) has it, and
only for itself; every change is in the audit log.

Kept in data/peace_of_mind.json (user -> {on, at}; run-time data, owner-only file, never shipped).
API: GET /api/peace · POST /api/peace {on: true|false}. Installed from app.py.
"""
import json
import os
import threading
import time

import auth
from flask import g, jsonify, request


class Peace:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self._c = (None, {})

    def _load(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return {}
        if self._c[0] != m:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    d = json.load(fh)
                self._c = (m, d if isinstance(d, dict) else {})
            except (OSError, ValueError):
                self._c = (m, {})
        return self._c[1]

    def on(self, user):
        return bool((self._load().get(user) or {}).get("on"))

    def set(self, user, on):
        with self.lock:
            d = dict(self._load())
            if on:
                d[user] = {"on": True, "at": round(time.time(), 3)}
            else:
                d.pop(user, None)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)
            self._c = (None, {})


def install(app, ctx):
    """ctx: base_dir, csrf_ok(), fresh(), audit, role_perms(role) -> the role's own permissions."""
    peace = Peace(os.path.join(ctx["base_dir"], "data", "peace_of_mind.json"))
    auth.PEACE["of"] = peace.on

    def who():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def can(role):
        """Only admins (roles that manage users) have the switch."""
        return "users" in set(ctx["role_perms"](role) or ())

    @app.route("/api/peace", methods=["GET"])
    def api_peace():
        user, role = who()
        if not user:
            return jsonify(error="Sign in."), 401
        return jsonify(on=peace.on(user), can=can(role))

    @app.route("/api/peace", methods=["POST"])
    def api_peace_set():
        user, role = who()
        if not user:
            return jsonify(error="Sign in."), 401
        if not can(role):
            return jsonify(error="Peace of mind is for administrators."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        if not isinstance(b.get("on"), bool):
            return jsonify(error="on: true or false."), 400
        peace.set(user, b["on"])
        ctx["audit"].add("peace_of_mind", user=user, target=user, detail="on: admin, audit and Settings only" if b["on"] else "off")
        return jsonify(ok=True, on=b["on"])

    return peace
