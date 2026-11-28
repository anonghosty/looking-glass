# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The guided tour's memory per person (tour.js; the user, 2026-11-19/20: a first-visit offer to take the tour or skip
it, remembered per person, on every platform and portal).

data/tour_seen.json: {user: {"pages": [page keys seen or skipped], "never": bool}}. Nothing else: no times, no content.
API (signed in, every role): GET /api/tour -> {pages, never}; POST /api/tour {page} (seen / skipped) or {never: true}
(CSRF). Installed from features.py.
"""
import json
import os
import re
import threading

from flask import g, jsonify, request

PAGE_RE = re.compile(r"^/[A-Za-z0-9/#_-]{0,40}$")
MAX_PAGES = 60


class TourPrefs:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def _read(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def get(self, user):
        p = self._read().get(user) or {}
        return {"pages": [x for x in p.get("pages") or [] if isinstance(x, str)][:MAX_PAGES], "never": bool(p.get("never"))}

    def mark(self, user, page=None, never=False):
        with self.lock:
            d = self._read()
            p = d.get(user) if isinstance(d.get(user), dict) else {}
            pages = [x for x in p.get("pages") or [] if isinstance(x, str)]
            if page and page not in pages:
                pages = (pages + [page])[-MAX_PAGES:]
            d[user] = {"pages": pages, "never": bool(p.get("never")) or bool(never)}
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh)
            os.replace(tmp, self.path)
            return d[user]


def install(app, ctx):
    """ctx: base_dir, csrf_ok."""
    prefs = TourPrefs(os.path.join(ctx["base_dir"], "data", "tour_seen.json"))

    def me():
        u = getattr(g, "user", None) or {}
        return "" if u.get("automation") else u.get("user", "")

    @app.route("/api/tour", methods=["GET", "POST"])
    def api_tour():
        u = me()
        if not u:
            return jsonify(error="Sign in again."), 401
        if request.method == "GET":
            return jsonify(prefs.get(u))
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True)
        b = b if isinstance(b, dict) else {}               # a list as the body: nothing marked, not an error 500
        page = b.get("page")
        if page is not None and not (isinstance(page, str) and PAGE_RE.match(page)):
            return jsonify(error="Not a page."), 400
        return jsonify(prefs.mark(u, page=page, never=b.get("never") is True))

    return prefs
