# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Refusals under /api/ answer JSON with an error in words, never an HTML page (2026-11-26: the every-route check,
tests/check_every_route.py, found 811 refusals under /api/ answered as Werkzeug's HTML pages; a page's script reads
{"error": ...}, and Werkzeug's stock pages name the framework, which anti-fingerprinting keeps out of every answer).

A message the code gave itself (abort(403, "...")) is kept; otherwise the plain words below. Pages (not /api/) keep
their HTML answers as before."""
from flask import jsonify, request
from werkzeug.exceptions import HTTPException

WORDS = {
    400: "That request is not right.",
    401: "Sign in first.",
    403: "Your account does not have access to this.",
    404: "Not found.",
    405: "That is not allowed here.",
    409: "That could not be done just now. Try again.",
    410: "That is no longer available.",
    413: "That request is too large.",
    415: "Send that as JSON.",
    422: "That request could not be used.",
    429: "Too many requests. Wait a moment and try again.",
}


def _own_words(e):
    """The description the code passed to abort(), if any (Werkzeug's own default text is never sent)."""
    d = e.description
    default = type(e).description if isinstance(type(e).description, str) else None
    return d if isinstance(d, str) and d and d != default else None


def install(app):
    @app.errorhandler(HTTPException)
    def _api_refusal(e):
        if not request.path.startswith("/api/") or e.code is None or not 400 <= e.code < 500:
            return e                       # pages and anything else: as before
        r = jsonify(error=_own_words(e) or WORDS.get(e.code, "That request could not be completed."))
        r.status_code = e.code
        if e.code == 405 and getattr(e, "valid_methods", None):
            r.headers["Allow"] = ", ".join(e.valid_methods)
        return r
    return {"words": WORDS}
