# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The request's JSON body, for routes that read fields from it.

body() is the JSON body when it is an object, else {}: a list, a number or a string as the body must not turn a route
into an error 500 (`(request.get_json(silent=True) or {}).get(...)` fails on [1]; audit 2026-11-27). The route then
answers as for an empty body (its own "missing field" message). One helper for every route (stepup.py's gate too).
"""
from flask import request


def body():
    b = request.get_json(silent=True)
    return b if isinstance(b, dict) else {}
