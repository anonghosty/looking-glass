# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Readable labels for the fields of Shadowserver's reports (static/data/field_labels.json, approved 2026-11-23).

The pages read the same file through static/js/lg-fields.js; this module gives CSV headers and PDFs the same words.
label("ip_header_urg") -> "IP header: URG flag". A field the file does not know (a report Shadowserver added later)
falls back to its name with spaces, first letter capitalised, so nothing is ever shown blank.
"""
import json
import os
import threading

import filesig

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static", "data", "field_labels.json")
_lock = threading.Lock()
_cache = {"sig": None, "labels": {}}


def _labels():
    try:
        sig = filesig.sig(PATH)
    except OSError:
        return {}
    with _lock:
        if _cache["sig"] != sig:
            try:
                with open(PATH, encoding="utf-8") as f:
                    got = json.load(f).get("labels") or {}
                _cache["labels"] = {str(k): str(v) for k, v in got.items() if isinstance(v, str) and v.strip()}
            except (OSError, ValueError, AttributeError):
                _cache["labels"] = {}
            _cache["sig"] = sig
        return _cache["labels"]


def plain(name):
    """The fallback: the raw name with spaces, first letter capitalised."""
    s = str(name or "").replace("_", " ").strip()
    return s[:1].upper() + s[1:]


def label(name):
    """The readable label for a report field; x:name (a record's extra field) is looked up by its name."""
    key = str(name or "").removeprefix("x:")
    return _labels().get(key) or plain(key)


def known():
    """How many fields have a label (for checks)."""
    return len(_labels())
