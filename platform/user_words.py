# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Error words written for the person reading them, kept apart from the error itself.

An answer to the browser shows an error's words only when Looking Glass wrote them for the reader: raised as Said, or
registered with register(). Anything else (a library's own message, Python's) gets a fixed fallback, and its detail
belongs in the service's log or the audit, never in an answer (CodeQL py/stack-trace-exposure, 2026-11-25: the
connectors and the passkey checks passed str(e) to answers, and the passkey library's own text reached the browser).

The words are looked up by the error, not read from it: words(e) returns what register() stored for exactly that
error object, or the fallback.
"""
import weakref

FALLBACK = "That could not be done. Try again, or ask an administrator to check the service's log."
_WORDS = weakref.WeakKeyDictionary()


def register(exc, text):
    """Keep text as the words to show for this error (an error class of Looking Glass's own calls this)."""
    try:
        _WORDS[exc] = str(text)
    except TypeError:            # an object that cannot be weakly referenced: it simply gets the fallback
        pass
    return exc


class Said(ValueError):
    """A ValueError whose text Looking Glass wrote for the reader: safe to show in an answer. detail (optional) is for
    the log or the audit only, never shown."""

    def __init__(self, text, detail=""):
        super().__init__(text)
        self.detail = str(detail or "")
        register(self, text)


def words(exc, fallback=FALLBACK):
    """The words to show in an answer for exc: what Looking Glass wrote for it, else the fallback."""
    try:
        return _WORDS.get(exc, fallback)
    except TypeError:
        return fallback
