# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shares and cut lists in words that never mislead, for every page, PDF and CSV (the user, 2026-11-26: "check every
chart, everything, every grain of sand: nothing gets missing on the whole platform"). The browser has the same rules
in static/js/loader.js (LGShare): the same text for the same share on a page and in its PDF (Bend law f compares them).

    pct(x, d=0)             a part that has records is never "0%", a part of the whole is never "100%": "<1%", ">99%"
                            (d decimals: "<0.1%", ">99.9%"); x is a fraction (0..1); rounded half up
    of(part, total, d=0)    the same for a count of a total, rounded half up exactly (a total of 0: "0%")
    part(n, total)          a count's share in combination tables and PDFs: one decimal under 10%, whole percents above
    cut(shown, total, noun) "Top 8 of 23 networks" when a list is cut, "" when every one is shown
    other(rows, total)      what the rows leave out of the total (an "Other" row's count), never below 0
"""
import math


def _words(r, d, pos, part):
    """r: the share in units of the last digit shown (per cent, or tenths of a per cent with d=1)."""
    whole = 100 * 10 ** d
    if pos and r <= 0:                          # rounded away: never "0%" for a part that has records
        return f"<{_digits(1, d)}%"
    if part and r >= whole:                     # rounded up to the whole: never "100%" for a part
        return f">{_digits(whole - 1, d)}%"
    return f"{_digits(r, d)}%"


def _digits(r, d):
    if not d:
        return str(r)
    s = str(r).rjust(d + 1, "0")
    return f"{s[:-d]}.{s[-d:]}"


def pct(x, d=0):
    x = x or 0
    return _words(math.floor(x * 100 * 10 ** d + 0.5), d, x > 0, x < 1)


def of(part, total, d=0):
    if not total:
        return "0%"
    return _words((2 * part * 100 * 10 ** d + total) // (2 * total), d, part > 0, part < total)


def part(n, total):
    """A count's share of a total in tables and sentences (combos.py, combo_pdf.py: one rule, audit 3-13): one decimal
    under 10% ("<0.1%" rather than "0%" for at least one), whole percents from 10%, ">99%" rather than "100%" for a part
    of the whole; none, or a total of 0: "0%" (the same as of() and LGShare.of)."""
    n, total = n or 0, total or 0
    if not n or total <= 0:
        return "0%"
    if n < .001 * total:
        return "<0.1%"
    return of(n, total, 1) if n < .1 * total else of(n, total)


def cut(shown, total, noun=""):
    return f"Top {shown:,} of {total:,}{' ' + noun if noun else ''}" if total > shown else ""


def other(rows, total, key="count"):
    return max(0, (total or 0) - sum((r.get(key) or 0) for r in rows or []))
