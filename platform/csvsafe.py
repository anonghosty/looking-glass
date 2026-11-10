"""Spreadsheet-safe CSV cells (no formula injection).

A cell that starts with = + - @ (or tab / carriage return, or the full-width forms some Excel locales accept) is
run as a formula when the CSV is opened in a spreadsheet. Values such as a device's vendor or product text come
from the scanned hosts themselves, so an attacker could plant "=HYPERLINK(...)". Such cells get a leading
apostrophe, which spreadsheets show as plain text. Numbers, strings that are only a number ("-3", "+1.5",
"12%"), and the "-" placeholder (dashes only) are left as they are.

Used by every CSV export (app.py reports, services_api.py host list, management.py tables). The browser downloads
in static/js/app.js and static/js/services.js apply the same rule.
"""
import csv
import re

TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n", "＝", "＋", "－", "＠")
_NUMBER = re.compile(r"[+-]?\d+(?:[.,]\d+)*%?|-+")   # a number, or the "-" placeholder (dashes only)


def cell(v):
    """One cell, made safe. Non-strings pass through unchanged."""
    if isinstance(v, str) and v[:1] in TRIGGERS and not _NUMBER.fullmatch(v):
        return "'" + v
    return v


def row(values):
    return [cell(v) for v in values]


class writer:
    """csv.writer whose rows are made safe: drop-in for csv.writer(buf)."""

    def __init__(self, f, *a, **kw):
        self._w = csv.writer(f, *a, **kw)

    def writerow(self, values):
        return self._w.writerow(row(values))

    def writerows(self, rows):
        for r in rows:
            self.writerow(r)
