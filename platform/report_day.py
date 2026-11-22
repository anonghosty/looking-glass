# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Which day Intel gathered counts (the user, 2026-11-17: "across reports is supposed to count 16 Nov only ie
yesterday"). Before, it counted every day in memory: on 17 Nov a services pattern counted 53 devices across 15 and 16
Nov while the Executive portal, showing 16 Nov, counted 50 (and 43 on 16 Nov alone).

A scope:
* None or "report": the report day, the day being replayed (the Executive portal's default day); when it is not in
  memory, the newest day there. What researchers and management are shown: Intel gathered, Across reports, the Notes
  window, analyst-code pages, a services report's page.
* "YYYY-MM-DD": that day (the Executive portal's chosen day); every day in memory when it is not there.
* "memory": every day in memory: the analysts' combination search and code resolution, which have their own range.

select(days, scope, replay_now) -> the day copies to count (each with .start).
"""
from datetime import timezone


def report_date(replay_now):
    """The report day's date (YYYY-MM-DD), or None when the replay time cannot be read."""
    try:
        t = replay_now() if replay_now else None
    except Exception:                                  # noqa: BLE001  (outside a running platform)
        t = None
    if t is None:
        return None
    if t.tzinfo and t.utcoffset():
        t = t.astimezone(timezone.utc)
    return t.date().isoformat()


def select(days, scope=None, replay_now=None):
    days = [d for d in days if d is not None]
    if scope == "memory" or not days:
        return days
    if scope in (None, "report"):
        date = report_date(replay_now)
        hit = [d for d in days if d.start.date().isoformat() == date]
        return hit[:1] or [max(days, key=lambda d: d.start)]
    hit = [d for d in days if d.start.date().isoformat() == scope]
    return hit[:1] or days


def scope_key(scope):
    return scope if scope not in (None, "report") else "report"
