# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Replay schedule: which day Looking Glass replays, and how far into it the replay is.

Shadowserver delivers a day's reports during the following day, so "yesterday" is usually not in MongoDB
at midnight. Instead of a fixed "now minus 24 hours" clock (which would skip everything before the import),
every day is replayed IN FULL, from 00:00 to 24:00 at real speed, starting when its report has arrived:

  playing   the day is replaying; position = 00:00 of the day + time since it started
  waiting   the previous day has finished (or nothing has started yet) and the next day's report is not in
            MongoDB yet; the replay holds at 00:00 of that day and is checked every minute
  settling  the report has started arriving; we wait until no new report has arrived for SETTLE, then the
            day replays from 00:00. Reports that arrive later still are added to the playing day at once
            (app.py checks MongoDB every 15 seconds) and announced in the browser.

When a day ends and the next day's report is already in, the next day starts straight away (no gap).
If the replay ever falls more than a day behind, it skips to the newest available day.
The state is saved to a small JSON file so a service restart continues where it was.
"""
import json
import os
import threading
from datetime import datetime, timedelta, timezone

DAY = timedelta(days=1)


def _utcnow():
    return datetime.now(timezone.utc)


def _start(dt):
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def _iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if dt else None


def _parse(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


class ReplaySchedule:
    def __init__(self, path, offset_hours, settle_seconds, has_data, now=_utcnow, logger=None):
        self.path = path
        self.offset = timedelta(hours=offset_hours)
        self.settle = timedelta(seconds=settle_seconds)
        self.has_data = has_data          # callable(day_start) -> number of records for that day
        self._now = now
        self.log = logger
        self.lock = threading.RLock()
        self.day = None                   # 00:00 of the day being replayed (or awaited)
        self.started = None               # wall time at which that day's 00:00 was played; None = not playing
        self.seen_at = None               # wall time the awaited day's report was first seen (or last grew)
        self.seen_rows = None             # rows of the awaited day at the last check (growth restarts the settle)
        self.on_start = None              # callback(day) when a day starts (used to reload it fully)
        self._started_day = None          # a day that just started; on_start runs for it once the lock is released
        self._memo = None                 # has_data answers of the tick running now (_rows)
        self._load()

    # ------------------------------------------------------------------ state
    def _load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                s = json.load(f)
            day, started, seen = _parse(s.get("day")), _parse(s.get("started")), _parse(s.get("seen_at"))
            # ignore a stale file (for example after the service was off for days)
            if day and day >= self.target() - 2 * DAY:
                self.day, self.started, self.seen_at = day, started, seen
        except Exception as e:   # a broken file just means starting fresh
            self._warn("Could not read replay schedule %s: %s", self.path, e)

    def _save(self):
        if not self.path:
            return
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump({"day": _iso(self.day), "started": _iso(self.started), "seen_at": _iso(self.seen_at)}, f)
            os.replace(tmp, self.path)
        except Exception as e:
            self._warn("Could not save replay schedule: %s", e)

    def _warn(self, *a):
        if self.log:
            self.log.warning(*a)

    def target(self, now=None):
        """The day a fixed 24-hour delay would show: normally yesterday."""
        return _start((now or self._now()) - self.offset)

    # ------------------------------------------------------------------ queries
    def position(self, now=None):
        """(replay time, state) where state is playing, waiting or settling."""
        now = now or self._now()
        with self.lock:
            if self.day is None:
                return now - self.offset, "playing"
            if self.started is None:
                return self.day, ("settling" if self.seen_at else "waiting")
            pos = self.day + (now - self.started)
            end = self.day + DAY
            # hold on the last moment of the day until the next tick moves on
            return (min(pos, end - timedelta(milliseconds=1)), "playing")

    def status(self, now=None):
        now = now or self._now()
        pos, state = self.position(now)
        with self.lock:
            normal = now - self.offset
            return {
                "state": state,
                "replay_now": _iso(pos),
                "replay_day": self.day.date().isoformat() if self.day else pos.date().isoformat(),
                "day_start": _iso(self.day or _start(pos)),
                "day_end": _iso((self.day or _start(pos)) + DAY),
                "started_at": _iso(self.started),
                "report_seen_at": _iso(self.seen_at),
                "settle_until": _iso(self.seen_at + self.settle) if self.seen_at else None,
                "delay_seconds": max(0, round((normal - pos).total_seconds())) if state == "playing" else None,
            }

    # ------------------------------------------------------------------ transitions
    def tick(self, now=None):
        """Advance the schedule. Called every few seconds from a background thread.

        The day reload (on_start) runs AFTER the lock is released: loading a day from MongoDB takes seconds, and
        while the lock is held every page asking for the replay position (position, status) would wait for it."""
        try:
            self._tick(now)
        finally:
            with self.lock:
                day, self._started_day = self._started_day, None
            if day is not None and self.on_start:
                try:
                    self.on_start(day)
                except Exception as e:
                    self._warn("on_start failed: %s", e)

    def _rows(self, day):
        """has_data(day), asked once per day per tick (audit 2026-11-27: up to three MongoDB counts of one day per
        tick); outside a tick it asks every time."""
        memo = self._memo
        if memo is None:
            return self.has_data(day)
        if day not in memo:
            memo[day] = self.has_data(day)
        return memo[day]

    def _tick(self, now=None):
        with self.lock:                   # (re-entrant: the tick itself runs under the same lock)
            self._memo = {}
            try:
                self._tick_once(now)
            finally:
                self._memo = None

    def _tick_once(self, now=None):
        now = now or self._now()
        with self.lock:
            T = self.target(now)
            if self.day is None:
                # first start: if yesterday's report is in, play it on the normal 24-hour schedule
                if self._rows(T):
                    self._begin(T, T + self.offset, now, "first start")
                else:
                    self._await(T, now)
                return
            if self.started is None:
                self._check_waiting(now, T)
                return
            if self.day + (now - self.started) < self.day + DAY:
                return
            # the day has been replayed completely: move on
            nxt = self.day + DAY
            if nxt < T and self._rows(T):
                nxt = T          # more than a day behind: skip to the newest day
            if self._rows(nxt):
                # the report was already in before the previous day ended: continue without a gap
                cont = self.started + DAY if nxt == self.day + DAY else now
                self._begin(nxt, cont, now, "previous day finished, report already in")
            else:
                self._await(nxt, now)

    def _check_waiting(self, now, T):
        if self.day < T and self._rows(T) and not self._rows(self.day):
            self._await(T, now)             # the awaited day never came; move on to the newest one
            return
        if not self._rows(self.day):
            # nothing loaded (yet): keep any settle time already running. A failed or not-yet-finished load
            # (for example right after a restart) must not make the schedule forget that the report arrived.
            return
        rows = self._rows(self.day)
        if self.seen_at is not None and self.seen_rows is not None and rows > self.seen_rows:
            # another report arrived while settling: wait the settle time again from now
            self.seen_at, self.seen_rows = now, rows
            self._save()
            self._warn("More of the %s reports arrived (%s rows); replay starts %ss after the last one",
                       self.day.date(), rows, int(self.settle.total_seconds()))
            return
        self.seen_rows = rows
        if self.seen_at is None:
            self.seen_at = now
            self._save()
            self._warn("Report for %s has arrived; replay starts after %ss settle time", self.day.date(),
                       int(self.settle.total_seconds()))
            if self.settle.total_seconds() > 0:
                return
        if now - self.seen_at >= self.settle:
            self._begin(self.day, now, now, "report arrived")

    def _begin(self, day, started, now, why):
        self.day, self.started, self.seen_at, self.seen_rows = day, started, None, None
        self._save()
        self._warn("Replay of %s from 00:00 started at %s (%s)", day.date(), _iso(started), why)
        self._started_day = day           # reloaded by tick() once the lock is released

    def _await(self, day, now):
        if self.day != day or self.started is not None:
            self._warn("Waiting for the %s report", day.date())
        self.day, self.started, self.seen_at, self.seen_rows = day, None, None, None
        self._save()
        if self._rows(day):
            self._check_waiting(now, self.target(now))
