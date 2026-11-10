"""Where and when each infection / category name was last seen, beyond the day held in memory.

The Definitions page says which reports a name was seen in. Only the replay day is in memory, so a name seen a few days
ago looked "never seen". This keeps a small record, data/seen_names.json:

    {"names": {"wd": {"Sinkhole DNS": "2026-11-07"}, ...}, "days": ["2026-10-26", ..., "2026-11-08"]}

* every replay day that passes through memory is added (app.py calls update() once a minute at most);
* when the record does not exist yet, the last BACKFILL_DAYS days are read from MongoDB once, in the background, by one
  worker only (a lock file);
* sightings older than KEEP_DAYS days are dropped. The page shows "Seen in" for the replay day, otherwise "Last seen in
  <report> on <date>", otherwise "Not seen in the last N days".

Reports are stored by their readable name (the report list's label). Nothing here identifies a host.
"""
import json
import os
import threading
import time
from datetime import date, timedelta

KEEP_DAYS = 30
BACKFILL_DAYS = 14


class SeenIndex:
    def __init__(self, path, logger=None):
        self.path, self.log = path, logger
        self.lock = threading.Lock()
        self.data, self.mtime = {"names": {}, "days": []}, None
        self.refresh()

    def refresh(self):
        """Read the record if another worker (or the backfill) changed it."""
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return
        if m == self.mtime:
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return
        with self.lock:
            for n, reps in (d.get("names") or {}).items():
                cur = self.data["names"].setdefault(n, {})
                for r, day in reps.items():
                    if cur.get(r, "") < day:
                        cur[r] = day
            self.data["days"] = sorted(set(self.data["days"]) | set(d.get("days") or []))
            self.mtime = m

    def update(self, day_iso, events, labels):
        """Add one day's sightings (events with 'infection' and 'source'); saved only when something is new."""
        new = False
        with self.lock:
            names = self.data["names"]
            for e in events:
                n = (e.get("infection") or "").lower()
                if not n:
                    continue
                rep = labels.get(e.get("source"), e.get("source") or "")
                cur = names.setdefault(n, {})
                if cur.get(rep, "") < day_iso:
                    cur[rep], new = day_iso, True
            if day_iso not in self.data["days"]:
                self.data["days"] = sorted(set(self.data["days"]) | {day_iso})
                new = True
            if new:
                self._prune()
                self._save()

    def _prune(self):
        if not self.data["days"]:
            return
        cut = (date.fromisoformat(self.data["days"][-1]) - timedelta(days=KEEP_DAYS)).isoformat()
        self.data["days"] = [d for d in self.data["days"] if d > cut]
        for n in list(self.data["names"]):
            kept = {r: d for r, d in self.data["names"][n].items() if d > cut}
            if kept:
                self.data["names"][n] = kept
            else:
                del self.data["names"][n]

    def _save(self):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
            self.mtime = os.path.getmtime(self.path)
        except OSError as exc:
            if self.log:
                self.log.warning("seen index not saved: %s", exc)

    def last_seen(self, name):
        """[(report, last date)] for a name, newest first."""
        with self.lock:
            reps = self.data["names"].get((name or "").lower(), {})
            return sorted(reps.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)

    def covered_days(self):
        with self.lock:
            return len(self.data["days"])

    def backfill(self, load_day, day_start, utcnow, labels_fn):
        """Once per installation: the last BACKFILL_DAYS days from MongoDB, in the background, one worker. A marker
        (<record>.done) says it has run; the record itself may already exist from the replay days."""
        done = self.path + ".done"
        if os.path.exists(done):
            return
        lock = self.path + ".backfill"
        try:
            fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            if time.time() - os.path.getmtime(lock) < 3600:
                return                                   # another worker is on it
            os.utime(lock)                               # a stale lock (crashed worker): take it over

        def run():
            try:
                for back in range(BACKFILL_DAYS, 0, -1):
                    day = day_start(utcnow() - timedelta(days=back))
                    try:
                        d = load_day(day)
                    except Exception as exc:             # a day that cannot be read is skipped
                        if self.log:
                            self.log.warning("seen index: %s not read: %s", day.date(), exc)
                        continue
                    self.update(day.date().isoformat(), d.events, labels_fn())
                    del d
                    time.sleep(1)
                if self.log:
                    self.log.warning("seen index: %d names over %d days", len(self.data["names"]), self.covered_days())
                with open(done, "w") as f:
                    f.write(f"backfilled {BACKFILL_DAYS} days\n")
            finally:
                try:
                    os.remove(lock)
                except OSError:
                    pass
        threading.Thread(target=run, name="seen-index-backfill", daemon=True).start()
