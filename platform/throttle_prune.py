"""Clearing out old failed-login records (external review, 2026-11-11).

auth.Throttle keeps a list of failure times per (address, name), per address, and per register/setup/forgot key.
A list was only trimmed when that same key was looked at again, so a key that was never used again (a one-off
guessed name, an address that went away) stayed in memory for as long as the service ran. On a public install that
grows without end. sweep() drops every time older than the longest window the throttle uses, and every key left
empty. It runs at most once a minute, from the calls that add a failure, so it costs nothing on normal requests.

Nothing about the locks changes: a time older than the longest window (1 hour) is already ignored by every check.
"""

LONGEST_WINDOW = 3600      # auth.Throttle: 15 minutes per name, 1 hour per address / registrations / setup / forgot
EVERY = 60                 # seconds between sweeps


class Sweeper:
    def __init__(self, longest=LONGEST_WINDOW, every=EVERY):
        self.longest, self.every, self.last = longest, every, 0.0

    def due(self, now):
        return now - self.last >= self.every

    def sweep(self, fail, now):
        """Trim `fail` ({key: [times]}) in place. Call with the throttle's lock held. Returns keys removed."""
        self.last = now
        gone = 0
        for key in list(fail):
            kept = [t for t in fail[key] if now - t < self.longest]
            if kept:
                fail[key] = kept
            else:
                del fail[key]
                gone += 1
        return gone

    def maybe(self, fail, now):
        return self.sweep(fail, now) if self.due(now) else 0
