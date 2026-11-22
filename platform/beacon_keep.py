# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The beacon decoder's public answers, kept across restarts (the user, 2026-11-17: after every restart Intel gathered
took about 22 s, almost all of it decoding the day's request lines again: 1,535 lines at about 14 ms each).

beacon_decode._summary works out, per request line and host, the public summary of its beacon: format, operator,
version, OS family and state, the fields researchers may see (beacon_decode.public). Those answers are kept here, in
data/beacon_summaries.json (mode 600), so the first count after a restart reads them instead of decoding again.

What the file holds: per entry a SHA-256 of the request line and host (never the line, the host or any address) and
the public summary. Never the decoded JSON, the key, the MAC or any other device detail.
Kept only while the decoder is the same: the file carries a fingerprint of beacon_decode.py; a different decoder (an
update that decodes more, or differently) starts an empty file, so an answer is never older than the code.
At most MAX_ENTRIES (BEACON_KEEP_MAX in .env, for countries with many more check-ins), the oldest dropped first.
Written at most once every FLUSH_SECONDS while new answers come in, and at exit: a big file is not rewritten over and
over during a busy day. Each different summary is held once in memory (nearly all are the same few), so 200,000 kept
answers cost little more than their keys.
Any problem reading or writing the file only means decoding again, as before: never an error for the page."""
import atexit
import collections
import hashlib
import json
import logging
import os
import threading
import time

MAX_ENTRIES = int(os.environ.get("BEACON_KEEP_MAX", "200000"))
FLUSH_SECONDS = 60
log = logging.getLogger("looking-glass")


def fingerprint(path):
    """The decoder's identity: a hash of its source file (any change, a different decoder)."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()[:16]
    except OSError:
        return ""


def key_of(url, host):
    return hashlib.sha256(f"{url}\0{host or ''}".encode("utf-8", "replace")).hexdigest()[:40]


class SummaryStore:
    def __init__(self, path, version):
        self.path, self.version = path, version
        self.lock = threading.Lock()
        self.data = collections.OrderedDict()
        self.shared = {}                              # each different summary once: entries point to it
        self.dirty, self.flushed_at = 0, time.time()
        self.hits = self.misses = 0
        self._load()
        atexit.register(self.flush)

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict) or raw.get("version") != self.version or not self.version:
            return                                   # another decoder's answers: not used
        for k, v in (raw.get("entries") or {}).items():
            if isinstance(k, str) and isinstance(v, list) and all(isinstance(p, list) and len(p) == 2 for p in v):
                self.data[k] = self._one(tuple((str(a), b if isinstance(b, (str, int, float, bool)) or b is None else str(b))
                                               for a, b in v))
        while len(self.data) > MAX_ENTRIES:
            self.data.popitem(last=False)

    def _one(self, summary):
        return self.shared.setdefault(summary, summary)

    def get(self, url, host):
        with self.lock:
            hit = self.data.get(key_of(url, host))
            if hit is None:
                self.misses += 1
            else:
                self.hits += 1
            return hit

    def put(self, url, host, summary):
        k = key_of(url, host)
        with self.lock:
            if self.data.get(k) == summary:
                return
            self.data[k] = self._one(summary)
            self.data.move_to_end(k)
            while len(self.data) > MAX_ENTRIES:
                self.data.popitem(last=False)
            self.dirty += 1
            due = time.time() - self.flushed_at > FLUSH_SECONDS
        if due:
            self.flush()

    def flush(self):
        with self.lock:
            if not self.dirty:
                return
            body = {"version": self.version, "entries": {k: [list(p) for p in v] for k, v in self.data.items()}}
            self.dirty, self.flushed_at = 0, time.time()
        tmp = f"{self.path}.{os.getpid()}.tmp"
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(body, f, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:                          # a full disk or a read-only folder: decoding again next time
            log.warning("beacon answers not kept (%s): they are worked out again after a restart", e)
            try:
                os.remove(tmp)
            except OSError:
                pass
