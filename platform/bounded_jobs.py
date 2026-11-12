"""Background work with a fixed number of worker threads and a bounded waiting list.

Before (external review, 2026-11-12) the Executive page started one thread per new filter combination for its 7-day
baseline, with no limit: clicking through many combinations started many threads, each reading up to seven days of
data at once. Jobs now run on at most `workers` threads; up to `queued` more wait their turn; beyond that a job is
refused (submit returns False) and the caller asks again later. The threads are daemon threads, as before, so they
never hold up a restart. Used by management.py.
"""
import queue
import threading


class Jobs:
    def __init__(self, name, workers, queued):
        self.name, self.workers = name, max(1, int(workers))
        self.limit = self.workers + max(0, int(queued))      # running + waiting
        self.q, self.lock, self.n, self.started = queue.Queue(), threading.Lock(), 0, 0

    def submit(self, fn, *args):
        """Run fn(*args) in the background; False when the waiting list is full (nothing is queued)."""
        with self.lock:
            if self.n >= self.limit:
                return False
            self.n += 1
            if self.started < self.workers:                   # workers start when first needed
                self.started += 1
                threading.Thread(target=self._work, daemon=True, name=f"{self.name}-{self.started}").start()
        self.q.put((fn, args))
        return True

    def pending(self):
        with self.lock:
            return self.n

    def _work(self):
        while True:
            fn, args = self.q.get()
            try:
                fn(*args)
            except Exception:                                 # noqa: BLE001  the job logs its own failures
                pass
            finally:
                with self.lock:
                    self.n -= 1
