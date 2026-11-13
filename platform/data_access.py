"""Logging who views host-level data (CIS Controls v8.1 safeguard 3.14, "Log Sensitive Data Access"; review, 2026-11-13).

Exports were already logged per person (reports, CSV files, advisories, audit evidence). Viewing host-level data on the
pages was not: one host's activity, the lists of hosts behind a figure, a record's full details, an analysis. This
module writes one audit entry per view, in the "Data access and exports" tab:

    data_viewed     a page showed host-level data       detail: what kind, the selection (host references, never an IP)
    data_exported   a host list was downloaded (CSV)    (the services hosts.csv had no audit entry before: a gap)

Who, when, from where and what, like every audit entry. A host appears only as its opaque reference (HostRefs, the one
the pages use), never its address, so the audit log does not become a second copy of the data. The same person viewing
the same thing again within REPEAT_WINDOW seconds is not logged again (the audit log is append-only; a page polls).
The built-in self-test's accounts are not logged. DATA_ACCESS_LOG=0 in .env turns it off (the Audit portal then says
so, and CIS 3.14 is no longer backed by LG-15).
"""
import os
import threading
import time

import ip_find

REPEAT_WINDOW = 600
# path -> (event, what it shows): GET requests answered 200 are logged
SENSITIVE = {
    "/api/related": ("data_viewed", "one host's activity (map)"),
    "/api/insight": ("data_viewed", "an analysis (map)"),
    "/api/insight/drill": ("data_viewed", "hosts behind a figure (map)"),
    "/api/svc/insight": ("data_viewed", "an analysis (services)"),
    "/api/svc/drill": ("data_viewed", "hosts behind a figure (services)"),
    "/api/svc/detail": ("data_viewed", "a record's details (services)"),
    "/api/svc/hosts.csv": ("data_exported", "host list download (services CSV)"),
}
# the request parameters that say what was looked at (others are display options)
KEYS = ("ref", "kind", "value", "metric", "source", "report", "service", "family", "issue", "region", "city", "network",
        "attack", "infection", "severity", "code", "id")


def enabled():
    return os.environ.get("DATA_ACCESS_LOG", "1") != "0"


class DataAccessLog:
    def __init__(self, audit_add, user_of, host_ref):
        self.add, self.user_of, self.host_ref = audit_add, user_of, host_ref
        self.seen, self.lock = {}, threading.Lock()

    def selection(self, args):
        """What was looked at, from the request's parameters: addresses replaced by their host reference."""
        parts = []
        for k in KEYS:
            v = args.get(k)
            if v:
                v = ip_find.sub(str(v), lambda ip: f"host {self.host_ref(ip)}")
                parts.append(f"{k}={v[:60]}")
        return ", ".join(parts)[:220] or "the whole selection"

    def record(self, path, args, status):
        if not enabled() or status != 200 or path not in SENSITIVE:
            return False
        user = self.user_of() or ""
        if not user or user.startswith("lg-selftest"):
            return False
        event, what = SENSITIVE[path]
        sel = self.selection(args)
        key = (user, path, sel)
        now = time.time()
        with self.lock:
            if now - self.seen.get(key, 0) < REPEAT_WINDOW:
                return False
            self.seen[key] = now
            if len(self.seen) > 20000:                    # forget old keys, never grow without bound
                cut = now - REPEAT_WINDOW
                self.seen = {k: t for k, t in self.seen.items() if t > cut}
        self.add(event, user=user, target=what, detail=sel)
        return True


def register(app, audit_add, user_of, host_ref):
    """Log host-level data views after each request (Flask after_request); returns the logger."""
    log = DataAccessLog(audit_add, user_of, host_ref)
    from flask import request

    @app.after_request
    def _data_access(resp):
        try:
            if request.method == "GET":
                log.record(request.path, request.args, resp.status_code)
        except Exception:          # noqa: BLE001  (logging a view must never break the page)
            pass
        return resp
    return log
