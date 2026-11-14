"""Logging who views host-level data (CIS Controls v8.1 safeguard 3.14, "Log Sensitive Data Access"; review, 2026-11-13).

Exports were already logged per person (reports, CSV files, advisories, audit evidence). Viewing host-level data on the
pages was not: one host's activity, the lists of hosts behind a figure, a record's full details, an analysis. This
module writes one audit entry per view, in the "Data access and exports" tab:

    data_viewed     a page showed host-level data       detail: what kind, the selection (host references, never an IP)
    data_exported   a host list was downloaded (CSV)    (the services hosts.csv had no audit entry before: a gap)

Who, when, from where and what, like every audit entry. A host appears only as its opaque reference (HostRefs, the one
the pages use), never its address, so the audit log does not become a second copy of the data. The same person viewing
the same thing again within REPEAT_WINDOW seconds is not logged again (the audit log is append-only; a page polls);
every download is logged, the same list downloaded twice included.
The built-in self-test's accounts are not logged. DATA_ACCESS_LOG=0 in .env turns it off (the Audit portal then says
so, and CIS 3.14 is no longer backed by LG-15).
"""
import os
import re
import threading
import time

import ip_find

REPEAT_WINDOW = 600
# path -> (event, what it shows): GET requests answered 200 are logged
SENSITIVE = {
    "/api/events": ("data_viewed", "events (map)"),            # review 2026-11-13: the map's events were not logged
    "/api/svc/events": ("data_viewed", "records (services)"),
    "/api/related": ("data_viewed", "one host's activity (map)"),
    "/api/insight": ("data_viewed", "an analysis (map)"),
    "/api/insight/drill": ("data_viewed", "hosts behind a figure (map)"),
    "/api/svc/insight": ("data_viewed", "an analysis (services)"),
    "/api/svc/drill": ("data_viewed", "hosts behind a figure (services)"),
    "/api/svc/detail": ("data_viewed", "a record's details (services)"),
    "/api/svc/hosts.csv": ("data_exported", "host list download (services CSV)"),
    # routes with a part in the path, by their rule (review 2026-11-13: an advisor opening one organisation's advisory
    # saw its IP addresses, ports and reports, and nothing was logged)
    "/api/advisory/<fid>/net": ("data_viewed", "an organisation's hosts (advisory)"),
    # the advisory's PDF as it stands, read in the browser: the same hosts, so the same entry (review 2026-11-13)
    "/advisory/<fid>/preview": ("data_viewed", "an organisation's advisory report (preview)"),
    # the Abused or Compromised portal's records of one report on one day, with their host addresses (review 2026-11-14)
    "/api/intelligence/report": ("data_viewed", "a report's records (Abused or Compromised)"),
}
# Every request parameter says what was looked at, except these display and time options (review 2026-11-13: a list
# of the parameters to keep missed src_ip and most services filters, so different hosts' views were one "whole
# selection" and the repeats were dropped). A parameter added later is logged by default.
IGNORE = frozenset(("at", "demo", "from", "to", "limit", "latest", "since", "time", "n", "format", "_", "page", "sort", "download", "all"))
# the lists the pages save as CSV files (download=1): an export, every time
DOWNLOADS = {"/api/insight/drill": "host list download (map CSV)", "/api/svc/drill": "host list download (services CSV)"}
RAW_MAX = 120          # each value is cut to this BEFORE the address finder reads it (a long value costs nothing)
SHOWN_MAX = 60
_TAIL = re.compile(r"[0-9A-Fa-f:.]+$")


def _cut(v, n):
    """v cut to n characters; when something was cut, a half address left at the end goes too."""
    return v if len(v) <= n else _TAIL.sub("", v[:n]) + "…"


def enabled():
    return os.environ.get("DATA_ACCESS_LOG", "1") != "0"


class DataAccessLog:
    def __init__(self, audit_add, user_of, host_ref):
        self.add, self.user_of, self.host_ref = audit_add, user_of, host_ref
        self.seen, self.lock = {}, threading.Lock()

    def selection(self, args):
        """What was looked at, from the request's parameters: addresses replaced by their host reference."""
        parts = []
        for k in sorted(set(args.keys()) - IGNORE)[:20]:
            vals = args.getlist(k) if hasattr(args, "getlist") else [args.get(k)]
            for v in [str(x) for x in vals if x][:10]:
                v = ip_find.sub(_cut(v, RAW_MAX), lambda ip: f"host {self.host_ref(ip)}")
                name = ip_find.sub(_cut(k, 40), lambda ip: "host")
                parts.append(f"{_cut(name, 30)}={_cut(v, SHOWN_MAX)}")
        sel = ", ".join(parts)
        return (_cut(sel, 400) if sel else "") or "the whole selection"

    def record(self, path, args, status):
        if not enabled() or status != 200 or path not in SENSITIVE:
            return False
        user = self.user_of() or ""
        if not user or user.startswith("lg-selftest"):
            return False
        event, what = SENSITIVE[path]
        if args.get("download") == "1" and path in DOWNLOADS:
            # the drill-down list saved as a CSV in the browser: the page fetches it for the file, so the download is
            # logged as an export (review 2026-11-13: a list that fitted on screen was saved with no request at all)
            event, what = "data_exported", DOWNLOADS[path]
        sel = self.selection(args)
        key = (user, path, sel)
        now = time.time()
        with self.lock:
            # every download is its own audit line: each copy of host data leaving the platform counts, even the same
            # list twice (review 2026-11-13); only VIEWS are written once per person and selection per window
            if event != "data_exported" and now - self.seen.get(key, 0) < REPEAT_WINDOW:
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
                rule = request.url_rule.rule if request.url_rule is not None else ""
                if rule in SENSITIVE and rule != request.path:
                    # a route with a part in its path: logged by its rule, the part (a finding's ID) in the selection
                    from werkzeug.datastructures import MultiDict
                    args = MultiDict(list(request.args.items(multi=True)) + [(k, str(v)) for k, v in (request.view_args or {}).items()])
                    log.record(rule, args, resp.status_code)
                else:
                    log.record(request.path, request.args, resp.status_code)
        except Exception:          # noqa: BLE001  (logging a view must never break the page)
            pass
        return resp
    return log
