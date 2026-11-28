# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
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
The built-in self-test's accounts are not logged. DATA_ACCESS_LOG=0 in .env turns the views off (the Audit portal then
says so, and CIS 3.14 is no longer backed by LG-15); downloads (data_exported) are always logged.
"""
import collections
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
    # the devices behind decoded beacons handed over as a finding (beacon_findings.py): their addresses for analysts
    "/api/beacon/finding/<fid>": ("data_viewed", "the devices behind decoded beacons (finding)"),
}
# Every request parameter says what was looked at, except these display and time options (review 2026-11-13: a list
# of the parameters to keep missed src_ip and most services filters, so different hosts' views were one "whole
# selection" and the repeats were dropped). A parameter added later is logged by default.
IGNORE = frozenset(("at", "demo", "from", "to", "limit", "latest", "since", "time", "n", "format", "_", "page", "sort", "download", "all"))
# views whose selection is sent in the request body (POST), never in the URL: logged from the body
BODY_VIEWS = frozenset(("/api/intelligence/report",))
# the lists the pages save as CSV files (download=1): an export, every time
DOWNLOADS = {"/api/insight/drill": "host list download (map CSV)", "/api/svc/drill": "host list download (services CSV)"}
SHOWN_MAX = 60         # each value is cut to this BEFORE the address finder reads it (a long value costs nothing)
_TAIL = re.compile(r"[0-9A-Fa-f:.]+$")


SEEN_MAX = 20000       # the views remembered for REPEAT_WINDOW; past it the oldest are forgotten first


def _cut(v, n):
    """v cut to n characters (the audit log keeps one short line per view); when something was cut, a half address
    left at the end goes too, and the text says in words how much is kept: "(the first 58 of 300 characters)", never
    "…" (the owner's rule, audit 2026-11-27)."""
    if len(v) <= n:
        return v
    kept = _TAIL.sub("", v[:n])
    return f"{kept} (the first {len(kept):,} of {len(v):,} characters)"


def enabled():
    return os.environ.get("DATA_ACCESS_LOG", "1") != "0"


class DataAccessLog:
    def __init__(self, audit_add, user_of, host_ref):
        self.add, self.user_of, self.host_ref = audit_add, user_of, host_ref
        # (person, path, selection) -> when last logged, oldest first: forgetting the old ones costs only them
        self.seen, self.lock = collections.OrderedDict(), threading.Lock()

    def selection(self, args):
        """What was looked at, from the request's parameters: addresses replaced by their host reference."""
        parts = []
        for k in sorted(set(args.keys()) - IGNORE)[:20]:
            vals = args.getlist(k) if hasattr(args, "getlist") else [args.get(k)]
            for v in [str(x) for x in vals if x][:10]:
                # cut once, BEFORE the address finder reads it (a long value costs nothing), so the count of kept
                # characters is of what was sent; the addresses in what is kept become host references
                v = ip_find.sub(_cut(v, SHOWN_MAX), lambda ip: f"host {self.host_ref(ip)}")
                name = ip_find.sub(_cut(k, 30), lambda ip: "host")
                parts.append(f"{name}={v}")
        sel = ", ".join(parts)
        return (_cut(sel, 400) if sel else "") or "the whole selection"

    def record(self, path, args, status):
        if status != 200 or path not in SENSITIVE:
            return False
        event, what = SENSITIVE[path]
        if args.get("download") == "1" and path in DOWNLOADS:
            # the drill-down list saved as a CSV in the browser: the page fetches it for the file, so the download is
            # logged as an export (review 2026-11-13: a list that fitted on screen was saved with no request at all)
            event, what = "data_exported", DOWNLOADS[path]
        # DATA_ACCESS_LOG=0 turns off the VIEWS only: a download is a copy of host data leaving the platform, so it is
        # always written to the audit log (this module is the one place these downloads are logged: no second entry)
        if event != "data_exported" and not enabled():
            return False
        user = self.user_of() or ""
        if not user or user.startswith("lg-selftest"):
            return False
        sel = self.selection(args)
        key = (user, path, sel)
        now = time.time()
        with self.lock:
            # every download is its own audit line: each copy of host data leaving the platform counts, even the same
            # list twice (review 2026-11-13); only VIEWS are written once per person and selection per window
            if event != "data_exported":
                # a download is never looked up here, so it leaves no key (audit 2026-11-27: each one was stored)
                if now - self.seen.get(key, 0) < REPEAT_WINDOW:
                    return False
                self.seen[key] = now
                self.seen.move_to_end(key)
                # forget the expired keys and, past SEEN_MAX, the oldest: only what goes is touched (audit
                # 2026-11-27: past 20,000 views in the window every request rebuilt the whole dict, and it kept growing)
                while self.seen:
                    k0, t0 = next(iter(self.seen.items()))
                    if now - t0 < REPEAT_WINDOW and len(self.seen) <= SEEN_MAX:
                        break
                    del self.seen[k0]
        self.add(event, user=user, target=what, detail=sel)
        return True


def register(app, audit_add, user_of, host_ref):
    """Log host-level data views after each request (Flask after_request); returns the logger."""
    log = DataAccessLog(audit_add, user_of, host_ref)
    from flask import request

    @app.after_request
    def _data_access(resp):
        try:
            if request.method == "POST" and request.path in BODY_VIEWS:
                # a view sent in the request body, so its addresses and searches stay out of URLs and the access log
                # (2026-11-14): logged from the body, the same way
                from werkzeug.datastructures import MultiDict
                b = request.get_json(silent=True) or {}
                pairs = [(k, str(v)) for k, v in b.items() if k != "filters" and not isinstance(v, (dict, list)) and v not in (None, "")]
                for k, vs in (b.get("filters") or {}).items() if isinstance(b.get("filters"), dict) else []:
                    pairs += [(str(k), str(v)) for v in (vs if isinstance(vs, list) else [vs])]
                log.record(request.path, MultiDict(pairs), resp.status_code)
            elif request.method == "GET":
                rule = request.url_rule.rule if request.url_rule is not None else ""
                if rule in SENSITIVE and rule != request.path:
                    # a route with a part in its path: logged by its rule, the part (a finding's ID) in the selection
                    from werkzeug.datastructures import MultiDict
                    args = MultiDict(list(request.args.items(multi=True)) + [(k, str(v)) for k, v in (request.view_args or {}).items()])
                    log.record(rule, args, resp.status_code)
                else:
                    log.record(request.path, request.args, resp.status_code)
        except Exception as exc:   # noqa: BLE001  (logging a view must never break the page)
            try:
                app.logger.warning("data access not logged for %s: %s", request.path, exc)
            except Exception:      # noqa: BLE001, S110
                pass
        return resp
    return log
