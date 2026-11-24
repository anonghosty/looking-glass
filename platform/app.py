# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shadowserver live threat map: Flask backend.

Replays events from REPLAY_OFFSET_HOURS ago (default 24h: yesterday) as if they were happening now.

Every collection that describes a source -> destination communication is discovered automatically
(see sources.py) and the replay day's rows of all of them are loaded into memory, normalised into one
schema and tagged with their source report (collection) and attack type. Rows are found with the
existing `filename` index: filenames start with the report date, e.g.
"2026-11-05-event4_sinkhole_http-123-country-geo.csv". If no files match, FALLBACK_SCAN=1 queries
`extracted_date` instead (slow without an index on that field).
"""
import bisect
import hashlib
import json
import os
import random
import re
import sys
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl  # noqa: F401  (analytics_api.py's, through this module)

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, render_template, request  # noqa: F401  (Response: also the moved modules', through this module)
from pymongo import MongoClient
from werkzeug.datastructures import MultiDict  # noqa: F401  (analytics_api.py's, through this module)

from geo import Geocoder
from malpedia import Malpedia
from privacy import AsnRegistry, HostRefs, mask_event, mask_ip, mask_text
from respcache import ResultCache, day_key, filters_key

RCACHE = ResultCache()      # whole-day results shared by every viewer, keyed on the loaded day (see respcache.py)
from settings import Settings
import timezones  # noqa: E402  (display time zone: Settings > Country)
import special_reports  # noqa: E402  (one-off Special Reports, kept out of the replay)
import auth
import security
import services_api
from schedule import ReplaySchedule
from services import report_info
from sources import INTERNAL, STD_FIELDS, Registry, normalise

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

MAPBOX_TOKEN = os.environ.get("MAPBOX_TOKEN", "")
OFFSET_HOURS = float(os.environ.get("REPLAY_OFFSET_HOURS", "24"))
MAX_PER_POLL = int(os.environ.get("MAX_EVENTS_PER_POLL", "400"))
DAY_RELOAD_SECONDS = int(os.environ.get("DAY_RELOAD_SECONDS", "600"))
# once a day's report starts arriving, wait this long (so every report is imported) before replaying it from 00:00
SETTLE_SECONDS = int(os.environ.get("REPORT_SETTLE_SECONDS", "600"))

import db_connect  # noqa: E402  (where the database is: loopback or internal only; TLS for one on another computer)
import filesig  # noqa: E402
try:
    _DB_KW = db_connect.kwargs(os.environ.get)
except db_connect.Refused as _why:     # a public or unencrypted database: the service does not start, and says why
    raise SystemExit(f"Looking Glass will not start: {_why} (platform/.env, see docs/CONFIGURATION.md)") from None
client = MongoClient(
    **_DB_KW,
    username=os.environ.get("MONGO_USER") or None,
    password=os.environ.get("MONGO_PASSWORD") or None,
    authSource=os.environ.get("MONGO_AUTH_SOURCE", "admin"),
    serverSelectionTimeoutMS=5000,
    tz_aware=True,
)
db = client[os.environ.get("MONGO_DB", "shadowserver")]

app = Flask(__name__)
app.json.sort_keys = False   # keep breakdown order (most relevant first)


@app.url_defaults
def _static_version(endpoint, values):
    """Scripts and styles get ?v=<file time> in their address: after an update every browser loads the new code at once
    instead of a copy it kept (otherwise buttons can run old code until the cache expires)."""
    if endpoint == "static" and "filename" in values and "v" not in values:
        try:
            values["v"] = int(os.stat(os.path.join(app.static_folder, values["filename"])).st_mtime)
        except OSError:
            pass

# the geocoding cache lives in data/ (the only folder the hardened service may write; deploy/looking-glass.service.template)
_GEOCACHE = os.path.join(BASE_DIR, "data", "geocache.json")
if not os.path.exists(_GEOCACHE) and os.path.exists(os.path.join(BASE_DIR, "geocache.json")):
    import shutil
    shutil.copy2(os.path.join(BASE_DIR, "geocache.json"), _GEOCACHE)
geocoder = Geocoder(MAPBOX_TOKEN, _GEOCACHE)
_csv = lambda v: [x.strip() for x in (v or "").split(",") if x.strip()]
registry = Registry(
    db,
    exclude=_csv(os.environ.get("EXCLUDE_COLLECTIONS", "outdated_dnssec_key")),
    include=_csv(os.environ.get("MONGO_COLLECTIONS")) or None,   # empty = auto-discover all
    ttl=int(os.environ.get("REGISTRY_REFRESH_SECONDS", "3600")),  # full re-check; new collections: within 15 s
    logger=app.logger,
    fallback_scan=os.environ.get("FALLBACK_SCAN") == "1",
)

EVENT_FIELDS = STD_FIELDS + ["source", "source_label", "attack_class"]
# Every field the map, stream, Intel and analyses can be narrowed by (one model everywhere).
# src_asn / dst_asn take a company name, demo alias or AS number; "request" is the request path (GET /x/).
FILTER_FIELDS = ("source", "attack_class", "infection", "severity", "tag", "src_city", "dst_geo", "dst_port",
                 "protocol", "src_geo", "http_host", "src_ip", "src_asn", "dst_asn", "dst_ip", "dst_city",
                 "http_agent", "request", "beacon")
# "beacon" is not a stored field: the decoded beacon's label ("CLogin check-in, Android"), beacon_stats.label()
FACET_FIELDS = ("source", "attack_class", "infection", "severity", "tag", "src_city", "dst_geo", "dst_port", "protocol", "src_geo")
EMPTY_LABEL = {"infection": "unknown", "tag": "untagged", "severity": "unrated"}

asn_registry = AsnRegistry(os.path.join(BASE_DIR, "data", "asns.json"), logger=app.logger)
# Settings shared by both platforms (country, constituency): defaults from .env, saved on /settings
settings = Settings(os.path.join(BASE_DIR, "data", "settings.json"))
host_refs = HostRefs(os.environ.get("REF_SECRET"))
malpedia = Malpedia(os.environ.get("MALPEDIA_TOKEN"), os.path.join(BASE_DIR, "data", "malpedia_cache.json"), logger=app.logger)
import cves  # noqa: E402  (NVD, CISA KEV and EPSS for the services platform's issues)
from malpedia import MAX_PER_MINUTE as MAX_MP  # noqa: E402,F401  (lookup_jobs.py's, through this module)
import offline_names  # noqa: E402  (MISP Galaxy + MITRE ATT&CK, read from data/ only: behind Malpedia, nothing sent out)
OFFLINE_NAMES = offline_names.OfflineNames(os.path.join(BASE_DIR, "data"), needles=Malpedia.needles)
cve_intel = cves.CveIntel(os.path.join(BASE_DIR, "data", "cve_cache.json"), os.environ.get("NVD_API_KEY", ""), logger=app.logger)
PUBLIC_DEMO = os.environ.get("PUBLIC_DEMO") == "1"   # force demo masking for every request
# requests slower than SLOW_REQUEST_S, by route pattern only, so slow pages in real use can be found (slow_log.py);
# first, so it times the whole request
import slow_log  # noqa: E402
slow_log.install(app, os.path.join(BASE_DIR, "data"))
# who is using the service and what each request costs, for the Task monitor (request_tracker.py; memory only)
import request_tracker  # noqa: E402
request_tracker.install_start(app)
# who may connect, host names, cross-site writes, security headers, request size (security.py, docs/SECURITY.md)
security.install(app, app.logger)
# login, accounts, roles and sessions (auth.py): every page and API needs a login
AUTH = auth.install(app, BASE_DIR, app.logger)
request_tracker.install_tag(app)     # after the sign-in check: the running request knows its account
# heavy views per person: at most HEAVY_PER_USER at once (the rest wait their turn), HEAVY_PER_MINUTE a minute
# (request_limits.py; review of d82a436: one person could hold every thread)
import request_limits  # noqa: E402
HEAVY_LIMITS = request_limits.install(
    app, ("/api/stats", "/api/geo", "/api/insight", "/api/insight/drill", "/api/svc/stats", "/api/svc/insight",
          "/api/svc/drill", "/api/svc/regions", "/api/svc/hosts.csv", "/api/mgmt/report", "/api/insight/report",
          "/api/svc/report", "/api/insight/report.pdf", "/api/svc/report.pdf", "/api/intelligence/host", "/api/intel/match"),
    lambda: (None if (getattr(g, "user", None) or {}).get("automation")
             else ("u:" + g.user["user"]) if getattr(g, "user", None) else ("a:" + (request.remote_addr or ""))))
# the security self-test clears this computer's login counters itself, so it never restarts the service (retest_reset.py)
import retest_reset  # noqa: E402
retest_reset.install(app, {"throttle": AUTH["throttle"], "audit": AUTH["audit"]})
# admins see locked sign-ins and can lift one (lockouts.py)
import lockouts  # noqa: E402
lockouts.install(app, {"throttle": AUTH["throttle"], "audit": AUTH["audit"], "has_perm": AUTH["has_perm"],
                       "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"]})
# definitions, notes and network corrections name the person by their registered full name, not the username (people.py)
from people import People  # noqa: E402
people = People(AUTH["users"])


def _by(e, key="curated_by"):
    """Who defined or changed a record, as shown to people: their full name (people.py)."""
    return people.name((e or {}).get(key, ""), (e or {}).get(key + "_name", ""))


def defined_entry(e):
    """A definition with evidence (references or a Malpedia family); shipped ones have no author and are Looking Glass's."""
    return bool(e and (e.get("references") or e.get("malpedia") or e.get("description")))


def _me():
    """The signed-in account's username, and the full name saved with what they change (kept if the account goes)."""
    u = (getattr(g, "user", None) or {}).get("user", "admin")
    return u, people.full_name(u)

from pymongo.errors import OperationFailure as _MongoAuthError, PyMongoError as _MongoError  # noqa: E402
_DB_WARNED = {"at": 0.0}


@app.errorhandler(_MongoError)
def _database_unavailable(exc):
    """MongoDB down, unreachable, or refusing the account in .env: a clear 503 (never a crash page), logged at most
    once a minute with what to check."""
    if isinstance(exc, _MongoAuthError) and getattr(exc, "code", None) in (13, 18):
        why = "MongoDB refuses the account in platform/.env (MONGO_USER / MONGO_PASSWORD / MONGO_AUTH_SOURCE)"
    else:
        why = f"MongoDB at {db_connect.describe(os.environ.get)} cannot be reached"
    if time.time() - _DB_WARNED["at"] > 60:
        _DB_WARNED["at"] = time.time()
        app.logger.error("Report database unavailable: %s (%s: %s). See docs/OPERATIONS.md.", why, exc.__class__.__name__, str(exc)[:200])
    msg = f"The report database cannot be read: {why}. An administrator can check it with tools/envcheck.sh."
    if request.path.startswith("/api/"):
        return jsonify(error=msg, database=False), 503
    return render_template("denied.html", message=msg), 503


def is_demo():
    """Masked data: public demo mode, the Demo button, or an account whose role lacks the 'unmasked' permission
    (enforced on the server: a viewer cannot unmask data by changing the address)."""
    if PUBLIC_DEMO or request.args.get("demo") == "1":
        return True
    u = getattr(g, "user", None)
    return bool(u) and "unmasked" not in u.get("perms", ())


host_refs.strict = is_demo    # demo mode: host filters accept only opaque references, never a raw address
asn_registry.strict = is_demo  # and network filters only the aliases, never a real company name or AS number


def utcnow():
    return datetime.now(timezone.utc)


def replay_now():
    """The moment being replayed, from the replay schedule (see schedule.py)."""
    return schedule.position()[0]


def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value, default):
    """A time from a request (at=, from=, to=), kept within the replay day and the day before it. Any other day
    would make the server load it from MongoDB and drop the replay day from memory (security report #4)."""
    if not value:
        return default
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        # always UTC: a time with its own offset (+05:37) would start "its" day at a different moment, and every
        # offset would load another copy of the day into memory (external review, 2026-11-11)
        dt = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return default
    day = day_start(replay_now())
    lo, hi = day - timedelta(days=1), day + timedelta(days=1) - timedelta(microseconds=1)
    return min(max(dt, lo), hi)


def day_start(dt):
    if dt.tzinfo and dt.utcoffset():                   # a day always starts at 00:00 UTC (one copy per day in memory)
        dt = dt.astimezone(timezone.utc)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def parse_filters(args):
    """{field: set(values)} for the filters present in the query string. Placeholder labels map to ''."""
    out = {}
    for field in FILTER_FIELDS:
        values = {("" if v == EMPTY_LABEL.get(field) else v) for v in args.getlist(field) if v}
        if field in ("src_ip", "dst_ip", "http_host", "http_agent", "request"):
            values = {host_refs.resolve(v) for v in values}   # accept opaque references (demo mode)
        elif field in ("src_asn", "dst_asn"):
            values = set().union(*(asn_registry.resolve(v) for v in values)) if values else set()
        if values:
            out[field] = values
    return out


def field_value(ev, f):
    """A record's value for one filter: the decoded beacon's label, the device for the 'carries every ticked infection'
    filter (narrow_filters), else the stored field."""
    if f == "beacon":
        return beacon_stats.label(ev)
    if f == CARRIERS:
        return ev.get("src_ip")
    return ev.get(f)


def matches(ev, flt):
    return all(field_value(ev, f) in vals for f, vals in flt.items())


# two or more infections ticked: only the devices carrying every one of them (the user, 2026-11-20: "make it narrow to
# devices carrying both"). Their records of the ticked infections are what the map, the stream, the figures and the
# lists show. Worked out once per loaded day and choice (facets.carriers), as a hidden filter on the device.
CARRIERS = "_carries_all"


def narrow_filters(flt, day, args=None):
    """Only when the page asks for it (inf_all=1, sent by the map since 2026-11-20): a selection saved before (an
    analyst code, a finding's records) keeps the devices it was made with (either infection)."""
    vals = (flt or {}).get("infection")
    if not vals or len(vals) < 2 or args is None or args.get("inf_all") != "1":
        return flt
    devs = RCACHE.get(("carriers", day_key(day), tuple(sorted(map(str, vals)))),
                      lambda: _facets.carriers(day.events, lambda e: e.get("infection") or "", lambda e: e.get("src_ip"), vals))
    return dict(flt, **{CARRIERS: devs})


# ---------------------------------------------------------------- day store
import itertools as _itertools  # noqa: E402
import facets as _facets  # noqa: E402  (drop-down counts that follow the other filters)
import address_blocks as _address_blocks  # noqa: E402  (records per /24, for Settings → Constituency)
import beacon_stats  # noqa: E402  (the Beacon filter, the Decoded beacons figure and its Details list)
_DAY_SERIAL = _itertools.count(1)
# a loaded day is checked against MongoDB every DAY_RELOAD_SECONDS and kept, with every cached answer, when its rows
# are the same; reloaded in full at least every DAY_MAX_AGE_SECONDS anyway (speed review, 2026-11-15: the 10-minute
# full reload of every day took 13-16 s each time and threw away every cached filter)
DAY_MAX_AGE_SECONDS = int(os.environ.get("DAY_MAX_AGE_SECONDS", "3600"))
from respcache import settled  # noqa: E402  (the settle rule for new rows, shared with the services store)
import load_stamps  # noqa: E402  (the pipeline's marks: count rows only when one moved)
_STAMPS = load_stamps.Stamps(db)


class Day:
    def __init__(self, start, events):
        self.start = start
        self.events = events                       # sorted by extracted_date
        self.keys = [e["_t"] for e in events]       # epoch seconds, for bisect
        self.loaded_at = time.time()
        self.checked_at = self.loaded_at           # last time MongoDB was found to hold the same rows (see DayStore.get)
        self.serial = next(_DAY_SERIAL)            # identity of this copy: the response caches key on it (respcache.day_key)
        self.force = False                         # reload at the next get(), whatever the counts say
        self.per_source = {}
        self.arrived = {}          # report -> time its newest row was inserted in MongoDB (from the ObjectId)
        self.sig = None            # rows per report in MongoDB when loaded (see DayStore.signature)
        self.version = "0"
        self.raw_total, self.asn_raw = 0, Counter()


class DayStore:
    def __init__(self):
        self.days = {}
        self.lock = threading.Lock()
        self.loading = {}
        self.changes = {}          # day start -> reports that arrived or grew while the service was running
        self.gen = 0               # moved on by reset(): a load begun before it is thrown away, not stored

    def _fetch_collection(self, src, start, end):
        c = db[src["name"]]
        prefixes = [start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")]
        last = None
        out = []
        # Streamed from the cursor, not first gathered into a list of whole documents (2026-11-17: the largest report
        # of a day took 155 MB to hold raw, 86 MB streamed), and without the fields normalise() throws away
        # (sources.INTERNAL apart from _id), the same rows and extras as before.
        skip = {k: 0 for k in INTERNAL if k != "_id"}
        seen = [False]

        def rows():
            if src["filename_index"]:
                for d in c.find({"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in prefixes]}, skip):
                    seen[0] = True
                    yield d
            if not seen[0] and os.environ.get("FALLBACK_SCAN") == "1":
                yield from c.find({"extracted_date": {"$gte": start, "$lt": end}}, skip)

        for d in rows():
            ed = d.get("extracted_date")
            if isinstance(ed, str):
                try:
                    ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
                except ValueError:
                    ed = None
            if not isinstance(ed, datetime):
                continue
            if ed.tzinfo is None:
                ed = ed.replace(tzinfo=timezone.utc)
            if start <= ed < end:
                n = normalise(d, src)
                n["id"] = f"{src['name']}:{d['_id']}"
                n["_t"] = ed.timestamp()
                n["extracted_date"] = iso(ed)
                out.append(n)
                oid = d.get("_id")
                if isinstance(oid, ObjectId):
                    out_at = oid.generation_time
                    last = out_at if last is None or out_at > last else last
        return out, last

    def signature(self, start):
        """Rows per report for a day, counted straight in MongoDB (indexed filename prefix, so it is cheap).
        Compared every few seconds with the loaded copy, so a newly imported report is picked up at once."""
        end = start + timedelta(days=1)
        prefixes = [start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")]
        sig = {}
        for s in registry.get():
            c = db[s["name"]]
            if s["filename_index"]:
                n = c.count_documents({"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in prefixes]})
            elif os.environ.get("FALLBACK_SCAN") == "1":
                n = c.count_documents({"extracted_date": {"$gte": start, "$lt": end}})
            else:
                n = 0
            if n:
                sig[s["name"]] = n
        return sig

    def _load(self, start, old=None):
        """Load a day. With `old` (the copy in memory, same constituency), the reports whose row count has not changed
        are taken over from it as they are, and only the others are read and prepared again (speed review, 2026-11-15:
        a pipeline batch touches one or two reports, but every report was read, prepared and geocoded again)."""
        t0 = time.time()
        end = start + timedelta(days=1)
        srcs = registry.get()
        stamp = _STAMPS.of([start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")])   # the pipeline's marks, before anything
        try:
            sig = self.signature(start)   # taken before the rows, so anything inserted meanwhile triggers a reload
        except Exception:
            sig = None
        keep = {}
        if old is not None and sig and old.sig and getattr(old, "gen", None) == self.gen and getattr(old, "by_src", None) is not None \
                and getattr(old, "settings_version", None) == settings.version:
            keep = {n: b for n, b in old.by_src.items() if sig.get(n) and old.sig.get(n) == sig.get(n)}
        fetch = [s for s in srcs if s["name"] not in keep]
        with ThreadPoolExecutor(max_workers=6) as pool:
            parts = list(pool.map(lambda s: (s, *self._fetch_collection(s, start, end)), fetch))
        by_src, fresh = {}, []
        for s, rows, last in parts:
            asn = Counter()
            for e in rows:                      # every network seen (for the Settings page), before the constituency
                for side in ("src", "dst"):
                    if e[f"{side}_asn"]:
                        asn[str(e[f"{side}_asn"])] += 1
            raw = len(rows)
            # the address blocks, both sides like the networks above, for Settings → Network names & types
            # (address_blocks.py), before the constituency
            blocks = _address_blocks.tally(rows, (("src_ip", "src_asn"), ("dst_ip", "dst_asn")))
            # constituency (Settings): keep events whose source or destination host is in it
            if settings.restricted:
                rows = [e for e in rows if settings.in_scope(e["src_asn"], e["src_ip"]) or settings.in_scope(e["dst_asn"], e["dst_ip"])]
            by_src[s["name"]] = {"raw": raw, "asn": asn, "blocks": blocks, "rows": rows, "last": last}
            fresh += rows
        names = {s["name"] for s in srcs}
        for n, b in keep.items():               # taken over: already prepared, geocoded and referenced
            if n in names:
                by_src[n] = b
        # geocode every distinct place of the new rows once, in parallel
        places = {(e[f"{s}_geo"], e[f"{s}_region"], e[f"{s}_city"]) for e in fresh for s in ("src", "dst")}
        with ThreadPoolExecutor(max_workers=8) as pool:
            resolved = dict(zip(places, pool.map(lambda p: geocoder.lookup(*p), places)))
        geocoder.flush()
        for e in fresh:
            for f, v in e.items():
                if isinstance(v, datetime):
                    e[f] = iso(v)
            e["src_coords"] = resolved.get((e["src_geo"], e["src_region"], e["src_city"]))
            e["dst_coords"] = resolved.get((e["dst_geo"], e["dst_region"], e["dst_city"]))
            e["src_ref"] = host_refs.ref(e["src_ip"])
            e["request"] = _request_path(e["http_url"]) if e.get("http_url") else ""   # filterable request path
        events, per, arrived = [], {}, {}
        raw_total, asn_raw, block_raw = 0, Counter(), Counter()
        for s in srcs:
            b = by_src.get(s["name"])
            if not b:
                continue
            raw_total += b["raw"]; asn_raw.update(b["asn"]); block_raw.update(b.get("blocks") or {})
            events += b["rows"]
            if b["rows"]:
                per[s["name"]] = len(b["rows"])
                if b["last"]:
                    arrived[s["name"]] = iso(b["last"])
        events.sort(key=lambda e: e["_t"])
        app.logger.warning("Loaded %s: %d events from %d collections %s, %d places in %.1fs%s",
                           start.date(), len(events), len(per), per, len(places), time.time() - t0,
                           f" ({len(keep)} unchanged reports kept, {len(fetch)} read)" if keep else "")
        day = Day(start, events)
        day.per_source = per
        day.arrived = arrived
        day.sig = sig
        day.by_src, day.gen, day.settings_version = by_src, self.gen, settings.version
        if sig is not None:
            load_stamps.counted(day, stamp, t0)
        day.raw_total, day.asn_raw, day.block_raw = raw_total, asn_raw, block_raw
        day.version = hashlib.md5(json.dumps([sorted(per.items()), settings.version]).encode(), usedforsecurity=False).hexdigest()[:10]
        return day

    def reset(self):
        """Forget every loaded day (Settings changed the constituency): the next request reloads them. A load already
        running is not stored when it ends: it loads again, with the new constituency (external review, 2026-11-12:
        it finished after the reset and put the old constituency's day back)."""
        with self.lock:
            self.days.clear()
            self.changes.clear()
            self.gen += 1

    def _record_changes(self, start, old, new):
        """Remember which reports arrived (or grew) when a day is reloaded, so the browser can announce them."""
        if old is None:          # first load after a start: nothing is "new", the reports were already there
            return
        log = self.changes.setdefault(start, [])
        labels = {s["name"]: s["label"] for s in registry.get()}
        for name, rows in new.per_source.items():
            before = old.per_source.get(name, 0)
            if rows > before:
                log.append({"source": name, "label": labels.get(name, name), "rows": rows, "added": rows - before,
                            "new": before == 0, "arrived_at": new.arrived.get(name), "seen_at": iso(utcnow())})
                app.logger.warning("New report data for %s: %s +%d rows (now %d)", start.date(), name, rows - before, rows)
        del log[:-50]

    def check(self, dt):
        """Reload a day when MongoDB has more (or different) rows than the loaded copy, once the counts have settled:
        the same new counts on two checks in a row (15 s apart), or SETTLE_MAX_SECONDS after the first change while a
        pipeline run keeps adding rows (speed review, 2026-11-15: a run inserting in batches made the day reload back to
        back). Only the reports that changed are read again (_load with the copy in memory)."""
        start = day_start(dt)
        day = self.days.get(start)
        if day is None or start > utcnow():
            return False
        # the pipeline's marks first: counting every report's rows only when one moved (load_stamps.py)
        now = time.time()
        stamp = _STAMPS.of([start.strftime("%Y-%m-%d"), (start + timedelta(days=1)).strftime("%Y-%m-%d")])
        if load_stamps.skip_count(day, stamp, now):
            return False
        try:
            sig = self.signature(start)
        except Exception:
            app.logger.exception("Report check failed for %s", start.date())
            return False
        load_stamps.counted(day, stamp, now)
        if sig == day.sig:
            day.pending = None
            return False
        if not settled(day, sig, time.time()):
            return False
        self.invalidate(start)
        self.get(start)
        return True

    def peek(self, dt):
        """Number of records in MongoDB for that day (before the constituency), without loading anything (0 if not
        loaded). The replay schedule uses it: a narrow constituency with no events must not look like a missing report."""
        day = self.days.get(day_start(dt))
        return getattr(day, "raw_total", len(day.events)) if day else 0

    def invalidate(self, dt):
        with self.lock:
            day = self.days.get(day_start(dt))
            if day:
                day.force = True           # next get() reloads it

    def _still_same(self, start, day):
        """The day's time is up: if MongoDB holds the same rows per report (and the copy is not too old), keep it."""
        if day is None or day.force or not day.events or day.sig is None:
            return False
        if time.time() - day.loaded_at >= DAY_MAX_AGE_SECONDS:
            return False
        try:
            same = self.signature(start) == day.sig
        except Exception:
            return False
        if same:
            day.checked_at = time.time()
        return same

    def get(self, dt):
        start = day_start(dt)
        with self.lock:
            day = self.days.get(start)
            # an empty day (file not imported yet) is retried every minute
            ttl = DAY_RELOAD_SECONDS if day and day.events else 60
            fresh = day and not day.force and time.time() - day.checked_at < ttl
            if fresh:
                return day
        if self._still_same(start, day):
            return day
        with self.lock:
            day = self.days.get(start)
            ev = self.loading.get(start)
            leader = ev is None
            if leader:
                ev = self.loading[start] = threading.Event()
        if not leader:
            if day:                      # stale copy is fine while another thread reloads
                return day
            ev.wait(120)
            return self.days.get(start) or Day(start, [])
        try:
            # unchanged reports are taken over from the copy in memory, unless it is due its hourly full reload
            base = day if day is not None and time.time() - day.loaded_at < DAY_MAX_AGE_SECONDS else None
            for _ in range(3):
                gen = self.gen
                new = self._load(start, old=base)
                with self.lock:
                    if self.gen != gen:          # the constituency changed while loading: load again with it
                        base = None
                        day = None
                        continue
                    self._record_changes(start, day, new)
                    self.days[start] = new
                    for k in [k for k in self.days if k < start - timedelta(days=2)]:
                        del self.days[k]
                return new
            return new
        except Exception:
            app.logger.exception("Day load failed for %s", start.date())
            return day or Day(start, [])
        finally:
            with self.lock:
                self.loading.pop(start, None)
            ev.set()


store = DayStore()

# Which day is replayed and where: each day plays in full from 00:00 once its report is in MongoDB.
schedule = ReplaySchedule(os.path.join(BASE_DIR, "data", "schedule.json"), OFFSET_HOURS, SETTLE_SECONDS,
                          has_data=store.peek, logger=app.logger)


def _reload_day(day):
    store.invalidate(day)
    store.get(day)


schedule.on_start = _reload_day


def schedule_loop():
    """Background: keep the relevant days loaded, reload one as soon as MongoDB has new report rows for it
    (checked every 15 seconds; reports arrive at different times) and advance the schedule."""
    while True:
        try:
            registry.check()             # a new report (collection) is picked up within one tick
            pos, _ = schedule.position()
            # the day before too: it stays in memory anyway while the replay runs, but a restart used to lose it until a page
            # asked for it, and what Looking Glass compares (its "asks", the across-reports figures) shrank to the
            # replay day's first reports (2026-11-15: after a restart Looking Glass "had nothing to ask")
            days = [d for d in {day_start(pos) - timedelta(days=1), day_start(pos), day_start(pos) + timedelta(days=1),
                                schedule.target()} if d <= utcnow()]
            for d in days:
                store.get(d)
                store.check(d)
            schedule.tick()
            try:
                svc["tick"](days)        # publicly accessible / vulnerable services: same days, same 15-second checks
            except Exception:
                app.logger.exception("Services tick failed")
        except Exception:
            app.logger.exception("Replay schedule tick failed")
        time.sleep(15)


def public(ev):
    """Event as sent to the browser: company names added, and masked when demo mode is on."""
    out = {k: v for k, v in ev.items() if k not in ("_t", "_bc")}      # _bc: beacon_stats' per-record label
    out["src_asn_name"] = asn_registry.label(ev["src_asn"], False)
    out["dst_asn_name"] = asn_registry.label(ev["dst_asn"], False)
    if is_demo():
        out["request"] = mask_text(out.get("request"))
        return mask_event(out, asn_registry)
    return out


def window(t_from, t_to):
    """All events in [t_from, t_to), possibly spanning two days."""
    out = []
    d = day_start(t_from)
    while d < t_to:
        day = store.get(d)
        lo = bisect.bisect_left(day.keys, t_from.timestamp())
        hi = bisect.bisect_left(day.keys, t_to.timestamp())
        out.extend(day.events[lo:hi])
        d += timedelta(days=1)
    return out


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    return render_template("index.html", mapbox_token=MAPBOX_TOKEN, offset_hours=OFFSET_HOURS, malpedia_enabled=malpedia.enabled and AUTH["has_perm"]("malpedia"),
                           enrich_enabled=AUTH["has_perm"]("malpedia"))


@app.route("/api/clock")
def api_clock():
    srcs = registry.get()
    st = schedule.status()
    start = parse_iso(st["day_start"], day_start(replay_now()))
    day = store.days.get(start)          # never loads here: the background loop keeps it current
    labels = {s["name"]: s["label"] for s in srcs}
    reports = sorted(({"source": n, "label": labels.get(n, n), "rows": r, "arrived_at": (day.arrived or {}).get(n)}
                      for n, r in (day.per_source.items() if day else [])), key=lambda x: -x["rows"])
    return jsonify(server_now=iso(utcnow()), offset_hours=OFFSET_HOURS, sources=len(srcs), demo_forced=PUBLIC_DEMO or "unmasked" not in (getattr(g, "user", None) or {}).get("perms", ()),
                   settle_seconds=SETTLE_SECONDS, data_version=day.version if day else "0",
                   day_total=len(day.events) if day else 0, reports=reports,
                   report_changes=store.changes.get(start, [])[-20:],
                   sources_version=registry.version, new_sources=registry.added[-10:],
                   unsupported=len(registry.unsupported), tz=settings.tz(start + timedelta(hours=12)), **st)


@app.route("/api/sources")
def api_sources():
    """The collections the map integrates, with the replay day's row counts and when each report arrived."""
    day = store.get(parse_iso(request.args.get("at"), replay_now()))
    return jsonify(day=day.start.date().isoformat(), sources=[
        {**s, "rows_today": day.per_source.get(s["name"], 0), "arrived_at": day.arrived.get(s["name"])}
        for s in registry.get()
    ])


@app.route("/api/events")
def api_events():
    """Events with extracted_date in [from, to) (replay-clock times), filtered and capped."""
    rn = replay_now()
    t_to = parse_iso(request.args.get("to"), rn)
    t_from = parse_iso(request.args.get("from"), t_to - timedelta(seconds=10))
    if t_to - t_from > timedelta(minutes=30):
        t_from = t_to - timedelta(minutes=30)
    try:
        limit = max(1, min(int(request.args.get("limit", MAX_PER_POLL)), 2000))
    except ValueError:
        limit = MAX_PER_POLL
    flt = narrow_filters(parse_filters(request.args), store.get(t_to), request.args)
    if request.args.get("latest") == "1":
        # most recent `limit` matching events of the replay day up to `to` (used to backfill a filtered view)
        day = store.get(t_to)
        hi = bisect.bisect_left(day.keys, t_to.timestamp())
        matched = [e for e in day.events[:hi] if matches(e, flt)]
        events = matched[-limit:]
        return jsonify(events=[public(e) for e in events], total=len(matched), returned=len(events), sampled=False,
                       **{"from": events[0]["extracted_date"] if events else iso(t_to), "to": iso(t_to)})
    events = [e for e in window(t_from, t_to) if matches(e, flt)]
    total = len(events)
    if total > limit:
        events = sorted(random.sample(events, limit), key=lambda e: e["_t"])
    return jsonify(events=[public(e) for e in events], total=total, returned=len(events),
                   sampled=total > limit, **{"from": iso(t_from), "to": iso(t_to)})


@app.route("/api/facets")
def api_facets():
    """Filter values (with counts) for the whole replay day; with filters in the query, each field's counts follow
    every OTHER filter (facets.py, the user 2026-11-19)."""
    day = store.get(parse_iso(request.args.get("at"), replay_now()))
    demo = is_demo()
    beacons = not demo and beacon_stats.ready(day)      # labelled in the background once per loaded day
    flt = narrow_filters(parse_filters(request.args), day, request.args)
    key = ("facets", day_key(day), demo, asn_registry.mtime, registry.version, beacons, filters_key(flt))
    return jsonify(RCACHE.get(key, lambda: _facets_core(day, demo, beacons, flt)))


def _facets_core(day, demo, beacons=False, flt=None):
    result = {}
    pool = _facets.pools(day.events, flt or {}, field_value)
    for field in FACET_FIELDS:
        c = Counter(e[field] for e in pool.of(field))
        rows = [{"value": v or EMPTY_LABEL.get(field, ""), "count": n} for v, n in c.most_common(300)]
        result[field] = [r for r in rows if r["value"]]
    if (flt or {}).get("infection"):          # infections ticked: what else their devices carry (facets.overlap)
        result["infection"] = _facets.overlap(pool, lambda e: e.get("infection") or EMPTY_LABEL.get("infection", ""),
                                              lambda e: e.get("src_ip"))
        result["infection_unit"] = "devices"
    # severity of each infection (most common one), so the UI can color infections consistently
    sev = {}
    for e in day.events:
        sev.setdefault(e["infection"] or "unknown", Counter())[e["severity"]] += 1
    result["infection_severity"] = {k: c.most_common(1)[0][0] for k, c in sev.items()}
    # source and destination networks, grouped by company (all ASNs of an operator together), like Intel shows them;
    # aliases in demo mode. The value is what the src_asn / dst_asn filters take (asn_registry.resolve).
    for side in ("src", "dst"):
        c = Counter(asn_registry.company(e[f"{side}_asn"], demo) for e in pool.of(f"{side}_asn") if e[f"{side}_asn"])
        result[f"{side}_asn"] = [{"value": v, "count": n} for v, n in c.most_common(300) if v]
    if beacons:                           # analysts and admins: the beacons Looking Glass decoded (beacon_stats.py)
        result["beacon"] = beacon_stats.facet_rows(pool.of("beacon"))
    elif not demo:
        result["beacon_pending"] = True   # still being labelled: the page asks again shortly
    result["source_labels"] = {s["name"]: s["label"] for s in registry.get()}
    result["source_class"] = {s["name"]: s["class"] for s in registry.get()}
    result["day"] = day.start.date().isoformat()
    result["day_total"] = len(day.events)
    result["filtered"] = bool(flt)
    result["matching"] = pool.total     # records matching every filter (the whole day without filters)
    return result


@app.route("/api/stats")
def api_stats():
    """Totals and top-N counts for the WHOLE replay day: every record of every report, never just the part
    already replayed. The replay only drives the map and the stream; these figures stay fixed for the day
    (they change only when late rows arrive in MongoDB, picked up on the periodic day reload)."""
    rn = parse_iso(request.args.get("at"), replay_now())
    day = store.get(rn)
    flt = narrow_filters(parse_filters(request.args), day, request.args)
    demo = is_demo()
    key = ("stats", day_key(day), demo, settings.version, asn_registry.mtime, filters_key(flt))
    out = dict(RCACHE.get(key, lambda: _stats_core(day, flt, demo)))      # shared by every viewer of the same selection
    # what depends on the replay moment is worked out per request
    out["as_of"] = iso(rn)
    out["current_quarter"] = max(0, min(95, int((rn.timestamp() - day.start.timestamp()) // 900)))
    out["current_hour"] = min(23, int((rn.timestamp() - day.start.timestamp()) // 3600))
    return jsonify(out)


def _stats_core(day, flt, demo):
    sofar = [e for e in day.events if matches(e, flt)] if flt else day.events
    out = {
        "total": len(sofar),
        # reports without a source (or destination) side must not count an empty value as a host
        "unique_src_ip": len({e["src_ip"] for e in sofar if e["src_ip"]}),
        "unique_dst_ip": len({e["dst_ip"] for e in sofar if e["dst_ip"]}),
        # (every event gets a name from sources.py, but an empty one must never count as a type: review, 2026-11-12)
        "unique_infection": len({e["infection"] for e in sofar if e["infection"]}),
        "critical": sum(1 for e in sofar if e["severity"] == "critical"),
        "day_total": len(day.events),
        "unique_sources": len({e["source"] for e in sofar}),
    }
    # hosts that show up in more than one report today (cross-report correlation)
    seen = {}
    for e in sofar:
        if e["src_ip"]:
            seen.setdefault(e["src_ip"], set()).add(e["source"])
    out["multi_source_hosts"] = sum(1 for s in seen.values() if len(s) > 1)
    for field, n in (("source", 12), ("attack_class", 8), ("infection", 8), ("tag", 8), ("src_city", 8), ("src_geo", 8),
                     ("dst_geo", 8), ("http_host", 8), ("dst_port", 6), ("severity", 5)):
        c = Counter(e[field] for e in sofar)
        out[field] = [{"value": v or EMPTY_LABEL.get(field, "unknown"), "count": k} for v, k in c.most_common(n)]
    if demo:
        # concealed label, but an opaque reference as value so the entry can still be analysed
        for r in out["http_host"]:
            r["label"] = mask_text(r["value"])
            r["value"] = host_refs.ref(r["value"])
    # networks: grouped by company (both ASNs of one operator count together), named or aliased
    for side in ("src", "dst"):
        by_company = Counter()
        for e in sofar:
            if e[f"{side}_asn"]:
                key = asn_registry.alias(e[f"{side}_asn"]) if demo else (asn_registry.name(e[f"{side}_asn"]) or f"AS{e[f'{side}_asn']}")
                by_company[key] += 1
        rows = []
        for name, k in by_company.most_common(8):
            asns = [] if demo else sorted(asn_registry.resolve(name))
            rows.append({"value": name, "label": name, "count": k, "asns": asns})
        out[f"{side}_network"] = rows
    # 15-minute activity buckets for the whole replay day; current_quarter marks where the replay is
    buckets = [0] * 96
    for e in sofar:
        buckets[min(95, int((e["_t"] - day.start.timestamp()) // 900))] += 1
    out["timeline"] = buckets
    out["loaded_at"] = iso(datetime.fromtimestamp(day.loaded_at, timezone.utc))
    out["day"] = day.start.date().isoformat()
    # events per hour split by attack type (stacked chart)
    classes = [r["value"] for r in out["attack_class"]]
    hours = {c: [0] * 24 for c in classes}
    for e in sofar:
        h = int((e["_t"] - day.start.timestamp()) // 3600) % 24
        if e["attack_class"] in hours:
            hours[e["attack_class"]][h] += 1
    out["hours_by_class"] = hours
    return out


@app.route("/api/geo")
def api_geo():
    """Every location and connection of the whole replay day (matching the filters), for the map's
    always-visible layer: source places, destination places and source -> destination flows with counts.
    Places are cities (as geocoded), so demo mode needs no masking here."""
    rn = parse_iso(request.args.get("at"), replay_now())
    day = store.get(rn)
    flt = narrow_filters(parse_filters(request.args), day, request.args)
    return jsonify(RCACHE.get(("geo", day_key(day), filters_key(flt)), lambda: _geo_core(day, flt)))


def _geo_core(day, flt):
    ev = [e for e in day.events if matches(e, flt)] if flt else day.events
    flows, srcs, dsts = {}, {}, {}

    def place(e, side):
        return {"city": (e[f"{side}_city"] or "").title(), "region": (e[f"{side}_region"] or "").title(), "cc": e[f"{side}_geo"] or "",
                "key": e[f"{side}_city"] or ""}

    for e in ev:
        sc, dc = e.get("src_coords"), e.get("dst_coords")
        if sc:
            k = tuple(sc)
            s = srcs.get(k)
            if s is None:
                s = srcs[k] = {"pos": sc, **place(e, "src"), "count": 0, "classes": Counter(), "hosts": set()}
            s["count"] += 1; s["classes"][e["attack_class"]] += 1
            if e["src_ip"]: s["hosts"].add(e["src_ip"])
        if dc:
            k = tuple(dc)
            d = dsts.get(k)
            if d is None:
                d = dsts[k] = {"pos": dc, **place(e, "dst"), "count": 0, "classes": Counter()}
            d["count"] += 1; d["classes"][e["attack_class"]] += 1
        if sc and dc and sc != dc:
            k = (tuple(sc), tuple(dc))
            f = flows.get(k)
            if f is None:
                f = flows[k] = {"src": sc, "dst": dc, "src_name": place(e, "src"), "dst_name": place(e, "dst"),
                                "count": 0, "classes": Counter()}
            f["count"] += 1; f["classes"][e["attack_class"]] += 1

    def out(x):
        x = dict(x)
        x["class"] = x.pop("classes").most_common(1)[0][0]
        if "hosts" in x:
            x["hosts"] = len(x["hosts"])
        return x

    no_dst = sum(1 for e in ev if e.get("src_coords") and not e.get("dst_coords"))
    return dict(day=day.start.date().isoformat(), total=len(ev), no_location=sum(1 for e in ev if not e.get("src_coords") and not e.get("dst_coords")),
                no_destination=no_dst, sources=sorted((out(s) for s in srcs.values()), key=lambda r: -r["count"]),
                destinations=sorted((out(d) for d in dsts.values()), key=lambda r: -r["count"]),
                flows=sorted((out(f) for f in flows.values()), key=lambda r: -r["count"]))


from replay_counts import ReplayCounts  # noqa: E402  (a selection's replayed counter, polled every 2 s per map tab)
REPLAY_COUNTS = ReplayCounts()


@app.route("/api/replayed")
def api_replayed():
    """Exact number of the day's records (matching the filters) whose event time is at or before the replay
    position, i.e. how many have been replayed in the event stream so far. Cheap: called every few seconds."""
    rn = parse_iso(request.args.get("at"), replay_now())
    day = store.get(rn)
    flt = narrow_filters(parse_filters(request.args), day, request.args)
    if flt:
        # the selection's records found once per loaded day and kept (replay_counts.py); each poll is a binary search.
        # hosts: distinct source hosts (the empty stream says "its IP address" or "their N IP addresses")
        m = REPLAY_COUNTS.of(day, filters_key(flt), lambda e: matches(e, flt), lambda e: e["src_ip"])
        replayed, nxt = REPLAY_COUNTS.at(m, rn.timestamp())
        total, hosts = len(m["keys"]), m["hosts"]
    else:
        hi = bisect.bisect_right(day.keys, rn.timestamp())
        replayed, total, hosts = hi, len(day.events), None
        nxt = day.events[hi] if hi < len(day.events) else None
    # the next matching event after the replay position, so an empty stream can say when something will appear
    next_at = nxt["extracted_date"] if nxt else None
    return jsonify(replayed=replayed, total=total, at=iso(rn), day=day.start.date().isoformat(), next_at=next_at, hosts=hosts)


def _report_def(name):
    """Shadowserver's report name, rating and our plain-language definition (data/service_reports.json)."""
    info = report_info(name) or {}
    return {"title": info.get("title", ""), "rating": info.get("severity", ""), "def": info.get("def", ""),
            "why": info.get("why", ""), "url": info.get("url", "")}


@app.route("/api/report_glossary")
def api_report_glossary():
    """Definitions of every detected report, both platforms, for the Glossary tab."""
    day = store.get(replay_now())
    comms = [{"label": s["label"], "rows": day.per_source.get(s["name"], 0), "name": s["name"], **_report_def(s["name"])}
             for s in registry.get()]
    return jsonify(communications=comms)


def _unsupported_public(s):
    d = s["diagnostic"]
    return {"name": s["name"], "label": s["label"], "class": s["class"], "layout": d["layout"],
            "missing": d["missing"], "missing_fields": d["missing_fields"], "warnings": d["warnings"],
            "required_ok": d["required_ok"], "required_total": d["required_total"]}


@app.route("/api/diagnostics")
def api_diagnostics():
    """Compatibility diagnostic of every discovered report: which fields it has of those the platform uses."""
    registry.get()
    pick = lambda s: {"name": s["name"], "label": s["label"], "filename_index": s["filename_index"], **s["diagnostic"]}
    return jsonify(supported=[pick(s) for s in registry.items], unsupported=[pick(s) for s in registry.unsupported],
                   new=registry.added[-10:])


@app.route("/api/overview")
def api_overview():
    """Whole-day summary of the replay day for the intro page (no network names or IPs)."""
    day = store.get(replay_now())
    srcs = registry.get()
    # the counting over every event is shared (cached per loaded day); names, definitions and the schedule are fresh
    return jsonify(**RCACHE.get(("overview", day_key(day)), lambda: _overview_counts(day)),
        day=day.start.date().isoformat(), total=len(day.events),
        reports_total=len(srcs), reports_active=len(day.per_source),
        reports=[{"name": s["name"], "label": s["label"], "class": s["class"], "rows": day.per_source.get(s["name"], 0),
                  "warnings": s["diagnostic"]["warnings"], **_report_def(s["name"])}
                 for s in sorted(srcs, key=lambda s: (-day.per_source.get(s["name"], 0), s["label"]))],
        # discovered (they have source/destination fields) but missing fields the platform needs: future work
        unsupported=[_unsupported_public(s) for s in registry.unsupported],
        # next phase (publicly accessible / vulnerable services): scan / population reports already in MongoDB
        services_reports=len([n for n in registry.names if re.match(r"(scan6?|population6?)_", n)]),
        schedule=schedule.status(), tz=settings.tz(day.start + timedelta(hours=12)),
        # Shadowserver's one-off Special Reports: listed apart, never replayed nor counted (special_reports.py)
        special=special_reports.listing(db, scope=settings.in_scope if settings.restricted else None, version=settings.version),
    )


def _overview_counts(day):
    ev = day.events
    t0 = day.start.timestamp()
    timeline = [0] * 96
    for e in ev:
        timeline[min(95, int((e["_t"] - t0) // 900))] += 1
    hosts = {}
    for e in ev:
        if e["src_ip"]:
            hosts.setdefault(e["src_ip"], set()).add(e["source"])
    classes = Counter(e["attack_class"] for e in ev)
    infections = Counter(e["infection"] or "unknown" for e in ev)
    cities = Counter(e["src_city"] for e in ev if e["src_city"])
    peak = max(range(96), key=lambda i: timeline[i]) if ev else None
    return dict(
        classes=[{"value": k, "count": v} for k, v in classes.most_common()],
        source_hosts=len(hosts), cross_report_hosts=sum(1 for s in hosts.values() if len(s) > 1),
        infections=len(infections), top_infections=[{"value": k, "count": v} for k, v in infections.most_common(3)],
        cities=len(cities), top_city=(cities.most_common(1)[0][0].title() if cities else None),
        countries_targeted=len({e["dst_geo"] for e in ev if e["dst_geo"]}),
        critical=sum(1 for e in ev if e["severity"] == "critical"),
        timeline=timeline, peak_quarter=peak,
    )


@app.route("/api/related")
def api_related():
    """What one source host did on the whole replay day."""
    rn = parse_iso(request.args.get("at"), replay_now())
    ip = host_refs.resolve(request.args.get("ref") or request.args.get("src_ip", ""))
    demo = is_demo()
    day = store.get(rn)
    mine = [e for e in day.events if e["src_ip"] == ip] if ip else []
    m = mask_text if demo else (lambda s: s)
    return jsonify(
        src_ip=mask_ip(ip) if demo else ip, count=len(mine),
        first=mine[0]["extracted_date"] if mine else None,
        last=mine[-1]["extracted_date"] if mine else None,
        infections=[v for v, _ in Counter(e["infection"] or "unknown" for e in mine).most_common(10)],
        hosts=[m(v) for v, _ in Counter(e["http_host"] for e in mine if e["http_host"]).most_common(10)],
        dst_ips=[(mask_ip(v) if demo else v) for v, _ in Counter(e["dst_ip"] for e in mine if e["dst_ip"]).most_common(10)],
        sources=[{"source": v, "label": next((e["source_label"] for e in mine if e["source"] == v), v), "count": k}
                 for v, k in Counter(e["source"] for e in mine).most_common()],
    )


# ---------------------------------------------------------------- analytics
INSIGHT_KINDS = {
    "source": "Source report", "attack_class": "Attack type",
    "src_city": "Affected city", "infection": "Infection / category", "http_host": "C2 / sinkhole domain",
    "dst_geo": "Target country", "src_ip": "Source host", "src_asn": "Source network", "dst_asn": "Destination network",
    "dst_ip": "Destination IP",
    # from the map: a connection "SRC_CITY|CC>DST_CITY|CC" and a destination place "DST_CITY|CC"
    "route": "Connection", "dst_place": "Destination place",
    "dst_port": "Target port", "http_agent": "User agent", "request": "Request path", "severity": "Severity",
    "src_geo": "Source country", "dst_city": "Destination city",
    "tag": "Tag", "protocol": "Protocol",
    # a time window of the day, optionally within another selection: "START_MIN+MINUTES[|kind|value]"
    "time": "Time window",
    # any combination of the map filters, as a query string: "attack_class=Scanning&src_city=ACCRA"
    "filters": "Filtered selection",
}
# Analytics: the figures, breakdowns and drill-downs of the Analyse panels on both platforms (analytics_api.py, moved out of app.py unchanged, 2026-11-24)
import analytics_api as _mod_analytics_api  # noqa: E402
_mod_analytics_api.install(app, sys.modules[__name__])
from analytics_api import _parse_time_value  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _hm  # noqa: E402,F401  (analytics_api.py)
# values that are concealed in demo mode: the browser gets an opaque reference instead, resolved here
REF_KINDS = ("dst_ip", "http_host", "http_agent", "request")
from analytics_api import _place_parts  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _median  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _top  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _request_path  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _fmt_dur  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _select_slice  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _slice_on  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _rhythm  # noqa: E402,F401  (analytics_api.py)
from analytics_api import _hhmmss  # noqa: E402,F401  (analytics_api.py)


DRILL_METRICS = ("events", "share", "hosts", "c2", "dst_ips", "interval", "multi", "reports", "cross", "beacons")
DRILL_LIMIT = 300
from analytics_api import api_insight_drill  # noqa: E402,F401  (analytics_api.py)


# The PDF and ZIP reports of an analysis figure, on both platforms (report_downloads.py, moved out of app.py unchanged, 2026-11-24)
import report_downloads as _mod_report_downloads  # noqa: E402
_mod_report_downloads.install(app, sys.modules[__name__])
from report_downloads import SOURCES_TEXT, _bd_rows, _enrich_names, _file_base, _pdf_label, _pdf_rows, _report_response, _scope_text, _short, _value_label, _view_json, api_insight, api_insight_report_pdf, api_svc_report_pdf  # noqa: E402,F401
# ---------------------------------------------------------------- infection knowledge base
KB_PATH = os.path.join(BASE_DIR, "data", "infections.json")
_kb = {"mtime": None, "data": {}}


# The definitions this site's researchers and admins write (Settings / Definitions page) are kept apart from the
# shipped knowledge base, so an upgrade (which replaces data/infections.json) never loses them.
LOCAL_DEFS_PATH = os.path.join(BASE_DIR, "data", "definitions.json")
# The infection knowledge base: researchers' definitions and the curated notes (infection_kb.py, moved out of app.py unchanged, 2026-11-24)
import infection_kb as _mod_infection_kb  # noqa: E402
_mod_infection_kb.install(app, sys.modules[__name__])
from infection_kb import knowledge_base  # noqa: E402,F401  (infection_kb.py)


ISSUES_PATH = os.path.join(BASE_DIR, "data", "issues.json")
_ikb = {"mtime": None, "data": {}}
from infection_kb import issues_kb  # noqa: E402,F401  (infection_kb.py)
from infection_kb import issue_resolve  # noqa: E402,F401  (infection_kb.py)
from infection_kb import issues_resolve  # noqa: E402,F401  (infection_kb.py)
from infection_kb import api_issues_batch  # noqa: E402,F401  (infection_kb.py)


_SVC_ISSUES = {"at": 0.0, "data": {}}
from infection_kb import _svc_issue_stats  # noqa: E402,F401  (infection_kb.py)
from infection_kb import _cve_loop  # noqa: E402,F401  (infection_kb.py)


# ------------------------------------------------------------------ look-up jobs (progress window on the page)
_JOBS, _JOBS_LOCK = {}, threading.Lock()
# Look-up jobs with a progress window on the page: names and issues explained, checked against the sources (lookup_jobs.py, moved out of app.py unchanged, 2026-11-24)
import lookup_jobs as _mod_lookup_jobs  # noqa: E402
_mod_lookup_jobs.install(app, sys.modules[__name__])
from lookup_jobs import _LookupStopped  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _job_new  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _job_log  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import api_lookups_start  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import api_lookups_stop  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import api_lookups_status  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import api_asns  # noqa: E402,F401  (lookup_jobs.py)


MALPEDIA_FIELDS = ("infection", "tag", "family", "hash", "md5", "sha1", "sha256")

# Why a Shadowserver name has no Malpedia family, in plain words, from the evidence: the reports the name appears in
# (honeypots record what a device DID; sinkholes record which malware or service it CONTACTED), their attack type, and
# the Looking Glass knowledge base (data/infections.json).
_ACTIVITY = {
    "Brute force": "trying to log in to other computers by guessing passwords",
    "Scanning": "scanning the internet, knocking on other computers to find open or weak services",
    "DDoS": "taking part in a denial-of-service attack, flooding a target with traffic",
    "Initial access": "running a malicious program that was offered to it (a first step attackers use to break in)",
    "Spam": "sending spam e-mail",
    "IP spoofing": "sending traffic with a forged sender address",
}
_EVIDENCE = {"at": 0.0, "data": {}}
# set for one request when the report database cannot be read: the evidence already in memory (maybe none) is used
# instead of reading stored days, so the Definitions to-do list still lists its names (external review, 2026-11-14:
# with MongoDB down the list came back empty)
_EV_OFFLINE = threading.local()
# one rebuild at a time: the others use the copy they have (2026-11-14: eight requests after the minute ran out each
# rebuilt it, four times the time of one)
_EV_BUILD = threading.Lock()
from seen_index import SeenIndex  # noqa: E402
SEEN = SeenIndex(os.path.join(BASE_DIR, "data", "seen_names.json"), logger=app.logger)
from lookup_jobs import _name_evidence  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _build_name_evidence  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _last_seen  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import malpedia_explain  # noqa: E402,F401  (lookup_jobs.py)


_MISSES_PATH = os.path.join(BASE_DIR, "data", "malpedia_names.json")
_MISSES_LOCK = threading.Lock()
from lookup_jobs import _read_names  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _write_names  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _is_services_report  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _record_check  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _unchecked_names  # noqa: E402,F401  (lookup_jobs.py)


_AUTOCHECK = {"running": False, "done": 0, "left": 0, "error": "", "at": ""}
from lookup_jobs import _autocheck  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _autocheck_loop  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import _curated  # noqa: E402,F401  (lookup_jobs.py)
from lookup_jobs import mp_resolve  # noqa: E402,F401  (lookup_jobs.py)


import name_sources  # noqa: E402  (one card per name, all sources side by side; refresh of the local copies)
NAME_SOURCES = name_sources.NameSources(OFFLINE_NAMES, malpedia, {
    "curated": lambda n: _curated(n), "kb": lambda: knowledge_base(), "mp_card": lambda r: _mp_card(r),
    "record": lambda n, f: _record_check(n, f), "explain": lambda n: malpedia_explain(n), "by": lambda e: _by(e)})
_NAME_SOURCES_API = name_sources.install(app, {
    "base_dir": BASE_DIR, "offline": OFFLINE_NAMES, "allowed": lambda: _kb_allowed(),
    "can_refresh": lambda: AUTH["has_perm"]("settings"), "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
    "audit": AUTH["audit"], "python": os.path.join(BASE_DIR, ".venv", "bin", "python")
    if os.path.exists(os.path.join(BASE_DIR, ".venv", "bin", "python")) else sys.executable})
from lookup_jobs import _ReportDefs  # noqa: E402,F401  (lookup_jobs.py)


import attack_map  # noqa: E402  (MITRE ATT&CK: report mappings, malware techniques, CVE links; step 2)
ATTACK = attack_map.AttackMap(os.path.join(BASE_DIR, "data"), OFFLINE_NAMES,
                              report_map=lambda: (REPORT_MAP.get() or {}).get("reports") or {},
                              report_defs=lambda: _ReportDefs, audit=AUTH["audit"])
ATTACK.labels = lambda: {x["label"]: x["name"] for x in registry.get()}     # "Seen in" labels -> report keys
NAME_SOURCES.attack = ATTACK
attack_map.install(app, {"map": ATTACK, "allowed": lambda: _kb_allowed(), "change_allowed": lambda: _kb_change_allowed(),
                         "fresh": AUTH["fresh"], "me": lambda: _me(),
                         # MITRE's full text of a technique: everyone who reads ATT&CK in Looking Glass
                         "readers": lambda: any(AUTH["has_perm"](p) for p in ("view", "definitions", "advisory", "management")),
                         # admins: the "trust CTID's CVE mappings in advisories" setting (off by default)
                         "can_admin": lambda: AUTH["has_perm"]("settings"), "csrf_ok": AUTH["csrf_ok"]})
from lookup_jobs import _mp_card  # noqa: E402,F401  (lookup_jobs.py)


# Every explanation card carries the researchers' notes on its name (notes.py): the map, services, Executive and the PDF
# reports all use these three look-ups, so the notes are added here once.
_mp_resolve_plain, _issue_resolve_plain, _issues_resolve_plain = mp_resolve, issue_resolve, issues_resolve
# The researchers' notes on every explanation card (map, services, Executive, PDF) (card_notes.py, moved out of app.py unchanged, 2026-11-24)
import card_notes as _mod_card_notes  # noqa: E402
_mod_card_notes.install(app, sys.modules[__name__])
from card_notes import _noted  # noqa: E402,F401  (card_notes.py)
from card_notes import mp_resolve  # noqa: E402,F401  (card_notes.py)
from card_notes import _with_attack  # noqa: E402,F401  (card_notes.py)
from card_notes import issue_resolve  # noqa: E402,F401  (card_notes.py)
from card_notes import issues_resolve  # noqa: E402,F401  (card_notes.py)
from card_notes import api_malpedia_batch  # noqa: E402,F401  (card_notes.py)
from card_notes import api_malpedia  # noqa: E402,F401  (card_notes.py)


# ---------------------------------------------------------------- Settings: definitions for names Malpedia does not know
_URL_RE = __import__("re").compile(r"^https?://[^\s<>\"']{4,500}$")
# Settings: definitions for names Malpedia does not know, and the names checked against the sources (name_definitions.py, moved out of app.py unchanged, 2026-11-24)
import name_definitions as _mod_name_definitions  # noqa: E402
_mod_name_definitions.install(app, sys.modules[__name__])
from name_definitions import api_kb_unresolved  # noqa: E402,F401  (name_definitions.py)
from name_definitions import _kb_unresolved  # noqa: E402,F401  (name_definitions.py)
from name_definitions import api_kb_malpedia_search  # noqa: E402,F401  (name_definitions.py)
from name_definitions import api_kb_check  # noqa: E402,F401  (name_definitions.py)
from name_definitions import api_kb_entry  # noqa: E402,F401  (name_definitions.py)
from name_definitions import api_infections  # noqa: E402,F401  (name_definitions.py)
from name_definitions import api_infections_missing  # noqa: E402,F401  (name_definitions.py)
from name_definitions import healthz  # noqa: E402,F401  (name_definitions.py)


# Load the replay day and run the replay schedule as soon as the process starts (gunicorn and `python app.py`).
# Publicly accessible / vulnerable services platform (/services): single-host reports, same replay schedule.
svc = services_api.register(app, {
    "db": db, "schedule": schedule, "asns": asn_registry, "refs": host_refs, "is_demo": is_demo,
    "replay_now": replay_now, "parse_iso": parse_iso, "iso": iso, "utcnow": utcnow, "offset_hours": OFFSET_HOURS,
    "exclude": _csv(os.environ.get("EXCLUDE_COLLECTIONS", "outdated_dnssec_key")),
    "registry_ttl": int(os.environ.get("REGISTRY_REFRESH_SECONDS", "3600")),
    "reload_seconds": DAY_RELOAD_SECONDS, "fallback": os.environ.get("FALLBACK_SCAN") == "1",
    "settings": settings,
    "country_name": lambda: _country_index().get(settings.data["country"], {}).get("country", settings.data["country"]),
    "country_names": lambda: _country_index().get(settings.data["country"], {}).get("names", []),
    # names the administrator said mean the country itself (region_matches.py), and the map's own region names: a
    # region named like the country (Belize District, Djibouti) is that region, not "region unknown"
    "country_chosen_names": lambda: [k for k, v in (globals().get("REGION_MATCHES").of(settings.data["country"])
                                                    if globals().get("REGION_MATCHES") else {}).items() if v == "__country__"],
    "map_region_names": lambda: __import__("region_matches").map_region_names(ADM1_DIR, settings.data["country"]),
    "region_version": lambda: globals()["REGION_MATCHES"].version() if globals().get("REGION_MATCHES") else 0,
})


# ---------------------------------------------------------------- settings (both platforms)
ADM1_DIR = os.path.join(BASE_DIR, "static", "data", "adm1")
# SETTINGS_TOKEN (an X-Settings-Token header) was removed on 2026-11-11: the sign-in check runs first, so it never let
# a script in on its own, and for a signed-in account without the Settings permission it was a way around that
# permission. Settings now have one rule: a signed-in account with the 'settings' permission (administrators).


def _settings_writable():
    """Settings need the 'settings' permission (auth.py), from a signed-in account."""
    return AUTH["has_perm"]("settings")


def _settings_change_allowed():
    """A change also needs the session's CSRF token (sent by the Settings page), on top of the Origin checks."""
    return AUTH["has_perm"]("settings") and AUTH["csrf_ok"]()


def _kb_allowed():
    """Malware-name definitions: admins (settings) and researchers (definitions)."""
    return _settings_writable() or AUTH["has_perm"]("definitions")


def _kb_change_allowed():
    return _settings_change_allowed() or (AUTH["has_perm"]("definitions") and AUTH["csrf_ok"]())


# Intel gathered: indicators per infection / issue and cross-report leads for researchers (intel.py)
import intel as _intel  # noqa: E402


def _defined_titles():
    out = {("infections", n): (e.get("title") or n) for n, e in knowledge_base().items() if defined_entry(e)}
    # a CVE with a public record (CVE.org / NVD / CISA KEV, already cached) is defined by that record; a researcher's own
    # definition still wins (the user, 2026-11-19: "No definition yet" on a CVE whose record the platform had)
    out.update({("issues", c.lower()): t for c, t in cve_intel.known_titles().items()})
    out.update({("issues", n.lower()): (e.get("title") or n) for n, e in issues_kb().items() if defined_entry(e)})
    return out                                     # names in lower case (intel.py compares them so)


# researchers' notes (new findings) on a name, shown on every card and in the PDF reports (notes.py)
import notes as _notes  # noqa: E402
NOTES = _notes.install(app, {"people": people, "audit": AUTH["audit"], "allowed": _kb_allowed, "change_allowed": _kb_change_allowed,
                             "fresh": AUTH["fresh"], "base_dir": BASE_DIR, "logger": app.logger})

INTEL = _intel.install(app, {"store": store, "svc_store": svc["store"], "replay_now": replay_now,   # the report day
                             "allowed": _kb_allowed, "defined": _defined_titles,
                             "services_view": lambda n: SVC_KB["view"](n),     # Services in Intel gathered (services_kb.py)
                             "cross": lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"],   # every category
                                                                        hold_small=True),     # researchers: no code below 5 hosts
                             # a cross-report pattern's devices: the CVEs, issues and infections they carry (names, counts)
                             "carried": lambda hosts: SVC_INTEL.carried(hosts),
                             "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()},
                                                **{x["name"]: x["label"] for x in svc["registry"].get()}},
                             # Spam URL: the link's host is a "Spam link host", masked when in the country (review 2026-11-13)
                             "inbound": lambda: {x["name"] for x in registry.get() if x.get("layout") == "inbound"},
                             "country": lambda: settings.data["country"]})
# Explore a match of "Looking Glass asks": only the records that carry the indicator, per name and report (intel_match.py)
import intel_match as _intel_match  # noqa: E402
INTEL_MATCH = _intel_match.install(app, INTEL, {"allowed": _kb_allowed, "labels": INTEL.ctx["labels"]})
# the decoded beacon in a record's HTTP request, for analysts and admins (beacon_decode.py; researchers get its public
# parts through Intel gathered, masked views never the blob)
import beacon_decode as _beacon_decode  # noqa: E402
_beacon_decode.install(app, {"csrf_ok": AUTH["csrf_ok"], "sees_hosts": lambda: not is_demo()})


# combination codes and the analyst's combination search (combos.py)
import combos as _combos  # noqa: E402
# Explore a match of Looking Glass asks: only the records that carry the indicator, per name and report (intel_match_api.py, moved out of app.py unchanged, 2026-11-24)
import intel_match_api as _mod_intel_match_api  # noqa: E402
_mod_intel_match_api.install(app, sys.modules[__name__])
from intel_match_api import _combo_fetch  # noqa: E402,F401  (intel_match_api.py)
from intel_match_api import _combo_explain  # noqa: E402,F401  (intel_match_api.py)
from intel_match_api import _adm1_shapes  # noqa: E402,F401  (intel_match_api.py)
from intel_match_api import _combo_pdf  # noqa: E402,F401  (intel_match_api.py)


import advisory as _advisory_mod  # noqa: E402
_IMPACT = _advisory_mod.Impact(BASE_DIR)    # the reports' impact flags (data/report_impact.json), for the analysts' PDF

COMBOS = _combos.install(app, {
    "intel": INTEL, "store": store, "svc_store": svc["store"],
    "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}},
    "fetch": _combo_fetch, "network": lambda asn: asn_registry.company(asn, False) if asn else "",
    "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "is_demo": is_demo, "audit": AUTH["audit"], "notes": NOTES,
    "explain": _combo_explain, "build_pdf": _combo_pdf, "scope_text": lambda: _scope_text(), "base_dir": BASE_DIR,
    "can_note": _kb_change_allowed, "shapes": lambda: _adm1_shapes(), "country": lambda: settings.data["country"],
    "svc_matcher": lambda entry, scope="memory": SVC_INTEL.matcher(entry, scope), "svc_new_code": lambda r, items: SVC_INTEL.new_code(r, items),
    # each device's infections, issues and CVEs on a day; the report day (report_day.py)
    "host_flags": lambda hosts, scope=None, load=True: SVC_INTEL.host_flags(hosts, scope, load), "replay_now": replay_now,
    "title_of": lambda n: SVC_KB["title_of"](n),
    "cross": lambda hosts, scope="memory": SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"],   # a search's devices
                                                              scope=scope),          # across every category, on the search's day(s)
    # the Impact section of the analysts' PDF: the same rule as the advisory's (advisory.Impact.summary)
    "impact_of": lambda names: _IMPACT.of_names(names, lambda n: SVC_KB["title_of"](n)),
    "logger": app.logger})
NOTES.codes = COMBOS            # notes carry combination codes; their meaning is read from the code book

# findings: notes the team follows up, researcher -> management -> analyst -> advisory (findings.py, /findings)
import findings as _findings  # noqa: E402
FINDINGS = _findings.install(app, {"people": people, "audit": AUTH["audit"], "fresh": AUTH["fresh"], "csrf_ok": AUTH["csrf_ok"],
                                   "has_perm": AUTH["has_perm"], "describe": COMBOS.describe, "base_dir": BASE_DIR,
                                   "known": lambda c: bool(COMBOS.resolve_any(c)), "logger": app.logger})
NOTES.findings = FINDINGS
from intel_match_api import _people_of  # noqa: E402,F401  (intel_match_api.py)


FINDINGS.people_of = _people_of
FINDINGS.title_of = lambda n: SVC_KB["title_of"](n)     # a services report's finding shows its title
# decoded beacons handed over to an analyst or a manager as a finding, each seeing them at their level (beacon_findings.py)
import beacon_findings as _beacon_findings  # noqa: E402
BEACON_FINDINGS_CTX = {"store": store, "labels": INTEL.ctx["labels"], "findings": FINDINGS, "has_perm": AUTH["has_perm"],
                       "book": COMBOS, "defined": INTEL.ctx["defined"], "sees_hosts": lambda: not is_demo(),
                       "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"], "audit": AUTH["audit"]}
_beacon_findings.install(app, BEACON_FINDINGS_CTX)      # "acodes" is added below, once the analyst codes exist
# requests Looking Glass could not decode, as families on the Findings page, to send to its creator (beacon_unknown.py)
import beacon_unknown as _beacon_unknown  # noqa: E402
_beacon_unknown.install(app, {"store": store, "labels": INTEL.ctx["labels"], "base_dir": BASE_DIR, "sees_hosts": lambda: not is_demo(),
                              "csrf_ok": AUTH["csrf_ok"], "audit": AUTH["audit"], "people_name": lambda u: people.name(u),
                              "can_approve": lambda: AUTH["has_perm"]("settings")})

# analyst codes: an analyst's selection passed to researchers and management without an address (acodes.py)
import acodes as _acodes  # noqa: E402


import recent_days as _recent_days                  # noqa: E402
RECENT_DAYS = _recent_days.RecentDays()
from intel_match_api import _day_for  # noqa: E402,F401  (intel_match_api.py)


ACODES = _acodes.install(app, {
    "book": COMBOS, "findings": FINDINGS, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
    "is_demo": is_demo, "audit": AUTH["audit"], "day": _day_for, "slice": _slice_on, "svc_scope": svc["scope_events"],
    "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}},
    "network": lambda asn: asn_registry.company(asn, False) if asn else "", "defined": _defined_titles,
    "people_name": lambda u: people.name(u, ""), "base_dir": BASE_DIR,
    "cross": lambda hosts, hold_small=False: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"],
                                                       hold_small=hold_small),     # every category for the code's hosts
    # the same with each CVE's / issue's hosts (server side only: a CVE ticked on the code's page, 2026-11-14)
    "cross_hosts": lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"], with_hosts=True)})
BEACON_FINDINGS_CTX["acodes"] = ACODES       # a beacon finding's records as an analyst selection (Show in Executive)
COMBOS.acode_records = ACODES.records          # the Combinations page searches analyst codes too
COMBOS.acode_allowed = ACODES.allowed          # …only those of the channels this user is in (findings.py)

# management decides which views an analyst's report carries: the researcher's, or the across-report views too
import combo_review as _combo_review  # noqa: E402
_combo_review.install(app, {"book": COMBOS, "findings": FINDINGS, "notes": NOTES, "describe": COMBOS.describe,
                            "base_dir": BASE_DIR, "day": _day_for, "svc_matcher": lambda entry: SVC_INTEL.matcher(entry),
                            "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                            "fresh": AUTH["fresh"], "is_demo": is_demo, "audit": AUTH["audit"],
                            "people_name": lambda u: people.name(u, ""),
                            "network": lambda asn: asn_registry.company(asn, False) if asn else "",
                            "acodes": ACODES,      # the drill-down's own analyst code (management's figures of that selection)
                            "cross": lambda hosts, with_hosts=False, scope="memory": SVC_INTEL.for_hosts(
                                hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"], with_hosts=with_hosts, scope=scope)})

# findings over time: the day their records were reported, their devices in the latest report again, time to act
import finding_watch as _finding_watch  # noqa: E402
_combo_labels = lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}}
FINDING_WATCH = _finding_watch.install(app, {
    "findings": FINDINGS, "book": COMBOS, "acodes": ACODES, "has_perm": AUTH["has_perm"], "replay_now": replay_now, "audit": AUTH["audit"],
    "stores": {"comms": store, "services": svc["store"]}, "network": lambda asn: asn_registry.company(asn, False) if asn else "",
    "svc_matcher": lambda entry: SVC_INTEL.matcher(entry), "comms_matcher": lambda entry: _combos.Matcher(entry, _combo_labels()),
    "logger": app.logger, "no_loop": not os.path.basename(sys.argv[0] or "").startswith("gunicorn")})

# the organisation (name and logo, set in Settings) and the advisor's advisories on decided findings
import organisation as _organisation  # noqa: E402
from intel_match_api import _site_demo  # noqa: E402,F401  (intel_match_api.py)


import advisory as _advisory  # noqa: E402
import audit_portal as _audit_portal  # noqa: E402
# the Audit portal (auditor role and admins, read only): the log by tab, dashboard and control checks, access review,
# the log's integrity and evidence exports (audit_portal.py, audit_chain.py, audit_report.py)
# signed checkpoints of the audit log and signed backup checksums (audit_checkpoint.py; its daily job starts below)
import audit_checkpoint as _audit_checkpoint  # noqa: E402
AUDIT_SIGNER = _audit_checkpoint.Signer(os.path.join(BASE_DIR, "data"))
_audit_portal.install(app, {"has_perm": AUTH["has_perm"], "users": AUTH["users"], "roles": AUTH["roles"], "sessions": AUTH["sessions"],
                            "signer": lambda: AUDIT_SIGNER, "throttle": AUTH["throttle"],
                            "audit": AUTH["audit"], "people": people, "perms_catalog": auth.PERMS, "auditor_role": auth.AUDITOR_ROLE,
                            "access_mode": security.access_mode,
                            "tls": lambda: os.path.exists(os.path.join(BASE_DIR, "data", "tls", "cert.pem")) or os.environ.get("TRUST_PROXY") == "1"})
# Audit portal → Sender check (sender_audit.py, read only) and Settings → Workers (pipeline_settings.py): the pipeline's
# DKIM sender check, its quarantine and its settings; mailbox and database passwords are never shown or edited
import sender_audit as _sender_audit  # noqa: E402
import pipeline_settings as _pipeline_settings  # noqa: E402
_sender_audit.install(app, {"base_dir": BASE_DIR, "has_perm": AUTH["has_perm"], "audit": AUTH["audit"],
                            # the report map (REPORT_MAP, made further down) says whether a new report type is defined
                            "report_entry": lambda name: REPORT_MAP.entry(name)})
PIPELINE_SETTINGS = _pipeline_settings.install(app, {   # it writes requests only into its own data/ (the pipeline applies them)
    "base_dir": BASE_DIR, "data_dir": os.path.join(BASE_DIR, "data"), "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
    "fresh": AUTH["fresh"], "audit": AUTH["audit"], "users": AUTH["users"], "throttle": AUTH["throttle"],
    "client": lambda: (request.remote_addr or "", request.headers.get("User-Agent", "")),
    # readable report names for the held-back files (scan_http -> its title in the report list)
    "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}}})
# Settings → Password policy (password_policy.py): expiry after N days, and "every account changes its password now"
import password_policy as _password_policy  # noqa: E402
_password_policy.install(app, {"policy": AUTH["password_policy"], "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                               "fresh": AUTH["fresh"], "audit": AUTH["audit"], "users": AUTH["users"], "throttle": AUTH["throttle"],
                               "client": lambda: (request.remote_addr or "", request.headers.get("User-Agent", ""))})
import peace as _peace  # noqa: E402
PEACE = _peace.install(app, {"base_dir": BASE_DIR, "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"], "audit": AUTH["audit"],
                             "role_perms": lambda role: AUTH["roles"].perms(role or "")})   # an admin's "Peace of mind"
import greetings as _greetings  # noqa: E402
GREETED = _greetings.install(app, {"base_dir": BASE_DIR, "people_name": lambda u: people.name(u, "")})   # the Overview's greeting
import overview as _overview  # noqa: E402
_overview.install(app, {"has_perm": AUTH["has_perm"]})     # the Overview page of every role
import notifications as _notifications  # noqa: E402
import system_alerts as _system_alerts  # noqa: E402  (restarts, pipeline runs, disk, name refresh: admins' bell)
if os.path.basename(sys.argv[0] or "").startswith("gunicorn"):     # the service starting, not a test importing app
    _system_alerts.note_start(os.path.join(BASE_DIR, "data"))
NOTIFS = _notifications.install(app, {"base_dir": BASE_DIR, "findings": FINDINGS, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                                      "people_name": lambda u: people.name(u, ""),
                                      "labels": lambda s: _findings.LABEL.get(s, s),
                                      "system": (NOTIFS_ALERTS := _system_alerts.Alerts(BASE_DIR))})
import tlp as _tlp  # noqa: E402
_tlp.install(app)               # the Traffic Light Protocol levels, for the Definitions page's card
ORG = _organisation.install(app, {"base_dir": BASE_DIR, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                                  "fresh": AUTH["fresh"], "is_demo": _site_demo, "audit": AUTH["audit"]})
ADVISORIES = _advisory.install(app, {"base_dir": BASE_DIR, "findings": FINDINGS, "book": COMBOS, "org": ORG,
                                     "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
                                     "is_demo": _site_demo, "audit": AUTH["audit"], "people_name": lambda u: people.name(u, ""),
                                     "title_of": lambda n: SVC_KB["title_of"](n), "describe": COMBOS.describe,
                                     "network": lambda asn: asn_registry.company(asn, False) if asn else "",
                                     "scope_text": lambda: _scope_text(), "attack": ATTACK})


import netypes  # noqa: E402  (network types: built-in sectors and the ones this site added)
_NET_LOCK = threading.Lock()
DATA_DIR = os.path.join(BASE_DIR, "data")


def _nets_allowed():
    return _settings_writable() or AUTH["has_perm"]("networks")


@app.route("/api/networks")
def api_networks():
    """The network registry (AS number -> company name and type) for editing: unreviewed first, then the busiest."""
    if not _nets_allowed():
        return jsonify(error="Editing network names needs the 'networks' permission (researchers, admins)."), 403
    # "events": the network's records on the day the map shows (both platforms, before the constituency), the same
    # count as Settings' network list; None when that day is not loaded. It used to be events_last_check, a figure
    # Identify networks noted once and never updated (0 for every network it never looked up)
    start = day_start(replay_now())
    on_day = _address_blocks.network_records([store.days.get(start), svc["store"].days.get(start)])
    recs = (lambda a: None) if on_day is None else (lambda a: on_day.get(a, 0))   # noqa: E731
    rows = [{"asn": a, "name": v.get("name", ""), "holder": v.get("holder", ""), "country": v.get("country", ""),
             "type": v.get("type", "unknown"), "role": v.get("role", ""), "reviewed": bool(v.get("reviewed")),
             "source": v.get("source", ""), "note": v.get("note", ""), "events": recs(a),
             "updated": v.get("updated", ""), "by": _by(v, "updated_by")} for a, v in asn_registry.all().items()]
    # every network in the reports is listed from the start, not only those Identify networks has looked up: one not
    # identified yet is "not reviewed", with its events and no name (2026-11-13: a fresh install showed an empty list)
    known = {r["asn"] for r in rows}
    counts, meta = _networks_in_data_cached()
    rows += [{"asn": a, "name": "", "holder": "", "country": (meta.get(a) or {}).get("country", ""), "type": "unknown",
              "role": (meta.get(a) or {}).get("role", ""), "reviewed": False, "source": "", "identified": False,
              "note": "", "events": recs(a), "updated": "", "by": ""} for a in counts if a not in known]
    rows.sort(key=lambda r: (r["reviewed"], -(r["events"] or 0)))
    return jsonify(networks=rows, types=people.with_names(netypes.all_types(DATA_DIR)), identifying=bool(_ASN_JOB and _ASN_JOB.running()),
                   can_lookup=_lookup_allowed(), events_day=start.date().isoformat() if on_day is not None else "")


def _lookup_allowed():
    """Who may look networks up: the admins (Settings) and the researchers (networks), as for editing the names."""
    return bool(_settings_change_allowed() or AUTH["has_perm"]("networks"))


_LOOKUP_SEEN = {}          # user -> times of their look-ups in the last minute (a page cannot hammer the free APIs)


@app.route("/api/networks/lookup", methods=["POST"])
def api_networks_lookup():
    """Look up a few networks of the reports by hand (2026-11-13: the network list shows every network in the reports,
    and those without a name had no way to be looked up outside Settings → Identify networks). Body {asns: [...]}: at
    most 10 AS numbers, each one in the reports loaded. The same look-up as Identify networks (asn_lookup.identify:
    PeeringDB and RIPEstat, only the AS numbers are sent); the names are saved not reviewed, for a person to check."""
    import asn_lookup
    if not (_settings_change_allowed() or (AUTH["has_perm"]("networks") and AUTH["csrf_ok"]())):
        return jsonify(error="Only researchers and admins can look networks up."), 403
    if not AUTH["fresh"]():
        return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    if _ASN_JOB and _ASN_JOB.running():
        return jsonify(error="Networks are being identified right now (Settings → Identify networks); try again when it has finished."), 409
    b = request.get_json(silent=True)
    if not isinstance(b, dict) or not isinstance(b.get("asns"), list):
        return jsonify(error="asns: a list of AS numbers expected"), 400
    asns = []
    for a in b["asns"][:10]:
        a = str(a).strip().upper().removeprefix("AS")
        if not a.isdigit() or len(a) > 10:
            return jsonify(error="An AS number is digits only, for example 64500."), 400
        asns.append(a)
    counts, meta = _networks_in_data_cached()
    asns = [a for a in dict.fromkeys(asns) if a in counts]
    if not asns:
        return jsonify(error="None of these networks is in the reports loaded."), 404
    who = (getattr(g, "user", None) or {}).get("user", "token")
    now = time.time()
    recent = [t for t in _LOOKUP_SEEN.get(who, []) if now - t < 60]
    if len(recent) >= 12:
        return jsonify(error="Many look-ups in the last minute: wait a moment."), 429
    _LOOKUP_SEEN[who] = recent + [now]
    with _NET_LOCK:
        st = asn_lookup.identify(asn_registry.path, {a: counts[a] for a in asns}, meta)
    reg = asn_lookup.load(asn_registry.path)["asns"]
    names = {a: (reg.get(a) or {}).get("name", "") for a in asns}
    AUTH["audit"].add("networks_lookup", user=who, target=", ".join(f"AS{a}" for a in asns),
                      detail=f"{st.get('added', 0)} named, {st.get('failed', 0)} failed")
    return jsonify(asked=len(asns), found=st.get("added", 0), failed=st.get("failed", 0), names=names)


@app.route("/api/networks/types", methods=["POST"])
def api_networks_types():
    """Add a network type (sector) that the built-in list does not cover; it is then offered everywhere."""
    if not (_settings_change_allowed() or (AUTH["has_perm"]("networks") and AUTH["csrf_ok"]())):
        return jsonify(error="Only researchers and admins can add network types."), 403
    if not AUTH["fresh"]():
        return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    b = request.get_json(silent=True) or {}
    who = (getattr(g, "user", None) or {}).get("user", "admin")
    try:
        key = netypes.add(DATA_DIR, b.get("label"), b.get("alias"), by=who, today=utcnow().date().isoformat())
    except ValueError as exc:
        return jsonify(error=security.public_error(exc)), 400
    AUTH["audit"].add("network_type_added", user=who, target=key, detail=f"{b.get('label')} (demo: {b.get('alias') or 'Organisation'})")
    return jsonify(saved=True, key=key, types=people.with_names(netypes.all_types(DATA_DIR)))


@app.route("/api/networks/entry", methods=["POST"])
def api_networks_entry():
    """Correct a network's company name, type or note (marked reviewed, so look-ups never overwrite it)."""
    import json as _json, re as _re
    if not (_settings_change_allowed() or (AUTH["has_perm"]("networks") and AUTH["csrf_ok"]())):
        return jsonify(error="Only researchers and admins can change network names."), 403
    if not AUTH["fresh"]():
        return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    if _ASN_JOB and _ASN_JOB.running():
        return jsonify(error="Networks are being identified right now; try again when it has finished."), 409
    b = request.get_json(silent=True)
    if not isinstance(b, dict):
        return jsonify(error="JSON expected"), 400
    asn = str(b.get("asn") or "").strip().upper().removeprefix("AS")
    name = _re.sub(r"\s+", " ", str(b.get("name") or "")).strip()
    kind, note = str(b.get("type") or "unknown"), _re.sub(r"[\x00-\x1f]", " ", str(b.get("note") or "")).strip()[:200]
    if not _re.fullmatch(r"\d{1,10}", asn):
        return jsonify(error="An AS number is digits only, for example 64500."), 400
    if not 2 <= len(name) <= 80 or _re.search(r"[<>\x00-\x1f]", name):
        return jsonify(error="The company name: 2 to 80 characters, no < or >."), 400
    if kind not in netypes.keys(DATA_DIR):
        return jsonify(error="Unknown network type: add it first (Add a type)."), 400
    path = asn_registry.path
    with _NET_LOCK:
        try:
            with open(path, encoding="utf-8") as f:
                data = _json.load(f)
        except FileNotFoundError:                       # a fresh install: the first network named by hand starts it
            data = {"asns": {}}
        e = data.setdefault("asns", {}).get(asn)
        if e is None:
            # a network in the reports that Identify networks has not looked up yet: named by hand, it joins the
            # registry (2026-11-13: every network in the reports is listed for review from the start)
            if asn not in _networks_in_data_cached()[0]:
                return jsonify(error=f"AS{asn} is not in the reports loaded."), 404
            meta = _networks_in_data_cached()[1].get(asn) or {}
            e = data["asns"][asn] = {"name": "", "type": "unknown", "country": meta.get("country", ""), "role": meta.get("role", ""),
                                     "events_last_check": _networks_in_data_cached()[0].get(asn, 0)}
        before = (e.get("name"), e.get("type"), e.get("note") or "")
        e.update(name=name, type=kind, note=note, reviewed=True, source="edited",
                 updated=utcnow().date().isoformat(), updated_by=_me()[0], updated_by_name=_me()[1])
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(data, f, indent=1, ensure_ascii=False)
        os.replace(tmp, path)
    AUTH["audit"].add("network_edited", user=(getattr(g, "user", None) or {}).get("user", "token"), target=f"AS{asn}",
                      detail=(f"{before[0]} ({before[1]}) -> {name} ({kind})" if (before[0], before[1]) != (name, kind) else f"{name} ({kind})")
                      + ("; note changed" if before[2] != (note or "") else ""))
    return jsonify(saved=True, asn=asn)


@app.route("/definitions")
def definitions_page():
    if not (_kb_allowed() or _nets_allowed()):
        return render_template("denied.html", message="Definitions are for researchers and admins."), 403
    return render_template("definitions.html")


_COUNTRY_INDEX = {"mtime": None, "data": {}}


def _country_index():
    """Every country and territory in the world (static/data/adm1/index.json, manage/fetch_world_boundaries.py), with
    its continent and its region map (regions, or the whole country as one area), read once and cached: it is
    consulted for every record when deciding whether a region is 'unknown'."""
    path = os.path.join(ADM1_DIR, "index.json")
    try:
        m = filesig.sig(path)
        if m != _COUNTRY_INDEX["mtime"]:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
            _COUNTRY_INDEX.update(mtime=m, data=raw.get("countries", {}),
                                  continents=raw.get("continents") or sorted({c.get("continent") or "" for c in raw.get("countries", {}).values()} - {""}))
    except (OSError, ValueError):
        pass
    return _COUNTRY_INDEX["data"]


def _continents():
    _country_index()
    return _COUNTRY_INDEX.get("continents") or []


_COUNTRY_BBOX = {}


def _country_bbox(cc):
    """[west, south, east, north] of the country (from its region boundaries file), cached; None if unknown. The map
    opens on a view that includes it, wherever in the world the country is (east may pass 180 for a country across
    the 180th meridian)."""
    cc = (cc or "").upper()
    if cc not in _COUNTRY_BBOX:
        box = None
        if re.fullmatch(r"[A-Z]{2}", cc):
            try:
                with open(os.path.join(ADM1_DIR, f"{cc}.json"), encoding="utf-8") as f:
                    b = json.load(f).get("bbox")
                if isinstance(b, list) and len(b) == 4 and all(isinstance(v, (int, float)) for v in b):
                    box = [round(float(v), 3) for v in b]
            except (OSError, ValueError):
                pass
        _COUNTRY_BBOX[cc] = box
    return _COUNTRY_BBOX[cc]


@app.route("/settings")
def settings_page():
    if not _settings_writable():
        return render_template("denied.html", message="Settings are for admin accounts. Ask an admin, or log in as one."), 403
    return render_template("settings.html")


@app.route("/api/settings", methods=["GET"])
def api_settings():
    """Current settings, plus what can be chosen: every country in the world by continent (with its region map, or
    the whole country as one area), and every network seen in yesterday's data on either platform (grouped by company,
    with their record counts before the constituency)."""
    # it lists network company names: admins only (viewers and public screens: security report #6)
    if not _settings_writable():
        return jsonify(error="Settings are for admin accounts."), 403
    rn = replay_now()
    cday, sday = store.days.get(day_start(rn)), svc["store"].days.get(day_start(rn))
    counts = Counter()
    for d in (cday, sday):
        if d is not None:
            counts.update(getattr(d, "asn_raw", {}))
    companies = {}
    for asn, info in asn_registry.all().items():
        if asn == "0":
            continue
        name = info.get("name") or f"AS{asn}"
        c = companies.setdefault(name, {"name": name, "type": info.get("type", ""), "asns": [], "records": 0, "demo_alias": info.get("demo_alias", "")})
        c["asns"].append(asn); c["records"] += counts.get(asn, 0)
    for asn, n in counts.items():   # networks seen in the data but not (yet) in the registry
        if asn not in asn_registry.all() and asn != "0":
            companies.setdefault(f"AS{asn}", {"name": f"AS{asn}", "type": "unknown", "asns": [asn], "records": n, "demo_alias": ""})
    nets = sorted(companies.values(), key=lambda c: (-c["records"], c["name"]))
    return jsonify(settings=settings.public(), writable=_settings_writable(),
                   type_labels=netypes.labels(DATA_DIR),
                   countries=sorted(_country_index().values(), key=lambda c: c["country"]), continents=_continents(),
                   networks=nets,
                   # the time zones each country offers (its own, then UTC), with today's offset: Settings > Country
                   zones={c: [{**timezones.info(z), "label": f"{timezones.city(z)} ({timezones.info(z)['offset']})"}
                              for z in timezones.choices(c)] for c in _country_index()},
                   data_regions=sorted((sday.region_raw if sday is not None else {}).items(), key=lambda kv: -kv[1]),
                   totals={"communications": getattr(cday, "raw_total", 0), "services": getattr(sday, "raw_total", 0)},
                   day=day_start(rn).date().isoformat())


_ASN_JOB = None


def _asn_job():
    global _ASN_JOB
    if _ASN_JOB is None:
        import asn_lookup
        _ASN_JOB = asn_lookup.IdentifyJob(os.path.join(BASE_DIR, "data", "asns.json"))
    return _ASN_JOB


def _networks_in_data():
    """Every AS number in the days held in memory (both platforms, whole country), with its events, country and role."""
    counts, meta = Counter(), {}
    for d in list(store.days.values()):
        counts.update(getattr(d, "asn_raw", {}) or {})
        for e in d.events:
            for side, role in (("src", "source"), ("dst", "destination")):
                a = str(e.get(f"{side}_asn") or "").strip()
                if a.isdigit():
                    m = meta.setdefault(a, {"country": e.get(f"{side}_geo") or "", "roles": set()})
                    m["roles"].add(role)
    for d in list(svc["store"].days.values()):
        counts.update(getattr(d, "asn_raw", {}) or {})
        for e in d.events:
            a = str(e.get("asn") or "").strip()
            if a.isdigit():
                m = meta.setdefault(a, {"country": e.get("geo") or "", "roles": set()})
                m["roles"].add("service")
    for m in meta.values():
        r = m.pop("roles")
        m["role"] = "both" if {"source", "destination"} <= r else (next(iter(r)) if len(r) == 1 else "both")
    counts = Counter({str(a): n for a, n in counts.items() if str(a).isdigit() and str(a) != "0"})
    return counts, meta


_NETS_CACHE = {"key": None, "val": (Counter(), {})}


def _networks_in_data_cached():
    """_networks_in_data() for the network list: worked out again only when a loaded day changes."""
    key = tuple(sorted((str(k), len(d.events), getattr(d, "version", "")) for k, d in list(store.days.items()))) + \
        tuple(sorted((str(k), len(d.events), getattr(d, "version", "")) for k, d in list(svc["store"].days.items())))
    if _NETS_CACHE["key"] != key:
        _NETS_CACHE.update(key=key, val=_networks_in_data())
    return _NETS_CACHE["val"]


@app.route("/api/asns/identify", methods=["GET", "POST"])
def api_asns_identify():
    """Settings > Identify networks: look up the names and types of the AS numbers in the data (PeeringDB, RIPEstat;
    asn_lookup.py), skipping those already identified. POST starts it in the background; GET reports its progress."""
    if request.method == "GET":
        if not _settings_writable():
            return jsonify(error="Settings are for admin accounts."), 403
        return jsonify(_asn_job().status)
    if not _settings_change_allowed():
        return jsonify(error="Only an admin account can do this (refresh the page if it has been open for long)."), 403
    if not AUTH["fresh"]():
        return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    started = _asn_job().start(_networks_in_data)
    AUTH["audit"].add("networks_identify", user=(getattr(g, "user", None) or {}).get("user", "token"),
                      detail="started" if started else "already running")
    return jsonify(started=started, status=_asn_job().status), (202 if started else 200)


@app.route("/api/settings", methods=["POST"])
def api_settings_save():
    if not _settings_change_allowed():
        return jsonify(error="Settings can only be changed by an account with the Settings permission (administrators)."), 403
    if not AUTH["fresh"]():
        return jsonify(error="For your security, sign out and sign in again to change Settings (stay-signed-in sessions older than 12 hours can only view).", reauth=True), 403
    # JSON only: a cross-site page can only send text/plain or a form without asking the server first (report #2);
    # an empty or unreadable body is refused instead of meaning "the defaults"
    if request.mimetype != "application/json":
        return jsonify(error="Send the settings as JSON (Content-Type: application/json)."), 415
    body = request.get_json(silent=True)
    if not isinstance(body, dict) or "country" not in body:
        return jsonify(error="The settings must be a JSON object with country, networks and cidrs."), 400
    clean, errors = Settings.validate(body, countries=set(_country_index()))
    if errors:
        return jsonify(error="; ".join(errors)), 400
    changed_scope = (clean["networks"] != settings.data["networks"] or clean["cidrs"] != settings.data["cidrs"])
    settings.save(clean)
    # which network each chosen block was ticked or added under (the Settings page's rows; address_blocks.py, r90):
    # beside settings.json, never part of it; a failure only costs the page that hint
    try:
        kept = _address_blocks.remember(_address_blocks.chosen_path(settings), clean["cidrs"], body.get("block_networks"))
    except OSError as e:
        kept = 0
        app.logger.warning("The chosen blocks' networks were not recorded: %s", e)
    if changed_scope:              # both platforms reload their days with the new constituency, straight away
        store.reset(); svc["store"].reset()
        rn = replay_now()
        threading.Thread(target=lambda: (store.get(rn), svc["store"].get(rn)), daemon=True, name="settings-reload").start()
    app.logger.warning("Settings saved: country %s, time zone %s, %d networks, %d ranges", clean["country"], clean["timezone"],
                       len(clean["networks"]), len(clean["cidrs"]))
    AUTH["audit"].add("settings_changed", user=(getattr(g, "user", None) or {}).get("user", "token"),
                      detail=f"country {clean['country']}, time zone {clean['timezone']}, {len(clean['networks'])} networks, "
                             f"{len(clean['cidrs'])} ranges ({kept} kept with their network)")
    return jsonify(settings=settings.public())


# Region names as Shadowserver writes them, matched to the map by the administrator (region_matches.py, 2026-11-15)
import region_matches as _region_matches  # noqa: E402
_RM_CTX = {"data_dir": DATA_DIR, "adm1_dir": ADM1_DIR, "country_index": lambda: _country_index(), "settings": settings,
           "settings_writable": lambda: _settings_writable(), "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
           "audit": AUTH["audit"],
           "region_raw": lambda: getattr(svc["store"].days.get(day_start(replay_now())), "region_raw", {}) or {}}
_region_matches.install(app, _RM_CTX)
REGION_MATCHES = _RM_CTX["region_matches"]


@app.route("/api/settings/public")
def api_settings_public():
    """What the portals show: the country and a summary of the constituency (never the AS list in demo mode)."""
    idx = _country_index().get(settings.data["country"], {})
    out = {"country": settings.data["country"], "country_name": idx.get("country", settings.data["country"]),
           "restricted": settings.restricted, "networks": len(settings.data["networks"]), "cidrs": len(settings.data["cidrs"]),
           "has_regions": bool(idx.get("regions")), "bbox": _country_bbox(settings.data["country"]),
           # 2026-11-15, the whole world: "regions", or "whole" (drawn as one area), or None (no map at all)
           "map_kind": idx.get("kind") or ("regions" if idx.get("regions") else None), "continent": idx.get("continent", ""),
           "country_names": idx.get("names", []),
           # the administrator's matches of report region names to this map (region_matches.py): every map uses them
           "region_matches": REGION_MATCHES.of(settings.data["country"]),
           "tz": settings.tz(),                       # the display time zone today (timezones.py)
           # changes when settings are saved, and stays the same across service restarts
           "version": settings.data.get("updated_at") or "env"}
    return jsonify(out)

# ------------------------------------------------------------------ the management portal (aggregates only)
import management  # noqa: E402
import reports_pdf as _reports_pdf  # noqa: E402
def _combo_filter(code, section, events, day=None):
    """The records of a combination code among these events (the Executive portal's code filter); [] when the code is
    unknown here or belongs to the other platform. Counts only leave the portal, never these records. An analyst code
    (LG-A) is its selection on its own day: on another day it matches nothing."""
    code = (code or "").strip().upper()
    if "," in code:                           # several codes (a review's views): the records of any of them, once each
        seen, out = set(), []
        for c in [x.strip() for x in code.split(",") if x.strip()][:25]:
            for e in _combo_filter(c, section, events, day) or []:
                if id(e) not in seen:
                    seen.add(id(e)); out.append(e)
        return out
    if _acodes.ACODE_RX.match(code):
        entry = COMBOS.get(code)
        if not entry or entry.get("kind") != "a" or ("infections" if entry["platform"] == "comms" else "issues") != section:
            return []
        if not ACODES.allowed(code):          # another channel's analyst code (findings.py)
            return []
        if day is None or day.start.date().isoformat() not in (entry.get("days") or [entry["day"]]):
            return []
        return ACODES.records(entry, day)
    if not _combos.CODE_RX.match(code):
        return []
    entry = COMBOS.resolve(code)
    if entry and entry["section"] == "services" and section == "issues":     # a services pattern code (services_intel.py)
        # on the day the portal shows: a host calls a sinkhole, and a value may be shown, as on that day (report_day.py)
        return SVC_INTEL.matcher(entry, day.start.date().isoformat() if day is not None else None).match(events)
    if not entry or entry["section"] != section:
        return []
    labels = {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}}
    return _combos.Matcher(entry, labels).match(events)


# who viewed host-level data, and the services host-list download: audit entries (data_access.py; CIS 3.14)
import data_access as _data_access  # noqa: E402
DATA_ACCESS = _data_access.register(app, lambda event, **kw: AUTH["audit"].add(event, **kw),
                                    lambda: (getattr(g, "user", None) or {}).get("user", ""), host_refs.ref)

_mgmt = management.register(app, {
    "data_dir": DATA_DIR, "combo_filter": _combo_filter,
    "infections_of": lambda ips: SVC_INTEL.infections_of(ips),       # services hosts also calling botnet sinkholes
    "AUTH": AUTH, "store": store, "svc_store": svc["store"], "registry": registry, "asn_registry": asn_registry,
    "type_labels": lambda: netypes.labels(DATA_DIR), "replay_now": replay_now, "public_demo": lambda: PUBLIC_DEMO,
    "read_names": _read_names, "knowledge_base": knowledge_base, "issues_kb": issues_kb, "cve_intel": cve_intel,
    "mp_resolve": mp_resolve, "issues_resolve": issues_resolve, "scope_text": _scope_text, "build_pdf": _reports_pdf.build,
    "sources_text": SOURCES_TEXT, "user": lambda: getattr(g, "user", None), "country": lambda: settings.data["country"],
    "geocode": lambda cc, region, city: geocoder.lookup(cc or settings.data["country"], region, city),
    "tz": lambda at=None: settings.tz(at),                 # the display time zone (Settings > Country; timezones.py)
})

# where each Shadowserver report type belongs (researchers' page): kept current from Shadowserver's schema (report_map.py)
import report_map as _report_map  # noqa: E402
REPORT_MAP = _report_map.ReportMap(
    BASE_DIR, collections=db.list_collection_names,
    fields_of=lambda n: list((db[n].find_one(sort=[("_id", -1)]) or {}).keys()), logger=app.logger)
# the Services section of the Definitions page: each services report as something researchers study (services_kb.py),
# with its patterns, across reports and sinkholes (svc_patterns.py, services_intel.py)
import services_kb as _services_kb  # noqa: E402
import svc_patterns as _svc_patterns  # noqa: E402
import services_intel as _services_intel  # noqa: E402
PATTERNS = _svc_patterns.Patterns(BASE_DIR)
SVC_INTEL = _services_intel.ServicesIntel({
    "svc_store": svc["store"], "comms_store": store, "patterns": PATTERNS,
    "labels": lambda: {x["name"]: x["label"] for x in registry.get()},     # the sinkhole reports' names
    "load_day": lambda: (svc["store"].get(replay_now()), store.get(replay_now())),     # both: sinkholes are compared too
    "replay_now": replay_now,                          # Intel gathered counts the report day (report_day.py)
    "on_codes": lambda *a: getattr(INTEL, "on_codes", None) and INTEL.on_codes(*a)})
SVC_KB = _services_kb.install(app, {
    "patterns": PATTERNS, "services_intel": SVC_INTEL, "change_allowed": _kb_change_allowed, "fresh": AUTH["fresh"],
    "audit": AUTH["audit"], "user": lambda: getattr(g, "user", None),
    "report_map": REPORT_MAP, "svc_store": svc["store"], "load_day": lambda: svc["store"].get(replay_now()),
    "report_info": report_info, "notes": NOTES, "allowed": _kb_allowed,
    "cve_card": lambda n: cve_intel.card(n, fetch=False), "issues_kb": issues_kb,
    "collections": lambda: [n for n in db.list_collection_names() if not n.startswith(_report_map.NO_REPORT)]})

# The Intelligence portal: Shadowserver's Intelligence reports for analysts and admins, counts for management
# (intelligence.py, 2026-11-14)
import intelligence as _intelligence  # noqa: E402
INTELLIGENCE = _intelligence.install(app, {
    "db": db, "report_map": REPORT_MAP, "settings": settings, "has_perm": AUTH["has_perm"], "is_demo": is_demo,
    "csrf_ok": AUTH["csrf_ok"],             # the views it is sent in a request body (POST) carry the page's token
    "audit": AUTH["audit"], "svc_reports": lambda: {x["name"] for x in svc["registry"].get()},
    "network": lambda asn: asn_registry.company(asn, False) if asn else "",
    "alias": asn_registry.alias,            # external accounts' masked view: a network by its demo alias, as on both platforms
    "cross":lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"])})

# A few heavy read-only answers, kept a few minutes and computed one at a time; any change starts afresh
# (response_cache.py). Last, so every route exists.
import response_cache as _response_cache  # noqa: E402
RESPONSE_CACHE = _response_cache.install(app, ("api_kb_services", "api_intel_summary", "api_intel_leads", "api_kb_unresolved",
                                               "api_attack"), live={"api_kb_unresolved": lambda: {"check": dict(_AUTOCHECK)}},
                                        data_dir=os.path.join(BASE_DIR, "data"),
                                        days_key=lambda: __import__("warmup").days_key([store, svc["store"]]))
# Settings → Task monitor: the service, its jobs, requests, cache, database, machine and pipeline, for admins (task_monitor.py)
import task_monitor as _task_monitor  # noqa: E402
_task_monitor.install(app, {"base_dir": BASE_DIR, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
                            "audit": AUTH["audit"], "cache": RESPONSE_CACHE, "throttle": AUTH["throttle"],
                            "heavy_limits": HEAVY_LIMITS,
                            "alerts": NOTIFS_ALERTS if "NOTIFS_ALERTS" in globals() else None})

# Not when app.py is merely imported by a script or check: the schedule state file belongs to the server.
_SERVING = __name__ == "__main__" or "gunicorn" in os.path.basename(sys.argv[0] if sys.argv else "")
if _SERVING or os.environ.get("THREATMAP_SCHEDULE") == "1":
    threading.Thread(target=schedule_loop, daemon=True, name="replay-schedule").start()
if _SERVING:
    threading.Thread(target=_autocheck_loop, daemon=True, name="malpedia-new-names").start()
    threading.Thread(target=_cve_loop, daemon=True, name="cve-lookups").start()
    threading.Thread(target=_mgmt["prewarm"], daemon=True, name="mgmt-baseline-prewarm").start()
    threading.Thread(target=REPORT_MAP.loop, daemon=True, name="report-map").start()
    threading.Thread(target=_audit_checkpoint.loop, args=(AUDIT_SIGNER, AUTH["audit"], app.logger), daemon=True,
                     name="audit-checkpoint").start()

# The Definitions page's heavy summaries, worked out in the background whenever the days in memory change, so nobody
# waits for them (warmup.py; speed review 2026-11-15)
import warmup as _warmup  # noqa: E402
# the views everyone opens first, unfiltered: worked out once per copy of the day, masked (researchers, partners) and
# not (analysts, admins), so the first person after a reload does not wait (speed review 2026-11-15: 3.5 s)
_WARM_VIEWS = ("/api/svc/stats?n=80", "/api/svc/facets", "/api/stats", "/api/facets", "/api/geo")


def _warm_views():
    adapter = app.url_map.bind("localhost")
    for path in _WARM_VIEWS:
        for masked in (False, True):
            url = path + (("&" if "?" in path else "?") + "demo=1" if masked else "")
            ep, va = adapter.match(path.split("?")[0])
            with app.test_request_context(url):
                app.view_functions[ep](**va)


WARMUP = _warmup.install({
    "stores": lambda: [store, svc["store"]], "logger": app.logger, "start": _SERVING,
    "jobs": [("first views", _warm_views),
             ("Intel gathered", lambda: INTEL.index()),
             ("services definitions", lambda: _services_kb._stats(svc["store"], lambda: svc["store"].get(replay_now()))),
             ("sinkholes per report", lambda: SVC_INTEL.index()),
             ("names seen", _name_evidence)]})

# New features install themselves from features.py with these shared parts, so this file does not grow (2026-11-16)
import features as _features  # noqa: E402
FEATURES = _features.install(app, {"db": db, "registry": registry, "svc": svc, "replay_now": replay_now,
                                   "day_start": day_start, "AUTH": AUTH, "app_logger": app.logger,
                                   "store": store, "settings": settings, "findings": FINDINGS, "acodes": ACODES,
                                   "asns": asn_registry, "serving": _SERVING, "attack": ATTACK})

if __name__ == "__main__":
    # `python app.py` (tests, development) listens on this computer only unless BIND_HOST says otherwise; the service
    # runs under gunicorn (deploy/), which has its own bind setting (external review, 2026-11-12)
    app.run(host=os.environ.get("BIND_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False, threaded=True)
