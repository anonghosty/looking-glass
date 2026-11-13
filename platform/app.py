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
from urllib.parse import parse_qsl

from bson import ObjectId
from dotenv import load_dotenv
from flask import Flask, Response, g, jsonify, render_template, request
from pymongo import MongoClient
from werkzeug.datastructures import MultiDict

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
from sources import STD_FIELDS, Registry, normalise

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

MAPBOX_TOKEN = os.environ.get("MAPBOX_TOKEN", "")
OFFSET_HOURS = float(os.environ.get("REPLAY_OFFSET_HOURS", "24"))
MAX_PER_POLL = int(os.environ.get("MAX_EVENTS_PER_POLL", "400"))
DAY_RELOAD_SECONDS = int(os.environ.get("DAY_RELOAD_SECONDS", "600"))
# once a day's report starts arriving, wait this long (so every report is imported) before replaying it from 00:00
SETTLE_SECONDS = int(os.environ.get("REPORT_SETTLE_SECONDS", "600"))

client = MongoClient(
    host=os.environ.get("MONGO_HOST", "localhost"),
    port=int(os.environ.get("MONGO_PORT", "27017")),
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
                 "http_agent", "request")
FACET_FIELDS = ("source", "attack_class", "infection", "severity", "tag", "src_city", "dst_geo", "dst_port", "protocol", "src_geo")
EMPTY_LABEL = {"infection": "unknown", "tag": "untagged", "severity": "unrated"}

asn_registry = AsnRegistry(os.path.join(BASE_DIR, "data", "asns.json"), logger=app.logger)
# Settings shared by both platforms (country, constituency): defaults from .env, saved on /settings
settings = Settings(os.path.join(BASE_DIR, "data", "settings.json"))
host_refs = HostRefs(os.environ.get("REF_SECRET"))
malpedia = Malpedia(os.environ.get("MALPEDIA_TOKEN"), os.path.join(BASE_DIR, "data", "malpedia_cache.json"), logger=app.logger)
import cves  # noqa: E402  (NVD, CISA KEV and EPSS for the services platform's issues)
from malpedia import MAX_PER_MINUTE as MAX_MP  # noqa: E402
cve_intel = cves.CveIntel(os.path.join(BASE_DIR, "data", "cve_cache.json"), os.environ.get("NVD_API_KEY", ""), logger=app.logger)
PUBLIC_DEMO = os.environ.get("PUBLIC_DEMO") == "1"   # force demo masking for every request
# who may connect, host names, cross-site writes, security headers, request size (security.py, docs/SECURITY_REPORT.md)
security.install(app, app.logger)
# login, accounts, roles and sessions (auth.py): every page and API needs a login
AUTH = auth.install(app, BASE_DIR, app.logger)
# the security self-test clears this computer's login counters itself, so it never restarts the service (retest_reset.py)
import retest_reset  # noqa: E402
retest_reset.install(app, {"throttle": AUTH["throttle"], "audit": AUTH["audit"]})
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
        why = f"MongoDB at {os.environ.get('MONGO_HOST', '127.0.0.1')}:{os.environ.get('MONGO_PORT', '27017')} cannot be reached"
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


def matches(ev, flt):
    return all(ev.get(f) in vals for f, vals in flt.items())


# ---------------------------------------------------------------- day store
class Day:
    def __init__(self, start, events):
        self.start = start
        self.events = events                       # sorted by extracted_date
        self.keys = [e["_t"] for e in events]       # epoch seconds, for bisect
        self.loaded_at = time.time()
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
        docs, last = [], None
        if src["filename_index"]:
            q = {"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in prefixes]}
            docs = list(c.find(q))
        if not docs and os.environ.get("FALLBACK_SCAN") == "1":
            docs = list(c.find({"extracted_date": {"$gte": start, "$lt": end}}))
        out = []
        for d in docs:
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

    def _load(self, start):
        t0 = time.time()
        end = start + timedelta(days=1)
        srcs = registry.get()
        try:
            sig = self.signature(start)   # taken before the rows, so anything inserted meanwhile triggers a reload
        except Exception:
            sig = None
        with ThreadPoolExecutor(max_workers=6) as pool:
            parts = list(pool.map(lambda s: (s, *self._fetch_collection(s, start, end)), srcs))
        events, per, arrived = [], {}, {}
        raw_total, asn_raw = 0, Counter()
        for s, rows, last in parts:
            raw_total += len(rows)
            for e in rows:                      # every network seen (for the Settings page), before the constituency
                for side in ("src", "dst"):
                    if e[f"{side}_asn"]:
                        asn_raw[str(e[f"{side}_asn"])] += 1
            # constituency (Settings): keep events whose source or destination host is in it
            if settings.restricted:
                rows = [e for e in rows if settings.in_scope(e["src_asn"], e["src_ip"]) or settings.in_scope(e["dst_asn"], e["dst_ip"])]
            events += rows
            if rows:
                per[s["name"]] = len(rows)
                if last:
                    arrived[s["name"]] = iso(last)
        # geocode every distinct place once, in parallel
        places = {(e[f"{s}_geo"], e[f"{s}_region"], e[f"{s}_city"]) for e in events for s in ("src", "dst")}
        with ThreadPoolExecutor(max_workers=8) as pool:
            resolved = dict(zip(places, pool.map(lambda p: geocoder.lookup(*p), places)))
        geocoder.flush()
        for e in events:
            for f, v in e.items():
                if isinstance(v, datetime):
                    e[f] = iso(v)
            e["src_coords"] = resolved.get((e["src_geo"], e["src_region"], e["src_city"]))
            e["dst_coords"] = resolved.get((e["dst_geo"], e["dst_region"], e["dst_city"]))
        for e in events:
            e["src_ref"] = host_refs.ref(e["src_ip"])
            e["request"] = _request_path(e["http_url"]) if e.get("http_url") else ""   # filterable request path
        events.sort(key=lambda e: e["_t"])
        app.logger.warning("Loaded %s: %d events from %d collections %s, %d places in %.1fs",
                           start.date(), len(events), len(per), per, len(places), time.time() - t0)
        day = Day(start, events)
        day.per_source = per
        day.arrived = arrived
        day.sig = sig
        day.raw_total, day.asn_raw = raw_total, asn_raw
        day.version = hashlib.md5(json.dumps([sorted(per.items()), settings.version]).encode()).hexdigest()[:10]
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
        """Reload a day straight away if MongoDB has more (or different) rows than the loaded copy."""
        start = day_start(dt)
        day = self.days.get(start)
        if day is None or start > utcnow():
            return False
        try:
            sig = self.signature(start)
        except Exception:
            app.logger.exception("Report check failed for %s", start.date())
            return False
        if sig == day.sig:
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
                day.loaded_at = 0          # next get() reloads it

    def get(self, dt):
        start = day_start(dt)
        with self.lock:
            day = self.days.get(start)
            # an empty day (file not imported yet) is retried every minute
            ttl = DAY_RELOAD_SECONDS if day and day.events else 60
            fresh = day and time.time() - day.loaded_at < ttl
            if fresh:
                return day
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
            for _ in range(3):
                gen = self.gen
                new = self._load(start)
                with self.lock:
                    if self.gen != gen:          # the constituency changed while loading: load again with it
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
            days = [d for d in {day_start(pos), day_start(pos) + timedelta(days=1), schedule.target()} if d <= utcnow()]
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
    out = {k: v for k, v in ev.items() if k != "_t"}
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
    flt = parse_filters(request.args)
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
    """Filter values (with counts) for the whole replay day."""
    day = store.get(parse_iso(request.args.get("at"), replay_now()))
    demo = is_demo()
    key = ("facets", day_key(day), demo, asn_registry.mtime, registry.version)
    return jsonify(RCACHE.get(key, lambda: _facets_core(day, demo)))


def _facets_core(day, demo):
    result = {}
    for field in FACET_FIELDS:
        c = Counter(e[field] for e in day.events)
        rows = [{"value": v or EMPTY_LABEL.get(field, ""), "count": n} for v, n in c.most_common(300)]
        result[field] = [r for r in rows if r["value"]]
    # severity of each infection (most common one), so the UI can color infections consistently
    sev = {}
    for e in day.events:
        sev.setdefault(e["infection"] or "unknown", Counter())[e["severity"]] += 1
    result["infection_severity"] = {k: c.most_common(1)[0][0] for k, c in sev.items()}
    # source and destination networks, grouped by company (all ASNs of an operator together), like Intel shows them;
    # aliases in demo mode. The value is what the src_asn / dst_asn filters take (asn_registry.resolve).
    for side in ("src", "dst"):
        c = Counter(asn_registry.company(e[f"{side}_asn"], demo) for e in day.events if e[f"{side}_asn"])
        result[f"{side}_asn"] = [{"value": v, "count": n} for v, n in c.most_common(300) if v]
    result["source_labels"] = {s["name"]: s["label"] for s in registry.get()}
    result["source_class"] = {s["name"]: s["class"] for s in registry.get()}
    result["day"] = day.start.date().isoformat()
    result["day_total"] = len(day.events)
    return result


@app.route("/api/stats")
def api_stats():
    """Totals and top-N counts for the WHOLE replay day: every record of every report, never just the part
    already replayed. The replay only drives the map and the stream; these figures stay fixed for the day
    (they change only when late rows arrive in MongoDB, picked up on the periodic day reload)."""
    rn = parse_iso(request.args.get("at"), replay_now())
    day = store.get(rn)
    flt = parse_filters(request.args)
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
    flt = parse_filters(request.args)
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
    flt = parse_filters(request.args)
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
        special=special_reports.listing(db),
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


def _parse_time_value(value):
    """'1080+60|infection|android.badbox2' -> (1080, 60, 'infection', 'android.badbox2')."""
    span, _, scope = (value or "").partition("|")
    start_s, _, dur_s = span.partition("+")
    try:   # minutes; fractions allowed so a window can end exactly at the replay position
        start, dur = max(0.0, min(1439.0, float(start_s))), max(1 / 60, min(1440.0, float(dur_s or 60)))
    except ValueError:
        start, dur = 0.0, 1440.0
    sk, _, sv = scope.partition("|")
    if sk not in INSIGHT_KINDS or sk == "time":
        sk, sv = "", ""
    return start, dur, sk, sv


def _hm(minutes):
    if minutes >= 1440:
        return "24:00"
    m = int(minutes)
    s = int(round((minutes - m) * 60))
    return f"{m // 60 % 24:02d}:{m % 60:02d}" + (f":{s:02d}" if s else "")
# values that are concealed in demo mode: the browser gets an opaque reference instead, resolved here
REF_KINDS = ("dst_ip", "http_host", "http_agent", "request")


def _place_parts(v):
    city, _, cc = (v or "").partition("|")
    return city, cc


def _median(xs):
    xs = sorted(xs)
    n = len(xs)
    if not n:
        return None
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def _top(events, field, n=8, label=None, key=None):
    c = Counter((key(e[field]) if key else e[field]) for e in events if e[field])
    total = sum(c.values()) or 1
    return [{"value": v, "label": label(v) if label else v, "count": k, "share": round(k / total, 4)} for v, k in c.most_common(n)]


def _request_path(url):
    # "GET /sck/29965/?m=a11&step=669 HTTP/1.0" -> "GET /sck/29965/"
    parts = url.split(" ")
    if len(parts) >= 2:
        return f"{parts[0]} {parts[1].split('?')[0]}"
    return url.split("?")[0]


def _fmt_dur(seconds):
    if seconds is None:
        return None
    if seconds < 90:
        return f"{seconds:.0f}s"
    if seconds < 5400:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def _select_slice(kind, value, rn):
    """(day, all events of the whole replay day, events matching kind=value)."""
    return _slice_on(store.get(rn), kind, value)


def _slice_on(day, kind, value):
    """The same selection on a given day (also one loaded from the history: analyst codes, combos.py)."""
    sofar = day.events
    if kind == "time":
        start, dur, sk, sv = _parse_time_value(value)
        t0 = day.start.timestamp() + start * 60
        t1 = t0 + dur * 60
        base = _slice_on(day, sk, sv)[2] if sk else sofar
        return day, sofar, [e for e in base if t0 <= e["_t"] < t1]
    if kind == "filters":
        # the same filter logic as the map, stream and Intel, so the numbers agree everywhere
        pairs = parse_qsl(value or "", keep_blank_values=False)
        flt = parse_filters(MultiDict(pairs))
        # a time window ("time=1080+60") narrows by event time; it is not a map filter
        windows = []
        for k, v in pairs:
            if k == "time":
                start, dur, _, _ = _parse_time_value(v)
                t0 = day.start.timestamp() + start * 60
                windows.append((t0, t0 + dur * 60))
        return day, sofar, [e for e in sofar if matches(e, flt) and all(a <= e["_t"] < b for a, b in windows)]
    if kind in REF_KINDS:
        value = host_refs.resolve(value)                # opaque reference (demo mode) or the value itself
    match_value = "" if value == EMPTY_LABEL.get(kind) else value
    if kind == "request":
        ev = [e for e in sofar if e["http_url"] and _request_path(e["http_url"]) == value]
    elif kind == "dst_port":
        ev = [e for e in sofar if str(e["dst_port"] or "") == str(match_value)]
    elif kind in ("src_asn", "dst_asn"):
        wanted = asn_registry.resolve(value)            # company name, demo alias or AS number
        ev = [e for e in sofar if e[kind] in wanted]
    elif kind == "src_ip":
        real_ip = host_refs.resolve(value)              # opaque host reference or IP
        ev = [e for e in sofar if e["src_ip"] == real_ip]
    elif kind == "route":
        s, _, d = value.partition(">")
        (sc, sg), (dc, dg) = _place_parts(s), _place_parts(d)
        ev = [e for e in sofar if (e["src_city"] or "") == sc and (e["src_geo"] or "") == sg
              and (e["dst_city"] or "") == dc and (e["dst_geo"] or "") == dg]
    elif kind == "dst_place":
        dc, dg = _place_parts(value)
        ev = [e for e in sofar if (e["dst_city"] or "") == dc and (e["dst_geo"] or "") == dg]
    else:
        ev = [e for e in sofar if e[kind] == match_value]
    return day, sofar, ev


def _rhythm(ts):
    """(median gap in seconds, coefficient of variation) for a host's event times, or (None, None)."""
    if len(ts) < 3:
        return None, None
    d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
    if len(d) < 2:
        return None, None
    mean = sum(d) / len(d)
    sd = (sum((x - mean) ** 2 for x in d) / len(d)) ** 0.5
    return _median(d), (sd / mean if mean else None)


def _hhmmss(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%H:%M:%S")


DRILL_METRICS = ("events", "share", "hosts", "c2", "dst_ips", "interval", "multi", "reports", "cross")
DRILL_LIMIT = 300


@app.route("/api/insight/drill")
def api_insight_drill():
    """The list behind one figure of the analysis view: which hosts, domains, reports or destinations it counts,
    with follow-up priorities for hosts. Demo mode masks IPs, networks and domains like everywhere else."""
    kind = request.args.get("kind", "")
    value = request.args.get("value", "")
    metric = request.args.get("metric", "")
    if kind not in INSIGHT_KINDS or metric not in DRILL_METRICS:
        return jsonify(error="unknown kind or metric"), 400
    rn = parse_iso(request.args.get("at"), replay_now())
    demo = is_demo()
    day, sofar, ev = _select_slice(kind, value, rn)
    mip = mask_ip if demo else (lambda s: s)
    mt = mask_text if demo else (lambda s: s)
    labels = {s["name"]: s["label"] for s in registry.get()}
    classes = {s["name"]: s["class"] for s in registry.get()}
    n = len(ev)

    # per-host profile inside the selection, plus whole-day context for the same hosts
    hosts = {}
    for e in ev:
        if not e["src_ip"]:          # destination-only reports have no source host to follow up
            continue
        h = hosts.get(e["src_ip"])
        if h is None:
            h = hosts[e["src_ip"]] = {"ts": [], "e": e, "crit": 0}
        h["ts"].append(e["_t"])
        if e["severity"] == "critical":
            h["crit"] += 1
    day_src, day_inf = {}, {}
    for e in sofar:
        if e["src_ip"] in hosts:
            day_src.setdefault(e["src_ip"], set()).add(e["source"])
            day_inf.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")

    def host_row(ip):
        h = hosts[ip]
        s = h["e"]
        med, cv = _rhythm(h["ts"])
        srcs, infs = day_src.get(ip, set()), day_inf.get(ip, set())
        kinds = {classes.get(x) for x in srcs} - {None}
        reasons, score = [], 0
        if len(kinds) > 1:
            reasons.append("Several kinds of activity"); score += 4
        if len(srcs) > 1:
            reasons.append(f"In {len(srcs)} reports"); score += 2
        if len(infs) > 1:
            reasons.append(f"{len(infs)} infections / categories"); score += 2
        if cv is not None and cv < 0.5:
            reasons.append("Regular beaconing"); score += 1
        if h["crit"]:
            reasons.append("Critical"); score += 1
        return {
            "ref": s["src_ref"], "ip": mip(ip), "followup": reasons, "score": score, "events": len(h["ts"]),
            "infections": sorted(infs), "reports": sorted(labels.get(x, x) for x in srcs),
            "kinds": sorted(kinds), "city": s["src_city"], "network": asn_registry.label(s["src_asn"], demo) or "",
            "interval": _fmt_dur(med) or "", "rhythm": "" if cv is None else ("Regular" if cv < 0.5 else "Irregular"),
            "first": _hhmmss(h["ts"][0]), "last": _hhmmss(h["ts"][-1]),
        }

    def ranked(ips):
        rows = [host_row(ip) for ip in ips]
        rows.sort(key=lambda r: (-r["score"], -r["events"]))
        return rows

    def group(field, key=None):
        g = {}
        for e in ev:
            v = e[field]
            if not v:
                continue
            v = key(v) if key else v
            x = g.get(v)
            if x is None:
                x = g[v] = {"events": 0, "hosts": set(), "crit": 0, "inf": set(), "dst": set(), "geo": set(),
                            "asn": set(), "ports": set(), "dom": set(), "src": set(), "t0": e["_t"], "t1": e["_t"]}
            x["events"] += 1; x["inf"].add(e["infection"] or "unknown")
            if e["src_ip"]: x["hosts"].add(e["src_ip"])
            if e["dst_ip"]: x["dst"].add(e["dst_ip"])
            x["src"].add(e["source"]); x["t1"] = e["_t"]
            if e["severity"] == "critical": x["crit"] += 1
            if e["dst_geo"]: x["geo"].add(e["dst_geo"])
            if e["dst_asn"]: x["asn"].add(e["dst_asn"])
            if e["dst_port"]: x["ports"].add(str(e["dst_port"]))
            if e["http_host"]: x["dom"].add(mt(e["http_host"]))
        return sorted(g.items(), key=lambda kv: -kv[1]["events"])

    H = {"ip": "Host IP", "followup": "Follow-up", "events": "Events", "infections": "Infections / categories",
         "reports": "Reports", "city": "City", "network": "Network", "interval": "Repeat interval",
         "rhythm": "Rhythm", "first": "First seen", "last": "Last seen", "kinds": "Kinds of activity"}
    cols = lambda *keys: [[k, H[k]] for k in keys]
    out = {"metric": metric, "row_kind": None, "intro": "", "empty": "Nothing to list for this selection yet."}

    if metric == "hosts":
        rows = ranked(hosts)
        n_fu = sum(1 for r in rows if r["score"] >= 2)
        out.update(title="Source hosts, ranked for follow-up", row_kind="src_ip",
                   intro=f"{len(rows):,} source hosts. {n_fu:,} of them have stronger signs of compromise "
                         "(several kinds of activity, several reports or several infections) and are listed first.",
                   columns=cols("ip", "followup", "events", "infections", "reports", "city", "network", "interval", "first", "last"),
                   rows=rows)
    elif metric == "cross":
        rows = ranked([ip for ip in hosts if len(day_src.get(ip, ())) > 1])
        mixed = sum(1 for r in rows if len(r["kinds"]) > 1)
        out.update(title="Hosts seen in more than one report", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts appear in several Shadowserver reports on the same day. "
                         f"{mixed:,} of them show more than one kind of activity (for example botnet C2 traffic and attacks) "
                         "and should be followed up first.",
                   columns=cols("ip", "reports", "kinds", "followup", "events", "infections", "city", "network", "first", "last"),
                   rows=rows, empty="None of these hosts appear in another report yet.")
    elif metric == "multi":
        rows = ranked([ip for ip in hosts if len(day_inf.get(ip, ())) > 1])
        out.update(title="Hosts with more than one infection / category", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts carry more than one infection or category on the same day. "
                         "This suggests several infections on one device, or proxy software bundled with malware.",
                   columns=cols("ip", "infections", "followup", "events", "reports", "city", "network", "first", "last"),
                   rows=rows, empty="No host in this selection shows more than one infection / category yet.")
    elif metric == "interval":
        rows = [r for r in (host_row(ip) for ip in hosts) if r["interval"]]
        rows.sort(key=lambda r: (r["rhythm"] != "Regular", -r["events"]))
        reg = sum(1 for r in rows if r["rhythm"] == "Regular")
        out.update(title="Repeat behaviour of hosts", row_kind="src_ip",
                   intro=f"{len(rows):,} hosts were seen at least three times. {reg:,} repeat at a regular rhythm, "
                         "which points to automated beaconing or scripted attacks; they are listed first.",
                   columns=cols("ip", "interval", "rhythm", "events", "infections", "followup", "city", "network", "first", "last"),
                   rows=rows, empty="No host has been seen often enough (three times or more) to measure a rhythm yet.")
    elif metric in ("events", "reports"):
        if metric == "events":
            g = {}
            for e in ev:
                k = (e["infection"] or "unknown", e["source"])
                x = g.setdefault(k, {"events": 0, "hosts": set(), "crit": 0})
                x["events"] += 1; x["crit"] += e["severity"] == "critical"
                if e["src_ip"]: x["hosts"].add(e["src_ip"])
            rows = [{"value": inf, "infection": inf, "report": labels.get(src, src), "events": x["events"],
                     "hosts": len(x["hosts"]), "critical": x["crit"], "share": f"{x['events'] / max(1, n):.1%}"}
                    for (inf, src), x in sorted(g.items(), key=lambda kv: -kv[1]["events"])]
            out.update(title="Events by infection / category and report", row_kind="infection",
                       intro=f"{n:,} events, split by what Shadowserver reported and in which report.",
                       columns=[["infection", "Infection / category"], ["report", "Report"], ["events", "Events"],
                                ["hosts", "Source hosts"], ["critical", "Critical"], ["share", "Share of selection"]],
                       rows=rows)
        else:
            rows = [{"value": src, "report": labels.get(src, src), "kind": classes.get(src, ""), "events": x["events"],
                     "hosts": len(x["hosts"]), "critical": x["crit"], "infections": len(x["inf"]),
                     "share": f"{x['events'] / max(1, n):.1%}"} for src, x in group("source")]
            out.update(title="Reports in this selection", row_kind="source",
                       intro=f"{len(rows):,} Shadowserver report{'s' if len(rows) != 1 else ''} contain these events.",
                       columns=[["report", "Report"], ["kind", "Attack type"], ["events", "Events"], ["hosts", "Source hosts"],
                                ["infections", "Infections / categories"], ["critical", "Critical"], ["share", "Share of selection"]],
                       rows=rows)
    elif metric == "share":
        mine = Counter(e["source"] for e in ev)
        allc = Counter(e["source"] for e in sofar)
        tot = max(1, len(sofar))
        rows = [{"value": src, "report": labels.get(src, src), "kind": classes.get(src, ""), "all": k,
                 "share_all": f"{k / tot:.1%}", "mine": mine.get(src, 0),
                 "mine_share": f"{mine.get(src, 0) / k:.1%}" if k else ""} for src, k in allc.most_common()]
        out.update(title="How this selection compares with all events", row_kind="source",
                   intro=f"This selection has {n:,} of the {len(sofar):,} events Shadowserver reported for the day ({n / tot:.1%}). "
                         "Each report below shows its size and how much of it belongs to this selection.",
                   columns=[["report", "Report"], ["kind", "Attack type"], ["all", "All events"], ["share_all", "Share of all events"],
                            ["mine", "In this selection"], ["mine_share", "Selection's part of the report"]],
                   rows=rows)
    elif metric == "c2":
        rows = [{"value": host_refs.ref(d) if demo else d, "domain": mt(d), "events": x["events"], "hosts": len(x["hosts"]),
                 "infections": sorted(x["inf"]), "dst": len(x["dst"]), "first": _hhmmss(x["t0"]), "last": _hhmmss(x["t1"])}
                for d, x in group("http_host")]
        out.update(title="C2 / sinkhole domains contacted", row_kind="http_host",
                   intro=f"{len(rows):,} domain names the hosts tried to reach, most contacted first.",
                   columns=[["domain", "Domain"], ["events", "Events"], ["hosts", "Source hosts"], ["infections", "Infections / categories"],
                            ["dst", "Destination IPs"], ["first", "First seen"], ["last", "Last seen"]],
                   rows=rows,
                   empty="These reports record only IP addresses, not domain names. Open Destination IPs to see where the hosts connected.")
    elif metric == "dst_ips":
        rows = []
        for d, x in group("dst_ip"):
            rows.append({"value": d, "dst": mip(d), "country": next(iter(x["geo"]), ""),
                         "network": asn_registry.label(next(iter(x["asn"])), demo) if x["asn"] else "",
                         "ports": sorted(x["ports"], key=lambda p: int(p) if p.isdigit() else 0), "domains": sorted(x["dom"])[:3],
                         "events": x["events"], "hosts": len(x["hosts"]), "infections": sorted(x["inf"])})
        out.update(title="Destination IPs contacted", row_kind="dst_ip",
                   intro=f"{len(rows):,} destination addresses (sinkholes, honeypot sensors or targets), most contacted first.",
                   columns=[["dst", "Destination IP"], ["country", "Country"], ["network", "Network"], ["ports", "Ports"],
                            ["domains", "Domains"], ["events", "Events"], ["hosts", "Source hosts"], ["infections", "Infections / categories"]],
                   rows=rows)
        if demo:
            for r in rows:
                r["value"] = host_refs.ref(r["value"])   # concealed, but still clickable

    rows = out.get("rows", [])
    out["total"] = len(rows)
    out["rows"] = rows if request.args.get("all") == "1" else rows[:DRILL_LIMIT]   # all=1: CSV export
    out.setdefault("columns", [])
    return jsonify(out)


# ------------------------------------------------------------------ PDF reports of an analysis figure (both platforms)
def _scope_text():
    idx = _country_index().get(settings.data["country"], {})
    c = idx.get("country", settings.data["country"])
    if settings.restricted:
        n, k = len(settings.data["networks"]), len(settings.data["cidrs"])
        return f"{c} · constituency: {n} network{'s' if n != 1 else ''}" + (f" and {k} address range{'s' if k != 1 else ''}" if k else "")
    return f"{c} · whole country"


def _view_json(name):
    """Run another endpoint's view with this request's arguments; (data, None) or (None, error response)."""
    res = app.view_functions[name]()
    if isinstance(res, tuple):
        return None, res
    return res.get_json(), None


def _pdf_label():
    import re as _re
    return _re.sub(r"[\x00-\x1f]", " ", request.args.get("label") or "").strip()[:160]


def _file_base(parts):
    import re as _re
    return "looking-glass_" + ("_".join(_re.sub(r"[^\w.-]+", "-", str(p)).strip("-")[:40] for p in parts if p) or "report")


def _report_response(pdf, base, cols, prow):
    """format=pdf: the PDF alone. Otherwise (default) a ZIP with the PDF and the complete list as CSV."""
    import io as _io, zipfile
    if request.args.get("format") == "pdf":
        return Response(pdf, mimetype="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{base}.pdf"', "Cache-Control": "no-store"})
    import csvsafe   # no spreadsheet formulas in any cell
    buf = _io.StringIO()
    w = csvsafe.writer(buf)
    w.writerow([lbl for _, lbl in cols])
    for r in prow:
        w.writerow([r.get(k, "") for k, _ in cols])
    z = _io.BytesIO()
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{base}.pdf", pdf)
        zf.writestr(f"{base}.csv", "\ufeff" + buf.getvalue())
    return Response(z.getvalue(), mimetype="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{base}.zip"', "Cache-Control": "no-store"})


def _short(x):
    if x.get("kind") == "cve":
        bits = [f"CVSS {x['cvss']['score']} {x['cvss'].get('severity', '')}".strip()] if x.get("cvss") else []
        if x.get("exploited"):
            bits.append("ACTIVELY EXPLOITED (CISA KEV)")
        if x.get("epss") is not None:
            bits.append(f"EPSS {x['epss']:.1%}")
        if x.get("pending"):
            bits.append("not looked up yet")
        elif not x.get("found"):
            bits.append("no public record")
        name = (x.get("kev") or {}).get("name") or (x.get("description") or "")[:90]
        return f"{name} ({', '.join(bits)})" if name else ", ".join(bits)
    if x.get("found") and x.get("kind") == "actor":
        return f"{x.get('name')} (threat actor)"
    if x.get("found"):
        return f"{x.get('name')} ({x.get('family')})"
    if x.get("curated"):
        return f"{x.get('title')} (Looking Glass definition)"
    return x.get("title") or "not in Malpedia"


def _enrich_names(ordered):
    """[(name, stat)] -> ({name: card}, {name: stat}, note). At most 60 names (Malpedia answers are cached)."""
    if not AUTH["has_perm"]("malpedia"):
        return {}, {}, ""
    out, stats = {}, {}
    for name, stat in ordered:
        if len(out) >= 60:
            break
        if not name or name.startswith("ref:") or name in out:
            continue
        try:
            out[name] = mp_resolve(name)[0]
        except ValueError:
            continue
        except RuntimeError as exc:
            out[name] = {"found": False, "pending": True, "title": "Not checked yet",
                         "reason": f"Malpedia did not answer in time ({security.public_error(exc, 'no answer')}). Download the report again in a minute."}
        stats[name] = stat
    note = ("Each infection / category was looked up on Malpedia, the malware encyclopedia of Fraunhofer FKIE (malware "
            "families, and threat actors for group names). Names Malpedia does not list are explained from the definitions "
            "written by the security researchers of the organisation that uses this platform, with their references, or "
            "from the evidence in the reports."
            if malpedia.enabled else
            "Malpedia is not set up on this platform, so the infections / categories are explained from the definitions "
            "written by the security researchers of the organisation that uses this platform (with their references) and "
            "the Looking Glass knowledge base, or from the evidence in the reports.")
    return out, stats, note


def _bd_rows(rows, total, hosts=False):
    out = []
    for r in rows:
        share = r.get("share")
        share = share if isinstance(share, (int, float)) else (r.get("count", 0) / max(1, total))
        row = [r.get("label") or r.get("value") or "(none)", f"{r.get('count', 0):,}"]
        if hosts:
            row.append(f"{r.get('hosts', 0):,}")
        out.append(row + [f"{share:.1%}"])
    return out


def _pdf_rows(columns, rows, enr, issues=False, row_name=False):
    """Cells as printed text; plus what each infection (or issue) is, when the list has them."""
    has_inf = enr and (row_name or any(k in (("issues",) if issues else ("infections", "infection")) for k, _ in columns))
    label = "What it is (CVE: NVD / CISA KEV / EPSS; others: definition)" if issues else "What it is (Malpedia / definition)"
    cols = columns + ([["_explained", label]] if has_inf else [])
    out = []
    for r in rows:
        x = {}
        for k, _ in cols:
            v = r.get(k)
            if k == "_explained":
                names = ([r.get("name")] if row_name else (r.get("issues") or [])) if issues else \
                    [n for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n]
                v = "; ".join(f"{n}: {_short(enr[n])}" for n in names if n in enr)
            elif k == "followup":
                v = "; ".join(v or []) or "Monitor"
            elif isinstance(v, list):
                v = ", ".join(str(i) for i in v)
            elif isinstance(v, (int, float)):
                v = f"{v:,}"
            elif k in ("first", "last") and isinstance(v, str) and "T" in v:
                v = v.replace("T", " ")[:19]
            elif k == "city":
                v = (v or "").title()
            x[k] = "" if v is None else v
        out.append(x)
    return cols, out


SOURCES_TEXT = [
    "Data: the Shadowserver Foundation's free daily network reports for the constituency (sinkholes, honeypots and "
    "internet-wide scans). An event is one report row; one host can appear in many rows and reports.",
    "Malware families and threat actors: Malpedia (Fraunhofer FKIE), malpedia.caad.fkie.fraunhofer.de.",
    "Looking Glass definitions: written by the security researchers of the organisation that uses this platform, for "
    "names that Malpedia does not list and for issues that are not CVEs, each with its references (evidence) and the "
    "name of the researcher who wrote it.",
    "Vulnerabilities (CVEs): NIST National Vulnerability Database (description, CVSS score), CISA Known Exploited "
    "Vulnerabilities catalog (confirmed active exploitation) and FIRST EPSS (probability of exploitation in the next 30 days).",
    "Figures describe the replay day up to the time of the analysis. The complete list is in the CSV file delivered "
    "with this report.",
]


@app.route("/api/insight/report.pdf")
@app.route("/api/insight/report")
def api_insight_report_pdf():
    """PDF of one analysis figure on the network-communications platform (same arguments as the drill-down + all=1)."""
    if not AUTH["has_perm"]("export"):
        return jsonify(error="Your role cannot download reports (permission 'export')."), 403
    if request.args.get("all") != "1":
        return jsonify(error="all=1 expected"), 400
    I, err = _view_json("api_insight")
    if err:
        return err
    D, err = _view_json("api_insight_drill")
    if err:
        return err
    import reports_pdf
    rows = D.get("rows") or []
    # what to explain: the selection's infections by events, then any other name in the list
    inf_b = (I.get("breakdowns") or {}).get("infection") or []
    ordered = [(r["value"], f"{r['count']:,} events ({r['share']:.1%} of the selection)") for r in inf_b if r.get("value")]
    if I.get("kind") == "infection":
        ordered.insert(0, (I["value"], f"{I['total']:,} events"))
    seen = Counter(n for r in rows for n in ([r.get("infection")] if r.get("infection") else (r.get("infections") or [])) if n)
    ordered += [(n, f"on {k:,} listed entr{'y' if k == 1 else 'ies'}") for n, k in seen.most_common()]
    enr, stats, note = _enrich_names(ordered)

    pts = list(I.get("insights") or [])
    hostish = D.get("row_kind") == "src_ip"
    priorities = None
    if hostish and rows:
        top = [r for r in rows if r.get("score", 0) >= 2][:15] or rows[:10]
        priorities = (["Host IP", "Follow-up", "Events", "Infections / categories", "Reports", "Network"],
                      [[r.get("ip"), "; ".join(r.get("followup") or []) or "Monitor", f"{r.get('events', 0):,}",
                        ", ".join(r.get("infections") or []), ", ".join(r.get("reports") or []), r.get("network")] for r in top],
                      [0.12, 0.2, 0.07, 0.23, 0.23, 0.15])
    if enr:
        f = sum(1 for x in enr.values() if x.get("found") and x.get("kind") != "actor")
        a = sum(1 for x in enr.values() if x.get("kind") == "actor")
        c = sum(1 for x in enr.values() if x.get("curated"))
        pts.append(f"Of the {len(enr)} infections / categories explained in this report, {f} are malware families in Malpedia"
                   + (f", {a} {'is a threat actor' if a == 1 else 'are threat actors'}" if a else "")
                   + (f", {c} {'has' if c == 1 else 'have'} a Looking Glass definition" if c else "")
                   + (f" and {len(enr) - f - a - c} {'is' if len(enr) - f - a - c == 1 else 'are'} not malware or not listed (explained from the report evidence)"
                      if len(enr) - f - a - c else "") + ".")
    peak = I.get("peak_hour")
    kpis = [(f"{I.get('total', 0):,}", "events in this selection"), (f"{I.get('share', 0):.1%}", f"of the day's {I.get('all_total', 0):,} events"),
            (f"{I.get('hosts', 0):,}", "source hosts"), (f"{I.get('reports', 0):,}", "reports"),
            (f"{I.get('cross_report_hosts', 0):,}", "hosts in several reports"), (f"{I.get('multi_infected', 0):,}", "hosts with several infections"),
            (f"{I.get('regular_beacons', 0):,}", "hosts beaconing regularly"), (I.get("beacon_median_label") or "", "typical repeat interval"),
            (f"{I.get('c2_hosts', 0):,}", "C2 / sinkhole domains"), (f"{I.get('dst_ips', 0):,}", "destination IPs"),
            (f"{peak:02d}:00 UTC" if peak is not None else "", "peak hour"), (f"{len(rows):,}", f"entries in this list")]
    B = I.get("breakdowns") or {}
    for r in B.get("src_city") or []:
        r["label"] = str(r.get("label") or "").title()
    titles = [("source", "Reports"), ("attack_class", "Attack types"), ("infection", "Infections / categories"), ("severity", "Severity"),
              ("src_city", "Cities"), ("src_asn", "Source networks"), ("http_host", "C2 / sinkhole domains"), ("dst_geo", "Destination countries"),
              ("dst_asn", "Destination networks"), ("dst_ip", "Destination IPs"), ("dst_port", "Destination ports"), ("tag", "Tags"),
              ("request", "Requested paths"), ("http_agent", "User agents")]
    total = I.get("total", 0)
    bds = [(lbl, [lbl, "Events", "Share"], _bd_rows(B[k], total)) for k, lbl in titles if B.get(k)]
    charts = [(lbl, B[k]) for k, lbl in (("source", "Reports"), ("infection", "Infections / categories"), ("src_asn", "Source networks"),
                                          ("src_city", "Cities"), ("attack_class", "Attack types"), ("dst_geo", "Destination countries")) if B.get(k)]
    gl = []
    labels = {x["name"]: x["label"] for x in registry.get()}
    for r in B.get("source") or ([{"value": I["value"]}] if I.get("kind") == "source" else []):
        d = _report_def(r["value"])
        item = (d.get("title") or labels.get(r["value"], r["value"]), " ".join(v for v in (d.get("def"), d.get("why")) if v), d.get("url"))
        if item[0] not in {x[0] for x in gl}:
            gl.append(item)
    cols, prow = _pdf_rows(D.get("columns") or [], rows, enr)
    sel = _pdf_label() or f"{I.get('kind_label', '')}: {I.get('value_label') or I.get('value', '')}"
    base = _file_base([(I.get("as_of") or "")[:10], sel, D.get("metric")])
    spec = {"platform_label": "Network communications", "csv_name": f"{base}.csv", "title": D.get("title"), "selection": sel, "day": (I.get("as_of") or "")[:10],
            "generated_by": (getattr(g, "user", None) or {}).get("user", ""), "scope": _scope_text(), "demo": is_demo(),
            "intro": D.get("intro"), "summary_points": pts, "kpis": kpis, "hours": I.get("hours"), "peak_hour": peak,
            "priorities": priorities, "enrichment": enr, "enrichment_stats": stats, "enrichment_note": note,
            "columns": cols, "rows": prow, "total": D.get("total", len(rows)), "breakdowns": bds, "charts": charts,
            "glossary": gl, "sources": SOURCES_TEXT}
    pdf = reports_pdf.build(spec)
    AUTH["audit"].add("report_pdf", user=(getattr(g, "user", None) or {}).get("user", ""), target=f"comms:{D.get('metric')}",
                      detail=f"{sel[:80]} · {len(rows)} rows")
    return _report_response(pdf, base, cols, prow)


@app.route("/api/svc/report.pdf")
@app.route("/api/svc/report")
def api_svc_report_pdf():
    """PDF of one analysis figure on the publicly accessible / vulnerable services platform."""
    if not AUTH["has_perm"]("export"):
        return jsonify(error="Your role cannot download reports (permission 'export')."), 403
    if request.args.get("all") != "1":
        return jsonify(error="all=1 expected"), 400
    I, err = _view_json("svc_insight")
    if err:
        return err
    D, err = _view_json("svc_drill")
    if err:
        return err
    import reports_pdf
    rows = D.get("rows") or []
    pts = list(I.get("findings") or [])
    priorities = None
    if D.get("row_kind") == "ip" and rows:
        top = [r for r in rows if len(r.get("issues") or []) > 1 or "critical" in (r.get("followup") or [])][:15] or rows[:10]
        priorities = (["Host IP", "Follow-up", "Issues", "Reports / services", "Records", "Network", "Device / product"],
                      [[r.get("ip"), "; ".join(r.get("followup") or []) or "Monitor", ", ".join(r.get("issues") or []),
                        ", ".join(r.get("services") or []), f"{r.get('events', 0):,}", r.get("network"), r.get("device")] for r in top],
                      [0.11, 0.13, 0.22, 0.22, 0.06, 0.13, 0.13])
    hours = None
    hb = I.get("hours_by_family") or {}
    if hb:
        hours = [sum(v[i] for v in hb.values()) for i in range(24)]
    peak = I.get("peak_hour")
    kpis = [(f"{I.get('total', 0):,}", "records in this selection"), (f"{I.get('share', 0):.1%}", f"of the day's {I.get('day_total', 0):,} records"),
            (f"{I.get('hosts', 0):,}", "hosts"), (f"{I.get('vulnerable_hosts', 0):,}", "hosts with a concrete issue"),
            (f"{I.get('multi_issue_hosts', 0):,}", "hosts with several issues"), (f"{I.get('cross_report_hosts', 0):,}", "hosts in several reports"),
            (f"{I.get('critical', 0):,}", "critical records"), (f"{I.get('high', 0):,}", "high-severity records"),
            (f"{I.get('services', 0):,}", "services (reports)"), (f"{I.get('networks', 0):,}", "networks"),
            (f"{I.get('issues', 0):,}", "different issues"), (f"{I.get('regions', 0):,}", "regions")]
    B = I.get("breakdowns") or {}
    total = I.get("total", 0)
    titles = [("service", "Services (reports)"), ("family", "Report families"), ("issue", "Issues"), ("severity", "Severity"),
              ("network", "Networks"), ("region", "Regions"), ("city", "Cities"), ("port", "Ports"), ("tag", "Tags"),
              ("vendor", "Vendors"), ("product", "Products"), ("device_type", "Device types"), ("sector", "Sectors")]
    bds = [(lbl, [lbl, "Records", "Hosts", "Share"], _bd_rows(B[k], total, hosts=True)) for k, lbl in titles if B.get(k)]
    charts = [(lbl, B[k]) for k, lbl in (("service", "Services (reports)"), ("issue", "Issues"), ("network", "Networks"),
                                          ("region", "Regions"), ("port", "Ports"), ("vendor", "Vendors")) if B.get(k)]
    G, _ = _view_json("svc_glossary")
    gl = []
    names = {str(r.get("value")) for r in B.get("service") or []} | {str(r.get("label")) for r in B.get("service") or []}
    for x in (G or {}).get("reports", []):
        if x["name"] in names or x["label"] in names:
            if (x.get("title") or x["label"]) not in {y[0] for y in gl}:
                gl.append((x.get("title") or x["label"], " ".join(v for v in (x.get("def"), x.get("why")) if v), x.get("url")))
    # the issues explained: CVEs (NVD, CISA KEV, EPSS) and the others (definitions; never looked up)
    enr, stats, note = {}, {}, ""
    if AUTH["has_perm"]("malpedia"):
        counts = {}
        for r in B.get("issue") or []:
            counts[r["value"]] = (r.get("count", 0), r.get("hosts", 0))
        listed = Counter(i for r in rows for i in ([r.get("name")] if D.get("row_kind") == "issue" else (r.get("issues") or [])) if i)
        order = sorted(set(counts) | set(listed), key=lambda i: (-counts.get(i, (0, 0))[1], -listed.get(i, 0)))[:80]
        enr = issues_resolve(order, budget=20)
        for i in order:
            c = counts.get(i)
            stats[i] = f"{c[0]:,} records on {c[1]:,} hosts" if c else f"on {listed.get(i, 0):,} listed entr{'y' if listed.get(i, 0) == 1 else 'ies'}"
        kev = [i for i, x in enr.items() if x.get("exploited")]
        if kev:
            pts.insert(0, f"{len(kev)} of the issues in this selection {'is a vulnerability' if len(kev) == 1 else 'are vulnerabilities'} "
                          f"that CISA confirms {'is' if len(kev) == 1 else 'are'} being actively exploited (Known Exploited Vulnerabilities "
                          f"catalog): {', '.join(kev[:8])}{'…' if len(kev) > 8 else ''}. Hosts with these should be patched first.")
        crit = [i for i, x in enr.items() if (x.get("cvss") or {}).get("score") and x["cvss"]["score"] >= 9]
        if crit:
            pts.append(f"{len(crit)} CVE{'s' if len(crit) != 1 else ''} in this selection {'is' if len(crit) == 1 else 'are'} rated critical (CVSS 9 or more).")
        note = ("Issues that are CVEs were looked up in the NIST National Vulnerability Database (description, CVSS score), "
                "CISA's Known Exploited Vulnerabilities catalog (confirmed active exploitation, required action) and FIRST EPSS "
                "(probability of exploitation in the next 30 days). Other issues are not looked up anywhere: they are explained "
                "from the definitions written by the security researchers of the organisation that uses this platform and the "
                "Looking Glass knowledge base, with their references.")
    cols, prow = _pdf_rows(D.get("columns") or [], rows, enr, issues=True, row_name=D.get("row_kind") == "issue")
    sel = _pdf_label() or "Selection"
    base = _file_base([I.get("day"), sel, D.get("metric")])
    spec = {"platform_label": "Publicly accessible / vulnerable services", "title": D.get("title"), "selection": sel,
            "csv_name": f"{base}.csv", "enrichment": enr, "enrichment_stats": stats, "enrichment_note": note,
            "enrichment_title": "Issues explained",
            "day": I.get("day"), "generated_by": (getattr(g, "user", None) or {}).get("user", ""), "scope": _scope_text(),
            "demo": is_demo(), "intro": D.get("intro"), "summary_points": pts, "kpis": kpis, "hours": hours, "peak_hour": peak,
            "priorities": priorities, "columns": cols, "rows": prow, "total": D.get("total", len(rows)), "breakdowns": bds,
            "charts": charts, "glossary": gl[:40], "sources": [SOURCES_TEXT[0], SOURCES_TEXT[2], SOURCES_TEXT[3], SOURCES_TEXT[4]]}
    pdf = reports_pdf.build(spec)
    AUTH["audit"].add("report_pdf", user=(getattr(g, "user", None) or {}).get("user", ""), target=f"services:{D.get('metric')}",
                      detail=f"{sel[:80]} · {len(rows)} rows")
    return _report_response(pdf, base, cols, prow)


@app.route("/api/insight")
def api_insight():
    """Analytics for one entity (city, infection, C2 host, country, host, ASN) over the whole replay day."""
    kind = request.args.get("kind", "")
    value = request.args.get("value", "")
    if kind not in INSIGHT_KINDS:
        return jsonify(error="unknown kind"), 400
    rn = parse_iso(request.args.get("at"), replay_now())
    demo = is_demo()
    day, sofar, ev = _select_slice(kind, value, rn)
    n = len(ev)
    mip = mask_ip if demo else (lambda s: s)

    # per-host timing -> beaconing analysis
    by_host = {}
    for e in ev:
        if e["src_ip"]:
            by_host.setdefault(e["src_ip"], []).append(e["_t"])
    intervals, regular = [], 0
    multi = 0
    for ip, ts in by_host.items():
        if len(ts) >= 3:
            d = [b - a for a, b in zip(ts, ts[1:]) if b > a]
            if len(d) >= 2:
                m = _median(d)
                intervals.append(m)
                mean = sum(d) / len(d)
                sd = (sum((x - mean) ** 2 for x in d) / len(d)) ** 0.5
                if mean and sd / mean < 0.5:
                    regular += 1
    host_infections = {}
    for e in ev:
        if e["src_ip"]:
            host_infections.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")
    # co-infection: hosts in this slice that show >1 infection anywhere today
    all_inf = {}
    for e in sofar:
        if e["src_ip"] in by_host:
            all_inf.setdefault(e["src_ip"], set()).add(e["infection"] or "unknown")
    multi = sum(1 for s in all_inf.values() if len(s) > 1)

    hours = [0] * 24
    for e in ev:
        hours[int((e["_t"] - day.start.timestamp()) // 3600) % 24] += 1
    peak_hour = max(range(24), key=lambda h: hours[h]) if n else None

    # --- extra chart data for the analysis view
    t0 = day.start.timestamp()
    cur_hour = max(0, min(23, int((rn.timestamp() - t0) // 3600)))   # replay position marker only
    hours_by_class = {}
    timeline = [0] * 96
    for e in ev:
        hours_by_class.setdefault(e["attack_class"], [0] * 24)[int((e["_t"] - t0) // 3600) % 24] += 1
        timeline[min(95, int((e["_t"] - t0) // 900))] += 1
    severity = [{"value": v or "unrated", "count": k} for v, k in Counter(e["severity"] for e in ev).most_common()]

    hosts_sorted = sorted(by_host.items(), key=lambda kv: -len(kv[1]))
    top_hosts = []
    for ip, ts in hosts_sorted[:10]:
        sample = next(e for e in ev if e["src_ip"] == ip)
        top_hosts.append({
            "ip": mip(ip), "ref": sample["src_ref"], "count": len(ts), "city": sample["src_city"],
            "asn": asn_registry.label(sample["src_asn"], demo),
            "infections": sorted(host_infections.get(ip, [])),
            "first": iso(datetime.fromtimestamp(ts[0], timezone.utc)), "last": iso(datetime.fromtimestamp(ts[-1], timezone.utc)),
        })
    top10_share = sum(len(ts) for _, ts in hosts_sorted[:10]) / n if n else 0
    company = lambda a: asn_registry.company(a, demo)

    labels = {s["name"]: s["label"] for s in registry.get()}
    mt = mask_text if demo else (lambda s: s)
    breakdowns = {
        "source": _top(ev, "source", 12, label=lambda v: labels.get(v, v)),
        "attack_class": _top(ev, "attack_class"),
        "infection": _top(ev, "infection"),
        "src_city": _top(ev, "src_city"),
        "src_asn": _top(ev, "src_asn", key=company),          # grouped by company (or alias)
        # grouped by the real value, shown masked in demo mode (the value becomes an opaque reference below)
        "http_host": _top(ev, "http_host", label=mt),
        "dst_ip": _top(ev, "dst_ip", label=mip),
        "dst_geo": _top(ev, "dst_geo"),
        "dst_asn": _top(ev, "dst_asn", key=company),
        "dst_port": _top(ev, "dst_port"),
        "http_agent": _top(ev, "http_agent", 5, label=mt),
        "severity": _top(ev, "severity"),
        "tag": _top(ev, "tag", 6),
    }
    paths = Counter(_request_path(e["http_url"]) for e in ev if e["http_url"])
    breakdowns["request"] = [{"value": v, "label": mt(v), "count": k, "share": round(k / (sum(paths.values()) or 1), 4)} for v, k in paths.most_common(6)]
    if demo:
        for key in REF_KINDS:
            for r in breakdowns.get(key, []):
                r["value"] = host_refs.ref(r["value"])
    for r in breakdowns["dst_port"]:
        r["value"] = str(r["value"])
    breakdowns = {k: v for k, v in breakdowns.items() if v and not (k == kind)}

    # cross-report correlation: the same hosts seen in other collections today
    slice_hosts = set(by_host)
    host_sources = {}
    for e in sofar:
        if e["src_ip"] in slice_hosts:
            host_sources.setdefault(e["src_ip"], set()).add(e["source"])
    cross_hosts = [ip for ip, s in host_sources.items() if len(s) > 1]
    other_src = Counter(s for ip in cross_hosts for s in host_sources[ip] if not (kind == "source" and s == value))
    n_reports = len({e["source"] for e in sofar})

    # plain-language findings
    insights = []
    if n:
        day_txt = rn.strftime("%Y-%m-%d")
        share = n / max(1, len(sofar))
        share_txt = "less than 0.1%" if 0 < share < 0.001 else f"{share:.1%}"
        insights.append(f"Shadowserver reported {n:,} event{'' if n == 1 else 's'} for {day_txt}. "
                        f"That is {share_txt} of all {len(sofar):,} events across {n_reports} reports.")
        src_b = breakdowns.get("source")
        if src_b and kind != "source":
            parts = ", ".join(f"{r['label']} {r['share']:.0%}" for r in src_b[:4])
            insights.append(f"Found in {len(src_b)} report{'s' if len(src_b) > 1 else ''}: {parts}.")
        insights.append(f"{len(by_host):,} different source hosts were involved. The 10 most active hosts account for {top10_share:.0%} of these events.")
        if cross_hosts and kind != "src_ip":
            top_other = ", ".join(f"{labels.get(s, s)} ({k:,})" for s, k in other_src.most_common(3))
            cls = {s["name"]: s["class"] for s in registry.get()}
            mixed = sum(1 for ip in cross_hosts if len({cls.get(s) for s in host_sources[ip]}) > 1)
            msg = f"{len(cross_hosts):,} of these hosts also appear in other reports on the same day, most often in {top_other}."
            if mixed:
                msg += (f" {mixed:,} of them {'shows' if mixed == 1 else 'show'} more than one kind of activity"
                        " (for example botnet C2 traffic and attacks), which strongly suggests a compromised device.")
            else:
                msg += " They contact several sinkholes, which suggests several infections or command channels on the same device."
            insights.append(msg)
        if kind == "src_ip" and len(host_sources.get(value, ())) > 1:
            insights.append(f"This host appears in {len(host_sources[value])} different reports on the same day.")
        if intervals:
            insights.append(f"Hosts seen more than once typically repeat every {_fmt_dur(_median(intervals))} (median). "
                            f"{regular:,} of these {len(intervals):,} hosts repeat at a regular rhythm, which points to automated beaconing or scripted attacks.")
        if multi:
            insights.append(f"{multi:,} of these hosts show more than one infection / category on the same day, which suggests several infections on one device or proxy software bundled with malware.")
        if peak_hour is not None:
            insights.append(f"Activity peaked between {peak_hour:02d}:00 and {(peak_hour + 1) % 24:02d}:00 UTC, with {hours[peak_hour]:,} events.")
        for key, what in (("source", "report"), ("infection", "infection / category"), ("src_asn", "source network"), ("http_host", "C2 domain"), ("src_city", "affected city")):
            b = breakdowns.get(key)
            if b and b[0]["share"] >= 0.5 and len(b) > 1:
                lbl = b[0]["label"].title() if key == "src_city" else b[0]["label"]
                insights.append(f"By {what}, {lbl} accounts for most of these events ({b[0]['share']:.0%}).")
        hosts_n = len({e["http_host"] for e in ev if e["http_host"]})
        if kind != "http_host" and hosts_n > 1:
            insights.append(f"{hosts_n:,} different C2 / sinkhole domains were contacted.")

    return jsonify(
        kind=kind, kind_label=INSIGHT_KINDS[kind], value=value, as_of=iso(rn),
        total=n, share=round(n / max(1, len(sofar)), 4), all_total=len(sofar),
        hosts=len(by_host), asns=len({e["src_asn"] for e in ev}), c2_hosts=len({e["http_host"] for e in ev if e["http_host"]}),
        dst_ips=len({e["dst_ip"] for e in ev}),
        first=ev[0]["extracted_date"] if ev else None, last=ev[-1]["extracted_date"] if ev else None,
        beacon_median=_median(intervals), beacon_median_label=_fmt_dur(_median(intervals)), regular_beacons=regular,
        multi_infected=multi, hours=hours, peak_hour=peak_hour,
        hours_by_class=hours_by_class, current_hour=cur_hour, timeline=timeline, severity=severity,        insights=insights, breakdowns=breakdowns, top_hosts=top_hosts,
        cross_report_hosts=len(cross_hosts), reports=len({e["source"] for e in ev}),
        value_label=_value_label(kind, value, demo, labels),
        scope=dict(zip(("kind", "value"), _parse_time_value(value)[2:])) if kind == "time" else None,
        scope_label=(lambda s: _value_label(s[2], s[3], demo, labels) if s[2] else None)(_parse_time_value(value)) if kind == "time" else None,
        asns_covered=[] if demo or kind not in ("src_asn", "dst_asn") else sorted(asn_registry.resolve(value)),
    )


def _value_label(kind, value, demo, labels):
    """Human (and, in demo mode, concealed) title for the entity being analysed."""
    if kind == "time":
        start, dur, sk, sv = _parse_time_value(value)
        return f"{_hm(start)} to {_hm(start + dur)} UTC"   # the browser adds the selection it belongs to
    if kind == "source":
        return labels.get(value, value)
    if kind in ("src_asn", "dst_asn"):
        asns = sorted(asn_registry.resolve(value))
        if demo:
            return asn_registry.alias(asns[0]) if asns else value
        name = asn_registry.name(asns[0]) if asns else None
        return f"{name} ({', '.join('AS' + a for a in asns)})" if name else f"AS{value}"
    if kind == "src_ip":
        ip = host_refs.resolve(value)
        return mask_ip(ip) if demo else ip
    if kind in REF_KINDS:
        value = host_refs.resolve(value)
    if kind == "dst_ip":
        return mask_ip(value) if demo else value
    if kind in ("http_host", "http_agent", "request"):
        return mask_text(value) if demo else value
    if kind == "dst_port":
        return f"Port {value}"
    return None   # route / dst_place: the browser writes them with full country names


# ---------------------------------------------------------------- infection knowledge base
KB_PATH = os.path.join(BASE_DIR, "data", "infections.json")
_kb = {"mtime": None, "data": {}}


# The definitions this site's researchers and admins write (Settings / Definitions page) are kept apart from the
# shipped knowledge base, so an upgrade (which replaces data/infections.json) never loses them.
LOCAL_DEFS_PATH = os.path.join(BASE_DIR, "data", "definitions.json")


def knowledge_base():
    """data/infections.json (shipped) with data/definitions.json (this site's own definitions) on top; re-read
    automatically when either file changes."""
    import json
    try:
        m = (os.path.getmtime(KB_PATH), os.path.getmtime(LOCAL_DEFS_PATH) if os.path.exists(LOCAL_DEFS_PATH) else 0)
        if m != _kb["mtime"]:
            with open(KB_PATH, encoding="utf-8") as f:
                data = {k.lower(): v for k, v in json.load(f).get("infections", {}).items()}
            try:
                with open(LOCAL_DEFS_PATH, encoding="utf-8") as f:
                    for k, v in (json.load(f).get("infections") or {}).items():
                        data[k.lower()] = dict(data.get(k.lower(), {}), **v)
            except FileNotFoundError:
                pass
            except ValueError as exc:
                app.logger.warning("Local definitions (data/definitions.json) not loaded: %s", exc)
            _kb["data"], _kb["mtime"] = data, m
    except (OSError, ValueError) as exc:
        app.logger.warning("Infection knowledge base not loaded: %s", exc)
    return _kb["data"]


ISSUES_PATH = os.path.join(BASE_DIR, "data", "issues.json")
_ikb = {"mtime": None, "data": {}}


def issues_kb():
    """data/issues.json (shipped) with the 'issues' of data/definitions.json on top. Keys are lower-case; each entry
    keeps its display name in 'name'."""
    import json
    try:
        m = (os.path.getmtime(ISSUES_PATH) if os.path.exists(ISSUES_PATH) else 0,
             os.path.getmtime(LOCAL_DEFS_PATH) if os.path.exists(LOCAL_DEFS_PATH) else 0)
        if m != _ikb["mtime"]:
            data = {}
            for path in (ISSUES_PATH, LOCAL_DEFS_PATH):
                try:
                    with open(path, encoding="utf-8") as f:
                        for k, v in (json.load(f).get("issues") or {}).items():
                            data[k.lower()] = dict(data.get(k.lower(), {}), **v, name=v.get("name") or k)
                except FileNotFoundError:
                    pass
            _ikb["data"], _ikb["mtime"] = data, m
    except (OSError, ValueError) as exc:
        app.logger.warning("Issue definitions not loaded: %s", exc)
    return _ikb["data"]


def issue_resolve(name, fetch=True):
    """What an issue is: a CVE (NVD, CISA KEV, EPSS; plus the researchers' notes), or the definition of a non-CVE
    issue (never looked up anywhere: its definition and references are used)."""
    cur = issues_kb().get((name or "").strip().lower())
    if cves.is_cve(name):
        c = cve_intel.card(name, fetch=fetch)
        if cur and (cur.get("references") or cur.get("description")):
            c["curated_references"], c["note"] = cur.get("references", []), cur.get("description", "")
            c["note_by"], c["note_updated"] = _by(cur), cur.get("updated", "")
        return c
    if cur:
        return {"found": False, "curated": True, "kind": "issue", "title": cur.get("title") or name, "type": cur.get("type", ""),
                "description": cur.get("description", ""), "references": cur.get("references", []),
                "updated": cur.get("updated", ""), "by": _by(cur)}
    return {"found": False, "offline": True, "kind": "issue", "title": "No definition yet",
            "text": f'"{name}" has no definition yet. A security researcher of your organisation can add one, with '
                    "references, on the Definitions page."}


def issues_resolve(names, budget=15.0, progress=None):
    """Several issues: CVEs as one batch (CISA KEV, EPSS per 100, CVE.org four at a time; NVD's analysis from the
    background check), then the others (definitions, never looked up)."""
    names = [n for n in dict.fromkeys(str(x).strip() for x in names) if n]
    out = {}
    ids = [n for n in names if cves.is_cve(n)]
    if ids:
        # budget: no more fetching once spent (external review, 2026-11-12: it was ignored); a progress window (the
        # look-up the user started and watches) has no limit
        cards = cve_intel.lookup_many(ids, progress=progress, budget=None if progress else budget)
        for n in ids:
            out[n] = issue_resolve(n, fetch=False) if cards.get(n.upper()) is None else cards[n.upper()]
            cur = issues_kb().get(n.lower())
            if cur and (cur.get("references") or cur.get("description")):
                out[n].update(curated_references=cur.get("references", []), note=cur.get("description", ""),
                              note_by=_by(cur), note_updated=cur.get("updated", ""))
    others = [n for n in names if n not in out]
    if others and progress:
        progress("step", f"{len(others)} other issue{'s' if len(others) != 1 else ''} (not CVEs): explained from their definitions, never looked up")
    for n in others:
        out[n] = issue_resolve(n, fetch=False)
        if progress:
            progress("item", f"{n}: {'definition by ' + (out[n].get('by') or 'Looking Glass') if out[n].get('curated') else 'no definition yet'}")
    return out


@app.route("/api/issues/batch")
def api_issues_batch():
    """Explain the issues of a services list: CVEs from NVD / CISA KEV / EPSS, other issues from their definitions."""
    if not AUTH["has_perm"]("malpedia"):
        return jsonify(error="Your role cannot use look-ups (permission 'malpedia')."), 403
    names = [v.strip() for v in (request.args.get("values") or "").split(",") if v.strip() and len(v.strip()) <= 80]
    names = list(dict.fromkeys(names))
    if len(names) > 120:
        return jsonify(error="At most 120 issues at a time."), 400
    try:
        res = issues_resolve(names)
    except ValueError as exc:
        return jsonify(error=security.public_error(exc)), 400
    return jsonify(results=res, pending=sum(1 for x in res.values() if x.get("pending")), cve=cve_intel.status())


_SVC_ISSUES = {"at": 0.0, "data": {}}


def _svc_issue_stats():
    """issue -> {records, hosts} over the services days in memory (refreshed at most every minute)."""
    if time.time() - _SVC_ISSUES["at"] < 60 and _SVC_ISSUES["data"]:
        return _SVC_ISSUES["data"]
    st = {}
    for d in list(svc["store"].days.values()):
        for e in d.events:
            for i in e["issues"]:
                x = st.setdefault(i, {"records": 0, "hosts": set()})
                x["records"] += 1; x["hosts"].add(e["ip"])
    _SVC_ISSUES.update(at=time.time(), data=st)
    return st


def _cve_loop():
    """Every 30 minutes: look up the CVEs the services reports contain (at NVD's pace), one worker at a time."""
    import fcntl
    time.sleep(120)
    while True:
        try:
            with open(os.path.join(BASE_DIR, "data", ".cve_check.lock"), "w") as lf:
                try:
                    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    lf = None
                if lf:
                    ids = [i for i in _svc_issue_stats() if cves.is_cve(i)]
                    if ids:
                        cve_intel.prefetch(ids)
        except Exception as exc:                       # never let the background check stop the platform
            app.logger.warning("CVE background check: %s", exc)
        time.sleep(600)                                # NVD's analysis follows within minutes of new CVEs


# ------------------------------------------------------------------ look-up jobs (progress window on the page)
_JOBS, _JOBS_LOCK = {}, threading.Lock()


def _job_new(kind, total, user):
    import secrets as _secrets
    jid = _secrets.token_urlsafe(12)
    with _JOBS_LOCK:
        for k in [k for k, j in _JOBS.items() if time.time() - j["t0"] > 1800]:     # finished jobs are kept 30 minutes
            _JOBS.pop(k, None)
        _JOBS[jid] = {"id": jid, "kind": kind, "user": user, "t0": time.time(), "state": "running", "total": total,
                      "done": 0, "cached": 0, "failed": 0, "current": "", "log": [], "results": None, "error": ""}
    return _JOBS[jid]


def _job_log(job, text):
    job["log"].append(f"{time.strftime('%H:%M:%S', time.gmtime())}  {text}")
    del job["log"][:-400]


@app.route("/api/lookups", methods=["POST"])
def api_lookups_start():
    """Start a look-up of many names in the background: kind=issues (CVEs: CISA KEV, EPSS, CVE.org; others: definitions)
    or kind=malpedia (infections / categories). The page follows it with GET /api/lookups/<id>."""
    if not (AUTH["has_perm"]("malpedia") or AUTH["has_perm"]("definitions") or AUTH["has_perm"]("management")):
        return jsonify(error="Your role cannot use look-ups."), 403
    if not AUTH["csrf_ok"]():
        return jsonify(error="Refused (the request did not come from this page)."), 403
    b = request.get_json(silent=True) or {}
    kind = b.get("kind")
    values = list(dict.fromkeys(str(v).strip() for v in (b.get("values") or []) if str(v).strip() and len(str(v).strip()) <= 100))
    if kind not in ("issues", "malpedia") or not values:
        return jsonify(error="kind (issues or malpedia) and values expected"), 400
    if len(values) > 400:
        return jsonify(error="At most 400 names at a time."), 400
    user = (getattr(g, "user", None) or {}).get("user", "")
    with _JOBS_LOCK:
        if sum(1 for j in _JOBS.values() if j["user"] == user and j["state"] == "running") >= 2:
            return jsonify(error="You already have two look-ups running; wait for one to finish."), 429
    demo = is_demo()
    job = _job_new(kind, len(values), user)

    def say(kind_, text, done=None):
        if kind_ == "item":
            job["current"] = text
            if done is None:
                job["done"] += 1
            else:
                job["done"] = done
            if "failed" in text or "could not" in text or "answered" in text:
                job["failed"] += 1
        _job_log(job, text)

    def run_issues():
        ids = [v for v in values if cves.is_cve(v)]
        _job_log(job, f"{len(values)} issue{'s' if len(values) != 1 else ''}: {len(ids)} CVE{'s' if len(ids) != 1 else ''}, "
                      f"{len(values) - len(ids)} other{'s' if len(values) - len(ids) != 1 else ''}")
        job["results"] = issues_resolve(values, progress=say)
        job["done"] = job["total"]

    def run_malpedia():
        out = {}
        _job_log(job, f"{len(values)} name{'s' if len(values) != 1 else ''}; Malpedia " + ("is set up: answers are cached a week, "
                 f"at most {MAX_MP} new questions a minute" if malpedia.enabled else
                 "is not set up: the Looking Glass definitions and knowledge base answer"))
        for v in values:
            if demo and v.startswith("ref:"):
                job["done"] += 1
                continue
            job["current"] = v
            for attempt in range(8):
                try:
                    card = mp_resolve(v)[0]
                    break
                except ValueError as exc:
                    card = {"found": False, "reason": str(exc)}
                    break
                except RuntimeError as exc:
                    if "Too many" in str(exc) and attempt < 7:
                        _job_log(job, f"{v}: Malpedia's limit reached ({MAX_MP} questions a minute): waiting 15 s, then continuing")
                        time.sleep(15)
                        continue
                    card = {"found": False, "pending": True, "reason": f"Not checked yet: {security.public_error(exc, 'Malpedia did not answer')}."}
                    job["failed"] += 1
                    break
            out[v] = card
            job["done"] += 1
            what = ("Malpedia: " + card.get("name", "") + (" (threat actor)" if card.get("kind") == "actor" else f" ({card.get('family')})")) \
                if card.get("found") else ("definition: " + card.get("title", "")) if card.get("curated") else (card.get("title") or card.get("reason") or "not found")
            _job_log(job, f"{v}: {what}")
        job["results"] = out

    def run():
        try:
            (run_issues if kind == "issues" else run_malpedia)()
            job["state"] = "done"
            _job_log(job, f"Finished: {job['total']} looked up in {time.time() - job['t0']:.0f} s"
                          + (f", {job['failed']} could not be checked" if job["failed"] else ""))
        except Exception as exc:                      # the page shows it; the platform carries on
            app.logger.exception("look-up job %s failed", kind)   # full details in the server log only
            job["state"], job["error"] = "failed", security.public_error(exc)
            _job_log(job, f"Stopped: {job['error']}")
    threading.Thread(target=run, daemon=True, name=f"lookup-{kind}").start()
    return jsonify(id=job["id"], total=job["total"])


@app.route("/api/lookups/<jid>")
def api_lookups_status(jid):
    j = _JOBS.get(jid)
    if not j or j["user"] != (getattr(g, "user", None) or {}).get("user", ""):
        return jsonify(error="No such look-up (finished ones are kept 30 minutes)."), 404
    try:                                   # a bad value is the start of the log, not a server error (external review)
        since = max(0, int(request.args.get("since") or 0))
    except ValueError:
        since = 0
    out = {k: j[k] for k in ("id", "kind", "state", "total", "done", "failed", "current", "error")}
    out.update(elapsed=round(time.time() - j["t0"]), log=j["log"][since:], log_len=len(j["log"]))
    if j["state"] == "done":
        out["results"] = j["results"]
    return jsonify(out)


@app.route("/api/asns")
def api_asns():
    """The ASN registry (company names). Not available in demo mode."""
    if is_demo():
        return jsonify(error="not available in demo mode"), 403
    return jsonify(asn_registry.all())


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
from seen_index import SeenIndex  # noqa: E402
SEEN = SeenIndex(os.path.join(BASE_DIR, "data", "seen_names.json"), logger=app.logger)


def _name_evidence():
    """name -> {'classes': set, 'reports': set} over the days in memory (refreshed at most every minute)."""
    if time.time() - _EVIDENCE["at"] < 60 and _EVIDENCE["data"]:
        return _EVIDENCE["data"]
    labels = {x["name"]: x["label"] for x in registry.get()}
    ev = {}
    for d in list(store.days.values()):
        for e in d.events:
            x = ev.setdefault((e["infection"] or "").lower(), {"classes": set(), "reports": set()})
            x["classes"].add(e["attack_class"]); x["reports"].add(labels.get(e["source"], e["source"]))
        SEEN.update(d.start.date().isoformat(), d.events, labels)      # where and when, kept beyond this day (seen_index.py)
    SEEN.refresh()
    SEEN.backfill(store._load, day_start, utcnow, lambda: {x["name"]: x["label"] for x in registry.get()})
    _EVIDENCE.update(at=time.time(), data=ev)
    return ev


def _last_seen(name, now_reports):
    """For a name not in the replay day: [{report, date}] where it was last seen (newest first), from seen_index.py."""
    if now_reports:
        return []
    return [{"report": r, "date": d} for r, d in SEEN.last_seen(name)[:3]]


def malpedia_explain(name):
    """What a name that Malpedia does not list really is, why it is not there, and what to do; for non-specialists."""
    import re as _re
    n = (name or "").strip()
    low = n.lower()
    kb = knowledge_base().get(low, {})
    kind = (kb.get("type") or "")
    ev = _name_evidence().get(low, {"classes": set(), "reports": set()})
    classes, reports = ev["classes"], sorted(ev["reports"])
    seen = ", ".join(reports) if reports else ""
    acts = [c for c in classes if c in _ACTIVITY]
    if acts and len(acts) == len(classes):
        doing = " and ".join(_ACTIVITY[c] for c in sorted(acts))
        return {"verdict": "activity", "title": "Not malware: an activity",
                "text": (f'"{n}" is not the name of a malicious program. Shadowserver\'s decoy systems '
                         f'({seen or "honeypots"}) saw this device {doing}. Malpedia only describes malicious programs, '
                         "so it has no entry for an activity."),
                "advice": "The device is probably infected or being misused: check what software runs on it, update it, "
                          "and change its passwords.", "seen_in": reports}
    if _re.search(r"proxy|socks|residential", f"{low} {kind.lower()}") and "botnet" in kind.lower():
        return {"verdict": "proxy-botnet", "title": "Malware that turns devices into proxies",
                "text": (f'"{n}"{f" ({kb.get("title")})" if kb.get("title") else ""} is malware that secretly turns the '
                         "infected device into a proxy, so criminals can send their traffic through it and hide behind "
                         f"the owner's address. Shadowserver saw the device contacting its servers ({seen or 'sinkhole'}). "
                         "Malpedia has no entry under exactly this name."),
                "advice": "Treat the device as infected: reset or reinstall it, update it, and change its passwords.",
                "seen_in": reports}
    if _re.search(r"proxy|socks|residential", f"{low} {kind.lower()}"):
        return {"verdict": "proxy", "title": "A proxy network, not a single malware program",
                "text": (f'"{n}"{f" ({kb.get("title")})" if kb.get("title") else ""} is a network that sends other people\'s '
                         "internet traffic through devices like this one, often through an app or software kit bundled with "
                         f"free apps. Shadowserver saw the device contacting this network's servers ({seen or 'sinkhole'}). "
                         "Malpedia describes malware families; proxy networks are services (often abused) and are usually "
                         "not listed there."),
                "advice": "Find and remove the app that added the device to the proxy network: strangers may be using "
                          "the owner's internet connection.", "seen_in": reports}
    if _re.search(r"adware|hijack|miner|unwanted|riskware", kind.lower()):
        return {"verdict": "unwanted", "title": "Unwanted software, rather than a malware family",
                "text": (f'"{n}"{f" ({kind})" if kind else ""} is unwanted software: it shows advertising, changes browser '
                         "settings or uses the computer to mine cryptocurrency, usually after being installed together with "
                         "something else. Malpedia concentrates on malware used in attacks, so it may not list it."),
                "advice": "Uninstall the unwanted program and check the browser's extensions and settings.",
                "seen_in": reports}
    if _re.search(r"abandon|misconfig", kind.lower()) or low in ("popcorntime", "non-authoritative-whois", "cryptodns-resolver"):
        first = (kb.get("description") or "").split(". ")[0].rstrip(".")
        return {"verdict": "software", "title": "Old or misconfigured software, not a malware family",
                "text": ((first + ". ") if first else "") + ("Its old servers are now run by Shadowserver (a 'sinkhole'), "
                         "so devices that still use it are reported, but it is not a malicious program in itself, so "
                         "Malpedia does not list it."),
                "advice": "Remove or update the software on the device.", "seen_in": reports}
    if _re.search(r"generic|unknown|unclassified|^event\d?_|^wd$", low) or kind.lower() in ("unclassified", "malware (unidentified)"):
        return {"verdict": "generic", "title": "A general label, not a specific malware",
                "text": ("Shadowserver's sinkhole saw this device connect to a server once used by malware, but could not "
                         f'tell which malware it was, so it used the general label "{n}". Malpedia lists specific malware '
                         "families, so there is nothing to match."),
                "advice": "Treat the device as possibly infected: run a security scan on it.", "seen_in": reports}
    what = f" ({kind})" if kind else ""
    return {"verdict": "unlisted", "title": "Probably malware, but not in Malpedia under this name",
            "text": (f'"{n}" looks like malware{what}, but Malpedia has no entry under this name: it may be new, '
                     "seen mostly in one region, or called something else there."
                     + (f" Looking Glass describes it as: {kb.get('title')}." if kb.get("title") else "")),
            "advice": "Treat the device as infected: run a security scan, and read the Looking Glass description of "
                      "this name.", "seen_in": reports}


_MISSES_PATH = os.path.join(BASE_DIR, "data", "malpedia_names.json")
_MISSES_LOCK = threading.Lock()


def _read_names():
    import json as _json
    try:
        with open(_MISSES_PATH, encoding="utf-8") as f:
            return _json.load(f)
    except (OSError, ValueError):
        return {}


def _write_names(m):
    import json as _json
    tmp = f"{_MISSES_PATH}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(m, f, indent=1)
    os.replace(tmp, _MISSES_PATH)


def _record_check(name, family, asked=True):
    """Remember that a name was checked against Malpedia and what came back ("" = nothing). Names with nothing that
    no administrator has defined yet are the to-do list in Settings."""
    now = utcnow().isoformat(timespec="seconds")
    with _MISSES_LOCK:
        m = _read_names()
        x = m.setdefault(name.lower(), {"first": now, "count": 0})
        x["family"], x["checked"] = family or "", now
        if asked:
            x["count"] = x.get("count", 0) + 1; x["last"] = now
        _write_names(m)


def _unchecked_names():
    """Infections / categories in the loaded reports that nobody has checked against Malpedia yet (new reports
    bring new names; they appear here by themselves)."""
    seen, ev = _read_names(), _name_evidence()
    return sorted(n for n, x in ev.items() if n and n not in seen and not _curated(n)
                  and not (x["classes"] and x["classes"] <= set(_ACTIVITY)))


_AUTOCHECK = {"running": False, "done": 0, "left": 0, "error": "", "at": ""}


def _autocheck(limit=None):
    """Check the new names against Malpedia in the background, slowly (at most 20 a minute, so users' own lookups
    still fit in the 30-a-minute limit). One worker process at a time (a lock file)."""
    import fcntl
    if _AUTOCHECK["running"] or not malpedia.enabled:
        return False
    lockf = open(os.path.join(BASE_DIR, "data", ".malpedia_check.lock"), "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lockf.close()
        return False
    names = _unchecked_names()[: limit or None]
    _AUTOCHECK.update(running=True, done=0, left=len(names), error="", at=utcnow().isoformat(timespec="seconds"))

    def run():
        try:
            for n in names:
                try:
                    lr = malpedia.lookup("infection", n)
                    _record_check(n, (lr.get("family") or {}).get("id") or (f"actor:{lr['actor']['id']}" if lr.get("actor") else ""), asked=False)
                except ValueError:
                    _record_check(n, "", asked=False)
                except RuntimeError as exc:          # rate limit / unreachable: wait and carry on later
                    _AUTOCHECK["error"] = str(exc)
                    time.sleep(60)
                    continue
                _AUTOCHECK["done"] += 1; _AUTOCHECK["left"] -= 1
                time.sleep(3)
        finally:
            _AUTOCHECK["running"] = False
            fcntl.flock(lockf, fcntl.LOCK_UN); lockf.close()
    threading.Thread(target=run, daemon=True, name="malpedia-autocheck").start()
    return True


def _autocheck_loop():
    """Every 30 minutes (the report schedule), check names that new reports brought in."""
    time.sleep(90)
    while True:
        try:
            if malpedia.enabled and _unchecked_names():
                _autocheck(limit=200)
        except Exception as exc:                       # never let the background check stop the platform
            app.logger.warning("Malpedia background check: %s", exc)
        time.sleep(1800)


def _curated(name):
    """The administrator's definition of a name (data/infections.json), when it carries references or a Malpedia id."""
    e = knowledge_base().get((name or "").lower()) or {}
    return e if (e.get("references") or e.get("malpedia")) else None


def mp_resolve(name):
    """Look a name up the way users see it: the administrator's Malpedia family if set, else Malpedia's best match;
    if none, the administrator's own definition with its references; if none, the plain explanation (and the name is
    added to the administrator's to-do list)."""
    cur = _curated(name)
    if not malpedia.enabled:                         # no Malpedia token: the researchers' definitions, then the knowledge base
        e = cur or knowledge_base().get((name or "").lower()) or {}
        if e.get("description") or e.get("title"):
            return {"found": False, "curated": True, "offline": True, "title": e.get("title") or name, "type": e.get("type", ""),
                    "description": e.get("description", ""), "references": e.get("references", []),
                    "updated": e.get("updated", ""), "by": _by(e) or ("Looking Glass" if not cur else ""),
                    "malpedia_id": e.get("malpedia", ""), "seen_in": malpedia_explain(name)["seen_in"]}, {}
        x = malpedia_explain(name)
        return {"found": False, "offline": True, **x, "reason": f"{x['title']}. {x['text']}"}, {}
    ov = (cur or {}).get("malpedia") or ""
    r = (malpedia.lookup("actor", ov[6:]) if ov.startswith("actor:") else malpedia.lookup("family", ov)) if ov \
        else malpedia.lookup("infection", name)
    card = _mp_card(r)
    _record_check(name, (card.get("family") or f"actor:{card.get('actor')}") if card else "")
    if card:
        if cur and cur.get("malpedia"):
            card["matched_by"] = "the administrator's definition"
        if cur and cur.get("references"):
            card["curated_references"] = cur["references"]
        return card, r
    if cur:
        return {"found": False, "curated": True, "title": cur.get("title") or name, "type": cur.get("type", ""),
                "description": cur.get("description", ""), "references": cur.get("references", []),
                "updated": cur.get("updated", ""), "by": _by(cur),
                "seen_in": malpedia_explain(name)["seen_in"]}, r
    x = malpedia_explain(name)
    return {"found": False, **x, "reason": f"{x['title']}. {x['text']}",
            "near": [m["id"] for m in (r.get("matches") or [])[:3]]}, r


def _mp_card(r):
    """The Malpedia family of a lookup result, for the page (the same fields as the single look-up card); or the
    threat actor, when the name is a group rather than a malware family."""
    fam = r.get("family")
    if not fam and r.get("actor"):
        a, m = r["actor"], r.get("actor_match") or {}
        return {"found": True, "kind": "actor", "actor": a["id"], "family": "", "name": a["name"], "url": a["url"],
                "matched_by": m.get("matched_by", ""), "description": a["description"], "alt_names": a["synonyms"],
                "country": a["country"], "sponsor": a["sponsor"], "targets": a["targets"], "sectors": a["sectors"],
                "families": a["families"], "references": a["references"][:6], "reference_count": a["reference_count"]}
    if not fam:
        return None
    best = (r.get("matches") or [{}])[0]
    return {"found": True, "family": fam["id"], "name": fam.get("name") or fam["id"], "url": fam.get("url"),
            "matched_by": best.get("matched_by", ""), "description": fam.get("description") or "",
            "alt_names": (fam.get("alt_names") or [])[:8], "attribution": (fam.get("attribution") or [])[:6],
            "updated": fam.get("updated"), "references": (fam.get("references") or [])[:6],
            "reference_count": fam.get("reference_count", 0)}


# Every explanation card carries the researchers' notes on its name (notes.py): the map, services, Executive and the PDF
# reports all use these three look-ups, so the notes are added here once.
_mp_resolve_plain, _issue_resolve_plain, _issues_resolve_plain = mp_resolve, issue_resolve, issues_resolve


def _noted(card, section, name):
    n = globals().get("NOTES")
    return n.attach(card, section, name) if n else card


def mp_resolve(name):  # noqa: F811
    card, r = _mp_resolve_plain(name)
    return _noted(card, "infections", name), r


def issue_resolve(name, fetch=True):  # noqa: F811
    return _noted(_issue_resolve_plain(name, fetch=fetch), "issues", name)


def issues_resolve(names, budget=15.0, progress=None):  # noqa: F811
    return {n: _noted(c, "issues", n) for n, c in _issues_resolve_plain(names, budget=budget, progress=progress).items()}


@app.route("/api/malpedia/batch")
def api_malpedia_batch():
    """Enrich a list of infections / categories: each unique name is looked up once (cached for a week, so repeated
    lists cost no Malpedia calls). ?values=a,b,c (at most 80). For each: the matching Malpedia family, or why none."""
    if not AUTH["has_perm"]("malpedia"):
        return jsonify(error="Your role cannot use Malpedia lookups (permission 'malpedia')."), 403
    names = []                                       # without a Malpedia token the researchers' definitions answer
    for v in (request.args.get("values") or "").split(","):
        v = v.strip()
        if v and len(v) <= 100 and v.lower() not in {n.lower() for n in names}:
            names.append(v)
    if len(names) > 80:
        return jsonify(error="At most 80 names at a time."), 400
    out, pending = {}, 0
    for v in names:
        if is_demo() and v.startswith("ref:"):          # masked references are not names
            continue
        try:
            out[v] = mp_resolve(v)[0]
            continue
        except ValueError as exc:
            out[v] = {"found": False, "reason": security.public_error(exc)}
            continue
        except RuntimeError as exc:                     # rate limit or Malpedia unreachable: try again later
            pending += 1
            out[v] = {"found": False, "pending": True, "reason": f"Not checked yet: {security.public_error(exc, 'Malpedia did not answer')}. Try again in a minute."}
    return jsonify(results=out, looked_up=len(names), pending=pending, malpedia=malpedia.enabled)


@app.route("/api/malpedia")
def api_malpedia():
    """Look up a field value on Malpedia: ?field=infection|tag|family|md5|sha256&value=... (token stays here)."""
    if not AUTH["has_perm"]("malpedia"):          # permission first: the answer must not depend on the set-up
        return jsonify(error="Your role cannot use Malpedia lookups (permission 'malpedia')."), 403
    field = request.args.get("field", "infection")
    value = request.args.get("value", "")
    if not malpedia.enabled and field not in ("infection", "tag"):     # names still get the researchers' definitions
        return jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    if field not in MALPEDIA_FIELDS:
        return jsonify(error=f"field must be one of {', '.join(MALPEDIA_FIELDS)}"), 400
    try:
        if field in ("infection", "tag"):
            card, r = mp_resolve(value)
            r = dict(r)
            if card.get("kind") == "actor":
                r["actor_card"] = card
            elif card.get("curated"):
                r["curated"] = card
            elif not card.get("found"):
                r["explain"] = card
            elif card.get("curated_references"):
                r["curated_references"] = card["curated_references"]
                if card.get("matched_by") == "the administrator's definition":
                    r["matches"] = [{"id": card["family"], "matched_by": card["matched_by"], "alt_names": []}]
        else:
            r = malpedia.lookup(field, value)
    except ValueError as e:
        return jsonify(error=security.public_error(e)), 400
    except RuntimeError as e:
        return jsonify(error=security.public_error(e, "Malpedia did not answer. Try again in a minute.")), 429 if "Too many" in str(e) else 502
    return jsonify(r)


# ---------------------------------------------------------------- Settings: definitions for names Malpedia does not know
_URL_RE = __import__("re").compile(r"^https?://[^\s<>\"']{4,500}$")


@app.route("/api/kb/unresolved")
def api_kb_unresolved():
    """Names a look-up could not match (most seen first), and the names already defined by an administrator."""
    if not _kb_allowed():
        return jsonify(error="Definitions are for researchers and admins."), 403
    names = _read_names()
    misses = {n: x for n, x in names.items() if not x.get("family")}
    kb, ev = knowledge_base(), _name_evidence()
    def row(n, m=None):
        e, x = kb.get(n.lower()) or {}, ev.get(n.lower(), {"classes": set(), "reports": set()})
        return {"name": n, "count": (m or {}).get("count", 0), "last": (m or {}).get("last") or (m or {}).get("checked", ""),
                "family_found": (names.get(n.lower()) or {}).get("family", ""),
                "reports": sorted(x["reports"]), "last_seen": _last_seen(n, x["reports"]), "seen_days": SEEN.covered_days(),
                "kinds": sorted(x["classes"]), "title": e.get("title", ""),
                "type": e.get("type", ""), "description": e.get("description", ""), "references": e.get("references", []),
                "malpedia": e.get("malpedia", ""), "defined": bool(e.get("references") or e.get("malpedia")),
                "updated": e.get("updated", ""), "by": _by(e) or ("Looking Glass" if defined_entry(e) else "")}
    todo =[row(n, m) for n, m in sorted(misses.items(), key=lambda kv: -kv[1].get("count", 0))
            if not _curated(n) and malpedia_explain(n)["verdict"] != "activity"]
    done = [row(n) for n, e in sorted(kb.items()) if e.get("references") or e.get("malpedia")]
    new = [row(n) for n in _unchecked_names()]
    for r in new:
        r["unchecked"] = True
    # every infection / category in the loaded reports (activities such as scanning left out)
    every = [row(n, names.get(n)) for n, x in sorted(ev.items(), key=lambda kv: -len(kv[1]["reports"]))
             if n and not (x["classes"] and x["classes"] <= set(_ACTIVITY))]
    # issues of the services platform: CVEs (looked up) and the others (defined by researchers)
    ikb, issues = issues_kb(), []
    for name, x in sorted(_svc_issue_stats().items(), key=lambda kv: -len(kv[1]["hosts"])):
        e = ikb.get(name.lower()) or {}
        item = {"name": name, "records": x["records"], "hosts": len(x["hosts"]), "cve": cves.is_cve(name),
                "defined": bool(e.get("description") or e.get("references")), "title": e.get("title", ""),
                "by": _by(e) or ("Looking Glass" if defined_entry(e) else ""), "updated": e.get("updated", "")}
        if item["cve"]:
            c = cve_intel.card(name, fetch=False)
            item.update(found=c["found"], pending=c["pending"], exploited=c["exploited"],
                        cvss=(c.get("cvss") or {}).get("score"), severity=(c.get("cvss") or {}).get("severity", ""),
                        epss=c.get("epss"), title=item["title"] or (c.get("kev") or {}).get("name", ""))
        issues.append(item)
    return jsonify(unresolved=todo, defined=done, unchecked=new, all=every, check=_AUTOCHECK, malpedia=malpedia.enabled,
                   issues=issues, cve=cve_intel.status())


@app.route("/api/kb/malpedia-search")
def api_kb_malpedia_search():
    """Settings editor: find the Malpedia family a malware is listed under (any name or alias, e.g. 'proslikefan')."""
    if not _kb_allowed():
        return jsonify(error="Definitions are for researchers and admins."), 403
    if not malpedia.enabled:
        return jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    q = (request.args.get("q") or "").strip()
    if not 3 <= len(q) <= 60:
        return jsonify(error="Type 3 to 60 characters."), 400
    try:
        hits = malpedia.find(q)[:10]
        actors = malpedia._get("find/actor/" + __import__("urllib.parse").parse.quote(q.lower(), safe="")) or []
    except RuntimeError as e:
        return jsonify(error=security.public_error(e, "Malpedia did not answer. Try again in a minute.")), 429
    out = [{"id": h["id"], "alt_names": h["alt_names"][:6], "matched_by": h["matched_by"],
            "url": "https://malpedia.caad.fkie.fraunhofer.de/details/" + h["id"]} for h in hits]
    out += [{"id": "actor:" + a["name"], "alt_names": (a.get("synonyms") or [])[:6], "matched_by": f"threat actor {a.get('common_name') or a['name']}",
             "url": "https://malpedia.caad.fkie.fraunhofer.de/actor/" + a["name"]} for a in actors[:6] if a.get("name")]
    return jsonify(results=out)


@app.route("/api/kb/check", methods=["POST"])
def api_kb_check():
    """Settings: check the new names (from new reports) against Malpedia now, in the background."""
    if not _kb_change_allowed():
        return jsonify(error="Only researchers and admins can start this."), 403
    if not malpedia.enabled:
        return jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    started = _autocheck()
    return jsonify(started=started, check=_AUTOCHECK,
                   note="" if started else "A check is already running (perhaps in another worker); refresh in a minute.")


@app.route("/api/kb/entry", methods=["GET", "POST"])
def api_kb_entry():
    """GET ?name= : one name's definition. POST: an administrator defines or corrects a name (data/infections.json):
    title, type, plain description, references (evidence, http/https links) and optionally the Malpedia family id."""
    if request.method == "GET":
        if not _kb_allowed():
            return jsonify(error="Definitions are for researchers and admins."), 403
        n = (request.args.get("name") or "").strip()
        e = (issues_kb() if request.args.get("section") == "issues" else knowledge_base()).get(n.lower()) or {}
        return jsonify(name=n, title=e.get("title", ""), type=e.get("type", ""), description=e.get("description", ""),
                       references=e.get("references", []), malpedia=e.get("malpedia", ""), updated=e.get("updated", ""),
                       by=_by(e))
    if not _kb_change_allowed():
        return jsonify(error="Only researchers and admins can change definitions."), 403
    if not AUTH["fresh"]():
        return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    import json as _json, re as _re
    b = request.get_json(silent=True)
    if not isinstance(b, dict):
        return jsonify(error="JSON expected"), 400
    section = "issues" if b.get("section") == "issues" else "infections"
    display = str(b.get("name") or "").strip()
    name = display.lower()
    if section == "issues":
        if not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:()/+-]{0,79}", display):
            return jsonify(error="The issue: letters, digits, spaces and . _ : ( ) / + -, up to 80 characters."), 400
        if cves.is_cve(display):
            display = display.upper()
    elif not _re.fullmatch(r"[a-z0-9][a-z0-9 ._:-]{0,79}", name):
        return jsonify(error="The name: letters, digits, dot, dash, underscore or space, up to 80 characters."), 400
    title, kind = str(b.get("title") or "").strip()[:120], str(b.get("type") or "").strip()[:80]
    desc = str(b.get("description") or "").strip()[:2000]
    refs = [str(u).strip() for u in (b.get("references") or []) if str(u).strip()][:12]
    bad = [u for u in refs if not _URL_RE.match(u)]
    if bad:
        return jsonify(error=f"References must be web links starting with http:// or https:// ({bad[0][:60]})."), 400
    mp_id = str(b.get("malpedia") or "").strip() if section == "infections" else ""
    if mp_id and not _re.fullmatch(r"[a-z0-9]{2,10}\.[a-z0-9_]{2,60}|actor:[a-z0-9][a-z0-9_-]{1,80}", mp_id):
        return jsonify(error="The Malpedia id looks like win.lumma or apk.badbox, or actor:tick for a threat actor (or leave it empty)."), 400
    if mp_id and malpedia.enabled:
        try:
            if not (malpedia.actor(mp_id[6:]) if mp_id.startswith("actor:") else malpedia.family(mp_id)):
                return jsonify(error=f"Malpedia has no family {mp_id}: use Find in Malpedia to pick the right one, or leave it empty."), 400
        except RuntimeError:
            pass                                        # Malpedia busy or unreachable: keep the administrator's id
    if not (refs or mp_id):
        return jsonify(error="Give at least one reference (evidence), or the Malpedia family id."), 400
    if section == "issues" and cves.is_cve(display):
        if not (refs or desc):
            return jsonify(error="For a CVE, add a note or at least one reference (NVD, CISA and EPSS are shown anyway)."), 400
    elif not mp_id and not (title and desc):
        return jsonify(error="Without a Malpedia family, give a title and a plain description."), 400
    with _MISSES_LOCK:
        try:
            with open(LOCAL_DEFS_PATH, encoding="utf-8") as f:
                data = _json.load(f)
        except FileNotFoundError:
            data = {"about": "Definitions written on this site (Settings / Definitions page). Kept on upgrades; "
                             "they take precedence over data/infections.json.", "infections": {}}
        inf = data.setdefault(section, {})
        key = next((k for k in inf if k.lower() == name), display if section == "issues" else name)
        base = (issues_kb() if section == "issues" else knowledge_base()).get(name) or {}
        e = inf.setdefault(key, {k: v for k, v in base.items() if k != "name"})
        e.update({k: v for k, v in (("title", title), ("type", kind), ("description", desc)) if v})
        e["references"] = refs
        if section == "infections":
            e["malpedia"] = mp_id
        e["status"], e["confidence"] = "reviewed", e.get("confidence") or "high"
        e["updated"] = utcnow().date().isoformat()
        e["curated_by"], e["curated_by_name"] = _me()     # username (stable) and full name (kept if the account goes)
        tmp = LOCAL_DEFS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, LOCAL_DEFS_PATH)
        if section == "infections":
            m = _read_names()
            if name in m:                               # checked again on the next look-up, with the new definition
                m.pop(name)
                _write_names(m)
    _kb["mtime"] = _ikb["mtime"] = None
    AUTH["audit"].add("definition_saved", user=(getattr(g, "user", None) or {}).get("user", "token"),
                      target=(f"issue:{display}" if section == "issues" else name),
                      detail=f"{'malpedia ' + mp_id + ', ' if mp_id else ''}{len(refs)} reference(s)")
    return jsonify(saved=True, name=key)


@app.route("/api/infections")
def api_infections():
    # who defined each one by full name, never the account name (external review, 2026-11-12: usernames were sent)
    out = {}
    for k, v in knowledge_base().items():
        e = {f: x for f, x in v.items() if f not in ("curated_by", "curated_by_name")}
        if v.get("curated_by"):
            e["by"] = _by(v)
        out[k] = e
    return jsonify(out)


@app.route("/api/infections/missing")
def api_infections_missing():
    """Infections in the replay day that have no knowledge-base entry (or only a needs-review one)."""
    kb = knowledge_base()
    day = store.get(parse_iso(request.args.get("at"), replay_now()))
    seen = Counter((e["infection"] or "unknown").lower() for e in day.events)
    missing = [{"infection": k, "count": n} for k, n in seen.most_common() if k not in kb]
    review = [{"infection": k, "count": n} for k, n in seen.most_common() if k in kb and kb[k].get("status") != "reviewed"]
    return jsonify(day=day.start.date().isoformat(), seen=len(seen), missing=missing, needs_review=review)


@app.route("/healthz")
def healthz():
    return jsonify(ok=True, replay_now=iso(replay_now()))


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
    out.update({("issues", n.lower()): (e.get("title") or n) for n, e in issues_kb().items() if defined_entry(e)})
    return out                                     # names in lower case (intel.py compares them so)


# researchers' notes (new findings) on a name, shown on every card and in the PDF reports (notes.py)
import notes as _notes  # noqa: E402
NOTES = _notes.install(app, {"people": people, "audit": AUTH["audit"], "allowed": _kb_allowed, "change_allowed": _kb_change_allowed,
                             "fresh": AUTH["fresh"], "base_dir": BASE_DIR, "logger": app.logger})

INTEL = _intel.install(app, {"store": store, "svc_store": svc["store"], "allowed": _kb_allowed, "defined": _defined_titles,
                             "services_view": lambda n: SVC_KB["view"](n),     # Services in Intel gathered (services_kb.py)
                             "cross": lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"],   # every category
                                                                        hold_small=True),     # researchers: no code below 5 hosts
                             "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()},
                                                **{x["name"]: x["label"] for x in svc["registry"].get()}}})


# combination codes and the analyst's combination search (combos.py)
import combos as _combos  # noqa: E402


def _combo_fetch(section, cols, start):
    """One day of the given reports straight from MongoDB, inside the constituency, as the day stores load them."""
    end = start + timedelta(days=1)
    out = []
    if section == "infections":
        for s in registry.get():
            if s["name"] not in cols:
                continue
            rows, _ = store._fetch_collection(s, start, end)
            if settings.restricted:
                rows = [e for e in rows if settings.in_scope(e["src_asn"], e["src_ip"]) or settings.in_scope(e["dst_asn"], e["dst_ip"])]
            for e in rows:
                for f, v in list(e.items()):
                    if isinstance(v, datetime):
                        e[f] = iso(v)
            out += rows
    else:
        st = svc["store"]
        for s in svc["registry"].get():
            if s["name"] not in cols:
                continue
            rows, _ = st._fetch(s, start, end)
            if settings.restricted:
                rows = [e for e in rows if settings.in_scope(e["asn"], e["ip"])]
            out += rows
    return out


def _combo_explain(section, name):
    try:
        return issue_resolve(name, fetch=False) if section == "issues" else mp_resolve(name)[0]
    except Exception:                    # noqa: BLE001  (an explanation is a nice-to-have in the PDF)
        return None


def _adm1_shapes():
    """The country's first-level regions (static/data/adm1/<country>.json), as the Executive report draws them; None if absent."""
    p = os.path.join(app.static_folder, "data", "adm1", f"{settings.data['country']}.json")
    try:
        with open(p, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _combo_pdf(spec):
    import reports_pdf
    return reports_pdf.build(spec)


COMBOS = _combos.install(app, {
    "intel": INTEL, "store": store, "svc_store": svc["store"],
    "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}},
    "fetch": _combo_fetch, "network": lambda asn: asn_registry.company(asn, False) if asn else "",
    "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "is_demo": is_demo, "audit": AUTH["audit"], "notes": NOTES,
    "explain": _combo_explain, "build_pdf": _combo_pdf, "scope_text": lambda: _scope_text(), "base_dir": BASE_DIR,
    "can_note": _kb_change_allowed, "shapes": lambda: _adm1_shapes(), "country": lambda: settings.data["country"],
    "svc_matcher": lambda entry: SVC_INTEL.matcher(entry), "svc_new_code": lambda r, items: SVC_INTEL.new_code(r, items),
    "title_of": lambda n: SVC_KB["title_of"](n),
    "cross": lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"]),     # a search's devices across every category
    "logger": app.logger})
NOTES.codes = COMBOS            # notes carry combination codes; their meaning is read from the code book

# findings: notes the team follows up, researcher -> management -> analyst -> advisory (findings.py, /findings)
import findings as _findings  # noqa: E402
FINDINGS = _findings.install(app, {"people": people, "audit": AUTH["audit"], "fresh": AUTH["fresh"], "csrf_ok": AUTH["csrf_ok"],
                                   "has_perm": AUTH["has_perm"], "describe": COMBOS.describe, "base_dir": BASE_DIR,
                                   "known": lambda c: bool(COMBOS.resolve_any(c)), "logger": app.logger})
NOTES.findings = FINDINGS


def _people_of(kind):
    """The active accounts that do a job, by what their role may do (roles are configurable): managers (management),
    researchers (definitions), analysts (see addresses and export). Names only, for the "send to" lists."""
    need = {"management": {"management"}, "researcher": {"definitions"}, "analyst": {"unmasked", "export"}, "advisor": {"advisory"}}[kind]
    out = []
    for name, u in AUTH["users"].all().items():
        if (u or {}).get("status") != "active" or name.startswith(auth.TEST_PREFIX):
            continue
        if need <= set(AUTH["roles"].perms(u.get("role") or "")):
            out.append({"user": name, "name": people.name(name), "role": u.get("role") or ""})
    return sorted(out, key=lambda p: p["name"].lower())


FINDINGS.people_of = _people_of
FINDINGS.title_of = lambda n: SVC_KB["title_of"](n)     # a services report's finding shows its title

# analyst codes: an analyst's selection passed to researchers and management without an address (acodes.py)
import acodes as _acodes  # noqa: E402


def _day_for(platform, iso):
    """A day of either platform: the copy in memory, or loaded from MongoDB (not kept)."""
    st = store if platform == "comms" else svc["store"]
    try:
        start = datetime.fromisoformat(iso).replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    d = st.days.get(start)
    if d is not None:
        return d
    try:
        return st._load(start)
    except Exception:                    # noqa: BLE001  (an unreadable day: the code has no records)
        app.logger.exception("Analyst code: day %s could not be loaded", iso)
        return None


ACODES = _acodes.install(app, {
    "book": COMBOS, "findings": FINDINGS, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
    "is_demo": is_demo, "audit": AUTH["audit"], "day": _day_for, "slice": _slice_on, "svc_scope": svc["scope_events"],
    "labels": lambda: {**{x["name"]: x["label"] for x in registry.get()}, **{x["name"]: x["label"] for x in svc["registry"].get()}},
    "network": lambda asn: asn_registry.company(asn, False) if asn else "", "defined": _defined_titles,
    "people_name": lambda u: people.name(u, ""), "base_dir": BASE_DIR,
    "cross": lambda hosts: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"])})     # every category for the code's hosts
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
                            "cross": lambda hosts, with_hosts=False: SVC_INTEL.for_hosts(hosts, SVC_KB["title_of"], kind_of=SVC_KB["kind_of"],
                                                                                         with_hosts=with_hosts)})

# the organisation (name and logo, set in Settings) and the advisor's advisories on decided findings
import organisation as _organisation  # noqa: E402


def _site_demo():
    """Demo mode for the site (public demo or ?demo=1), not a role without addresses: advisors and admins write here."""
    return bool(PUBLIC_DEMO or request.args.get("demo") == "1")


import advisory as _advisory  # noqa: E402
import audit_portal as _audit_portal  # noqa: E402
# the Audit portal (auditor role and admins, read only): the log by tab, dashboard and control checks, access review,
# the log's integrity and evidence exports (audit_portal.py, audit_chain.py, audit_report.py)
_audit_portal.install(app, {"has_perm": AUTH["has_perm"], "users": AUTH["users"], "roles": AUTH["roles"], "sessions": AUTH["sessions"],
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
    "client": lambda: (request.remote_addr or "", request.headers.get("User-Agent", ""))})
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
NOTIFS = _notifications.install(app, {"base_dir": BASE_DIR, "findings": FINDINGS, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                                      "people_name": lambda u: people.name(u, ""),
                                      "labels": lambda s: _findings.LABEL.get(s, s)})
import tlp as _tlp  # noqa: E402
_tlp.install(app)               # the Traffic Light Protocol levels, for the Definitions page's card
ORG = _organisation.install(app, {"base_dir": BASE_DIR, "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"],
                                  "fresh": AUTH["fresh"], "is_demo": _site_demo, "audit": AUTH["audit"]})
ADVISORIES = _advisory.install(app, {"base_dir": BASE_DIR, "findings": FINDINGS, "book": COMBOS, "org": ORG,
                                     "has_perm": AUTH["has_perm"], "csrf_ok": AUTH["csrf_ok"], "fresh": AUTH["fresh"],
                                     "is_demo": _site_demo, "audit": AUTH["audit"], "people_name": lambda u: people.name(u, ""),
                                     "title_of": lambda n: SVC_KB["title_of"](n), "describe": COMBOS.describe,
                                     "network": lambda asn: asn_registry.company(asn, False) if asn else "",
                                     "scope_text": lambda: _scope_text()})


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
    rows = [{"asn": a, "name": v.get("name", ""), "holder": v.get("holder", ""), "country": v.get("country", ""),
             "type": v.get("type", "unknown"), "role": v.get("role", ""), "reviewed": bool(v.get("reviewed")),
             "source": v.get("source", ""), "note": v.get("note", ""), "events": v.get("events_last_check", 0),
             "updated": v.get("updated", ""), "by": _by(v, "updated_by")} for a, v in asn_registry.all().items()]
    rows.sort(key=lambda r: (r["reviewed"], -r["events"]))
    return jsonify(networks=rows, types=people.with_names(netypes.all_types(DATA_DIR)), identifying=bool(_ASN_JOB and _ASN_JOB.running()))


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
        with open(path, encoding="utf-8") as f:
            data = _json.load(f)
        e = data.setdefault("asns", {}).get(asn)
        if e is None:
            return jsonify(error=f"AS{asn} is not in the registry (it is added when it appears in the reports)."), 404
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
    """The 54 African countries with region boundaries (static/data/adm1/index.json), read once and cached:
    it is consulted for every record when deciding whether a region is 'unknown'."""
    path = os.path.join(ADM1_DIR, "index.json")
    try:
        m = os.path.getmtime(path)
        if m != _COUNTRY_INDEX["mtime"]:
            with open(path, encoding="utf-8") as f:
                _COUNTRY_INDEX.update(mtime=m, data=json.load(f).get("countries", {}))
    except (OSError, ValueError):
        pass
    return _COUNTRY_INDEX["data"]


_COUNTRY_BBOX = {}


def _country_bbox(cc):
    """[west, south, east, north] of the country (from its region boundaries file), cached; None if unknown. The map
    opens on a view that includes it, wherever in Africa the country is."""
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
    """Current settings, plus what can be chosen: African countries with region boundaries, and every network seen
    in yesterday's data on either platform (grouped by company, with their record counts before the constituency)."""
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
                   countries=sorted(_country_index().values(), key=lambda c: c["country"]), networks=nets,
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
    if changed_scope:              # both platforms reload their days with the new constituency, straight away
        store.reset(); svc["store"].reset()
        rn = replay_now()
        threading.Thread(target=lambda: (store.get(rn), svc["store"].get(rn)), daemon=True, name="settings-reload").start()
    app.logger.warning("Settings saved: country %s, time zone %s, %d networks, %d ranges", clean["country"], clean["timezone"],
                       len(clean["networks"]), len(clean["cidrs"]))
    AUTH["audit"].add("settings_changed", user=(getattr(g, "user", None) or {}).get("user", "token"),
                      detail=f"country {clean['country']}, time zone {clean['timezone']}, {len(clean['networks'])} networks, "
                             f"{len(clean['cidrs'])} ranges")
    return jsonify(settings=settings.public())


@app.route("/api/settings/public")
def api_settings_public():
    """What the portals show: the country and a summary of the constituency (never the AS list in demo mode)."""
    idx = _country_index().get(settings.data["country"], {})
    out = {"country": settings.data["country"], "country_name": idx.get("country", settings.data["country"]),
           "restricted": settings.restricted, "networks": len(settings.data["networks"]), "cidrs": len(settings.data["cidrs"]),
           "has_regions": bool(idx.get("regions")), "bbox": _country_bbox(settings.data["country"]),
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
        return SVC_INTEL.matcher(entry).match(events)
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
    "on_codes": lambda *a: getattr(INTEL, "on_codes", None) and INTEL.on_codes(*a)})
SVC_KB = _services_kb.install(app, {
    "patterns": PATTERNS, "services_intel": SVC_INTEL, "change_allowed": _kb_change_allowed, "fresh": AUTH["fresh"],
    "audit": AUTH["audit"], "user": lambda: getattr(g, "user", None),
    "report_map": REPORT_MAP, "svc_store": svc["store"], "load_day": lambda: svc["store"].get(replay_now()),
    "report_info": report_info, "notes": NOTES, "allowed": _kb_allowed,
    "cve_card": lambda n: cve_intel.card(n, fetch=False), "issues_kb": issues_kb,
    "collections": lambda: [n for n in db.list_collection_names() if not n.startswith(_report_map.NO_REPORT)]})

# Not when app.py is merely imported by a script or check: the schedule state file belongs to the server.
_SERVING = __name__ == "__main__" or "gunicorn" in os.path.basename(sys.argv[0] if sys.argv else "")
if _SERVING or os.environ.get("THREATMAP_SCHEDULE") == "1":
    threading.Thread(target=schedule_loop, daemon=True, name="replay-schedule").start()
if _SERVING:
    threading.Thread(target=_autocheck_loop, daemon=True, name="malpedia-new-names").start()
    threading.Thread(target=_cve_loop, daemon=True, name="cve-lookups").start()
    threading.Thread(target=_mgmt["prewarm"], daemon=True, name="mgmt-baseline-prewarm").start()
    threading.Thread(target=REPORT_MAP.loop, daemon=True, name="report-map").start()

if __name__ == "__main__":
    # `python app.py` (tests, development) listens on this computer only unless BIND_HOST says otherwise; the service
    # runs under gunicorn (deploy/), which has its own bind setting (external review, 2026-11-12)
    app.run(host=os.environ.get("BIND_HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False, threaded=True)
