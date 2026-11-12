"""Publicly accessible / vulnerable services: the single-host Shadowserver reports (scan_*, population_*, device_id,
compromised_*, blocklist). They describe one host in the constituency (ip, port, network, place) instead of a
source -> destination communication, so they are shown without a map.

Discovery: a collection qualifies when its newest documents have an `ip` field and no src_/dst_ fields.
Every candidate gets a compatibility check (`diagnose_service`); compatible ones are loaded, the others are
listed with what they lack. Field analysis (tools/analyze_services.py) showed these fields in (almost) every
such report, so they form the common record:

  ip, port, protocol, asn, geo, region, city, hostname, naics, sector, severity, tag, category,
  timestamp / extracted_date (event time), filename (per-day loading)

About a third add device fields (device_vendor / type / model / version), product banners (server,
server_type, serverid_software, application) or issue markers (CVE tags, ssl_poodle, freak_vulnerable,
cert_expired); those are normalised to vendor, device_type, product, version and issues. Everything else is
kept as `extras` for the details view.
"""
import hashlib
import json
import re
import threading
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from sources import Registry, _is_time

CORE = ("ip", "port", "protocol", "asn", "geo", "region", "city", "hostname", "naics", "sector", "severity", "tag",
        "category")
USED = set(CORE) | {"_id", "timestamp", "extracted_date", "logged_date", "filename", "line_hash", "hostname_source",
                    "device_vendor", "device_type", "device_model", "device_version", "version"}
EXTRA_MAX = 300
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "": 5}

# readable service names (from the collection name)
ACR = {"http": "HTTP", "ssl": "SSL/TLS", "ssh": "SSH", "smtp": "SMTP", "imap": "IMAP", "pop3": "POP3", "amqp": "AMQP",
       "afp": "AFP", "bgp": "BGP", "isakmp": "ISAKMP (IPsec VPN)", "msmq": "MSMQ", "ntrip": "NTRIP", "ard": "Apple Remote Desktop",
       "dns": "DNS", "ftp": "FTP", "ntp": "NTP", "rdp": "RDP", "smb": "SMB", "snmp": "SNMP", "vnc": "VNC", "mdns": "mDNS",
       "mqtt": "MQTT", "cwmp": "CWMP (TR-069)", "ipp": "IPP printing", "ipmi": "IPMI", "epmd": "EPMD", "gtp": "GTP",
       "ics": "Industrial control (ICS)", "msrpc": "MS-RPC", "tftp": "TFTP", "ssdp": "SSDP", "stun": "STUN", "slp": "SLP", "qotd": "QOTD",
       "chargen": "CharGen", "socks": "SOCKS proxy", "telnet": "Telnet", "redis": "Redis", "mysql": "MySQL",
       "mssql": "MS SQL", "postgres": "PostgreSQL", "mongodb": "MongoDB", "couchdb": "CouchDB", "elasticsearch": "Elasticsearch",
       "kubernetes": "Kubernetes API", "ldap": "LDAP", "netbios": "NetBIOS", "portmapper": "Portmapper", "rsync": "rsync",
       "ubiquiti": "Ubiquiti discovery", "exchange": "Microsoft Exchange", "radmin": "Radmin", "rdpeudp": "RDP (UDP)",
       "mikrotik": "MikroTik", "service": "service", "proxy": "proxy", "vulnerable": "(vulnerable)", "tcp": "TCP", "udp": "UDP",
       "badsecrets": "Bad secrets", "ws": "WS", "discovery": "Discovery", "ddos": "DDoS", "middlebox": "middlebox",
       "loop": "Loop", "dos": "DoS", "nat": "NAT", "pmp": "PMP", "ip": "IP", "tunnel": "tunnel", "freak": "FREAK", "poodle": "POODLE",
       "dvr": "DVR", "dhcpdiscover": "DHCP discover", "cisco": "Cisco", "smart": "Smart", "install": "Install",
       "ntpmonitor": "NTP monitor", "id": "identification", "iot": "IoT", "website": "website"}
FAMILIES = [  # (name pattern, family, what it means)
    (r"^compromised_", "Compromised", "devices or websites showing signs of compromise"),
    (r"^blocklist", "Blocklisted", "addresses listed on public abuse blocklists"),
    (r"^device_id", "Identified device", "devices fingerprinted on the internet (vendor, type, model)"),
    (r"^scan6?_", "Exposed service", "services reachable from the internet, found by Shadowserver scans"),
    (r"^population6?_", "Service population", "counts of internet-facing hosts running a protocol"),
]


_DEFS = {"mtime": None, "data": {}}
DEFS_PATH = __import__("os").path.join(__import__("os").path.dirname(__file__), "data", "service_reports.json")
SS_BASE = "https://www.shadowserver.org/what-we-do/network-reporting/"


def report_info(name):
    """Official Shadowserver report name, rating, definition and link for a collection (IPv6 variants included)."""
    import os
    try:
        m = os.path.getmtime(DEFS_PATH)
        if m != _DEFS["mtime"]:
            with open(DEFS_PATH) as f:
                _DEFS["data"] = json.load(f).get("reports", {})
            _DEFS["mtime"] = m
    except (OSError, ValueError):
        pass
    key = re.sub(r"^(scan|population)6_", r"\1_", name)
    key = re.sub(r"^event6_", "event4_", key).replace("device_id6", "device_id")
    d = _DEFS["data"].get(key)
    if not d:
        return None
    return {**d, "url": SS_BASE + d["url"] if d.get("url") else SS_BASE, "ipv6": key != name}


def family_of(name):
    for pat, fam, _ in FAMILIES:
        if re.match(pat, name):
            return fam
    return "Other"


def official_name(name):
    """The report's name as Shadowserver publishes it, without the word 'Report': scan_dns -> 'DNS Open Resolvers',
    scan6_http -> 'Accessible HTTP (IPv6)', population_bgp -> 'Open BGP Service (population)'. None if unknown."""
    info = report_info(name)
    if not info or not info.get("title"):
        return None
    t = re.sub(r"\s+(Special\s+)?Report$", "", info["title"].strip())
    if name.startswith("population") and info.get("population_variant"):
        t += " (population)"
    return t + (" (IPv6)" if info.get("ipv6") else "")


def service_of(name):
    """Official Shadowserver report name when known (data/service_reports.json, checked against MongoDB file names
    and Shadowserver's report pages); otherwise a readable name built from the collection name."""
    official = official_name(name)
    if official:
        return official
    v6 = bool(re.match(r"^(scan|population|device_id)6", name)) or name.endswith("6")
    base = re.sub(r"^(scan6?|population6?)_", "", name)
    if name.startswith("device_id"):
        label = "Device identification"
    elif name.startswith("compromised_"):
        label = "Compromised " + base.replace("compromised_", "").replace("iot", "IoT")
    elif name == "blocklist":
        label = "Blocklist"
    else:
        label = " ".join(ACR.get(w, w.capitalize()) for w in base.split("_"))
        if name.startswith("population"):
            label += " population"     # keeps e.g. 'ISAKMP (IPsec VPN) population' apart from the scan_isakmp report
    return label + (" (IPv6)" if v6 else "")


def _s(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(v)


def diagnose_service(fields, docs, has_fn_index, fallback_scan=False):
    """Compatibility check for a single-host report (same idea as sources.diagnose)."""
    present = set(fields)
    first = lambda k: next((d[k] for d in docs if d.get(k) not in (None, "")), None)
    required = [
        ("Event time", ["extracted_date"], "places each record on the replay timeline"),
        ("Host", ["ip"], "the exposed or affected device"),
        ("Country", ["geo"], "which constituency the host belongs to"),
        ("Report file name", ["filename"], "loads one day's rows quickly"),
    ]
    recommended = [
        ("Port", ["port"], "which service is exposed"),
        ("City or region", ["city", "region"], "where the host is"),
        ("Network", ["asn"], "network (company) analysis"),
        ("Severity", ["severity"], "critical / high figures"),
        ("Tags", ["tag"], "what was found (for example cve-…, exposed-admin-panel)"),
    ]
    checks, missing, warnings = [], [], []
    for need, alts, why in required:
        ok, note = any(a in present for a in alts), ""
        if ok and need == "Event time" and first("extracted_date") is not None and not _is_time(first("extracted_date")):
            ok, note = False, "present, but not a date"
        if ok and need == "Report file name" and not (has_fn_index or fallback_scan):
            ok, note = False, "present, but has no index (create one, or set FALLBACK_SCAN=1)"
        checks.append({"need": need, "fields": alts, "ok": ok, "required": True, "why": why, "note": note})
        if not ok:
            missing.append(need + (f" ({note})" if note else ""))
    for need, alts, why in recommended:
        ok = any(a in present for a in alts)
        checks.append({"need": need, "fields": alts, "ok": ok, "required": False, "why": why, "note": ""})
        if not ok:
            warnings.append(need)
    return {"compatible": not missing, "layout": "single-host", "checks": checks, "missing": missing,
            "missing_fields": [], "warnings": warnings,
            "required_ok": sum(1 for c in checks if c["required"] and c["ok"]), "required_total": len(required)}


class ServiceRegistry(Registry):
    """Discovers the single-host reports (same refresh / announce logic as the communications registry)."""

    def _build(self):
        items, empty, unsupported = [], set(), []
        names = self.db.list_collection_names()
        self.names = set(names)
        for name in sorted(names):
            if name.startswith(("discovered_fields_", "files_")) or name in self.exclude:
                continue
            c = self.db[name]
            try:
                docs = list(c.find().sort("_id", -1).limit(3))
            except Exception:
                continue
            if not docs:
                empty.add(name)
                continue
            fields = []
            for d in docs:
                fields += [k for k in d if k not in fields]
            if any(re.search(r"src|dst", k, re.I) for k in fields) or "http_referer_ip" in fields:
                continue                      # a communication: shown on the map platform
            if "ip" not in fields:
                continue                      # not about a host
            try:
                has_fn_index = any(list(ix["key"].keys())[0] == "filename" for ix in c.list_indexes())
            except Exception:
                has_fn_index = False
            diag = diagnose_service(fields, docs, has_fn_index, self.fallback_scan)
            entry = {"name": name, "label": service_of(name), "class": family_of(name), "family": family_of(name),
                     "layout": "single-host", "filename_index": has_fn_index, "diagnostic": diag,
                     "fields": sorted(f for f in fields if f not in ("_id", "line_hash"))}
            (items if diag["compatible"] else unsupported).append(entry)
        self.empty = empty
        self._unsupported_next = unsupported
        return items


def normalise_service(doc, src):
    g = doc.get
    out = {k: _s(g(k)) for k in CORE}
    out["severity"] = out["severity"].strip().lower()     # some reports write CRITICAL
    tags =[t.strip() for t in out["tag"].replace(",", ";").split(";") if t.strip()]
    issues = [t.upper() for t in tags if t.lower().startswith("cve-")]
    if str(g("ssl_poodle", "")).upper() == "Y":
        issues.append("POODLE (SSLv3)")
    if str(g("freak_vulnerable", "")).upper() == "Y":
        issues.append("FREAK")
    if str(g("cert_expired", "")).upper() == "Y":
        issues.append("Expired certificate")
    for t in tags:
        if t in ("exposed-admin-panel", "device-implant", "badcandy", "cpanel-compromised", "open-dir", "vulnerable"):
            issues.append(t.replace("-", " ").capitalize())
    if src["family"] == "Compromised" and not issues:
        issues.append("Compromised")
    product = next((_s(g(k)) for k in ("device_model", "server", "server_type", "serverid_software", "application")
                    if g(k) not in (None, "")), "")
    extras = {}
    for k, v in doc.items():
        if k in USED or v in (None, ""):
            continue
        sv = _s(v)
        extras[k] = sv if len(sv) <= EXTRA_MAX else sv[:EXTRA_MAX] + "…"
    return {
        **out, "tags": tags, "issues": issues, "vulnerable": bool(issues),
        "vendor": _s(g("device_vendor")), "device_type": _s(g("device_type")), "product": product[:80],
        "version": _s(g("version") or g("device_version") or g("serverid_version"))[:60],
        "report": src["name"], "report_label": src["label"], "family": src["family"], "service": src["label"],
        "extras": extras,
    }


class Day:
    def __init__(self, start, events):
        self.start, self.events = start, events
        self.keys = [e["_t"] for e in events]
        self.loaded_at = time.time()
        self.per_source, self.arrived, self.sig, self.version = {}, {}, None, "0"
        self.raw_total, self.asn_raw, self.region_raw = 0, Counter(), Counter()


class ServiceStore:
    """One replay day of single-host records in memory (same model as the communications DayStore)."""

    def __init__(self, db, registry, refs, logger, reload_seconds=600, fallback_scan=False, settings=None):
        self.db, self.registry, self.refs, self.log = db, registry, refs, logger
        self.settings = settings          # constituency (settings.Settings): applied while loading a day
        self.reload_seconds, self.fallback_scan = reload_seconds, fallback_scan
        self.days, self.loading, self.changes = {}, {}, {}
        self.lock = threading.Lock()

    @staticmethod
    def day_start(dt):
        if dt.tzinfo and dt.utcoffset():               # a day always starts at 00:00 UTC (one copy per day in memory)
            dt = dt.astimezone(timezone.utc)
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    def _prefixes(self, start):
        return [start.strftime("%Y-%m-%d"), (start + timedelta(days=1)).strftime("%Y-%m-%d")]

    def signature(self, start):
        sig = {}
        for s in self.registry.get():
            n = self.db[s["name"]].count_documents(
                {"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in self._prefixes(start)]}) if s["filename_index"] else 0
            if n:
                sig[s["name"]] = n
        return sig

    def _fetch(self, src, start, end):
        c = self.db[src["name"]]
        docs = []
        if src["filename_index"]:
            docs = list(c.find({"$or": [{"filename": {"$regex": "^" + re.escape(p)}} for p in self._prefixes(start)]}))
        if not docs and self.fallback_scan:
            docs = list(c.find({"extracted_date": {"$gte": start, "$lt": end}}))
        out, last = [], None
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
                n = normalise_service(d, src)
                n["id"] = f"{src['name']}:{d['_id']}"
                n["_t"] = ed.timestamp()
                n["extracted_date"] = _s(ed)
                n["ip_ref"] = self.refs.ref(n["ip"])
                out.append(n)
                gt = getattr(d.get("_id"), "generation_time", None)
                if gt and (last is None or gt > last):
                    last = gt
        return out, last

    def _load(self, start):
        t0 = time.time()
        end = start + timedelta(days=1)
        try:
            sig = self.signature(start)
        except Exception:
            sig = None
        srcs = self.registry.get()
        with ThreadPoolExecutor(max_workers=6) as pool:
            parts = list(pool.map(lambda s: (s, *self._fetch(s, start, end)), srcs))
        events, per, arrived = [], {}, {}
        raw_total, asn_raw, region_raw = 0, Counter(), Counter()
        st = self.settings
        for s, rows, last in parts:
            raw_total += len(rows)
            for e in rows:                 # before the constituency: what the Settings page offers and matches
                if e["asn"]:
                    asn_raw[str(e["asn"])] += 1
                region_raw[e["region"]] += 1
            if st is not None and st.restricted:
                rows = [e for e in rows if st.in_scope(e["asn"], e["ip"])]
            events += rows
            if rows:
                per[s["name"]] = len(rows)
                if last:
                    arrived[s["name"]] = _s(last)
        events.sort(key=lambda e: e["_t"])
        day = Day(start, events)
        day.per_source, day.arrived, day.sig = per, arrived, sig
        day.raw_total, day.asn_raw, day.region_raw = raw_total, asn_raw, region_raw
        day.version = hashlib.md5(json.dumps([sorted(per.items()), st.version if st else 0]).encode()).hexdigest()[:10]
        if self.log:
            self.log.warning("Services: loaded %s: %d records from %d reports in %.1fs", start.date(), len(events), len(per), time.time() - t0)
        return day

    def _record_changes(self, start, old, new):
        if old is None:
            return
        log = self.changes.setdefault(start, [])
        labels = {s["name"]: s["label"] for s in self.registry.get()}
        now = _s(datetime.now(timezone.utc))
        for name, rows in new.per_source.items():
            before = old.per_source.get(name, 0)
            if rows > before:
                log.append({"source": name, "label": labels.get(name, name), "rows": rows, "added": rows - before,
                            "new": before == 0, "arrived_at": new.arrived.get(name), "seen_at": now})
        del log[:-50]

    def get(self, dt):
        start = self.day_start(dt)
        with self.lock:
            day = self.days.get(start)
            ttl = self.reload_seconds if day and day.events else 60
            if day and time.time() - day.loaded_at < ttl:
                return day
            ev = self.loading.get(start)
            leader = ev is None
            if leader:
                ev = self.loading[start] = threading.Event()
        if not leader:
            if day:
                return day
            ev.wait(120)
            return self.days.get(start) or Day(start, [])
        try:
            for _ in range(3):
                gen = getattr(self, "gen", 0)
                new = self._load(start)
                with self.lock:
                    if getattr(self, "gen", 0) != gen:   # the constituency changed while loading: load again with it
                        day = None
                        continue
                    self._record_changes(start, day, new)
                    self.days[start] = new
                    for k in [k for k in self.days if k < start - timedelta(days=2)]:
                        del self.days[k]
                return new
            return new
        except Exception:
            if self.log:
                self.log.exception("Services: day load failed for %s", start.date())
            return day or Day(start, [])
        finally:
            with self.lock:
                self.loading.pop(start, None)
            ev.set()

    def reset(self):
        """Forget every loaded day (the constituency changed): the next request reloads them; a load already running
        loads again instead of storing the old constituency's day (external review, 2026-11-12)."""
        with self.lock:
            self.days.clear()
            self.changes.clear()
            self.gen = getattr(self, "gen", 0) + 1

    def check(self, dt):
        start = self.day_start(dt)
        day = self.days.get(start)
        if day is None:
            return False
        try:
            sig = self.signature(start)
        except Exception:
            return False
        if sig == day.sig:
            return False
        with self.lock:
            day.loaded_at = 0
        self.get(start)
        return True


# ---------------------------------------------------------------------------------------------- filtering
SCALAR = ("family", "report", "severity", "service", "port", "protocol", "city", "region", "asn", "sector",
          "vendor", "device_type", "product", "version", "ip", "hostname", "geo")
LISTS = ("tag", "issue")
FILTER_KEYS = SCALAR + LISTS + ("vulnerable",)
EMPTY = {"vendor": "unknown vendor", "device_type": "unknown type", "product": "unknown product", "severity": "unrated",
         "city": "unknown city", "sector": "unknown sector"}


def _masked(refs):
    """True in a masked request (external role, demo mode): the same test the IP and network filters use."""
    try:
        return bool(refs.strict())
    except Exception:      # outside a request
        return False


def parse_filters(args, refs, asns):
    out = {}
    for k in SCALAR + LISTS:
        vals = {("" if v == EMPTY.get(k) else v) for v in args.getlist(k) if v is not None and v != "__none__"}
        if not vals:
            continue
        if k == "ip":
            vals = {refs.resolve(v) for v in vals}
        elif k == "hostname" and _masked(refs):
            # a masked view shows no host name ("hidden"), so it filters on none: a name typed into the request must
            # not tell whether that host is in the data (external review, 2026-11-11)
            vals = {"\x00masked-hostname"}
        elif k == "asn":
            vals = set().union(*(asns.resolve(v) for v in vals))
        out[k] = vals
    if args.get("vulnerable") in ("1", "yes", "true"):
        out["vulnerable"] = {True}
    return out


def matches(e, flt):
    for k, vals in flt.items():
        if k == "tag":
            if not vals.intersection(e["tags"]):
                return False
        elif k == "issue":
            if not vals.intersection(e["issues"]):
                return False
        elif e.get(k) not in vals:
            return False
    return True


def parse_time(value):
    """'START+MINUTES' (fractional minutes from 00:00) -> (start_s, end_s) offsets, or None."""
    m = re.match(r"^\s*([\d.]+)\+([\d.]+)\s*$", value or "")
    if not m:
        return None
    a = float(m.group(1)) * 60
    return a, a + float(m.group(2)) * 60
