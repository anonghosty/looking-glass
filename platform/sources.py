"""Discover which Shadowserver collections describe a source -> destination communication, and
normalise their different layouts into one event schema.

Layouts seen in the database:
  standard  event4_* / event6_* / microsoft_sinkhole_http: src_ip, src_geo, ... dst_ip, dst_geo, ...
  legacy    2018-2021 reports (darknet, microsoft_sinkhole, sinkhole_http_drone, hp_*_scan, ...):
            the local host is ip/port/asn/geo/region/city, the far end is dst_*
  referer   event4_sinkhole_http_referer: the source is http_referer_ip/_geo/...
  inbound   spam_url: src_* is the remote sender, ip/geo/... is the local (target) host
  target    destination-only reports (dst_* but no src_*): drawn as points at the destination

A collection qualifies when one of its latest documents has field names containing "src" or "dst"
(or the referer source fields), it has a filename index (for fast per-day loading), and it is not
excluded (EXCLUDE_COLLECTIONS).
"""
import re
import threading
import time
from datetime import datetime, timezone

import special_reports

STD_FIELDS = [
    "timestamp", "extracted_date", "logged_date", "protocol", "severity", "infection", "tag", "family", "category",
    "src_ip", "src_port", "src_asn", "src_geo", "src_region", "src_city", "src_hostname", "src_naics", "src_sector",
    "dst_ip", "dst_port", "dst_asn", "dst_geo", "dst_region", "dst_city", "dst_hostname", "dst_naics", "dst_sector",
    "device_vendor", "device_type", "device_model", "application", "version", "machine_name",
    "http_host", "http_url", "http_agent", "http_referer", "ssl_cipher", "ssl_servername",
    "public_source", "forwarded_by", "event_id", "detail", "filename", "line_hash",
]
INTERNAL = {"_id", "sic", "dst_sic", "src_sic"}
PROTOCOLS = {"tcp", "udp", "icmp", "sctp"}
EXTRA_MAX = 1500

# attack type by collection name (first match wins)
CLASS_RULES = [
    (r"ddos", "DDoS"),
    (r"brute_force", "Brute force"),
    (r"initial_access", "Initial access"),
    (r"spoof", "IP spoofing"),
    (r"spam", "Spam"),
    (r"sinkhole|drone", "Botnet C2"),
    (r"scan|darknet", "Scanning"),
]
ACRONYMS = {"http": "HTTP", "dns": "DNS", "smb": "SMB", "rdp": "RDP", "adb": "ADB", "ics": "ICS", "ddos": "DDoS",
            "ikev2": "IKEv2", "ip": "IP", "url": "URL", "amp": "amplification", "hp": "Honeypot", "rocketmq": "RocketMQ"}


def attack_class(name):
    for pat, label in CLASS_RULES:
        if re.search(pat, name):
            return label
    return "Other"


def label_for(name):
    base = re.sub(r"^event[46]_", "", name)
    words = [ACRONYMS.get(w, w.capitalize()) for w in base.split("_")]
    label = " ".join(words)
    if name.startswith("event6_"):
        label += " (IPv6)"
    return label


def detect_layout(fields):
    f = set(fields)
    if "src_ip" in f and "ip" in f and "geo" in f:
        return "inbound"
    if "src_ip" in f or "src_geo" in f:
        return "standard"
    if "ip" in f and "geo" in f and any(k.startswith("dst_") for k in f):
        return "legacy"            # old reports: local host is ip/geo/... (may also carry http_referer_*)
    if "http_referer_ip" in f:
        return "referer"
    if "dst_ip" in f or "dst_geo" in f:
        return "target"            # destination-only: events are drawn as points at the destination
    return None


def _s(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v
    return str(v)


def normalise(doc, src):
    """Map a raw document of collection `src` (a registry entry) to the standard schema + extras."""
    layout = src["layout"]
    g = doc.get
    out = {f: _s(g(f)) for f in STD_FIELDS}
    used = set(STD_FIELDS)

    if layout == "legacy":
        m = {"src_ip": "ip", "src_asn": "asn", "src_geo": "geo", "src_region": "region", "src_city": "city",
             "src_hostname": "hostname", "src_naics": "naics", "src_sector": "sector"}
        for k, v in m.items():
            out[k] = _s(g(v)); used.add(v)
        out["src_port"] = _s(g("src_port") or g("port")); used.add("port")
        out["http_url"] = _s(g("http_url") or g("url")); used.add("url")
        out["http_agent"] = _s(g("http_agent") or g("agent")); used.add("agent")
        typ = _s(g("type")).strip()
        if typ.lower() in PROTOCOLS:
            out["protocol"] = out["protocol"] or typ
            used.add("type")
        elif typ:
            out["infection"] = out["infection"] or typ
            used.add("type")
    elif layout == "referer":
        for part in ("ip", "port", "asn", "geo", "region", "city", "hostname", "naics", "sector"):
            out[f"src_{part}"] = _s(g(f"http_referer_{part}")); used.add(f"http_referer_{part}")
    elif layout == "inbound":
        m = {"dst_ip": "ip", "dst_port": "port", "dst_asn": "asn", "dst_geo": "geo", "dst_region": "region",
             "dst_city": "city", "dst_hostname": "hostname", "dst_naics": "naics", "dst_sector": "sector"}
        for k, v in m.items():
            out[k] = _s(g(k)) or _s(g(v)); used.add(v)
        out["http_url"] = _s(g("http_url") or g("url")); used.add("url")

    # DDoS reports: the attacked host may be given as a network
    if not out["dst_ip"] and g("dst_network"):
        out["dst_ip"] = _s(g("dst_network")).split("/")[0]
    if not out["infection"]:
        out["infection"] = out["family"] or out["tag"] or out["application"] or src["name"]
    out["category"] = out["category"] or src["name"]

    extras = {}
    for k, v in doc.items():
        if k in used or k in INTERNAL or v in (None, "") or k.startswith("http_referer_"):
            continue
        sv = v.isoformat() if isinstance(v, datetime) else str(v)
        extras[k] = sv if len(sv) <= EXTRA_MAX else sv[:EXTRA_MAX] + "…"
    out["source"] = src["name"]
    out["source_label"] = src["label"]
    out["attack_class"] = src["class"]
    out["extras"] = extras
    return out


# ------------------------------------------------------------------ compatibility diagnostic
# Where each layout keeps the source and the destination host (raw field-name prefix).
PREFIXES = {"standard": ("src_", "dst_"), "legacy": ("", "dst_"), "referer": ("http_referer_", "dst_"),
            "inbound": ("src_", "")}


def _is_time(v):
    if isinstance(v, datetime):
        return True
    try:
        datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return True
    except ValueError:
        return False


def diagnose(fields, docs, layout, has_fn_index, fallback_scan=False):
    """Check a collection's fields against what the platform needs to put its rows on the map.

    Required (without them the rows cannot be replayed or drawn): event time, source host, source country
    and a way to load one day quickly (filename index, or FALLBACK_SCAN=1).
    Recommended (shown, but the report still loads): destination (else a point instead of an arc), city,
    destination country, network, severity, infection.
    """
    present = set(fields)
    first = lambda k: next((d[k] for d in docs if d.get(k) not in (None, "")), None)
    common_rec = [
        ("Severity", ["severity"], "critical / high / info figures"),
        ("Infection / category", ["infection", "tag", "family", "category", "type"], "infection analysis and colours"),
    ]
    if layout == "target":
        # destination-only reports: the destination is what goes on the map (as a point)
        required = [
            ("Event time", ["extracted_date"], "places each event on the replay timeline"),
            ("Destination host", ["dst_ip"], "the targeted or contacted device"),
            ("Destination country", ["dst_geo"], "puts the destination on the map"),
            ("Report file name", ["filename"], "loads one day's rows quickly"),
        ]
        recommended = [
            ("Source", ["src_ip", "src_geo"], "the other end of the connection; without it events show as a point at the destination"),
            ("Destination city or region", ["dst_city", "dst_region"], "places the destination on a city instead of a country"),
            ("Destination network", ["dst_asn"], "network (company) analysis"),
        ] + common_rec
    else:
        sp, dp = PREFIXES.get(layout or "standard")
        required = [
            ("Event time", ["extracted_date"], "places each event on the replay timeline"),
            ("Source host", [sp + "ip"], "the infected or attacking device"),
            ("Source country", [sp + "geo"], "puts the source on the map"),
            ("Report file name", ["filename"], "loads one day's rows quickly"),
        ]
        recommended = [
            ("Destination", [dp + "ip", dp + "geo"], "the other end of the connection; without it events show as a point at the source"),
            ("Source city or region", [sp + "city", sp + "region"], "places the source on a city instead of a country"),
            ("Destination country", [dp + "geo"], "draws the arc to the right country"),
            ("Source network", [sp + "asn"], "network (company) analysis"),
        ] + common_rec
    checks, missing, missing_fields, warnings = [], [], [], []
    for need, alts, why in required:
        ok = any(a in present for a in alts)
        note = ""
        if ok and need == "Event time" and first("extracted_date") is not None and not _is_time(first("extracted_date")):
            ok, note = False, "present, but not a date"
        if ok and need == "Report file name" and not (has_fn_index or fallback_scan):
            ok, note = False, "present, but has no index (create one, or set FALLBACK_SCAN=1)"
        checks.append({"need": need, "fields": alts, "ok": ok, "required": True, "why": why, "note": note})
        if not ok:
            missing.append(need + (f" ({note})" if note else ""))
            if not note:
                missing_fields.append(" or ".join(alts))
    for need, alts, why in recommended:
        ok = any(a in present for a in alts)
        checks.append({"need": need, "fields": alts, "ok": ok, "required": False, "why": why, "note": ""})
        if not ok:
            warnings.append(need)
    if not layout:
        missing.insert(0, "a field layout the platform knows (src_*, dst_*, ip/geo + dst_*, or http_referer_*)")
    return {"compatible": bool(layout) and not missing, "layout": layout or "unrecognised", "checks": checks,
            "missing": missing, "missing_fields": missing_fields, "warnings": warnings,
            "required_ok": sum(1 for c in checks if c["required"] and c["ok"]), "required_total": len(required)}


class Registry:
    """Cached list of qualifying collections; refreshed every `ttl` seconds.

    Discovery: a collection is a candidate when its latest documents have source/destination fields.
    Every candidate gets a compatibility diagnostic (see `diagnose`): compatible ones are loaded onto the map
    (`items`); the others are listed in `unsupported`, with the fields they lack, for a future update."""

    def __init__(self, db, exclude=(), include=None, ttl=6 * 3600, logger=None, fallback_scan=False):
        self.db = db
        self.exclude = set(exclude)
        self.include = set(include) if include else None
        self.ttl = ttl
        self.log = logger
        self.fallback_scan = fallback_scan
        self.lock = threading.Lock()
        self.build_lock = threading.Lock()
        self.items = []
        self.unsupported = []     # candidates that failed the diagnostic: [{"name", "label", "diagnostic", ...}]
        self._unsupported_next = []
        self.built_at = 0
        self.names = set()        # every collection name seen at the last build
        self.empty = set()        # collections skipped only because they had no documents yet
        self.added = []           # [{"name", "label", "at", "compatible", ...}] report types found while running
        self.version = 0          # bumped whenever the list of reports (supported or not) changes

    def check(self):
        """Cheap test, run every few seconds: rebuild at once when a collection was created or dropped, or a
        collection that was still empty has received its first documents (so a new report shows up quickly)."""
        try:
            names = set(self.db.list_collection_names())
            filled = any(self.db[n].estimated_document_count() for n in self.empty if n in names)
        except Exception:
            return False
        if self.built_at and names == self.names and not filled:
            return False
        before = {i["name"] for i in self.items + self.unsupported}
        self.get(force=True)
        if self.built_at and before:
            now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            for i in self.items + self.unsupported:
                if i["name"] not in before:
                    d = i["diagnostic"]
                    self.added.append({"name": i["name"], "label": i["label"], "at": now,
                                       "compatible": d["compatible"], "missing": d["missing"],
                                       "warnings": d["warnings"], "required_ok": d["required_ok"],
                                       "required_total": d["required_total"]})
                    if self.log:
                        self.log.warning("New report type %s: %s", i["name"],
                                         "compatible, loaded onto the map" if d["compatible"]
                                         else "NOT compatible yet, missing " + "; ".join(d["missing"]))
            del self.added[:-20]
        return True

    def _build(self):
        items, empty, unsupported = [], set(), []
        names = self.db.list_collection_names()
        self.names = set(names)
        for name in sorted(names):
            if name.startswith("discovered_fields_") or name in self.exclude:
                continue
            if special_reports.is_special(name):          # one-off Special Reports: listed apart, never replayed
                continue
            if self.include is not None and name not in self.include:
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
            if not any(re.search(r"src|dst", k, re.I) for k in fields) and "http_referer_ip" not in fields:
                continue
            layout = detect_layout(fields)
            try:
                has_fn_index = any(list(ix["key"].keys())[0] == "filename" for ix in c.list_indexes())
            except Exception:
                has_fn_index = False
            diag = diagnose(fields, docs, layout, has_fn_index, self.fallback_scan)
            entry = {
                "name": name, "label": label_for(name) + (" (legacy)" if layout == "legacy" else ""),
                "class": attack_class(name), "layout": layout,
                "filename_index": has_fn_index,
                "latest": str(docs[0].get("timestamp", "")) if docs else "",
                "diagnostic": diag,
            }
            (items if diag["compatible"] else unsupported).append(entry)
        self.empty = empty
        self._unsupported_next = unsupported
        return items

    def get(self, force=False):
        with self.lock:
            if not force and self.items and time.time() - self.built_at < self.ttl:
                return self.items
        with self.build_lock:            # one build at a time; the others use its result
            with self.lock:
                if not force and self.items and time.time() - self.built_at < self.ttl:
                    return self.items
            return self._rebuild()

    def _rebuild(self):
        items = self._build()
        unsupported = self._unsupported_next
        with self.lock:
            if ([i["name"] for i in items] != [i["name"] for i in self.items]
                    or [i["name"] for i in unsupported] != [i["name"] for i in self.unsupported]):
                self.version += 1
            self.items, self.unsupported, self.built_at = items, unsupported, time.time()
        if self.log:
            self.log.warning("Source registry: %d collections (%s)", len(items), ", ".join(i["name"] for i in items))
            if unsupported:
                self.log.warning("Discovered but not compatible yet: %s", "; ".join(
                    f"{i['name']} (missing {', '.join(i['diagnostic']['missing'])})" for i in unsupported))
        return items
