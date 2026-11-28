# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""ASN -> company names, and demo-mode masking for public presentations.

* data/asns.json maps AS numbers to a display name, a network type and a stable demo alias
  ("Telco 1", "Institution 3", "Provider 2", ...). It is re-read automatically when it changes.
  ASNs that belong to the same company (same name) share one alias, e.g. an operator's AS64500 and AS64501.
* Demo mode is applied on the server, so concealed values never reach the browser:
  AS numbers and company names become aliases, IP addresses become an opaque label ("Host 3f9a2c41b07e",
  host_label.py: no part of the address is shown), hostnames and machine names are removed, and IP addresses inside
  any other text field (URLs, cookies, banners ...) get the same label. Locations are kept.
* Every source host gets an opaque reference (src_ref) so drill-downs ("analyse this host") still work
  in demo mode without exposing the IP.
"""
import hashlib
import hmac
import ipaddress
import itertools
import json
import os
import re
import threading
import time
import filesig  # noqa: E402
import counting_keys as _ck  # noqa: E402  (one network rule: numbers, 0 as unknown, names folded)

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
IPV4_FULL = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
IPV6 = re.compile(r"\b([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):[0-9a-fA-F:]{2,}\b")
HIDE_FIELDS = ("src_hostname", "dst_hostname", "machine_name")
REFS_MAX = 500000             # host references kept for resolving (HostRefs.to_ip)
UNLISTED_MAX = 200000         # aliases of AS numbers missing from data/asns.json kept for resolving


def _keep(table, key, value, cap, lock):
    """Remember key -> value in a bounded table: a key used again moves to the newest end, and at the cap only the
    oldest tenth is dropped (audit 2026-11-27, 6-13: the whole table was cleared, so every reference or alias a page
    had just been given stopped resolving at once; a drill-down from an open page then found nothing)."""
    with lock:
        if key in table:
            del table[key]                     # dicts keep insertion order: re-inserted = the newest
        table[key] = value
        if len(table) > cap:
            for k in list(itertools.islice(iter(table), max(1, cap // 10))):
                del table[k]


class AsnRegistry:
    def __init__(self, path, logger=None):
        self.path = path
        self.log = logger
        self.lock = threading.Lock()
        self.mtime = None
        self.asns = {}
        self.company_alias = {}   # name -> alias shared by all ASNs of that company
        self.alias_asns = {}      # alias -> set of ASNs
        self.spelling = {}        # folded company name -> its one spelling
        self.unlisted = {}        # "Unlisted network 3f9a2c" -> the AS number it was given for (masked filters)
        self._un_lock = threading.Lock()
        # set by the app: True when the current request is masked (demo mode, or a role without 'unmasked'). Then a
        # network filter accepts only the demo aliases, never a real company name or AS number, so a viewer cannot test
        # whether a given network is in the data (as HostRefs.strict does for addresses)
        self.strict = lambda: False

    def _load(self):
        # called for every name lookup (tens of thousands per analysis): check the file at most every 5 seconds
        now = time.monotonic()
        if self.mtime is not None and now - getattr(self, "_checked", 0.0) < 5:
            return
        self._checked = now
        try:
            m = filesig.sig(self.path)
        except OSError:
            return
        if m == self.mtime:
            return
        with self.lock:
            try:
                with open(self.path, encoding="utf-8") as f:
                    asns = json.load(f).get("asns", {})
            except (OSError, ValueError) as exc:
                if self.log:
                    self.log.warning("ASN registry not loaded: %s", exc)
                return
            # one alias per company: the alias of its busiest ASN. A company is its name trimmed and case-folded
            # (counting_keys.fold: "Example Telecom " is "Example Telecom"), shown in the spelling of its busiest ASN
            # (count audit round 2, 2026-11-26: the two spellings were two networks with two aliases)
            by_name, spelling = {}, {}
            for a, v in sorted(asns.items(), key=lambda kv: (-kv[1].get("events_last_check", 0), kv[0])):
                k = _ck.fold(v.get("name")) or f"as{a}"
                by_name.setdefault(k, v.get("demo_alias") or f"Network {a}")
                if _ck.clean_name(v.get("name")):
                    spelling.setdefault(k, _ck.clean_name(v.get("name")))
            alias_asns = {}
            for a, v in asns.items():
                alias = by_name[_ck.fold(v.get("name")) or f"as{a}"]
                alias_asns.setdefault(alias, set()).add(a)
            self.asns, self.company_alias, self.alias_asns, self.mtime = asns, by_name, alias_asns, m
            self.spelling = spelling

    def _entry(self, asn):
        a = _ck.norm_asn(asn)
        return a, (self.asns.get(a) or self.asns.get(str(asn)) if a else None)

    def name(self, asn):
        """The company's name in its one spelling (the busiest ASN's, trimmed), or None."""
        self._load()
        a, v = self._entry(asn)
        if not v:
            return None
        k = _ck.fold(v.get("name"))
        return getattr(self, "spelling", {}).get(k) or _ck.clean_name(v.get("name")) or None

    def alias(self, asn):
        self._load()
        a, v = self._entry(asn)
        if not a:
            return ""                     # no network, 0, AS0: unknown, never a network (count audit round 2)
        if not v:
            # each AS number missing from data/asns.json gets its own stable alias (not one "Unlisted network" for
            # all of them, which a filter could not take back: count audit round 2, item 7). The alias is a keyed hash
            # of the number (the masked ids' secret), so it says nothing about the number.
            tag = hmac.new(_ID_SECRET, f"asn:{a}".encode(), hashlib.sha256).hexdigest()[:6]
            al = f"Unlisted network {tag}"
            _keep(self.unlisted, al, a, UNLISTED_MAX, self._un_lock)
            return al
        return self.company_alias.get(_ck.fold(v.get("name")) or f"as{a}", v.get("demo_alias", "Network"))

    def label(self, asn, demo):
        """What to display for an ASN: 'Example Telecom (AS64500)' or 'Telco 1' in demo mode."""
        a = _ck.norm_asn(asn)
        if not a:
            return ""
        if demo:
            return self.alias(a)
        n = self.name(a)
        return f"{n} (AS{a})" if n else f"AS{a}"

    def resolve(self, value):
        """Turn a displayed value (alias, company name or AS number) back into the set of AS numbers it covers.
        Masked requests (strict): aliases only; anything else matches no network."""
        self._load()
        if value == _ck.UNKNOWN_NET:
            # the "Unknown network" row of a list: the records without a network, masked or not (the filters compare
            # through counting_keys.norm_asn, so 0, "AS0", "-" and the like match it too: review 2026-11-27)
            return {"", "0", None}
        if value in self.alias_asns:
            return set(self.alias_asns[value])
        un = getattr(self, "unlisted", {})
        if value in un:
            return {un[value]}
        try:
            strict = self.strict()
        except Exception:      # outside a request
            strict = False
        if strict:
            return {"\x00unknown-alias"}
        k = _ck.fold(value)
        by_name = {a for a, v in self.asns.items() if k and _ck.fold(v.get("name")) == k}
        if by_name:
            return by_name
        a = _ck.norm_asn(value)
        return {a} if a else {str(value).replace("AS", "")}

    def company(self, asn, demo):
        """Grouping key for an ASN: company name (or alias in demo mode); "" for no network (none, 0, AS0)."""
        a = _ck.norm_asn(asn)
        if not a:
            return ""
        return self.alias(a) if demo else (self.name(a) or f"AS{a}")

    def all(self):
        self._load()
        return self.asns


class HostRefs:
    """Opaque, per-process references for source IPs (HMAC), resolvable only on the server."""

    def __init__(self, secret=None):
        self.secret = (secret or os.urandom(16).hex()).encode()
        global _ID_SECRET
        _ID_SECRET = self.secret                # masked_id: the record ids of masked views, under the same secret
        self.to_ip = {}
        self._lock = threading.Lock()
        # set by the app: True when the current request is in demo mode. Then only references this server issued are
        # accepted, never a raw address, so a viewer cannot test whether a given IP is in the data (security report #6)
        self.strict = lambda: False
        import host_label
        host_label.use(self)               # masked views label addresses with these references

    def ref(self, ip):
        if not ip:
            return ""
        r = hmac.new(self.secret, ip.encode(), hashlib.sha256).hexdigest()[:12]
        _keep(self.to_ip, r, ip, REFS_MAX, self._lock)
        return r

    def resolve(self, value):
        # read under the lock that ref() writes under: a reference evicted between "in" and the look-up raised KeyError
        with self._lock:
            if isinstance(value, str) and value.startswith("Host ") and value[5:] in self.to_ip:
                value = value[5:]          # a label copied from a masked view (host_label.py)
            ip = self.to_ip.get(value) if isinstance(value, str) else None
        if ip is not None:
            return ip
        try:
            strict = self.strict()
        except Exception:      # outside a request
            strict = False
        return "\x00unknown-reference" if strict and value else value


_ID_SECRET = os.urandom(16).hex().encode()       # replaced by the server's REF_SECRET when HostRefs is made
_REPORT_FILE = re.compile(r"^(\d{4}-\d{2}-\d{2})-([^-]+)-")


def masked_id(record_id):
    """A record's id as masked viewers get it: still one per record (the page keys its list, pins and highlight on it),
    but no longer the database record ("event4_sinkhole_http:6af0…" -> "ev-3f9a2c41b07e5d1a"). Same secret as the
    host labels, so it stays the same across requests (security test of v2026.11.17.4)."""
    if not record_id:
        return ""
    return "ev-" + hmac.new(_ID_SECRET, str(record_id).encode(), hashlib.sha256).hexdigest()[:16]


def masked_filename(name):
    """A report file's name as masked viewers get it: its date and report type only. Shadowserver adds "details based
    on the organization and filters used to generate the report" (report_schema, report-filename.md), which can name a
    constituent's organisation when reports are filtered per network ("2026-11-16-scan_http-lakeside-asn.csv")
    while the masked view shows that network as "Telco 3" (security test of v2026.11.17.4)."""
    m = _REPORT_FILE.match(str(name or ""))
    return f"{m.group(1)}-{m.group(2)}" if m else ""


def mask_ip(ip):
    """Demo / external masking: an opaque label, "Host 3f9a2c41b07e" (host_label.py). Earlier versions kept the
    2nd and 4th parts (x.161.x.34); in a constituency of a few address blocks that left too few candidates."""
    if not ip:
        return ""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return mask_text(ip)
    import host_label
    return host_label.label(ip)


def mask_text(s):
    """IP addresses inside free text (URLs, banners, cookies...) replaced by the same opaque label."""
    import host_label
    return host_label.label_text(s)


def partial_mask_text(s):
    """The researchers' threat values only (intel.py: C2 URLs and other attacker infrastructure, never a
    constituent's host): addresses keep their 2nd and 4th parts (x.161.x.34), so different C2 servers still tell
    apart without a stable per-host ID, which researchers must never get."""
    if not s or not isinstance(s, str):
        return s
    import ip_find                                 # the one finder every masker shares (external review, 2026-11-12)

    def part(ip):
        if ":" in ip:
            g = ip.split(":")
            return f"x:{g[1] if len(g) > 1 else 'x'}:x:x"
        p = ip.split(".")
        return f"x.{p[1]}.x.{p[3]}"
    return ip_find.sub(s, part)


def mask_event(ev, asns):
    """Return a demo-safe copy of a public event."""
    out = dict(ev)
    for s in ("src", "dst"):
        out[f"{s}_ip"] = mask_ip(ev.get(f"{s}_ip", ""))
        out[f"{s}_asn"] = asns.alias(ev.get(f"{s}_asn")) if ev.get(f"{s}_asn") else ""
        out[f"{s}_asn_name"] = out[f"{s}_asn"]
    for f in HIDE_FIELDS:
        if out.get(f):
            out[f] = "hidden"
    for f in ("http_url", "http_host", "http_referer", "http_agent", "ssl_servername", "detail"):
        out[f] = mask_text(out.get(f, ""))
    # the report file: date and type only; the record: an id that is not the database record (masked_filename/_id)
    out["filename"] = masked_filename(ev.get("filename"))
    out["id"] = masked_id(ev.get("id"))
    # an encoded beacon in the request decodes to the device's MAC, UUID and CPU id (beacon_decode.py): replaced
    import beacon_decode
    out["http_url"] = beacon_decode.mask_url(out["http_url"])
    # the line hash is a hash of the raw report line: anyone holding a guess of the line (an address, a port, a
    # time) can hash it and confirm the address; the event ID is an ID. Neither is sent (review 2026-11-13)
    for f in ("line_hash", "event_id", "_id"):
        out.pop(f, None)
    # report-specific fields: an allowlist (masked_fields.py), so user names, passwords, banners, paths and any field
    # a report adds later stay hidden; the fields shown are masked for hosts, addresses, e-mails, dates and IDs
    import masked_fields
    out["extras"], out["extras_hidden"] = masked_fields.event_extras(ev.get("extras"))
    out["demo"] = True
    return out
