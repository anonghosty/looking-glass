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
import json
import os
import re
import threading
import time

IPV4 = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b")
IPV4_FULL = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
IPV6 = re.compile(r"\b([0-9a-fA-F]{1,4}):([0-9a-fA-F]{1,4}):[0-9a-fA-F:]{2,}\b")
HIDE_FIELDS = ("src_hostname", "dst_hostname", "machine_name")


class AsnRegistry:
    def __init__(self, path, logger=None):
        self.path = path
        self.log = logger
        self.lock = threading.Lock()
        self.mtime = None
        self.asns = {}
        self.company_alias = {}   # name -> alias shared by all ASNs of that company
        self.alias_asns = {}      # alias -> set of ASNs
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
            m = os.path.getmtime(self.path)
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
            # one alias per company: the alias of its busiest ASN
            by_name = {}
            for a, v in sorted(asns.items(), key=lambda kv: -kv[1].get("events_last_check", 0)):
                by_name.setdefault(v.get("name") or f"AS{a}", v.get("demo_alias") or f"Network {a}")
            alias_asns = {}
            for a, v in asns.items():
                alias = by_name[v.get("name") or f"AS{a}"]
                alias_asns.setdefault(alias, set()).add(a)
            self.asns, self.company_alias, self.alias_asns, self.mtime = asns, by_name, alias_asns, m

    def name(self, asn):
        self._load()
        v = self.asns.get(str(asn))
        return v.get("name") if v else None

    def alias(self, asn):
        self._load()
        v = self.asns.get(str(asn))
        if not v:
            return "Unlisted network" if asn else ""
        return self.company_alias.get(v.get("name") or f"AS{asn}", v.get("demo_alias", "Network"))

    def label(self, asn, demo):
        """What to display for an ASN: 'Example Telecom (AS64500)' or 'Telco 1' in demo mode."""
        if not asn:
            return ""
        if demo:
            return self.alias(asn)
        n = self.name(asn)
        return f"{n} (AS{asn})" if n else f"AS{asn}"

    def resolve(self, value):
        """Turn a displayed value (alias, company name or AS number) back into the set of AS numbers it covers.
        Masked requests (strict): aliases only; anything else matches no network."""
        self._load()
        if value in self.alias_asns:
            return set(self.alias_asns[value])
        try:
            strict = self.strict()
        except Exception:      # outside a request
            strict = False
        if strict:
            return {"\x00unknown-alias"}
        by_name = {a for a, v in self.asns.items() if v.get("name") == value}
        if by_name:
            return by_name
        return {str(value).replace("AS", "")}

    def company(self, asn, demo):
        """Grouping key for an ASN: company name (or alias in demo mode)."""
        if not asn:
            return ""
        return self.alias(asn) if demo else (self.name(asn) or f"AS{asn}")

    def all(self):
        self._load()
        return self.asns


class HostRefs:
    """Opaque, per-process references for source IPs (HMAC), resolvable only on the server."""

    def __init__(self, secret=None):
        self.secret = (secret or os.urandom(16).hex()).encode()
        self.to_ip = {}
        # set by the app: True when the current request is in demo mode. Then only references this server issued are
        # accepted, never a raw address, so a viewer cannot test whether a given IP is in the data (security report #6)
        self.strict = lambda: False
        import host_label
        host_label.use(self)               # masked views label addresses with these references

    def ref(self, ip):
        if not ip:
            return ""
        r = hmac.new(self.secret, ip.encode(), hashlib.sha256).hexdigest()[:12]
        if len(self.to_ip) > 500000:
            self.to_ip.clear()
        self.to_ip[r] = ip
        return r

    def resolve(self, value):
        if isinstance(value, str) and value.startswith("Host ") and value[5:] in self.to_ip:
            value = value[5:]              # a label copied from a masked view (host_label.py)
        if value in self.to_ip:
            return self.to_ip[value]
        try:
            strict = self.strict()
        except Exception:      # outside a request
            strict = False
        return "\x00unknown-reference" if strict and value else value


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
    for f in ("http_url", "http_host", "http_referer", "http_agent", "ssl_servername", "detail", "filename"):
        out[f] = mask_text(out.get(f, ""))
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
