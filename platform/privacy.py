"""ASN -> company names, and demo-mode masking for public presentations.

* data/asns.json maps AS numbers to a display name, a network type and a stable demo alias
  ("Telco 1", "Institution 3", "Provider 2", ...). It is re-read automatically when it changes.
  ASNs that belong to the same company (same name) share one alias, e.g. an operator's AS64500 and AS64501.
* Demo mode is applied on the server, so concealed values never reach the browser:
  AS numbers and company names become aliases, IP addresses lose their first and third parts
  (x.161.x.34, so neither the owner nor the network range can be looked up), hostnames and machine names are removed, and IP addresses inside any other text
  field (URLs, cookies, banners ...) are masked. Locations are kept.
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
        """Turn a displayed value (alias or AS number) back into the set of AS numbers it covers."""
        self._load()
        if value in self.alias_asns:
            return set(self.alias_asns[value])
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

    def ref(self, ip):
        if not ip:
            return ""
        r = hmac.new(self.secret, ip.encode(), hashlib.sha256).hexdigest()[:12]
        if len(self.to_ip) > 500000:
            self.to_ip.clear()
        self.to_ip[r] = ip
        return r

    def resolve(self, value):
        if value in self.to_ip:
            return self.to_ip[value]
        try:
            strict = self.strict()
        except Exception:      # outside a request
            strict = False
        return "\x00unknown-reference" if strict and value else value


def mask_ip(ip):
    """Demo / external masking. The FIRST and THIRD parts are hidden: x.161.x.34. Keeping the leading octets
    (154.161.x.x) would leave the network prefix, which a WHOIS / BGP lookup turns into the owner and its range;
    without the first and third octets neither the owner nor the CIDR range can be looked up.
    IPv6: x:f0f8:x:x:x:x:x:1a2b (first and third groups hidden, and the middle of the address)."""
    if not ip:
        return ""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return mask_text(ip)
    if a.version == 4:
        p = str(a).split(".")
        return f"x.{p[1]}.x.{p[3]}"
    p = a.exploded.split(":")
    return f"x:{p[1]}:x:x:x:x:x:{p[7]}"


def mask_text(s):
    """IP addresses inside free text (URLs, banners, cookies...) masked the same way."""
    if not s or not isinstance(s, str):
        return s
    s = IPV4_FULL.sub(lambda m: f"x.{m.group(2)}.x.{m.group(4)}", s)
    return IPV6.sub(lambda m: f"x:{m.group(2)}:x:x", s)


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
    out["extras"] = {k: mask_text(v) for k, v in (ev.get("extras") or {}).items()}
    out["demo"] = True
    return out
