"""Settings shared by both platforms (network communications map and publicly accessible / vulnerable services).

  country       ISO-3166 alpha-2 code of the country the CSIRT covers (default GH). The services platform draws
                that country's regions (static/data/adm1/<ISO2>.json) and labels; region values equal to the
                country name mean "region unknown".
  networks      the constituency: AS numbers the CSIRT is responsible for. Empty = the whole country (everything
                in the reports).
  cidrs         extra address ranges in the constituency (for example a government network without its own AS).

A record is in the constituency when its host's AS number is in `networks` or its address is in `cidrs`
(communications: the source or the destination side). Both platforms apply this while loading a day, so every
figure, list, analysis and export reflects it.

Defaults come from the environment (.env) at deployment: COUNTRY, CONSTITUENT_ASNS (comma separated AS numbers),
CONSTITUENT_CIDRS. Saving on the /settings page writes data/settings.json, which then takes precedence.
"""
import ipaddress
import json
import os
import threading
import time

import timezones


def _csv(v):
    return [x.strip() for x in (v or "").split(",") if x.strip()]


class Settings:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.version = 0
        self.data = self._defaults()
        self._load()
        self._compile()

    @staticmethod
    def _defaults():
        country = (os.environ.get("COUNTRY") or "GH").upper()
        zone = os.environ.get("TIMEZONE") or timezones.default_zone(country)
        return {"country": country,
                "timezone": zone if timezones.valid(country, zone) else timezones.default_zone(country),
                "networks": [a.upper().replace("AS", "") for a in _csv(os.environ.get("CONSTITUENT_ASNS"))],
                "cidrs": _csv(os.environ.get("CONSTITUENT_CIDRS")),
                "updated_at": None, "source": "environment (.env)"}

    def _load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as f:
                saved = json.load(f)
            self.data.update({k: saved[k] for k in ("country", "timezone", "networks", "cidrs", "updated_at") if k in saved})
            self.data["source"] = "settings page (data/settings.json)"
        except (OSError, ValueError):
            pass
        # a file saved before time zones existed, or a zone not (or no longer) offered: the country's usual zone
        if not timezones.valid(self.data["country"], self.data.get("timezone")):
            self.data["timezone"] = timezones.default_zone(self.data["country"])

    def _compile(self):
        self.asns = {str(a) for a in self.data["networks"]}
        nets = []
        for c in self.data["cidrs"]:
            try:
                nets.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass
        self.nets = nets
        self.restricted = bool(self.asns or self.nets)

    MAX_NETWORKS, MAX_CIDRS = 2000, 500

    @staticmethod
    def validate(d, countries=None):
        """Clean a submitted settings dict; returns (clean, errors). `countries`: the accepted country codes."""
        errors = []
        country = str(d.get("country") or "GH").upper()
        if len(country) != 2 or not country.isalpha():
            errors.append("country must be a two-letter code")
        elif countries and country not in countries:
            errors.append(f"country {country} is not one of the {len(countries)} countries with region maps")
        # the time zone: one of the country's own (or UTC); not given = the country's usual zone
        zone = d.get("timezone")
        if zone in (None, ""):
            zone = timezones.default_zone(country)
        elif not isinstance(zone, str) or not timezones.valid(country, zone):
            errors.append(f"time zone must be one of {', '.join(timezones.choices(country))} for {country}")
            zone = timezones.default_zone(country)
        base = {"country": country, "timezone": zone, "networks": [], "cidrs": []}
        if not isinstance(d.get("networks") or [], list) or not isinstance(d.get("cidrs") or [], list):
            errors.append("networks and cidrs must be lists")
            return base, errors
        if len(d.get("networks") or []) > Settings.MAX_NETWORKS:
            errors.append(f"at most {Settings.MAX_NETWORKS} AS numbers")
        if len(d.get("cidrs") or []) > Settings.MAX_CIDRS:
            errors.append(f"at most {Settings.MAX_CIDRS} address ranges")
        if errors:
            return base, errors
        networks = []
        for a in d.get("networks") or []:
            a = str(a).upper().replace("AS", "").strip()
            if a.isdigit():
                networks.append(a)
            elif a:
                errors.append(f"not an AS number: {a}")
        cidrs = []
        for c in d.get("cidrs") or []:
            c = str(c).strip()
            if not c:
                continue
            try:
                cidrs.append(str(ipaddress.ip_network(c, strict=False)))
            except ValueError:
                errors.append(f"not an address range: {c}")
        return {"country": country, "timezone": zone, "networks": sorted(set(networks), key=int), "cidrs": cidrs}, errors

    def save(self, clean):
        with self.lock:
            self.data.update(clean, updated_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), source="settings page (data/settings.json)")
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({k: self.data[k] for k in ("country", "timezone", "networks", "cidrs", "updated_at")}, f, indent=2)
            os.replace(tmp, self.path)
            self._compile()
            self.version += 1

    def in_scope(self, asn, ip):
        """Is a host (AS number, address) in the constituency? Always true without a restriction."""
        if not self.restricted:
            return True
        if asn and str(asn) in self.asns:
            return True
        if ip and self.nets:
            try:
                a = ipaddress.ip_address(ip)
            except ValueError:
                return False
            return any(a in n for n in self.nets if n.version == a.version)
        return False

    def public(self):
        return {**self.data, "restricted": self.restricted, "version": self.version}

    def tz(self, at=None):
        """The display time zone at a moment (timezones.info): {"zone", "city", "offset", "same_as_utc", ...}."""
        return timezones.info(self.data.get("timezone") or timezones.UTC_NAME, at)
