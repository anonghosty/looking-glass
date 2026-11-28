# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""One rule for the buckets every page counts in: sector, region, network and "is this row the same row" (count audit,
round 2, 2026-11-26). Before, the Executive portal, the quarterly report, the services page and the advisory each had
their own: the same host landed in "Telco / ISP" on one page and in Shadowserver's "Communications" on another,
"ELGEYO-MARAKWET" was "Elgeyo-marakwet" here and "Elgeyo-Marakwet" there, AS0 was a network on one page and unknown on
the next, and a row sent in two files of one day (a geo and an ASN subscription) counted twice.

  sector_of(asn, reg_all, labels)    the network type of the company (data/asns.json), by its label; "Unknown"
                                     Shadowserver's own `sector` column is shown as "Industry (Shadowserver)"
  network_of(asn, registry, masked)  the company (or its demo alias); "" for an unknown network (no number, 0, AS0)
  norm_asn(v)                        "AS064500" -> "64500"; "", None, "0", "AS0", anything not a number -> ""
  fold(name)                         the grouping form of a name: trimmed, inner spaces collapsed, case-folded
  region_key(value, country=None)    the region as every page groups and shows it: the administrator's region matches
                                     (region_matches.py), then the country's map, then the country-name rule ("KENYA"
                                     alone is the country: Unknown region); one spelling per region
  row_key(collection, filename, line_hash)   (collection, report day, line hash): one row however many files carry it
  window(ed, start, end)             "in" / "outside" / "undated": where a row's time puts it against a day

configure(...) is called once by app.py; until then (a test, a script) regions are worked out without a map.
"""
import json
import os
import re
import threading
import time

UNKNOWN_NET = "Unknown network"
UNKNOWN_REGION = "Unknown region"
UNKNOWN_SECTOR = "Unknown"
INDUSTRY_LABEL = "Industry (Shadowserver)"
SECTOR_LABEL = "Sectors (network type)"


# ------------------------------------------------------------------ networks
def norm_asn(v):
    """An AS number as a plain string of digits without leading zeros, or "" when there is none (0 is no network)."""
    if v is None or v is False:
        return ""
    if isinstance(v, float):
        if v != v:                                   # NaN
            return ""
        v = int(v)
    s = str(v).strip().upper()
    if s.startswith("AS"):
        s = s[2:].strip()
    if not s.isdigit():
        return ""
    s = s.lstrip("0")
    return s


def clean_name(name):
    """A name as shown: trimmed, inner spaces collapsed (its usual spelling otherwise kept)."""
    return re.sub(r"\s+", " ", str(name or "")).strip()


def fold(name):
    """The grouping form of a name: "Example Telecom " and "example  telecom" are one company."""
    return clean_name(name).casefold()


def network_of(asn, registry, masked=False):
    """The company of an AS number as every page groups networks (AsnRegistry.company: names folded, one spelling);
    "" when the record has no network. Count "" apart as UNKNOWN_NET, never as a network."""
    a = norm_asn(asn)
    if not a:
        return ""
    try:
        return registry.company(a, masked) or ""
    except Exception:                                # noqa: BLE001  (a stub registry in a test)
        return f"AS{a}"


def network_label(asn, registry, masked=False):
    """network_of, with UNKNOWN_NET for a record without a network (a row in a list)."""
    return network_of(asn, registry, masked) or UNKNOWN_NET


# ------------------------------------------------------------------ sectors
def sector_of(asn, reg_all, labels):
    """The sector of a record: the network type of its AS number in data/asns.json, by its label (netypes.py).
    reg_all: {asn: {"type": ...}} (AsnRegistry.all()); labels: {type key: label} (netypes.labels). A record without a
    network, a network without a type, or a type no longer defined (a custom type deleted in Settings): "Unknown"."""
    a = norm_asn(asn)
    v = (reg_all.get(a) or reg_all.get(str(asn)) or {}) if a else {}
    t = (v.get("type") or "unknown") if isinstance(v, dict) else "unknown"
    return labels.get(t) or labels.get("unknown") or UNKNOWN_SECTOR


class Sectors:
    """sector_of for many records: worked out once per AS number, again when the registry or the types change."""

    def __init__(self, reg_all, labels):
        self.reg, self.labels, self.memo = reg_all, labels, {}

    def __call__(self, asn):
        r = self.memo.get(asn)
        if r is None:
            r = self.memo[asn] = sector_of(asn, self.reg, self.labels)
        return r


_SEC = {"obj": None, "t": 0.0, "key": None, "lock": threading.Lock()}


def sector_now(asn, registry=None, type_labels=None):
    """sector_of with the platform's own registry and network types (configure(registry=, type_labels=)), for code
    that sees one record at a time (a filter): the registry and the types are read again at most once a second."""
    reg = registry if registry is not None else _CFG.get("registry")
    tl = type_labels if type_labels is not None else _CFG.get("type_labels")
    if reg is None:
        return UNKNOWN_SECTOR
    now = time.monotonic()
    key = (id(reg), id(tl))
    obj = _SEC["obj"]
    if obj is None or _SEC["key"] != key or now - _SEC["t"] > 1:
        with _SEC["lock"]:
            try:
                if tl is not None:
                    labels = tl()
                else:
                    import netypes
                    labels = netypes.labels(os.path.dirname(getattr(reg, "path", "") or "."))
                obj = Sectors(reg.all(), labels)
            except Exception:                        # noqa: BLE001  (a registry being rewritten: the last one)
                obj = _SEC["obj"] or Sectors({}, {})
            _SEC.update(obj=obj, t=now, key=key)
    return obj(asn)


def industry_of(value):
    """Shadowserver's own `sector` column as shown under "Industry (Shadowserver)": "" when the report gives none."""
    return clean_name(value)


# ------------------------------------------------------------------ regions
def smart_title(s):
    """"MURANG'A" -> "Murang'a", "ELGEYO-MARAKWET" -> "Elgeyo-Marakwet", "NAIROBI  AREA" -> "Nairobi Area"."""
    words = clean_name(s).split(" ")
    out = []
    for w in words:
        out.append("-".join("/".join(p[:1].upper() + p[1:].lower() for p in part.split("/")) for part in w.split("-")))
    return " ".join(x for x in out if x)


_CFG = {"country": None, "adm1": None, "data": None, "names": None}
_ST = {"lock": threading.Lock(), "sig": None, "checked": 0.0, "find": None, "regions": {}, "memo": {}, "cc": ""}


def configure(country=None, adm1_dir=None, data_dir=None, country_names=None, registry=None, type_labels=None):
    """country(): the ISO code of the country (Settings); adm1_dir: static/data/adm1; data_dir: the platform's data folder
    (region_matches.json); country_names(cc): the country's own spellings (index.json); registry: the AsnRegistry and
    type_labels(): the network types' labels (sector_now)."""
    _CFG.update(country=country, adm1=adm1_dir, data=data_dir, names=country_names, registry=registry, type_labels=type_labels)
    _SEC.update(obj=None)
    with _ST["lock"]:
        _ST.update(sig=None, checked=0.0, memo={})


def default_registry(registry):
    """The registry sector_now() uses when configure() named none (a module registered on its own, a test)."""
    if _CFG.get("registry") is None and registry is not None:
        _CFG["registry"] = registry
        _SEC.update(obj=None)


def configured():
    return _CFG["country"] is not None


def configure_from_base(base):
    """For a run outside the platform (the quarterly report made by a script): the same files the platform reads."""
    if configured():
        return
    adm1 = os.path.join(base, "static", "data", "adm1")

    def country():
        try:
            with open(os.path.join(base, "data", "settings.json"), encoding="utf-8") as fh:
                return str(json.load(fh).get("country") or "").upper()
        except (OSError, ValueError):
            return ""

    def names(cc):
        try:
            with open(os.path.join(adm1, "index.json"), encoding="utf-8") as fh:
                c = (json.load(fh).get("countries") or {}).get(cc) or {}
            return [c.get("country", "")] + list(c.get("names") or [])
        except (OSError, ValueError):
            return []
    configure(country, adm1, os.path.join(base, "data"), names)


def _sig_of(path):
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except (OSError, TypeError):
        return None


def _finder():
    """The resolver of the configured country (map + the administrator's matches + country names), rebuilt when one
    of them changes (checked at most once a second: this runs for every record)."""
    now = time.monotonic()
    if _ST["find"] is not None and now - _ST["checked"] < 1:
        return _ST["find"]
    import region_matches as RM
    try:
        cc = str((_CFG["country"] or (lambda: ""))() or "").upper()
    except Exception:                                # noqa: BLE001
        cc = ""
    mpath = os.path.join(_CFG["adm1"], f"{cc}.json") if _CFG["adm1"] and re.fullmatch(r"[A-Z]{2}", cc) else None
    cpath = os.path.join(_CFG["data"], "region_matches.json") if _CFG["data"] else None
    sig = (cc, _sig_of(mpath), _sig_of(cpath))
    with _ST["lock"]:
        _ST["checked"] = now
        if sig == _ST["sig"] and _ST["find"] is not None:
            return _ST["find"]
        file = None
        if mpath:
            try:
                with open(mpath, encoding="utf-8") as fh:
                    file = json.load(fh)
            except (OSError, ValueError):
                file = None
        chosen = {}
        if cpath:
            try:
                with open(cpath, encoding="utf-8") as fh:
                    d = json.load(fh)
                chosen = dict((d or {}).get(cc) or {}) if isinstance(d, dict) else {}
            except (OSError, ValueError):
                chosen = {}
        try:
            names = [n for n in ((_CFG["names"] or (lambda c: []))(cc) or []) if n]
        except Exception:                            # noqa: BLE001
            names = []
        _ST.update(sig=sig, find=RM.resolver(file, chosen, names), regions=(file or {}).get("regions") or {}, memo={}, cc=cc)
        return _ST["find"]


def region_key(value, country=None):
    """The region of a record as every page groups and shows it (one spelling): the map's own name of the region the
    value resolves to, UNKNOWN_REGION when there is none or it is the country itself, else the value in title case
    (accents, case and suffixes such as "County" folded the same way as the maps do: region_matches.norm)."""
    if value is None:
        return UNKNOWN_REGION
    v = str(value)
    if not v.strip() or v == UNKNOWN_REGION:
        return UNKNOWN_REGION
    find = _finder()
    import region_matches as RM
    if country and str(country).upper() != _ST["cc"]:
        # another country's region (a destination abroad): no map of ours applies, the same title rule
        n = RM.norm(v)
        return smart_title(n) if n else UNKNOWN_REGION
    memo = _ST["memo"]
    hit = memo.get(v)
    if hit is not None:
        return hit
    key = find(v)
    if key == RM.COUNTRY:
        out = UNKNOWN_REGION
    elif key:
        out = clean_name((_ST["regions"].get(key) or {}).get("name")) or smart_title(key)
    else:
        n = RM.norm(v)
        out = smart_title(n) if n else UNKNOWN_REGION
    if len(memo) > 50000:
        memo.clear()
    memo[v] = out
    return out


def is_unknown_region(label):
    return not label or label == UNKNOWN_REGION


def regions_version():
    """Changes when the map, the matches or the country change (a part of cached answers' keys)."""
    _finder()
    return _ST["sig"]


# ------------------------------------------------------------------ rows
def row_key(collection, filename, line_hash):
    """One stored row, however many files of the same report day carry it (a country file and an ASN file of one day:
    "2026-11-20-scan_http-kenya-geo.csv" and "2026-11-20-scan_http-lakeside-asn.csv"). None when the row has no line
    hash (never merged with another)."""
    if not line_hash:
        return None
    return (collection, str(filename or "")[:10], str(line_hash))


class Dedup:
    """Keeps the first copy of each row_key, O(1) per row; .dups counts the copies left out."""

    def __init__(self):
        self.seen, self.dups = set(), 0

    def first(self, collection, filename, line_hash):
        k = row_key(collection, filename, line_hash)
        if k is None:
            return True
        if k in self.seen:
            self.dups += 1
            return False
        self.seen.add(k)
        return True


class Rows(list):
    """A day loader's rows of one report, with what it left out: dups (copies in another file of the same report day),
    outside / undated (rows of the day's own report file dated outside the days it can be shown on / without a time)."""

    def __init__(self, rows=(), dups=0, outside=0, undated=0):
        super().__init__(rows)
        self.dups, self.outside, self.undated = dups, outside, undated


def notes_of(by_src):
    """{dups, outside, undated} summed over a loaded day's reports (by_src: name -> {"dups", "outside", "undated"})."""
    out = {"dups": 0, "outside": 0, "undated": 0}
    for b in (by_src or {}).values():
        for k in out:
            out[k] += int((b or {}).get(k) or 0)
    return out


def window(ed, start, end):
    """"in" when start <= ed < end, "undated" when the row has no time, else "outside"."""
    if ed is None:
        return "undated"
    return "in" if start <= ed < end else "outside"


def load_note(dups=0, outside=0, undated=0, day=""):
    """The sentence a page shows beside its load figures; "" when there is nothing to say."""
    parts = []
    if dups:
        parts.append(f"{dups:,} row{'s' if dups != 1 else ''} also in another file that day (counted once)")
    if outside:
        parts.append(f"{outside:,} row{'s' if outside != 1 else ''} of this day's report files "
                     f"{'are' if outside != 1 else 'is'} dated outside {day or 'this day'} (not shown on any day)")
    if undated:
        parts.append(f"{undated:,} row{'s' if undated != 1 else ''} of this day's report files "
                     f"{'have' if undated != 1 else 'has'} no time (not shown on any day)")
    return ("; ".join(parts) + ".") if parts else ""
