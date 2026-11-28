# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shared by tests/verify_*.py: independent re-derivation of both platforms' records straight from MongoDB (own code, not the platform's).
The buckets follow the one counting rule (counting_keys.py, 2026-11-26), whose KEYS come from there (Keys below): a row
in two files of one report day is read once (row_key), regions in their one spelling (region_key), networks by company,
Sectors = the network type of data/asns.json (read here), Shadowserver's own `sector` column = the industry."""
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(1, BASE_DIR)
import counting_keys as CK  # noqa: E402  the keys of the one counting rule (not the platforms' code)


class Keys:
    """The one rule's buckets for this installation, configured from its own files as app.py configures them:
    sector(asn), network(asn) (a company, folded; UNKNOWN_NET folded for none, 0, AS0), region(value), industry(value)."""

    def __init__(self, base=BASE_DIR):
        import netypes
        CK.configure_from_base(base)
        try:
            with open(os.path.join(base, "data", "asns.json"), encoding="utf-8") as fh:
                self.asns = json.load(fh).get("asns", {}) or {}
        except (OSError, ValueError):
            self.asns = {}
        self.labels = netypes.labels(os.path.join(base, "data"))
        self.UNKNOWN_NET = CK.fold(CK.UNKNOWN_NET)
        self.UNKNOWN_REGION = CK.UNKNOWN_REGION
        self.UNKNOWN_SECTOR = CK.sector_of("", self.asns, self.labels)
        self._m = {}

    def company(self, a, masked=False):
        """network_of's registry: a company is its name trimmed and case-folded, or the AS number alone without one."""
        v = self.asns.get(a) or {}
        return CK.fold(v.get("name")) or f"as{a}"

    def _memo(self, kind, v, f):
        k = (kind, v)
        r = self._m.get(k)
        if r is None:
            r = self._m[k] = f(v)
        return r

    def sector(self, asn):
        return self._memo("s", asn, lambda a: CK.sector_of(a, self.asns, self.labels))

    def network(self, asn):
        return self._memo("n", asn, lambda a: CK.fold(CK.network_of(a, self) or CK.UNKNOWN_NET))

    def region(self, v):
        return self._memo("r", v, CK.region_key)

    @staticmethod
    def industry(v):
        return CK.industry_of(v)

    @staticmethod
    def fold(v):
        return CK.fold(v)

CLASS_RULES = [(r"ddos", "DDoS"), (r"brute_force", "Brute force"), (r"initial_access", "Initial access"),
               (r"spoof", "IP spoofing"), (r"spam", "Spam"), (r"sinkhole|drone", "Botnet C2"), (r"scan|darknet", "Scanning")]
klass = lambda n: next((l for p, l in CLASS_RULES if re.search(p, n)), "Other")
FAM = [(r"^compromised_", "Compromised"), (r"^blocklist", "Blocklisted"), (r"^device_id", "Identified device"),
       (r"^scan6?_", "Exposed service"), (r"^population6?_", "Service population")]
fam = lambda n: next((f for p, f in FAM if re.match(p, n)), "Other")
MARK = {"exposed-admin-panel": "Exposed admin panel", "device-implant": "Device implant", "badcandy": "Badcandy",
        "cpanel-compromised": "Cpanel compromised", "open-dir": "Open dir", "vulnerable": "Vulnerable"}


def S(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(v)


class Once:
    """first(collection, doc): True for the first copy of a row (counting_keys.row_key: collection, report day from
    the file name, line hash); a row without a line hash is always its own row. .dups counts the copies left out."""

    def __init__(self):
        self.seen, self.dups = set(), 0

    def first(self, collection, d):
        k = CK.row_key(collection, d.get("filename"), d.get("line_hash"))
        if k is None:
            return True
        if k in self.seen:
            self.dups += 1
            return False
        self.seen.add(k)
        return True


# the same key inside MongoDB (an aggregation of one collection): report day + line hash, or the document itself
_LH = {"$toString": {"$ifNull": ["$line_hash", ""]}}
ROW_EXPR = {"$cond": [{"$gt": [{"$strLenCP": _LH}, 0]},
                      {"d": {"$substrCP": [{"$toString": {"$ifNull": ["$filename", ""]}}, 0, 10]}, "h": _LH}, "$_id"]}


def count_rows(coll, match):
    """The documents of one collection matching `match`, a row sent in two files of one report day counted once."""
    r = list(coll.aggregate([{"$match": match}, {"$group": {"_id": ROW_EXPR}}, {"$count": "n"}], allowDiskUse=True))
    return r[0]["n"] if r else 0


def day_docs(db, names, start):
    """The day's rows (files dated the day or the next, timed inside the day), each row once however many files of one
    report day carry it (counting_keys.row_key: collection, report day, line hash)."""
    end = start + timedelta(days=1)
    pre = (start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d"))
    once = Once()
    for n in names:
        for d in db[n].find({"$or": [{"filename": {"$regex": "^" + p}} for p in pre]}):
            ed = d.get("extracted_date")
            if isinstance(ed, str):
                try:
                    ed = datetime.fromisoformat(ed.replace("Z", "+00:00"))
                except ValueError:
                    continue
            if not isinstance(ed, datetime):
                continue
            if ed.tzinfo is None:
                ed = ed.replace(tzinfo=timezone.utc)
            if start <= ed < end and once.first(n, d):
                yield n, d, ed.timestamp()


def comms(db, names, layouts, start):
    out = []
    for n, d, t in day_docs(db, names, start):
        lay = layouts.get(n, "standard")
        g = lambda k: S(d.get(k))
        if lay == "legacy":
            src = lambda p: S(d.get(p.replace("src_", "")))
        else:
            src = lambda p: S(d.get(p))
        dst = (lambda p: S(d.get(p)) or S(d.get(p.replace("dst_", "")))) if lay == "inbound" else (lambda p: S(d.get(p)))
        inf = g("infection") or (g("type") if lay == "legacy" and g("type").lower() not in ("tcp", "udp", "icmp", "sctp") else "") \
            or g("family") or g("tag") or g("application") or n
        out.append({"source": n, "attack_class": klass(n), "src_ip": src("src_ip"), "src_asn": src("src_asn"),
                    "src_region": src("src_region"), "src_city": src("src_city"), "severity": g("severity"),
                    "dst_geo": dst("dst_geo"), "dst_ip": dst("dst_ip") or S(d.get("dst_network")).split("/")[0],
                    "http_host": g("http_host"), "infection": inf, "_t": t})
    return out


def services(db, names, labels, start):
    out = []
    for n, d, t in day_docs(db, names, start):
        tags = [x.strip() for x in S(d.get("tag")).replace(",", ";").split(";") if x.strip()]
        issues = [x.upper() for x in tags if x.lower().startswith("cve-")]
        if S(d.get("ssl_poodle")).upper() == "Y": issues.append("POODLE (SSLv3)")
        if S(d.get("freak_vulnerable")).upper() == "Y": issues.append("FREAK")
        if S(d.get("cert_expired")).upper() == "Y": issues.append("Expired certificate")
        issues += [MARK[x] for x in tags if x in MARK]
        if S(d.get("device_type")).strip().lower() == "ai-attack-framework" and "AI attack framework" not in issues:
            issues.append("AI attack framework")       # an issue by its device type (2026-11-17), written out here again
        if fam(n) == "Compromised" and not issues:
            issues.append("Compromised")
        out.append({"ip": S(d.get("ip")), "asn": S(d.get("asn")), "region": S(d.get("region")), "city": S(d.get("city")),
                    "severity": S(d.get("severity")).strip().lower(), "issues": issues, "tags": tags,
                    "report": n, "family": fam(n), "service": labels.get(n, n), "vendor": S(d.get("device_vendor")),
                    "sector": S(d.get("sector")), "_t": t})
    return out


def title(s):
    return " ".join(w.capitalize() if not w.isupper() or len(w) > 3 else w for w in str(s or "").lower().split()) if s else ""
