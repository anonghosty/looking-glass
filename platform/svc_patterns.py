"""Pattern fields of the publicly accessible / vulnerable services reports: which fields of a report make patterns for
researchers, and what each record gives (used by services_intel.py).

* data/pattern_fields.json (shipped, replaced by updates): per report the identity fields that cluster hosts in a way
  that means something, chosen from real data; the tag field for every report; fields that are never pattern fields
  (they name or locate a host).
* data/pattern_fields_local.json (this site, kept on updates): a researcher's own choice per report (signed, dated);
  it replaces the shipped one for that report.
* data/product_rules.json + data/product_rules_local.json: how to read a product and its version out of a response.

kinds: exact (the value as it is), template (text with what names a host masked: hostmask.py; a hex / binary response
stays as it is), product (product + version by the rules; nothing when no rule matches), tags (the tag field as a set,
its CVEs left to Issues). items(report, record) -> [(label, value)]. suggest(report, records) -> how each field of the
report groups hosts, and whether it may be a pattern field. Researchers see only values that MIN_HOSTS hosts share.
"""
import collections
import json
import os
import re
import threading
import time

import hostmask
from report_map import sibling

MIN_HOSTS = 5
HEX = re.compile(r"^(?:0x)?[0-9a-f]{8,}$", re.I)
CVE = re.compile(r"(?i)^cve-\d{4}-\d{4,7}$")
VERSION = re.compile(r"\d+(?:\.\d+)+[\w.()+-]*|\d{4}\.\d+")
KINDS = ("exact", "template", "product", "tags")
# where a field of the raw report sits in a services record (services.normalise_service)
MAPPED = {"device_vendor": "vendor", "device_type": "device_type", "version": "version", "port": "port", "protocol": "protocol",
          "tag": "tag", "severity": "severity"}


def _read(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def field_value(e, field):
    """A raw report field from a services record (some are normalised, the rest are kept in extras)."""
    if field == "device_model":
        return e.get("product") if e.get("report", "").startswith("device_id") else (e.get("extras") or {}).get(field)
    if field in MAPPED:
        return e.get(MAPPED[field])
    return (e.get("extras") or {}).get(field)


class Patterns:
    def __init__(self, base_dir):
        d = os.path.join(base_dir, "data")
        self.paths = {"fields": os.path.join(d, "pattern_fields.json"), "local": os.path.join(d, "pattern_fields_local.json"),
                      "rules": os.path.join(d, "product_rules.json"), "rules_local": os.path.join(d, "product_rules_local.json")}
        self.lock = threading.Lock()
        self._c = {}

    # ---- configuration (files re-read when they change)
    def _load(self, key, default):
        p = self.paths[key]
        try:
            m = os.path.getmtime(p)
        except OSError:
            m = None
        c = self._c.get(key)
        if not c or c[0] != m:
            c = (m, _read(p, default))
            self._c[key] = c
        return c[1]

    def shipped(self):
        return self._load("fields", {"reports": {}, "all_reports": [], "never": [], "never_patterns": []})

    def local(self):
        return self._load("local", {"reports": {}})

    def rules(self):
        own = (self._load("rules_local", {"rules": []}) or {}).get("rules") or []
        return own + ((self._load("rules", {"rules": []}) or {}).get("rules") or [])

    def never(self, field):
        s = self.shipped()
        return field in set(s.get("never") or []) or any(re.search(p, field) for p in s.get("never_patterns") or [])

    def fields_for(self, report):
        """[{field, kind, label}] for a report: the researcher's choice, else the shipped one; the tag field always."""
        base = sibling(report)
        own = (self.local().get("reports") or {}).get(base)
        chosen = own["fields"] if own else (self.shipped().get("reports") or {}).get(base, [])
        out, seen = [], set()
        for f in list(chosen) + list(self.shipped().get("all_reports") or []):
            k = (f.get("field"), f.get("kind"))
            if k in seen or not f.get("field") or f.get("kind") not in KINDS or self.never(f["field"]):
                continue
            seen.add(k)
            out.append({"field": f["field"], "kind": f["kind"], "label": f.get("label") or f["field"].replace("_", " ").capitalize()})
        return out

    def choice(self, report):
        """Who set the pattern fields of a report: {"by", "date", "fields"} for a researcher's choice, else None."""
        return (self.local().get("reports") or {}).get(sibling(report))

    # ---- what one record gives
    def product(self, text):
        t = str(text or "")
        low = t.lower()
        for r in self.rules():
            c = str(r.get("contains") or "")
            i = low.find(c.lower()) if c else -1
            if i < 0:
                continue
            v = ""
            if r.get("version"):
                m = VERSION.search(t[i + len(c): i + len(c) + 40])
                v = m.group(0).rstrip(".-") if m else ""
                while v.endswith(")") and v.count(")") > v.count("("):
                    v = v[:-1]                             # "7.24.4)" from "(MikroTik 7.24.4)"; "15.5(3)S4b" stays
            return f"{r.get('product') or c} {v}".strip()
        return ""

    def value(self, kind, raw):
        if raw in (None, "", "-"):
            return []
        if kind == "tags":
            tags = [t.strip().lower() for t in re.split(r"[;,]", str(raw)) if t.strip()]
            return sorted({t for t in tags if not CVE.match(t)})
        s = str(raw).strip()
        if kind == "exact":
            return [s[:200]] if s.strip("0:") else []
        if kind == "template":
            if HEX.match(s.replace(" ", "")):
                return [s[:200]]                       # a binary response: masking would make them all alike
            m = hostmask.mask(s)
            return [] if (not m or hostmask.looks_like_host(m)) else [m[:200]]
        if kind == "product":
            p = self.product(s)
            return [p] if p else []
        return []

    def items(self, report, e, fields=None):
        """[(label, value)] the record gives for its report's pattern fields (masked; never a host)."""
        out = []
        for f in fields if fields is not None else self.fields_for(report):
            for v in self.value(f["kind"], field_value(e, f["field"])):
                out.append((f["label"] if f["kind"] != "tags" else "Tag", v))
        return out

    # ---- suggestions
    def suggest(self, report, records):
        """How each field of a report groups its hosts, from records in memory: [{field, present, clusters, covered,
        unique, may, why, chosen}], the fields that group hosts best first. A field that names hosts may not be chosen."""
        chosen = {(f["field"], f["kind"]) for f in self.fields_for(report)}
        hosts = {e.get("ip") for e in records}
        n = max(1, len(hosts))
        fields = set()
        for e in records:
            fields.update((e.get("extras") or {}).keys())
            fields.update(k for k in MAPPED if field_value(e, k) not in (None, ""))
            if report.startswith("device_id") and e.get("product"):
                fields.add("device_model")
        out = []
        for f in sorted(fields):
            groups = collections.defaultdict(set)
            for e in records:
                raw = field_value(e, f)
                if raw in (None, "", "-"):
                    continue
                groups[str(raw)[:200]].add(e.get("ip"))
            if not groups:
                continue
            present = set().union(*groups.values())
            big = [h for h in groups.values() if len(h) >= MIN_HOSTS]
            covered = set().union(*big) if big else set()
            unique = sum(1 for h in groups.values() if len(h) == 1) / len(groups)
            text = any(re.search(r"[a-z]{3,}.*\s", v, re.I) for v in list(groups)[:50])
            kind = "tags" if f == "tag" else "template" if text else "exact"
            row = {"field": f, "kind": kind, "present": round(len(present) / n, 2), "clusters": len(big),
                   "covered": round(len(covered) / max(1, len(present)), 2), "unique": round(unique, 2),
                   "chosen": any(c[0] == f for c in chosen)}
            noise = f in set(self.shipped().get("noise") or [])
            row["noise"] = noise
            if self.never(f):
                row.update(may=False, why="names or locates a host (never a pattern field)")
            elif noise:
                row.update(may=True, why="says little on its own (a port, a size, a rating); better with other fields")
            elif unique > .85 and len(big) == 0:
                row.update(may=False, why="almost one value per host: it would point at hosts")
            elif len(groups) <= 1:
                row.update(may=True, why="the same on every host: says nothing")
            elif not big:
                row.update(may=True, why=f"no value is shared by {MIN_HOSTS} hosts yet")
            else:
                row.update(may=True, why=f"{len(big)} groups of {MIN_HOSTS}+ hosts, {int(row['covered'] * 100)}% of the hosts in them")
            out.append(row)
        out.sort(key=lambda r: (not r["chosen"], not r["may"], r.get("noise", False), -(r["clusters"] * r["covered"]), r["field"]))
        return out

    # ---- a researcher's choice
    def save(self, report, fields, user, reviewed=()):
        """Store a researcher's pattern fields for a report (the IPv4 report holds them for its IPv6 twin). reviewed:
        the report's fields known when the choice was made (Looking Glass asks again when new ones appear)."""
        clean = []
        for f in fields:
            fld, kind = str(f.get("field") or "").strip(), str(f.get("kind") or "")
            if not re.match(r"^[a-z0-9_]{1,60}$", fld) or kind not in KINDS:
                raise ValueError(f"{fld or '?'}: not a field of the report, or not a known kind")
            if self.never(fld):
                raise ValueError(f"{fld} names or locates a host: it cannot be a pattern field")
            clean.append({"field": fld, "kind": kind, "label": str(f.get("label") or fld.replace("_", " ").capitalize())[:60]})
        with self.lock:
            d = _read(self.paths["local"], {"reports": {}})
            d.setdefault("reports", {})[sibling(report)] = {"fields": clean, "by": user, "date": time.strftime("%Y-%m-%d", time.gmtime()),
                                                            "reviewed": sorted(set(reviewed))}
            tmp = self.paths["local"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.paths["local"])
        return clean

    def reset(self, report):
        with self.lock:
            d = _read(self.paths["local"], {"reports": {}})
            (d.get("reports") or {}).pop(sibling(report), None)
            tmp = self.paths["local"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.paths["local"])

    def add_rule(self, contains, product, version, user):
        contains, product = str(contains or "").strip()[:60], str(product or "").strip()[:60]
        if len(contains) < 3 or not product:
            raise ValueError("A rule needs the text to look for (3 characters or more) and the product's name.")
        if hostmask.mask(contains) != contains:
            raise ValueError("The text to look for must not be a host name, address or e-mail.")
        with self.lock:
            d = _read(self.paths["rules_local"], {"rules": []})
            d.setdefault("rules", []).insert(0, {"contains": contains, "product": product, "version": bool(version),
                                                "by": user, "date": time.strftime("%Y-%m-%d", time.gmtime())})
            tmp = self.paths["rules_local"] + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(d, f, indent=1, ensure_ascii=False)
            os.replace(tmp, self.paths["rules_local"])
