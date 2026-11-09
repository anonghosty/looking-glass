"""Network types (the sector of the company behind an AS number), shared by the network-name editor, the Settings
constituency filter, demo-mode aliases ("Telco 1", "Institution 2") and the automatic identification (PeeringDB,
RIPEstat, name rules in asn_lookup.py).

Built-in types cover PeeringDB's categories (Cable/DSL/ISP, NSP, Content, Enterprise, Educational/Research, Non-Profit,
Government, Route Server / Collector), the sectors Shadowserver reports, and the usual critical-infrastructure
sectors. Administrators and researchers can add their own in data/network_types.json (kept on upgrades).
"""
import json
import os
import re
import threading

# key, label, demo-mode alias word. Keys never change (they are stored in data/asns.json).
BUILTIN = [
    ("isp", "Telco / ISP", "Telco"),
    ("mobile", "Mobile operator", "Telco"),
    ("satellite", "Satellite provider", "Telco"),
    ("hosting", "Hosting", "Provider"),
    ("cloud", "Cloud / CDN", "Provider"),
    ("datacentre", "Data centre", "Provider"),
    ("ixp", "Exchange (IXP)", "Exchange"),
    ("bank", "Bank", "Institution"),
    ("finance", "Finance / insurance", "Institution"),
    ("government", "Government", "Institution"),
    ("defence", "Defence / military", "Institution"),
    ("lawenforcement", "Police / law enforcement", "Institution"),
    ("education", "University / research", "Institution"),
    ("school", "School", "Institution"),
    ("health", "Health care", "Institution"),
    ("energy", "Energy / utilities (power, water)", "Organisation"),
    ("mining", "Mining / oil and gas", "Organisation"),
    ("transport", "Transport / logistics", "Organisation"),
    ("media", "Media / broadcasting", "Organisation"),
    ("retail", "Retail / e-commerce", "Organisation"),
    ("manufacturing", "Manufacturing / industry", "Organisation"),
    ("agriculture", "Agriculture / food", "Organisation"),
    ("nonprofit", "Non-profit / NGO", "Institution"),
    ("international", "International organisation", "Institution"),
    ("enterprise", "Enterprise", "Organisation"),
    ("private", "Private", "Network"),
    ("unknown", "Unknown", "Network"),
]
_LOCK = threading.Lock()
_CACHE = {"mtime": None, "data": None, "path": None}


def _path(data_dir):
    return os.path.join(data_dir, "network_types.json")


def all_types(data_dir):
    """[{key, label, alias, builtin}] in display order: built-in first, then the site's own (alphabetical)."""
    p = _path(data_dir)
    m = os.path.getmtime(p) if os.path.exists(p) else 0
    if _CACHE["path"] != p or _CACHE["mtime"] != m:
        custom = {}
        try:
            with open(p, encoding="utf-8") as f:
                custom = json.load(f).get("types", {})
        except (OSError, ValueError):
            pass
        out = [{"key": k, "label": l, "alias": a, "builtin": True} for k, l, a in BUILTIN]
        known = {t["key"] for t in out}
        for k, v in sorted(custom.items(), key=lambda kv: kv[1].get("label", kv[0]).lower()):
            if k not in known:
                out.append({"key": k, "label": v.get("label") or k, "alias": v.get("alias") or "Organisation", "builtin": False,
                            "by": v.get("by", ""), "added": v.get("added", "")})
        _CACHE.update(path=p, mtime=m, data=out)
    return _CACHE["data"]


def keys(data_dir):
    return {t["key"] for t in all_types(data_dir)}


def labels(data_dir):
    return {t["key"]: t["label"] for t in all_types(data_dir)}


def aliases(data_dir):
    return {t["key"]: t["alias"] for t in all_types(data_dir)}


def add(data_dir, label, alias, by="", today=""):
    """A new type from its label; returns its key. ValueError when the label is not acceptable or already exists."""
    label = re.sub(r"\s+", " ", str(label or "")).strip()
    alias = re.sub(r"\s+", " ", str(alias or "")).strip() or "Organisation"
    if not 2 <= len(label) <= 60 or re.search(r"[<>\x00-\x1f]", label):
        raise ValueError("The type name: 2 to 60 characters, no < or >.")
    if not re.fullmatch(r"[A-Za-z][A-Za-z -]{1,23}", alias):
        raise ValueError("The demo-mode word: letters only, up to 24 characters (for example Institution or Organisation).")
    key = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")[:40]
    if not key:
        raise ValueError("The type name needs letters or digits.")
    existing = all_types(data_dir)
    if key in {t["key"] for t in existing} or label.lower() in {t["label"].lower() for t in existing}:
        raise ValueError(f'A type "{label}" already exists.')
    p = _path(data_dir)
    with _LOCK:
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            data = {"about": "Network types added on this site (Settings / Definitions page). Kept on upgrades.", "types": {}}
        data.setdefault("types", {})[key] = {"label": label, "alias": alias.title(), "by": by, "added": today}
        tmp = f"{p}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, ensure_ascii=False)
        os.replace(tmp, p)
    _CACHE["mtime"] = None
    return key
