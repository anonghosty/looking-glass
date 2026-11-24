# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shadowserver's own mapping of one event (approved 2026-11-23).

Some reports (the honeypot scanner events: ADB, HTTP, IKEv2, RDP, RocketMQ, SMB, SNMP) carry, per event, the MITRE
ATT&CK tactics and techniques Shadowserver tagged it with (threat_framework, threat_tactic_id, threat_technique_id),
the vulnerability or exploit it concerned (vulnerability_enum CVE or EDB, vulnerability_id, CVSS class, score,
severity and version) and the device it targeted (target_vendor, target_product, target_class). Shadowserver fills
them only sometimes: for_row() returns None when a record has none of them.

This is Shadowserver's statement about the event, kept apart from Looking Glass's own per-report suggestion
(attack_map.py) and never changing it. Technique and tactic names come from the local copy of MITRE ATT&CK
(data/names_attack.json, refreshed weekly); an ID the copy does not know is kept as it is, with its MITRE link.
"""
import json
import os
import re
import threading

import filesig

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
NAMES_FILE = "names_attack.json"
FIELDS = ("threat_framework", "threat_tactic_id", "threat_technique_id", "vulnerability_enum", "vulnerability_id",
          "vulnerability_class", "vulnerability_score", "vulnerability_severity", "vulnerability_version",
          "target_vendor", "target_product", "target_class")
TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
TAID = re.compile(r"^TA\d{4}$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MAX_IDS = 12                                              # a record never lists more; more would be noise

_lock = threading.Lock()
_cache = {"path": None, "sig": None, "techniques": {}, "tactics": {}}


def _names(data_dir=None):
    path = os.path.join(data_dir or DATA_DIR, NAMES_FILE)
    try:
        sig = filesig.sig(path)
    except OSError:
        return {}, {}
    with _lock:
        if _cache["path"] != path or _cache["sig"] != sig:
            try:
                with open(path, encoding="utf-8") as f:
                    d = json.load(f)
                _cache["techniques"] = d.get("techniques") if isinstance(d.get("techniques"), dict) else {}
                _cache["tactics"] = d.get("tactics") if isinstance(d.get("tactics"), dict) else {}
            except (OSError, ValueError, AttributeError):
                _cache["techniques"], _cache["tactics"] = {}, {}
            _cache["path"], _cache["sig"] = path, sig
        return _cache["techniques"], _cache["tactics"]


def _s(v, n=120):
    return str(v if v is not None else "").strip()[:n]


def ids(value, pattern):
    """'T1190;T1059', 'T1190, T1059', ['T1190', 'T1059'] -> ['T1190', 'T1059'] (valid IDs only, once each, in order)."""
    if isinstance(value, (list, tuple)):
        parts = [str(x) for x in value]
    else:
        parts = re.split(r"[;,\s|]+", str(value or ""))
    out = []
    for p in parts:
        p = p.strip().upper()
        if pattern.match(p) and p not in out:
            out.append(p)
    return out[:MAX_IDS]


def technique_url(tid):
    return f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"


def for_row(doc, data_dir=None):
    """{techniques: [{id, name, url, known}], tactics: [{id, name, url, known}], vulnerability: {...} or None,
    target: {...} or None, framework} for a record that carries Shadowserver's mapping, else None."""
    if not isinstance(doc, dict) or not any(doc.get(k) not in (None, "", []) for k in FIELDS):
        return None
    techs, tactics = _names(data_dir)
    t_out = []
    for tid in ids(doc.get("threat_technique_id"), TID):
        t = techs.get(tid) or {}
        t_out.append({"id": tid, "name": _s(t.get("name")) or tid, "url": _s(t.get("url"), 200) or technique_url(tid),
                      "known": bool(t)})
    a_out = []
    for ta in ids(doc.get("threat_tactic_id"), TAID):
        t = tactics.get(ta) or {}
        a_out.append({"id": ta, "name": _s(t.get("name")) or ta, "url": _s(t.get("url"), 200) or f"https://attack.mitre.org/tactics/{ta}/",
                      "known": bool(t)})
    vid = _s(doc.get("vulnerability_id"), 40)
    vuln = None
    if vid:
        kind = _s(doc.get("vulnerability_enum"), 12).upper() or ("CVE" if CVE.match(vid.upper()) else "")
        vuln = {"id": vid.upper() if CVE.match(vid.upper()) else vid, "kind": kind, "is_cve": bool(CVE.match(vid.upper())),
                "scheme": _s(doc.get("vulnerability_class"), 12), "score": _s(doc.get("vulnerability_score"), 8),
                "severity": _s(doc.get("vulnerability_severity"), 20).capitalize(), "scheme_version": _s(doc.get("vulnerability_version"), 8)}
    tgt = {k: _s(doc.get(f"target_{k}"), 80) for k in ("vendor", "product", "class")}
    tgt = tgt if any(tgt.values()) else None
    if not (t_out or a_out or vuln or tgt):
        return None
    return {"framework": _s(doc.get("threat_framework"), 40) or ("MITRE ATT&CK" if (t_out or a_out) else ""),
            "techniques": t_out, "tactics": a_out, "vulnerability": vuln, "target": tgt}


SEEN_TTL = 600                                            # the Definitions page asks often; the counts move slowly


class Seen:
    """Per report, the techniques Shadowserver tagged its events with, over the days the map holds in memory:
    {report: [{id, name, url, count}]} (most first), plus {report: events with a mapping}. Only reports whose
    Shadowserver schema has threat_technique_id are read (report_map facts), and the answer is kept SEEN_TTL seconds."""

    def __init__(self, store, report_facts, now=None):
        self.store = store
        self.report_facts = report_facts                  # () -> {report: {"fields": [...]}}
        self.now = now or __import__("time").time
        self._lock = threading.Lock()
        self._kept = (0.0, None)

    def reports(self):
        try:
            facts = self.report_facts() or {}
        except Exception:                                 # noqa: BLE001  (no report map yet)
            return set()
        return {k for k, v in facts.items() if isinstance(v, dict) and "threat_technique_id" in (v.get("fields") or [])}

    def get(self):
        with self._lock:
            at, kept = self._kept
            if kept is not None and self.now() - at < SEEN_TTL:
                return kept
        names = self.reports()
        counts, events = {}, {}
        for day in list(getattr(self.store, "days", {}).values()):
            by_src = getattr(day, "by_src", None) or {}
            for name in names:
                for ev in (by_src.get(name) or {}).get("rows") or []:
                    m = ev.get("ss_attack") if isinstance(ev, dict) else None
                    if not m:
                        continue
                    events[name] = events.get(name, 0) + 1
                    for t in m.get("techniques") or []:
                        c = counts.setdefault(name, {}).setdefault(t["id"], {"id": t["id"], "name": t["name"], "url": t["url"], "count": 0})
                        c["count"] += 1
        out = {"techniques": {k: sorted(v.values(), key=lambda x: (-x["count"], x["id"])) for k, v in counts.items()},
               "events": events}
        with self._lock:
            self._kept = (self.now(), out)
        return out


def summary(m):
    """One line for CSV cells and PDF rows: 'T1190 Exploit Public-Facing Application; CVE-2023-28771 (CVSS 9.8)'."""
    if not m:
        return ""
    parts = [f"{t['id']} {t['name']}" if t["name"] != t["id"] else t["id"] for t in m.get("techniques") or []]
    v = m.get("vulnerability")
    if v:
        parts.append(v["id"] + (f" ({v['scheme'] or 'CVSS'} {v['score']})" if v.get("score") else ""))
    tg = m.get("target")
    if tg:
        what = " ".join(x for x in (tg.get("vendor"), tg.get("product")) if x)
        if tg.get("class"):
            what = f"{what} ({tg['class']})" if what else tg["class"]
        parts.append("targets " + what)
    return "; ".join(p.strip() for p in parts if p.strip())
