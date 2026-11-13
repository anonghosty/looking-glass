"""MITRE ATT&CK mapping (2026-11-13, approved design, step 2).

What it does:
  a. Malware families: the ATT&CK Software entry that matches a name brings the techniques MITRE links to it (and the
     groups that use it): "Known for this malware".
  b. Reports: a shipped rule table (data/attack_rules.json) suggests techniques for each Shadowserver report from its
     name, type and group, with a certainty (observed / possible) and the constituent's role.
  c. Every report has a mapping (data/attack_mappings.json): suggested, reviewed, not mapped yet, or "please check".
     A new report gets its suggestion on first arrival and is asked about on the Definitions page.
  d. Researchers confirm or change a mapping in a picker (short list, then a search over the local copy of ATT&CK;
     retired techniques hidden); several techniques, or "No ATT&CK technique fits", with a note. Audited. A reviewed
     mapping is never replaced by a suggestion.
  e. Shadowserver changing a report's type or description, or MITRE retiring a technique, puts the mapping back to
     "please check"; the old one stays shown until confirmed. A new ATT&CK version (the weekly refresh) is compared
     with the old one: revoked -> MITRE's named replacement is the suggestion; deprecated -> the short list; split ->
     the new sub-techniques; renamed -> shown under the new name, no review; software links -> updated automatically;
     new techniques -> in the picker at once. One notice per update on the Definitions page, one audit entry.
  f. Certainty and role in plain words: Observed (the report saw it), Known for this malware (MITRE's links),
     Possible (an exposure an attacker could use); "this device was used for...", "attackers can use this exposure for...".
  h. CVEs: MITRE CTID's Mappings Explorer KEV -> ATT&CK mappings (Apache 2.0, © MITRE), from a local copy.
Only local copies are read; nothing about hosts leaves the server. Documents (PDFs, advisories) carry the ATT&CK
version they were made with.
"""
import hashlib
import json
import os
import re
import threading
import time
from datetime import datetime, timezone

from offline_names import ATTACK_FILE, FULL_FILE, TID, tactic_label  # noqa: F401  (tactic_label re-exported for callers)

RULES_FILE = "attack_rules.json"
MAPPINGS_FILE = "attack_mappings.json"
KEV_FILE = "attack_kev.json"
KEV_TREE = "https://api.github.com/repos/center-for-threat-informed-defense/mappings-explorer/git/trees/main?recursive=1"
KEV_RAW = "https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/"
KEV_LICENCE = ("MITRE Center for Threat-Informed Defense, Mappings Explorer (KEV to ATT&CK). © MITRE, licensed under the "
               "Apache License 2.0.")
CERTAINTY = {"observed": "Observed (the report saw it)", "known": "Known for this malware (MITRE's links)",
             "possible": "Possible (an exposure an attacker could use)"}
ROLE = {"used": "this device was used for it", "target": "this address was the target of it",
        "host": "this host was used for it", "exposure": "attackers can use this exposure for it",
        "known": "MITRE links this technique to the malware", "cve": "attackers can use this vulnerability for it"}
KEV_KIND = {"exploitation_technique": "how it is exploited", "primary_impact": "main impact", "secondary_impact": "further impact"}
STATES = ("suggested", "reviewed", "none", "check")
# "How to defend": MITRE's mitigations of a technique, the ones that suit the kind of report first (a simple preference
# per role): an exposed service is closed or limited first; an infection or C2 is filtered and cleaned on the endpoint first
MIT_PREF = {
    "exposure": ["M1035", "M1030", "M1042", "M1051", "M1032", "M1026", "M1036", "M1037"],
    "cve": ["M1051", "M1035", "M1030", "M1048", "M1050", "M1016"],
    "used": ["M1031", "M1037", "M1049", "M1040", "M1038", "M1021", "M1047"],
    "host": ["M1021", "M1031", "M1037", "M1049", "M1017", "M1054"],
    "target": ["M1037", "M1031", "M1030"],
}
DEFEND_MAX = 3
MAX_NOTE = 600
MAX_PICK = 12


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def version_of(doc):
    v = (doc or {}).get("versions") or {}
    return v.get("enterprise") or next(iter(v.values()), "")


# ------------------------------------------------------------------------------------------------ new ATT&CK version
def diff_versions(old_doc, new_doc):
    """What changed between two ATT&CK indexes (offline_names.build_attack)."""
    ot, nt = (old_doc or {}).get("techniques") or {}, (new_doc or {}).get("techniques") or {}
    act = lambda d, t: (d.get(t) or {}).get("state") == "active"
    new = sorted(t for t in nt if act(nt, t) and not act(ot, t))
    renamed = sorted(t for t in nt if act(nt, t) and act(ot, t) and nt[t]["name"] != ot[t]["name"])
    revoked = {t: nt[t].get("revoked_by", "") for t in ot if act(ot, t) and (nt.get(t) or {}).get("state") == "revoked"}
    deprecated = sorted(t for t in ot if act(ot, t) and (t not in nt or nt[t]["state"] == "deprecated"))
    split = {}
    for t in ot:
        if act(ot, t) and "." not in t:
            subs = sorted(s for s in nt if s.startswith(t + ".") and act(nt, s) and not act(ot, s))
            if subs:
                split[t] = subs
    os_, ns = ({e.get("id"): sorted(e.get("techniques") or []) for e in (d or {}).get("entries") or [] if e.get("id")}
               for d in (old_doc, new_doc))
    software = sorted(i for i in ns if i in os_ and os_[i] != ns[i])
    return {"from": version_of(old_doc), "to": version_of(new_doc), "new": new, "renamed": renamed, "revoked": revoked,
            "deprecated": deprecated, "split": split, "software": software}


class AttackMap:
    def __init__(self, data_dir, offline, report_map=None, report_defs=None, audit=None):
        """offline: OfflineNames (its ATT&CK index); report_map() -> {key: report entry}; report_defs() -> {key: {def, why}}."""
        self.dir = data_dir
        self.offline = offline
        self.report_map = report_map or (lambda: {})
        self.report_defs = report_defs or (lambda: {})
        self.audit = audit
        self.labels = lambda: {}                          # app.py: {report label: collection} from the source registry
        self.lock = threading.Lock()
        self._rules = (None, None)
        self._kev = (None, None)

    # ---------------------------------------------------------------------------------------------- data
    def attack_doc(self):
        if not self.offline:                              # no copy of ATT&CK given: names and rules still work
            return {}
        doc, _ = self.offline._load(ATTACK_FILE)
        return doc or {}

    def version(self):
        return version_of(self.attack_doc())

    def techniques(self):
        return self.attack_doc().get("techniques") or {}

    def tech(self, tid, techs=None, role=""):
        """A technique for the page and documents: name, tactics, link, state, MITRE's short description (what it is),
        its short detection text when MITRE gives one, and up to three mitigations ordered for the role (how to defend)."""
        t = (techs or self.techniques()).get(tid) or {}
        return {"id": tid, "name": t.get("name") or tid, "tactics": t.get("tactics") or [], "url": t.get("url") or
                f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/", "state": t.get("state") or "unknown",
                "revoked_by": t.get("revoked_by", ""), "desc": t.get("desc", ""), "detect": t.get("detect", ""),
                "defend": self.defences(t, role)}

    def defences(self, t, role=""):
        """Up to DEFEND_MAX mitigations of a technique: [{id, name, text, url}], those that suit the role first, then
        MITRE's own order."""
        mits = self.attack_doc().get("mitigations") or {}
        rows = [m for m in (t.get("mitigations") or []) if isinstance(m, list) and len(m) == 2]
        pref = MIT_PREF.get(role, [])
        rows.sort(key=lambda m: pref.index(m[0]) if m[0] in pref else len(pref) + 1)
        out = []
        for mid, txt in rows[:DEFEND_MAX]:
            m = mits.get(mid) or {}
            out.append({"id": mid, "name": m.get("name") or mid, "text": txt or m.get("text", ""),
                        "url": m.get("url") or f"https://attack.mitre.org/mitigations/{mid}/"})
        return out

    def full_description(self, tid):
        """MITRE's whole description of a technique (its own file, read when someone expands one)."""
        if not TID.match(str(tid or "")):
            return None
        try:
            with open(os.path.join(self.dir, FULL_FILE), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            return None
        txt = (d.get("descriptions") or {}).get(tid)
        return {"id": tid, "description": txt, "version": version_of(d)} if txt else None

    def rules(self):
        path = os.path.join(self.dir, RULES_FILE)
        try:
            m = os.path.getmtime(path)
        except OSError:
            return {"rules": [], "names": []}
        if self._rules[0] != m:
            try:
                with open(path, encoding="utf-8") as f:
                    self._rules = (m, json.load(f))
            except (OSError, ValueError):
                self._rules = (m, {"rules": [], "names": []})
        return self._rules[1]

    def _read(self):
        try:
            with open(os.path.join(self.dir, MAPPINGS_FILE), encoding="utf-8") as f:
                d = json.load(f)
        except (OSError, ValueError):
            d = {}
        d.setdefault("reports", {}); d.setdefault("notices", [])
        return d

    def _write(self, d):
        path = os.path.join(self.dir, MAPPINGS_FILE)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)

    def _locked(self, fn):
        """Read, change and write data/attack_mappings.json under a lock shared by every process (gunicorn workers and
        the fetch script)."""
        import fcntl
        with self.lock:
            fd = os.open(os.path.join(self.dir, ".attack_mappings.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX)
                d = self._read()
                out = fn(d)
                self._write(d)
                return out
            finally:
                os.close(fd)

    # ---------------------------------------------------------------------------------------------- suggestions
    @staticmethod
    def _matches(rule, key, e):
        m = rule.get("match") or {}
        if "report" in m and not re.search(m["report"], key or ""):
            return False
        if "type" in m and (e.get("type") or "") not in m["type"]:
            return False
        if "group" in m and (e.get("group") or "") not in m["group"]:
            return False
        return bool(m)

    def suggest(self, key, e=None):
        e = e if e is not None else (self.report_map().get(key) or {})
        for r in self.rules().get("rules") or []:
            if self._matches(r, key, e):
                return r
        return None

    def basis(self, key, e):
        """What a mapping was made against: Shadowserver's type, group, title and description of the report."""
        d = self.report_defs().get(key) or {}
        text = " | ".join(str(x or "") for x in (e.get("type"), e.get("taxonomy"), e.get("section"), e.get("group"),
                                                   e.get("title"), d.get("def"), d.get("why")))
        return hashlib.sha256(text.encode()).hexdigest()[:16], f"{e.get('type') or '?'} · {e.get('title') or key}"

    def _fresh_entry(self, key, e, now):
        r = self.suggest(key, e)
        sig, txt = self.basis(key, e)
        base = {"first_seen": now, "basis": sig, "basis_text": txt, "note": "", "by": "", "at": ""}
        if r:
            return {**base, "status": "suggested", "techniques": list(r.get("techniques") or []), "rule": r.get("id"),
                    "certainty": r.get("certainty", "possible"), "role": r.get("role", "exposure"), "why": r.get("why", "")}
        return {**base, "status": "none", "techniques": [], "rule": "", "certainty": "", "role": "", "why": ""}

    def sync(self):
        """New reports get their suggestion; a report whose type or description Shadowserver changed goes back to
        "please check" (reviewed) or gets a new suggestion (not reviewed). Returns how many changed."""
        reports = self.report_map()
        if not reports:
            return 0
        def go(d):
            now, n = _now(), 0
            for key, e in reports.items():
                m = d["reports"].get(key)
                if not m:
                    d["reports"][key] = self._fresh_entry(key, e, now); n += 1
                    continue
                sig, txt = self.basis(key, e)
                if m.get("basis") == sig:
                    continue
                if m.get("status") in ("reviewed", "check"):
                    if m.get("status") == "reviewed":
                        m["previous"] = {k: m.get(k) for k in ("techniques", "nofit", "note", "by", "at")}
                    m.update(status="check", check_reason=f"Shadowserver changed the report ({m.get('basis_text', '?')} → {txt})",
                             check_suggest=list((self.suggest(key, e) or {}).get("techniques") or []), basis=sig, basis_text=txt)
                else:
                    fresh = self._fresh_entry(key, e, m.get("first_seen") or now)
                    m.update({k: v for k, v in fresh.items() if k != "first_seen"})
                n += 1
            return n
        # cheap when nothing changed: compare first, write only when something is new
        d = self._read()
        if all(k in d["reports"] and d["reports"][k].get("basis") == self.basis(k, e)[0] for k, e in reports.items()):
            return 0
        return self._locked(go)

    # ---------------------------------------------------------------------------------------------- display
    def _items(self, tids, certainty, role, status, why="", report="", techs=None, retired=None):
        techs = techs if techs is not None else self.techniques()
        out = []
        for tid in tids or []:
            t = self.tech(tid, techs, role)
            keep = ("id", "name", "tactics", "url", "state", "desc") + (() if certainty == "known" else ("detect", "defend"))
            out.append({**{k: t[k] for k in keep}, "certainty": certainty,
                        "certainty_label": CERTAINTY.get(certainty, ""), "role": ROLE.get(role, ""), "status": status,
                        "why": why, "report": report, "retired_in": (retired or {}).get(tid, "")})
        return out

    def mapping(self, key):
        return self._read()["reports"].get(key)

    def report_items(self, key, title=""):
        """The techniques a report's mapping gives, for cards and documents. Reviewed and suggested ones (marked);
        a mapping to check shows what it had (marked 'please check'); none / no-fit give nothing."""
        m = self.mapping(key)
        if not m:
            e = self.report_map().get(key) or {}
            r = self.suggest(key, e) if e else None
            if not r:
                return []
            return self._items(r.get("techniques"), r.get("certainty"), r.get("role"), "suggested", r.get("why", ""), title or e.get("title", key))
        if m.get("nofit"):
            return []
        tids = m.get("techniques") or ((m.get("previous") or {}).get("techniques") if m.get("status") == "check" else [])
        return self._items(tids, m.get("certainty") or "possible", m.get("role") or "exposure",
                           {"reviewed": "reviewed", "suggested": "suggested", "check": "please check"}.get(m.get("status"), ""),
                           m.get("why", ""), title or (self.report_map().get(key) or {}).get("title", key), retired=m.get("retired"))

    def for_reports(self, keys):
        out, seen = [], set()
        for k in keys or []:
            for it in self.report_items(k):
                if (it["id"], it["report"]) not in seen:
                    seen.add((it["id"], it["report"])); out.append(dict(it, report_key=k))
        return out

    def keys_for_titles(self, titles):
        """Report keys for the labels a card's "Seen in" shows: the platform's own report labels (the source registry,
        label -> collection), then Shadowserver's titles (the report map), then keys as they are."""
        rm = self.report_map()
        low = {str(v.get("title") or "").lower(): k for k, v in rm.items()}
        try:
            low.update({str(lbl).lower(): k for lbl, k in (self.labels() or {}).items()})
        except Exception:                                 # noqa: BLE001  (no registry yet)
            pass
        out = []
        for t in titles or []:
            k = low.get(str(t).lower()) or (t if t in rm else "")
            if k and k not in out:
                out.append(k)
        return out

    def name_items(self, name):
        out = []
        for r in self.rules().get("names") or []:
            try:
                if re.search(r.get("match") or "^$", (name or "").lower()):
                    out += self._items(r.get("techniques"), r.get("certainty", "observed"), r.get("role", "used"), "suggested",
                                       r.get("why", ""), "")
            except re.error:
                continue
        return out

    def card_attack(self, name, card):
        """ATT&CK for a name's card: observed (its reports' mappings, Shadowserver's naming), known for this malware
        (MITRE's Software entry that matched), with the groups MITRE says use it, and the version used."""
        sw = card if card.get("source") == "mitre-attack" else next(
            (a for a in card.get("also") or [] if a.get("source") == "mitre-attack"), None)
        items = self.name_items(name) + self.for_reports(self.keys_for_titles(card.get("seen_in") or []))
        known = []
        if sw and sw.get("techniques"):
            known = self._items(sw["techniques"], "known", "known", "MITRE", "", "")
        if not (items or known):
            return None
        return {"version": self.version(), "techniques": items + known, "software": (sw or {}).get("name", ""),
                "software_id": (sw or {}).get("id", ""), "groups": (sw or {}).get("groups") or []}

    # ---------------------------------------------------------------------------------------------- CVEs (CTID KEV)
    def kev(self):
        path = os.path.join(self.dir, KEV_FILE)
        try:
            m = os.path.getmtime(path)
        except OSError:
            return {}
        if self._kev[0] != m:
            try:
                with open(path, encoding="utf-8") as f:
                    self._kev = (m, json.load(f))
            except (OSError, ValueError):
                self._kev = (m, {})
        return self._kev[1]

    def cve_attack(self, cve):
        k = self.kev()
        rows = (k.get("cves") or {}).get(str(cve or "").upper()) or []
        if not rows:
            return None
        techs = self.techniques()
        items = []
        for tid, kind in rows:
            it = self._items([tid], "possible", "cve", "CTID", KEV_KIND.get(kind, kind), "", techs)[0]
            it["kind"] = KEV_KIND.get(kind, kind)
            items.append(it)
        return {"version": self.version(), "mapped_with": k.get("attack_version", ""), "kev_date": k.get("kev_date", ""),
                "techniques": items, "source": "MITRE CTID Mappings Explorer (KEV)", "licence": KEV_LICENCE}

    # ---------------------------------------------------------------------------------------------- the picker
    def search(self, q, limit=30):
        q = (q or "").strip().lower()[:60]
        if not q:
            return []
        out = []
        for tid, t in sorted(self.techniques().items()):
            if t.get("state") != "active":
                continue                                  # retired or revoked techniques are hidden
            hay = f"{tid.lower()} {t['name'].lower()} {' '.join(t.get('tactics') or []).lower()}"
            if tid.lower().startswith(q) or all(w in hay for w in q.split()):
                out.append(self.tech(tid))
            if len(out) >= limit:
                break
        return out

    def shortlist(self, key, limit=10):
        """5-10 fitting techniques: the rule's short list, the current and suggested ones, then others of the same
        tactics; active only."""
        techs = self.techniques()
        m = self.mapping(key) or {}
        r = self.suggest(key) or {}
        base = list(dict.fromkeys((m.get("check_offer") or []) + (m.get("check_suggest") or []) + (m.get("techniques") or [])
                                  + (r.get("techniques") or []) + (r.get("shortlist") or [])))
        tactics = {ta for t in base for ta in (techs.get(t) or {}).get("tactics") or []}
        out = [t for t in base if (techs.get(t) or {}).get("state") == "active"]
        if len(out) < 5:
            for tid, t in sorted(techs.items()):
                if len(out) >= limit:
                    break
                if t.get("state") == "active" and "." not in tid and tid not in out and tactics & set(t.get("tactics") or []):
                    out.append(tid)
        return [self.tech(t, techs) for t in out[:limit]]

    def review(self, key, techniques, nofit, note, user, name=""):
        """A researcher's choice: one or more techniques, or "No ATT&CK technique fits". Never overwritten by a
        suggestion. Returns (mapping, error)."""
        if key not in self.report_map() and not self.mapping(key):
            return None, "No such report."
        techs = self.techniques()
        ids = [str(t).strip().upper() for t in techniques or [] if str(t).strip()]
        ids = list(dict.fromkeys(ids))[:MAX_PICK]
        bad = [t for t in ids if not TID.match(t) or (techs.get(t) or {}).get("state") != "active"]
        if bad:
            return None, f"Not a current ATT&CK technique: {bad[0][:20]}."
        if bool(nofit) == bool(ids):
            return None, "Choose at least one technique, or \"No ATT&CK technique fits\"."
        note = re.sub(r"\s+", " ", str(note or "")).strip()[:MAX_NOTE]
        e = self.report_map().get(key) or {}
        sig, txt = self.basis(key, e) if e else ("", "")
        r = self.suggest(key, e) or {}
        def go(d):
            m = d["reports"].setdefault(key, {"first_seen": _now()})
            m.update(status="reviewed", techniques=ids, nofit=bool(nofit), note=note, by=user, by_name=name or user, at=_now(),
                     version=version_of(self.attack_doc()), basis=sig or m.get("basis", ""), basis_text=txt or m.get("basis_text", ""),
                     certainty=m.get("certainty") or r.get("certainty") or "possible", role=m.get("role") or r.get("role") or "exposure",
                     why=m.get("why") or r.get("why", ""))
            for k in ("previous", "check_reason", "check_suggest", "check_offer", "retired"):
                m.pop(k, None)
            return dict(m)
        m = self._locked(go)
        if self.audit:
            self.audit.add("attack_mapping_reviewed", user=user, target=key,
                           detail=("no ATT&CK technique fits" if nofit else ", ".join(ids)) + (f"; note: {note[:120]}" if note else ""))
        return m, ""

    def todo(self):
        """The reports to look at: suggestions to confirm, not mapped yet, and please check."""
        d = self._read()
        rm = self.report_map()
        out = []
        for key, m in d["reports"].items():
            if m.get("status") == "reviewed":
                continue
            e = rm.get(key) or {}
            techs = m.get("techniques") or []
            out.append({"report": key, "title": e.get("title") or key, "section": e.get("section", ""), "type": e.get("type", ""),
                        "status": m.get("status"), "why": m.get("why", ""), "certainty": m.get("certainty", ""), "role": m.get("role", ""),
                        "techniques": [self.tech(t) for t in techs], "previous": [self.tech(t) for t in (m.get("previous") or {}).get("techniques") or []],
                        "check_reason": m.get("check_reason", ""), "check_suggest": [self.tech(t) for t in m.get("check_suggest") or []],
                        "retired": m.get("retired") or {}, "first_seen": m.get("first_seen", "")})
        order = {"check": 0, "suggested": 1, "none": 2}
        return sorted(out, key=lambda x: (order.get(x["status"], 3), x["section"], x["title"]))

    def summary(self):
        d = self._read()
        st = {s: 0 for s in STATES}
        for m in d["reports"].values():
            st[m.get("status", "none")] = st.get(m.get("status", "none"), 0) + 1
        return {"version": self.version(), "counts": st, "notice": (d["notices"] or [None])[-1],
                "kev": {k: self.kev().get(k) for k in ("attack_version", "kev_date", "count")} if self.kev() else None}

    def reviewed(self):
        d = self._read()
        rm = self.report_map()
        return [{"report": k, "title": (rm.get(k) or {}).get("title") or k, "section": (rm.get(k) or {}).get("section", ""),
                 "type": (rm.get(k) or {}).get("type", ""), "status": "reviewed", "certainty": m.get("certainty", ""), "role": m.get("role", ""),
                 "why": m.get("why", ""), "techniques": [self.tech(t) for t in m.get("techniques") or []],
                 "nofit": bool(m.get("nofit")), "note": m.get("note", ""), "by": m.get("by_name") or m.get("by", ""), "at": m.get("at", ""),
                 "version": m.get("version", "")}
                for k, m in sorted(d["reports"].items(), key=lambda kv: (rm.get(kv[0]) or {}).get("title") or kv[0]) if m.get("status") == "reviewed"]


# ------------------------------------------------------------------------------------------------ the refresh's part
def apply_update(data_dir, old_doc, new_doc):
    """Called by manage/fetch_offline_names.py when a new ATT&CK copy is saved. Compares it with the old one and puts the
    affected mappings to "please check" (reviewed ones never change by themselves). Returns the summary (also kept as
    the Definitions page's notice), or None when nothing changed."""
    if not (old_doc or {}).get("techniques"):
        return None                                       # the first copy: nothing to compare
    dv = diff_versions(old_doc, new_doc)
    if not any((dv["new"], dv["renamed"], dv["revoked"], dv["deprecated"], dv["split"], dv["software"])) and dv["from"] == dv["to"]:
        return None
    am = AttackMap(data_dir, None)
    am.attack_doc = lambda: new_doc
    to_v = dv["to"] or "?"

    def go(d):
        items = []
        for key, m in d["reports"].items():
            tids = m.get("techniques") or []
            hit_rev = {t: dv["revoked"][t] for t in tids if t in dv["revoked"]}
            hit_dep = [t for t in tids if t in dv["deprecated"]]
            hit_split = {t: dv["split"][t] for t in tids if t in dv["split"]}
            if not (hit_rev or hit_dep or hit_split):
                continue
            if m.get("status") == "reviewed":
                m["previous"] = {k: m.get(k) for k in ("techniques", "nofit", "note", "by", "at")}
            reasons = ([f"{t} was retired in ATT&CK v{to_v}" + (f"; MITRE names {r} as its replacement" if r else "") for t, r in hit_rev.items()]
                       + [f"{t} was deprecated in ATT&CK v{to_v} with no replacement" for t in hit_dep]
                       + [f"{t} was split into sub-techniques in ATT&CK v{to_v}: {', '.join(s)}" for t, s in hit_split.items()])
            suggest = [r for r in hit_rev.values() if r] + [t for t in tids if t not in hit_rev and t not in hit_dep]
            m.update(status="check", check_reason="; ".join(reasons), check_suggest=list(dict.fromkeys(suggest)),
                     check_offer=sorted({s for subs in hit_split.values() for s in subs}),
                     retired={**(m.get("retired") or {}), **{t: f"v{to_v}" for t in list(hit_rev) + hit_dep}})
            items.append(key)
        notice = {"at": _now(), "from": dv["from"], "to": dv["to"], "to_check": len(items), "items": items,
                  "new_techniques": len(dv["new"]), "renamed": len(dv["renamed"]), "retired": len(dv["revoked"]) + len(dv["deprecated"]),
                  "split": len(dv["split"]), "software_updated": len(dv["software"]),
                  "text": (f"ATT&CK v{dv['from'] or '?'} → v{to_v}: {len(items)} mapping{'s' if len(items) != 1 else ''} to check, "
                           f"{len(dv['new'])} new technique{'s' if len(dv['new']) != 1 else ''}, "
                           f"{len(dv['software'])} malware famil{'ies' if len(dv['software']) != 1 else 'y'} updated"
                           + (f", {len(dv['renamed'])} renamed" if dv["renamed"] else ""))}
        d["notices"] = (d["notices"] + [notice])[-20:]
        return notice
    return am._locked(go)


def build_kev(doc, path=""):
    """A CTID Mappings Explorer KEV file -> {cves: {CVE: [[technique, kind]]}, attack_version, kev_date, count}."""
    meta = (doc or {}).get("metadata") or {}
    cves = {}
    for m in (doc or {}).get("mapping_objects") or []:
        if not isinstance(m, dict):
            continue
        cve, tid, kind = str(m.get("capability_id") or "").upper(), str(m.get("attack_object_id") or "").upper(), m.get("mapping_type")
        if re.match(r"^CVE-\d{4}-\d{4,7}$", cve) and TID.match(tid) and kind in KEV_KIND:
            row = [tid, kind]
            if row not in cves.setdefault(cve, []):
                cves[cve].append(row)
    return {"source": "ctid-kev", "attack_version": str(meta.get("attack_version") or "")[:20],
            "kev_date": str(meta.get("mapping_framework_version") or "")[:20], "path": path[:200], "count": len(cves), "cves": cves}


def latest_kev_path(tree):
    """The newest enterprise KEV mapping file in the repository listing (highest ATT&CK version, then date)."""
    best = None
    for x in (tree or {}).get("tree") or []:
        p = str(x.get("path") or "")
        mm = re.match(r"^mappings/kev/attack-(\d+)\.(\d+)/kev-(\d\d)\.(\d\d)\.(\d{4})/enterprise/[\w.-]+\.json$", p)
        if mm:
            a, b, mo, dd, yy = (int(g) for g in mm.groups())
            k = (a, b, yy, mo, dd)
            if not best or k > best[0]:
                best = (k, p)
    return best[1] if best else ""


# ------------------------------------------------------------------------------------------------ text for documents
def attack_lines(att):
    """Plain text for PDFs and CSV: grouped by tactic, every technique with its certainty; the version first.
    Nothing is cut: every technique is listed."""
    if not att or not att.get("techniques"):
        return []
    v = att.get("version")
    out = []
    obs = [t for t in att["techniques"] if t["certainty"] != "known"]
    known = [t for t in att["techniques"] if t["certainty"] == "known"]
    if obs:
        bits = []
        for t in obs:
            s = f"{t['id']} {t['name']} ({t['certainty_label'].split(' (')[0].lower()}: {t['role']}"
            s += f"; {t['status']}" if t.get("status") in ("suggested", "please check") else ""
            s += f"; retired in {t['retired_in']}" if t.get("retired_in") else ""
            bits.append(s + ")")
        out.append(f"MITRE ATT&CK v{v}: " + "; ".join(bits) + ".")
    if known:
        by = {}
        for t in known:
            by.setdefault((t.get("tactics") or ["Other"])[0], []).append(f"{t['id']} {t['name']}")
        out.append(f"Known for this malware (MITRE ATT&CK v{v}, {att.get('software') or 'Software'}): "
                   + "; ".join(f"{ta}: {', '.join(v2)}" for ta, v2 in by.items()) + ".")
        if att.get("groups"):
            out.append(f"Groups MITRE says use it: {', '.join(att['groups'])}.")
    if att.get("source"):                                 # CVE techniques (CTID KEV)
        out.append(f"Source: {att.get('licence') or att['source']}" + (f" Mapped with ATT&CK v{att['mapped_with']}." if att.get("mapped_with") else ""))
    return out


def ids_text(att):
    """Short: 'T1071.001, T1110.001 (ATT&CK v20.1)' for CSV cells and the Executive card."""
    if not att or not att.get("techniques"):
        return ""
    ids = list(dict.fromkeys(t["id"] for t in att["techniques"] if t["certainty"] != "known"))
    known = len({t["id"] for t in att["techniques"] if t["certainty"] == "known"})
    return (", ".join(ids) + (f"; {known} known for this malware" if known else "") + f" (ATT&CK v{att.get('version')})").strip("; ")


def by_tactic(att):
    """{tactic: [technique, ...]} for the Executive view."""
    out = {}
    for t in (att or {}).get("techniques") or []:
        for ta in (t.get("tactics") or ["Other"])[:1]:
            out.setdefault(ta, [])
            if t["id"] not in [x["id"] for x in out[ta]]:
                out[ta].append(t)
    return out


# ------------------------------------------------------------------------------------------------ routes
def install(app, ctx):
    """GET /api/attack (summary, to-do, reviewed), /api/attack/search?q=, /api/attack/shortlist?report=;
    POST /api/attack/mapping {report, techniques, nofit, note}. ctx: map (AttackMap), allowed(), change_allowed(),
    fresh(), me() -> (user, name)."""
    from flask import jsonify, request
    am = ctx["map"]

    @app.route("/api/attack")
    def api_attack():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        try:
            am.sync()
        except OSError:
            pass
        return jsonify(summary=am.summary(), todo=am.todo(), reviewed=am.reviewed(),
                       certainty=CERTAINTY, roles=ROLE)

    @app.route("/api/attack/search")
    def api_attack_search():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        return jsonify(results=am.search(request.args.get("q", "")), version=am.version())

    @app.route("/api/attack/shortlist")
    def api_attack_shortlist():
        if not ctx["allowed"]():
            return jsonify(error="Definitions are for researchers and admins."), 403
        return jsonify(results=am.shortlist(str(request.args.get("report", ""))[:80]), version=am.version())

    @app.route("/api/attack/technique/<tid>")
    def api_attack_technique(tid):
        """MITRE's full description of one technique (public MITRE text), for whoever reads ATT&CK in Looking Glass:
        researchers, advisors, management and analysts."""
        if not ctx.get("readers", ctx["allowed"])():
            return jsonify(error="Not for your role."), 403
        d = am.full_description(str(tid)[:12].upper())
        if not d:
            return jsonify(error="No such technique in the local copy of ATT&CK."), 404
        return jsonify(**d, notice="© The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation.")

    @app.route("/api/attack/mapping", methods=["POST"])
    def api_attack_mapping():
        if not ctx["change_allowed"]():
            return jsonify(error="Only researchers and admins can change mappings."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True)
        if not isinstance(b, dict):
            return jsonify(error="JSON expected"), 400
        tl = b.get("techniques") or []
        if not isinstance(tl, list):
            return jsonify(error="techniques: a list"), 400
        user, name = ctx["me"]()
        m, err = am.review(str(b.get("report") or "")[:80], tl, bool(b.get("nofit")), b.get("note"), user, name)
        if err:
            return jsonify(error=err), 400
        return jsonify(ok=True, mapping=m, todo=am.todo())

    return am
