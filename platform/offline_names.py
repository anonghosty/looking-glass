"""Offline explanations of malware / botnet / tool names, behind Malpedia (2026-11-13).

Two free sources are downloaded once by manage/fetch_offline_names.py (at most once a week) and kept in data/:
  data/names_misp_galaxy.json   MISP Galaxy clusters malpedia.json, botnet.json and tool.json (github.com/MISP/misp-galaxy)
  data/names_attack.json        MITRE ATT&CK malware and tool objects (github.com/mitre-attack/attack-stix-data)
Each is a compact index (name, synonyms, description, references) written by build_misp() / build_attack() below.

A look-up only reads these files: nothing about a name, a host or a report is ever sent anywhere. The only traffic is
the download itself, started by an administrator (or a weekly cron line), which asks GitHub for public files.

Order of the answers (app.py mp_resolve): the researchers' own definition > Malpedia (with a token) > MISP Galaxy >
MITRE ATT&CK > "not found". The card says which source answered and carries the source's licence notice:
  - MISP Galaxy's Malpedia cluster is Malpedia's content (Fraunhofer FKIE), licensed CC BY-NC-SA 3.0;
  - the other MISP Galaxy clusters are CC0 1.0 / BSD 2-Clause (MISP Project);
  - ATT&CK keeps MITRE's notice (copyright, and reproduced with the permission of The MITRE Corporation).
"""
import json
import os
import re
import threading

MISP_FILE = "names_misp_galaxy.json"
ATTACK_FILE = "names_attack.json"
MISP_CLUSTERS = ("malpedia", "botnet", "tool")            # best first: Malpedia's own text, then botnets, then tools
MISP_URL = "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/{}.json"
ATTACK_URLS = {
    "enterprise": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "mobile": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/mobile-attack/mobile-attack.json",
    "ics": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/ics-attack/ics-attack.json",
}
REFRESH_DAYS = 7                                          # the fetch script refuses to download again sooner (unless --force)

LICENCE = {
    "malpedia": ("Malpedia (Fraunhofer FKIE) via MISP Galaxy. Malpedia content is licensed CC BY-NC-SA 3.0 "
                 "(creativecommons.org/licenses/by-nc-sa/3.0/)."),
    "botnet": "MISP Galaxy, Botnet cluster (MISP Project), licensed CC0 1.0 / BSD 2-Clause.",
    "tool": "MISP Galaxy, Tool cluster (MISP Project), licensed CC0 1.0 / BSD 2-Clause.",
    "attack": ("MITRE ATT&CK. © The MITRE Corporation. This work is reproduced and distributed with the permission of "
               "The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation."),
}
LICENCE_SHORT = {"malpedia": "Malpedia content via MISP Galaxy, CC BY-NC-SA 3.0", "botnet": "MISP Galaxy, CC0 1.0 / BSD 2-Clause",
                 "tool": "MISP Galaxy, CC0 1.0 / BSD 2-Clause", "attack": "MITRE ATT&CK, © The MITRE Corporation"}
LABEL = {"malpedia": "MISP Galaxy · Malpedia cluster", "botnet": "MISP Galaxy · Botnet cluster",
         "tool": "MISP Galaxy · Tool cluster", "attack": "MITRE ATT&CK"}

MAX_DESC = 4000              # characters of a description kept
MAX_SYN = 20                 # synonyms kept per entry
MAX_REFS = 12                # references kept per entry
MAX_NAME = 120


def flat(x):
    """'Pseudo_Manuscrypt' == 'pseudo manuscrypt' == 'pseudomanuscrypt'."""
    return re.sub(r"[^a-z0-9]", "", str(x or "").lower())


def _s(x, n):
    return re.sub(r"\s+", " ", str(x or "")).strip()[:n] if isinstance(x, (str, int, float)) else ""


def _urls(refs):
    """Only http(s) links, de-duplicated, at most MAX_REFS (the page also refuses any other scheme)."""
    out = []
    for u in refs or []:
        u = _s(u, 500)
        if re.match(r"^https?://[^\s<>\"']+$", u) and u not in out:
            out.append(u)
        if len(out) >= MAX_REFS:
            break
    return out


def _syn(values, name):
    out, seen = [], {flat(name)}
    for v in values or []:
        v = _s(v, MAX_NAME)
        if v and flat(v) and flat(v) not in seen:
            seen.add(flat(v)); out.append(v)
        if len(out) >= MAX_SYN:
            break
    return out


# ---------------------------------------------------------------------------------------------- building the indexes
def build_misp(clusters):
    """{cluster: parsed MISP Galaxy JSON} -> the compact index written to data/names_misp_galaxy.json."""
    entries = []
    versions = {}
    for c in MISP_CLUSTERS:
        doc = clusters.get(c)
        if not isinstance(doc, dict) or not isinstance(doc.get("values"), list):
            continue
        versions[c] = doc.get("version")
        for v in doc["values"]:
            if not isinstance(v, dict):
                continue
            name = _s(v.get("value"), MAX_NAME)
            if not name:
                continue
            meta = v.get("meta") if isinstance(v.get("meta"), dict) else {}
            entries.append({"cluster": c, "name": name, "synonyms": _syn(meta.get("synonyms"), name),
                            "description": _s(v.get("description"), MAX_DESC), "references": _urls(meta.get("refs")),
                            "uuid": _s(v.get("uuid"), 64)})
    return {"source": "misp-galaxy", "versions": versions, "entries": entries}


_CITE = re.compile(r"\s*\(Citation:[^)]*\)")
_MDLINK = re.compile(r"\[([^\]]+)\]\((?:https?://[^)\s]+)\)")


def attack_text(d):
    """ATT&CK descriptions are Markdown with '(Citation: ...)' marks: plain text for the card."""
    d = _MDLINK.sub(r"\1", str(d or ""))
    d = _CITE.sub("", d)
    d = re.sub(r"<[^>]{1,40}>", "", d)                   # the odd <code> tag
    return _s(d, MAX_DESC)


TID = re.compile(r"^T\d{4}(?:\.\d{3})?$")             # T1071, T1071.001 (enterprise, mobile, ICS)


def _own_ref(o):
    ext = [r for r in o.get("external_references") or [] if isinstance(r, dict)]
    return ext, next((r for r in ext if r.get("source_name") in ("mitre-attack", "mitre-mobile-attack", "mitre-ics-attack")
                      and r.get("external_id")), {})


SHORT_DESC = 300          # characters of MITRE's text kept per technique in the index (whole sentences)
SHORT_DETECT = 220
FULL_FILE = "attack_descriptions.json"    # the full descriptions, read only when someone expands one


def short_text(text, limit=SHORT_DESC):
    """The first sentence of MITRE's text, plus the next while it fits in `limit`: whole sentences, never cut midway
    (a first sentence longer than the limit is kept whole)."""
    t = attack_text(text)
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z(\[])", t)
    out = parts[0] if parts else ""
    for p in parts[1:]:
        if len(out) + 1 + len(p) > limit:
            break
        out += " " + p
    return out


def tactic_label(phase):
    """'command-and-control' -> 'Command and Control'."""
    words = str(phase or "").split("-")
    return " ".join(w if w in ("and", "or", "of") else w.capitalize() for w in words)


def build_attack(bundles):
    """{domain: parsed STIX bundle} -> the compact index written to data/names_attack.json:
    entries   malware and tools (revoked and deprecated left out), each with the techniques MITRE links to it and the
              groups MITRE says use it (step 2, the ATT&CK mapping);
    techniques every technique by ID (T1071.001), with its name, tactics, link and state: active, revoked (with the
              technique that replaces it, from the STIX "revoked-by" relationship) or deprecated."""
    entries, notice, seen, versions = [], "", set(), {}
    techs, by_stix, sw_of, uses, groups, revoked_by = {}, {}, {}, {}, {}, {}
    coas, mitigates, full = {}, [], {}                    # mitigations (course-of-action), their links, full texts
    for dom in ATTACK_URLS:
        b = bundles.get(dom)
        if not isinstance(b, dict) or not isinstance(b.get("objects"), list):
            continue
        for o in b["objects"]:
            if not isinstance(o, dict):
                continue
            t = o.get("type")
            if t == "x-mitre-collection" and dom not in versions:   # the ATT&CK release, e.g. 18.0
                versions[dom] = _s(o.get("x_mitre_version"), 20)
            if t == "marking-definition" and not notice:
                notice = _s((o.get("definition") or {}).get("statement") if isinstance(o.get("definition"), dict) else "", 400)
            if t == "attack-pattern":
                ext, own = _own_ref(o)
                tid = _s(own.get("external_id"), 20)
                if not TID.match(tid):
                    continue
                by_stix[o.get("id")] = tid
                state = "revoked" if o.get("revoked") else "deprecated" if o.get("x_mitre_deprecated") else "active"
                old = techs.get(tid)
                if old and old["state"] == "active" and state != "active":
                    continue                              # the same ID in two domains: the active one counts
                techs[tid] = {"name": _s(o.get("name"), 120), "state": state, "domain": dom,
                              "tactics": [tactic_label(k.get("phase_name")) for k in o.get("kill_chain_phases") or []
                                          if isinstance(k, dict) and k.get("phase_name")][:6],
                              "url": (_urls([own.get("url")]) or [""])[0], "sub": "." in tid,
                              "desc": short_text(o.get("description"))}
                if o.get("x_mitre_detection"):
                    techs[tid]["detect"] = short_text(o.get("x_mitre_detection"), SHORT_DETECT)
                if state == "active" and o.get("description"):
                    full[tid] = attack_text(o.get("description"))
            elif t == "course-of-action":                 # a mitigation: M1035 Limit Access to Resource Over Network
                ext, own = _own_ref(o)
                mid = _s(own.get("external_id"), 12)
                if re.match(r"^M\d{4}$", mid) and not o.get("revoked") and not o.get("x_mitre_deprecated"):
                    coas[o.get("id")] = mid
                    techs.setdefault("_mitigations", {})[mid] = {"name": _s(o.get("name"), 120), "text": short_text(o.get("description"), 200),
                                                                 "url": (_urls([own.get("url")]) or [""])[0]}
            elif t == "intrusion-set":
                groups[o.get("id")] = _s(o.get("name"), 80)
            elif t == "relationship":
                rt, src, dst = o.get("relationship_type"), o.get("source_ref"), o.get("target_ref")
                if o.get("revoked") or o.get("x_mitre_deprecated"):
                    continue
                if rt == "uses":
                    uses.setdefault(src, set()).add(dst)
                elif rt == "revoked-by":
                    revoked_by[src] = dst
                elif rt == "mitigates":                   # course-of-action -> attack-pattern, with what it means there
                    mitigates.append((src, dst, short_text(o.get("description"), 200)))
            if t not in ("malware", "tool") or o.get("revoked") or o.get("x_mitre_deprecated"):
                continue
            name = _s(o.get("name"), MAX_NAME)
            if not name or o.get("id") in seen:
                continue
            seen.add(o.get("id"))
            ext, own = _own_ref(o)
            sw_of[o.get("id")] = len(entries)
            entries.append({"cluster": "attack", "kind": t, "name": name,
                            "synonyms": _syn((o.get("x_mitre_aliases") or []) + (o.get("aliases") or []), name),
                            "description": attack_text(o.get("description")),
                            "references": _urls([r.get("url") for r in ext if r is not own]),
                            "id": _s(own.get("external_id"), 20), "url": _urls([own.get("url")])[0] if _urls([own.get("url")]) else "",
                            "platforms": [_s(p, 40) for p in (o.get("x_mitre_platforms") or [])[:8]]})
    mits = techs.pop("_mitigations", {})
    for src, dst, txt in mitigates:                       # each technique's mitigations: [M-id, what it means for it]
        mid, tid = coas.get(src), by_stix.get(dst)
        if mid and tid in techs and techs[tid]["state"] == "active":
            row = [mid, txt or mits.get(mid, {}).get("text", "")]
            lst = techs[tid].setdefault("mitigations", [])
            if mid not in [m[0] for m in lst]:
                lst.append(row)
    for src, dst in revoked_by.items():                   # the named replacement of a revoked technique
        a, b2 = by_stix.get(src), by_stix.get(dst)
        if a and b2 and a in techs:
            techs[a]["revoked_by"] = b2
    for sid, i in sw_of.items():                          # techniques MITRE links to the software, and its groups
        tl = sorted({by_stix[d] for d in uses.get(sid, ()) if d in by_stix and techs.get(by_stix[d], {}).get("state") == "active"})
        entries[i]["techniques"] = tl[:150]
        entries[i]["groups"] = sorted({groups[g] for g, ds in uses.items() if g in groups and sid in ds})[:30]
    return {"source": "mitre-attack", "notice": notice, "versions": versions, "entries": entries, "techniques": techs,
            "mitigations": mits, "full": full}           # "full" is written to its own file by the fetch script


# ---------------------------------------------------------------------------------------------- looking names up
class OfflineNames:
    """Reads the two indexes from data/ (again when a file changes) and answers name look-ups from them."""

    def __init__(self, data_dir, needles=None):
        self.dir = data_dir
        self.needles = needles or (lambda n: [(n or "").strip().lower()])
        self.lock = threading.Lock()
        self._files = {}                                  # file -> (mtime, doc, index {flat name: [(entry, how)]})

    def _load(self, fname):
        path = os.path.join(self.dir, fname)
        try:
            m = os.path.getmtime(path)
        except OSError:
            return None, {}
        with self.lock:
            hit = self._files.get(fname)
            if hit and hit[0] == m:
                return hit[1], hit[2]
            try:
                with open(path, encoding="utf-8") as f:
                    doc = json.load(f)
            except (OSError, ValueError):
                return None, {}
            idx = {}
            ents = [e for e in doc.get("entries") or [] if isinstance(e, dict) and e.get("name")]
            # two rules for synonyms (real cross-listings: MISP's Botnet cluster lists "Mirai (ELF)", the Malpedia
            # cluster's own entry name, as a synonym of katana; 127 MISP synonyms are another entry's name, 43 are
            # shared by differently named entries): a synonym that is another entry's own name never answers for that
            # name, and a synonym listed by entries of different names answers for none of them (ambiguous). Entries of
            # the same name in several clusters count as one family.
            names = {flat(e["name"]) for e in ents}
            owners = {}
            for e in ents:
                for s in e.get("synonyms") or []:
                    owners.setdefault(flat(s), set()).add(flat(e["name"]))
            for e in ents:
                own = flat(e["name"])
                idx.setdefault(own, []).append((e, "name"))
                for s in e.get("synonyms") or []:
                    fs = flat(s)
                    if not fs or fs == own:
                        continue
                    if fs in names or len(owners.get(fs, ())) > 1:
                        continue
                    idx.setdefault(fs, []).append((e, s))
            self._files[fname] = (m, doc, idx)
            return doc, idx

    def status(self):
        """What is installed: per source, the number of entries and when it was downloaded."""
        out = {}
        for key, fname in (("misp-galaxy", MISP_FILE), ("mitre-attack", ATTACK_FILE)):
            doc, _ = self._load(fname)
            out[key] = {"installed": bool(doc), "entries": len((doc or {}).get("entries") or []),
                        "fetched": (doc or {}).get("fetched", ""), "versions": (doc or {}).get("versions") or {}}
        return out

    @property
    def available(self):
        return any(v["installed"] for v in self.status().values())

    def _best(self, fname, name):
        """The best entry of one index for a name. Only entries with a description answer (a bare name says nothing,
        and in MISP Galaxy's own entries such ones match the wrong thing: 'popcorntime' the old video app, not the ransomware).
        A name match on any search string beats a synonym match (in MISP Galaxy, 'elf.mirai' is listed as a synonym of
        another family, while 'mirai' is Mirai's own name); then the plainest search string first (the full name
        before the shortened one), then Malpedia's cluster before botnet before tool."""
        doc, idx = self._load(fname)
        if not idx:
            return None, doc
        order = {c: i for i, c in enumerate(MISP_CLUSTERS + ("attack",))}
        found = []
        for i, needle in enumerate(self.needles(name)):
            for e, how in idx.get(flat(needle)) or []:
                if e.get("description"):
                    found.append(((how != "name", i, order.get(e.get("cluster"), 9)), {"entry": e, "how": how, "needle": needle}))
        if not found:
            return None, doc
        return min(found, key=lambda f: f[0])[1], doc

    def lookup_all(self, name):
        """Every offline source that knows the name, one card each, in order: MISP Galaxy, then MITRE ATT&CK."""
        name = (name or "").strip()
        if not name or len(name) > 100:
            return []
        out = []
        for fname in (MISP_FILE, ATTACK_FILE):
            hit, doc = self._best(fname, name)
            if hit:
                out.append(self._card(hit, doc, name))
        return out

    def lookup(self, name):
        """The first card for a name, or None: MISP Galaxy first, MITRE ATT&CK second."""
        cards = self.lookup_all(name)
        return cards[0] if cards else None

    @staticmethod
    def _card(hit, doc, name):
        e, how = hit["entry"], hit["how"]
        c = e.get("cluster", "")
        attack = c == "attack"
        if how == "name":
            matched = f"name {e['name']}" + (f" (searched as \"{hit['needle']}\")" if flat(hit["needle"]) != flat(name) else "")
        else:
            matched = f"alternative name {how}"
        notice = LICENCE.get(c, "")
        if attack and (doc or {}).get("notice") and doc["notice"] not in notice:
            notice = f"MITRE ATT&CK. {doc['notice']} This work is reproduced and distributed with the permission of The MITRE Corporation."
        return {
            "found": False, "reference": True, "source": "mitre-attack" if attack else "misp-galaxy", "cluster": c,
            "source_label": LABEL.get(c, c), "licence": notice, "licence_short": LICENCE_SHORT.get(c, ""), "title": e["name"], "name": e["name"],
            "id": e.get("id", ""), "url": e.get("url", ""), "kind": "", "type": ("ATT&CK " + e.get("kind", "")) if attack else "",
            "description": e.get("description", ""), "alt_names": list(e.get("synonyms") or [])[:12],
            "references": list(e.get("references") or [])[:6], "reference_count": len(e.get("references") or []),
            "platforms": list(e.get("platforms") or []), "matched_by": matched,
            "techniques": list(e.get("techniques") or []), "groups": list(e.get("groups") or []),
            "fetched": (doc or {}).get("fetched", ""),
        }
