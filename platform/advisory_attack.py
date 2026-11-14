"""MITRE ATT&CK in advisories (2026-11-13, approved addition): each technique with MITRE's own short definition ("What it
is", marked MITRE), why Looking Glass put it in this advisory ("Why it is in this advisory": the mapping's role and the
advisory's own figures; not MITRE's words), and up to three of MITRE's mitigations that suit the kind of report ("How to
defend"), with the link to attack.mitre.org.

Only reviewed mappings go to recipients. A suggested (not yet reviewed) one is shown to the advisor, flagged, and must be
confirmed for this advisory or removed before the report can be generated; the server refuses otherwise (advisory.py
calls pending() before generating, marking drafted and sending). The advisor's choices are kept in the advisory
(attack_decisions) and are part of its content fingerprint, so a change after generating makes the report out of date.
A generated report keeps the techniques it carried (the snapshot), so a sent advisory shows what the recipient got.
Only counts and products are used, never an address: the text is the same for every reader.
"""
import re

DECIDE = ("confirm", "remove", "restore")
REVIEWED = ("reviewed", "confirmed for this advisory")


def key_of(t):
    """One technique in one place: 'T1133|scan_rdp' (a report's mapping), 'T1568.002|name:tinba-dga' (Shadowserver's
    name) or 'T1190|cve:CVE-2024-1234:how attackers exploit it' (CTID's KEV mapping of a CVE)."""
    if t.get("cve"):
        return f"{t['id']}|cve:{t['cve']}:{t.get('kind_key') or ''}"
    return f"{t['id']}|{t.get('report_key') or 'name:' + str(t.get('category') or '')}"


def _why(t, devices):
    """"Why it is in this advisory", in Looking Glass's words: the mapping and the advisory's figures (no address)."""
    role = t.get("role") or ""
    if t.get("cve"):
        hit = [d for d in devices if t["cve"] in (d.get("cves") or [])]
        src = (f"MITRE CTID maps {t['cve']} to this technique ({t.get('kind') or 'mapped'}): {role}."
               + (" Looking Glass's administrators trust CTID's mappings." if t.get("trusted") else ""))
        if hit:
            src += f" {len(hit)} {'host' if len(hit) == 1 else 'hosts'} in this advisory {'has' if len(hit) == 1 else 'have'} it."
        return src
    if t.get("report_key"):
        title = t.get("report") or t["report_key"]
        hit = [d for d in devices if title in (d.get("reports") or [])]
        src = f"Looking Glass maps the report “{title}” to this technique: {role}."
    else:
        c = t.get("category") or ""
        hit = [d for d in devices if c in (d.get("categories") or [])]
        src = f"Shadowserver names the infection “{c}” this way ({(t.get('why') or '').rstrip('.')}): {role}."
    if hit:
        labels = {}
        for d in hit:
            for lb in d.get("labels") or []:
                labels[lb] = labels.get(lb, 0) + 1
        top = [lb for lb, _ in sorted(labels.items(), key=lambda kv: -kv[1])[:3]]
        noun = "host" if len(hit) == 1 else "hosts"
        src += f" {len(hit)} {noun} in this advisory {'is' if len(hit) == 1 else 'are'} in it" + (f" (most often: {', '.join(top)})" if top else "") + "."
    return src


def build(am, auto, adv):
    """The advisory's techniques for the advisor: {version, techniques (what goes out), pending (suggested, waiting for
    the advisor), removed}. Reviewed mappings go out; suggested ones only once the advisor confirms them here."""
    if not am or not am.version():
        return None                                       # no copy of ATT&CK downloaded: no ATT&CK section, nothing to decide
    try:
        items = am.for_reports([r["key"] for r in auto.get("reports") or []])
        for c in auto.get("categories") or []:
            items += [dict(it, category=c) for it in am.name_items(c)]
        # the CVEs the advisory names: CTID's KEV mappings, suggestions until reviewed, unless the admins trust CTID
        trusted = bool((am.ctid_trust() or {}).get("on"))
        for c in auto.get("cves") or []:
            for t in (am.cve_attack(c) or {}).get("techniques") or []:
                items.append(dict(t, cve=c, status="reviewed" if trusted else "suggested", trusted=trusted))
    except Exception:                                     # noqa: BLE001  (a damaged copy must never break an advisory)
        return None
    if not items:
        return None
    dec = adv.get("attack_decisions") or {}
    out, pending, removed, seen = [], [], [], set()
    for t in items:
        k = key_of(t)
        if k in seen:
            continue
        seen.add(k)
        t = dict(t, key=k, why_here=_why(t, auto.get("devices") or []))
        d = dec.get(k)
        if d == "remove":
            removed.append(t)
        elif t.get("status") == "reviewed":
            out.append(t)
        elif d == "confirm":
            out.append(dict(t, status="confirmed for this advisory"))
        else:
            pending.append(t)
    return {"version": am.version(), "techniques": out, "pending": pending, "removed": removed}


def for_recipients(att):
    """What goes out: reviewed or advisor-confirmed techniques only, nothing pending or removed."""
    if not att or not att.get("techniques"):
        return None
    ts = [t for t in att["techniques"] if t.get("status") in REVIEWED]
    return {"version": att.get("version"), "techniques": ts} if ts else None


def pending_text(att):
    """The refusal when suggested mappings are still waiting ("" when none)."""
    p = (att or {}).get("pending") or []
    if not p:
        return ""
    uniq = list(dict.fromkeys(f"{t['id']} {t['name']}" if t.get("name") and t["name"] != t["id"] else t["id"] for t in p))
    names = ", ".join(uniq[:4]) + (f" and {len(uniq) - 4} more" if len(uniq) > 4 else "")
    return (f"{len(p)} MITRE ATT&CK mapping{'s are' if len(p) != 1 else ' is'} only suggested, not reviewed ({names}): "
            "confirm or remove each on the advisory page first. Only reviewed mappings go to recipients.")


def decide(adv, att, key, action):
    """The advisor's choice for one technique of this advisory. Returns an error text or ""."""
    if action not in DECIDE:
        return "action: confirm, remove or restore"
    known = {t["key"] for part in ("techniques", "pending", "removed") for t in (att or {}).get(part) or []}
    if not isinstance(key, str) or key not in known or not re.match(r"^T\d{4}(\.\d{3})?\|", key):
        return "Not a technique of this advisory."
    dec = adv.setdefault("attack_decisions", {})
    if action == "restore":
        dec.pop(key, None)
    else:
        dec[key] = action
    return ""


def confirm_all(adv, att, keys=None):
    """"Confirm all for this advisory": confirms the techniques still pending in THIS advisory (only those of `keys`, the
    ones the advisor saw, when given). Kept in the advisory only: the researchers' mappings are not touched. Returns
    (confirmed keys, error)."""
    pending = [t["key"] for t in (att or {}).get("pending") or []]
    if keys is not None:
        if not isinstance(keys, list) or len(keys) > 500 or not all(isinstance(k, str) for k in keys):
            return [], "keys: the list of techniques shown"
        pending = [k for k in pending if k in set(keys)]
    if not pending:
        return [], "Nothing left to confirm: every technique of this advisory is decided."
    dec = adv.setdefault("attack_decisions", {})
    for k in pending:
        dec[k] = "confirm"
    return pending, ""


def snapshot(att):
    """What a generated report carries, kept with it: the recipients' techniques with their texts."""
    keep = ("id", "name", "tactics", "url", "certainty", "certainty_label", "role", "status", "report", "category", "desc",
            "detect", "defend", "why_here", "key", "cve", "kind", "note", "comment", "trusted", "mapped_id")
    r = for_recipients(att)
    return {"version": r["version"], "techniques": [{k: t.get(k) for k in keep if t.get(k) not in (None, "", [])} for t in r["techniques"]]} if r else None
