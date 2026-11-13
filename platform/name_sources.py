"""One card per malware / botnet name, with every source side by side (2026-11-13, approved design, step 1).

Sources, in order: the researchers' own definition (Looking Glass), Malpedia (with a token), MISP Galaxy, MITRE ATT&CK
(the last two from the copies in data/, offline_names.py). The headline is the researchers' definition when there is one,
else the first source that knows the name; every other source that knows it is listed under "Also described by" with
its own description, other names, references and credit / licence. When none knows it: "No source knows this name",
with the plain explanation from the reports (malpedia_explain in app.py).

Only names are matched, and only against Malpedia (the existing look-up) and the local copies: nothing about hosts leaves
the server. The researchers' definitions always win and are never overwritten.

Also here: the status of the local copies and the "Refresh sources" button (admins), which runs
manage/fetch_offline_names.py in the background; every refresh is in the audit log (written by that script).
"""
import json
import os
import subprocess
import sys
import threading
import time

from flask import g, jsonify, request

MALPEDIA_LICENCE = ("Malpedia (Fraunhofer FKIE), malpedia.caad.fkie.fraunhofer.de. Malpedia content is licensed "
                    "CC BY-NC-SA 3.0 (creativecommons.org/licenses/by-nc-sa/3.0/).")
MALPEDIA_SHORT = "Malpedia, CC BY-NC-SA 3.0"
SKIP_VERDICTS = ("activity", "generic", "software")   # not malware names: a malware list would only match by accident
REFRESH_STATUS = "names_refresh.json"                # written by manage/fetch_offline_names.py
MANUAL_GAP = 3600                                    # the button downloads at most once an hour
FOLD_KEYS = ("source", "source_label", "licence", "licence_short", "name", "title", "id", "url", "kind", "type",
             "family", "description", "alt_names", "attribution", "references", "reference_count", "platforms",
             "matched_by", "by", "updated", "country", "sponsor", "families", "techniques", "groups")


def source_text(x):
    """'Source: ...' for a card, as one line of plain text (PDFs, CSV): the source and its credit / licence."""
    if not x:
        return ""
    if x.get("curated"):
        who = x.get("by") or "the researchers"
        return f"Source: Looking Glass definition, written by {who}" + (f" on {x['updated']}" if x.get("updated") else "") + "."
    if x.get("licence"):
        return f"Source: {x['licence']}"
    if x.get("nosource"):
        return "Source: no source knows this name; explained from the evidence in the reports."
    return ""


def also_text(x):
    """'Also described by: ...' as one line of plain text: each other source, the name it uses and its page."""
    parts = []
    for a in (x or {}).get("also") or []:
        bit = a.get("source_label") or a.get("source") or "Another source"
        nm = a.get("name") or a.get("title") or ""
        bit += f" as {nm}" if nm else ""
        if a.get("url"):
            bit += f" ({a['url']})"
        if a.get("licence_short"):
            bit += f" [{a['licence_short']}]"
        parts.append(bit)
    return ("Also described by: " + "; ".join(parts) + ".") if parts else ""


class NameSources:
    def __init__(self, offline, malpedia, ctx):
        """ctx: curated(name) -> the researchers' entry with references or a Malpedia id; kb() -> the definitions;
        mp_card(lookup) -> the Malpedia card; record(name, family) -> remember the Malpedia check; explain(name) ->
        the plain explanation; by(entry) -> the author's name."""
        self.offline, self.malpedia, self.ctx = offline, malpedia, ctx
        self.attack = None                         # set by app.py: the ATT&CK mapping (attack_map.AttackMap)

    # ---------------------------------------------------------------------------------------------- the cards
    def _own(self, name):
        """The researchers' definition as a card (headline), or None. Without a Malpedia token the Looking Glass
        knowledge base answers too (as before)."""
        cur = self.ctx["curated"](name)
        e = cur
        if not self.malpedia.enabled and not e:
            e = self.ctx["kb"]().get((name or "").lower()) or None
        if not e or not (e.get("title") or e.get("description")):
            return None
        return {"found": False, "curated": True, "source": "looking-glass", "source_label": "Looking Glass definition",
                "title": e.get("title") or name, "name": e.get("title") or name, "type": e.get("type", ""),
                "description": e.get("description", ""), "references": e.get("references", []),
                "updated": e.get("updated", ""), "by": self.ctx["by"](e) or ("Looking Glass" if not cur else ""),
                "malpedia_id": e.get("malpedia", ""), "offline": not self.malpedia.enabled}

    def _malpedia(self, name, cur):
        """Malpedia's card (the researchers' chosen family or actor first), and the raw look-up. Raises as before
        (RuntimeError: rate limit / unreachable; ValueError: a bad value)."""
        if not self.malpedia.enabled:
            return None, {}
        ov = (cur or {}).get("malpedia") or ""
        r = (self.malpedia.lookup("actor", ov[6:]) if ov.startswith("actor:") else self.malpedia.lookup("family", ov)) if ov \
            else self.malpedia.lookup("infection", name)
        card = self.ctx["mp_card"](r)
        self.ctx["record"](name, (card.get("family") or f"actor:{card.get('actor')}") if card else "")
        if card:
            actor = card.get("kind") == "actor"
            card.update(source="malpedia", source_label="Malpedia · threat actor" if actor else "Malpedia",
                        licence=MALPEDIA_LICENCE, licence_short=MALPEDIA_SHORT)
            yara = (r.get("family") or {}).get("yara")
            if yara:
                card["yara"] = yara
            if cur and cur.get("malpedia"):
                card["matched_by"] = "the administrator's definition"
            if cur and cur.get("references"):
                card["curated_references"] = cur["references"]
        return card, r

    def offline_cards(self, name, explained=None):
        x = explained or self.ctx["explain"](name)
        if x.get("verdict") in SKIP_VERDICTS:
            return []
        try:
            cards = self.offline.lookup_all(name)
        except Exception:                          # noqa: BLE001  (a damaged copy must never break a look-up)
            return []
        for c in cards:
            c["offline"] = not self.malpedia.enabled
        return cards

    @staticmethod
    def fold(card):
        return {k: card[k] for k in FOLD_KEYS if card.get(k) not in (None, "", [], {})}

    def resolve(self, name):
        """(headline card with 'also' and 'sources', the raw Malpedia look-up) for a name."""
        x = self.ctx["explain"](name)
        cur = self.ctx["curated"](name)
        own = self._own(name)
        mcard, r = self._malpedia(name, cur)
        cards = [c for c in [own, mcard] + self.offline_cards(name, x) if c]
        if cards:
            head, others = cards[0], cards[1:]
        else:
            head, others = {"found": False, "nosource": True, "offline": not self.malpedia.enabled, **x,
                            "reason": f"{x['title']}. {x['text']}"}, []
        head = dict(head)
        head["also"] = [self.fold(c) for c in others]
        head["sources"] = [c.get("source_label") for c in cards]
        head.setdefault("seen_in", x.get("seen_in") or [])
        if not head.get("found") and r.get("matches"):
            head["near"] = [m["id"] for m in (r.get("matches") or [])[:3]]
        if self.attack:                            # MITRE ATT&CK techniques (attack_map.py, step 2)
            try:
                att = self.attack.card_attack(name, head)
            except Exception:                      # noqa: BLE001  (a damaged copy must never break a look-up)
                att = None
            if att:
                head["attack"] = att
        if head.get("source") == "mitre-attack":   # its technique list lives in head["attack"], not twice
            head.pop("techniques", None)
        return head, r

    def known_by(self, name, family_found=""):
        """The labels of the sources that know a name, cheaply (Definitions page rows): Malpedia from the recorded
        check, the offline copies from their indexes."""
        out = []
        if family_found:
            out.append("Malpedia · threat actor" if str(family_found).startswith("actor:") else "Malpedia")
        out += [c["source_label"] for c in self.offline_cards(name)]
        return out

    def other_sources(self, name):
        """Every source but the researchers' own, full cards (the Definitions editor shows them alongside)."""
        cards = []
        if self.malpedia.enabled:
            try:
                mcard, _ = self._malpedia(name, None)
                if mcard:
                    cards.append(self.fold(mcard))
            except (RuntimeError, ValueError):
                pass
        cards += [self.fold(c) for c in self.offline_cards(name)]
        return cards


# -------------------------------------------------------------------------------------------------- refresh + status
def install(app, ctx):
    """Routes: GET /api/name-sources (status; researchers and admins), POST /api/name-sources/refresh (admins).
    ctx: base_dir, offline (OfflineNames), allowed() (Definitions page), can_refresh() (admins), csrf_ok(), fresh(),
    audit, python (the .venv interpreter)."""
    data_dir = os.path.join(ctx["base_dir"], "data")
    script = os.path.join(ctx["base_dir"], "manage", "fetch_offline_names.py")
    state = {"proc": None, "started": 0.0, "lock": threading.Lock()}

    def last():
        try:
            with open(os.path.join(data_dir, REFRESH_STATUS), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}

    def running():
        p = state["proc"]
        return bool(p and p.poll() is None)

    def status():
        st = ctx["offline"].status()
        lr = last()
        return {"sources": [
                    {"key": "misp-galaxy", "label": "MISP Galaxy", "installed": st["misp-galaxy"]["installed"],
                     "entries": st["misp-galaxy"]["entries"], "fetched": st["misp-galaxy"]["fetched"],
                     "versions": st["misp-galaxy"]["versions"]},
                    {"key": "mitre-attack", "label": "MITRE ATT&CK", "installed": st["mitre-attack"]["installed"],
                     "entries": st["mitre-attack"]["entries"], "fetched": st["mitre-attack"]["fetched"],
                     "versions": st["mitre-attack"]["versions"]}],
                "last": {k: lr.get(k) for k in ("at", "by", "ok", "message")} if lr else {},
                "running": running(), "can_refresh": bool(ctx["can_refresh"]())}

    @app.route("/api/name-sources")
    def api_name_sources():
        if not (ctx["allowed"]() or ctx["can_refresh"]()):
            return jsonify(error="For researchers and admins."), 403
        return jsonify(status())

    @app.route("/api/name-sources/refresh", methods=["POST"])
    def api_name_sources_refresh():
        if not ctx["can_refresh"]():
            return jsonify(error="Only administrators can refresh the sources."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="The page is out of date (security token): reload it and try again."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        with state["lock"]:
            if running():
                return jsonify(error="A refresh is already running.", **status()), 409
            since = time.time() - max(state["started"], _ts(last().get("at")))
            if since < MANUAL_GAP:
                return jsonify(error=f"The sources were refreshed {int(since // 60)} minutes ago; try again in "
                                     f"{int((MANUAL_GAP - since) // 60) + 1} minutes.", **status()), 429
            user = ((getattr(g, "user", None) or {}).get("user") or "admin")[:60]
            env = dict(os.environ, LG_OFFLINE_NAMES_DIR=data_dir)
            state["proc"] = subprocess.Popen([ctx.get("python") or sys.executable, script, "--force", "--by", user],
                                             cwd=ctx["base_dir"], env=env, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            state["started"] = time.time()
        ctx["audit"].add("name_sources_refresh_started", user=user, target="MISP Galaxy, MITRE ATT&CK",
                         detail="started from the Definitions page")
        return jsonify(started=True, **status())

    return {"status": status}


def _ts(iso):
    from datetime import datetime
    try:
        return datetime.fromisoformat(iso).timestamp()
    except (TypeError, ValueError):
        return 0.0
