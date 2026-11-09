"""Malpedia lookups (https://malpedia.caad.fkie.fraunhofer.de) for infections, tags and sample hashes.

The API token stays on the server (MALPEDIA_TOKEN in .env); browsers only see the results. Answers are cached
in data/malpedia_cache.json for a week, so repeated lookups are instant and Malpedia is not asked twice.
"""
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = "https://malpedia.caad.fkie.fraunhofer.de/api/"
SITE = "https://malpedia.caad.fkie.fraunhofer.de/details/"
HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
ACTOR_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,80}$")             # tick, apt28, angry_likho
FAMILY_ID = re.compile(r"^[a-z0-9]+(?:\.[a-z0-9_-]+)+$")        # win.emotet, elf.mirai, apk.badbox_2
MAX_CACHE = 3000              # entries kept in data/malpedia_cache.json (oldest dropped)
MAX_PER_MINUTE = 30           # Malpedia API calls per minute (cached answers do not count)
# Shadowserver naming -> preferred Malpedia platform prefix
PLATFORM_HINT = {"android": "apk.", "apk": "apk.", "elf": "elf.", "linux": "elf.", "mirai": "elf.", "win": "win.", "js": "js.", "jar": "jar."}


class Malpedia:
    def __init__(self, token, cache_path, ttl=7 * 86400, logger=None):
        self.token = (token or "").strip()
        self.cache_path = cache_path
        self.ttl = ttl
        self.log = logger
        self.lock = threading.Lock()
        self.cache = {}
        try:
            with open(cache_path) as f:
                self.cache = json.load(f)
        except (OSError, ValueError):
            self.cache = {}

    @property
    def enabled(self):
        return bool(self.token)

    # ------------------------------------------------------------------ http + cache
    def _get(self, path):
        now = time.time()
        with self.lock:
            hit = self.cache.get(path)
            if hit and now - hit["t"] < self.ttl:
                return hit["data"]
            # at most MAX_PER_MINUTE calls a minute, so nobody can use up the API quota through this server
            self.calls = [t for t in getattr(self, "calls", []) if now - t < 60]
            if len(self.calls) >= MAX_PER_MINUTE:
                raise RuntimeError("Too many Malpedia lookups at the moment; try again in a minute")
            self.calls.append(now)
        req = urllib.request.Request(BASE + path, headers={"Authorization": "apitoken " + self.token,
                                                           "User-Agent": "LookingGlass/1.0", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                data = None
            else:
                raise RuntimeError(f"Malpedia answered {e.code}") from None
        except (urllib.error.URLError, TimeoutError) as e:
            raise RuntimeError(f"Malpedia could not be reached ({getattr(e, 'reason', e)})") from None
        with self.lock:
            self.cache[path] = {"t": now, "data": data}
            if len(self.cache) > MAX_CACHE:            # bounded: drop the oldest answers
                for k, _ in sorted(self.cache.items(), key=lambda kv: kv[1].get("t", 0))[: len(self.cache) - MAX_CACHE]:
                    self.cache.pop(k, None)
            tmp = self.cache_path + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(self.cache, f)
                os.replace(tmp, self.cache_path)
            except OSError:
                pass
        return data

    # ------------------------------------------------------------------ name matching
    @staticmethod
    def needles(name):
        """Search strings for a Shadowserver infection / tag name, most specific first."""
        n = (name or "").strip().lower()[:100]                  # names are short; never feed long text to the patterns
        out = [n]
        base = n.split(".")[-1]                                  # android.badbox2 -> badbox2
        for prefix in ("likely-rat-", "likely-", "avalanche-"):
            if base.startswith(prefix):
                base = base[len(prefix):]
        # words Shadowserver adds to say what was seen, not part of the malware's name: lumma-stealer-beacon -> lumma
        changed = True
        while changed:
            changed = False
            for suffix in ("-p2p", "-dga", "-proxy", "-sinkhole", "-beacon", "-download", "-payload", "-c2", "-cnc",
                           "-checkin", "-dropper", "-stealer", "-rat", "-botnet", "-bot"):
                if base.endswith(suffix) and len(base) > len(suffix) + 2:
                    base = base[: -len(suffix)]; changed = True
        out += [base, base.rstrip("0123456789"), re.sub(r"[-_.]", "", base), re.sub(r"[-_.]", " ", base)]
        return [x for i, x in enumerate(out) if x and len(x) >= 3 and x not in out[:i]]

    def find(self, name):
        """Malpedia families matching a name, best first, with why they matched."""
        n = (name or "").lower()
        hint = next((p for k, p in PLATFORM_HINT.items() if n.startswith(k + ".") or n.startswith(k + "-")), None)
        seen, results = set(), []
        for needle in self.needles(name):
            for r in self._get("find/family/" + urllib.parse.quote(needle, safe="")) or []:
                fid = r.get("name")
                if not fid or fid in seen:
                    continue
                seen.add(fid)
                short = fid.split(".", 1)[-1].lower()
                alts = [a for a in r.get("alt_names", []) if a]
                flat = lambda x: re.sub(r"[^a-z0-9]", "", x.lower())   # pseudo_manuscrypt == pseudomanuscrypt
                if short == needle or flat(short) == flat(needle):
                    how, score = f"family name {fid}", 100
                elif any(flat(a) == flat(needle) for a in alts):
                    how, score = f"alternative name {next(a for a in alts if flat(a) == flat(needle))}", 90
                elif short.startswith(needle) or re.search(r"(^|[_-])" + re.escape(needle), short):
                    how, score = f"partial name ({needle})", 60
                else:
                    how, score = f"partial alternative name ({needle})", 40
                if hint and fid.startswith(hint):
                    score += 5
                results.append({"id": fid, "alt_names": alts, "matched_by": how, "needle": needle, "score": score})
            if any(r["score"] >= 90 for r in results):
                break                                             # a clear match: no need for looser searches
        return sorted(results, key=lambda r: -r["score"])

    def find_actor(self, name):
        """Malpedia threat actors whose name or synonym is exactly this name (no partial matches: actor names are
        short words, and a partial match would name the wrong group)."""
        flat = lambda x: re.sub(r"[^a-z0-9]", "", (x or "").lower())
        for needle in self.needles(name)[:2]:
            for r in self._get("find/actor/" + urllib.parse.quote(needle, safe="")) or []:
                aid, common, syn = r.get("name") or "", r.get("common_name") or "", [s for s in r.get("synonyms") or [] if s]
                if flat(aid) == flat(needle) or flat(common) == flat(needle):
                    return {"id": aid, "matched_by": f"threat actor name {common or aid}", "score": 100}
                hit = next((s for s in syn if flat(s) == flat(needle)), None)
                if hit:
                    return {"id": aid, "matched_by": f"threat actor alias {hit}", "score": 90}
        return None

    def actor(self, aid):
        if not ACTOR_ID.match(aid or ""):
            return None
        a = self._get("get/actor/" + urllib.parse.quote(aid, safe="")) or {}
        if not a:
            return None
        meta = a.get("meta") or {}
        refs = meta.get("refs") or []
        return {
            "id": aid, "name": a.get("value") or aid, "description": a.get("description") or "",
            "synonyms": (meta.get("synonyms") or [])[:12], "country": meta.get("country") or "",
            "sponsor": meta.get("cfr-suspected-state-sponsor") or "", "targets": (meta.get("cfr-suspected-victims") or [])[:12],
            "sectors": (meta.get("targeted-sector") or meta.get("cfr-target-category") or [])[:8],
            "families": sorted((a.get("families") or {}).keys())[:20], "references": refs[:12], "reference_count": len(refs),
            "url": SITE.replace("/details/", "/actor/") + aid,
        }

    # ------------------------------------------------------------------ data
    def family(self, fid):
        if not FAMILY_ID.match(fid or ""):
            return None
        f = self._get("get/family/" + urllib.parse.quote(fid, safe=".")) or {}
        if not f:
            return None
        yara = {}
        try:
            for tlp, rules in (self._get("get/yara/" + urllib.parse.quote(fid, safe=".")) or {}).items():
                yara[tlp.replace("tlp_", "").upper()] = len(rules)
        except RuntimeError:
            pass
        return {
            "id": fid, "name": f.get("common_name") or fid, "description": f.get("description") or "",
            "alt_names": f.get("alt_names") or [], "attribution": f.get("attribution") or [],
            "updated": f.get("updated"), "references": (f.get("urls") or [])[:12], "reference_count": len(f.get("urls") or []),
            "yara": yara, "url": SITE + fid,
        }

    def sample(self, h):
        if not HASH.match(h or ""):
            raise ValueError("not an MD5, SHA-1 or SHA-256 hash")
        info = self._get(f"get/sample/{urllib.parse.quote(h.lower(), safe='')}/info")
        return {"hash": h.lower(), "found": bool(info), "info": info}

    def lookup(self, field, value):
        """Look up a value from an event or analysis. Infection / tag / family names find the malware family;
        md5 / sha1 / sha256 values check Malpedia's sample collection.
        Values are checked before anything is sent to Malpedia (security report #5): hashes must be hex of the right
        length, family ids look like 'win.emotet', names are at most 100 characters; every value is URL-encoded."""
        value = (value or "").strip()
        if not value:
            return {"field": field, "value": value, "kind": "none", "matches": [], "family": None}
        if len(value) > 100:
            raise ValueError("value too long")
        if field in ("md5", "sha1", "sha256", "hash"):
            if not HASH.match(value):
                raise ValueError("not an MD5, SHA-1 or SHA-256 hash")
            return {"field": field, "value": value, "kind": "sample", **self.sample(value)}
        if HASH.match(value):
            return {"field": field, "value": value, "kind": "sample", **self.sample(value)}
        if field == "actor":
            if not ACTOR_ID.match(value):
                raise ValueError("not a Malpedia actor id (for example tick)")
            return {"field": field, "value": value, "kind": "family", "matches": [], "family": None,
                    "actor": self.actor(value), "actor_match": {"id": value, "matched_by": "chosen"}}
        if field == "family":
            if not FAMILY_ID.match(value):
                raise ValueError("not a Malpedia family id (for example win.emotet)")
            fam = self.family(value)
            return {"field": field, "value": value, "kind": "family", "matches": [{"id": value, "matched_by": "chosen", "alt_names": []}], "family": fam}
        matches = self.find(value)
        best = matches[0] if matches and matches[0]["score"] >= 60 else None
        out = {"field": field, "value": value, "kind": "family", "matches": matches[:8],
               "family": self.family(best["id"]) if best else None}
        if not out["family"]:                 # not a malware family: perhaps a threat actor (group) name
            am = self.find_actor(value)
            if am:
                out["actor"], out["actor_match"] = self.actor(am["id"]), am
        return out
