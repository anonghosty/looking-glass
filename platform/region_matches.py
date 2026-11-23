# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Region names as Shadowserver writes them, matched to the country's map by the administrator (2026-11-15).

The reports' region names come from IP geolocation and are spelt in many ways (ISO 3166-2, English, local, with or
without accents). The maps (static/data/adm1, manage/fetch_world_boundaries.py) know their own names, the ISO names and
aliases, and that covers most of them; for every country in the world it cannot cover all. So Settings shows each
region name found in yesterday's reports with what it matched, and for a name the map does not know it suggests the
closest region; the administrator confirms the suggestion, picks another region, or says the name is the country
itself (then it counts as "region unknown"). The choices are this installation's own:

  data/region_matches.json     {"<ISO2>": {"<report name, upper case>": "<map region key>" | "__country__"}}

kept on upgrades, used by every map (services regions, Settings preview, Executive portal and its PDF), each change
in the audit log (region_match_set / region_match_removed).

  GET  /api/settings/region-matches?country=XX   report names of yesterday with status, suggestion, the map's regions
  POST /api/settings/region-matches              {country, name, target}: target = a region key, "__country__", or ""
                                                 (empty: remove the choice). Settings permission, CSRF, fresh sign-in.
"""
import difflib
import json
import os
import re
import threading
import unicodedata

from flask import g, jsonify, request
import filesig  # noqa: E402

COUNTRY = "__country__"
SUFFIXES = (" REGION", " PROVINCE", " STATE", " GOVERNORATE", " COUNTY", " DISTRICT", " PREFECTURE", " DEPARTMENT",
            " WILAYA", " ATOLL")
SUGGEST_AT = 0.72          # how alike a name must be to be offered as a suggestion (0..1, difflib ratio)


def norm(n):
    """The same as norm() in static/js/regions.js and manage/region_aliases.py."""
    s = unicodedata.normalize("NFKD", str(n or "")).encode("ascii", "ignore").decode().upper().strip()
    for x in SUFFIXES:
        if s.endswith(x):
            s = s[: -len(x)].strip()
    return s


def flat(n):
    return re.sub(r"[^A-Z]", "", norm(n))


class Matches:
    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "region_matches.json")
        self.lock = threading.Lock()
        self._cache = (None, {})

    def all(self):
        try:
            m = filesig.sig(self.path)
        except OSError:
            return {}
        if self._cache[0] != m:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    d = json.load(fh)
                self._cache = (m, d if isinstance(d, dict) else {})
            except (OSError, ValueError):
                self._cache = (m, {})
        return self._cache[1]

    def of(self, cc):
        return dict(self.all().get(str(cc or "").upper(), {}))

    def version(self):
        """Changes whenever the choices change (the file's time and size): part of the cached services answers' keys."""
        try:
            st = os.stat(self.path)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return 0

    def set(self, cc, name, target):
        with self.lock:
            d = {k: dict(v) for k, v in self.all().items()}
            mine = d.setdefault(cc, {})
            if target:
                mine[name] = target
            else:
                mine.pop(name, None)
            if not mine:
                d.pop(cc, None)
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(d, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, self.path)
            self._cache = (None, {})


def region_names(file):
    """Every name that is a region on this map (keys, names, aliases), normalised. Some regions carry the country's
    own name (Belize District, Djibouti, Guatemala, the State of Mexico): such a name lands on that region, not on
    "region unknown". An administrator can still say otherwise (Settings, region matches). Empty for a one-area map."""
    if not file or file.get("whole"):
        return set()
    out = set()
    for key, reg in (file.get("regions") or {}).items():
        out.update(x for x in [key, norm(reg.get("name")), *(reg.get("aliases") or [])] if x)
    return out


def focus_bbox(file, counts):
    """The default frame of a map: the regions holding 98% of the records, when that is clearly smaller than the
    whole country (islands far apart: Seychelles, Kiribati, the Bahamas), so a printed map is readable. counts:
    {map key: records}. Returns (bbox [west, south, east, north], zoomed). The same rule as focusBox() in
    static/js/regions.js."""
    full = (file or {}).get("bbox")
    if not full or file.get("whole"):
        return full, False
    rows = sorted(((k, n) for k, n in (counts or {}).items() if n and k in file["regions"]), key=lambda kv: -kv[1])
    tot = sum(n for _, n in rows)
    if not tot:
        return full, False
    w = s = float("inf")
    e = n = float("-inf")
    cum = 0
    for k, c in rows:
        for poly in file["regions"][k].get("polys") or []:
            for x, y in (poly[0] if poly else []):
                w, e, s, n = min(w, x), max(e, x), min(s, y), max(n, y)
        cum += c
        if cum >= 0.98 * tot:
            break
    if not (e > w and n > s):
        return full, False
    fw, fh = full[2] - full[0], full[3] - full[1]
    hw = max((e - w) * 1.12, max(0.25, fw * 0.03)) / 2
    hh = max((n - s) * 1.12, max(0.25, fh * 0.03)) / 2
    cx, cy = (w + e) / 2, (s + n) / 2
    box = [cx - hw, cy - hh, cx + hw, cy + hh]
    if (box[2] - box[0]) * (box[3] - box[1]) >= 0.35 * fw * fh:
        return full, False
    return box, True


_NAMES_CACHE = {}


def map_region_names(adm1_dir, cc):
    """region_names() of a country's map file, read again only when the file changes."""
    if not re.fullmatch(r"[A-Z]{2}", str(cc or "")):
        return set()
    p = os.path.join(adm1_dir, f"{cc}.json")
    try:
        m = filesig.sig(p)
    except OSError:
        return set()
    hit = _NAMES_CACHE.get(p)
    if not hit or hit[0] != m:
        try:
            with open(p, encoding="utf-8") as fh:
                hit = (m, region_names(json.load(fh)))
        except (OSError, ValueError):
            hit = (m, set())
        _NAMES_CACHE[p] = hit
    return hit[1]


def resolver(file, chosen=None, country_names=()):
    """name -> map key, "__country__" or None, for one country's map file plus the administrator's choices."""
    chosen = {norm(k): v for k, v in (chosen or {}).items()}
    regions = (file or {}).get("regions") or {}
    if (file or {}).get("whole"):
        only = next(iter(regions), None)
        return lambda name: chosen.get(norm(name)) or only
    exact, loose = {}, {}
    # keys first, then names, then aliases: a region's own name wins over another region's alias (as regions.js)
    for pick in (lambda k, r: [k], lambda k, r: [norm(r.get("name"))], lambda k, r: r.get("aliases") or []):
        for key, reg in regions.items():
            for a in pick(key, reg):
                if not a:
                    continue
                exact.setdefault(a, key)
                f = re.sub(r"[^A-Z]", "", a)
                if f:
                    loose.setdefault(f, key)
    cn = {norm(c) for c in country_names if c}

    def find(name):
        n = norm(name)
        if not n:
            return COUNTRY
        if n in chosen:
            return chosen[n]
        if n in exact:                          # a region named like the country is that region
            return exact[n]
        if n in cn:
            return COUNTRY
        return loose.get(flat(name))
    return find


def suggest(name, file, country_names=()):
    """(target, score) of the closest map region for a name the map does not know, or of "the country itself"."""
    n = norm(name)
    best, score = None, 0.0
    for key, reg in ((file or {}).get("regions") or {}).items():
        for a in {key, norm(reg.get("name")), *(reg.get("aliases") or [])}:
            if not a:
                continue
            r = difflib.SequenceMatcher(None, n, a).ratio()
            if min(len(a), len(n)) >= 4 and (a in n or n in a):   # "COTE D IVOIRE LAGUNES" holds "LAGUNES"
                r = max(r, 0.7 + 0.3 * min(len(a), len(n)) / max(len(a), len(n)))   # (never short codes like "RA")
            if r > score:
                best, score = key, r
    for c in country_names:
        r = difflib.SequenceMatcher(None, n, norm(c)).ratio()
        if r > score:
            best, score = COUNTRY, r
    return (best, round(score, 2)) if score >= SUGGEST_AT else (None, round(score, 2))


def install(app, ctx):
    """ctx: data_dir, adm1_dir, country_index() -> {ISO2: {...}}, settings, settings_writable(), csrf_ok(), fresh(),
    audit, region_raw() -> {report name: records} of yesterday (services platform)."""
    M = Matches(ctx["data_dir"])
    ctx["region_matches"] = M

    def map_file(cc):
        """A country's map file. The code must be two capital letters AND a country the map index knows; the file name is
        taken from the index's own key (not from the request), and the path must stay inside the maps folder
        (CodeQL py/path-injection, alert 33: the two-letter check alone was not recognised)."""
        if not re.fullmatch(r"[A-Z]{2}", cc or ""):
            return None
        known = next((k for k in ctx["country_index"]() if k == cc), None)
        if known is None:
            return None
        base = os.path.realpath(ctx["adm1_dir"])
        path = os.path.realpath(os.path.join(base, known + ".json"))
        if not path.startswith(base + os.sep):
            return None
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None

    @app.route("/api/settings/region-matches")
    def api_region_matches():
        if not ctx["settings_writable"]():
            return jsonify(error="Settings are for admin accounts."), 403
        cc = str(request.args.get("country") or ctx["settings"].data["country"]).upper()
        info = ctx["country_index"]().get(cc) or {}
        f = map_file(cc)
        names = [info.get("country", "")] + list(info.get("names") or [])
        chosen = M.of(cc)
        auto = resolver(f, {}, names)
        rows = []
        for raw, n in sorted((ctx["region_raw"]() or {}).items(), key=lambda kv: -kv[1]):
            up = norm(raw)
            if up in {norm(k) for k in chosen}:
                tgt = next(v for k, v in chosen.items() if norm(k) == up)
                rows.append({"name": raw, "records": n, "status": "chosen", "target": tgt})
                continue
            hit = auto(raw)
            if hit == COUNTRY:
                rows.append({"name": raw, "records": n, "status": "country", "target": COUNTRY})
            elif hit:
                rows.append({"name": raw, "records": n, "status": "map", "target": hit})
            else:
                s, score = suggest(raw, f, names)
                rows.append({"name": raw, "records": n, "status": "none", "suggestion": s, "score": score})
        regions = sorted(((k, v.get("name", k)) for k, v in ((f or {}).get("regions") or {}).items()), key=lambda x: x[1])
        return jsonify(country=cc, whole=bool((f or {}).get("whole")), regions=[{"key": k, "name": nm} for k, nm in regions],
                       rows=rows, chosen=chosen)

    @app.route("/api/settings/region-matches", methods=["POST"])
    def api_region_matches_set():
        if not ctx["settings_writable"]():
            return jsonify(error="Settings are for admin accounts."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        if request.mimetype != "application/json":          # as the Settings save (security review of d82a436)
            return jsonify(error="Send the match as JSON (Content-Type: application/json)."), 415
        b = request.get_json(silent=True) or {}
        cc = str(b.get("country") or "").upper()
        name = norm(b.get("name"))
        target = str(b.get("target") or "")
        if cc not in ctx["country_index"]():
            return jsonify(error="Unknown country."), 400
        if not name or len(name) > 120:
            return jsonify(error="Give the region name as the reports write it."), 400
        f = map_file(cc)
        if target and target != COUNTRY and target not in ((f or {}).get("regions") or {}):
            return jsonify(error="That region is not on this country's map."), 400
        before = M.of(cc).get(name)
        M.set(cc, name, target)
        who = (getattr(g, "user", None) or {}).get("user", "")
        shown = "the country itself (region unknown)" if target == COUNTRY else ((f or {}).get("regions") or {}).get(target, {}).get("name", target)
        if target:
            ctx["audit"].add("region_match_set", user=who, target=f"{cc}: {name}", detail=f"-> {shown}" + (f" (was {before})" if before else ""))
        else:
            ctx["audit"].add("region_match_removed", user=who, target=f"{cc}: {name}", detail=f"was {before or 'not set'}")
        return jsonify(ok=True, chosen=M.of(cc))
