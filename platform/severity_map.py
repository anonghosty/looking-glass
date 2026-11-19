"""The severity map (the user, 2026-11-18): every infection and issue the reports carried, with its criticality and where
the criticality comes from, on the Definitions page. Researchers and administrators only (the user, 2026-11-19).

* Rated by Shadowserver: the highest severity Shadowserver gave the records that carry the name (pdf_refs.py:
  data/name_levels.json, learned from every day loaded and once from every report, name_levels_catchup.py). A new name
  is mapped as its day loads.
* Not rated: a name the reports carried (data/name_kinds.json) that no record rates.
* Rated by a researcher: only a NOT RATED name may be rated, never one Shadowserver rated (the user's decision,
  2026-11-18). The rating is kept in data/name_ratings.json with who and when, written to the audit log, and the PDFs'
  References section shows it flagged "Researcher's rating". When Shadowserver later rates the name, Shadowserver's
  rating is used and the researcher's is shown beside it as replaced.
CVEs are not on the map: a CVE is rated by its CVSS score (NVD).

API (under /api/kb/, the Definitions page's addresses): GET /api/kb/severity-map; POST /api/kb/severity-map/rate
{name, level}, level "" takes the rating back (the page's CSRF token). Both need the 'definitions' permission, which
only researchers and administrators hold (auth.EXCLUSIVE_PERMS).
Installed from features.py: severity_map.install(app, {"base_dir", "has_perm", "csrf_ok", "audit", "people_name"}).
"""
import json
import os
import re
import threading
import time

from flask import g, jsonify, request

import pdf_refs

CVE_RX = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.I)
NAME_RX = re.compile(r"^[^\x00-\x1f<>]{1,120}$")
RATINGS_MAX = 50000


class Ratings:
    """data/name_ratings.json: {name: {"level", "by", "at"}}, written whole and atomically."""

    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self._cache = (None, {})

    def all(self):
        try:
            m = os.path.getmtime(self.path)
        except OSError:
            return {}
        if self._cache[0] == m:
            return self._cache[1]
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
            out = {str(k): v for k, v in (d.items() if isinstance(d, dict) else [])
                   if isinstance(v, dict) and pdf_refs.level(v.get("level"))}
        except (OSError, ValueError):
            out = {}
        self._cache = (m, out)
        return out

    def set(self, name, level, by):
        with self.lock:
            cur = dict(self.all())
            if level:
                if name not in cur and len(cur) >= RATINGS_MAX:
                    raise ValueError("too many ratings")
                cur[name] = {"level": level, "by": by, "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            else:
                cur.pop(name, None)
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(cur, fh, sort_keys=True)
            os.replace(tmp, self.path)
            self._cache = (None, {})
            return cur.get(name)


def build_rows(auto, kinds, rated, people_name=None):
    """The map's rows, one per name (names differing only in case are one), CVEs left out.
    auto: {name: Shadowserver's level}; kinds: {name: "Infection" | "Issue"}; rated: {name: {"level", "by", "at"}}."""
    shown = {}                                           # lower-case -> the name as the reports write it
    for src in (auto, kinds, rated):
        for n in src:
            if n and not CVE_RX.match(n):
                shown.setdefault(n.lower(), n)
    low = lambda d: {k.lower(): v for k, v in d.items()}  # noqa: E731
    a_, k_, r_ = low(auto), low(kinds), low(rated)
    out = []
    for key, n in shown.items():
        sev = pdf_refs.level(a_.get(key))
        r = r_.get(key) or {}
        rl = pdf_refs.level(r.get("level"))
        row = {"name": n, "kind": k_.get(key) or "", "level": sev or rl,
               "source": "shadowserver" if sev else ("researcher" if rl else "")}
        if rl:
            by = r.get("by") or ""
            row.update(rated_by=(people_name(by) if people_name else "") or by, rated_at=str(r.get("at") or ""),
                       rated_level=rl, replaced=bool(sev))
        out.append(row)
    order = {lv: i for i, lv in enumerate(pdf_refs.LEVELS)}
    # not rated first (they need a researcher), then by criticality, then by name
    out.sort(key=lambda r: (0 if not r["source"] else 1, order.get(r["level"], len(order)), r["name"].lower()))
    return out


def install(app, ctx):
    hp = ctx["has_perm"]
    ratings = Ratings(os.path.join(ctx["base_dir"], "data", "name_ratings.json"))
    pdf_refs.RATINGS["get"] = ratings.all             # the PDFs' References section reads them (pdf_refs.researcher_level)

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def allowed():
        # researchers and administrators only (the user, 2026-11-19): 'definitions' belongs to no other role
        return hp("definitions")

    def rows():
        return build_rows(pdf_refs.all_levels(), pdf_refs.all_kinds(), ratings.all(), ctx.get("people_name"))

    def payload(rs):
        return {"rows": rs, "levels": list(pdf_refs.LEVELS),
                "counts": {"not_rated": sum(1 for r in rs if not r["source"]),
                           "shadowserver": sum(1 for r in rs if r["source"] == "shadowserver"),
                           "researcher": sum(1 for r in rs if r["source"] == "researcher"),
                           "replaced": sum(1 for r in rs if r.get("replaced")),
                           "all": len(rs)}}

    @app.route("/api/kb/severity-map")
    def api_severity_map():
        if not allowed():
            return jsonify(error="The severity map is for researchers and administrators."), 403
        return jsonify(**payload(rows()))

    @app.route("/api/kb/severity-map/rate", methods=["POST"])
    def api_severity_map_rate():
        if not allowed():
            return jsonify(error="Only researchers and administrators rate names."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True) or {}
        name, level = str(b.get("name") or "").strip(), str(b.get("level") or "").strip().lower()
        if not NAME_RX.match(name) or CVE_RX.match(name):
            return jsonify(error="Not a name this map rates."), 400
        if level and level not in pdf_refs.LEVELS:
            return jsonify(error="Choose critical, high, medium, low or info."), 400
        row = next((r for r in rows() if r["name"].lower() == name.lower()), None)
        if row is None:
            return jsonify(error="The reports have not carried this name."), 404
        if row["source"] == "shadowserver":
            # the user's decision (2026-11-18): Shadowserver's own ratings are never changed
            return jsonify(error="Shadowserver rates this name from its records: its rating is used, not changed here."), 409
        name = row["name"]
        old = {k: v for k, v in ratings.all().items() if k.lower() == name.lower()}
        before = next((v.get("level") for v in old.values()), "")
        if (before or "") == level:
            return jsonify(ok=True, **payload(rows()))
        try:
            for k in old:
                if k != name:
                    ratings.set(k, "", me())                 # one rating per name, whatever its case
            ratings.set(name, level, me())
        except ValueError:
            return jsonify(error="The severity map holds as many ratings as it can."), 400
        ctx["audit"].add("severity_rated", user=me(), target=name,
                         detail=(f"{before or 'not rated'} to {level}" if level else f"{before} taken back: not rated"))
        return jsonify(ok=True, **payload(rows()))

    return {"ratings": ratings, "rows": rows}
