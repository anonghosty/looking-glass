# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Settings: definitions for names Malpedia does not know, and the names checked against the sources

Moved out of app.py unchanged (the app.py refactor, 2026-11-24). Every name it uses from app.py, its own included, is
read from the app module when the code runs (_A.name), so it behaves exactly as it did inside app.py: a name replaced on
app.py reaches this code too. app.py calls install() where this code was, which registers the routes and hooks in the
same order, and keeps every name defined here under its old name.
"""
_A = None          # the app module (app.py), set by install()


class _Recorder:
    """@_R.route(...) and the like: kept in order, registered on the Flask app by install()."""

    def __init__(self):
        self.calls = []

    def __getattr__(self, kind):
        def deco_or_factory(*args, **kwargs):
            if kind in ("before_request", "after_request", "teardown_request", "context_processor") and len(args) == 1 \
                    and callable(args[0]) and not kwargs:
                self.calls.append((kind, (), {}, args[0]))
                return args[0]

            def deco(fn):
                self.calls.append((kind, args, kwargs, fn))
                return fn
            return deco
        return deco_or_factory


_R = _Recorder()




@_R.route("/api/kb/unresolved")
def api_kb_unresolved():
    """Names a look-up could not match (most seen first), and the names already defined by an administrator."""
    if not _A._kb_allowed():
        return _A.jsonify(error="Definitions are for researchers and admins."), 403
    db_ok = True
    try:
        _A._name_evidence()
    except _A._MongoError:
        db_ok = False                      # list the names anyway; "seen in" shows only what is in memory
        _A._EV_OFFLINE.on = True
    try:
        return _A._kb_unresolved(db_ok)
    finally:
        _A._EV_OFFLINE.on = False


def _kb_unresolved(db_ok):
    names = _A._read_names()
    misses = {n: x for n, x in names.items() if not x.get("family")}
    kb, ev = _A.knowledge_base(), _A._name_evidence()
    def row(n, m=None):
        e, x = kb.get(n.lower()) or {}, ev.get(n.lower(), {"classes": set(), "reports": set()})
        return {"name": n, "count": (m or {}).get("count", 0), "last": (m or {}).get("last") or (m or {}).get("checked", ""),
                "family_found": (names.get(n.lower()) or {}).get("family", ""),
                "reports": sorted(x["reports"]), "last_seen": _A._last_seen(n, x["reports"]), "seen_days": _A.SEEN.covered_days(),
                "kinds": sorted(x["classes"]), "title": e.get("title", ""),
                "type": e.get("type", ""), "description": e.get("description", ""), "references": e.get("references", []),
                "malpedia": e.get("malpedia", ""), "defined": bool(e.get("references") or e.get("malpedia")),
                "updated": e.get("updated", ""), "by": _A._by(e) or ("Looking Glass" if _A.defined_entry(e) else ""),
                # which sources know the name (Malpedia from its recorded check, MISP Galaxy / ATT&CK from the copies)
                "sources": _A.NAME_SOURCES.known_by(n, (names.get(n.lower()) or {}).get("family", ""))}
    todo =[row(n, m) for n, m in sorted(misses.items(), key=lambda kv: -kv[1].get("count", 0))
            if not _A._curated(n) and _A.malpedia_explain(n)["verdict"] != "activity" and not _A._is_services_report(n)]
    todo = [r for r in todo if not r["sources"]]     # "No source knows": none of Malpedia, MISP Galaxy, ATT&CK
    done = [row(n) for n, e in sorted(kb.items()) if e.get("references") or e.get("malpedia")]
    new = [row(n) for n in _A._unchecked_names()]
    for r in new:
        r["unchecked"] = True
    # every infection / category in the loaded reports (activities such as scanning left out)
    every = [row(n, names.get(n)) for n, x in sorted(ev.items(), key=lambda kv: -len(kv[1]["reports"]))
             if n and not (x["classes"] and x["classes"] <= set(_A._ACTIVITY))]
    # issues of the services platform: CVEs (looked up) and the others (defined by researchers)
    ikb, issues = _A.issues_kb(), []
    for name, x in sorted(_A._svc_issue_stats().items(), key=lambda kv: -len(kv[1]["hosts"])):
        e = ikb.get(name.lower()) or {}
        item = {"name": name, "records": x["records"], "hosts": len(x["hosts"]), "cve": _A.cves.is_cve(name),
                "defined": bool(e.get("description") or e.get("references")), "title": e.get("title", ""),
                "by": _A._by(e) or ("Looking Glass" if _A.defined_entry(e) else ""), "updated": e.get("updated", "")}
        if item["cve"]:
            c = _A.cve_intel.card(name, fetch=False)
            item.update(found=c["found"], pending=c["pending"], exploited=c["exploited"],
                        cvss=(c.get("cvss") or {}).get("score"), severity=(c.get("cvss") or {}).get("severity", ""),
                        epss=c.get("epss"), title=item["title"] or _A.cve_intel.known_title(name))   # KEV name, CNA title or 1st sentence
        # what it is, in full under its title (the user, 2026-11-19): a CVE's public description; another issue's definition
        desc = _A.cve_intel.known_description(name) if item["cve"] else ""
        item["description"] = desc if desc and desc != item["title"] else ("" if item["cve"] else e.get("description", ""))
        issues.append(item)
    return _A.jsonify(unresolved=todo, defined=done, unchecked=new, all=every, check=_A._AUTOCHECK, malpedia=_A.malpedia.enabled,
                   issues=issues, cve=_A.cve_intel.status(), database=db_ok,
                   database_note="" if db_ok else ("The report database cannot be read just now, so where and when each name "
                                                   "was seen may be missing. The names themselves are listed."))


@_R.route("/api/kb/malpedia-search")
def api_kb_malpedia_search():
    """Settings editor: find the Malpedia family a malware is listed under (any name or alias, e.g. 'proslikefan')."""
    if not _A._kb_allowed():
        return _A.jsonify(error="Definitions are for researchers and admins."), 403
    if not _A.malpedia.enabled:
        return _A.jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    q = (_A.request.args.get("q") or "").strip()
    if not 3 <= len(q) <= 60:
        return _A.jsonify(error="Type 3 to 60 characters."), 400
    try:
        hits = _A.malpedia.find(q)[:10]
        actors = _A.malpedia._get("find/actor/" + __import__("urllib.parse").parse.quote(q.lower(), safe="")) or []
    except RuntimeError as e:
        return _A.jsonify(error=_A.security.public_error(e, "Malpedia did not answer. Try again in a minute.")), 429
    out = [{"id": h["id"], "alt_names": h["alt_names"][:6], "matched_by": h["matched_by"],
            "url": "https://malpedia.caad.fkie.fraunhofer.de/details/" + h["id"]} for h in hits]
    out += [{"id": "actor:" + a["name"], "alt_names": (a.get("synonyms") or [])[:6], "matched_by": f"threat actor {a.get('common_name') or a['name']}",
             "url": "https://malpedia.caad.fkie.fraunhofer.de/actor/" + a["name"]} for a in actors[:6] if a.get("name")]
    return _A.jsonify(results=out)


@_R.route("/api/kb/check", methods=["POST"])
def api_kb_check():
    """Settings: check the new names (from new reports) against Malpedia now, in the background."""
    if not _A._kb_change_allowed():
        return _A.jsonify(error="Only researchers and admins can start this."), 403
    if not _A.malpedia.enabled:
        return _A.jsonify(error="Malpedia lookups are not set up (MALPEDIA_TOKEN in .env)."), 503
    started = _A._autocheck()
    return _A.jsonify(started=started, check=_A._AUTOCHECK,
                   note="" if started else "A check is already running (perhaps in another worker); refresh in a minute.")


@_R.route("/api/kb/entry", methods=["GET", "POST"])
def api_kb_entry():
    """GET ?name= : one name's definition. POST: an administrator defines or corrects a name (data/infections.json):
    title, type, plain description, references (evidence, http/https links) and optionally the Malpedia family id."""
    if _A.request.method == "GET":
        if not _A._kb_allowed():
            return _A.jsonify(error="Definitions are for researchers and admins."), 403
        n = (_A.request.args.get("name") or "").strip()
        e = (_A.issues_kb() if _A.request.args.get("section") == "issues" else _A.knowledge_base()).get(n.lower()) or {}
        others = _A.NAME_SOURCES.other_sources(n) if n and _A.request.args.get("section") != "issues" else []
        return _A.jsonify(name=n, title=e.get("title", ""), type=e.get("type", ""), description=e.get("description", ""),
                       references=e.get("references", []), malpedia=e.get("malpedia", ""), updated=e.get("updated", ""),
                       by=_A._by(e), sources=others)       # the other sources' text and links, shown alongside the editor
    if not _A._kb_change_allowed():
        return _A.jsonify(error="Only researchers and admins can change definitions."), 403
    if not _A.AUTH["fresh"]():
        return _A.jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
    import json as _json, re as _re
    b = _A.request.get_json(silent=True)
    if not isinstance(b, dict):
        return _A.jsonify(error="JSON expected"), 400
    section = "issues" if b.get("section") == "issues" else "infections"
    display = str(b.get("name") or "").strip()
    name = display.lower()
    if section == "issues":
        if not _re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:()/+-]{0,79}", display):
            return _A.jsonify(error="The issue: letters, digits, spaces and . _ : ( ) / + -, up to 80 characters."), 400
        if _A.cves.is_cve(display):
            display = display.upper()
    elif not _re.fullmatch(r"[a-z0-9][a-z0-9 ._:-]{0,79}", name):
        return _A.jsonify(error="The name: letters, digits, dot, dash, underscore or space, up to 80 characters."), 400
    title, kind = str(b.get("title") or "").strip()[:120], str(b.get("type") or "").strip()[:80]
    desc = str(b.get("description") or "").strip()[:2000]
    refs = [str(u).strip() for u in (b.get("references") or []) if str(u).strip()][:12]
    bad = [u for u in refs if not _A._URL_RE.match(u)]
    if bad:
        return _A.jsonify(error=f"References must be web links starting with http:// or https:// ({bad[0][:60]})."), 400
    mp_id = str(b.get("malpedia") or "").strip() if section == "infections" else ""
    if mp_id and not _re.fullmatch(r"[a-z0-9]{2,10}\.[a-z0-9_]{2,60}|actor:[a-z0-9][a-z0-9_-]{1,80}", mp_id):
        return _A.jsonify(error="The Malpedia id looks like win.lumma or apk.badbox, or actor:tick for a threat actor (or leave it empty)."), 400
    if mp_id and _A.malpedia.enabled:
        try:
            if not (_A.malpedia.actor(mp_id[6:]) if mp_id.startswith("actor:") else _A.malpedia.family(mp_id)):
                return _A.jsonify(error=f"Malpedia has no family {mp_id}: use Find in Malpedia to pick the right one, or leave it empty."), 400
        except RuntimeError:
            pass                                        # Malpedia busy or unreachable: keep the administrator's id
    # a CVE needs only a note or a reference (NVD, CISA and EPSS are shown anyway); the general rule below came first
    # and refused a CVE note without a reference, so the CVE rule could never be reached (found by r91's coverage tests)
    if section == "issues" and _A.cves.is_cve(display):
        if not (refs or desc):
            return _A.jsonify(error="For a CVE, add a note or at least one reference (NVD, CISA and EPSS are shown anyway)."), 400
    elif not (refs or mp_id):
        return _A.jsonify(error="Give at least one reference (evidence), or the Malpedia family id."), 400
    elif not mp_id and not (title and desc):
        return _A.jsonify(error="Without a Malpedia family, give a title and a plain description."), 400
    with _A._MISSES_LOCK:
        try:
            with open(_A.LOCAL_DEFS_PATH, encoding="utf-8") as f:
                data = _json.load(f)
        except FileNotFoundError:
            data = {"about": "Definitions written on this site (Settings / Definitions page). Kept on upgrades; "
                             "they take precedence over data/infections.json.", "infections": {}}
        inf = data.setdefault(section, {})
        key = next((k for k in inf if k.lower() == name), display if section == "issues" else name)
        base = (_A.issues_kb() if section == "issues" else _A.knowledge_base()).get(name) or {}
        e = inf.setdefault(key, {k: v for k, v in base.items() if k != "name"})
        e.update({k: v for k, v in (("title", title), ("type", kind), ("description", desc)) if v})
        e["references"] = refs
        if section == "infections":
            e["malpedia"] = mp_id
        e["status"], e["confidence"] = "reviewed", e.get("confidence") or "high"
        e["updated"] = _A.utcnow().date().isoformat()
        e["curated_by"], e["curated_by_name"] = _A._me()     # username (stable) and full name (kept if the account goes)
        tmp = _A.LOCAL_DEFS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            _json.dump(data, f, indent=2, ensure_ascii=False)
        _A.os.replace(tmp, _A.LOCAL_DEFS_PATH)
        if section == "infections":
            m = _A._read_names()
            if name in m:                               # checked again on the next look-up, with the new definition
                m.pop(name)
                _A._write_names(m)
    _A._kb["mtime"] = _A._ikb["mtime"] = None
    _A.AUTH["audit"].add("definition_saved", user=(getattr(_A.g, "user", None) or {}).get("user", "token"),
                      target=(f"issue:{display}" if section == "issues" else name),
                      detail=f"{'malpedia ' + mp_id + ', ' if mp_id else ''}{len(refs)} reference(s)")
    return _A.jsonify(saved=True, name=key)


@_R.route("/api/infections")
def api_infections():
    # who defined each one by full name, never the account name (external review, 2026-11-12: usernames were sent)
    out = {}
    import external_access
    outside = external_access.is_external(getattr(_A.g, "user", None) and _A.g.user.get("perms"))   # no staff names to externals
    for k, v in _A.knowledge_base().items():
        e = {f: x for f, x in v.items() if f not in ("curated_by", "curated_by_name")}
        if v.get("curated_by") and not outside:
            e["by"] = _A._by(v)
        out[k] = e
    return _A.jsonify(out)


@_R.route("/api/infections/missing")
def api_infections_missing():
    """Infections in the replay day that have no knowledge-base entry (or only a needs-review one)."""
    kb = _A.knowledge_base()
    day = _A.store.get(_A.parse_iso(_A.request.args.get("at"), _A.replay_now()))
    seen = _A.Counter((e["infection"] or "unknown").lower() for e in day.events)
    missing = [{"infection": k, "count": n} for k, n in seen.most_common() if k not in kb]
    review = [{"infection": k, "count": n} for k, n in seen.most_common() if k in kb and kb[k].get("status") != "reviewed"]
    return _A.jsonify(day=day.start.date().isoformat(), seen=len(seen), missing=missing, needs_review=review)


@_R.route("/healthz")
def healthz():
    return _A.jsonify(ok=True, replay_now=_A.iso(_A.replay_now()))


def install(flask_app, app_module):
    """Register this code's routes and hooks on the Flask app, in their order, and use app_module for its names."""
    global _A
    _A = app_module
    for kind, args, kwargs, fn in _R.calls:
        target = getattr(flask_app, kind)
        if args or kwargs or kind not in ("before_request", "after_request", "teardown_request", "context_processor"):
            target(*args, **kwargs)(fn)
        else:
            target(fn)
