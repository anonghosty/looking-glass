# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The infection knowledge base: researchers' definitions and the curated notes

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




def knowledge_base():
    """data/infections.json (shipped) with data/definitions.json (this site's own definitions) on top; re-read
    automatically when either file changes."""
    import json
    try:
        m = (_A.filesig.sig(_A.KB_PATH), _A.filesig.sig(_A.LOCAL_DEFS_PATH) if _A.os.path.exists(_A.LOCAL_DEFS_PATH) else 0)
        if m != _A._kb["mtime"]:
            with open(_A.KB_PATH, encoding="utf-8") as f:
                data = {k.lower(): v for k, v in json.load(f).get("infections", {}).items()}
            try:
                with open(_A.LOCAL_DEFS_PATH, encoding="utf-8") as f:
                    for k, v in (json.load(f).get("infections") or {}).items():
                        data[k.lower()] = dict(data.get(k.lower(), {}), **v)
            except FileNotFoundError:
                pass
            except ValueError as exc:
                _A.app.logger.warning("Local definitions (data/definitions.json) not loaded: %s", exc)
            _A._kb["data"], _A._kb["mtime"] = data, m
    except (OSError, ValueError) as exc:
        _A.app.logger.warning("Infection knowledge base not loaded: %s", exc)
    return _A._kb["data"]


def issues_kb():
    """data/issues.json (shipped) with the 'issues' of data/definitions.json on top. Keys are lower-case; each entry
    keeps its display name in 'name'."""
    import json
    try:
        m = (_A.filesig.sig(_A.ISSUES_PATH) if _A.os.path.exists(_A.ISSUES_PATH) else 0,
             _A.filesig.sig(_A.LOCAL_DEFS_PATH) if _A.os.path.exists(_A.LOCAL_DEFS_PATH) else 0)
        if m != _A._ikb["mtime"]:
            data = {}
            for path in (_A.ISSUES_PATH, _A.LOCAL_DEFS_PATH):
                try:
                    with open(path, encoding="utf-8") as f:
                        for k, v in (json.load(f).get("issues") or {}).items():
                            data[k.lower()] = dict(data.get(k.lower(), {}), **v, name=v.get("name") or k)
                except FileNotFoundError:
                    pass
            _A._ikb["data"], _A._ikb["mtime"] = data, m
    except (OSError, ValueError) as exc:
        _A.app.logger.warning("Issue definitions not loaded: %s", exc)
    return _A._ikb["data"]


def issue_resolve(name, fetch=True):
    """What an issue is: a CVE (NVD, CISA KEV, EPSS; plus the researchers' notes), or the definition of a non-CVE
    issue (never looked up anywhere: its definition and references are used)."""
    cur = _A.issues_kb().get((name or "").strip().lower())
    if _A.cves.is_cve(name):
        c = _A.cve_intel.card(name, fetch=fetch)
        if cur and (cur.get("references") or cur.get("description")):
            c["curated_references"], c["note"] = cur.get("references", []), cur.get("description", "")
            c["note_by"], c["note_updated"] = _A._by(cur), cur.get("updated", "")
        return c
    if cur:
        return {"found": False, "curated": True, "kind": "issue", "title": cur.get("title") or name, "type": cur.get("type", ""),
                "description": cur.get("description", ""), "references": cur.get("references", []),
                "updated": cur.get("updated", ""), "by": _A._by(cur)}
    return {"found": False, "offline": True, "kind": "issue", "title": "No definition yet",
            "text": f'"{name}" has no definition yet. A security researcher of your organisation can add one, with '
                    "references, on the Definitions page."}


def issues_resolve(names, budget=15.0, progress=None, stop=None):
    """Several issues: CVEs as one batch (CISA KEV, EPSS per 100, CVE.org four at a time; NVD's analysis from the
    background check), then the others (definitions, never looked up). stop: () -> True once the look-up was stopped."""
    names = [n for n in dict.fromkeys(str(x).strip() for x in names) if n]
    out = {}
    ids = [n for n in names if _A.cves.is_cve(n)]
    if ids:
        # budget: no more fetching once spent (external review, 2026-11-12: it was ignored); a progress window (the
        # look-up the user started and watches) has no limit
        cards = _A.cve_intel.lookup_many(ids, progress=progress, budget=None if progress else budget, stop=stop)
        for n in ids:
            out[n] = _A.issue_resolve(n, fetch=False) if cards.get(n.upper()) is None else cards[n.upper()]
            cur = _A.issues_kb().get(n.lower())
            if cur and (cur.get("references") or cur.get("description")):
                out[n].update(curated_references=cur.get("references", []), note=cur.get("description", ""),
                              note_by=_A._by(cur), note_updated=cur.get("updated", ""))
    others = [n for n in names if n not in out]
    if others and progress:
        progress("step", f"{len(others)} other issue{'s' if len(others) != 1 else ''} (not CVEs): explained from their definitions, never looked up")
    for n in others:
        out[n] = _A.issue_resolve(n, fetch=False)
        if progress:
            progress("item", f"{n}: {'definition by ' + (out[n].get('by') or 'Looking Glass') if out[n].get('curated') else 'no definition yet'}")
    return out


@_R.route("/api/issues/batch")
def api_issues_batch():
    """Explain the issues of a services list: CVEs from NVD / CISA KEV / EPSS, other issues from their definitions."""
    if not _A.AUTH["has_perm"]("malpedia"):
        return _A.jsonify(error="Your role cannot use look-ups (permission 'malpedia')."), 403
    names = [v.strip() for v in (_A.request.args.get("values") or "").split(",") if v.strip() and len(v.strip()) <= 80]
    names = list(dict.fromkeys(names))
    if len(names) > 120:
        return _A.jsonify(error="At most 120 issues at a time."), 400
    try:
        res = _A.issues_resolve(names)
    except ValueError as exc:
        return _A.jsonify(error=_A.security.public_error(exc)), 400
    return _A.jsonify(results=res, pending=sum(1 for x in res.values() if x.get("pending")), cve=_A.cve_intel.status())


def _svc_issue_stats():
    """issue -> {records, hosts} over the services days in memory (refreshed at most every minute)."""
    if _A.time.time() - _A._SVC_ISSUES["at"] < 60 and _A._SVC_ISSUES["data"]:
        return _A._SVC_ISSUES["data"]
    st = {}
    for d in list(_A.svc["store"].days.values()):
        for e in d.events:
            for i in e["issues"]:
                x = st.setdefault(i, {"records": 0, "hosts": set()})
                x["records"] += 1; x["hosts"].add(e["ip"])
    _A._SVC_ISSUES.update(at=_A.time.time(), data=st)
    return st


def _cve_loop():
    """Every 30 minutes: look up the CVEs the services reports contain (at NVD's pace), one worker at a time."""
    import fcntl
    _A.time.sleep(120)
    while True:
        try:
            with open(_A.os.path.join(_A.BASE_DIR, "data", ".cve_check.lock"), "w") as lf:
                try:
                    fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError:
                    lf = None
                if lf:
                    ids = [i for i in _A._svc_issue_stats() if _A.cves.is_cve(i)]
                    if ids:
                        _A.cve_intel.prefetch(ids)
        except Exception as exc:                       # never let the background check stop the platform
            _A.app.logger.warning("CVE background check: %s", exc)
        _A.time.sleep(600)                                # NVD's analysis follows within minutes of new CVEs


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
