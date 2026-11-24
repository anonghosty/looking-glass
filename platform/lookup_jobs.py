# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Look-up jobs with a progress window on the page: names and issues explained, checked against the sources

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




class _LookupStopped(Exception):
    """A look-up stopped by the person who started it (POST /api/lookups/<id>/stop)."""


def _job_new(kind, total, user):
    import secrets as _secrets
    jid = _secrets.token_urlsafe(12)
    with _A._JOBS_LOCK:
        for k in [k for k, j in _A._JOBS.items() if _A.time.time() - j["t0"] > 1800]:     # finished jobs are kept 30 minutes
            _A._JOBS.pop(k, None)
        _A._JOBS[jid] = {"id": jid, "kind": kind, "user": user, "t0": _A.time.time(), "state": "running", "total": total,
                      "done": 0, "cached": 0, "failed": 0, "current": "", "log": [], "results": None, "error": ""}
    return _A._JOBS[jid]


def _job_log(job, text):
    job["log"].append(f"{_A.time.strftime('%H:%M:%S', _A.time.gmtime())}  {text}")
    del job["log"][:-400]


@_R.route("/api/lookups", methods=["POST"])
def api_lookups_start():
    """Start a look-up of many names in the background: kind=issues (CVEs: CISA KEV, EPSS, CVE.org; others: definitions)
    or kind=malpedia (infections / categories). The page follows it with GET /api/lookups/<id>."""
    if not (_A.AUTH["has_perm"]("malpedia") or _A.AUTH["has_perm"]("definitions") or _A.AUTH["has_perm"]("management")):
        return _A.jsonify(error="Your role cannot use look-ups."), 403
    if not _A.AUTH["csrf_ok"]():
        return _A.jsonify(error="Refused (the request did not come from this page)."), 403
    b = _A.request.get_json(silent=True) or {}
    kind = b.get("kind")
    values = list(dict.fromkeys(str(v).strip() for v in (b.get("values") or []) if str(v).strip() and len(str(v).strip()) <= 100))
    if kind not in ("issues", "malpedia") or not values:
        return _A.jsonify(error="kind (issues or malpedia) and values expected"), 400
    if len(values) > 400:
        return _A.jsonify(error="At most 400 names at a time."), 400
    user = (getattr(_A.g, "user", None) or {}).get("user", "")
    with _A._JOBS_LOCK:
        if sum(1 for j in _A._JOBS.values() if j["user"] == user and j["state"] == "running") >= 2:
            return _A.jsonify(error="You already have two look-ups running; wait for one to finish."), 429
    demo = _A.is_demo()
    job = _A._job_new(kind, len(values), user)

    def say(kind_, text, done=None):
        if job.get("cancel"):                     # closed by the person who started it: stop between two names
            raise _A._LookupStopped()
        if kind_ == "item":
            job["current"] = text
            if done is None:
                job["done"] += 1
            else:
                job["done"] = done
            if "failed" in text or "could not" in text or "answered" in text:
                job["failed"] += 1
        _A._job_log(job, text)

    def run_issues():
        ids = [v for v in values if _A.cves.is_cve(v)]
        _A._job_log(job, f"{len(values)} issue{'s' if len(values) != 1 else ''}: {len(ids)} CVE{'s' if len(ids) != 1 else ''}, "
                      f"{len(values) - len(ids)} other{'s' if len(values) - len(ids) != 1 else ''}")
        job["results"] = _A.issues_resolve(values, progress=say, stop=lambda: bool(job.get("cancel")))
        job["done"] = job["total"]

    def run_malpedia():
        out = {}
        _A._job_log(job, f"{len(values)} name{'s' if len(values) != 1 else ''}; Malpedia " + ("is set up: answers are cached a week, "
                 f"at most {_A.MAX_MP} new questions a minute" if _A.malpedia.enabled else
                 "is not set up: the Looking Glass definitions and knowledge base answer"))
        for v in values:
            if job.get("cancel"):                 # closed by the person who started it
                raise _A._LookupStopped()
            if demo and v.startswith("ref:"):
                job["done"] += 1
                continue
            job["current"] = v
            for attempt in range(8):
                if job.get("cancel"):
                    raise _A._LookupStopped()
                try:
                    card = _A.mp_resolve(v)[0]
                    break
                except ValueError as exc:
                    card = {"found": False, "reason": str(exc)}
                    break
                except RuntimeError as exc:
                    if "Too many" in str(exc) and attempt < 7:
                        _A._job_log(job, f"{v}: Malpedia's limit reached ({_A.MAX_MP} questions a minute): waiting 15 s, then continuing")
                        for _ in range(15):           # the wait ends at once when the look-up is stopped
                            if job.get("cancel"):
                                raise _A._LookupStopped()
                            _A.time.sleep(1)
                        continue
                    card = {"found": False, "pending": True, "reason": f"Not checked yet: {_A.security.public_error(exc, 'Malpedia did not answer')}."}
                    job["failed"] += 1
                    break
            out[v] = card
            job["done"] += 1
            what = ("Malpedia: " + card.get("name", "") + (" (threat actor)" if card.get("kind") == "actor" else f" ({card.get('family')})")) \
                if card.get("found") else ("definition: " + card.get("title", "")) if card.get("curated") else (card.get("title") or card.get("reason") or "not found")
            _A._job_log(job, f"{v}: {what}")
        job["results"] = out

    def run():
        try:
            (run_issues if kind == "issues" else run_malpedia)()
            job["state"] = "done"
            _A._job_log(job, f"Finished: {job['total']} looked up in {_A.time.time() - job['t0']:.0f} s"
                          + (f", {job['failed']} could not be checked" if job["failed"] else ""))
        except _A._LookupStopped:                        # closed by the person who started it (the user, 2026-11-19)
            job["state"] = "stopped"
            _A._job_log(job, f"Stopped by you after {job['done']} of {job['total']}")
        except Exception as exc:                      # the page shows it; the platform carries on
            _A.app.logger.exception("look-up job %s failed", kind)   # full details in the server log only
            job["state"], job["error"] = "failed", _A.security.public_error(exc)
            _A._job_log(job, f"Stopped: {job['error']}")
    _A.threading.Thread(target=run, daemon=True, name=f"lookup-{kind}").start()
    return _A.jsonify(id=job["id"], total=job["total"])


@_R.route("/api/lookups/<jid>/stop", methods=["POST"])
def api_lookups_stop(jid):
    """Stop a look-up: the window was closed before it finished (the user, 2026-11-19: "I should be able to close it
    even when it's loading so it stops searching"). Only the person who started it; it stops between two names."""
    if not _A.AUTH["csrf_ok"]():
        return _A.jsonify(error="Refused (the request did not come from this page)."), 403
    j = _A._JOBS.get(jid)
    if not j or j["user"] != (getattr(_A.g, "user", None) or {}).get("user", ""):
        return _A.jsonify(error="No such look-up."), 404
    if j["state"] == "running":
        j["cancel"] = True
    return _A.jsonify(ok=True, state=j["state"])


@_R.route("/api/lookups/<jid>")
def api_lookups_status(jid):
    j = _A._JOBS.get(jid)
    if not j or j["user"] != (getattr(_A.g, "user", None) or {}).get("user", ""):
        return _A.jsonify(error="No such look-up (finished ones are kept 30 minutes)."), 404
    try:                                   # a bad value is the start of the log, not a server error (external review)
        since = max(0, int(_A.request.args.get("since") or 0))
    except ValueError:
        since = 0
    out = {k: j[k] for k in ("id", "kind", "state", "total", "done", "failed", "current", "error")}
    out.update(elapsed=round(_A.time.time() - j["t0"]), log=j["log"][since:], log_len=len(j["log"]))
    if j["state"] == "done":
        out["results"] = j["results"]
    return _A.jsonify(out)


@_R.route("/api/asns")
def api_asns():
    """The ASN registry (company names). Not available in demo mode."""
    if _A.is_demo():
        return _A.jsonify(error="not available in demo mode"), 403
    return _A.jsonify(_A.asn_registry.all())


def _name_evidence():
    """name -> {'classes': set, 'reports': set} over the days in memory (refreshed at most every minute)."""
    if getattr(_A._EV_OFFLINE, "on", False):
        return _A._EVIDENCE["data"] or {}
    if _A.time.time() - _A._EVIDENCE["at"] < 60 and _A._EVIDENCE["data"]:
        return _A._EVIDENCE["data"]
    if _A._EVIDENCE["data"]:
        if not _A._EV_BUILD.acquire(blocking=False):
            return _A._EVIDENCE["data"]                 # another request is rebuilding it: this one uses the last copy
    else:
        _A._EV_BUILD.acquire()                          # the first build: wait for it rather than build it twice
        if _A._EVIDENCE["data"]:
            _A._EV_BUILD.release()
            return _A._EVIDENCE["data"]
    try:
        return _A._build_name_evidence()
    finally:
        _A._EV_BUILD.release()


def _build_name_evidence():
    labels = {x["name"]: x["label"] for x in _A.registry.get()}
    ev = {}
    for d in list(_A.store.days.values()):
        for e in d.events:
            x = ev.setdefault((e["infection"] or "").lower(), {"classes": set(), "reports": set()})
            x["classes"].add(e["attack_class"]); x["reports"].add(labels.get(e["source"], e["source"]))
        _A.SEEN.update(d.start.date().isoformat(), d.events, labels)      # where and when, kept beyond this day (seen_index.py)
    _A.SEEN.refresh()
    _A.SEEN.backfill(_A.store._load, _A.day_start, _A.utcnow, lambda: {x["name"]: x["label"] for x in _A.registry.get()})
    _A._EVIDENCE.update(at=_A.time.time(), data=ev)
    return ev


def _last_seen(name, now_reports):
    """For a name not in the replay day: [{report, date}] where it was last seen (newest first), from seen_index.py."""
    if now_reports:
        return []
    return [{"report": r, "date": d} for r, d in _A.SEEN.last_seen(name)[:3]]


def malpedia_explain(name):
    """What a name that Malpedia does not list really is, why it is not there, and what to do; for non-specialists."""
    import re as _re
    n = (name or "").strip()
    low = n.lower()
    kb = _A.knowledge_base().get(low, {})
    kind = (kb.get("type") or "")
    ev = _A._name_evidence().get(low, {"classes": set(), "reports": set()})
    classes, reports = ev["classes"], sorted(ev["reports"])
    seen = ", ".join(reports) if reports else ""
    acts = [c for c in classes if c in _A._ACTIVITY]
    if acts and len(acts) == len(classes):
        doing = " and ".join(_A._ACTIVITY[c] for c in sorted(acts))
        return {"verdict": "activity", "title": "Not malware: an activity",
                "text": (f'"{n}" is not the name of a malicious program. Shadowserver\'s decoy systems '
                         f'({seen or "honeypots"}) saw this device {doing}. Malpedia only describes malicious programs, '
                         "so it has no entry for an activity."),
                "advice": "The device is probably infected or being misused: check what software runs on it, update it, "
                          "and change its passwords.", "seen_in": reports}
    if _re.search(r"proxy|socks|residential", f"{low} {kind.lower()}") and "botnet" in kind.lower():
        return {"verdict": "proxy-botnet", "title": "Malware that turns devices into proxies",
                "text": (f'"{n}"{f" ({kb.get("title")})" if kb.get("title") else ""} is malware that secretly turns the '
                         "infected device into a proxy, so criminals can send their traffic through it and hide behind "
                         f"the owner's address. Shadowserver saw the device contacting its servers ({seen or 'sinkhole'}). "
                         "Malpedia has no entry under exactly this name."),
                "advice": "Treat the device as infected: reset or reinstall it, update it, and change its passwords.",
                "seen_in": reports}
    if _re.search(r"proxy|socks|residential", f"{low} {kind.lower()}"):
        return {"verdict": "proxy", "title": "A proxy network, not a single malware program",
                "text": (f'"{n}"{f" ({kb.get("title")})" if kb.get("title") else ""} is a network that sends other people\'s '
                         "internet traffic through devices like this one, often through an app or software kit bundled with "
                         f"free apps. Shadowserver saw the device contacting this network's servers ({seen or 'sinkhole'}). "
                         "Malpedia describes malware families; proxy networks are services (often abused) and are usually "
                         "not listed there."),
                "advice": "Find and remove the app that added the device to the proxy network: strangers may be using "
                          "the owner's internet connection.", "seen_in": reports}
    if _re.search(r"adware|hijack|miner|unwanted|riskware", kind.lower()):
        return {"verdict": "unwanted", "title": "Unwanted software, rather than a malware family",
                "text": (f'"{n}"{f" ({kind})" if kind else ""} is unwanted software: it shows advertising, changes browser '
                         "settings or uses the computer to mine cryptocurrency, usually after being installed together with "
                         "something else. Malpedia concentrates on malware used in attacks, so it may not list it."),
                "advice": "Uninstall the unwanted program and check the browser's extensions and settings.",
                "seen_in": reports}
    if _re.search(r"abandon|misconfig", kind.lower()) or low in ("popcorntime", "non-authoritative-whois", "cryptodns-resolver"):
        first = (kb.get("description") or "").split(". ")[0].rstrip(".")
        return {"verdict": "software", "title": "Old or misconfigured software, not a malware family",
                "text": ((first + ". ") if first else "") + ("Its old servers are now run by Shadowserver (a 'sinkhole'), "
                         "so devices that still use it are reported, but it is not a malicious program in itself, so "
                         "Malpedia does not list it."),
                "advice": "Remove or update the software on the device.", "seen_in": reports}
    if _re.search(r"generic|unknown|unclassified|^event\d?_|^wd$", low) or kind.lower() in ("unclassified", "malware (unidentified)"):
        return {"verdict": "generic", "title": "A general label, not a specific malware",
                "text": ("Shadowserver's sinkhole saw this device connect to a server once used by malware, but could not "
                         f'tell which malware it was, so it used the general label "{n}". Malpedia lists specific malware '
                         "families, so there is nothing to match."),
                "advice": "Treat the device as possibly infected: run a security scan on it.", "seen_in": reports}
    what = f" ({kind})" if kind else ""
    return {"verdict": "unlisted", "title": "Probably malware, but no source lists it under this name",
            "text": (f'"{n}" looks like malware{what}, but none of the sources (Malpedia, MISP Galaxy, MITRE ATT&CK) has '
                     "an entry under this name: it may be new, seen mostly in one region, or called something else there."
                     + (f" Looking Glass describes it as: {kb.get('title')}." if kb.get("title") else "")),
            "advice": "Treat the device as infected: run a security scan, and read the Looking Glass description of "
                      "this name.", "seen_in": reports}


def _read_names():
    import json as _json
    try:
        with open(_A._MISSES_PATH, encoding="utf-8") as f:
            return _json.load(f)
    except (OSError, ValueError):
        return {}


def _write_names(m):
    import json as _json
    tmp = f"{_A._MISSES_PATH}.{_A.os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        _json.dump(m, f, indent=1)
    _A.os.replace(tmp, _A._MISSES_PATH)


def _is_services_report(name):
    """True for the name of a publicly accessible / vulnerable services report (scan_mikrotik_service, scan_http...): a
    report, never malware. 2026-11-13: on 10 November the combination reports asked Malpedia about services report
    names as if they were malware; they were recorded and stayed on the Definitions to-do list."""
    n = (name or "").strip().lower()
    if not n:
        return False
    try:
        if n in {s["name"].lower() for s in _A.svc["registry"].get()}:
            return True
    except Exception:                              # noqa: BLE001  (no registry yet: the report map still answers)
        pass
    try:
        reps = _A.REPORT_MAP.get().get("reports") or {}
        e = reps.get(n)
        return bool(e and e.get("section") == "Services")
    except Exception:                              # noqa: BLE001
        return False


def _record_check(name, family, asked=True):
    """Remember that a name was checked against Malpedia and what came back ("" = nothing). Names with nothing that
    no administrator has defined yet are the to-do list in Settings. A services report's name is never recorded."""
    if _A._is_services_report(name):
        return
    now = _A.utcnow().isoformat(timespec="seconds")
    with _A._MISSES_LOCK:
        m = _A._read_names()
        x = m.setdefault(name.lower(), {"first": now, "count": 0})
        x["family"], x["checked"] = family or "", now
        if asked:
            x["count"] = x.get("count", 0) + 1; x["last"] = now
        _A._write_names(m)


def _unchecked_names():
    """Infections / categories in the loaded reports that nobody has checked against Malpedia yet (new reports
    bring new names; they appear here by themselves)."""
    seen, ev = _A._read_names(), _A._name_evidence()
    return sorted(n for n, x in ev.items() if n and n not in seen and not _A._curated(n)
                  and not (x["classes"] and x["classes"] <= set(_A._ACTIVITY)))


def _autocheck(limit=None):
    """Check the new names against Malpedia in the background, slowly (at most 20 a minute, so users' own lookups
    still fit in the 30-a-minute limit). One worker process at a time (a lock file)."""
    import fcntl
    if _A._AUTOCHECK["running"] or not _A.malpedia.enabled:
        return False
    lockf = open(_A.os.path.join(_A.BASE_DIR, "data", ".malpedia_check.lock"), "w")
    try:
        fcntl.flock(lockf, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lockf.close()
        return False
    names = _A._unchecked_names()[: limit or None]
    _A._AUTOCHECK.update(running=True, done=0, left=len(names), error="", at=_A.utcnow().isoformat(timespec="seconds"))

    def run():
        try:
            for n in names:
                try:
                    lr = _A.malpedia.lookup("infection", n)
                    _A._record_check(n, (lr.get("family") or {}).get("id") or (f"actor:{lr['actor']['id']}" if lr.get("actor") else ""), asked=False)
                except ValueError:
                    _A._record_check(n, "", asked=False)
                except RuntimeError as exc:          # rate limit / unreachable: wait and carry on later
                    _A._AUTOCHECK["error"] = str(exc)
                    _A.time.sleep(60)
                    continue
                _A._AUTOCHECK["done"] += 1; _A._AUTOCHECK["left"] -= 1
                _A.time.sleep(3)
        finally:
            _A._AUTOCHECK["running"] = False
            fcntl.flock(lockf, fcntl.LOCK_UN); lockf.close()
    _A.threading.Thread(target=run, daemon=True, name="malpedia-autocheck").start()
    return True


def _autocheck_loop():
    """Every 30 minutes (the report schedule), check names that new reports brought in."""
    _A.time.sleep(90)
    while True:
        try:
            if _A.malpedia.enabled and _A._unchecked_names():
                _A._autocheck(limit=200)
        except Exception as exc:                       # never let the background check stop the platform
            _A.app.logger.warning("Malpedia background check: %s", exc)
        _A.time.sleep(1800)


def _curated(name):
    """The administrator's definition of a name (data/infections.json), when it carries references or a Malpedia id."""
    e = _A.knowledge_base().get((name or "").lower()) or {}
    return e if (e.get("references") or e.get("malpedia")) else None


def mp_resolve(name):
    """Look a name up the way users see it: one card, the researchers' definition first, else the first source that
    knows it (Malpedia, MISP Galaxy, MITRE ATT&CK), with every other source under "Also described by"; else "No source
    knows this name" with the plain explanation (name_sources.py). Malpedia's checks still fill the to-do list."""
    return _A.NAME_SOURCES.resolve(name)


class _ReportDefs:                                   # Shadowserver's description of a report, for the ATT&CK mapping's basis
    get = staticmethod(lambda k, default=None: _A._report_def(k))


def _mp_card(r):
    """The Malpedia family of a lookup result, for the page (the same fields as the single look-up card); or the
    threat actor, when the name is a group rather than a malware family."""
    fam = r.get("family")
    if not fam and r.get("actor"):
        a, m = r["actor"], r.get("actor_match") or {}
        return {"found": True, "kind": "actor", "actor": a["id"], "family": "", "name": a["name"], "url": a["url"],
                "matched_by": m.get("matched_by", ""), "description": a["description"], "alt_names": a["synonyms"],
                "country": a["country"], "sponsor": a["sponsor"], "targets": a["targets"], "sectors": a["sectors"],
                "families": a["families"], "references": a["references"][:6], "reference_count": a["reference_count"]}
    if not fam:
        return None
    best = (r.get("matches") or [{}])[0]
    return {"found": True, "family": fam["id"], "name": fam.get("name") or fam["id"], "url": fam.get("url"),
            "matched_by": best.get("matched_by", ""), "description": fam.get("description") or "",
            "alt_names": (fam.get("alt_names") or [])[:8], "attribution": (fam.get("attribution") or [])[:6],
            "updated": fam.get("updated"), "references": (fam.get("references") or [])[:6],
            "reference_count": fam.get("reference_count", 0)}


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
