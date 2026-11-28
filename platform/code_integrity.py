# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The daily code check (r91): the installed code files against the release's fingerprints, inside the platform.

Every release lists the SHA-256 of every file it ships, in platform/ and database/ (.release_fingerprints, written by
the release builder through deploy/stale_files.py). Once a day (and a few minutes after each start, so after every
update), this compares the code files of the platform's folder and, when it is found, the database pipeline's folder
(the code folders and exclusions of deploy/stale_files.py) with that list, and finds:
  changed   a listed file whose content is not what the release shipped
  unknown   a file in a code folder that the release does not list (added here)
For each file and content (path + SHA-256), ONCE: an audit entry (code_integrity_finding, a system event). While any
finding stands: one alert in the administrators' bell (system_alerts.py), listing them.

What an administrator does, in Settings → Code check (the Settings permission, the page's CSRF token, a session younger
than 12 hours and their own password again: password_policy.check_own_password):
  "This is ours, keep it"            the file and its SHA-256 go into data/code_approved.json {path: sha256}; audited.
                                     If the file changes later, it is found again.
  "Not ours, move to quarantine"     the decision is recorded (data/code_integrity.json) and audited, and the page gives
                                     the command the administrator runs on the server, as themselves:
                                     deploy/verify_install.py --folder <folder> --quarantine <path>, which moves the file
                                     (never deletes it) to <folder>/backups/quarantine-<time>/<path>. The service itself
                                     never moves or deletes a code file: its code folders are read-only for it (the
                                     service's sandbox, ReadOnlyPaths), by design. The next check sees the file gone.
Then: check the whole installation against the signed release, deploy/verify_install.py --fetch (GUIDE below).

This compares with the list on this computer: it shows that the code is what that list says, which catches a changed
or added file; only deploy/verify_install.py --fetch compares with the signed release. Not checked: the maintainer's
working copy (tools/release_root is there, as deploy/stale_files.py says), and an installation whose release has no
fingerprint list (before r91). No outside connection: it reads files only. Nothing here holds an address or a report.
Installed from features.py: code_integrity.install(app, ctx).
"""
import hashlib
import importlib.util
import json
import os
import shlex
import threading
import time

from flask import g, jsonify, request

import people
import pipeline_link
import reqjson

STATE = "code_integrity.json"            # data/: the last check, its findings, what was audited, the "not ours" decisions
APPROVED = "code_approved.json"          # data/: {"platform/<path>": sha256} kept by an administrator
SYSTEM_USER = "looking-glass"
FIRST_AFTER = 180                        # seconds after a start before the first check
CHECK_EVERY = 24 * 3600                  # then once a day
KIND_TEXT = {"changed": "Changed: not what the release shipped", "unknown": "Not in the release: added here"}
GUIDE = ("Check the whole installation against the signed release: on the server, in the Looking Glass folder, run "
         "platform/deploy/verify_install.py --fetch (and, for the database pipeline, add --folder database). It fetches "
         "the release's signed tag from GitHub, checks its signature and compares every code file. A shipped file that "
         "was changed or moved to quarantine is put back as released with  git checkout <tag> -- <part>/<path>  in the "
         "Looking Glass folder, then restart Looking Glass.")
NOT_SERVICE = ("Looking Glass cannot change its own code (as intended: its code folders are read-only for the service), "
               "so the file is moved by you, on the server.")
REFUSE = "The code check is for administrators (permission 'settings')."
_LOCK = threading.Lock()
_SF = {}


# ------------------------------------------------------------------------------------------------ reading
def stale_files(base):
    """deploy/stale_files.py of this platform (the one writer and reader of the release's lists)."""
    path = os.path.join(base, "deploy", "stale_files.py")
    if path not in _SF:
        spec = importlib.util.spec_from_file_location("lg_stale_files_ci", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _SF[path] = mod
    return _SF[path]


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _write_json(path, d):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(d, fh, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else ""


def folders(base):
    """[(part, folder)]: the platform's folder, and the database pipeline's when it is found (pipeline_link)."""
    out = [("platform", os.path.abspath(base))]
    try:
        pdir = pipeline_link.find_dir(base)
    except Exception:                    # noqa: BLE001  (no pipeline here)
        pdir = None
    if pdir and os.path.abspath(str(pdir)) != out[0][1]:
        out.append(("database", os.path.abspath(str(pdir))))
    return out


def working_copy(base):
    return os.path.isdir(os.path.join(base, "tools", "release_root"))


def approved(base):
    """{key: sha256} an administrator kept as theirs (malformed entries left out)."""
    d = _read_json(os.path.join(base, "data", APPROVED)) or {}
    return {str(k): str(v) for k, v in d.items() if isinstance(v, str) and len(v) == 64}


def scan(base):
    """What the code folders hold against the release's lists, now: {checked, why, parts: {part: {checked, why,
    files}}, findings: [{key, part, rel, kind, sha256, expected, former}], problem}. Reads files only."""
    base = os.path.abspath(base)
    res = {"checked": False, "why": "", "parts": {}, "findings": [], "problem": ""}
    if working_copy(base):
        res["why"] = "maintainer's working copy (tools/release_root is here), not checked"
        return res
    SF = stale_files(base)
    ok_ = approved(base)
    for part, folder in folders(base):
        p = res["parts"][part] = {"checked": False, "why": "", "files": 0, "folder": folder}
        try:
            listed = SF.read_fingerprints(folder)
        except (SF.ListRefused, OSError) as e:
            p["why"] = f"the release's fingerprint list cannot be trusted: {e}"
            res["problem"] = res["problem"] or f"{part}: {p['why']}"
            continue
        if listed is None:
            p["why"] = f"no fingerprint list ({SF.FINGERPRINTS_NAME}) here: the release installed is older than r91"
            continue
        try:
            history = SF.read_list(folder, SF.HISTORY_NAME) or set()
        except (SF.ListRefused, OSError):
            history = set()
        files = [r for r in SF.code_files(folder, part) if not SF.kept(r)]
        p.update(checked=True, files=len(files))
        for rel in files:
            key = f"{part}/{rel}"
            try:
                sha = SF.sha256_of(os.path.join(folder, *rel.split("/")))
            except OSError:
                continue
            want = listed.get(rel)
            if want == sha or ok_.get(key) == sha:
                continue
            res["findings"].append({"key": key, "part": part, "rel": rel, "kind": "unknown" if want is None else "changed",
                                    "sha256": sha, "expected": want or "", "former": want is None and rel in history})
    res["checked"] = any(p["checked"] for p in res["parts"].values())
    if not res["checked"] and not res["why"]:
        res["why"] = "; ".join(f"{k}: {v['why']}" for k, v in res["parts"].items() if v["why"]) or "nothing to check"
    return res


# ------------------------------------------------------------------------------------------------ the check
def check(base, audit, now=None):
    """Scan, write each new finding (path + SHA-256) to the audit log once, keep the state; returns the state."""
    now = now or time.time()
    path = os.path.join(base, "data", STATE)
    with _LOCK:
        res = scan(base)
        st = _read_json(path) or {}
        audited = set(st.get("audited") or [])
        before = {(f.get("key"), f.get("sha256")): f.get("first_seen") for f in st.get("findings") or [] if isinstance(f, dict)}
        for f in res["findings"]:
            f["first_seen"] = before.get((f["key"], f["sha256"])) or now
            mark = f"{f['key']}|{f['sha256']}"
            if mark in audited:
                continue
            detail = f"{KIND_TEXT[f['kind']]}; sha256 {f['sha256']}"
            if f["expected"]:
                detail += f"; the release lists sha256 {f['expected']}"
            elif f["former"]:
                detail += "; an earlier release shipped a file of this name"
            audit.add("code_integrity_finding", user=SYSTEM_USER, target=f["key"], detail=detail)
            audited.add(mark)
        # "not ours" decisions: kept while that file and content are still flagged; once the file has left the code
        # folder (the administrator ran the command), that is recorded once and the decision dropped
        now_flagged = {(f["key"], f["sha256"]) for f in res["findings"]}
        decided = {}
        for k, d in (st.get("decided") or {}).items():
            if not isinstance(d, dict):
                continue
            if (k, d.get("sha256")) in now_flagged:
                decided[k] = d
            elif res["checked"] and not any(f["key"] == k for f in res["findings"]):
                part, _, rel = str(k).partition("/")
                pinfo = res["parts"].get(part) or {}
                if not pinfo.get("checked") or not pinfo.get("folder"):
                    decided[k] = d                  # that folder was not checked this time: nothing is known yet
                    continue
                if os.path.lexists(os.path.join(pinfo["folder"], *rel.split("/"))):
                    # still in the folder, no longer flagged: kept as ours (audited by the approval) or back as the
                    # release shipped it. The decision is dropped; it did NOT leave the folder (audit 2026-11-27: a
                    # false code_integrity_removed was written here)
                    continue
                audit.add("code_integrity_removed", user=SYSTEM_USER, target=k,
                          detail=f"the file marked not ours (sha256 {d.get('sha256')}) is no longer in the code folder")
        st["decided"] = decided
        st.update(at=now, checked=res["checked"], why=res["why"], problem=res["problem"], findings=res["findings"],
                  parts={k: {x: v[x] for x in ("checked", "why", "files")} for k, v in res["parts"].items()},
                  audited=sorted(audited))
        _write_json(path, st)
        return st


def state(base):
    return _read_json(os.path.join(base, "data", STATE)) or {}


def bell(base, now=None):
    """The administrators' alert while findings stand (and when the list cannot be trusted), for system_alerts.Alerts."""
    st = state(base)
    out = []
    fs = [f for f in st.get("findings") or [] if isinstance(f, dict) and f.get("key")]
    at = float(st.get("at") or now or time.time())
    if fs:
        ident = hashlib.sha256("\n".join(sorted(f"{f['key']}|{f.get('sha256')}" for f in fs)).encode()).hexdigest()[:16]
        changed = [f["key"] for f in fs if f.get("kind") == "changed"]
        unknown = [f["key"] for f in fs if f.get("kind") != "changed"]

        def names(xs):
            return ", ".join(xs[:5]) + (f" and {len(xs) - 5} more" if len(xs) > 5 else "")
        bits = ([f"changed: {names(changed)}"] if changed else []) + ([f"not in the release: {names(unknown)}"] if unknown else [])
        waiting = sum(1 for f in fs if ((st.get("decided") or {}).get(f["key"]) or {}).get("sha256") == f.get("sha256"))
        if waiting:
            bits.append(f"{waiting} marked not ours wait{'s' if waiting == 1 else ''} to be moved on the server (the "
                        "command is in Settings → Code check)")
        out.append({"key": f"code-integrity:{ident}", "problem": True,
                    "title": f"{len(fs)} code file{'s' if len(fs) != 1 else ''} not as the release shipped them",
                    "text": ("the daily code check found " + "; ".join(bits) + ". In Settings → Code check, keep each as "
                             "yours (with your password) or move it to quarantine; then check the installation against "
                             "the signed release (deploy/verify_install.py --fetch)."),
                    "at": at, "link": "/settings#cardCode", "perms": ("settings",)})
    if st.get("problem"):
        out.append({"key": "code-integrity-refused:" + hashlib.sha256(str(st["problem"]).encode()).hexdigest()[:16],
                    "problem": True, "title": "The daily code check could not run",
                    "text": f"{st['problem']}. Check the installation with deploy/verify_install.py --fetch.",
                    "at": at, "link": "/settings#cardCode", "perms": ("settings",)})
    return out


def quarantine_command(base, part, folder, rel):
    """The command an administrator runs on the server, as themselves (the service cannot change its own code): it
    moves <folder>/<rel> to <folder>/backups/quarantine-<time>/<rel>, never deleting it (deploy/verify_install.py)."""
    tool = os.path.join(os.path.abspath(base), "deploy", "verify_install.py")
    return " ".join(shlex.quote(x) for x in ("python3", tool, "--folder", folder, "--part", part, "--quarantine", rel))

# ------------------------------------------------------------------------------------------------ the routes
def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, serving, logger, people_name, and for the password re-check
    users, throttle, client."""
    base, hp, audit = ctx["base_dir"], ctx["has_perm"], ctx["audit"]
    log = ctx.get("logger")

    def loop():
        time.sleep(FIRST_AFTER)
        while True:
            try:
                check(base, audit)
            except Exception:              # noqa: BLE001  (logged; tried again at the next check)
                if log:
                    log.exception("code check failed")
            time.sleep(CHECK_EVERY)

    if ctx.get("serving"):
        threading.Thread(target=loop, daemon=True, name="code-check").start()

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def view(st):
        fs = []
        decided = st.get("decided") or {}
        for f in st.get("findings") or []:
            d = decided.get(f["key"]) if isinstance(decided.get(f["key"]), dict) else None
            d = d if d and d.get("sha256") == f["sha256"] else None      # a decision is for that exact content
            fs.append({"key": f["key"], "kind": f["kind"], "kind_text": KIND_TEXT.get(f["kind"], f["kind"]),
                       "sha256": f["sha256"], "expected": f.get("expected", ""), "former": bool(f.get("former")),
                       "first_seen": _when(f.get("first_seen")),
                       "decided": {"by": d.get("by", ""), "at": _when(d.get("at")), "command": d.get("command", "")} if d else None})
        return {"checked": bool(st.get("checked")), "why": st.get("why", ""), "problem": st.get("problem", ""),
                "at": _when(st.get("at")), "parts": st.get("parts") or {}, "findings": fs,
                "approved": len(approved(base)), "guide": GUIDE, "not_service": NOT_SERVICE,
                "every_hours": CHECK_EVERY // 3600}

    def guard(change=True):
        """None when the request may change something (the Settings permission, CSRF, a fresh session); else the
        refusal. Every POST route calls guard(change=True)."""
        if not hp("settings"):
            return jsonify(error=REFUSE), 403
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx.get("fresh", lambda: False)():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours).", reauth=True), 403
        if not all(k in ctx for k in ("users", "throttle", "client")):
            return jsonify(error="This needs a signed-in administrator's own password."), 403
        return None

    def the_finding(body):
        """(finding, state) for the file and SHA-256 the page showed, after checking again now; (None, state) when the
        file is no longer flagged or has changed since."""
        key, sha = str(body.get("key") or ""), str(body.get("sha256") or "")
        st = check(base, audit)
        f = next((x for x in st.get("findings") or [] if x["key"] == key and x["sha256"] == sha), None)
        return f, st

    @app.route("/api/admin/code-check")
    def api_code_check():
        if not hp("settings"):
            return jsonify(error=REFUSE), 403
        st = state(base)
        if not st:                                    # never checked yet (just started): now
            st = check(base, audit)
        return jsonify(**view(st))

    @app.route("/api/admin/code-check/approve", methods=["POST"])
    def api_code_check_approve():
        """"This is ours, keep it": the Settings permission, CSRF, a fresh session and the administrator's own password."""
        bad = guard(change=True)
        if bad:
            return bad
        body = reqjson.body()
        f, st = the_finding(body)
        if not f:
            return jsonify(error="That file is no longer flagged, or it changed since this page was opened: look again.",
                           **view(st)), 409
        import password_policy                       # the one password re-check
        bad = password_policy.check_own_password(ctx, "code_integrity_password_failed",
                                                 f"Settings → Code check: wrong password (keeping {f['key']})")
        if bad:
            return bad
        u = me()
        full = (ctx.get("people_name") or (lambda x: ""))(u) or people.person_label(u)   # never the sign-in name
        with _LOCK:
            ap = approved(base)
            ap[f["key"]] = f["sha256"]
            _write_json(os.path.join(base, "data", APPROVED), ap)
        audit.add("code_integrity_approved", user=u, target=f["key"],
                  detail=f"kept as ours by {full}: {KIND_TEXT[f['kind']]}; sha256 {f['sha256']} (found again if it changes)")
        return jsonify(ok=True, **view(check(base, audit)))

    @app.route("/api/admin/code-check/quarantine", methods=["POST"])
    def api_code_check_quarantine():
        """"Not ours, move to quarantine": the same checks. The decision is recorded and audited, and the answer gives
        the command the administrator runs on the server: the service never moves or deletes a code file (its code
        folders are read-only for it, by design)."""
        bad = guard(change=True)
        if bad:
            return bad
        body = reqjson.body()
        f, st = the_finding(body)
        if not f:
            return jsonify(error="That file is no longer flagged, or it changed since this page was opened: look again.",
                           **view(st)), 409
        import password_policy
        bad = password_policy.check_own_password(ctx, "code_integrity_password_failed",
                                                 f"Settings → Code check: wrong password (not ours: {f['key']})")
        if bad:
            return bad
        folder = dict(folders(base)).get(f["part"])
        if not folder:
            return jsonify(error="That file's folder is no longer found.", **view(st)), 409
        u = me()
        full = (ctx.get("people_name") or (lambda x: ""))(u) or people.person_label(u)   # never the sign-in name
        cmd = quarantine_command(base, f["part"], folder, f["rel"])
        with _LOCK:
            ap = approved(base)
            if ap.pop(f["key"], None) is not None:
                _write_json(os.path.join(base, "data", APPROVED), ap)
            st = state(base)
            dec = st.get("decided") if isinstance(st.get("decided"), dict) else {}
            dec[f["key"]] = {"sha256": f["sha256"], "kind": f["kind"], "by": full, "at": time.time(), "command": cmd}
            st["decided"] = dec
            _write_json(os.path.join(base, "data", STATE), st)
        audit.add("code_integrity_quarantine_decided", user=u, target=f["key"],
                  detail=(f"not ours, to be moved to quarantine, decided by {full}: {KIND_TEXT[f['kind']]}; sha256 "
                          f"{f['sha256']}; the administrator moves it on the server with: {cmd}"))
        return jsonify(ok=True, command=cmd, **view(state(base)))
    return {"check": lambda now=None: check(base, audit, now), "scan": lambda: scan(base), "state": lambda: state(base)}
