# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Settings → Update: update Looking Glass from the page, with a backup, a signed release and a way back.

The web service cannot change its own code (its code folders are read-only for it), and never runs anything as root.
So this module only asks: it writes data/update/request.json, and the update helper (deploy/update_helper.sh install,
once, with sudo) starts deploy/update_run.py as the installation's own user. That run backs up, fetches the release,
checks its signature, moves the code, installs the libraries from the locks, restarts and checks that Looking Glass
answers, putting the previous release back if it does not. It writes every step to data/update/log.jsonl, which this
module shows, so the page follows it live, also across the restart.

  GET  /api/admin/update   whether the helper is installed (and the command when not), whether this is an installation
                           from a release, the installed release, the last run (state, step, result) and its log
  POST /api/admin/update   {kind: "check"} looks for a newer release; {kind: "update", tag} installs that release.
                           'settings' permission, CSRF, a recent sign-in, and for "update" the every-time confirmation
                           (stepup.py, kind "update"). Refused while a run is busy or the helper is missing.
Whatever a request says, the helper installs only a release signed by the maintainer and newer than the installed one.
Every request is in the audit log, and the helper writes how it ended (update_done, update_failed, update_rolled_back).
Installed from features.py."""
import json
import os
import re
import time

TAG_RE = re.compile(r"\Av[0-9][0-9A-Za-z._-]{0,40}\Z")      # as deploy/verify_install.py
UNIT_DIR = "/etc/systemd/system"
COMMAND = "deploy/update_helper.sh install"
BUSY_FOR = 2 * 3600                                          # a run older than this is not "running" any more
LOG_LINES = 400


def unit_name():
    return (os.environ.get("LG_SERVICE") or "looking-glass").strip() + "-update"


def helper_installed(unit_dir=UNIT_DIR):
    return os.path.exists(os.path.join(unit_dir, unit_name() + ".path"))


def _read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            v = json.load(fh)
        return v if isinstance(v, dict) else {}
    except (OSError, ValueError):
        return {}


def _log(path, n=LOG_LINES):
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()[-n:]
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            x = json.loads(ln)
        except ValueError:
            continue
        if isinstance(x, dict):
            out.append({"t": x.get("t"), "step": str(x.get("step") or ""), "level": str(x.get("level") or "info"),
                        "msg": str(x.get("msg") or "")})
    return out


def _installed_tag(base):
    """The release of the installed commit, read from the local checkout (no connection), '' when none."""
    import subprocess
    try:
        r = subprocess.run(["git", "-C", base, "describe", "--tags", "--exact-match", "HEAD"], capture_output=True,
                           text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return ""
    tag = r.stdout.strip() if r.returncode == 0 else ""
    return tag if TAG_RE.match(tag) else ""


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, people_name (full name of an account)."""
    from flask import g, jsonify, request
    base = ctx["base_dir"]
    has_perm, csrf_ok, fresh, audit = ctx["has_perm"], ctx["csrf_ok"], ctx["fresh"], ctx["audit"]
    people_name = ctx.get("people_name") or (lambda u: u)
    state = os.path.join(base, "data", "update")
    request_file, status_file, log_file = (os.path.join(state, n) for n in ("request.json", "status.json", "log.jsonl"))

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def busy(st):
        return (st.get("state") == "running" and time.time() - float(st.get("started") or 0) < BUSY_FOR) \
            or os.path.exists(request_file)

    def view():
        st = _read_json(status_file)
        return {"helper": helper_installed(), "unit": unit_name(), "command": COMMAND,
                "release_install": os.path.isfile(os.path.join(base, ".release_fingerprints")),
                "installed": _installed_tag(base), "busy": busy(st), "waiting": os.path.exists(request_file),
                "status": {k: st.get(k) for k in ("state", "kind", "tag", "by", "started", "ended", "step", "result",
                                                   "installed", "newest", "newer")},
                "log": _log(log_file)}

    @app.route("/api/admin/update", methods=["GET", "POST"])
    def api_admin_update():
        if not me():
            return jsonify(error="Sign in again."), 401
        if not has_perm("settings"):
            return jsonify(error="Updating Looking Glass is for administrators (the 'settings' permission)."), 403
        if request.method == "GET":
            return jsonify(view())
        if request.mimetype != "application/json" or not csrf_ok():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not fresh():
            return jsonify(error="Sign in again first (sessions older than 12 hours can only view).", reauth=True), 403
        b = request.get_json(silent=True) or {}
        kind, tag = str(b.get("kind") or ""), str(b.get("tag") or "").strip()
        if kind not in ("check", "update"):
            return jsonify(error="Choose Check for an update, or Update."), 400
        if kind == "update" and not TAG_RE.match(tag):
            return jsonify(error="Check for an update first, then choose the release."), 400
        v = view()
        if not v["release_install"]:
            return jsonify(error="This folder was not installed from a release (for example a developer's working "
                                 "copy): its maintainer updates it."), 400
        if not v["helper"]:
            return jsonify(error=f"The update helper is not installed: on the server, in the platform folder, run "
                                 f"{COMMAND} (once)."), 400
        if v["busy"]:
            return jsonify(error="An update run is busy: its steps are shown below."), 409
        who = people_name(me()) or "an administrator"
        req = {"kind": kind, "tag": tag if kind == "update" else "", "by": who, "at": round(time.time(), 3)}
        os.makedirs(state, mode=0o700, exist_ok=True)
        tmp = f"{request_file}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(req, fh)
        os.replace(tmp, request_file)
        audit.add("update_requested" if kind == "update" else "update_check_requested", user=me(),
                  target=req["tag"], detail="Settings → Update")
        return jsonify(view())

    return {"view": view}
