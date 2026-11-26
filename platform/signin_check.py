# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""How sign-in and high-value actions are checked: a passkey, or an authenticator code (the user, 2026-11-25).

Before, ACCESS_MODE alone decided it (public: passkeys), so installations that had chosen "public" for an office
network, before the installer offered "any computer on our internal network", were asked for passkeys after updating,
and on an IP address no passkey can be registered at all. Now one setting decides, read here only (mode()):

  passkey  every person registers 2 passkeys and signs in with one; high-value actions are confirmed with a passkey.
           Recommended for an internet-facing site: a look-alike site cannot relay a passkey.
  code     every person signs in with the authenticator code; high-value actions are confirmed with a fresh code (or a
           passkey, where the person added one). Recommended for an internal network.

Where it comes from, the first that is set:
  1. SIGNIN_CHECK in the platform's .env (passkey or code): wins over everything, and the way back from the server
     (SIGNIN_CHECK=code, then deploy/reload.sh) when nobody can sign in through the browser;
  2. the administrators' choice in Settings (data/signin_check.json, owner-only);
  3. the default: passkey for ACCESS_MODE=public, code for local and private.

  GET  /api/admin/signin-check   the mode in use, where it comes from, the default, whether this administrator may
                                 switch to passkeys here (and why not)
  POST /api/admin/signin-check   {mode: "passkey" | "code"}: 'settings' permission, CSRF, a recent sign-in, and the
                                 every-time confirmation (stepup.py RULES, kind "signin"): with passkeys in force,
                                 switching back to codes needs a passkey, so a stolen session alone cannot weaken it.
                                 Switching to passkeys is refused unless this administrator is on the site's host name
                                 over HTTPS and has registered their own 2 passkeys (nobody locked out by mistake).
Every change is in the audit log with the old and new mode. Installed from features.py."""
import json
import os
import threading

import filesig

MODES = ("passkey", "code")
WORDS = {"passkey": "Passkey", "code": "Authenticator code"}
FILE = "signin_check.json"
_state = {"path": "", "sig": None, "value": ""}
_lock = threading.Lock()


def configure(base_dir):
    _state["path"] = os.path.join(base_dir, "data", FILE)
    _state["sig"] = None


CADDYFILE = "/etc/caddy/Caddyfile"


def caddy_domain_front(path=None):
    """Caddy is in front for a domain, set up by Looking Glass (deploy/caddy_front.sh --domain): what an internet-facing
    installation from the installer has. An internal one (--internal) or none is not that."""
    try:
        with open(path or CADDYFILE, encoding="utf-8") as fh:
            head = fh.read(4096)
    except OSError:
        return False
    return head.startswith("# Managed by Looking Glass") and "\n# internal: " not in head


def default():
    """passkey only for an internet-facing site: ACCESS_MODE=public with Caddy in front for a domain. Installations that
    chose "public" for an office network before the installer offered "any computer on our internal network"
    (2026-11-19) have no such Caddy, and keep the authenticator code after updating: nobody locked out."""
    import security
    return "passkey" if security.access_mode() == "public" and caddy_domain_front() else "code"


def _env():
    v = (os.environ.get("SIGNIN_CHECK") or "").strip().lower()
    return v if v in MODES else ""


def _kept():
    """The administrators' choice, read again whenever the file changes (size, time and inode, not the time alone)."""
    p = _state["path"]
    if not p:
        return ""
    try:
        sig = filesig.sig(p)                   # the one shared file signature (filesig.py)
    except OSError:
        sig = None
    if sig is None:
        _state["sig"], _state["value"] = None, ""
        return ""
    if sig != _state["sig"]:
        try:
            with open(p, encoding="utf-8") as fh:
                v = str((json.load(fh) or {}).get("mode") or "").lower()
        except (OSError, ValueError, AttributeError):
            v = ""
        _state["sig"], _state["value"] = sig, v if v in MODES else ""
    return _state["value"]


def source():
    """env, settings or default: where the mode in use comes from."""
    return "env" if _env() else "settings" if _kept() else "default"


def mode():
    """passkey or code: the one answer sign-in (auth.py) and the step-up gate (stepup.py) ask."""
    return _env() or _kept() or default()


def passkeys_required():
    return mode() == "passkey"


def _write(value):
    p = _state["path"]
    os.makedirs(os.path.dirname(p), exist_ok=True)
    tmp = f"{p}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"mode": value}, fh)
    os.replace(tmp, p)
    _state["sig"] = None


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit, store (the passkey store), min_passkeys."""
    from flask import g, jsonify, request
    import passkeys
    configure(ctx["base_dir"])
    has_perm, csrf_ok, fresh, audit = ctx["has_perm"], ctx["csrf_ok"], ctx["fresh"], ctx["audit"]
    store, minimum = ctx["store"], ctx["min_passkeys"]

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def may_passkey():
        """(True, "") when this administrator may switch to passkeys from here, else (False, why in plain words)."""
        rp, _why = passkeys.rp_of(request.host, request.is_secure)
        if not rp:
            return False, ("Passkeys work only on the site's host name over HTTPS with a trusted certificate, never on "
                           "an IP address: open Looking Glass by its name first.")
        n = store.count(me())
        if n < minimum:
            return False, (f"Register your own {minimum} passkeys first (Your account): with passkeys in force, "
                           f"everyone signs in with one. You have {n}.")
        return True, ""

    def view():
        ok, why = may_passkey()
        return {"mode": mode(), "source": source(), "default": default(), "words": WORDS,
                "may_passkey": ok, "why_not": why, "minimum": minimum}

    @app.route("/api/admin/signin-check", methods=["GET", "POST"])
    def api_admin_signin_check():
        if not me():
            return jsonify(error="Sign in again."), 401
        if not has_perm("settings"):
            return jsonify(error="Changing how sign-in is checked is for administrators (the 'settings' permission)."), 403
        if request.method == "GET":
            return jsonify(view())
        if request.mimetype != "application/json" or not csrf_ok():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not fresh():
            return jsonify(error="Sign in again first (sessions older than 12 hours can only view).", reauth=True), 403
        want = str((request.get_json(silent=True) or {}).get("mode") or "").strip().lower()
        if want not in MODES:
            return jsonify(error="Choose a passkey or the authenticator code."), 400
        if source() == "env":
            return jsonify(error=f"SIGNIN_CHECK={_env()} is set in the platform's .env, which wins: change it there "
                                 "and run deploy/reload.sh."), 400
        old = mode()
        if want == old:
            return jsonify(view())
        if want == "passkey":
            ok, why = may_passkey()
            if not ok:
                return jsonify(error=why), 400
        with _lock:
            _write(want)
        audit.add("signin_check_changed", user=me(), detail=f"{WORDS[old]} -> {WORDS[want]}")
        return jsonify(view())

    return {"mode": mode}
