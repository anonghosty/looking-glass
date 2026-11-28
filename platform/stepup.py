# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A fresh check before high-value actions (the user, 2026-11-24), against malware riding a signed-in browser.

Malware on a staff member's computer can use their open session from the same address and browser. Before a
high-value action Looking Glass therefore asks for something malware does not have:
- with passkeys in force (Settings' sign-in check, signin_check.py; by default on ACCESS_MODE=public): a passkey
  (passkeys.py), which a look-alike site cannot relay either;
- otherwise (by default internal installations): a fresh authenticator code (a passkey too, where the person added one).
A confirmation covers 10 minutes of high-value actions, except the most dangerous ones, which ask every time: changes
to accounts, roles and sign-up links, and turning on or changing a connector target. The list is RULES below, one
place, checked before every request on the server: no page can forget it. Every confirmation, failure and refusal is
in the audit log; wrong codes count towards the sign-in lock like a wrong sign-in.

Also here: the passkey pages and their API (/account, /api/passkeys), the administrators' passkey reset, and the
sign-in rule on public installations that a person registers MIN_PUBLIC passkeys before anything else.
"""
import hashlib
import os
import re
import secrets
import threading
import time

from flask import g, jsonify, redirect, render_template, request

import passkeys
import reqjson
import signin_check
import system_alerts
from user_words import words

WINDOW = 600                     # seconds one confirmation covers (the user, P5a)
GRANT_SECONDS = 120              # an every-time confirmation: used once, within this time, for that request only
# (methods, path pattern, extra test or None, kind, every time). The kinds' plain words are in WORDS.
RULES = [
    ({"GET"}, r"/api/svc/hosts\.csv", None, "export", False),
    ({"GET", "POST"}, r"/api/.*", lambda: request.args.get("all") == "1", "export", False),
    ({"GET"}, r"/api/combos/search/[^/]+/download", None, "export", False),
    ({"GET", "POST"}, r"/api/intelligence/export\.csv", None, "export", False),
    ({"GET"}, r"/api/advisory/[^/]+/export", None, "export", False),
    ({"GET", "POST"}, r"/api/intelligence(/report|/export\.csv)?", lambda: _arg("reveal") == "1", "reveal", False),
    ({"POST"}, r"/api/audit/trace", None, "trace", False),
    ({"POST"}, r"/api/admin/users/[^/]+(/passkeys/reset)?", None, "accounts", True),
    ({"POST"}, r"/api/admin/roles", None, "accounts", True),
    ({"POST"}, r"/api/admin/invites(/[^/]+/revoke)?", None, "accounts", True),
    ({"POST"}, r"/api/settings", None, "settings", False),
    ({"POST"}, r"/api/admin/config", None, "settings", False),
    # the whole-codebase audit (2026-11-27, the user: "add to all"): the pipeline's API key, settings and held release,
    # the organisation printed on advisories, the password policy (forcing every account: every time), and a decided
    # review's ZIP of unmasked addresses (its in-browser PDF preview opens in the browser's viewer and stays a view)
    ({"POST"}, r"/api/pipeline/(apikey|settings|release)", None, "settings", False),
    ({"POST"}, r"/api/organisation", None, "settings", False),
    ({"POST"}, r"/api/password-policy", None, "accounts", False),
    ({"POST"}, r"/api/password-policy/force", None, "accounts", True),
    ({"GET"}, r"/review/[^/]+/report", lambda: request.args.get("as") != "pdf", "export", False),
    ({"POST"}, r"/api/admin/quarterly/purge", None, "purge", False),
    ({"POST"}, r"/api/advisory/[^/]+/(generate|send)", None, "advisory", False),
    # every change to a target (save, on, off, scope, TLP, key, delete); testing changes nothing and needs no check
    ({"POST"}, r"/api/connectors(?!/test\Z)(/.*)?", None, "connector", True),
    ({"POST"}, r"/api/passkeys(/[^/]+/remove)?", None, "passkeys", True),
    # how sign-in is checked (signin_check.py): with passkeys in force, going back to codes needs a passkey
    ({"POST"}, r"/api/admin/signin-check", None, "signin", True),
    # Settings -> Update (platform_update.py): installing a release; looking for one changes nothing and needs no check
    ({"POST"}, r"/api/admin/update", lambda: _json().get("kind") == "update", "update", True),
]
WORDS = {"export": "download a complete or unmasked list", "reveal": "show leaked accounts unmasked",
         "trace": "trace a leak", "accounts": "change accounts, roles or sign-up links",
         "settings": "change the constituency or the configuration", "purge": "run the quarterly purge",
         "advisory": "generate or send an advisory", "connector": "turn on or change a connector",
         "passkeys": "add or remove a passkey", "signin": "change how sign-in is checked",
         "update": "update Looking Glass"}
_RULES = [(m, re.compile(p + r"\Z"), t, k, e) for m, p, t, k, e in RULES]
# the permission a path's change needs, where it is certain (the route refuses without it: app.py api_settings)
NEEDS_PERM = {"/api/settings": "settings", "/api/pipeline/apikey": "settings", "/api/pipeline/settings": "settings",
              "/api/pipeline/release": "settings", "/api/organisation": "settings", "/api/password-policy": "settings",
              "/api/password-policy/force": "settings"}
# the pages and calls a person may use while they still have to register their passkeys (public installations)
ENROL_OPEN = ("/account", "/api/passkeys", "/api/me", "/logout", "/static/", "/welcome")


def _json():
    """The request's JSON body when it is an object, else {}: a list or a number as the body must not turn the gate or
    a route into an error 500 (audit 2026-11-27, 8-8). The one shared helper (reqjson.py), used by the other routes too."""
    return reqjson.body()


def _arg(name):
    v = request.args.get(name)
    if v is None and request.method == "POST":
        v = request.form.get(name)
        if v is None and request.is_json:
            v = _json().get(name)
    return None if v is None else str(v)


def rule_for(method, path):
    """(kind, every_time) of the first rule this request matches, else None."""
    for methods, rx, test, kind, every in _RULES:
        if method in methods and rx.match(path) and (test is None or test()):
            return kind, every
    return None


def tests_off():
    """The test suite's own in-process checks switch the gate off (they sign in with throwaway sessions and test
    other things); check_stepup.py tests it with the gate on. The running service never sets this."""
    return os.environ.get("LG_STEPUP_TESTS_OFF") == "1"


def install(app, ctx):
    users, sessions, audit, throttle = ctx["users"], ctx["sessions"], ctx["audit"], ctx["throttle"]
    csrf_ok, totp_check = ctx["csrf_ok"], ctx["totp_check"]
    people_name = ctx.get("people_name") or (lambda n: n)
    has_perm = ctx.get("has_perm")
    store = passkeys.Store(os.path.join(ctx["base_dir"], "data", "passkeys.json"))
    challenges = passkeys.Challenges()
    grants, glock = {}, threading.Lock()
    hook = ctx.get("hook")
    if hook is not None:                     # auth.py's sign-in reads the same store (auth.PASSKEYS)
        hook.update(store=store, challenges=challenges, min_public=passkeys.MIN_PUBLIC)

    def public():
        """Passkeys in force: Settings' sign-in check (signin_check.py), no longer ACCESS_MODE alone (2026-11-25)."""
        return signin_check.passkeys_required()

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def skey():
        return (getattr(g, "user", None) or {}).get("key", "")

    def client():
        return request.remote_addr or "", request.headers.get("User-Agent", "")

    def session_field(name, default=None):
        with sessions.lock:
            return (sessions.s.get(skey()) or {}).get(name, default)

    def mark(**kw):
        with sessions.lock:
            s = sessions.s.get(skey())
            if s is not None:
                s.update(kw)
                sessions._persist(force=True)

    def how():
        """"passkey" or "code", and whether this person may also use the other (internal installations with passkeys)."""
        if public():
            return "passkey", False
        rp, _ = passkeys.rp_of(request.host, request.is_secure)
        return "code", bool(rp and store.count(me()))

    def window_left():
        at = session_field("stepup_at") or 0
        return max(0, int(at + WINDOW - time.time()))

    # ---------------- the gate, before every request (after auth.py's sign-in check)
    @app.before_request
    def _stepup_gate():
        u = getattr(g, "user", None)
        if not u or u.get("automation") or tests_off():
            return None
        p = request.path
        # public installations: a person without their passkeys registers them first (no grace, the user P4a)
        if public() and session_field("needs_passkeys") and store.count(u["user"]) < passkeys.MIN_PUBLIC:
            if not p.startswith(ENROL_OPEN):
                if p.startswith("/api/"):
                    return jsonify(error=f"Register your {passkeys.MIN_PUBLIC} passkeys first (Your account).",
                                   passkeys_needed=True), 403
                return redirect("/account?enrol=1")
        hit = rule_for(request.method, p)
        if not hit:
            return None
        kind, every = hit
        # a change the person may not make at all: no "confirm it is you" first, the route refuses it with its own words
        # (2026-11-26: an account without the Settings permission was asked to confirm, then refused). Only where the
        # permission is certain: a wrong one would let a permitted change through without the check.
        if has_perm and p in NEEDS_PERM and not has_perm(NEEDS_PERM[p]):
            return None
        if kind == "passkeys" and public() and session_field("needs_passkeys") and store.count(u["user"]) < passkeys.MIN_PUBLIC:
            return None                      # registering the first passkeys right after signing in
        if every:
            tok = request.headers.get("X-LG-Stepup") or ""
            with glock:
                gr = grants.pop(hashlib.sha256(tok.encode()).hexdigest(), None) if tok else None
            if gr and gr["key"] == skey() and gr["kind"] == kind and gr["method"] == request.method and gr["path"] == p \
                    and time.time() - gr["at"] < GRANT_SECONDS:
                audit.add("stepup_used", user=u["user"], target=p, detail=f"{kind}: confirmed for this action")
                return None
        elif window_left() > 0:
            return None
        h, also = how()
        audit.add("stepup_asked", user=u["user"], target=p, detail=f"{kind}: {h}" + (" (every time)" if every else ""))
        return jsonify(error=f"Confirm it is you to {WORDS[kind]}.", stepup=h, also_passkey=also, every_time=every,
                       kind=kind, action=WORDS[kind]), 403

    def finish(kind_path):
        """After a passed check: the window (10 minutes), and for an every-time action a grant for that one request."""
        method, path = kind_path
        mark(stepup_at=time.time())
        hit = rule_for(method, path) if method and path else None
        out = {"ok": True, "window": WINDOW}
        if hit and hit[1]:
            tok = secrets.token_urlsafe(24)
            with glock:
                now = time.time()
                for k in [k for k, v in grants.items() if now - v["at"] > GRANT_SECONDS]:
                    grants.pop(k, None)
                grants[hashlib.sha256(tok.encode()).hexdigest()] = {"key": skey(), "kind": hit[0], "method": method,
                                                                    "path": path, "at": now}
            out["grant"] = tok
        return out

    def target():
        b = _json()
        m, p = str(b.get("method") or "").upper()[:8], str(b.get("path") or "")[:300]
        return (m, p if p.startswith("/") else "")

    @app.route("/api/stepup/status")
    def api_stepup_status():
        if not me():
            return jsonify(error="Login required"), 401
        h, also = how()
        return jsonify(how=h, also_passkey=also, window_left=window_left(), passkeys=store.count(me()))

    @app.route("/api/stepup/code", methods=["POST"])
    def api_stepup_code():
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        if public():
            return jsonify(error="This site asks for your passkey."), 400
        ip, _ = client()
        if throttle.locked(ip, name):
            return jsonify(error="Too many wrong codes. Wait a few minutes."), 429
        code = re.sub(r"\s+", "", str(_json().get("code") or ""))[:12]
        if not code:                                   # nothing typed: not an attempt, nothing counted
            return jsonify(error="Type the code from your authenticator app."), 400
        with users.lock:
            users._load()
            uu = users.data["users"].get(name) or {}
            stp = totp_check(uu.get("totp"), code, uu.get("totp_last"))
            if stp is not None:
                uu["totp_last"] = stp               # each code works once, also across sign-in and step-up
                users.save()
        if stp is None:
            throttle.failed(ip, name)
            audit.add("stepup_failed", user=name, detail="wrong or reused authenticator code")
            return jsonify(error="Wrong or already used code."), 401
        throttle.ok(ip, name)
        t = target()
        audit.add("stepup_ok", user=name, target=t[1], detail="authenticator code")
        return jsonify(finish(t))

    @app.route("/api/stepup/passkey/options", methods=["POST"])
    def api_stepup_passkey_options():
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        rp, why = passkeys.rp_of(request.host, request.is_secure)
        if not rp:
            return jsonify(error=why), 400
        if not store.count(name):
            return jsonify(error="No passkey is registered for this account."), 400
        return jsonify(passkeys.authentication_options(store, challenges, "stepup:" + skey(), name, rp))

    @app.route("/api/stepup/passkey", methods=["POST"])
    def api_stepup_passkey():
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        ip, _ = client()
        if throttle.locked(ip, name):
            return jsonify(error="Too many failed checks. Wait a few minutes."), 429
        rp, origin = passkeys.rp_of(request.host, request.is_secure)
        if not rp:
            return jsonify(error=origin), 400
        b = _json()
        if not isinstance(b.get("credential"), dict) or not b["credential"].get("id"):
            return jsonify(error="No passkey answer was sent."), 400       # not an attempt, nothing counted
        try:
            passkeys.authenticate(store, challenges, "stepup:" + skey(), name, b.get("credential") or {}, rp, origin)
        except ValueError as e:
            throttle.failed(ip, name)
            audit.add("stepup_failed", user=name, detail=f"passkey: {(getattr(e, 'detail', '') or str(e))[:120]}")
            return jsonify(error=words(e)), 401
        throttle.ok(ip, name)
        t = target()
        audit.add("stepup_ok", user=name, target=t[1], detail="passkey")
        return jsonify(finish(t))

    # ---------------- the person's own passkeys
    @app.route("/account")
    def account_page():
        if not me():
            return redirect("/login?next=/account")
        rp, why = passkeys.rp_of(request.host, request.is_secure)
        return render_template("account.html", is_public=public(), minimum=passkeys.MIN_PUBLIC, enrol=request.args.get("enrol") == "1",
                               can=bool(rp), why="" if rp else why)

    @app.route("/api/passkeys")
    def api_passkeys():
        if not me():
            return jsonify(error="Login required"), 401
        rp, why = passkeys.rp_of(request.host, request.is_secure)
        return jsonify(passkeys=store.public_list(me()), minimum=passkeys.MIN_PUBLIC if public() else 0, public=public(),
                       can=bool(rp), why="" if rp else why,
                       enrolling=bool(public() and session_field("needs_passkeys") and store.count(me()) < passkeys.MIN_PUBLIC))

    @app.route("/api/passkeys/options", methods=["POST"])
    def api_passkeys_options():
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        rp, why = passkeys.rp_of(request.host, request.is_secure)
        if not rp:
            return jsonify(error=why), 400
        return jsonify(passkeys.registration_options(store, challenges, "reg:" + skey(), name, people_name(name), rp))

    @app.route("/api/passkeys", methods=["POST"])
    def api_passkeys_add():
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        rp, origin = passkeys.rp_of(request.host, request.is_secure)
        if not rp:
            return jsonify(error=origin), 400
        b = _json()
        enrolling = bool(public() and session_field("needs_passkeys"))     # the first two, right after signing in
        try:
            passkeys.register(store, challenges, "reg:" + skey(), name, b.get("credential") or {}, b.get("name"), rp, origin)
        except ValueError as e:
            audit.add("passkey_add_failed", user=name, detail=(getattr(e, 'detail', '') or str(e))[:160])
            return jsonify(error=words(e)), 400
        n = store.count(name)
        audit.add("passkey_added", user=name, detail=f"{n} passkey(s) now")
        if not enrolling:                   # the person's own bell says so (review 2026-11-25)
            system_alerts.note_passkey_change(os.path.dirname(store.path), name, "added", passkeys.clean_name(b.get("name"), n))
        if n >= passkeys.MIN_PUBLIC and session_field("needs_passkeys"):
            mark(needs_passkeys=False)
            audit.add("passkeys_enrolled", user=name, detail=f"{n} passkeys registered: the account is open")
        return jsonify(ok=True, passkeys=store.public_list(name))

    @app.route("/api/passkeys/<pid>/rename", methods=["POST"])
    def api_passkeys_rename(pid):
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        if not store.rename(name, pid[:16], _json().get("name")):
            return jsonify(error="No such passkey."), 404
        return jsonify(ok=True, passkeys=store.public_list(name))

    @app.route("/api/passkeys/<pid>/remove", methods=["POST"])
    def api_passkeys_remove(pid):
        name = me()
        if not name or not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        gone = next((c.get("name") or "Passkey" for c in store.of(name) if c["id"][:16] == pid[:16]), "Passkey")
        ok, why = store.remove(name, pid[:16], keep_at_least=passkeys.MIN_PUBLIC if public() else 0)
        if not ok:
            return jsonify(error=why), 400
        audit.add("passkey_removed", user=name, detail=f"{store.count(name)} passkey(s) left")
        system_alerts.note_passkey_change(os.path.dirname(store.path), name, "removed", gone)   # beside the store
        return jsonify(ok=True, passkeys=store.public_list(name))

    # ---------------- an administrator's reset (a person who lost every passkey): every time, audited
    @app.route("/api/admin/users/<name>/passkeys/reset", methods=["POST"])
    def api_passkeys_reset(name):
        who = me()
        if not who or not csrf_ok() or "users" not in (getattr(g, "user", None) or {}).get("perms", ()):
            return jsonify(error="Refused."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again first (sessions older than 12 hours can only view).", reauth=True), 403
        if name == who:
            return jsonify(error="Another administrator resets your passkeys."), 400
        if not users.get(name):
            return jsonify(error="No such account."), 404
        n = store.reset(name)
        sessions.end_user(name)
        audit.add("passkeys_reset", user=who, target=name, detail=f"{n} passkey(s) removed; the person registers new ones at their next sign-in")
        return jsonify(ok=True, removed=n)

    return {"store": store, "challenges": challenges, "rule_for": rule_for, "grants": grants}
