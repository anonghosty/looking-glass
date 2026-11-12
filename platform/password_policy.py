"""Password expiry: an administrator's policy that makes passwords expire, and a "change every password now" button.

Asked for by the user (2026-11-12). In Settings (administrators, Settings permission):
  * the policy: on or off, and how many days a password stays valid (PASSWORD_DAYS_MIN..PASSWORD_DAYS_MAX);
    switching it on makes EVERY account change its password at its next sign-in, then every N days;
  * "Require every account to change its password at next sign-in": any time, for example after a suspected leak.
Both need the administrator's own password again, and both are written to the audit log.

What a user sees (auth.py): the usual sign-in, name and password, then the authenticator code. If their password has
expired, the session is NOT opened yet: a box says the password has expired and asks for a new one (the same rules as
everywhere, and different from the expired one). Once it is saved they are taken straight to the platform, without
signing in again; their other sessions end. A password counts from when it was last set (pw_set_at on the account);
an account without that date (set before this existed) counts as expired once the policy starts.

Standards note, for the record: NIST SP 800-63B (Digital Identity Guidelines) advises against forcing periodic password
changes without a sign of compromise; many audit frameworks and regulators still ask for them. This is the
installation's choice, and it is shown as such in the Settings card.
"""
import json
import os
import threading
import time

from flask import g, jsonify, request
from werkzeug.security import check_password_hash

PASSWORD_DAYS_MIN, PASSWORD_DAYS_MAX, PASSWORD_DAYS_DEFAULT = 1, 3650, 90


class Policy:
    """data/password_policy.json: {enabled, days, enforced_at, forced_at, by, changed_at}."""

    def __init__(self, data_dir):
        self.path = os.path.join(data_dir, "password_policy.json")
        self.lock = threading.Lock()

    def get(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                d = json.load(fh)
        except (OSError, ValueError):
            d = {}
        return {"enabled": bool(d.get("enabled")), "days": int(d.get("days") or PASSWORD_DAYS_DEFAULT),
                "enforced_at": float(d.get("enforced_at") or 0), "forced_at": float(d.get("forced_at") or 0),
                "by": d.get("by", ""), "changed_at": float(d.get("changed_at") or 0)}

    def _save(self, d):
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(d, fh)
        os.replace(tmp, self.path)

    def set(self, enabled, days, by):
        """Switching on (or changing the days while on) starts the policy now: every account changes at next sign-in."""
        with self.lock:
            cur = self.get()
            now = time.time()
            start = now if enabled and not cur["enabled"] else cur["enforced_at"]
            self._save(dict(cur, enabled=bool(enabled), days=int(days), enforced_at=start, by=by, changed_at=now))
            return self.get()

    def force_all(self, by):
        with self.lock:
            cur = self.get()
            now = time.time()
            self._save(dict(cur, forced_at=now, by=by, changed_at=now))
            return self.get()

    def expired(self, account, now=None):
        """(True, why) when this account must set a new password before its session opens; (False, '') otherwise."""
        p = self.get()
        now = now or time.time()
        set_at = float((account or {}).get("pw_set_at") or 0)
        if p["forced_at"] and set_at < p["forced_at"]:
            return True, "An administrator asked every account to choose a new password."
        if p["enabled"]:
            if set_at < p["enforced_at"]:
                return True, "A password policy is now in force: every account chooses a new password once."
            if now - set_at > p["days"] * 86400:
                return True, f"Passwords last {p['days']} days here, and yours is older."
        return False, ""


def install(app, ctx):
    """ctx: policy (Policy), has_perm, csrf_ok, fresh, audit, users, throttle, client (-> (ip, ua))."""
    policy, hp, audit, users, throttle = ctx["policy"], ctx["has_perm"], ctx["audit"], ctx["users"], ctx["throttle"]

    def guard(change=False):
        if not hp("settings"):
            return jsonify(error="The password policy is for administrators (Settings permission)."), 403
        if change:
            if request.mimetype != "application/json" or not ctx["csrf_ok"]():
                return jsonify(error="Refused (the request did not come from this page)."), 403
            if not ctx["fresh"]():
                return jsonify(error="Sign in again to make changes (your session is older than 12 hours).", reauth=True), 403
        return None

    def own_password():
        """None when the signed-in administrator typed their own password; else an error response."""
        name = (getattr(g, "user", None) or {}).get("user", "")
        ip, _ = ctx["client"]()
        u = users.get(name) if name else None
        if not u or (getattr(g, "user", None) or {}).get("automation"):
            return jsonify(error="This needs a signed-in administrator's own password."), 403
        if throttle.locked(ip, name):
            return jsonify(error="Too many wrong passwords. Try again in 15 minutes."), 429
        pw = str((request.get_json(silent=True) or {}).get("password") or "")
        if not (u.get("hash") and check_password_hash(u["hash"], pw)):
            throttle.failed(ip, name)
            audit.add("password_policy_refused", user=name, detail="wrong password")
            return jsonify(error="That password is not right."), 403
        return None

    def view():
        p = policy.get()
        when = lambda t: time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(t)) if t else ""
        accounts = [u for n, u in users.all().items() if u.get("status") == "active" and not n.startswith("lg-selftest-")]
        due = sum(1 for u in accounts if policy.expired(u)[0])
        return {"enabled": p["enabled"], "days": p["days"], "since": when(p["enforced_at"]), "forced": when(p["forced_at"]),
                "by": p["by"], "accounts": len(accounts), "due": due,
                "min": PASSWORD_DAYS_MIN, "max": PASSWORD_DAYS_MAX}

    @app.route("/api/password-policy")
    def api_password_policy():
        bad = guard()
        return bad or jsonify(view())

    @app.route("/api/password-policy", methods=["POST"])
    def api_password_policy_save():
        bad = guard(change=True) or own_password()
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        enabled = bool(b.get("enabled"))
        try:
            days = int(b.get("days"))
        except (TypeError, ValueError):
            days = 0
        if not PASSWORD_DAYS_MIN <= days <= PASSWORD_DAYS_MAX:
            return jsonify(error=f"Days: a whole number from {PASSWORD_DAYS_MIN} to {PASSWORD_DAYS_MAX:,}."), 400
        before = policy.get()
        policy.set(enabled, days, g.user.get("user", ""))
        started = enabled and not before["enabled"]
        audit.add("password_policy_changed", user=g.user.get("user", ""),
                  detail=(f"on, passwords last {days} days" if enabled else "off") + (" — every account changes its password at its next sign-in" if started else "")
                  + f" (was {'on, ' + str(before['days']) + ' days' if before['enabled'] else 'off'})")
        return jsonify(ok=True, **view())

    @app.route("/api/password-policy/force", methods=["POST"])
    def api_password_policy_force():
        bad = guard(change=True) or own_password()
        if bad:
            return bad
        policy.force_all(g.user.get("user", ""))
        audit.add("password_change_forced", user=g.user.get("user", ""),
                  detail="every account must choose a new password at its next sign-in")
        return jsonify(ok=True, **view())

    return {"policy": policy}
