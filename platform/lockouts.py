"""Locked sign-ins, for admins (2026-11-14): one office or partner behind a single public address can lock itself out
(20 failures from one address in an hour lock the address), and the locks were invisible until they ran out.

  GET  /api/admin/lockouts          what is locked now: account (one name from one address) or address, failures, until
  POST /api/admin/lockouts/unlock   {ip, name?}: lift one account's lock from that address, or the whole address

Needs the 'users' permission; lifting also the CSRF token and a fresh sign-in, and is written to the audit log
(login_unlocked: who lifted which lock). The limits themselves are in .env (auth.Throttle).
"""
import ipaddress
import time

from flask import abort, g, jsonify, make_response, request


def install(app, ctx):
    """ctx: throttle (auth.Throttle), audit, has_perm, csrf_ok, fresh."""
    throttle, audit, has_perm = ctx["throttle"], ctx["audit"], ctx["has_perm"]

    def _limits():
        return {"account_fails": throttle.account_fails, "account_minutes": throttle.account_window // 60,
                "address_fails": throttle.address_fails, "address_minutes": throttle.address_window // 60}

    @app.route("/api/admin/lockouts")
    def api_admin_lockouts():
        if not has_perm("users"):
            return jsonify(error="Locked sign-ins are for accounts with the 'users' permission."), 403
        now = time.time()
        rows = [dict(r, minutes_left=max(1, round((r["until"] - now) / 60))) for r in throttle.lockouts()]
        return jsonify(locked=rows, limits=_limits())

    @app.route("/api/admin/lockouts/unlock", methods=["POST"])
    def api_admin_lockouts_unlock():
        if not has_perm("users"):
            return jsonify(error="Lifting a lock needs the 'users' permission."), 403
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            abort(403)
        if not ctx["fresh"]():
            abort(make_response(jsonify(error="For your security, sign out and sign in again to make changes.", reauth=True), 403))
        d = request.get_json(silent=True) or {}
        ip, name = d.get("ip"), d.get("name") or None
        try:
            ip = str(ipaddress.ip_address(ip if isinstance(ip, str) else ""))
        except ValueError:
            return jsonify(error="Not an address."), 400
        if name is not None and (not isinstance(name, str) or not 0 < len(name) <= 64):
            return jsonify(error="Not an account name."), 400
        n = throttle.unlock(ip, name)
        who = (getattr(g, "user", None) or {}).get("user", "")
        audit.add("login_unlocked", user=who, target=name or ip,
                  detail=(f"account {name} from {ip}" if name else f"address {ip} (every account tried from it)")
                  + f" · {n} counter(s) cleared")
        return jsonify(ok=True, cleared=n, locked=throttle.lockouts())
