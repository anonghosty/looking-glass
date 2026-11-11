"""Lets the security self-test start with clean login counters without restarting the service.

security_testing/security_retest.py fails logins on purpose (to check the locks), and the counters are kept in the
service's memory for an hour, so a second run would be refused. It used to restart the service first, which left
the platform unreachable for a few seconds every run (seen 2026-11-11). Now it asks for this instead:

  POST /api/selftest/reset-login-counters   with the automation key (X-LG-Automation, data/automation.key)

Only the automation key is accepted, and auth.py accepts that key only from this computer. Only this computer's own
loopback addresses are cleared (where the self-test logs in from): the counters of every other address stay, so it
can never unlock someone guessing passwords from elsewhere. Every use is in the audit log.
"""
from flask import g, jsonify

LOOPBACK = ("127.0.0.1", "::1")


def install(app, ctx):
    """ctx: throttle (auth.Throttle), audit."""
    throttle, audit = ctx["throttle"], ctx["audit"]

    @app.route("/api/selftest/reset-login-counters", methods=["POST"])
    def selftest_reset_login_counters():
        u = getattr(g, "user", None) or {}
        if not u.get("automation"):                       # the key, from this computer (auth.py); no account can
            return jsonify(error="Only the self-test on this computer (automation key) may do this."), 403
        n = sum(throttle.clear_address(ip) for ip in LOOPBACK)
        audit.add("selftest_counters_reset", user="automation", detail=f"login counters of this computer cleared ({n})")
        return jsonify(ok=True, cleared=n, addresses=list(LOOPBACK))
