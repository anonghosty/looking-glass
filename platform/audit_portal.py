"""The Audit portal's data (/audit, 2026-11-11): what an IT auditor (for example a CISA-certified one) asks for.

Every answer is read only and needs the 'audit' permission: the auditor role (fixed, auth.AUDITOR_ROLE) and the
administrators have it. Nothing here changes anything, and nothing here shows platform data (no infected host, no
constituency address): the audit log is about the people who use Looking Glass.

GET /api/audit/events     the log by tab (authentication, accounts and access, sessions, configuration changes, data
                          access and exports, workflow, system and self-test), for a period, searchable, paged
GET /api/audit/overview   the dashboard for a period: key figures, sign-ins per day, activity by hour, privileged
                          changes, exports by person, failed sign-ins by address, and the control checks
GET /api/audit/access     the access review: every account, its role and permissions, authenticator, last sign-in,
                          who approved it, and what needs attention (no authenticator, dormant, pending, every permission)
GET /api/audit/verify     the log's integrity (audit_chain.py): the chain from the first entry to the newest
GET /api/audit/export.csv the period's events as CSV (formula-safe)
GET /api/audit/report.pdf the evidence report: period, figures, control checks, integrity and its head hash, accounts
Every export and every integrity check is itself in the audit log (who, when, which period).

The thresholds are in .env, so each CSIRT sets its own: AUDIT_DORMANT_DAYS (90), AUDIT_MAX_ADMINS (3),
AUDIT_PENDING_DAYS (7), AUDIT_WORK_HOURS (07-19, UTC), and the retention in audit_chain.py.
"""
import collections
import io
import json
import os
import re
import time
from datetime import datetime, timedelta, timezone

from flask import Response, g, jsonify, render_template, request

import csvsafe

TABS = [("auth", "Authentication"), ("accounts", "Accounts and access"), ("sessions", "Sessions"),
        ("config", "Configuration changes"), ("data", "Data access and exports"), ("workflow", "Workflow"),
        ("system", "System and self-test")]
TAB_OF = {}
for _tab, _events in {
    "auth": ("login", "login_failed", "login_locked", "login_refused", "logout", "mfa_enrolled", "recovery_code_used",
             "reset_requested", "reset_failed", "password_reset", "setup_code_wrong", "register_limited"),
    "accounts": ("registered", "user_approve", "user_role", "user_revoke", "user_restore", "user_reset_mfa", "user_delete",
                 "user_allow_reset", "roles_changed"),
    "sessions": ("kicked", "session_misuse", "user_kick"),
    "config": ("settings_changed", "networks_identify", "network_edited", "network_type_added", "definition_saved",
               "peace_of_mind", "organisation_set"),
    "data": ("report_pdf", "combo_export", "advisory_download", "advisory_export", "advisory_report", "audit_export"),
    "workflow": ("finding_created", "finding_status", "finding_decision", "finding_reply", "finding_review_decision",
                 "combo_review_sent", "advisory_saved", "advisory_drafted", "advisory_sent", "note_added", "note_removed",
                 "analyst_code", "combo_code"),
    "system": ("selftest_counters_reset", "audit_verified"),
}.items():
    for _e in _events:
        TAB_OF[_e] = _tab
LABEL = {"login": "Signed in", "login_failed": "Failed sign-in", "login_locked": "Locked out", "login_refused": "Sign-in refused",
         "logout": "Signed out", "registered": "Account registered", "mfa_enrolled": "Authenticator set up",
         "recovery_code_used": "Recovery code used", "session_misuse": "Session misuse", "kicked": "Session ended by an admin",
         "user_kick": "Sessions ended by an admin", "user_approve": "Account approved", "user_role": "Role changed",
         "user_revoke": "Account revoked", "user_restore": "Account restored", "user_reset_mfa": "Authenticator reset",
         "user_delete": "Account deleted", "user_allow_reset": "Password reset allowed", "roles_changed": "Role permissions changed",
         "settings_changed": "Settings changed", "register_limited": "Registration limit reached",
         "setup_code_wrong": "Wrong setup code (first administrator)", "reset_requested": "Password reset requested",
         "reset_failed": "Password reset failed", "password_reset": "Password reset", "networks_identify": "Networks identified",
         "network_edited": "Network name edited", "network_type_added": "Network type added", "definition_saved": "Definition saved",
         "note_added": "Note added", "note_removed": "Note removed", "report_pdf": "Report downloaded",
         "finding_created": "Finding opened", "finding_status": "Finding moved", "finding_decision": "Finding decided",
         "finding_reply": "Finding replied to", "finding_review_decision": "Review decided", "combo_review_sent": "Sent to management",
         "combo_export": "Combination report", "advisory_saved": "Advisory saved", "advisory_report": "Advisory report generated",
         "advisory_drafted": "Advisory drafted", "advisory_sent": "Advisory sent", "advisory_export": "Advisory exported",
         "advisory_download": "Advisory report downloaded", "organisation_set": "Organisation set", "peace_of_mind": "Peace of mind",
         "analyst_code": "Analyst code made", "combo_code": "Combination code made",
         "selftest_counters_reset": "Self-test cleared its sign-in counters", "audit_export": "Audit evidence exported",
         "audit_verified": "Audit log integrity checked"}
ALERT = re.compile(r"failed|locked|misuse|refused|revoke|delete|limited|wrong")
PRIVILEGED = {"user_role", "roles_changed", "user_approve", "user_revoke", "user_restore", "user_delete", "user_reset_mfa",
              "user_allow_reset", "settings_changed", "peace_of_mind", "kicked", "user_kick"}
MAX_DAYS = 800


def _num(name, default):
    try:
        return int(float(os.environ.get(name, "") or default))
    except ValueError:
        return default


def _day(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d") if t else ""


def _when(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if t else ""


def install(app, ctx):
    """ctx: has_perm, users (auth.Users), roles (auth.Roles), sessions, audit (auth.Audit), people (People),
    perms_catalog (auth.PERMS), auditor_role, tls(), access_mode()."""
    hp, users, roles, sessions, audit, people = (ctx[k] for k in ("has_perm", "users", "roles", "sessions", "audit", "people"))
    work = os.environ.get("AUDIT_WORK_HOURS", "07-19")
    try:
        WORK_FROM, WORK_TO = (int(x) for x in work.split("-", 1))
    except ValueError:
        WORK_FROM, WORK_TO = 7, 19
    DORMANT, MAX_ADMINS, PENDING_DAYS = _num("AUDIT_DORMANT_DAYS", 90), _num("AUDIT_MAX_ADMINS", 3), _num("AUDIT_PENDING_DAYS", 7)
    verified = {"at": 0.0, "v": None}

    def allowed():
        return hp("audit")

    def deny():
        return jsonify(error="The Audit portal is for the auditor role and administrators (permission 'audit')."), 403

    def period():
        """(t0, t1, from, to) for ?from=YYYY-MM-DD&to=YYYY-MM-DD (UTC, both days included); default the last 30 days."""
        today = datetime.now(timezone.utc).date()
        def d(v, dflt):
            try:
                return datetime.strptime(str(v or "")[:10], "%Y-%m-%d").date()
            except ValueError:
                return dflt
        to = d(request.args.get("to"), today)
        fr = d(request.args.get("from"), to - timedelta(days=29))
        fr, to = min(fr, to), max(fr, to)
        fr = max(fr, to - timedelta(days=MAX_DAYS))
        t0 = datetime(fr.year, fr.month, fr.day, tzinfo=timezone.utc).timestamp()
        t1 = datetime(to.year, to.month, to.day, tzinfo=timezone.utc).timestamp() + 86400
        return t0, t1, fr.isoformat(), to.isoformat()

    def shaped(r):
        """One entry as the portal shows it: its tab, readable event, people by name, self-test and alert marks."""
        e = r.get("event", "")
        st = audit.is_selftest(r) or r.get("user") == "automation"
        out = {"t": r.get("t"), "when": _when(r.get("t")), "event": e, "label": LABEL.get(e, e.replace("_", " ").capitalize()),
               "tab": "system" if st else TAB_OF.get(e, "system"), "user": r.get("user", ""), "target": r.get("target", ""),
               "user_label": people.audit(r.get("user", "")), "target_label": people.audit(r.get("target", "")),
               "ip": r.get("ip", ""), "location": r.get("location", ""), "ua": r.get("ua", ""), "detail": r.get("detail", ""),
               "selftest": st, "alert": bool(ALERT.search(e)), "privileged": e in PRIVILEGED, "chained": "prev" in r}
        return out

    def rows_in(t0, t1):
        return [shaped(r) for r in audit.records() if t0 <= (r.get("t") or 0) < t1]

    # ------------------------------------------------------------------ the page
    @app.route("/audit")
    def audit_portal_page():
        if not allowed():
            return render_template("denied.html", message="The Audit portal is for the auditor role and administrators (permission 'audit')."), 403
        return render_template("audit.html", tabs=TABS, can_end="users" in (g.user or {}).get("perms", ()))

    # ------------------------------------------------------------------ the log by tab
    @app.route("/api/audit/events")
    def api_audit_events():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        tab = request.args.get("tab") or "all"
        q = (request.args.get("q") or "").strip().lower()[:100]
        show_st = request.args.get("selftests") == "1"
        rows = rows_in(t0, t1)
        # the System and self-test tab counts the self-test's events (they are what it shows); the others leave them out
        counts = collections.Counter(r["tab"] for r in rows if show_st or not r["selftest"] or r["tab"] == "system")
        if tab != "all":
            rows = [r for r in rows if r["tab"] == tab]
        if tab != "system" and not show_st:
            rows = [r for r in rows if not r["selftest"]]
        if request.args.get("alerts") == "1":
            rows = [r for r in rows if r["alert"]]
        if q:
            rows = [r for r in rows if q in json.dumps(r, ensure_ascii=False).lower()]
        rows.reverse()                                     # newest first
        try:
            limit = max(1, min(int(request.args.get("limit", 200)), 1000)); offset = max(0, int(request.args.get("offset", 0)))
        except ValueError:
            limit, offset = 200, 0
        return jsonify(rows=rows[offset:offset + limit], total=len(rows), counts=dict(counts), period={"from": fr, "to": to},
                       tabs=[{"key": k, "label": v} for k, v in TABS])

    # ------------------------------------------------------------------ the access review
    def access_rows():
        now = time.time()
        live = collections.Counter(s["user"] for s in sessions.list())
        out = []
        for n, u in sorted(users.all().items()):
            if n.startswith("lg-selftest-"):
                continue
            role = u.get("role", "external")
            perms = sorted(roles.perms(role))
            last = (u.get("last_login") or {}).get("at") or 0
            created = u.get("created") or (u.get("registered") or {}).get("at") or 0
            status = u.get("status", "active")
            since = last or created
            flags = []
            if status == "active" and not u.get("totp"):
                flags.append("no authenticator")
            if status == "active" and since and now - since > DORMANT * 86400:
                flags.append(f"no sign-in for {int((now - since) // 86400)} days")
            if status == "pending" and created and now - created > PENDING_DAYS * 86400:
                flags.append(f"pending for {int((now - created) // 86400)} days")
            if role == "admin":
                flags.append("every permission")
            out.append({"name": n, "full_name": ((u.get("profile") or {}).get("full_name") or ""), "organisation": ((u.get("profile") or {}).get("organisation") or ""),
                        "role": role, "permissions": perms, "status": status, "mfa": bool(u.get("totp")),
                        "recovery_left": len(u.get("recovery") or []), "created": _day(created), "approved_by": people.audit(u.get("approved_by", "")),
                        "approved_at": _day(u.get("approved_at")), "last_login": _when(last), "last_login_location": (u.get("last_login") or {}).get("location", ""),
                        "days_since_login": int((now - last) // 86400) if last else None, "sessions": live.get(n, 0), "flags": flags})
        return out

    @app.route("/api/audit/access")
    def api_audit_access():
        if not allowed():
            return deny()
        rows = access_rows()
        rmap = {r: sorted(roles.perms(r)) for r in roles.roles}
        return jsonify(accounts=rows, roles=[{"role": r, "permissions": p, "accounts": sum(1 for a in rows if a["role"] == r),
                                               "fixed": r in ("admin", "management", ctx["auditor_role"])} for r, p in sorted(rmap.items())],
                       perms=ctx["perms_catalog"], thresholds={"dormant_days": DORMANT, "max_admins": MAX_ADMINS, "pending_days": PENDING_DAYS})

    # ------------------------------------------------------------------ integrity
    def integrity(fresh=False):
        if fresh or not verified["v"] or time.time() - verified["at"] > 60:
            verified.update(at=time.time(), v=audit.chain.verify())
        return verified["v"]

    @app.route("/api/audit/verify")
    def api_audit_verify():
        if not allowed():
            return deny()
        v = integrity(fresh=True)
        audit.add("audit_verified", user=(g.user or {}).get("user", ""), detail=("chain whole" if v["ok"] else f"BROKEN at entry {v['break']['entry']}")
                  + f" · {v['entries']} entries · head {v['head'][:16]}")
        return jsonify(dict(v, first=_when(v["first"]), last=_when(v["last"]), checked=_when(time.time())))

    # ------------------------------------------------------------------ the dashboard and the control checks
    def overview(t0, t1):
        rows = [r for r in rows_in(t0, t1) if not r["selftest"]]
        by = collections.Counter(r["event"] for r in rows)
        days, d = [], datetime.fromtimestamp(t0, timezone.utc).date()
        end = datetime.fromtimestamp(t1 - 1, timezone.utc).date()
        while d <= end:
            days.append(d.isoformat()); d += timedelta(days=1)
        per_day = {x: {"ok": 0, "failed": 0, "locked": 0, "changes": 0, "exports": 0} for x in days}
        hours = [0] * 24
        fail_ip, export_by, active_users = collections.Counter(), collections.Counter(), set()
        after_hours = []
        for r in rows:
            day, h = _day(r["t"]), datetime.fromtimestamp(r["t"], timezone.utc).hour
            slot = per_day.get(day)
            e = r["event"]
            if e == "login":
                hours[h] += 1
                active_users.add(r["user"])
                if not (WORK_FROM <= h < WORK_TO):
                    after_hours.append(r)
            if slot:
                if e == "login":
                    slot["ok"] += 1
                elif e in ("login_failed", "login_refused"):
                    slot["failed"] += 1
                elif e == "login_locked":
                    slot["locked"] += 1
                if e in PRIVILEGED:
                    slot["changes"] += 1
                if r["tab"] == "data":
                    slot["exports"] += 1
            if e in ("login_failed", "login_refused", "login_locked"):
                fail_ip[(r["ip"], r["location"])] += 1
            if r["tab"] == "data":
                export_by[r["user_label"] or r["user"]] += 1
        ok_n, fail_n = by["login"], by["login_failed"] + by["login_refused"]
        tabs = collections.Counter(r["tab"] for r in rows)
        priv = [r for r in rows if r["privileged"]][-15:][::-1]
        return {"kpis": {"events": len(rows), "signins": ok_n, "failed": fail_n, "failure_rate": round(100 * fail_n / max(1, ok_n + fail_n), 1),
                         "lockouts": by["login_locked"], "privileged": sum(by[e] for e in PRIVILEGED), "exports": tabs["data"],
                         "people": len(active_users), "after_hours": len(after_hours), "misuse": by["session_misuse"],
                         "account_changes": tabs["accounts"], "config_changes": tabs["config"]},
                "per_day": [dict(day=x, **per_day[x]) for x in days], "hours": hours, "work_hours": [WORK_FROM, WORK_TO],
                "tabs": [{"key": k, "label": v, "n": tabs[k]} for k, v in TABS if k != "system"],
                "fail_sources": [{"ip": ip, "location": loc, "n": n} for (ip, loc), n in fail_ip.most_common(8)],
                "exports_by": [{"who": w, "n": n} for w, n in export_by.most_common(8)],
                "privileged_recent": priv, "after_hours_recent": after_hours[-8:][::-1]}

    def checks(t0, t1, ov=None):
        acc = access_rows()
        active = [a for a in acc if a["status"] == "active"]
        admins = [a for a in active if a["role"] == "admin"]
        no_mfa = [a for a in active if not a["mfa"]]
        dormant = [a for a in active if any(f.startswith("no sign-in") for f in a["flags"])]
        pending = [a for a in acc if any(f.startswith("pending") for f in a["flags"])]
        v = integrity()
        oldest = v.get("first") or 0
        ov = ov or overview(t0, t1)
        k = ov["kpis"]
        fixed = sorted(roles.perms(ctx["auditor_role"])) == ["audit"]
        tls = ctx["tls"]()
        names = lambda xs: ", ".join(people.audit(a["name"]) for a in xs[:8]) + (f" and {len(xs) - 8} more" if len(xs) > 8 else "")
        c = [
            ("Access control", "AC-1", "Every active account signs in with an authenticator (two factors)", not no_mfa,
             f"{len(active)} active accounts, all with an authenticator." if not no_mfa else f"Without an authenticator: {names(no_mfa)}."),
            ("Access control", "AC-2", f"No active account unused for {DORMANT} days or more", not dormant,
             "None." if not dormant else f"Dormant: {names(dormant)}. Review whether they still need access."),
            ("Access control", "AC-3", f"Administrators (every permission) kept to {MAX_ADMINS} or fewer", len(admins) <= MAX_ADMINS,
             f"{len(admins)} administrator(s): {names(admins) or 'none'}."),
            ("Access control", "AC-4", f"No registration waiting for approval longer than {PENDING_DAYS} days", not pending,
             "None." if not pending else f"Waiting: {names(pending)}."),
            ("Access control", "AC-5", "The auditor role is fixed to read-only audit access", fixed,
             "auditor = audit only; no one can change it." if fixed else "The auditor role does not have exactly 'audit'."),
            ("Authentication", "IA-1", "Failed sign-ins in the period", k["failed"] == 0 or k["failure_rate"] < 20,
             f"{k['failed']} failed of {k['signins'] + k['failed']} attempts ({k['failure_rate']} %), {k['lockouts']} lockout(s)."),
            ("Authentication", "IA-2", "No session misuse (a session cookie used from another address or browser)", k["misuse"] == 0,
             f"{k['misuse']} event(s) in the period."),
            ("Change management", "CM-1", "Every privileged change is logged with who, when and what",
             True, f"{k['privileged']} privileged change(s) in the period, each with its author, time and detail."),
            ("Logging and monitoring", "AU-1", "The audit log is unbroken (tamper-evident chain)", v["ok"],
             (f"{v['entries']} entries, chain whole" + (f"; {v['before_chain']} written before the chain started" if v["before_chain"] else "") + ".")
             if v["ok"] else f"Broken at entry {v['break']['entry']}: {v['break']['what']}."),
            ("Logging and monitoring", "AU-2", "The log covers the whole period (retention)", bool(oldest) and oldest <= t0,
             f"Oldest entry kept: {_when(oldest) or 'none'}; retention {v['retention_days']} days." ),
            ("Logging and monitoring", "AU-3", "Times are recorded in UTC by the server", True, "Every entry carries a UTC time stamp set by the server."),
            ("Data protection", "DP-1", "Sign-ins and sessions are encrypted (HTTPS)", tls,
             "HTTPS is on." if tls else "HTTPS is off: passwords and session cookies travel in clear on the network."),
            ("Data protection", "DP-2", "Data exports are logged per person", True, f"{k['exports']} export(s) in the period, each with who and what."),
        ]
        return [{"area": a, "id": i, "control": t, "ok": bool(ok), "evidence": e} for a, i, t, ok, e in c]

    @app.route("/api/audit/overview")
    def api_audit_overview():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        ov = overview(t0, t1)
        v = integrity()
        return jsonify(period={"from": fr, "to": to}, checks=checks(t0, t1, ov),
                       integrity=dict(v, first=_when(v["first"]), last=_when(v["last"])), access_mode=ctx["access_mode"](), **ov)

    # ------------------------------------------------------------------ evidence exports
    def logged_export(kind, fr, to, extra=""):
        audit.add("audit_export", user=(g.user or {}).get("user", ""), target=kind, detail=f"{fr} to {to}{extra}")

    @app.route("/api/audit/export.csv")
    def api_audit_export_csv():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        tab = request.args.get("tab") or "all"
        rows = rows_in(t0, t1)
        if tab != "all":
            rows = [r for r in rows if r["tab"] == tab]
        buf = io.StringIO()
        w = csvsafe.writer(buf)                        # every cell formula-safe
        w.writerow(["time_utc", "tab", "event", "by", "account", "address", "location", "browser", "detail", "self_test", "chained"])
        for r in rows:
            w.writerow([r["when"], r["tab"], r["label"], r["user_label"], r["target_label"], r["ip"], r["location"],
                        r["ua"], r["detail"], "yes" if r["selftest"] else "", "yes" if r["chained"] else "no"])
        logged_export("csv", fr, to, f" · {tab} · {len(rows)} entries")
        data = buf.getvalue().encode("utf-8-sig")
        return Response(data, mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="audit_{tab}_{fr}_{to}.csv"',
                                                             "Cache-Control": "no-store"})

    @app.route("/api/audit/report.pdf")
    def api_audit_report_pdf():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        import audit_report
        ov = overview(t0, t1)
        pdf = audit_report.build({"from": fr, "to": to, "generated": _when(time.time()),
                                  "by": people.audit((g.user or {}).get("user", "")), "kpis": ov["kpis"], "checks": checks(t0, t1, ov),
                                  "integrity": dict(integrity(fresh=True)), "accounts": access_rows(), "privileged": ov["privileged_recent"],
                                  "fail_sources": ov["fail_sources"], "exports_by": ov["exports_by"], "per_day": ov["per_day"],
                                  "first": _when(integrity()["first"]), "last": _when(integrity()["last"])})
        logged_export("pdf", fr, to, " · evidence report")
        return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="audit_evidence_{fr}_{to}.pdf"',
                                                                  "Cache-Control": "no-store"})
