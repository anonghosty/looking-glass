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

The thresholds are in .env, so each CSIRT sets its own: AUDIT_DORMANT_DAYS (45, CIS's figure), AUDIT_MAX_ADMINS (3),
AUDIT_PENDING_DAYS (7), AUDIT_WORK_HOURS (07-19, UTC), and the retention in audit_chain.py.
"""
import collections
import io
import json
import os
import re
import time
from datetime import date, datetime, timedelta, timezone

from flask import Response, g, jsonify, render_template, request

import control_map
import csvsafe
import data_access

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
    "data": ("report_pdf", "combo_export", "advisory_download", "advisory_export", "advisory_report", "audit_export",
             "data_exported", "data_viewed"),
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
LABEL["data_viewed"] = "Host-level data viewed"          # data_access.py (CIS 3.14)
LABEL["data_exported"] = "Host list downloaded"
LABEL["audit_sealed"] = "Entries before the chain sealed"
TAB_OF["audit_sealed"] = "system"
LABEL["audit_archive_removed"] = "Old audit archive removed by the retention"
TAB_OF["audit_archive_removed"] = "system"
LABEL["audit_archive_deleted_early"] = "Audit archive deleted BEFORE its retention ended"   # an alert (ALERT: "delete")
TAB_OF["audit_archive_deleted_early"] = "system"
LABEL["audit_archived"] = "Audit log archived (rotation recorded)"
TAB_OF["audit_archived"] = "system"
LABEL["audit_retention_set"] = "Audit log retention setting recorded"
TAB_OF["audit_retention_set"] = "config"
# Settings → Workers (pipeline_settings.py) and the sender check's releases (2026-11-12)
for _e, _l in (("pipeline_unlock", "Workers settings unlocked (password)"),
               ("pipeline_unlock_failed", "Workers settings: wrong password"),
               ("pipeline_settings_saved", "Workers (pipeline) settings changed"),
               ("pipeline_apikey_saved", "Shadowserver API key saved"),
               ("pipeline_apikey_checked", "Shadowserver API key checked"),
               ("sender_release", "Held-back report released"),
               ("pipeline_change_requested", "Workers (pipeline) change requested"),
               ("pipeline_request_applied", "Workers change applied by the pipeline"),
               ("pipeline_request_refused", "Workers change refused by the pipeline")):
    LABEL[_e], TAB_OF[_e] = _l, "config"
# the password policy (password_policy.py) and expired passwords at sign-in (2026-11-12)
for _e, _l, _t in (("password_policy_changed", "Password policy changed", "config"),
                   ("password_change_forced", "Every account must choose a new password", "config"),
                   ("password_policy_refused", "Password policy: wrong password", "config"),
                   ("password_expired", "Password expired at sign-in", "auth"),
                   ("password_changed", "New password after expiry", "auth")):
    LABEL[_e], TAB_OF[_e] = _l, _t
# The NIST SP 800-53 Rev. 5 controls the checks support, with their official titles (Release 5.2.0, read from NIST's
# OSCAL catalog, usnistgov/oscal-content, on 2026-11-11). The checks' own ids are LG-01…: they are Looking Glass checks,
# mapped to NIST controls, not NIST control numbers themselves.
NIST_RELEASE = "NIST SP 800-53 Rev. 5, Release 5.2.0"
NIST = {"AC-2": "Account Management", "AC-2(3)": "Disable Accounts", "AC-2(7)": "Privileged User Accounts",
        "AC-5": "Separation of Duties", "AC-6(5)": "Privileged Accounts", "AC-6(9)": "Log Use of Privileged Functions",
        "AC-7": "Unsuccessful Logon Attempts", "AC-12": "Session Termination", "AU-2": "Event Logging",
        "AU-3": "Content of Audit Records", "AU-6": "Audit Record Review, Analysis, and Reporting", "AU-8": "Time Stamps",
        "AU-9": "Protection of Audit Information", "AU-9(3)": "Cryptographic Protection",
        "AU-9(4)": "Access by Subset of Privileged Users", "AU-11": "Audit Record Retention", "AU-12": "Audit Record Generation",
        "IA-2(1)": "Multi-factor Authentication to Privileged Accounts",
        "IA-2(2)": "Multi-factor Authentication to Non-privileged Accounts", "SC-8": "Transmission Confidentiality and Integrity",
        "SC-8(1)": "Cryptographic Protection", "SC-23": "Session Authenticity"}
ALERT = re.compile(r"failed|locked|misuse|refused|revoke|delete|limited|wrong")
PRIVILEGED = {"user_role", "roles_changed", "user_approve", "user_revoke", "user_restore", "user_delete", "user_reset_mfa",
              "user_allow_reset", "settings_changed", "peace_of_mind", "kicked", "user_kick",
              "pipeline_unlock", "pipeline_settings_saved", "pipeline_apikey_saved", "sender_release",
              "pipeline_change_requested", "pipeline_request_applied", "password_policy_changed", "password_change_forced"}
MAX_DAYS = 800


def pretty(event, detail):
    """An entry's detail as a sentence for the page and the report (the CSV keeps the text as it was logged too)."""
    d = str(detail or "").strip()
    if event == "user_role":
        m = re.fullmatch(r"(\S+)\s*->\s*(\S+)", d)
        return f"Role changed from {m.group(1)} to {m.group(2)}" if m else d.replace("->", "to")
    if event == "user_approve":
        m = re.fullmatch(r"role (\S+)", d)
        return f"Approved with the role {m.group(1)}" if m else d
    if event == "settings_changed":
        m = re.fullmatch(r"country (\S+), (\d+) networks, (\d+) ranges", d)
        if m:
            n, r = int(m.group(2)), int(m.group(3))
            scope = "the whole country" if not n and not r else f"{n} network{'s' if n != 1 else ''} and {r} address range{'s' if r != 1 else ''}"
            return f"Country set to {m.group(1)}; constituency: {scope}"
        return d
    if event == "roles_changed":
        try:
            ch = json.loads(d) if d.startswith("{") else None
        except ValueError:
            ch = None
        if ch is not None:
            return "; ".join(f"{r} now: {', '.join(ps) or 'no permission'}" for r, ps in ch.items()) or "Saved without changes"
    if event == "peace_of_mind":
        return {"off": "Turned off"}.get(d, "Turned on: Admin, the Audit portal, Settings and the Overview only" if d.startswith("on") else d)
    return d.replace(" -> ", " to ")


def fmt(n):
    return f"{n:,}" if isinstance(n, int) else str(n)


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
    # defaults are CIS's own figures (CIS Controls v8.1 5.3: dormant accounts disabled after 45 days; 8.11: weekly
    # audit-log reviews), so the checks can back those safeguards out of the box (2026-11-13); .env still decides
    DORMANT, MAX_ADMINS, PENDING_DAYS = _num("AUDIT_DORMANT_DAYS", 45), _num("AUDIT_MAX_ADMINS", 3), _num("AUDIT_PENDING_DAYS", 7)
    FAIL_ALERT = _num("AUDIT_FAIL_ALERT", 10)
    verified = {"at": 0.0, "v": None}
    # where each control check's evidence is (the page opens that tab; "alerts" ticks Alerts only)
    VIEW = {"LG-01": {"tab": "access"}, "LG-02": {"tab": "access"}, "LG-03": {"tab": "access"}, "LG-04": {"tab": "access"},
            "LG-05": {"tab": "access"}, "LG-06": {"tab": "auth", "alerts": True}, "LG-07": {"tab": "sessions"},
            "LG-08": {"tab": "accounts"}, "LG-09": {"tab": "auth"}, "LG-10": {"tab": "evidence"}, "LG-11": {"tab": "evidence"},
            "LG-12": {"tab": "auth"}, "LG-13": {"tab": "system"}, "LG-14": None, "LG-15": {"tab": "data"}}

    def ntp_synchronised():
        """True / False from systemd (timedatectl), None when it cannot be read here."""
        try:
            import subprocess
            r = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True, text=True, timeout=3)
            v = r.stdout.strip().lower()
            return True if v == "yes" else False if v == "no" else None
        except Exception:                  # noqa: BLE001
            return None

    def last_review():
        """The newest integrity check or evidence export (an auditor's or administrator's review of the log)."""
        for r in reversed(audit.records()):
            if r.get("event") in ("audit_verified", "audit_export") and not audit.is_selftest(r):
                return {"t": r.get("t"), "by": people.audit(r.get("user", "")), "label": LABEL.get(r["event"], r["event"]).lower()}
        return None

    # the entries written before the chain started are sealed once (audit_chain.Chain.seal), the seal recorded in the chain
    try:
        new_seal = audit.chain.seal()
        if new_seal:
            audit.add("audit_sealed", user="Looking Glass", detail=f"{new_seal['entries']} entries written before the chain sealed · "
                      f"SHA-256 {new_seal['sha256']}", ip="", ua="")
    except OSError:
        pass

    # the retention setting goes into the chain at start-up when it is new or changed (audit_chain.py): every removal is
    # judged by the setting in force at that time, and every change of it is visible to an auditor
    try:
        audit.chain.record_retention_setting()
    except OSError:
        pass

    def setup_time(oldest):
        """When this installation started: its first audit entry or its first account, whichever came first."""
        made = [u.get("created") or (u.get("registered") or {}).get("at") or 0 for n, u in users.all().items() if not n.startswith("lg-selftest-")]
        made = [t for t in made if t]
        return min([t for t in (oldest, min(made) if made else 0) if t] or [0])

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
        # nothing is logged in the future: a period ending later ends today (review 2026-11-13: ?to=9999-12-31 went one
        # day past the last date Python has and answered 500)
        # …and nothing is logged before 1970: a date earlier than that starts there (re-check 2026-11-13: ?to=0001-01-01
        # went 29 days before the first date Python has)
        floor = date(1970, 1, 1)
        to = max(min(d(request.args.get("to"), today), today), floor)
        fr = max(min(d(request.args.get("from"), to - timedelta(days=29)), today), floor)
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
               "ip": r.get("ip", ""), "location": r.get("location", ""), "ua": r.get("ua", ""), "detail": pretty(e, r.get("detail", "")),
               "detail_logged": r.get("detail", ""),
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
        fail_ip_day = collections.Counter()          # (address, day): the brute-force pattern (IA-1)
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
                if r["tab"] == "data" and e != "data_viewed":          # views are counted apart (data_access.py)
                    slot["exports"] += 1
            if e in ("login_failed", "login_refused", "login_locked"):
                fail_ip[(r["ip"], r["location"])] += 1
                fail_ip_day[(r["ip"], day)] += 1
            if r["tab"] == "data" and e != "data_viewed":
                export_by[r["user_label"] or r["user"]] += 1
        ok_n, fail_n = by["login"], by["login_failed"] + by["login_refused"]
        tabs = collections.Counter(r["tab"] for r in rows)
        priv = [r for r in rows if r["privileged"]][-15:][::-1]
        return {"kpis": {"events": len(rows), "signins": ok_n, "failed": fail_n, "failure_rate": round(100 * fail_n / max(1, ok_n + fail_n), 1),
                         "lockouts": by["login_locked"], "privileged": sum(by[e] for e in PRIVILEGED),
                         "exports": tabs["data"] - by["data_viewed"], "views": by["data_viewed"],
                         "people": len(active_users), "after_hours": len(after_hours), "misuse": by["session_misuse"],
                         "account_changes": tabs["accounts"], "config_changes": tabs["config"]},
                "per_day": [dict(day=x, **per_day[x]) for x in days], "hours": hours, "work_hours": [WORK_FROM, WORK_TO],
                "tabs": [{"key": k, "label": v, "n": tabs[k]} for k, v in TABS if k != "system"],
                "fail_sources": [{"ip": ip, "location": loc, "n": n} for (ip, loc), n in fail_ip.most_common(8)],
                "exports_by": [{"who": w, "n": n} for w, n in export_by.most_common(8)],
                "worst_day": (lambda m: {"ip": m[0][0][0], "day": m[0][0][1], "n": m[0][1]} if m else None)(fail_ip_day.most_common(1)),
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
        # The checks give facts and evidence only, never a verdict: whether a control is effective is the auditor's judgement.
        # LG-06: the failures, lockouts and the most failures from one address in one day, against the configured alert level.
        worst = ov.get("worst_day")
        guess = bool(worst and worst["n"] >= FAIL_ALERT)
        ia1 = (f"{k['failed']} failed of {k['signins'] + k['failed']} attempts ({k['failure_rate']} %), {k['lockouts']} lockout(s); "
               + (f"most from one address in a day: {worst['n']} ({worst['ip']}, {worst['day']})" if worst else "no failure")
               + f". Configured alert level (AUDIT_FAIL_ALERT): {FAIL_ALERT} failures from one address in one day, "
               + ("reached in the period." if guess else "not reached in the period."))
        # AU-2: coverage from the start of the system (no entry can exist before it), and nothing removed
        started = setup_time(oldest)
        since = max(t0, started) if started else t0
        au2_ok = bool(oldest) and oldest <= since + 300 and not v["removed_archives"]
        au2 = (f"The system started on {_when(started)} ({max(0, int((time.time() - started) // 86400))} days ago); "
               if started else "") + (f"the log is complete since then: oldest entry {_when(oldest)}, nothing removed by the retention of {v['retention_days']} days."
               if au2_ok else (f"oldest entry kept {_when(oldest) or 'none'}; {v['removed_archives']} archive(s) removed by the retention of "
               f"{v['retention_days']} days, so the period is only partly covered." if v["removed_archives"] else
               f"but the oldest entry kept is from {_when(oldest) or 'none'}: entries from before it are missing (not removed by the "
               "retention; deleted outside Looking Glass, or kept by an older version that did not archive them).")) + (" The period chosen starts before the system existed." if started and t0 < started else "")
        names = lambda xs: ", ".join(people.audit(a["name"]) for a in xs[:8]) + (f" and {len(xs) - 8} more" if len(xs) > 8 else "")
        mfa_on = os.environ.get("MFA_REQUIRED", "1") != "0"
        privileged = [a for a in active if {"users", "settings"} & set(a["permissions"])]
        not_approved = [a for a in active if not a["approved_by"] and a["role"] != "admin"]
        idle, max_h = _num("SESSION_IDLE_MINUTES", 60), _num("SESSION_MAX_HOURS", 12)
        ntp = ntp_synchronised()
        seal = v.get("seal")
        review = last_review()
        REVIEW_DAYS = _num("AUDIT_REVIEW_DAYS", 7)             # CIS 8.11: weekly or more often
        reviewed = bool(review) and time.time() - review["t"] <= REVIEW_DAYS * 86400
        if seal and seal["state"] == "intact":
            sealed = (f" The {fmt(seal['entries'])} entries written before the chain started ({_when(seal['first'])} to {_when(seal['last'])}) were "
                      f"sealed on {_when(seal['sealed_at'])} (SHA-256 {seal['sha256'][:16]}…, recorded in the chain) and are unchanged since; "
                      "nothing can prove they were unchanged before the seal.")
        elif seal:
            sealed = f" The entries written before the chain were sealed on {_when(seal['sealed_at'])}; seal: {seal['state']}."
        else:
            sealed = ""
        au1 = ((f"{fmt(v['entries'])} entries; {fmt(v['chained'])} chained since the chain started, chain whole." + sealed)
               if v["ok"] else f"Broken at entry {v['break']['entry']}: {v['break']['what']}.")
        c = [
            ("Identification and authentication", "LG-01", "Multi-factor authentication is enforced for every account",
             ["IA-2(1)", "IA-2(2)"],
             ("Sign-in requires the password and a one-time code from an authenticator app (TOTP, RFC 6238) for every account, "
              "privileged or not; an account without an authenticator must set one up before its first session, and cannot be "
              "approved before it has one. " if mfa_on else "MFA_REQUIRED=0 in .env: accounts without an authenticator can sign in with a "
              "password alone. ") + (f"{len(active)} of {len(active)} active accounts have an authenticator." if not no_mfa
                                     else f"Without an authenticator: {names(no_mfa)}.")),
            ("Access control", "LG-02", f"Accounts unused for {DORMANT} days are reviewed or disabled", ["AC-2(3)"],
             "No active account unused that long." if not dormant else f"Active but unused that long: {names(dormant)}."),
            ("Access control", "LG-03", f"Privileged accounts are few (at most {MAX_ADMINS} administrators)", ["AC-6(5)", "AC-2(7)"],
             f"{len(admins)} administrator(s): {names(admins) or 'none'}. Accounts with privileged permissions (accounts or Settings): "
             f"{len(privileged)}: {names(privileged) or 'none'}."),
            ("Access control", "LG-04", "Account requests are approved by an administrator", ["AC-2"],
             (f"No request waiting longer than {PENDING_DAYS} days." if not pending else f"Waiting longer than {PENDING_DAYS} days: {names(pending)}.")
             + (" Every active account was approved by an administrator (administrators: the first one by the one-time setup code)."
                if not not_approved else f" Active without a recorded approval: {names(not_approved)}.")),
            ("Access control", "LG-05", "Auditors are separated from the duties they audit", ["AC-5", "AU-9(4)"],
             ("The auditor role holds exactly 'audit': fixed in the code, applied again at every start and every save of the roles, so "
              "no one can widen it. The Audit portal only reads (every request is a GET); the application has no function to edit or "
              "delete audit entries. Reading the log needs the 'audit' permission (auditors and administrators).") if fixed
             else "The auditor role does not hold exactly 'audit'."),
            ("Access control", "LG-06", "Unsuccessful sign-ins are limited and show no password guessing", ["AC-7"],
             "Enforced: 5 wrong attempts for an account from one address lock it for 15 minutes; 20 from one address in an hour lock "
             "the address. In the period: " + ia1),
            ("System and communications protection", "LG-07", "Sessions cannot be taken over and end on their own", ["SC-23", "AC-12"],
             f"Each session is bound to the address and browser that signed in (used elsewhere, it ends and is logged as misuse); it "
             f"ends after {idle} minutes idle and {max_h} hours in any case. Misuse events in the period: {k['misuse']}."),
            ("Audit and accountability", "LG-08", "Use of privileged functions is logged", ["AC-6(9)", "AU-12"],
             f"{k['privileged']} privileged action(s) in the period (roles, accounts, settings, sessions ended), each with who, when, "
             "from where and what. Approval of changes before they are made (CM-3) is a process outside the application."),
            ("Audit and accountability", "LG-09", "Audit records hold what an auditor needs", ["AU-3"],
             "Every entry: time (UTC), event, who, the account acted on, address, location, browser and detail."),
            ("Audit and accountability", "LG-10", "Audit records are protected against change (tamper-evident chain)", ["AU-9", "AU-9(3)"], au1),
            ("Audit and accountability", "LG-11", "Audit records are kept for the retention period", ["AU-11"], au2),
            ("Audit and accountability", "LG-12", "Time stamps come from a synchronised clock", ["AU-8"],
             "Every time stamp is set by the server in UTC. " + ("The server clock is synchronised (NTP)." if ntp is True else
             "The server clock is not synchronised (NTP)." if ntp is False else
             "The clock's synchronisation could not be read from the application (check timedatectl on the server).")),
            ("Audit and accountability", "LG-13", f"The audit log is reviewed (at least every {REVIEW_DAYS} days)", ["AU-6"],
             (f"Last review: {review['label']} by {review['by']} on {_when(review['t'])}" + ("." if reviewed else
              f", more than {REVIEW_DAYS} days ago.") if review else "No integrity check or evidence export recorded yet.")),
            ("System and communications protection", "LG-14", "Sign-ins and sessions are encrypted in transit", ["SC-8", "SC-8(1)"],
             "HTTPS is on (TLS)." if tls else "HTTPS is off: passwords and session cookies cross the network readable."),
            ("Audit and accountability", "LG-15", "Data access and exports are logged per person", ["AU-2", "AU-12"],
             f"{k['exports']} export(s) in the period (reports, CSV files, advisories, audit evidence), each with who and what. "
             + (f"Views of host-level data are logged too (one host's activity, the hosts behind a figure, a record's details, "
                f"an analysis): {k.get('views', 0)} in the period, each with who, when and what, hosts by reference, never "
                f"their address." if data_access.enabled() else
                "Views of host-level data are NOT logged on this system (DATA_ACCESS_LOG=0 in .env).")),
        ]
        # no pass or fail: the checks present the evidence, the auditor decides. LG → NIST → CIS: the CIS safeguards are
        # CIS's own mapping of the check's NIST controls (control_map.py), each with the NIST control it came through
        # what the checks found, for Looking Glass's reading of the CIS safeguards: "backed" only while the evidence meets
        # CIS's own figures on this system (control_map.BACKED; review, 2026-11-13)
        facts = {"mfa_required": mfa_on, "accounts_without_mfa": len(no_mfa), "dormant_days": DORMANT,
                 "dormant_active": len(dormant), "not_approved": len(not_approved), "retention_days": v.get("retention_days"),
                 "review_days": REVIEW_DAYS, "reviewed": reviewed, "tls": bool(tls),
                 "data_access_logged": data_access.enabled()}
        out = []
        for a, i, t, ns, e in c:
            cis, unmapped = control_map.cis_for(ns, i, facts)
            out.append({"area": a, "id": i, "control": t, "nist": [{"id": n, "title": NIST[n]} for n in ns], "evidence": e,
                        "cis": cis, "cis_unmapped": unmapped, "view": VIEW.get(i)})
        return out

    @app.route("/api/audit/overview")
    def api_audit_overview():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        ov = overview(t0, t1)
        v = integrity()
        started = setup_time(v.get("first") or 0)
        return jsonify(period={"from": fr, "to": to}, checks=checks(t0, t1, ov), started=_when(started), nist_release=NIST_RELEASE,
                       cis_release=control_map.CIS_RELEASE, cis_source=control_map.CIS_SOURCE, cis_attribution=control_map.CIS_ATTRIBUTION,
                       cis_note=control_map.CERTIFICATION_NOTE,
                       running_days=max(0, int((time.time() - started) // 86400)) if started else None,
                       integrity=dict(v, first=_when(v["first"]), last=_when(v["last"])), access_mode=ctx["access_mode"](), **ov)

    # ------------------------------------------------------------------ evidence exports
    def logged_export(kind, fr, to, extra=""):
        audit.add("audit_export", user=(g.user or {}).get("user", ""), target=kind, detail=f"{fr} to {to}{extra}")

    def csv_bytes(rows, first=None):
        """Shaped entries as CSV (UTF-8 with BOM for Excel; every cell formula-safe). first: number the rows from this
        entry number of the chain (the proof package's copy, so a row can be found in log/ and against the head)."""
        buf = io.StringIO()
        w = csvsafe.writer(buf)
        numbered = first is not None
        w.writerow((["entry"] if numbered else []) + ["time_utc", "tab", "event", "by", "account", "address", "location", "browser",
                                                       "detail", "detail_as_logged", "event_code", "self_test", "chained"])
        for i, r in enumerate(rows, first or 1):
            w.writerow(([i] if numbered else []) + [r["when"], r["tab"], r["label"], r["user_label"], r["target_label"], r["ip"],
                        r["location"], r["ua"], r["detail"], r["detail_logged"], r["event"], "yes" if r["selftest"] else "",
                        "yes" if r["chained"] else "no"])
        return buf.getvalue().encode("utf-8-sig")

    @app.route("/api/audit/export.csv")
    def api_audit_export_csv():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        tab = request.args.get("tab") or "all"
        if tab != "all" and tab not in dict(TABS):        # a known tab only: it goes into the file name (review 2026-11-13)
            return jsonify(error="Unknown tab."), 400
        rows = rows_in(t0, t1)
        if tab != "all":
            rows = [r for r in rows if r["tab"] == tab]
        logged_export("csv", fr, to, f" · {tab} · {len(rows)} entries")
        data = csv_bytes(rows)
        return Response(data, mimetype="text/csv", headers={"Content-Disposition": f'attachment; filename="audit_{tab}_{fr}_{to}.csv"',
                                                             "Cache-Control": "no-store"})

    @app.route("/api/audit/report.pdf")
    def api_audit_report_pdf():
        if not allowed():
            return deny()
        t0, t1, fr, to = period()
        import audit_report
        integrity(fresh=True)                          # one integrity result for the whole report (checks and section)
        ov = overview(t0, t1)
        pdf = audit_report.build({"from": fr, "to": to, "generated": _when(time.time()),
                                  "by": people.audit((g.user or {}).get("user", "")), "kpis": ov["kpis"], "checks": checks(t0, t1, ov),
                                  "integrity": dict(integrity()), "accounts": access_rows(), "privileged": ov["privileged_recent"],
                                  "fail_sources": ov["fail_sources"], "exports_by": ov["exports_by"], "per_day": ov["per_day"],
                                  "first": _when(integrity()["first"]), "last": _when(integrity()["last"]), "nist_release": NIST_RELEASE,
                                  "cis_release": control_map.CIS_RELEASE, "cis_source": control_map.CIS_SOURCE,
                                  "cis_attribution": control_map.CIS_ATTRIBUTION, "cis_note": control_map.CERTIFICATION_NOTE,
                                  "started": _when(setup_time(integrity().get("first") or 0)),
                                  "sealed_at": _when((integrity().get("seal") or {}).get("sealed_at")),
                                  "verifier_sha256": __import__("audit_proof").verifier_sha256()})
        logged_export("pdf", fr, to, f" · evidence report · head entry {integrity()['head_entry']} {integrity()['head']}")
        return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f'attachment; filename="audit_evidence_{fr}_{to}.pdf"',
                                                                  "Cache-Control": "no-store"})

    # ------------------------------------------------------------------ proof the auditor takes away (audit_proof.py)
    import audit_proof
    audit_proof.install(app, audit, allowed, deny,
                        lambda: ((g.user or {}).get("user", ""), people.audit((g.user or {}).get("user", ""))),
                        to_csv=lambda records, first: csv_bytes([shaped(r) for r in records], first=first))
