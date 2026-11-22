# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Settings → Configuration: every setting of the platform's .env except its secrets, explained, for administrators who
do not work in a terminal (the user, 2026-11-17).

Three kinds (the user chose which may change from the browser):
* TUNING (editable): replay timing, loading and counting, memory and speed limits, findings' deadlines, alerts. Kept in
  data/config.json (mode 600) and applied when the service starts (gunicorn.conf.py calls apply()), before any module
  reads its setting; a value kept here takes precedence over .env. Each has a range; nothing outside it is kept.
* READ-ONLY: the security switches (who can reach it, sign-in codes, sessions, the proxy, HTTPS hardening, sign-in
  locks), the audit log and its control checks, and the database connection. Shown with the line to change in .env:
  a stolen administrator session must not be able to weaken them (the user's decision).
* SECRETS (passwords, tokens, keys): never shown, only whether one is set.

  GET  /api/admin/config            every setting: value in use, where it comes from, default, range, help
  POST /api/admin/config            {values: {KEY: value or null}}: keep tuning values (null = back to .env / default)
  POST /api/admin/config/restart    restart the service so kept values apply (the days are loaded again, ~1 minute)

All need the 'settings' permission; the two changes also the CSRF token and a recent sign-in, and each is written to the
audit log with the old and new values (never a secret: secrets are not in this catalogue)."""
import json
import logging
import os
import signal
import threading
import time

log = logging.getLogger("looking-glass")
FILE = "config.json"
RESTART_GAP_S = 60                      # one restart a minute at most
R = "after a restart"

# (key, group, label, kind, default, min, max, help). kind: int, float, hours ("HH-HH")
TUNING = [
    ("REPLAY_OFFSET_HOURS", "Replay", "How far behind real time the replay runs", "float", 24, 0, 168,
     "Hours. 24 shows yesterday's events at today's clock time."),
    ("REPORT_SETTLE_SECONDS", "Replay", "Quiet time before a day replays", "int", 600, 60, 7200,
     "Seconds without a new report, once a day's reports start arriving, before that day replays from 00:00."),
    ("MAX_EVENTS_PER_POLL", "Replay", "Events sent to a browser per update", "int", 400, 50, 5000,
     "More are sampled. Higher draws more on the map but asks more of each screen."),
    ("DAY_RELOAD_SECONDS", "Loading and counting", "How often a loaded day is checked against the database", "int", 600, 60, 86400,
     "Seconds. The day and every answer worked out from it are kept while the database holds the same rows."),
    ("DAY_MAX_AGE_SECONDS", "Loading and counting", "A loaded day is read again in full at least this often", "int", 3600, 300, 86400,
     "Seconds, even when the database holds the same rows."),
    ("SETTLE_MAX_SECONDS", "Loading and counting", "Longest wait before new rows are loaded", "int", 120, 30, 3600,
     "Seconds. New rows load once their counts stop changing, or at least this often while a pipeline run keeps adding them."),
    ("COUNT_EVERY_SECONDS", "Loading and counting", "Full row count at least this often", "int", 600, 60, 86400,
     "Seconds. Between them, reports are counted only when the pipeline marks a change."),
    ("REGISTRY_REFRESH_SECONDS", "Loading and counting", "Full re-check of the list of reports", "int", 3600, 300, 86400,
     "Seconds. New reports are found within 15 seconds anyway."),
    ("BEACON_KEEP_MAX", "Memory and speed", "Decoded beacon answers kept across restarts", "int", 200000, 1000, 5000000,
     "The decoder's public answers (format, operator, version, OS family) kept so a restart does not decode the day again. "
     "About 170 bytes each in memory. Raise it for a country with many check-ins a day."),
    ("ANALYST_DAY_KEEP", "Memory and speed", "Older days kept for analyst codes", "int", 1, 0, 7,
     "An analyst code on a day older than the days in memory loads that whole day from the database; it is kept for "
     "its page and counts to share. Each kept day costs about as much memory as a day in memory. 0 keeps none: every "
     "request loads the day again (slower, least memory)."),
    ("ANALYST_DAY_KEEP_S", "Memory and speed", "How long such a day is kept", "int", 300, 30, 3600,
     "Seconds. A kept day is also dropped at once when the constituency or the stored data change."),
    ("NAME_LEVELS_DELAY_S", "Memory and speed", "Names' criticality learned from every report", "int", 120, 0, 3600,
     "Seconds after a start before every report's records are read once, gently, to learn each name's criticality for "
     "the PDFs' References section; it runs once per installation. 0 = never (the day loads still teach it)."),
    ("ANALYST_WARM_DELAY_S", "Memory and speed", "Analyst code counts worked out after a start", "int", 30, 0, 600,
     "Seconds after a start before the device counts of the open findings' analyst codes are worked out, so the "
     "Findings page does not wait for them. 0 = never ahead: the first person to open Findings waits for them."),
    ("MGMT_PAST_RECORDS", "Memory and speed", "Past records the Executive portal keeps in memory", "int", 3000000, 100000, 50000000,
     "For its 7-day baselines; roughly 200 to 300 MB per million. Above it, older days are read from the database when needed."),
    ("EXEC_BASELINE_WORKERS", "Memory and speed", "Executive baselines built at the same time", "int", 2, 1, 16,
     "Each reads up to 7 days of data."),
    ("EXEC_BASELINE_QUEUE", "Memory and speed", "Executive baselines waiting their turn", "int", 20, 1, 500,
     "When the list is full the page shows \"building\" and asks again on its next refresh."),
    ("HEAVY_PER_USER", "Memory and speed", "Heavy views one person may have worked on at once", "int", 3, 1, 50,
     "Statistics, map, analyses, drill-down lists, regions, reports. More wait their turn."),
    ("HEAVY_PER_MINUTE", "Memory and speed", "Heavy views one person may ask for in a minute", "int", 240, 10, 10000,
     "More are answered \"too many requests\" with a time to try again."),
    ("HEAVY_WAIT_S", "Memory and speed", "How long a heavy view waits for its turn", "int", 20, 1, 120, "Seconds."),
    ("SLOW_REQUEST_S", "Memory and speed", "A request is listed as slow above", "float", 2, 0.5, 120,
     "Seconds. Slow requests are listed in Settings → Task monitor."),
    ("FINDING_ACT_DAYS", "Findings", "Time to act", "int", 30, 0, 365,
     "Days after a finding's devices were last seen before a finding nobody is acting on closes on its own. 0: never."),
    ("FINDING_GRACE_DAYS", "Findings", "Never closed sooner than", "int", 7, 0, 90,
     "Days after a finding was opened."),
    ("SPIKE_RATIO", "Alerts", "A day is a spike at", "float", 1.5, 1.1, 20,
     "This many times the day before or more (a drop: the day before is this many times the day)."),
    ("SPIKE_MIN_EVENTS", "Alerts", "Smallest difference that is a spike", "int", 500, 0, 10000000,
     "Records, so a small report doubling is not a spike."),
    ("SPIKE_CACHE_SECONDS", "Alerts", "Spike comparison kept for", "int", 600, 60, 86400, "Seconds before it is counted again."),
    ("PIPELINE_STALE_HOURS", "Alerts", "Alert when no report run finished for", "float", 26, 1, 168,
     "Hours. The administrators' bell then says the pipeline may have stopped."),
]
TUNING_KEYS = {t[0] for t in TUNING}

# read-only: (key, group, label, default as shown, help). Changed in .env, then the service restarted.
READ_ONLY = [
    ("ACCESS_MODE", "Access and security", "Who can reach the sign-in page", "local", "local: this computer; private: plus the viewer networks; public: anyone."),
    ("VIEWER_NETWORKS", "Access and security", "Networks allowed in private mode", "", "Addresses and ranges, comma separated; internal = every private range."),
    ("ALLOWED_HOSTS", "Access and security", "Extra host names people type to reach it", "", "The computer's own names and addresses are always allowed."),
    ("MFA_REQUIRED", "Access and security", "Authenticator code at every sign-in", "1", "0 only in a closed lab."),
    ("REGISTRATION", "Access and security", "Create an account on the sign-in page", "1", "0: only administrators add people."),
    ("SESSION_IDLE_MINUTES", "Access and security", "Session ends after minutes without use", "60", ""),
    ("SESSION_MAX_HOURS", "Access and security", "Session ends after hours in any case", "12", ""),
    ("TRUST_PROXY", "Access and security", "A reverse proxy on this computer does HTTPS", "0", "1 with Caddy or nginx in front."),
    ("ALLOW_INSECURE_REMOTE_LOGIN", "Access and security", "Sign-in over plain HTTP from other computers", "0", "1 only in a closed lab."),
    ("PUBLIC_DEMO", "Access and security", "Mask everything for everyone", "0", "1 for public screens."),
    ("CSP_REPORT_ONLY", "Access and security", "Browser security policy only reports", "0", "Diagnostics only."),
    ("HSTS_MAX_AGE", "Access and security", "HTTPS-only memory in browsers (seconds)", "31536000", ""),
    ("HSTS_INCLUDE_SUBDOMAINS", "Access and security", "HTTPS-only for every name under the domain", "0", ""),
    ("HSTS_PRELOAD", "Access and security", "Ask browsers to preload HTTPS-only", "0", ""),
    ("LOGIN_ACCOUNT_FAILS", "Sign-in locks", "Failed sign-ins before an account is locked", "5", ""),
    ("LOGIN_ACCOUNT_LOCK_MIN", "Sign-in locks", "Account lock (minutes)", "15", ""),
    ("LOGIN_ADDRESS_FAILS", "Sign-in locks", "Failed sign-ins before an address is locked", "20", ""),
    ("LOGIN_ADDRESS_WINDOW_MIN", "Sign-in locks", "Address window (minutes)", "60", ""),
    ("DATA_ACCESS_LOG", "Audit", "Views of host-level data are logged", "1", ""),
    ("AUDIT_RETENTION_DAYS", "Audit", "Days archived audit entries are kept", "400", ""),
    ("AUDIT_GAP_DAYS", "Audit", "A gap this long after a removed archive is reported", "30", ""),
    ("AUDIT_ROTATE_MB", "Audit", "Audit log archived at (MB)", "5", ""),
    ("AUDIT_CHECKPOINT_HOURS", "Audit", "Signed checkpoint every (hours)", "24", ""),
    ("AUDIT_CHECKPOINT_COPY_DIR", "Audit", "Folder that gets a copy of every checkpoint", "", ""),
    ("AUDIT_DORMANT_DAYS", "Audit", "Control check: an account unused this long is dormant", "45", ""),
    ("AUDIT_MAX_ADMINS", "Audit", "Control check: administrator limit", "3", ""),
    ("AUDIT_PENDING_DAYS", "Audit", "Control check: registrations waiting longer than", "7", ""),
    ("AUDIT_WORK_HOURS", "Audit", "Working hours (UTC)", "07-19", ""),
    ("AUDIT_FAIL_ALERT", "Audit", "Control check: failed sign-ins from one address in a day", "10", ""),
    ("AUDIT_REVIEW_DAYS", "Audit", "Control check: review interval (days)", "7", ""),
    ("MONGO_HOST", "Database", "Database server", "127.0.0.1", ""),
    ("MONGO_PORT", "Database", "Database port", "27017", ""),
    ("MONGO_DB", "Database", "Reports database", "shadowserver", ""),
    ("MONGO_USER", "Database", "Database account", "", "The read-only account is recommended."),
    ("MONGO_AUTH_SOURCE", "Database", "Database the account is defined in", "admin", ""),
    ("MONGO_TLS", "Database", "TLS to the database", "0", ""),
    ("MONGO_COLLECTIONS", "Database", "Reports used (empty: all)", "", ""),
    ("EXCLUDE_COLLECTIONS", "Database", "Reports never used", "outdated_dnssec_key", ""),
    ("FALLBACK_SCAN", "Database", "Load reports without the file-name index", "0", "Leave off: it reads every row of such a report."),
    ("PIPELINE_DIR", "Database", "The pipeline's folder", "", "Empty: beside the platform."),
    ("LG_PORT", "Database", "Port the service listens on", "5000", ""),
    ("COUNTRY", "Country", "Country", "GH", "Changed on the General tab (Country)."),
    ("TIMEZONE", "Country", "Time zone", "", "Changed on the General tab (Country)."),
    ("CONSTITUENT_ASNS", "Country", "Constituency AS numbers", "", "Changed on the General tab (Constituency)."),
    ("CONSTITUENT_CIDRS", "Country", "Constituency address ranges", "", "Changed on the General tab (Constituency)."),
    ("CACHE_TTL_S", "Memory and speed", "Heavy answers kept (seconds)", "180", "Changed in Settings → Task monitor."),
]
# never shown: only whether one is set
SECRETS = [("MONGO_PASSWORD", "Database password"), ("MAPBOX_TOKEN", "Mapbox token"), ("MALPEDIA_TOKEN", "Malpedia token"),
           ("NVD_API_KEY", "NVD API key"), ("REF_SECRET", "Host reference secret")]
SECRET_KEYS = {k for k, _ in SECRETS}
GROUPS = ["Replay", "Loading and counting", "Memory and speed", "Findings", "Alerts", "Access and security", "Sign-in locks",
          "Audit", "Database", "Country", "Secrets"]
assert not (TUNING_KEYS & ({k for k, *_ in READ_ONLY} | SECRET_KEYS)), "a setting in two kinds"


def _path(base_dir):
    return os.path.join(base_dir, "data", FILE)


def validate(key, value):
    """(value as kept, None) or (None, why). Only tuning keys; numbers within their range."""
    spec = next((t for t in TUNING if t[0] == key), None)
    if spec is None:
        return None, f"{key} cannot be changed here."
    _k, _g, label, kind, _d, lo, hi, _h = spec
    if isinstance(value, bool):
        return None, f"{label}: a number is needed."
    try:
        v = float(str(value).strip()) if kind == "float" else int(str(value).strip())
    except (TypeError, ValueError):
        return None, f"{label}: {'a number' if kind == 'float' else 'a whole number'} is needed."
    if v != v or not lo <= v <= hi:                      # v != v: NaN
        return None, f"{label}: from {lo:,} to {hi:,}."
    return (repr(v) if kind == "float" else str(v)), None


def load(base_dir):
    """{KEY: value as kept}, only valid tuning values (a damaged or edited file never applies anything else)."""
    try:
        with open(_path(base_dir), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    out = {}
    for k, v in ((raw.get("values") if isinstance(raw, dict) else None) or {}).items():
        kept, _why = validate(k, v)
        if kept is not None:
            out[k] = kept
    return out


def _save(base_dir, values, who):
    p = _path(base_dir)
    tmp = f"{p}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "values": values, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "updated_by": who}, f, indent=1, sort_keys=True)
    os.replace(tmp, p)


def _env_file(base_dir):
    """The .env file's own values (name -> value), read by the very parser app.py's load_dotenv uses, so a value
    is never read differently here (an inline comment, quotes, export)."""
    try:
        from dotenv import dotenv_values
        return {k: v for k, v in dotenv_values(os.path.join(base_dir, ".env")).items() if v is not None}
    except Exception:                    # noqa: BLE001  (no .env, or unreadable: nothing from it)
        return {}


def apply(base_dir, environ=os.environ):
    """At service start (gunicorn.conf.py), before the app is loaded: .env's values first (never replacing what the
    service was given, as load_dotenv), then the values kept on this page, which take precedence. Returns them."""
    for k, v in _env_file(base_dir).items():
        environ.setdefault(k, v)
    kept = load(base_dir)
    for k, v in kept.items():
        environ[k] = v
    environ["LG_CONFIG_APPLIED"] = json.dumps(kept, sort_keys=True)     # what this start runs with (the page compares)
    return kept


def snapshot(base_dir, environ=os.environ):
    kept = load(base_dir)
    envf = _env_file(base_dir)
    try:
        running = json.loads(environ.get("LG_CONFIG_APPLIED") or "{}")
    except ValueError:
        running = {}
    items = []
    for key, group, label, kind, default, lo, hi, helptext in TUNING:
        now = environ.get(key)
        in_use = now if now not in (None, "") else str(default)
        if key in running:
            source = "this page"
        elif key in envf:
            source = ".env"
        else:
            source = "default"
        items.append({"key": key, "group": group, "label": label, "help": helptext, "kind": kind, "default": default,
                      "min": lo, "max": hi, "value": in_use, "source": source, "editable": True,
                      "saved": kept.get(key), "pending": kept.get(key) != running.get(key), "applies": R})
    for key, group, label, default, helptext in READ_ONLY:
        now = environ.get(key)
        value = now if now not in (None, "") else default
        item = {"key": key, "group": group, "label": label, "help": helptext, "default": default, "value": value,
                "source": ".env" if key in envf else "default", "editable": False, "env_line": f"{key}={value}"}
        if group == "Country":                  # chosen on the General tab, which takes precedence: .env is the start value
            item.update(value="set on the General tab", source="Settings → General", env_line=None, where="Settings → General")
        elif key == "CACHE_TTL_S":              # Settings → Task monitor keeps its own choice (response_cache.py)
            item.update(env_line=None, where="Settings → Task monitor")
            try:
                import response_cache
                item.update(value=str(response_cache.ttl()),
                            source="Settings → Task monitor" if response_cache._override() is not None else item["source"])
            except Exception:                   # noqa: BLE001
                pass
        items.append(item)
    for key, label in SECRETS:
        items.append({"key": key, "group": "Secrets", "label": label, "editable": False, "secret": True,
                      "set": bool(environ.get(key)), "help": "Never shown here. Set in .env."})
    return {"groups": GROUPS, "items": items, "pending_restart": any(i.get("pending") for i in items),
            "file": f"data/{FILE}"}


def _gunicorn_master():
    """The service's main process when this is its worker (gunicorn), else None."""
    try:
        ppid = os.getppid()
        with open(f"/proc/{ppid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\0", b" ").decode("utf-8", "replace")
        return ppid if "gunicorn" in cmd else None
    except OSError:
        return None


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, fresh, audit."""
    from flask import abort, g, jsonify, make_response, request
    hp, base = ctx["has_perm"], ctx["base_dir"]
    state = {"restart_at": 0.0}
    lock = threading.Lock()

    def who():
        return (getattr(g, "user", None) or {}).get("user", "")

    def denied():
        if not hp("settings"):
            return jsonify(error="The configuration is for administrators (the 'settings' permission)."), 403
        return None

    def recent_sign_in():
        if not ctx["fresh"]():
            abort(make_response(jsonify(error="For your security, sign out and sign in again to make changes.", reauth=True), 403))

    @app.route("/api/admin/config", methods=["GET", "POST"])
    def api_admin_config():
        bad = denied()
        if bad:
            return bad
        if request.method == "GET":
            return jsonify(snapshot(base))
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            abort(403)
        recent_sign_in()
        d = request.get_json(silent=True) or {}
        values = d.get("values")
        if not isinstance(values, dict) or not values or len(values) > len(TUNING):
            return jsonify(error='Send {"values": {"NAME": value}}.'), 400
        with lock:
            kept = load(base)
            changes, errors = [], []
            for k, v in values.items():
                if not isinstance(k, str) or k not in TUNING_KEYS:
                    errors.append(f"{str(k)[:60]} cannot be changed here." if isinstance(k, str) else "A setting name is needed.")
                    continue
                if v is None or v == "":
                    if k in kept:
                        changes.append((k, kept.pop(k), None))
                    continue
                val, why = validate(k, v)
                if why:
                    errors.append(why)
                elif kept.get(k) != val:
                    changes.append((k, kept.get(k), val))
                    kept[k] = val
            if errors:
                return jsonify(error=" ".join(errors[:5])), 400
            if changes:
                _save(base, kept, who())
                for k, old, new in changes:
                    ctx["audit"].add("config_changed", user=who(), target=k,
                                     detail=f"{old if old is not None else '(.env or default)'} -> {new if new is not None else '(.env or default)'}"
                                            " (applies after a restart)")
        return jsonify(ok=True, changed=len(changes), **snapshot(base))

    @app.route("/api/admin/config/restart", methods=["POST"])
    def api_admin_config_restart():
        bad = denied()
        if bad:
            return bad
        if request.mimetype != "application/json" or not ctx["csrf_ok"]():
            abort(403)
        recent_sign_in()
        master = _gunicorn_master()
        if not master:
            return jsonify(error="Restart the service from the server: deploy/reload.sh (this is not the running service)."), 409
        with lock:
            wait = RESTART_GAP_S - (time.time() - state["restart_at"])
            if wait > 0:
                return jsonify(error=f"A restart was just asked for. Try again in {int(wait) + 1} s."), 429
            state["restart_at"] = time.time()
        ctx["audit"].add("service_restarted", user=who(), target="configuration",
                         detail="restart asked for on Settings → Configuration")

        who_name = who()

        def later():                     # after the answer has left: systemd starts the service again (Restart=always)
            time.sleep(1.5)
            log.warning("restart asked for on Settings → Configuration by %s", who_name)
            try:
                os.kill(master, signal.SIGTERM)
            except OSError as e:
                log.error("restart failed: %s", e)
        threading.Thread(target=later, daemon=True, name="config-restart").start()
        return jsonify(ok=True, restarting=True)

    return {"snapshot": lambda: snapshot(base)}
