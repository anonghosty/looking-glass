"""Settings → Workers: the database pipeline's settings, edited in the web app instead of its .env.

What is here (2026-11-12, at the user's request): the sender check (record only, or block reports whose DKIM signature
does not pass, mail_auth.py), e-mail fetching (days back, folder, batch, certificate check, timeout), loading
performance (loader processes, insert chunk, download threads) and the unzip limits. Mailbox and database passwords
are never shown or edited here: they stay in the pipeline's .env, set by the installer.

Locked by default. Editing needs the Settings permission AND the signed-in administrator's own password again
(unlock, 10 minutes, this session only; a wrong password counts as a failed sign-in). Saving locks it again. Every
unlock, failed unlock, change (old → new value), API key save and release is in the audit log.

The Shadowserver report API key and secret: write-only. Saving checks them with Shadowserver first (test/ping, signed
with the secret as Shadowserver's API requires) and stores them only if Shadowserver accepts them; afterwards the page
shows only that they are set and when they were last checked, never the values.

Held-back reports (blocking on): listed here for administrators, each released only after the password; the release
is carried out by the pipeline's next run (mail_auth.request_release).
"""
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.request

from flask import g, jsonify, request
from werkzeug.security import check_password_hash

import pipeline_link

UNLOCK_SECONDS = 600
API_URL = os.environ.get("SHADOWSERVER_API_URL", "https://transform.shadowserver.org/api2/")
DOMAIN_RX = re.compile(r"^(?=.{3,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
FOLDER_RX = re.compile(r"^[^\x00-\x1f\"\\]{1,120}$")

# (key, group, label, kind, default, lo, hi, help, shown for MAIL_PROVIDER)
FIELDS = [
    ("REPORT_SOURCE", "email", "How the reports are fetched", "choice", "email", ("email", "api"), None,
     "By e-mail: the mailbox the reports are sent to. Shadowserver API: straight from Shadowserver with the API key below. "
     "Each scheduled run uses this; if it cannot be used that run and the other way is set up, the run uses the other "
     "way and says why in its log.", None),
    ("MAIL_AUTH", "sender", "Sender check", "choice", "log", ("log", "enforce", "off"), None,
     "Check each report e-mail's DKIM signature. Record only: every result is kept and shown in the Audit portal, "
     "nothing is held back. Block: a report that does not pass is held back (quarantine) until an administrator releases it.", None),
    ("MAIL_AUTH_DOMAIN", "sender", "Expected signer", "domain", "shadowserver.org", None, None,
     "The domain that must have signed a genuine report.", None),
    ("EMAIL_DAYS", "email", "Days back per run", "int", "7", 1, 60,
     "How many days back every run looks (e-mail or API); reports already fetched are skipped.", None),
    ("IMAP_FOLDER", "email", "Mailbox folder", "folder", "inbox", None, None, "The folder holding the reports.", "imap"),
    ("GMAIL_LABEL", "email", "Gmail label", "folder", "INBOX", None, None, "The label holding the reports.", "gmail_api"),
    ("MS_FOLDER", "email", "Mailbox folder", "folder", "inbox", None, None, "The folder holding the reports.", "microsoft_graph"),
    ("IMAP_FETCH_BATCH", "email", "Messages per fetch", "int", "25", 1, 500, "E-mails downloaded per request.", "imap"),
    ("IMAP_VERIFY_TLS", "email", "Check the mail server's certificate", "bool", "false", None, None,
     "Off only for a self-signed certificate: with it off, someone on the network path could read the mailbox.", "imap"),
    ("MAIL_TIMEOUT", "email", "Mail server timeout (seconds)", "int", "120", 5, 600, "How long to wait for the mail server.", None),
    ("WORKERS", "load", "Loader processes", "int", "6", 1, 64, "Parallel processes loading reports into MongoDB (each 100-200 MB of memory).", None),
    ("INSERT_CHUNK", "load", "Records per insert", "int", "2000", 100, 100000, "Records written to MongoDB at a time.", None),
    ("DOWNLOAD_THREADS", "load", "Download threads", "int", "4", 1, 32, "Reports downloaded from Shadowserver links at the same time.", None),
    ("ZIP_MAX_UNPACKED_MB", "unzip", "Largest unpacked size (MB)", "int", "2048", 16, 1048576,
     "A zip that would unpack to more is quarantined, not unpacked (zip bombs).", None),
    ("ZIP_MAX_RATIO", "unzip", "Largest compression ratio", "int", "200", 10, 100000, "Unpacked size divided by packed size.", None),
    ("ZIP_MAX_FILES", "unzip", "Most files in one zip", "int", "100", 1, 1000000, "", None),
    ("ZIP_KEEP_FREE_MB", "unzip", "Disk space kept free (MB)", "int", "1024", 0, 1048576, "Unpacking stops before the disk gets this full.", None),
]
GROUPS = [("email", "Getting the reports"), ("sender", "Sender check (DKIM, e-mail only)"), ("load", "Loading performance"),
          ("unzip", "Unzip limits")]
CHOICE_LABELS = {"REPORT_SOURCE": {"email": "By e-mail (the mailbox)", "api": "Shadowserver report API"},
                 "MAIL_AUTH": {"log": "Record only", "enforce": "Block", "off": "Off"}}
API_KEYS = ("SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET")


def validate(values, provider):
    """({key: clean value}, [errors]) for the fields sent; unknown keys and passwords are refused."""
    spec = {f[0]: f for f in FIELDS}
    clean, errors = {}, []
    for k, v in (values or {}).items():
        f = spec.get(k)
        if not f or (f[8] and f[8] != provider):
            errors.append(f"{k} cannot be set here")
            continue
        kind, lo, hi, label = f[3], f[5], f[6], f[2]
        v = str(v if v is not None else "").strip()
        if kind == "int":
            if not re.fullmatch(r"\d{1,9}", v) or not (lo <= int(v) <= hi):
                errors.append(f"{label}: a whole number from {lo:,} to {hi:,}")
                continue
            v = str(int(v))
        elif kind == "bool":
            if v.lower() not in ("true", "false"):
                errors.append(f"{label}: true or false")
                continue
            v = v.lower()
        elif kind == "choice":
            if v not in lo:
                errors.append(f"{label}: one of {', '.join(lo)}")
                continue
        elif kind == "domain":
            v = v.lower()
            if not DOMAIN_RX.match(v):
                errors.append(f"{label}: a domain name, for example shadowserver.org")
                continue
        elif kind == "folder":
            if not FOLDER_RX.match(v):
                errors.append(f"{label}: 1-120 characters, no quotes or backslashes")
                continue
        clean[k] = v
    return clean, errors


def _api(method, key, secret, url=None, timeout=15):
    """(answer, error): one call to Shadowserver's report API, the JSON body (with apikey) signed with HMAC-SHA256 of
    the secret in the HMAC2 header, as Shadowserver documents it. The key and secret never appear in an error."""
    body = json.dumps({"apikey": key}).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request((url or API_URL).rstrip("/") + "/" + method, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "HMAC2": sig, "User-Agent": "LookingGlass"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read(65536).decode("utf-8", "replace") or "null"), ""
    except urllib.error.HTTPError as exc:
        try:
            ans = json.loads(exc.read(65536).decode("utf-8", "replace") or "{}")
        except ValueError:
            ans = {}
        why = ans.get("error") if isinstance(ans, dict) else ""
        return None, str(why)[:200] if why else f"Shadowserver refused it (HTTP {exc.code})"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, f"Shadowserver could not be reached from this server ({type(exc).__name__})"


def ping(key, secret, url=None, timeout=15):
    """(ok, message): Shadowserver accepts this key and secret (test/ping) and lets it list reports
    (reports/subscribed: the report lists, for example the country, that the pipeline would download)."""
    ans, err = _api("test/ping", key, secret, url, timeout)
    if err or not (isinstance(ans, dict) and ans.get("pong")):
        return False, err or "unexpected answer to test/ping"
    subs, err = _api("reports/subscribed", key, secret, url, timeout)
    if err:
        return False, f"the key works, but may not list reports ({err})"
    names = [str(x) for x in subs] if isinstance(subs, list) else []
    return True, (f"Shadowserver accepted the key; reports for {', '.join(names[:6])}" if names
                  else "Shadowserver accepted the key, but no report list is subscribed to it")


def install(app, ctx):
    """ctx: base_dir, data_dir, has_perm, csrf_ok, fresh, audit, users, throttle, client (-> (ip, ua))."""
    hp, audit, users, throttle = ctx["has_perm"], ctx["audit"], ctx["users"], ctx["throttle"]
    unlocked = {}                                           # (user, session csrf) -> until
    api_state_path = os.path.join(ctx["data_dir"], "pipeline_api.json")

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), (u.get("user", ""), u.get("csrf") or "")

    def guard(change=False):
        if not hp("settings"):
            return jsonify(error="The Workers settings are for administrators (Settings permission)."), 403
        if change:
            if request.mimetype != "application/json" or not ctx["csrf_ok"]():
                return jsonify(error="Refused (the request did not come from this page)."), 403
            if not ctx["fresh"]():
                return jsonify(error="Sign in again to make changes (your session is older than 12 hours).", reauth=True), 403
        return None

    def is_unlocked():
        _, sk = me()
        until = unlocked.get(sk, 0)
        if until and until < time.time():
            unlocked.pop(sk, None)
        return unlocked.get(sk, 0) > time.time()

    def pdir():
        return pipeline_link.find_dir(ctx["base_dir"])

    def api_state():
        try:
            with open(api_state_path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def save_api_state(st):
        tmp = api_state_path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(st, fh)
        os.replace(tmp, api_state_path)

    @app.route("/api/pipeline/settings")
    def api_pipeline_settings():
        bad = guard()
        if bad:
            return bad
        d = pdir()
        if not d:
            return jsonify(found=False, message="The database pipeline is not on this computer: its settings are in its own .env.")
        env = pipeline_link.read_env(d / ".env")
        provider = (env.get("MAIL_PROVIDER") or "imap").lower()
        st = api_state()
        _, sk = me()
        return jsonify(found=True, provider=provider, unlocked=is_unlocked(),
                       unlocked_for=max(0, int(unlocked.get(sk, 0) - time.time())) if is_unlocked() else 0,
                       groups=[{"key": k, "label": lab} for k, lab in GROUPS],
                       fields=[{"key": f[0], "group": f[1], "label": f[2], "kind": f[3], "default": f[4],
                                "choices": [{"value": c, "label": CHOICE_LABELS.get(f[0], {}).get(c, c)} for c in f[5]] if f[3] == "choice" else None,
                                "min": f[5] if f[3] == "int" else None, "max": f[6] if f[3] == "int" else None,
                                "help": f[7], "value": env.get(f[0], f[4])}
                               for f in FIELDS if not f[8] or f[8] == provider],
                       api={"key_set": bool(env.get(API_KEYS[0])), "secret_set": bool(env.get(API_KEYS[1])),
                            "checked_at": st.get("checked_at"), "ok": st.get("ok"), "message": st.get("message", "")})

    @app.route("/api/pipeline/unlock", methods=["POST"])
    def api_pipeline_unlock():
        bad = guard(change=True)
        if bad:
            return bad
        name, sk = me()
        ip, _ = ctx["client"]()
        u = users.get(name) if name else None
        if not u or (getattr(g, "user", None) or {}).get("automation"):
            return jsonify(error="Unlocking needs a signed-in administrator's own password."), 403
        if throttle.locked(ip, name):
            return jsonify(error="Too many wrong passwords. Try again in 15 minutes."), 429
        pw = str((request.get_json(silent=True) or {}).get("password") or "")
        if not (u.get("hash") and check_password_hash(u["hash"], pw)):
            throttle.failed(ip, name)
            audit.add("pipeline_unlock_failed", user=name, detail="Settings → Workers: wrong password")
            return jsonify(error="That password is not right."), 403
        unlocked[sk] = time.time() + UNLOCK_SECONDS
        audit.add("pipeline_unlock", user=name, detail=f"Settings → Workers unlocked for {UNLOCK_SECONDS // 60} minutes")
        return jsonify(ok=True, unlocked_for=UNLOCK_SECONDS)

    @app.route("/api/pipeline/lock", methods=["POST"])
    def api_pipeline_lock():
        bad = guard(change=True)
        if bad:
            return bad
        unlocked.pop(me()[1], None)
        return jsonify(ok=True)

    def need_unlock():
        if not is_unlocked():
            return jsonify(error="Locked: enter your password (Edit) first.", locked=True), 403
        return None

    @app.route("/api/pipeline/settings", methods=["POST"])
    def api_pipeline_settings_save():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d = pdir()
        if not d:
            return jsonify(error="The database pipeline is not on this computer."), 404
        env = pipeline_link.read_env(d / ".env")
        provider = (env.get("MAIL_PROVIDER") or "imap").lower()
        clean, errors = validate((request.get_json(silent=True) or {}).get("values"), provider)
        if errors:
            return jsonify(error="; ".join(errors)), 400
        spec = {f[0]: f for f in FIELDS}
        if clean.get("REPORT_SOURCE") == "api" and not (env.get(API_KEYS[0]) and env.get(API_KEYS[1])):
            return jsonify(error="Save the Shadowserver API key (below) before choosing the API: Shadowserver checks it first."), 400
        changed = {k: v for k, v in clean.items() if env.get(k, spec[k][4]) != v}
        if changed:
            try:
                pipeline_link.write_env(d / ".env", changed)
            except (OSError, ValueError) as exc:
                return jsonify(error=f"The pipeline's .env could not be written ({type(exc).__name__}): check its owner."), 500
            audit.add("pipeline_settings_saved", user=me()[0],
                      detail="; ".join(f"{k}: {env.get(k, spec[k][4])} → {v}" for k, v in changed.items())[:900])
        unlocked.pop(me()[1], None)                         # saved: locked again
        return jsonify(ok=True, changed=sorted(changed), note="The pipeline uses them from its next run.")

    @app.route("/api/pipeline/apikey", methods=["POST"])
    def api_pipeline_apikey():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d = pdir()
        if not d:
            return jsonify(error="The database pipeline is not on this computer."), 404
        b = request.get_json(silent=True) or {}
        key, secret = str(b.get("key") or "").strip(), str(b.get("secret") or "").strip()
        if not (re.fullmatch(r"[A-Za-z0-9._-]{8,200}", key) and re.fullmatch(r"[\x21-\x7e]{8,200}", secret)):
            return jsonify(error="Paste the API key and the secret exactly as Shadowserver gave them."), 400
        ok, msg = ping(key, secret)
        now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        audit.add("pipeline_apikey_checked", user=me()[0], detail=f"new Shadowserver API key: {'accepted' if ok else 'refused'} ({msg})"[:300])
        if not ok:
            return jsonify(error=f"Not saved: {msg}"), 400
        try:
            pipeline_link.write_env(d / ".env", {API_KEYS[0]: key, API_KEYS[1]: secret})
        except (OSError, ValueError) as exc:
            return jsonify(error=f"The pipeline's .env could not be written ({type(exc).__name__})."), 500
        save_api_state({"checked_at": now, "ok": True, "message": msg})
        audit.add("pipeline_apikey_saved", user=me()[0], detail="Shadowserver API key and secret saved (values not logged)")
        unlocked.pop(me()[1], None)
        return jsonify(ok=True, message=msg, checked_at=now)

    @app.route("/api/pipeline/apikey/check", methods=["POST"])
    def api_pipeline_apikey_check():
        bad = guard(change=True)
        if bad:
            return bad
        d = pdir()
        env = pipeline_link.read_env(d / ".env") if d else {}
        if not (env.get(API_KEYS[0]) and env.get(API_KEYS[1])):
            return jsonify(error="No API key saved yet."), 404
        ok, msg = ping(env[API_KEYS[0]], env[API_KEYS[1]])
        now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        save_api_state({"checked_at": now, "ok": ok, "message": msg})
        audit.add("pipeline_apikey_checked", user=me()[0], detail=f"saved Shadowserver API key: {'accepted' if ok else 'refused'} ({msg})"[:300])
        return jsonify(ok=ok, message=msg, checked_at=now)

    @app.route("/api/pipeline/held")
    def api_pipeline_held():
        bad = guard()
        if bad:
            return bad
        d = pdir()
        ma = pipeline_link.mail_auth(d)
        if not ma:
            return jsonify(held=[])
        out = []
        for q, m in ma.held(d):
            out.append({"id": q.name, "at": m.get("at"), "result": m.get("result"), "reason": m.get("reason"),
                        "from_domain": m.get("from_domain"), "signer": m.get("signer"), "subject": m.get("subject"),
                        "files": len(m.get("files") or []), "links": len(m.get("links") or []),
                        "release_asked": (q / ma.RELEASE_FILE).exists()})
        return jsonify(held=out, mode=ma.mode(pipeline_link.read_env(d / ".env")))

    @app.route("/api/pipeline/release", methods=["POST"])
    def api_pipeline_release():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d = pdir()
        ma = pipeline_link.mail_auth(d)
        qid = str((request.get_json(silent=True) or {}).get("id") or "")
        match = [(q, m) for q, m in (ma.held(d) if ma else []) if q.name == qid]
        if not re.fullmatch(r"[0-9a-f]{20}", qid) or not match:
            return jsonify(error="No such held-back report."), 404
        q, m = match[0]
        ma.request_release(q, me()[0])
        audit.add("sender_release", user=me()[0], target=qid,
                  detail=f"held-back report released ({m.get('result')}: {m.get('reason')}) | {(m.get('subject') or '')[:120]}")
        return jsonify(ok=True, note="Released: the pipeline's next run lets it through.")

    return {"is_unlocked": is_unlocked}
