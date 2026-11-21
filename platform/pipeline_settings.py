"""Settings → Workers: the database pipeline's settings, changed from the web app.

What is here (2026-11-12, at the user's request): how the reports are fetched (e-mail or Shadowserver's report API),
the sender check (record only, or block reports whose DKIM signature does not pass), e-mail fetching, loading
performance and the unzip limits; the Shadowserver API key; the reports held back by the sender check. Mailbox and
database passwords, the mailbox address and the server are never shown or changed here.

The platform never writes the pipeline's files (external review, 2026-11-12). Its service is hardened
(ProtectSystem=strict, ProtectHome=read-only, ReadWritePaths=<platform>/data), and the web app should not be able to
rewrite the pipeline's configuration anyway. A change is a REQUEST written into the platform's own
data/pipeline_requests/; the pipeline checks it again with the same rules (worker_settings.py, the pipeline's own module,
loaded read-only from its folder: one copy of the rules) and applies it at the start of its next run (within about 30
minutes with the usual schedule), then writes the result back. The page shows what is waiting and what was applied or
refused; each result is recorded in the audit log.

A request that makes the pipeline LESS strict (the sender check lowered or another signer, the certificate check off, a
new API key, a release) is not applied on this page's word alone: the pipeline holds it until someone confirms it on
the server, on the pipeline's account (./confirm_request.sh <id>; worker_settings.weakens decides). This page says so
and shows the command; a compromised web app can then only make the pipeline stricter.

Locked by default. A request needs the Settings permission AND the signed-in administrator's own password again (unlock,
10 minutes, this session only; a wrong password counts as a failed sign-in). Saving locks it again. Every unlock, failed
unlock, request (old → new value), API key, release and result is in the audit log.

The Shadowserver API key and secret: write-only. Shadowserver checks them first (test/ping and reports/subscribed,
signed with the secret as Shadowserver's API requires); only accepted ones become a request. The request file holds them
(mode 600, in a folder only this account can open) until the pipeline applies it and deletes it; results never hold them.
"""
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.request

import https_only

from flask import g, jsonify, request

import password_policy
import pipeline_link
import report_files

UNLOCK_SECONDS = 600
API_URL = os.environ.get("SHADOWSERVER_API_URL", "https://transform.shadowserver.org/api2/")
API_KEYS = ("SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET")
NOT_HERE = "The database pipeline is not on this computer: its settings are in its own .env."


def _api(method, key, secret, url=None, timeout=15):
    """(answer, error): one call to Shadowserver's report API, the JSON body (with apikey) signed with HMAC-SHA256 of
    the secret in the HMAC2 header, as Shadowserver documents it. The key and secret never appear in an error."""
    base = (url or API_URL).rstrip("/")
    if not base.lower().startswith("https://"):       # SHADOWSERVER_API_URL comes from .env: the key goes only over https
        return None, "The report API address must start with https://."
    body = json.dumps({"apikey": key}).encode()
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(base + "/" + method, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "HMAC2": sig, "User-Agent": "LookingGlass"})
    try:
        with https_only.open(req, timeout=timeout) as r:     # redirects away from https refused too
            return json.loads(r.read(65536).decode("utf-8", "replace") or "null"), ""
    except https_only.NotHttps:
        return None, "Shadowserver's answer redirected away from https; the call was stopped."
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
    hp, audit = ctx["has_perm"], ctx["audit"]           # users, throttle, client: password_policy.check_own_password
    unlocked = {}                                           # (user, session csrf) -> until

    def ddir():                                             # the platform's own data folder, looked up on each use
        return ctx["data_dir"]

    def api_state_file():
        return os.path.join(ddir(), "pipeline_api.json")

    def logged_file():
        return os.path.join(ddir(), "pipeline_requests.logged.json")     # outside the requests folder the pipeline reads

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
        if unlocked.get(sk, 0) and unlocked[sk] < time.time():
            unlocked.pop(sk, None)
        return unlocked.get(sk, 0) > time.time()

    def need_unlock():
        if not is_unlocked():
            return jsonify(error="Locked: enter your password (Edit) first.", locked=True), 403
        return None

    def pipe():
        """(pipeline folder, its worker_settings module) or (None, None)."""
        d = pipeline_link.find_dir(ctx["base_dir"])
        return (d, pipeline_link.worker_settings(d)) if d else (None, None)

    def api_state():
        try:
            with open(api_state_file(), encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def save_api_state(st):
        tmp = api_state_file() + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(st, fh)
        os.replace(tmp, api_state_file())

    def log_results(ws):
        """Each result the pipeline wrote back goes into the audit log once (applied or refused, and what changed)."""
        try:
            with open(logged_file(), encoding="utf-8") as fh:
                done = set(json.load(fh))
        except (OSError, ValueError):
            done = set()
        new = [r for r in ws.results(ddir(), limit=200) if r.get("id") and r["id"] not in done]
        for r in reversed(new):
            audit.add("pipeline_request_" + ("applied" if r.get("status") == "applied" else "refused"), user=r.get("by", ""),
                      target=r["id"], detail=(f"{r.get('kind')}: " + ("; ".join(r.get("changed") or []) or r.get("reason") or "nothing changed")
                                              + (f" | confirmed on the server by {r['confirmed_on_server']}" if r.get("confirmed_on_server") else ""))[:900])
            done.add(r["id"])
        if new:
            os.makedirs(os.path.dirname(logged_file()), mode=0o700, exist_ok=True)
            tmp = logged_file() + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(sorted(done)[-2000:], fh)
            os.replace(tmp, logged_file())

    def weak(ws, req, env):
        """Why the pipeline will hold this request for confirmation on the server ([] = applied at the next run).
        An older pipeline without the rule: [] (it applies as before)."""
        f = getattr(ws, "weakens", None)
        return f(req, env) if f else []

    def waiting_list(ws, d, env):
        base = os.path.realpath(os.path.expanduser(env.get("DATA_DIR") or str(d)))    # the pipeline's DATA_DIR, as it uses it
        try:
            return ws.pending(ddir(), env, base)
        except TypeError:                                   # an older pipeline: no confirmation step
            return ws.pending(ddir())

    def confirm_note(ws, d, rid, why):
        cmd = ws.confirm_command(rid) if hasattr(ws, "confirm_command") else f"./confirm_request.sh {rid}"
        return (f"Requested and locked. This makes the pipeline less strict ({'; '.join(why)}), so it waits for "
                f"confirmation on the server: on the pipeline's account, in {d}, run {cmd} . The next run after that applies it.")

    def requested(ws, kind, payload, detail, why=()):
        rid = ws.make_request(ddir(), kind, payload, me()[0])
        audit.add("pipeline_change_requested", user=me()[0], target=rid,
                  detail=(f"{kind}: {detail}" + (f" | waits for confirmation on the server: {'; '.join(why)}" if why else ""))[:900])
        unlocked.pop(me()[1], None)                         # saved: locked again
        return rid

    @app.route("/api/pipeline/settings")
    def api_pipeline_settings():
        bad = guard()
        if bad:
            return bad
        d, ws = pipe()
        if not ws:
            return jsonify(found=False, message=NOT_HERE)
        log_results(ws)
        env = pipeline_link.read_env(d / ".env")
        provider = (env.get("MAIL_PROVIDER") or "imap").lower()
        waiting = waiting_list(ws, d, env)
        key_waiting = any(r.get("kind") == "apikey" for r in waiting)
        st = api_state()
        _, sk = me()
        return jsonify(found=True, provider=provider, unlocked=is_unlocked(),
                       unlocked_for=max(0, int(unlocked.get(sk, 0) - time.time())) if is_unlocked() else 0,
                       groups=[{"key": k, "label": lab} for k, lab in ws.GROUPS],
                       fields=[{"key": f[0], "group": f[1], "label": f[2], "kind": f[3], "default": f[4],
                                "choices": [{"value": c, "label": ws.CHOICE_LABELS.get(f[0], {}).get(c, c)} for c in f[5]] if f[3] == "choice" else None,
                                "min": f[5] if f[3] == "int" else None, "max": f[6] if f[3] == "int" else None,
                                "help": f[7], "value": env.get(f[0], f[4])}
                               for f in ws.FIELDS if not f[8] or f[8] == provider],
                       pending=waiting, results=ws.results(ddir(), limit=8), pipeline_dir=str(d),
                       api={"key_set": bool(env.get(API_KEYS[0]) and env.get(API_KEYS[1])), "key_waiting": key_waiting,
                            "checked_at": st.get("checked_at"), "ok": st.get("ok"), "message": st.get("message", "")})

    @app.route("/api/pipeline/unlock", methods=["POST"])
    def api_pipeline_unlock():
        bad = guard(change=True)
        if bad:
            return bad
        name, sk = me()
        bad = password_policy.check_own_password(ctx, "pipeline_unlock_failed", "Settings → Workers: wrong password",
                                                 need="Unlocking needs a signed-in administrator's own password.")
        if bad:
            return bad
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

    @app.route("/api/pipeline/settings", methods=["POST"])
    def api_pipeline_settings_save():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d, ws = pipe()
        if not ws:
            return jsonify(error=NOT_HERE), 404
        env = pipeline_link.read_env(d / ".env")
        provider = (env.get("MAIL_PROVIDER") or "imap").lower()
        clean, errors = ws.validate((request.get_json(silent=True) or {}).get("values"), provider)
        if errors:
            return jsonify(error="; ".join(errors)), 400
        key_ok = (env.get(API_KEYS[0]) and env.get(API_KEYS[1])) or any(r.get("kind") == "apikey" for r in ws.pending(ddir()))
        if clean.get("REPORT_SOURCE") == "api" and not key_ok:
            return jsonify(error="Save the Shadowserver API key (below) before choosing the API: Shadowserver checks it first."), 400
        changed = {k: v for k, v in clean.items() if env.get(k, ws.SPEC[k][4]) != v}
        if not changed:
            unlocked.pop(me()[1], None)
            return jsonify(ok=True, changed=[], note="Nothing had changed. Locked again.")
        why = weak(ws, {"kind": "settings", "values": changed}, env)
        rid = requested(ws, "settings", {"values": changed},
                        "; ".join(f"{k}: {env.get(k, ws.SPEC[k][4])} → {v}" for k, v in changed.items()), why)
        return jsonify(ok=True, changed=sorted(changed), request=rid, confirm=bool(why),
                       note=confirm_note(ws, d, rid, why) if why else
                       "Requested and locked: the pipeline checks and applies it at its next run (within about 30 minutes).")

    @app.route("/api/pipeline/apikey", methods=["POST"])
    def api_pipeline_apikey():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d, ws = pipe()
        if not ws:
            return jsonify(error=NOT_HERE), 404
        b = request.get_json(silent=True) or {}
        key, secret = str(b.get("key") or "").strip(), str(b.get("secret") or "").strip()
        if not ws.valid_api(key, secret):
            return jsonify(error="Paste the API key and the secret exactly as Shadowserver gave them."), 400
        ok, msg = ping(key, secret)
        now = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
        audit.add("pipeline_apikey_checked", user=me()[0], detail=f"new Shadowserver API key: {'accepted' if ok else 'refused'} ({msg})"[:300])
        if not ok:
            return jsonify(error=f"Not saved: {msg}"), 400
        why = weak(ws, {"kind": "apikey"}, {})
        rid = requested(ws, "apikey", {"key": key, "secret": secret}, "Shadowserver API key and secret (values not logged)", why)
        save_api_state({"checked_at": now, "ok": True, "message": msg})
        return jsonify(ok=True, message=msg, checked_at=now, request=rid, confirm=bool(why),
                       note=confirm_note(ws, d, rid, why) if why else "The pipeline saves it at its next run (within about 30 minutes).")

    @app.route("/api/pipeline/apikey/check", methods=["POST"])
    def api_pipeline_apikey_check():
        bad = guard(change=True)
        if bad:
            return bad
        d, _ = pipe()
        env = pipeline_link.read_env(d / ".env") if d else {}
        if not (env.get(API_KEYS[0]) and env.get(API_KEYS[1])):
            return jsonify(error="No API key saved yet (one waiting for the pipeline's next run is checked then)."), 404
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
        d, ws = pipe()
        ma = pipeline_link.mail_auth(d)
        if not ma:
            return jsonify(held=[])
        asked = set()
        for r in (ws.pending(ddir()) if ws else []):
            if r.get("kind") == "release":
                asked.update(x for x in ([r.get("qid")] + list(r.get("qids") or [])) if x)
        # the reports' readable names come from the report database; without it (down, or not yet set up) the list still
        # shows every held-back report, by its Shadowserver file name only
        try:
            labels = ctx["labels"]() if ctx.get("labels") else {}
        except Exception as exc:  # noqa: BLE001 - any database failure: the names are a nicety, the list is not
            labels = {}
            app.logger.warning("Held-back reports listed without readable report names: %s", type(exc).__name__)
        out = []
        for q, m in ma.held(pipeline_link.data_dir(d)):
            out.append({"id": q.name, "at": m.get("at"), "result": m.get("result"), "reason": m.get("reason"),
                        "hint": ma.hint(m.get("result"), m.get("reason")) if hasattr(ma, "hint") else "",
                        "from_domain": m.get("from_domain"), "signer": m.get("signer"), "subject": m.get("subject"),
                        "files": len(m.get("files") or []), "links": len(m.get("links") or []),
                        # the report files by their Shadowserver names (the user, 2026-11-15), flagged when not one
                        "names": [report_files.parse(n, labels) for n in (m.get("files") or [])[:200]],
                        "release_asked": (q / ma.RELEASE_FILE).exists() or q.name in asked})
        return jsonify(held=out, mode=ma.mode(pipeline_link.read_env(d / ".env")))

    @app.route("/api/pipeline/sender-week")
    def api_pipeline_sender_week():
        """The sender check over the last 7 days, day by day, and whether blocking can be switched on (2026-11-15)."""
        bad = guard()
        if bad:
            return bad
        d, _ = pipe()
        ma = pipeline_link.mail_auth(d)
        if not (ma and hasattr(ma, "readiness")):
            return jsonify(found=False)
        week = ma.readiness(pipeline_link.data_dir(d) / ".mail_state.sqlite")
        return jsonify(found=bool(week), mode=ma.mode(pipeline_link.read_env(d / ".env")), **(week or {}))

    @app.route("/api/pipeline/release", methods=["POST"])
    def api_pipeline_release():
        bad = guard(change=True) or need_unlock()
        if bad:
            return bad
        d, ws = pipe()
        ma = pipeline_link.mail_auth(d)
        body = request.get_json(silent=True) or {}
        # one report ("id") or several chosen on the page ("ids", the user 2026-11-15: one by one, or all)
        raw = body.get("ids") if isinstance(body.get("ids"), list) else [body.get("id")]
        ids = list(dict.fromkeys(str(x or "") for x in raw))
        held_now = {q.name: m for q, m in (ma.held(pipeline_link.data_dir(d)) if ma else [])}
        if not (ws and ids and len(ids) <= 500 and all(re.fullmatch(r"[0-9a-f]{20}", i) and i in held_now for i in ids)):
            return jsonify(error="No such held-back report." if len(ids) < 2 else
                           "One of the chosen reports is no longer held back: reload the list and choose again."), 404
        why = weak(ws, {"kind": "release"}, {})
        if hasattr(ws, "release_ids"):           # one request for all of them: one confirmation on the server
            rids = [ws.make_request(ddir(), "release", {"qids": ids, "qid": ids[0]}, me()[0])]
        else:                                    # a pipeline from before 2026-11-15 reads one id per request
            rids = [ws.make_request(ddir(), "release", {"qid": i}, me()[0]) for i in ids]
        for i in ids:
            m = held_now[i]
            audit.add("sender_release", user=me()[0], target=i,
                      detail=f"release requested ({m.get('result')}: {m.get('reason')}) | "
                             f"{', '.join(m.get('files') or [])[:200] or (m.get('subject') or '')[:120]}"
                             + (f" | request {', '.join(rids)} waits for confirmation on the server" if why else ""))
        rid = rids[0]
        many = f"{len(ids)} reports" if len(ids) > 1 else "the report"
        return jsonify(ok=True, request=rid, requests=rids, confirm=bool(why), count=len(ids),
                       note=confirm_note(ws, d, rid, why) if why and len(rids) == 1 else
                       (f"Release of {many} requested; each request waits for confirmation on the server: "
                        + "; ".join(confirm_note(ws, d, r, why) for r in rids)) if why else
                       f"Release of {many} requested: the pipeline's next run processes {'them' if len(ids) > 1 else 'it'}.")

    return {"is_unlocked": is_unlocked, "ctx": ctx}      # ctx: the checks point data_dir at a temporary folder
