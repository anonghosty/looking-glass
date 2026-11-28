# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Connectors (the user, 2026-11-24): Looking Glass's own analysis, pushed to the CSIRT's own OpenCTI and MISP.

Looking Glass only sends out (connector_net.py): no TAXII server, no new port. A target is one platform an
administrator sets up in Settings -> Connectors:
- what it is: OpenCTI (its TAXII Push collection) or MISP (its address);
- its key: entered once on the page, kept encrypted in data/connector_keys.enc under CONNECTOR_KEY_SECRET from .env
  (the service may write data/ only; a copy of data/ alone does not give the key away), never in the database, never
  sent back to a page, never logged. A key in .env named on the target (LG_TARGET_<ID>_KEY) is used instead;
- its TLP (AMBER unless chosen) and what it receives: networks of the constituency, whole or some address blocks, and
  other ranges; a new target starts with nothing ticked;
- off when saved; turned on separately.
Everything is tested before it can be saved: the address, the name, the port, the certificate, the key, the platform's
own conditions, then a test send. A failed test cannot be saved (the save needs the test's server-signed pass for
exactly those values; there is no "save anyway"). Turning on, changing or deleting a target asks for the fresh check
every time (stepup.py). The connectors worker (connectors_worker.py) does the sending.
"""
import base64
import calendar
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import threading
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import g, jsonify, request

import connector_net as net
from user_words import Said, words

KINDS = {"opencti": "OpenCTI (TAXII Push)", "misp": "MISP"}
TLPS = ("clear", "green", "amber", "amber+strict", "red")
PASS_SECONDS = 600
ID_RX = re.compile(r"^[a-f0-9]{8}$")
NAME_RX = re.compile(r"[^\w .,'()\-]+")
TAXII = "application/taxii+json;version=2.1"


def env_name(tid):
    return f"LG_TARGET_{tid.upper()}_KEY"


class Vault:
    """The targets' keys, encrypted (AES-GCM, the target's id as associated data) under CONNECTOR_KEY_SECRET."""

    def __init__(self, path, environ=os.environ):
        self.path, self.env, self.lock = path, environ, threading.Lock()

    def ready(self):
        return len((self.env.get("CONNECTOR_KEY_SECRET") or "").strip()) >= 32

    def _aes(self):
        secret = (self.env.get("CONNECTOR_KEY_SECRET") or "").strip()
        if len(secret) < 32:
            raise Said("CONNECTOR_KEY_SECRET is not set in .env (64 random hex characters; the installer makes it).")
        return AESGCM(hashlib.sha256(b"looking-glass connectors|" + secret.encode()).digest())

    def _load(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save(self, d):
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(d, f)
        os.replace(tmp, self.path)

    def put(self, tid, key):
        n = os.urandom(12)
        c = self._aes().encrypt(n, key.encode(), tid.encode())
        with self.lock:
            d = self._load()
            d[tid] = {"n": base64.b64encode(n).decode(), "c": base64.b64encode(c).decode()}
            self._save(d)

    def get(self, tid):
        e = self._load().get(tid)
        if not e:
            return None
        try:
            return self._aes().decrypt(base64.b64decode(e["n"]), base64.b64decode(e["c"]), tid.encode()).decode()
        except Exception:  # noqa: BLE001  (another secret, or a damaged file: no key)
            return None

    def drop(self, tid):
        with self.lock:
            d = self._load()
            if d.pop(tid, None) is not None:
                self._save(d)


class Targets:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()

    def all(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            return d.get("targets") if isinstance(d.get("targets"), dict) else {}
        except (OSError, ValueError, AttributeError):
            return {}

    def get(self, tid):
        return self.all().get(tid)

    def save(self, tid, t):
        with self.lock:
            d = self.all()
            if t is None:
                d.pop(tid, None)
            else:
                d[tid] = t
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"targets": d}, f, indent=1)
            os.replace(tmp, self.path)


def key_of(vault, tid, environ=os.environ):
    """(key, where): a key in .env named for this target first, else the stored one."""
    k = (environ.get(env_name(tid)) or "").strip()
    if k:
        return k, ".env"
    k = vault.get(tid)
    return (k, "stored") if k else (None, "")


# ---------------- the checks, one platform each: [(step, ok, words)]; a check that fails stops the rest
def _check(out, step, fn):
    try:
        result = fn()
        out.append({"step": step, "ok": True, "text": result})
        return True
    except net.Refused as e:
        out.append({"step": e.step or step, "ok": False, "text": words(e)})
    except ValueError as e:
        out.append({"step": step, "ok": False, "text": words(e)})
    return False


def _json(status, body, what):
    if status in (401, 403):
        raise Said(f"The key was refused ({status}): check the key, and that its user is active.")
    if status >= 400:
        raise Said(f"{what} answered {status}.")
    try:
        return json.loads(body or b"{}")
    except ValueError:
        raise Said(f"{what} did not answer with JSON: is this the right address?") from None


def collection_url(address):
    """OpenCTI shows the TAXII Push collection's address; objects are sent to <collection>/objects/."""
    a = address.rstrip("/")
    return a[:-len("/objects")] + "/" if a.endswith("/objects") else a + "/"


def probe(kind, address, key, tlp, send_test=True):
    """Every check, in order, before a target can be saved (and again before each push). Returns (ok, checks)."""
    out = []
    h = {"Accept": "application/json"}

    def reach():
        host, port, _ = net.parse(address)
        ip = net.resolve(host, port)
        return f"{host} is {ip}, port {port}: an address Looking Glass may send to."
    if not _check(out, "address", reach):
        return False, out
    if kind == "opencti":
        col = collection_url(address)
        hh = {"Authorization": f"Bearer {key}", "Accept": TAXII}

        def collection():
            s, b, _ = net.request("GET", col, hh)
            if s == 404:
                # OpenCTI answers 404 for a TAXII Push ingester that exists but is stopped (new ones start stopped;
                # checked on OpenCTI 7.261119)
                raise Said("OpenCTI does not know this collection, or its TAXII Push ingester is stopped. In OpenCTI: "
                                 "Data > Ingestion > TAXII Push, check the address's collection id and start the ingester.")
            j = _json(s, b, "OpenCTI's TAXII collection")
            if not j.get("can_write"):
                raise Said("This TAXII collection does not accept objects from this key's user: in OpenCTI, give "
                                 "the TAXII Push ingester to that user.")
            return f"Certificate trusted, key accepted; the collection \"{j.get('title') or j.get('id')}\" accepts objects."
        if not _check(out, "platform", collection):
            return False, out
        if send_test:
            def test_send():
                import connector_payload
                s, b, _ = net.request("POST", col + "objects/", {**hh, "Content-Type": TAXII},
                                      {"objects": connector_payload.test_objects(tlp)["objects"]})
                if s not in (200, 201, 202):
                    _json(s, b, "The test send")
                    raise Said(f"The test send answered {s}.")
                return "A test object was sent (in OpenCTI: Analyses -> Notes, \"Looking Glass connector test\")."
            if not _check(out, "test send", test_send):
                return False, out
        return True, out
    # MISP
    base = address.rstrip("/")
    hh = {"Authorization": key, **h, "Content-Type": "application/json"}

    def version():
        s, b, _ = net.request("GET", base + "/servers/getVersion", hh)
        j = _json(s, b, "MISP")
        return f"Certificate trusted, key accepted; MISP {j.get('version', '?')}."

    def rights():
        s, b, _ = net.request("GET", base + "/users/view/me", hh)
        j = _json(s, b, "MISP's user")
        role = j.get("Role") or {}
        missing = [w for k, w in (("perm_add", "create events"), ("perm_tagger", "tag"), ("perm_tag_editor", "create tags"))
                   if not role.get(k)]
        if missing:
            raise Said(f"This key's user may not {' or '.join(missing)}: in MISP, give it a role with the Add, Tagger and "
                             "Tag Editor rights only (Administration -> Add Role; no publishing, no sync).")
        if role.get("perm_site_admin") or role.get("perm_admin") or role.get("perm_sync"):
            raise Said("This key's user has more rights than Looking Glass needs (administrator or sync): give it a role "
                             "with the Add, Tagger and Tag Editor rights only.")
        return f"The key's user ({(j.get('User') or {}).get('email', '?')}) may create events, tag them and create the looking-glass tags."

    def taxonomy():
        s, b, _ = net.request("GET", base + "/taxonomies", hh)
        j = _json(s, b, "MISP's taxonomies")
        rows = j if isinstance(j, list) else []
        on = any(((r.get("Taxonomy") or {}).get("namespace") == "tlp" and (r.get("Taxonomy") or {}).get("enabled")) for r in rows)
        if not on:
            raise Said("The tlp taxonomy is not enabled: in MISP, Event Actions -> Taxonomies, enable tlp.")
        return "The tlp taxonomy is enabled."
    for step, fn in (("platform", version), ("rights", rights), ("taxonomy", taxonomy)):
        if not _check(out, step, fn):
            return False, out
    if send_test:
        def test_send():
            import connector_payload
            s, b, _ = net.request("POST", base + "/events/add", hh, connector_payload.misp_test_event(tlp))
            j = _json(s, b, "The test send")
            ev = (j.get("Event") or {})
            return f"A test event was sent (in MISP: event {ev.get('id', '?')}, \"Looking Glass connector test\", unpublished)."
        if not _check(out, "test send", test_send):
            return False, out
    return True, out


def install(app, ctx):
    base = ctx["base_dir"]
    data = os.path.join(base, "data")
    targets = Targets(os.path.join(data, "connectors.json"))
    vault = Vault(os.path.join(data, "connector_keys.enc"))
    paths = {"log": os.path.join(data, "connectors_log.jsonl")}     # a dict: a check points it at a temporary file
    audit, has_perm, csrf_ok, fresh = ctx["audit"], ctx["has_perm"], ctx["csrf_ok"], ctx["fresh"]
    settings = ctx.get("settings")
    full_name = ctx.get("people_name") or (lambda n: "")

    def people_name(u):
        """The full name, else the person code: never the sign-in name (pages and the Audit portal's target list)."""
        import people
        return (full_name(u) or "").strip() or people.person_label(u)
    passes, plock = {}, threading.Lock()
    secret = secrets.token_bytes(32)

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def guard(change=True):
        if not has_perm("settings"):
            return jsonify(error="Only administrators set up connectors."), 403
        if change and not csrf_ok():
            return jsonify(error="Refused (sign in again)."), 403
        if change and not fresh():
            return jsonify(error="Sign in again first (sessions older than 12 hours can only view).", reauth=True), 403
        return None

    def body():
        b = request.get_json(silent=True)
        return b if isinstance(b, dict) else {}

    def clean(b):
        kind = str(b.get("kind") or "")
        if kind not in KINDS:
            raise Said("Choose OpenCTI or MISP.")
        address = str(b.get("address") or "").strip()[:300]
        net.parse(address)
        tlp = str(b.get("tlp") or "amber").lower()
        if tlp not in TLPS:
            raise Said("Choose a TLP: clear, green, amber, amber+strict or red.")
        name = NAME_RX.sub("", str(b.get("name") or "")).strip()[:60] or f"{KINDS[kind].split(' ')[0]} {urlsplit(address).hostname}"
        return kind, address, tlp, name

    def sig(*parts):
        return hmac.new(secret, json.dumps(parts, sort_keys=True).encode(), hashlib.sha256).hexdigest()

    def public(tid, t):
        k, where = key_of(vault, tid)
        return {"id": tid, "name": t["name"], "kind": t["kind"], "kind_name": KINDS[t["kind"]], "address": t["address"],
                "tlp": t["tlp"], "on": bool(t.get("on")), "paused": t.get("paused") or "", "scope": t.get("scope") or {},
                "created": t.get("created"), "created_by": people_name(t.get("created_by") or ""), "last": t.get("last") or {},
                "key": where, "env_name": env_name(tid)}

    @app.route("/api/connectors")
    def api_connectors():
        r = guard(change=False)
        if r:
            return r
        unit = f"{(os.environ.get('LG_SERVICE') or 'looking-glass').strip()}-connectors.timer"
        return jsonify(targets=[public(k, v) for k, v in sorted(targets.all().items(), key=lambda x: x[1].get("created") or 0)],
                       kinds=KINDS, tlps=TLPS, vault_ready=vault.ready(),
                       ca_file=bool((os.environ.get("CONNECTOR_CA_FILE") or "").strip()),
                       # the sender runs as its own timer (deploy/connectors_timer.sh), never inside this service
                       sender_installed=os.path.exists(os.path.join("/etc/systemd/system", unit)), sender_unit=unit)

    @app.route("/api/connectors/test", methods=["POST"])
    def api_connectors_test():
        r = guard(change=True)
        if r:
            return r
        b = body()
        try:
            kind, address, tlp, name = clean(b)
        except (ValueError, net.Refused) as e:
            return jsonify(error=words(e)), 400
        key = str(b.get("key") or "").strip()
        tid = str(b.get("id") or "")
        if not key and ID_RX.match(tid):
            # testing a saved target again: its own key, and only to its own platform at its own address (audit
            # 2026-11-27: a saved key must never be sent to an address typed in the request); another address or
            # platform needs the key entered again
            saved = targets.get(tid) or {}
            if not saved or saved.get("kind") != kind or \
                    str(saved.get("address") or "").strip().rstrip("/") != address.rstrip("/"):
                return jsonify(error="The saved key is only sent to this target's own address: to test another address "
                                     "or platform, enter the key."), 400
            key = key_of(vault, tid)[0] or ""
        if not key or len(key) > 400:
            return jsonify(error="Enter the key (OpenCTI: the user's API token; MISP: the auth key)."), 400
        ok, checks = probe(kind, address, key, tlp)
        audit.add("connector_tested", user=me(), target=address, detail=f"{kind}: {'all checks passed' if ok else checks[-1]['text'][:160]}")
        out = {"ok": ok, "checks": checks}
        if ok:
            token = secrets.token_urlsafe(24)
            with plock:
                now = time.time()
                for k in [k for k, v in passes.items() if now - v["at"] > PASS_SECONDS]:
                    passes.pop(k, None)
                passes[token] = {"at": now, "user": me(), "sig": sig(kind, address, tlp, hashlib.sha256(key.encode()).hexdigest(), tid)}
            out["pass"] = token
        return jsonify(out)

    @app.route("/api/connectors", methods=["POST"])
    def api_connectors_save():
        r = guard(change=True)
        if r:
            return r
        if not vault.ready():
            return jsonify(error="Set CONNECTOR_KEY_SECRET in .env first (64 random hex characters), then restart."), 400
        b = body()
        try:
            kind, address, tlp, name = clean(b)
        except (ValueError, net.Refused) as e:
            return jsonify(error=words(e)), 400
        key = str(b.get("key") or "").strip()
        with plock:
            p = passes.pop(str(b.get("pass") or ""), None)
        if not p or p["user"] != me() or time.time() - p["at"] > PASS_SECONDS \
                or p["sig"] != sig(kind, address, tlp, hashlib.sha256(key.encode()).hexdigest(), ""):
            return jsonify(error="Test these exact values first: only a target whose test passed can be saved."), 400
        tid = secrets.token_hex(4)
        vault.put(tid, key)
        targets.save(tid, {"name": name, "kind": kind, "address": address, "tlp": tlp, "on": False, "scope": {},
                           "created": int(time.time()), "created_by": me()})
        audit.add("connector_saved", user=me(), target=name, detail=f"{KINDS[kind]} at {address}, TLP:{tlp.upper()}, off, nothing ticked")
        return jsonify(ok=True, target=public(tid, targets.get(tid)))

    def one(tid):
        t = targets.get(tid) if ID_RX.match(tid or "") else None
        return t

    @app.route("/api/connectors/<tid>/scope", methods=["POST"])
    def api_connectors_scope(tid):
        r = guard(change=True)
        if r:
            return r
        t = one(tid)
        if not t:
            return jsonify(error="No such target."), 404
        b = body()
        try:
            scope = clean_scope(b.get("scope") or {}, settings)
        except ValueError as e:
            return jsonify(error=words(e)), 400
        t["scope"] = scope
        targets.save(tid, t)
        audit.add("connector_scope", user=me(), target=t["name"], detail=scope_words(scope))
        return jsonify(ok=True, target=public(tid, t))

    @app.route("/api/connectors/<tid>/tlp", methods=["POST"])
    def api_connectors_tlp(tid):
        r = guard(change=True)
        if r:
            return r
        t = one(tid)
        tlp = str(body().get("tlp") or "").lower()
        if not t or tlp not in TLPS:
            return jsonify(error="No such target or TLP."), 400
        t["tlp"] = tlp
        targets.save(tid, t)
        audit.add("connector_tlp", user=me(), target=t["name"], detail=f"TLP:{tlp.upper()}")
        return jsonify(ok=True, target=public(tid, t))

    @app.route("/api/connectors/<tid>/<action>", methods=["POST"])
    def api_connectors_action(tid, action):
        r = guard(change=True)
        if r:
            return r
        t = one(tid)
        if not t or action not in ("on", "off", "delete", "key"):
            return jsonify(error="No such target or action."), 404
        if action == "on":
            key = key_of(vault, tid)[0]
            if not key:
                return jsonify(error="This target has no key: enter it again."), 400
            if not (t.get("scope") or {}).get("networks") and not (t.get("scope") or {}).get("cidrs"):
                return jsonify(error="Tick what this target receives first: nothing is ticked."), 400
            ok, checks = probe(t["kind"], t["address"], key, t["tlp"], send_test=False)
            if not ok:
                return jsonify(error="The checks did not pass: " + checks[-1]["text"], checks=checks), 400
            t.update(on=True, paused="", turned_on=int(time.time()), turned_on_by=me())
            audit.add("connector_on", user=me(), target=t["name"], detail=f"{scope_words(t.get('scope') or {})}; back-fill of 30 days starts")
        elif action == "off":
            t.update(on=False)
            audit.add("connector_off", user=me(), target=t["name"])
        elif action == "key":
            key = str(body().get("key") or "").strip()
            if not key or len(key) > 400:
                return jsonify(error="Enter the new key."), 400
            ok, checks = probe(t["kind"], t["address"], key, t["tlp"], send_test=False)
            if not ok:
                return jsonify(error="The new key did not pass: " + checks[-1]["text"], checks=checks), 400
            vault.put(tid, key)
            audit.add("connector_key", user=me(), target=t["name"], detail="key replaced (tested)")
        else:
            targets.save(tid, None)
            vault.drop(tid)
            audit.add("connector_deleted", user=me(), target=t["name"], detail="target and its stored key removed")
            return jsonify(ok=True)
        targets.save(tid, t)
        return jsonify(ok=True, target=public(tid, t))

    @app.route("/api/connectors/<tid>/log")
    def api_connectors_log(tid):
        r = guard(change=False)
        if r:
            return r
        # the newest 200 by default, up to LOG_MAX with ?n= ("Show all" on the page); the full count beside them, so the
        # page says "30 of N" and never passes a cut list as the whole log (2026-11-26)
        try:
            n = max(1, min(LOG_MAX, int(request.args.get("n") or 200)))
        except ValueError:
            n = 200
        return jsonify(log=read_log(paths["log"], tid, n), totals={"log": log_total(paths["log"], tid)})

    @app.route("/api/audit/connectors")
    def api_audit_connectors():
        """Data sent out (the Audit portal, read only; the user 2026-11-24, 4.6a): every target as it is set up (platform,
        address, TLP, what it receives, on, paused, who added it and when) and what went out in the period chosen (from,
        to: YYYY-MM-DD, UTC, both days included): each send, retry, revocation and failure. Never a key."""
        if not (has_perm("audit") or has_perm("settings")):
            return jsonify(error="Refused."), 403

        def day_ts(v, end):
            try:
                # the day in UTC whatever the server's time zone (time.mktime - time.timezone was an hour off in summer)
                t = calendar.timegm(time.strptime(str(v), "%Y-%m-%d"))
                return t + 86400 if end else t
            except (TypeError, ValueError, OverflowError):
                return None
        lo, hi = day_ts(request.args.get("from"), False), day_ts(request.args.get("to"), True)
        all_t = targets.all()
        rows = []
        for tid, t in sorted(all_t.items(), key=lambda x: x[1].get("created") or 0):
            rows.append({"name": t["name"], "kind": KINDS.get(t["kind"], t["kind"]), "address": t["address"],
                         "tlp": t["tlp"].upper(), "receives": scope_words(t.get("scope") or {}), "on": bool(t.get("on")),
                         "paused": t.get("paused") or "", "added_by": people_name(t.get("created_by") or ""),
                         "added": t.get("created")})
        events = [dict(e, target_name=(all_t.get(e.get("target")) or {}).get("name", e.get("target")))
                  # every entry of the log (the file is read whole either way): the period's figures count every send,
                  # not only those among the newest 5,000 entries (2026-11-26)
                  for e in read_log(paths["log"], None, None)
                  if (lo is None or e.get("at", 0) >= lo) and (hi is None or e.get("at", 0) < hi)]
        sends = [e for e in events if e.get("status") == "sent"]
        return jsonify(targets=rows, events=events[:1000], more=max(0, len(events) - 1000),
                       totals={"sends": len(sends), "devices": sum(int(e.get("devices") or 0) for e in sends),
                               "objects": sum(int(e.get("objects") or 0) for e in sends),
                               "revoked": sum(int(e.get("revoked") or 0) for e in events),
                               "failed": sum(1 for e in events if e.get("status") in ("failed", "refused", "paused"))})

    return {"targets": targets, "vault": vault, "paths": paths, "log_path": paths["log"], "probe": probe}


def clean_scope(s, settings):
    """{"networks": {asn: "whole" | [/24 blocks]}, "cidrs": [ranges]}: only what the constituency holds."""
    restricted = bool(getattr(settings, "restricted", False))
    allowed_asns = {int(a) for a in (getattr(settings, "asns", None) or []) if str(a).isdigit()} if restricted else None
    out = {"networks": {}, "cidrs": []}
    for asn, v in (s.get("networks") or {}).items():
        try:
            a = int(str(asn).upper().replace("AS", ""))
        except ValueError:
            raise Said(f"{asn} is not an AS number.") from None
        if allowed_asns is not None and a not in allowed_asns and not any(
                getattr(settings, "in_scope", lambda *_: False)(a, b.split("/")[0]) for b in (v if isinstance(v, list) else [])):
            raise Said(f"AS{a} is not in the constituency.")
        if v == "whole":
            out["networks"][str(a)] = "whole"
        elif isinstance(v, list) and v:
            blocks = []
            for b in v[:4096]:
                n = ipaddress.ip_network(str(b), strict=True)
                if n.version == 4 and n.prefixlen != 24:
                    raise Said(f"{b}: address blocks are /24.")
                blocks.append(str(n))
            out["networks"][str(a)] = sorted(set(blocks))
    own = {str(ipaddress.ip_network(c, strict=False)) for c in ((getattr(settings, "data", None) or {}).get("cidrs") or [])}
    for c in (s.get("cidrs") or [])[:4096]:
        try:
            n = str(ipaddress.ip_network(str(c), strict=False))
        except ValueError:
            raise Said(f"{c} is not an address range.") from None
        if restricted and n not in own:
            raise Said(f"{n} is not one of the constituency's other address ranges.")
        out["cidrs"].append(n)
    return out


def scope_words(scope):
    n = scope.get("networks") or {}
    whole = sum(1 for v in n.values() if v == "whole")
    part = sum(1 for v in n.values() if isinstance(v, list))
    c = len(scope.get("cidrs") or [])
    if not (whole or part or c):
        return "nothing ticked"
    return ", ".join(x for x in (f"{whole} whole network(s)" if whole else "", f"{part} network(s) in part" if part else "",
                                 f"{c} other range(s)" if c else "") if x)


def in_scope(scope, asn, ip):
    """True when a device (its network and address) is in what this target receives."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    v = (scope.get("networks") or {}).get(str(asn or ""))
    if v == "whole":
        return True
    if isinstance(v, list) and any(addr in ipaddress.ip_network(b) for b in v):
        return True
    return any(addr in ipaddress.ip_network(c) for c in scope.get("cidrs") or [])


def read_log(path, tid=None, n=200):
    out = []
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if tid is None or e.get("target") == tid:
                    out.append(e)
    except OSError:
        return []
    return (out if n is None else out[-n:])[::-1]          # n None: every entry, newest first


LOG_MAX = 5000                 # the most send-log entries one answer holds (the page's "Show all")


def log_total(path, tid=None):
    """How many send-log entries there are for a target (every one, not only those sent back)."""
    n = 0
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if tid is None or e.get("target") == tid:
                    n += 1
    except OSError:
        return 0
    return n
