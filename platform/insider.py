"""Making misuse by people who may see the data traceable (the user's insider package, 2026-11-18).

* Copies are recorded BEFORE they happen (fail closed): the page's copy buttons ask POST /api/copy/record first and copy
  only when it answers; when the copy cannot be recorded, nothing is copied (static/js/lg-copy.js). Every copy is one
  audit entry ("copied", the Audit portal's Copies tab): who, what kind of thing, how many lines and addresses, which
  page, when, and its seal's reference. NEVER the copied text: the audit log must not become a second copy of the data
  (the data_access.py rule).
* Each copy and each downloaded file is sealed (data/copy_seals.jsonl): keyed fingerprints (HMAC-SHA-256, the key in
  COPY_SEAL_KEY in .env or, when that is not set, data/copy_seal.key, owner-only, made at the first start) of the whole
  text, of each line and of each IP address in it; a download also gets the SHA-256 of the exact file, and of each file
  in a ZIP. Fingerprints only: no text, no address can be read back from them, and without the key they cannot be
  tested against guesses.
* "Trace a leak" (the Audit portal; auditors and administrators): text pasted or a file dropped there is fingerprinted
  in memory the same way and thrown away; the answer is every copy and download it matches, with who, when and what,
  exactly or by how many of its lines and addresses. Each trace is in the audit log ("leak_traced": who, when, how many
  matches; never what was searched) and at most TRACE_PER_MINUTE are answered a minute per person, so it cannot be used
  to test guesses.
* A person's own recovery codes are recorded as copied, without any fingerprint (they are the person's secret).
* Every page header names the person signed in by their registered full name (template value lg_name).

Limits, said plainly: blocking text selection and copying in the browser deters; a technical user can still get round it
(the browser's developer tools, the page source, a photo of the screen). The seals cap the lines and addresses kept per
copy or file at SEAL_ITEMS_MAX (the whole text or file is always fingerprinted, and the entry says when lines were left
out); seals older than the audit log's retention (AUDIT_RETENTION_DAYS) are removed.
Installed from features.py: insider.install(app, ctx).
"""
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import threading
import time
import zipfile

from flask import g, jsonify, request

import ip_find

SEAL_ITEMS_MAX = 50000          # lines + addresses kept per copy or file (the whole is always sealed)
TEXT_MAX = 5_000_000            # characters a copy may carry to be recorded
TRACE_MAX_BYTES = 25_000_000    # a file or text given to Trace a leak
TRACE_PER_MINUTE = 5
BODY_LIMITS = {"/api/copy/record": 12_000_000, "/api/audit/trace": TRACE_MAX_BYTES + 1_000_000}
COMMON_SHARE = 0.2              # a line in more than this share of the seals (a CSV header) does not count as a match
KINDS = {"event": "an event's details", "record": "a record's details", "addresses": "addresses", "code": "a code",
         "indicators": "indicator values", "note": "a note", "text": "text", "recovery": "recovery codes",
         "invite": "a sign-up link"}
SECRET_KINDS = ("recovery", "invite")        # recorded as copied, never fingerprinted: they are secrets


def _hid(n=4):
    return "S-" + secrets.token_hex(n)


def normal(text):
    """The text as it is compared: line ends unified, spaces at line ends and around the whole removed."""
    t = str(text or "").replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(ln.rstrip() for ln in t.split("\n")).strip()


class Sealer:
    def __init__(self, key, path):
        self.key, self.path, self.lock = key, path, threading.Lock()

    def h(self, kind, s):
        return hmac.new(self.key, (kind + ":" + s).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:24]

    def items(self, text):
        """(line fingerprints, address fingerprints) of a text."""
        lines, addrs, seen_l, seen_a = [], [], set(), set()
        for ln in normal(text).split("\n"):
            s = ln.strip()
            if len(s) >= 4 and s not in seen_l:
                seen_l.add(s); lines.append(self.h("L", s))
        for _a, _b, ip in ip_find.spans(text):            # an address on a line of its own is both a line and an address
            if ip not in seen_a:
                seen_a.add(ip); addrs.append(self.h("A", ip))
        return lines, addrs

    def seal_text(self, text):
        t = normal(text)
        lines, addrs = self.items(t)
        return {"whole": self.h("T", t), "lines": len(lines), "addresses": len(addrs), "items": (addrs + lines)}

    def seal_file(self, data, name=""):
        """A downloaded file: its SHA-256, and its text's (a ZIP: each file's) fingerprints."""
        out = {"sha256": hashlib.sha256(data).hexdigest(), "files": [], "items": [], "lines": 0, "addresses": 0}
        parts = [(name, data)]
        if data[:2] == b"PK":
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as z:
                    parts = []
                    for zi in z.infolist()[:200]:
                        if zi.file_size <= TRACE_MAX_BYTES * 4:
                            b = z.read(zi)
                            out["files"].append({"name": zi.filename[:120], "sha256": hashlib.sha256(b).hexdigest()})
                            parts.append((zi.filename, b))
            except (zipfile.BadZipFile, OSError, RuntimeError):
                parts = [(name, data)]
        for n, b in parts:
            if b[:4] == b"%PDF" or b[:2] == b"PK":
                continue                                    # a PDF: its SHA-256 only
            try:
                txt = b.decode("utf-8-sig")
            except UnicodeDecodeError:
                continue
            s = self.seal_text(txt)
            out["items"] += s["items"]; out["lines"] += s["lines"]; out["addresses"] += s["addresses"]
            out.setdefault("wholes", []).append(s["whole"])
        return out

    def write(self, entry):
        """Append one seal (fail closed: raises OSError when it cannot be written)."""
        items = list(dict.fromkeys(entry.pop("items", [])))
        entry["items_total"] = len(items)
        entry["items"] = items[:SEAL_ITEMS_MAX]
        entry["cut"] = len(items) > SEAL_ITEMS_MAX
        line = json.dumps(entry, separators=(",", ":")) + "\n"
        with self.lock:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()
                os.fsync(fh.fileno())
        return entry

    def all(self):
        try:
            with open(self.path, encoding="utf-8") as fh:
                for ln in fh:
                    try:
                        yield json.loads(ln)
                    except ValueError:
                        continue
        except OSError:
            return

    def prune(self, keep_days):
        """Seals older than keep_days removed (the audit log's retention)."""
        cut = time.time() - keep_days * 86400
        with self.lock:
            try:
                with open(self.path, encoding="utf-8") as fh:
                    lines = fh.readlines()
            except OSError:
                return 0
            keep = [ln for ln in lines if (json.loads(ln).get("t") or 0) >= cut] if lines else []
            if len(keep) == len(lines):
                return 0
            tmp = self.path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.writelines(keep)
            os.replace(tmp, self.path)
            return len(lines) - len(keep)

    def trace(self, text=None, data=None):
        """Every seal the text or file matches: [{seal, exact, lines, addresses, of}], the closest first."""
        q_whole, q_sha, q_items = set(), set(), set()
        if data is not None:
            f = self.seal_file(data)
            q_sha.add(f["sha256"]); q_sha.update(x["sha256"] for x in f["files"])
            q_whole.update(f.get("wholes") or []); q_items.update(f["items"])
        if text:
            s = self.seal_text(text)
            q_whole.add(s["whole"]); q_items.update(s["items"])
        seals = list(self.all())
        freq = {}
        for s in seals:
            for i in s.get("items") or []:
                if i in q_items:
                    freq[i] = freq.get(i, 0) + 1
        common = {i for i, n in freq.items() if len(seals) > 4 and n > COMMON_SHARE * len(seals)}
        out = []
        for s in seals:
            exact = s.get("whole") in q_whole or bool(set(s.get("wholes") or []) & q_whole) \
                or s.get("sha256") in q_sha or any(x.get("sha256") in q_sha for x in s.get("files") or [])
            hit = [i for i in s.get("items") or [] if i in q_items and i not in common]
            if not exact and not hit:
                continue
            out.append({"seal": s, "exact": exact, "matched": len(hit), "of": s.get("items_total") or len(s.get("items") or [])})
        out.sort(key=lambda r: (not r["exact"], -r["matched"], -(r["seal"].get("t") or 0)))
        return out, len(common)


def load_key(base_dir):
    """COPY_SEAL_KEY from .env, else data/copy_seal.key (made once, owner-only)."""
    k = os.environ.get("COPY_SEAL_KEY", "").strip()
    if k:
        return k.encode()
    p = os.path.join(base_dir, "data", "copy_seal.key")
    if not os.path.exists(p):
        os.makedirs(os.path.dirname(p), exist_ok=True)
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(secrets.token_urlsafe(48))
        except FileExistsError:
            pass
    with open(p) as fh:
        return fh.read().strip().encode()


def install(app, ctx):
    """ctx: base_dir, has_perm, csrf_ok, audit, people_name (username -> full name)."""
    hp, audit = ctx["has_perm"], ctx["audit"]
    sealer = Sealer(load_key(ctx["base_dir"]), os.path.join(ctx["base_dir"], "data", "copy_seals.jsonl"))
    traced = {}                                        # user -> [times] (Trace a leak's limit)
    full = ctx.get("people_name") or (lambda u: "")

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def name_of(u):
        return full(u) or u

    try:
        sealer.prune(int(float(os.environ.get("AUDIT_RETENTION_DAYS", "400") or 400)))
    except (OSError, ValueError):
        pass

    # the platform takes request bodies of 64 KB at most (security.py, report #7); a long list copied and a file traced
    # are larger, so these two take more, and only from someone signed in (Trace a leak: with the 'audit' permission)
    @app.before_request
    def _bigger_body():
        lim = BODY_LIMITS.get(request.path)
        if lim and request.method == "POST" and me() and (request.path != "/api/audit/trace" or hp("audit")):
            request.max_content_length = lim

    @app.context_processor
    def _signed_in_name():
        u = me()
        return {"lg_name": name_of(u) if u else ""}

    # ------------------------------------------------------------------ a copy, recorded before it happens
    @app.route("/api/copy/record", methods=["POST"])
    def api_copy_record():
        u = me()
        if not u:
            return jsonify(error="Sign in again."), 401
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True) or {}
        kind = str(b.get("kind") or "text")
        if kind not in KINDS:
            kind = "text"
        what = re.sub(r"[\x00-\x1f]", " ", str(b.get("what") or KINDS[kind]))[:160]
        page = re.sub(r"[\x00-\x1f]", " ", str(b.get("page") or ""))[:60]
        text = b.get("text")
        entry = {"id": _hid(), "t": round(time.time(), 3), "user": u, "kind": "copy", "what": what, "page": page}
        if kind in SECRET_KINDS:
            detail = f"{what} · not fingerprinted (a secret)"
            sid = ""
        else:
            if not isinstance(text, str) or not text.strip():
                return jsonify(error="Nothing to copy."), 400
            if len(text) > TEXT_MAX:
                return jsonify(error="Too much to copy at once: download it instead."), 413
            s = sealer.seal_text(text)
            entry.update(whole=s["whole"], lines=s["lines"], addresses=s["addresses"], items=s["items"])
            try:
                sealer.write(entry)
            except OSError:
                return jsonify(error="The copy could not be recorded, so nothing was copied."), 503
            sid = entry["id"]
            detail = f"{s['lines']:,} line{'s' if s['lines'] != 1 else ''}, {s['addresses']:,} address{'es' if s['addresses'] != 1 else ''}" \
                     + (f" · {page}" if page else "") + f" · seal {sid}"
        audit.add("copied", user=u, target=what, detail=detail)
        return jsonify(ok=True, id=sid)

    # ------------------------------------------------------------------ every downloaded file, sealed
    @app.after_request
    def _seal_download(resp):
        try:
            u = me()
            # people only: not the self-test's accounts, not the local check scripts' automation key (their downloads
            # would fill the seals and answer every trace)
            if not u or u.startswith("lg-selftest") or (getattr(g, "user", None) or {}).get("automation") or resp.status_code != 200:
                return resp
            disp = resp.headers.get("Content-Disposition", "")
            is_file = "attachment" in disp and not resp.direct_passthrough and not resp.is_streamed
            # a list the page saves as a CSV file in the browser (data_access.DOWNLOADS, download=1): its addresses
            is_list = request.method == "GET" and request.args.get("download") == "1" and resp.mimetype == "application/json"
            if not (is_file or is_list):
                return resp
            data = resp.get_data()
            name = (re.search(r'filename="?([^";]+)', disp) or [None, request.path])[1][:160]
            if is_file:
                f = sealer.seal_file(data, name)
                entry = {"id": _hid(), "t": round(time.time(), 3), "user": u, "kind": "download", "what": name,
                         "page": request.path[:60], "sha256": f["sha256"], "files": f["files"], "wholes": f.get("wholes") or [],
                         "lines": f["lines"], "addresses": f["addresses"], "items": f["items"]}
            else:
                s = sealer.seal_text(data.decode("utf-8", "replace"))
                entry = {"id": _hid(), "t": round(time.time(), 3), "user": u, "kind": "download", "what": "a list saved in the browser",
                         "page": request.path[:60], "lines": 0, "addresses": s["addresses"],
                         "items": s["items"][:s["addresses"]]}           # its addresses only (the JSON's lines are not the file's)
            sealer.write(entry)
        except Exception:                                  # noqa: BLE001  (a seal never breaks a download)
            pass
        return resp

    # ------------------------------------------------------------------ Trace a leak
    @app.route("/api/audit/trace", methods=["POST"])
    def api_audit_trace():
        if not hp("audit"):
            return jsonify(error="Trace a leak is for the auditor role and administrators (permission 'audit')."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        u, now = me(), time.time()
        recent = [t for t in traced.get(u, []) if now - t < 60]
        if len(recent) >= TRACE_PER_MINUTE:
            return jsonify(error=f"At most {TRACE_PER_MINUTE} traces a minute: wait a moment."), 429
        traced[u] = recent + [now]
        text, data, given = None, None, ""
        f = request.files.get("file")
        if f is not None:
            data = f.read(TRACE_MAX_BYTES + 1)
            if len(data) > TRACE_MAX_BYTES:
                return jsonify(error="The file is too large to trace here (25 MB at most)."), 413
            given = "a file"
        else:
            b = request.get_json(silent=True) or {}
            text = b.get("text") if isinstance(b.get("text"), str) else ""
            if len(text) > TRACE_MAX_BYTES:
                return jsonify(error="Too much text to trace at once."), 413
            given = "pasted text"
        if not text and not data:
            return jsonify(error="Paste the text or choose the file to trace."), 400
        found, common = sealer.trace(text=text, data=data)
        text = data = None                                  # nothing given is kept
        audit.add("leak_traced", user=u, target=given, detail=f"{len(found)} match{'es' if len(found) != 1 else ''}")
        rows = []
        for r in found[:200]:
            s = r["seal"]
            rows.append({"id": s.get("id"), "t": s.get("t"), "who": name_of(s.get("user", "")), "user": s.get("user", ""),
                         "kind": s.get("kind"), "what": s.get("what", ""), "page": s.get("page", ""), "exact": r["exact"],
                         "matched": r["matched"], "of": r["of"], "cut": bool(s.get("cut"))})
        return jsonify(ok=True, matches=rows, total=len(found), common_left_out=common)

    return {"sealer": sealer}
