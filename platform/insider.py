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
  matches; never what was searched). Against testing guesses (external review, 2026-11-19: one trace of a whole /16 of
  guessed addresses said how many matched, and halving found an address in 17 traces): a trace compares at most
  TRACE_MAX_ITEMS lines and TRACE_MAX_ITEMS addresses (more: the exact text or file only), a seal is reported only when
  it holds the exact text or file or at least TRACE_MIN_SHARE of what was given, and TRACE_PER_MINUTE / TRACE_PER_DAY
  traces are answered per person.
* Copies recorded: at most COPY_PER_MINUTE a minute per person (a flood would fill the disk and the audit log, and could
  make a line "common" so a trace leaves it out). A line counts as common by how many PEOPLE's seals hold it, never by
  how many seals: one person copying the same rows again and again cannot hide them. Seals past the retention are
  removed every day (not only at start), and a trace reads the seals file one line at a time.
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
import math
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
# Watching small traces (external review of 1a7b016 + the user, 2026-11-20): a trace of one or two addresses still
# answers yes or no, so someone with the audit permission could test about 100 guesses a day, slowly. Not closed (it
# would break real traces of short excerpts) but watched: SMALL_TRACE_ALERT traces of at most SMALL_TRACE_ITEMS lines
# or addresses (pasted or in a file) by one person within 24 hours put an alert in the administrators' bell (system_alerts.py). Only the time and the
# person are kept (data/trace_watch.json), never what was traced.
SMALL_TRACE_ITEMS = 3
SMALL_TRACE_ALERT = max(2, int(os.environ.get("SMALL_TRACE_ALERT", "20") or 20))
WATCH_FILE = "trace_watch.json"
TRACE_PER_DAY = 100
TRACE_MAX_ITEMS = 1000          # lines, and addresses, a trace compares one by one (more: the exact text or file only)
TRACE_MIN_SHARE = 0.5           # a seal is reported when it holds at least this share of what was given (or all of it)
COPY_PER_MINUTE = 30            # copies recorded per person a minute
BODY_LIMITS = {"/api/copy/record": 12_000_000, "/api/audit/trace": TRACE_MAX_BYTES + 1_000_000}
COMMON_SHARE = 0.2              # a line held by more than this share of the PEOPLE with seals does not count as a match
PRUNE_EVERY = 86400             # seals past the retention removed once a day
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
        return {"whole": self.h("T", t), "lines": len(lines), "addresses": len(addrs), "items": (addrs + lines),
                "line_items": lines, "addr_items": addrs}          # kept apart for a trace only (never written)

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
            out.setdefault("line_items", []).extend(s["line_items"]); out.setdefault("addr_items", []).extend(s["addr_items"])
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

    def trace(self, text=None, data=None, counts=None):
        """Every seal the text or file matches: ([{seal, exact, matched, of, given}], lines left out as common, whether the
        lines and addresses were compared one by one), the closest first. `counts` (a dict), when given, is filled with
        how many distinct lines and addresses were given, read the same way as they are compared (a file's text, each
        text file in a ZIP; a PDF has none), for the small-trace watch.
        Against testing guesses (external review, 2026-11-19): more than TRACE_MAX_ITEMS lines or addresses given are
        compared as a whole only (the exact text or file); a seal that is not exact is reported only when it holds at
        least TRACE_MIN_SHARE of what was given (a list of guesses never does, a real excerpt does). A line counts as
        common by the PEOPLE whose seals hold it, never by how many seals (one person copying the same rows many times
        cannot make them common). The seals file is read one line at a time, twice."""
        q_whole, q_sha, q_lines, q_addrs = set(), set(), set(), set()
        if data is not None:
            f = self.seal_file(data)
            q_sha.add(f["sha256"]); q_sha.update(x["sha256"] for x in f["files"])
            q_whole.update(f.get("wholes") or [])
            q_lines.update(f.get("line_items") or []); q_addrs.update(f.get("addr_items") or [])
        if text:
            s = self.seal_text(text)
            q_whole.add(s["whole"]); q_lines.update(s["line_items"]); q_addrs.update(s["addr_items"])
        if counts is not None:
            counts["lines"], counts["addresses"] = len(q_lines), len(q_addrs)
        one_by_one = len(q_lines) <= TRACE_MAX_ITEMS and len(q_addrs) <= TRACE_MAX_ITEMS
        if not one_by_one:
            q_lines, q_addrs = set(), set()                  # too much to compare line by line: the exact text or file only
        q_items = q_lines | q_addrs
        people, item_people = set(), {}
        for s in self.all():                                 # pass 1: who holds each line given (people, not seals)
            u = s.get("user") or ""
            people.add(u)
            if q_items:
                for i in s.get("items") or []:
                    if i in q_items:
                        item_people.setdefault(i, set()).add(u)
        common = {i for i, us in item_people.items() if len(people) > 4 and len(us) > COMMON_SHARE * len(people)}
        # the share is asked of the lines and of the addresses apart: a leak is often reformatted (a list of the addresses
        # taken out of a CSV) and then only its addresses match; a list of guesses holds few real ones of either kind
        g_lines, g_addrs = q_lines - common, q_addrs - common
        need_l = max(1, math.ceil(TRACE_MIN_SHARE * len(g_lines)))      # at least half of what was given, rounded up
        need_a = max(1, math.ceil(TRACE_MIN_SHARE * len(g_addrs)))
        out = []
        for s in self.all():                                 # pass 2: the matches
            exact = s.get("whole") in q_whole or bool(set(s.get("wholes") or []) & q_whole) \
                or s.get("sha256") in q_sha or any(x.get("sha256") in q_sha for x in s.get("files") or [])
            its = s.get("items") or []
            hit_l = sum(1 for i in its if i in g_lines) if g_lines else 0
            hit_a = sum(1 for i in its if i in g_addrs) if g_addrs else 0
            enough = (g_lines and hit_l >= need_l) or (g_addrs and hit_a >= need_a)
            if not exact and not enough:
                continue
            out.append({"seal": s, "exact": exact, "matched": hit_l + hit_a, "of": s.get("items_total") or len(its),
                        "given": len(g_lines) + len(g_addrs)})
        out.sort(key=lambda r: (not r["exact"], -r["matched"], -(r["seal"].get("t") or 0)))
        return out, len(common), one_by_one


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
    traced = {}                                        # user -> [times] (Trace a leak's limits)
    copied = {}                                        # user -> [times] (copies recorded a minute)
    limits_lock = threading.Lock()
    full = ctx.get("people_name") or (lambda u: "")
    pruned = {"at": 0.0}

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def name_of(u):
        return full(u) or u

    def prune_now():
        try:
            sealer.prune(int(float(os.environ.get("AUDIT_RETENTION_DAYS", "400") or 400)))
        except (OSError, ValueError):
            pass

    def prune_daily():
        """Seals past the retention removed once a day, behind the request (not only at start: a service that runs for
        months kept every seal; external review, 2026-11-19)."""
        now = time.time()
        with limits_lock:
            if now - pruned["at"] < PRUNE_EVERY:
                return
            pruned["at"] = now
        threading.Thread(target=prune_now, daemon=True, name="copy-seals-prune").start()

    watch_path = os.path.join(ctx["base_dir"], "data", WATCH_FILE)

    def note_small_trace(u):
        """One more small trace by u: its time kept for 24 hours (the bell's alert counts them; system_alerts.py)."""
        now = time.time()
        with limits_lock:
            try:
                with open(watch_path, encoding="utf-8") as fh:
                    d = json.load(fh)
                d = d if isinstance(d, dict) else {}
            except (OSError, ValueError):
                d = {}
            d = {k: [t for t in v if now - t < 86400] for k, v in d.items() if isinstance(v, list)}
            d[u] = d.get(u, []) + [round(now)]
            d = {k: v for k, v in d.items() if v}
            tmp = watch_path + ".tmp"
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(d, fh)
                os.replace(tmp, watch_path)
            except OSError:
                pass

    def over(book, u, per, window):
        """True when u already made `per` requests in the last `window` seconds; else counts this one."""
        now = time.time()
        with limits_lock:
            recent = [t for t in book.get(u, []) if now - t < window]
            if len(recent) >= per:
                book[u] = recent
                return True
            book[u] = recent + [now]
            return False

    prune_now()
    pruned["at"] = time.time()

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
        # a limit per person: a flood would fill the disk and the audit log, and could make lines "common" so that a trace
        # leaves them out (external review, 2026-11-19); the page copies nothing when it is refused (fail closed)
        if over(copied, u, COPY_PER_MINUTE, 60):
            return jsonify(error=f"At most {COPY_PER_MINUTE} copies a minute: wait a moment, or download the list instead."), 429
        prune_daily()
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
            prune_daily()
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
        u = me()
        if over(traced, u + "|min", TRACE_PER_MINUTE, 60):
            return jsonify(error=f"At most {TRACE_PER_MINUTE} traces a minute: wait a moment."), 429
        if over(traced, u + "|day", TRACE_PER_DAY, 86400):
            return jsonify(error=f"At most {TRACE_PER_DAY} traces a day per person: the rest tomorrow."), 429
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
        given_n = {}
        found, common, one_by_one = sealer.trace(text=text, data=data, counts=given_n)
        # small: few lines OR few addresses, pasted or in a file (a ZIP's files too). Counting lines alone missed an
        # uploaded file, and one address padded with filler lines (external review of e6702c4, 2026-11-20)
        small = (0 < given_n.get("lines", 0) <= SMALL_TRACE_ITEMS) or (0 < given_n.get("addresses", 0) <= SMALL_TRACE_ITEMS)
        text = data = None                                  # nothing given is kept
        if small:
            note_small_trace(u)
        audit.add("leak_traced", user=u, target=given, detail=f"{len(found)} match{'es' if len(found) != 1 else ''}")
        rows = []
        for r in found[:200]:
            s = r["seal"]
            rows.append({"id": s.get("id"), "t": s.get("t"), "who": name_of(s.get("user", "")), "user": s.get("user", ""),
                         "kind": s.get("kind"), "what": s.get("what", ""), "page": s.get("page", ""), "exact": r["exact"],
                         "matched": r["matched"], "of": r["of"], "given": r["given"], "cut": bool(s.get("cut"))})
        return jsonify(ok=True, matches=rows, total=len(found), common_left_out=common,
                       # more than TRACE_MAX_ITEMS lines or addresses: only the exact text or file was looked for
                       exact_only=not one_by_one, max_items=TRACE_MAX_ITEMS, min_share=TRACE_MIN_SHARE)

    return {"sealer": sealer, "prune_daily": prune_daily, "pruned": pruned}
