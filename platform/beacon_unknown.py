"""Requests Looking Glass could not decode: the long encoded values in the sinkhole reports' HTTP requests that no known
format decodes (beacon_decode.FORMATS), no known undecodable family names (OPAQUE) and the generic fallback cannot read,
grouped into families, so analysts see them and can send them to the Looking Glass creator for future automated decoding.

A family is one request shape: the path (numbers and long parts folded), the query parameter, the encoding and what
the value looks like (beacon_decode.shape: hash-sized, whole 16-byte blocks, random-looking...). The C2 hosts it was
sent to are listed with it (the threat's side; one family often spans many generated domains). Device addresses are
counted, never listed.

"Send to the Looking Glass creator" makes a decoding request, a JSON file the analyst downloads and pastes into a
private report on the http-requests-decoding repository (SEND_URL; the link opens it; nothing is sent by Looking Glass
itself). It carries ONLY up to 5 distinct HTTP request lines, as the sinkhole recorded them (an absolute
"GET http://host/..." cut to its path), each with the infection name it is filed under so the next release can map a
decoder to its family: no host, user agent, report or count, so as little data as possible leaves (the user,
2026-11-16). Decoded, a value may hold the device's own data, so the analyst confirms the CSIRT's rules (TLP) allow
sharing them; every download is logged as an export.
A family goes to the Looking Glass creator only once an administrator approves it (the user, 2026-11-16):
open -> asked (an analyst or admin, with a reason) -> approved or rejected (an administrator; a rejection gives its
reason and the family is open again) -> sent. The page shows the exact request lines before anything is asked; the
decoding request can be downloaded only once approved. A family can also be put away ("not a beacon"). Every step is
kept in data/beacon_unknown.json and in the audit log.

API (analysts and admins: the 'unmasked' permission, demo off): GET /api/beacon/unknown (with each family's request
lines), GET /api/beacon/unknown/<id>/request (approved or sent only: exactly the lines approved), POST /api/beacon/unknown/<id>/state
{state: asked|approved|rejected|sent|dismissed|open, why}; approved and rejected need the 'settings' permission.
Installed from app.py: beacon_unknown.install(app, ctx).
"""
import collections
import hashlib
import json
import os
import re
import threading
import time
import urllib.parse

from flask import Response, g, jsonify, request

import beacon_decode as B
import ip_find

# decoding requests go to their own repository, apart from the platform, and only through GitHub's private reporting
# (only the sender and the maintainer see a report; public issues there are switched off): the user, 2026-11-16
REPO = "https://github.com/anonghosty/http-requests-decoding"
SEND_URL = f"{REPO}/security/advisories/new"
MAX_SAMPLES = 5
TOP_HOSTS = 12


def _path_norm(path):
    """/u/12345/abcdefabcdef/x.php -> /u/<n>/<long>/x.php: one family, whatever the number or token in the path."""
    p = urllib.parse.urlsplit(path).path if "://" in path else path
    p = re.sub(r"/\d+(?=/|$)", "/<n>", p)
    return re.sub(r"/[A-Za-z0-9+_=%.-]{20,}(?=/|$)", "/<long>", p)[:120] or "/"


def _bucket(n):
    return f"{n // 16 * 16}-{n // 16 * 16 + 15}" if n < 256 else f"{n // 128 * 128}-{n // 128 * 128 + 127}"


def family_key(path, param, shp):
    return (_path_norm(path), param, shp["encoding"], shp["hint"], _bucket(shp["length"]))


_ENCODED = re.compile(r"[A-Za-z0-9+/%=_-]{16,}")      # a value that looks encoded (as beacon_decode's prefilter)


def request_line(url, keep=None, value=None):
    """The request as it goes to the Looking Glass creator: the method, the path and the parameter NAMES as the sinkhole
    recorded them, with only the undecoded value (the parameter `keep`, its longest copy if the name repeats) as it is.
    Every other parameter's value reads <value>, because a bot's own parameters can carry the device's address or
    machine name ("ip=41.66.1.2&host=MINISTRY-PC01", the reviewer, 2026-11-16); any address left anywhere reads
    <address>; an absolute URL loses its host. The shapes handled: "&" or ";" between parameters, raw spaces inside the
    query (the kept value ends at the first one), a target without a leading "/", a repeated name (the copy that looks
    encoded is kept) (security reviews of bc92a26 and 84bfb69).
    "GET http://c2.example/p?ip=1.2.3.4&k=QUJD HTTP/1.1", keep "k" -> "GET /p?ip=<value>&k=QUJD HTTP/1.1"."""
    toks = str(url or "").split()
    if not toks:
        return ""
    method = toks[0] if len(toks) > 1 and re.fullmatch(r"[A-Za-z]{3,10}", toks[0]) else ""
    proto = toks[-1] if len(toks) > 1 and re.fullmatch(r"HTTP/\d(?:\.\d)?", toks[-1], re.I) else ""
    target = " ".join(toks[(1 if method else 0):(len(toks) - 1 if proto else len(toks))])
    if "://" in target:
        s = urllib.parse.urlsplit(target)
        target = (s.path or "/") + (f"?{s.query}" if s.query else "")
    path, _, query = target.partition("?")
    path = path.split("#", 1)[0]
    if query:
        pieces = re.split(r"([&;])", query.split("#", 1)[0])
        pairs, seps = pieces[0::2], pieces[1::2]
        named = lambda p: urllib.parse.unquote(p.partition("=")[0]).strip()      # noqa: E731
        mine = [n for n, p in enumerate(pairs) if "=" in p and keep is not None and named(p) == keep]
        # one copy only: the one whose value (up to the first space) looks encoded, longest first; plain text never wins
        # over the blob (security review of 84bfb69)
        head = lambda n: pairs[n].partition("=")[2].strip().split(" ")[0]       # noqa: E731
        # the copy holding the very value the decoder could not decode (`value`), when it is known
        exact = [n for n in mine if value is not None and urllib.parse.unquote(head(n)).replace(" ", "+") == str(value)]
        keep_at = exact[0] if exact else \
            max(mine, key=lambda n: (bool(_ENCODED.fullmatch(head(n))), len(head(n)))) if mine else None
        out = []
        for n, pair in enumerate(pairs):
            name, eq, _value = pair.partition("=")
            if n == keep_at:
                # the value to decode, as recorded, up to the first raw space: what follows a space is another word,
                # which may name the device (security review of 84bfb69)
                rest = pair.partition("=")[2].strip()
                out.append(f"{name}={rest.split(' ')[0]}" + ("+<value>" if " " in rest else ""))
            elif eq:
                out.append(f"{name.replace(' ', '+')}=<value>")
            elif pair.strip():
                out.append("<value>")                     # a bare value with no name
            else:
                out.append("")
        q = out[0] + "".join(s + v for s, v in zip(seps, out[1:]))
        target = path + "?" + q
    else:
        target = path
    line = " ".join(x for x in (method, target, proto) if x)
    return ip_find.sub(line, lambda _a: "<address>")[:4000]


def lines_hash(lines):
    """A fingerprint of request lines: the page sends the one it showed, so an approval is for exactly those lines."""
    return hashlib.sha256(json.dumps(lines, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:32]


def family_id(key):
    return hashlib.sha256("\x1f".join(key).encode()).hexdigest()[:12]


class Unknown:
    def __init__(self, ctx):
        self.ctx = ctx
        self.lock = threading.Lock()
        self.cache = {"key": None, "at": 0.0, "data": None}
        self.path = os.path.join(ctx["base_dir"], "data", "beacon_unknown.json")

    # ---- the state the analysts keep: not a beacon / sent to the creator
    def states(self):
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f).get("families") or {}
        except (OSError, ValueError):
            return {}

    def set_state(self, fid, state, why, user, lines=None):
        with self.lock:
            st = self.states()
            prev = st.get(fid) or {}
            if state == "open":
                st.pop(fid, None)
            else:
                rec = {"state": state, "by": user, "at": round(time.time(), 3), "why": why[:300]}
                if state == "asked":                       # who asked and why stays with the family until it is sent
                    rec.update(asked_by=user, asked_why=why[:300], asked_at=rec["at"])
                elif prev.get("asked_by") and state in ("approved", "rejected", "sent"):
                    rec.update({k: prev[k] for k in ("asked_by", "asked_why", "asked_at") if k in prev})
                if state == "approved":                    # exactly the lines the administrator approved
                    rec["approved_requests"] = [dict(x) for x in (lines or [])]
                if state == "sent" and prev.get("state") == "approved":
                    rec.update(approved_by=prev.get("by"), approved_at=prev.get("at"),
                               approved_requests=prev.get("approved_requests") or [])
                st[fid] = rec
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.{os.getpid()}.tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"families": st}, f, indent=1)
            os.replace(tmp, self.path)

    # ---- the families in the days in memory
    def families(self):
        days = list(self.ctx["store"].days.values())
        key = tuple((d.start, getattr(d, "serial", 0), len(d.events)) for d in days)
        with self.lock:
            if self.cache["key"] == key and time.time() - self.cache["at"] < 3600:
                return self.cache["data"]
        labels = self.ctx["labels"]()
        fam = {}
        for d in days:
            day = d.start.date().isoformat()
            for e in d.events:
                url = e.get("http_url") or ""
                if "=" not in url or len(url) < B.MIN_BLOB:
                    continue
                host = (e.get("http_host") or "").lower() or None
                for u in B.unknown(url, host):
                    k = family_key(u["path"], u["param"], u["shape"])
                    f = fam.get(k)
                    if f is None:
                        f = fam[k] = {"key": k, "records": 0, "devices": set(), "hosts": collections.Counter(),
                                      "agents": collections.Counter(), "names": collections.Counter(), "reports": collections.Counter(),
                                      "days": set(), "lengths": [10 ** 9, 0], "values": collections.Counter(), "requests": []}
                    f["records"] += 1
                    if e.get("src_ip"):
                        f["devices"].add(e["src_ip"])
                    f["hosts"][host or "(no host)"] += 1
                    if e.get("http_agent"):
                        f["agents"][e["http_agent"][:120]] += 1
                    f["names"][e.get("infection") or ""] += 1
                    f["reports"][labels.get(e.get("source"), e.get("source") or "")] += 1
                    f["days"].add(day)
                    n = u["shape"]["length"]
                    f["lengths"] = [min(f["lengths"][0], n), max(f["lengths"][1], n)]
                    if len(f["values"]) < 10000:
                        f["values"][u["value"]] += 1
                    item = {"infection": e.get("infection") or "", "request": request_line(url, u["param"], u["value"])}
                    if len(f["requests"]) < MAX_SAMPLES and item not in f["requests"]:
                        f["requests"].append(item)
        out = []
        for k, f in fam.items():
            path, param, enc, hint, _ = k
            distinct = len(f["values"])
            out.append({"id": family_id(k), "path": path, "param": param, "encoding": enc, "hint": hint,
                        "lengths": f["lengths"], "records": f["records"], "devices": len(f["devices"]),
                        "distinct": distinct, "constant": distinct == 1 and f["records"] > 1,
                        "hosts": [h for h, _ in f["hosts"].most_common(TOP_HOSTS)], "hosts_total": len(f["hosts"]),
                        "agents": [a for a, _ in f["agents"].most_common(3)],
                        "names": [n for n, _ in f["names"].most_common(5) if n], "reports": [r for r, _ in f["reports"].most_common()],
                        "days": sorted(f["days"]), "_requests": f["requests"]})
        out.sort(key=lambda x: (-x["devices"], -x["records"]))
        with self.lock:
            self.cache.update(key=key, at=time.time(), data=out)
        return out

    def listing(self):
        st = self.states()
        people = self.ctx.get("people_name") or (lambda u: u)
        fams = []
        for f in self.families():
            s = st.get(f["id"]) or {}
            day = lambda t: time.strftime("%Y-%m-%d", time.gmtime(t)) if t else ""     # noqa: E731
            fams.append({**{k: v for k, v in f.items() if not k.startswith("_")}, "state": s.get("state", "open"),
                         "state_by": people(s["by"]) if s.get("by") else "", "state_why": s.get("why", ""),
                         "state_at": day(s.get("at")),
                         "asked_by": people(s["asked_by"]) if s.get("asked_by") else "", "asked_why": s.get("asked_why", ""),
                         "asked_at": day(s.get("asked_at")),
                         "approved_by": people(s["approved_by"]) if s.get("approved_by") else "",
                         # exactly what the decoding request would hold, shown before anyone asks to send it
                         "requests": [dict(x) for x in f["_requests"]],
                         "requests_hash": lines_hash([dict(x) for x in f["_requests"]]),
                         "label": f"{f['path']} ?{f['param']}=",
                         "issue_url": SEND_URL})
        return fams

    def request_file(self, fid):
        """The HTTP request lines of one family, nothing else. Once approved: exactly the lines the administrator
        approved, never lines gathered later from other days."""
        s = self.states().get(fid) or {}
        if s.get("state") in ("approved", "sent") and s.get("approved_requests"):
            reqs = [dict(x) for x in s["approved_requests"]]
        else:
            f = next((x for x in self.families() if x["id"] == fid), None)
            if not f:
                return None
            reqs = [dict(x) for x in f["_requests"]]
        return {"looking_glass_decoding_request": 2,
                "made": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "requests": reqs}


def install(app, ctx):
    """ctx: store, labels(), base_dir, sees_hosts(), csrf_ok(), audit, people_name(user)."""
    un = Unknown(ctx)

    def allowed():
        return bool((getattr(g, "user", None) or {}).get("user")) and ctx["sees_hosts"]()

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def approver():
        """Administrators approve what goes to the Looking Glass creator."""
        return allowed() and bool(ctx.get("can_approve") and ctx["can_approve"]())

    @app.route("/api/beacon/unknown")
    def api_beacon_unknown():
        if not allowed():
            return jsonify(error="Requests Looking Glass could not decode are for analysts and admins."), 403
        fams = un.listing()
        return jsonify(families=fams, open=sum(1 for f in fams if f["state"] == "open"), repo=REPO,
                       can_approve=approver(), waiting=sum(1 for f in fams if f["state"] == "asked"))

    @app.route("/api/beacon/unknown/<fid>/request")
    def api_beacon_unknown_request(fid):
        if not allowed():
            return jsonify(error="Requests Looking Glass could not decode are for analysts and admins."), 403
        fid = re.sub(r"[^0-9a-f]", "", fid)[:12]
        if (un.states().get(fid) or {}).get("state") not in ("approved", "sent"):
            return jsonify(error="An administrator approves this family before its decoding request can be downloaded."), 409
        req = un.request_file(fid)
        if req is None:
            return jsonify(error="No such family in the days in memory."), 404
        ctx["audit"].add("data_exported", user=me(), target=f"decoding request for the Looking Glass creator ({fid})",
                         detail=f"{len(req['requests'])} HTTP request line(s) with their infection names, nothing else")
        body = json.dumps(req, indent=1, ensure_ascii=False)
        return Response(body, mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="looking-glass-decoding-request-{fid[:12]}.json"'})

    @app.route("/api/beacon/unknown/<fid>/state", methods=["POST"])
    def api_beacon_unknown_state(fid):
        if not allowed():
            return jsonify(error="Requests Looking Glass could not decode are for analysts and admins."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True) or {}
        state = b.get("state")
        if state not in ("asked", "approved", "rejected", "sent", "dismissed", "open"):
            return jsonify(error="asked, approved, rejected, sent, dismissed or open"), 400
        fid = re.sub(r"[^0-9a-f]", "", fid)[:12]
        if not any(f["id"] == fid for f in un.families()) and state != "open":
            return jsonify(error="No such family in the days in memory."), 404
        why = str(b.get("why") or "").replace("\r", "").strip()[:300]
        now = (un.states().get(fid) or {}).get("state", "open")
        # the steps in order: ask (with a reason), an administrator approves or rejects (with a reason), then it is sent
        steps = {"asked": ("open", "rejected"), "approved": ("asked",), "rejected": ("asked",), "sent": ("approved",),
                 "dismissed": ("open", "rejected", "asked"), "open": ("dismissed", "rejected")}
        if now not in steps[state]:
            return jsonify(error=f"Not possible now: this family is {now}."), 409
        if state in ("approved", "rejected") and not approver():
            return jsonify(error="An administrator approves or rejects what goes to the Looking Glass creator."), 403
        if state in ("asked", "rejected") and not why:
            return jsonify(error="Say why." if state == "asked" else "Say why it is not approved."), 400
        lines = None
        if state == "approved":                    # bind the approval to the lines on the administrator's screen now
            f = next((x for x in un.families() if x["id"] == fid), None)
            lines = [dict(x) for x in (f or {}).get("_requests") or []]
            if not lines:
                return jsonify(error="No request lines to approve in the days in memory."), 409
            if str(b.get("seen") or "") != lines_hash(lines):
                return jsonify(error="The request lines have changed since this page was opened. Reload it and check them again."), 409
        un.set_state(fid, state, why, me(), lines)
        ctx["audit"].add("beacon_family_state", user=me(), target=fid, detail=state + (f" · {why[:100]}" if why else ""))
        return jsonify(ok=True)

    return un
