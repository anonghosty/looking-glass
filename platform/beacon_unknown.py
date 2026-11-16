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
A family can be marked "not a beacon" (a session token, an ID) or "sent"; both are kept in data/beacon_unknown.json and
are in the audit log.

API (analysts and admins: the 'unmasked' permission, demo off): GET /api/beacon/unknown,
GET /api/beacon/unknown/<id>/request, POST /api/beacon/unknown/<id>/state {state: dismissed|sent|open, why}.
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


def request_line(url):
    """The request as the sinkhole recorded it, without a host: "GET http://c2.example/p?k=v HTTP/1.1" -> "GET /p?k=v HTTP/1.1"."""
    parts = str(url).strip().split(" ")
    i = next((n for n, x in enumerate(parts) if "://" in x or x.startswith("/")), None)
    if i is None:
        return str(url).strip()[:4000]
    target = parts[i]
    if "://" in target:
        s = urllib.parse.urlsplit(target)
        target = (s.path or "/") + (f"?{s.query}" if s.query else "")
    parts[i] = target
    return " ".join(parts)[:4000]


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

    def set_state(self, fid, state, why, user):
        with self.lock:
            st = self.states()
            if state == "open":
                st.pop(fid, None)
            else:
                st[fid] = {"state": state, "by": user, "at": round(time.time(), 3), "why": why[:300]}
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
                    item = {"infection": e.get("infection") or "", "request": request_line(url)}
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
            fams.append({**{k: v for k, v in f.items() if not k.startswith("_")}, "state": s.get("state", "open"),
                         "state_by": people(s["by"]) if s.get("by") else "", "state_why": s.get("why", ""),
                         "state_at": time.strftime("%Y-%m-%d", time.gmtime(s["at"])) if s.get("at") else "",
                         "label": f"{f['path']} ?{f['param']}=",
                         "issue_url": SEND_URL})
        return fams

    def request_file(self, fid):
        """The HTTP request lines of one family, nothing else."""
        f = next((x for x in self.families() if x["id"] == fid), None)
        if not f:
            return None
        return {"looking_glass_decoding_request": 2,
                "made": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "requests": [dict(x) for x in f["_requests"]]}


def install(app, ctx):
    """ctx: store, labels(), base_dir, sees_hosts(), csrf_ok(), audit, people_name(user)."""
    un = Unknown(ctx)

    def allowed():
        return bool((getattr(g, "user", None) or {}).get("user")) and ctx["sees_hosts"]()

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    @app.route("/api/beacon/unknown")
    def api_beacon_unknown():
        if not allowed():
            return jsonify(error="Requests Looking Glass could not decode are for analysts and admins."), 403
        fams = un.listing()
        return jsonify(families=fams, open=sum(1 for f in fams if f["state"] == "open"), repo=REPO)

    @app.route("/api/beacon/unknown/<fid>/request")
    def api_beacon_unknown_request(fid):
        if not allowed():
            return jsonify(error="Requests Looking Glass could not decode are for analysts and admins."), 403
        fid = re.sub(r"[^0-9a-f]", "", fid)[:12]
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
        if state not in ("dismissed", "sent", "open"):
            return jsonify(error="dismissed, sent or open"), 400
        fid = re.sub(r"[^0-9a-f]", "", fid)[:12]
        if not any(f["id"] == fid for f in un.families()) and state != "open":
            return jsonify(error="No such family in the days in memory."), 404
        why = str(b.get("why") or "").replace("\r", "").strip()[:300]
        un.set_state(fid, state, why, me())
        ctx["audit"].add("beacon_family_state", user=me(), target=fid, detail=state + (f" · {why[:100]}" if why else ""))
        return jsonify(ok=True)

    return un
