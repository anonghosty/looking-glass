"""Analyst codes (LG-A-XXXXXXXX): an analyst's selection, passed to the researchers and management without an address.

The other way round from the researchers' combination codes (combos.py): an analyst, in an analysis window on the map
or the services platform (for example "Source network: Example Telecom · Host: …"), makes an analyst code for exactly that
selection on that day, with a title and a note. It becomes a finding on the Findings page (findings.py), marked as from
an analyst. Then:

* a researcher opens the code: a page of its own with the names (infections / issues) in exactly those records, their
  definitions, and Intel gathered for exactly those records (indicators, combinations with their LG-C codes, the
  cross-report patterns with their LG-X codes), never an address: a host is "1 host". The researcher answers on the
  finding with a reply and their own codes;
* management, in between, filters the Executive portal by the code (counts only) and reads both sides on the finding.

The code is a hash of the platform, the day and the selection; what it stands for is kept in the code book
(data/combo_codes.json, kind "a") with a description in which every host address is replaced by a count.

API: POST /api/analyst-codes {platform, kind, value | query, at, title, text} (analysts, admins: roles that see
addresses), GET /api/intel/acode/<code> (researchers, management, analysts, admins: no address), page /intel/<code>.
Installed from app.py: acodes.install(app, ctx).
"""
import collections
import hashlib
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import parse_qsl

from flask import g, jsonify, render_template, request

import intel as I

ACODE_RX = re.compile(r"^LG-A-[0-9A-F]{8}$")
HOST_FIELDS = {"src_ip", "ip", "src_ref", "ip_ref", "hostname", "src_hostname"}       # never shown to researchers
LABELS = {"src_asn": "Source network", "asn": "Network", "dst_asn": "Destination network", "infection": "Infection",
          "source": "Report", "service": "Service", "family": "Report family", "issue": "Issue", "attack_class": "Attack type",
          "src_region": "Region", "region": "Region", "src_city": "City", "city": "City", "src_geo": "Country", "geo": "Country",
          "dst_geo": "Destination country", "http_host": "C2 domain", "dst_ip": "Destination IP", "dst_port": "Destination port",
          "severity": "Severity", "sector": "Sector", "tag": "Tag", "time": "Time", "port": "Port", "src_ip": "Host", "ip": "Host"}


def acode(platform, day, sel):
    raw = json.dumps([platform, day, sel], sort_keys=True)
    return "LG-A-" + hashlib.sha256(raw.encode()).hexdigest()[:8].upper()


def install(app, ctx):
    """ctx: book (combos.CodeBook), findings (findings.Findings), has_perm(p), csrf_ok(), fresh(), is_demo(), audit,
    day(platform, iso) -> a Day (memory, or loaded from MongoDB), slice(day, kind, value) -> comms records,
    svc_scope(args, day) -> services records, labels() -> {collection: report}, network(asn) -> name, defined() ->
    {(section, name): title}, describe(code) -> text."""
    book, hp = ctx["book"], ctx["has_perm"]

    def analyst():
        return hp("unmasked") and hp("export")

    def reader():
        return analyst() or hp("definitions") or hp("management") or hp("settings")

    def user():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def pairs_of(entry):
        sel = entry["sel"]
        if entry["platform"] == "comms":
            if sel["kind"] == "filters":
                return parse_qsl(sel["value"] or "")
            return [(sel["kind"], sel["value"])]
        return [tuple(p) for p in sel["query"]]

    def label(platform, pairs, labels):
        """The selection in words, with every host address replaced by a count."""
        parts, hosts = [], 0
        for k, v in pairs:
            if k in HOST_FIELDS:
                hosts += 1
                continue
            if k in ("at", "demo", "n", "metric", "all"):
                continue
            if k in ("src_asn", "asn", "dst_asn"):
                v = f"{ctx['network'](v) or 'AS' + str(v)} (AS{v})"
            elif k == "source":
                v = labels.get(v, v)
            elif k == "time":
                v = v.split("+")[0]
                try:
                    m = int(v); v = f"from {m // 60:02d}:{m % 60:02d} UTC"
                except ValueError:
                    pass
            parts.append(f"{LABELS.get(k, k.replace('_', ' ').capitalize())}: {v}")
        if hosts:
            parts.append(f"{hosts} host{'s' if hosts != 1 else ''} (address{'es' if hosts != 1 else ''} held back)")
        return " · ".join(parts) or ("Whole day, all reports" if platform == "comms" else "Whole day, all services")

    paths = {"ids": os.path.join(ctx["base_dir"], "data", "acodes")}       # data/acodes/<code>.json (tests point it elsewhere)

    def ids_path(code):
        """data/acodes/<code>.json, only for a well-formed analyst code and only inside that folder."""
        if not ACODE_RX.match(code or ""):
            raise ValueError("not an analyst code")
        base = os.path.realpath(paths["ids"])
        p = os.path.realpath(os.path.join(base, f"{code}.json"))
        if not p.startswith(base + os.sep):
            raise ValueError("not an analyst code")
        return p

    def save_ids(code, evs):
        """The exact records of the selection when the analyst made the code: every role then sees exactly these, whatever
        its masking rules (masked roles may only filter by aliases, so the selection itself could not be re-applied)."""
        os.makedirs(paths["ids"], mode=0o700, exist_ok=True)
        tmp = ids_path(code) + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(e["id"] for e in evs if e.get("id")), f)
        os.replace(tmp, ids_path(code))

    def records(entry, day=None):
        """The records of an analyst code on its day (the given day object, or the code's day loaded)."""
        day = day or ctx["day"](entry["platform"], entry["day"])
        if day is None:
            return []
        try:
            with open(ids_path(entry["code"]), encoding="utf-8") as f:
                ids = set(json.load(f))
            return [e for e in day.events if e.get("id") in ids]
        except (OSError, ValueError, KeyError):
            pass                                  # made before the records were kept: apply the selection again
        if entry["platform"] == "comms":
            sel = entry["sel"]
            return ctx["slice"](day, sel["kind"], sel["value"])[2]
        from werkzeug.datastructures import MultiDict
        return ctx["svc_scope"](MultiDict(entry["sel"]["query"]), day)

    # ------------------------------------------------------------------ the analyst makes a code (and a finding)
    @app.route("/api/analyst-codes", methods=["POST"])
    def api_acode_new():
        if not analyst():
            return jsonify(error="Analyst codes are made by analysts (roles that see addresses)."), 403
        if ctx["is_demo"]():
            return jsonify(error="Demo mode is on: switch it off to make an analyst code."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        platform = "services" if b.get("platform") == "services" else "comms"
        title = str(b.get("title") or "").strip()[:140]
        text = str(b.get("text") or "").replace("\r", "").strip()[:2000]
        if not title:
            return jsonify(error="Give the finding a short title."), 400
        try:
            at = datetime.fromisoformat(str(b.get("at") or "").replace("Z", "+00:00"))
        except ValueError:
            at = datetime.now(timezone.utc)
        day_iso = (at if at.tzinfo else at.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).date().isoformat()
        if platform == "comms":
            kind, value = str(b.get("kind") or "")[:40], str(b.get("value") or "")[:2000]
            if not kind:
                return jsonify(error="No selection to make a code of."), 400
            sel = {"kind": kind, "value": value}
        else:
            q = [(k, v) for k, v in parse_qsl(str(b.get("query") or "")[:4000]) if k not in ("at", "demo", "n", "metric", "all")]
            sel = {"query": sorted(q)}
        code = acode(platform, day_iso, sel)
        entry = {"kind": "a", "platform": platform, "day": day_iso, "sel": sel, "code": "-"}     # "-": apply the selection
        evs = records(entry)
        entry.pop("code")
        if not evs:
            return jsonify(error="This selection has no records on its day: nothing to pass on."), 400
        labels = ctx["labels"]()
        entry["label"] = label(platform, pairs_of(entry), labels)
        host = (lambda e: e.get("src_ip")) if platform == "comms" else (lambda e: e.get("ip"))
        names = collections.Counter(n for e in evs for n in ([(e.get("infection") or "").lower()] if platform == "comms" else (e.get("issues") or [])) if n)
        entry.update(records=len(evs), hosts=len({host(e) for e in evs if host(e)}), names=[n for n, _ in names.most_common(12)])
        save_ids(code, evs)
        book.put(code, entry)
        me, role = user()
        item = ctx["findings"].create_analyst(code, "issues" if platform == "services" else "infections", entry["label"], title, text, me, role)
        ctx["audit"].add("analyst_code", user=me, target=code, detail=f"#{item['id']} {title[:60]} · {entry['label'][:80]}")
        return jsonify(code=code, finding=f"#{item['id']}", label=entry["label"], records=entry["records"], hosts=entry["hosts"])

    # ------------------------------------------------------------------ the researcher's view of an analyst code
    def view(code):
        entry = book.get(code)
        if not entry or entry.get("kind") != "a":
            return None
        evs = records(entry)
        section = "infections" if entry["platform"] == "comms" else "issues"
        labels = ctx["labels"]()
        host = (lambda e: e.get("src_ip") or "") if section == "infections" else (lambda e: e.get("ip") or "")
        rep = (lambda e: labels.get(e.get("source"), e.get("source") or "")) if section == "infections" else (lambda e: e.get("report_label") or e.get("report") or "")
        names_of = (lambda e: [(e.get("infection") or "").lower()] if e.get("infection") else []) if section == "infections" else (lambda e: e.get("issues") or [])
        defined = ctx["defined"]()
        per = collections.defaultdict(lambda: {"records": 0, "hosts": set(), "reports": collections.Counter(),
                                               "combos": collections.defaultdict(lambda: {"records": 0, "hosts": collections.Counter()}),
                                               "dev": collections.defaultdict(lambda: collections.defaultdict(set))})
        for e in evs:
            for n in names_of(e):
                p, r, h = per[n], rep(e), host(e)
                items = I.record_items(section, e, I._norm(n))
                p["records"] += 1; p["reports"][r] += 1
                c = p["combos"][(r, items)]; c["records"] += 1
                if h:
                    p["hosts"].add(h); c["hosts"][h] += 1; p["dev"][h][r].update(items)
        out = []
        for n, p in sorted(per.items(), key=lambda kv: -kv[1]["records"]):
            combos = []
            for (r, items), c in sorted(p["combos"].items(), key=lambda kv: -kv[1]["records"])[:12]:
                cc = I.combo_code(section, n, r, items)
                book.record(section, n, r, [items])
                combos.append({"report": r, "items": list(items), "records": c["records"], "devices": len(c["hosts"]),
                               "repeat": sum(1 for v in c["hosts"].values() if v > 1), "code": cc})
            pats = collections.Counter(tuple(sorted((r, tuple(sorted(i))) for r, i in reps.items())) for reps in p["dev"].values() if len(reps) > 1)
            if pats:
                book.record(section, n, None, [pt for pt, _ in pats.most_common(8)])
            out.append({"name": n, "defined": defined.get((section, n.lower()), ""), "records": p["records"], "devices": len(p["hosts"]),
                        "reports": [{"report": r, "records": k} for r, k in p["reports"].most_common()],
                        "combinations": combos, "combinations_total": len(p["combos"]),
                        "across": [{"code": I.cross_code(section, n, pt), "devices": k, "parts": [{"report": r, "items": list(i)} for r, i in pt]}
                                   for pt, k in pats.most_common(8)]})
        hosts = {host(e) for e in evs if host(e)}
        f = ctx["findings"].of_code(code)
        return {"code": code, "platform": entry["platform"], "section": section, "day": entry["day"], "label": entry.get("label", ""),
                "records": len(evs), "devices": len(hosts), "reports": len({rep(e) for e in evs}), "names": out,
                "finding": {"id": f["id"], "number": f"#{f['id']}", "title": f["title"], "text": f["text"], "status": f["status"]} if f else None,
                "in_memory": bool(evs)}

    @app.route("/api/intel/acode/<code>")
    def api_acode_view(code):
        if not reader():
            return jsonify(error="Analyst codes are for researchers, management, analysts and admins."), 403
        code = (code or "").strip().upper()
        if not ACODE_RX.match(code):
            return jsonify(error="An analyst code looks like LG-A-1A2B3C4D."), 400
        v = view(code)
        if v is None:
            return jsonify(error=f"{code} is not an analyst code known here."), 404
        return jsonify(v)

    @app.route("/api/analyst-codes")
    def api_acode_list():
        """Every analyst code, newest first, for the analysts' drop-down list on the Combinations page: the finding's
        title and status, the day, the platform and the selection in words (no address)."""
        if not analyst():
            return jsonify(error="The analysts' codes are listed for analysts."), 403
        with book.lock:
            book._load()
            items = [(c, dict(e)) for c, e in book.data.items() if e.get("kind") == "a"]
        out = []
        for c, e in items:
            f = ctx["findings"].of_code(c)
            out.append({"code": c, "day": e["day"], "platform": e["platform"], "label": e.get("label", ""), "records": e.get("records"),
                        "hosts": e.get("hosts"), "names": e.get("names", [])[:6], "first": e.get("first", ""),
                        "finding": {"number": f"#{f['id']}", "title": f["title"], "status": f["status"], "by": ctx["people_name"](f["user"])} if f else None})
        out.sort(key=lambda x: (x["first"], x["day"]), reverse=True)
        return jsonify(codes=out)

    @app.route("/intel/<code>")
    def acode_page(code):
        if not reader():
            return render_template("denied.html", message="Analyst codes are for researchers, management, analysts and admins."), 403
        return render_template("acode.html", code=(code or "").strip().upper()[:13])

    class API:
        pass
    api = API()
    api.records = records
    api.paths = paths
    api.describe = lambda entry: f"Analyst selection on {entry['day']} ({'network communications' if entry['platform'] == 'comms' else 'services'}): {entry.get('label', '')}"
    return api
