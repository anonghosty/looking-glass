"""Handing decoded beacons over: a researcher (or an analyst) sends the beacons Looking Glass decoded under a name to an
analyst or a manager, as a finding (findings.py), so they are looked into seriously and not lost in a mailbox.

What the finding holds is a selection, never a device: the infection name and the beacon's threat-side parts (format,
operator, version, OS family; an empty part means any). Who opens it sees it at their own level, worked out again from
the days in memory each time:

* analysts and admins (the 'unmasked' permission, demo off): the counts and the whole selection; on request
  (GET ...?records=1, "Show the devices", logged by data_access.py) every record behind it, with the host address they
  already see on the map, the time, the report (its readable name), the whole decoded JSON and the notes
  (beacon_decode.view). The Findings page shows no address until then;
* everyone else in the channel (researchers, management, advisors): counts only (records, devices, reports, days) and
  the selection, its parts held back while fewer than 5 devices carry it (the per-device rule).

Every hand-over names a person; only the people in the finding's channel and admins see it (findings.py). A researcher
may hand over only what they can see: a selection 5 or more devices carry.

API: POST /api/beacon/finding {name, format, operator, version, os_family, kind: analyst|management, to, comment, title},
GET /api/beacon/finding/<id>. Installed from app.py: beacon_findings.install(app, ctx).
"""
import time

from flask import g, jsonify, request

import beacon_decode

MIN_HOSTS = 5
MAX_RECORDS = 500                      # records listed for an analyst (the counts cover all of them)
PARTS = ("format", "operator", "version", "os_family")
PART_LABEL = {"format": "Format", "operator": "Operator", "version": "Version", "os_family": "OS"}


def selection(b):
    """The selection a request names: the name and the parts given (each at most 80 characters)."""
    sel = {"name": str(b.get("name") or "").strip()[:120]}
    for p in PARTS:
        v = str(b.get(p) or "").strip()[:80]
        if v:
            sel[p] = v
    return sel


def matches(e, sel):
    """The record is filed under the name and carries a beacon with every part the selection gives."""
    if (e.get("infection") or "").lower() != sel["name"].lower():
        return None
    url = e.get("http_url") or ""
    host = (e.get("http_host") or "").lower() or None
    for d in beacon_decode.decode(url) + beacon_decode.seen(url, host):
        pub = beacon_decode.public(d)
        if all(pub.get(p) == sel[p] or (p == "format" and pub.get("id") == sel[p]) for p in PARTS if p in sel):
            return d
    return None


def format_title(fmt):
    """A format's readable name ("clogin" -> "CLogin check-in"), never its code."""
    if fmt == "generic":
        return "Generic decode"
    for f in list(beacon_decode.FORMATS) + list(getattr(beacon_decode, "OPAQUE", [])):
        if getattr(f, "name", None) == fmt:
            return f.title
    return fmt


def shown_value(part, v):
    """A part as people read it: the format's title, the operating system's name."""
    if part == "format":
        return format_title(v)
    if part == "os_family":
        return beacon_decode.OS_TITLE.get(v, v)
    return v


def describe(sel, held=False):
    """The selection in words: "CLogin check-in WT:1.0.0 (Windows) under android.badbox2"."""
    if held:
        return f"decoded beacons under {sel['name']}"
    parts = " ".join(shown_value(p, sel[p]) for p in ("format", "version") if p in sel) or "decoded beacons"
    if "operator" in sel and sel["operator"].lower() not in parts.lower():
        parts += f", operator {sel['operator']}"
    if "os_family" in sel:
        parts += f" ({beacon_decode.OS_TITLE.get(sel['os_family'], sel['os_family'])})"
    return f"{parts} under {sel['name']}"


class BeaconFindings:
    def __init__(self, ctx):
        self.ctx = ctx

    def scan(self, sel, want_records):
        """(records, hosts, reports, days, [record views]) for a selection over the days in memory."""
        labels = self.ctx["labels"]()
        n, hosts, reps, days, rows = 0, set(), set(), set(), []
        for d in self.ctx["store"].days.values():
            for e in d.events:
                b = matches(e, sel)
                if not b:
                    continue
                n += 1
                if e.get("src_ip"):
                    hosts.add(e["src_ip"])
                rep = labels.get(e.get("source"), e.get("source") or "")
                reps.add(rep)
                days.add(d.start.date().isoformat())
                if want_records and len(rows) < MAX_RECORDS:
                    full = beacon_decode.view(e, sel["name"], (e.get("http_host") or "").lower() or None)
                    rows.append({"host": e.get("src_ip") or "", "port": e.get("src_port") or "", "time": str(e.get("timestamp") or "")[:19],
                                 "report": rep, "c2": e.get("http_host") or "", "beacons": full})
        return n, hosts, sorted(reps), sorted(days), rows

    def summary(self, sel, full, at_create=None, records=None):
        """full: the viewer sees hosts (the selection is never held back for them); records: list the records too
        (only ever for such a viewer)."""
        records = full if records is None else (records and full)
        n, hosts, reps, days, rows = self.scan(sel, records)
        devices = len(hosts)
        held = not full and max(devices, (at_create or {}).get("devices", 0)) < MIN_HOSTS
        shown = {p: sel[p] for p in PARTS if p in sel and not held}
        out = {"name": sel["name"], "selection": [{"label": PART_LABEL[p], "value": shown_value(p, v)} for p, v in shown.items()],
               "held": held, "records": n, "devices": devices, "reports": reps, "days": days,
               "said": describe(sel, held)[0].upper() + describe(sel, held)[1:],
               "contradicts": bool(sel.get("os_family") and beacon_decode.contradicts(sel["name"], sel["os_family"]) and not held)}
        if records:
            out["records_list"] = rows
            out["more"] = max(0, n - len(rows))
        return out


def install(app, ctx):
    """ctx: store, labels(), findings (findings.Findings), people_of(kind), has_perm(p), sees_hosts(), csrf_ok(), fresh(),
    audit."""
    bf = BeaconFindings(ctx)
    hp = ctx["has_perm"]
    f = ctx["findings"]

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def team():
        return hp("definitions") or hp("management") or hp("settings") or (hp("unmasked") and hp("export")) or hp("advisory")

    @app.route("/api/beacon/finding", methods=["POST"])
    def api_beacon_finding():
        """Hand decoded beacons over to an analyst or a manager, as a finding."""
        if not (hp("definitions") or hp("settings") or hp("unmasked")):
            return jsonify(error="Researchers, analysts and admins hand decoded beacons over."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        b = request.get_json(silent=True) or {}
        sel = selection(b)
        if not sel["name"]:
            return jsonify(error="Name the infection the beacons are filed under."), 400
        kind = b.get("kind") if b.get("kind") in ("analyst", "management") else None
        if not kind:
            return jsonify(error="Send it to an analyst or to a manager."), 400
        to, err = f.recipient(kind, b.get("to"))
        if not to:
            return jsonify(error=err), 400
        full = ctx["sees_hosts"]()
        n, hosts, reps, days, _ = bf.scan(sel, False)
        if not n:
            return jsonify(error="No record in the days in memory carries these beacons."), 404
        if not full and len(hosts) < MIN_HOSTS:
            # the researcher was never shown a selection fewer than 5 devices carry: it cannot come from their page
            return jsonify(error=f"Fewer than {MIN_HOSTS} devices carry these beacons: an analyst can hand them over."), 403
        comment = str(b.get("comment") or "").replace("\r", "").strip()[:1000]
        held = len(hosts) < MIN_HOSTS                  # the title is read by everyone in the channel
        title = (str(b.get("title") or "").strip()[:140] or f"Decoded beacons: {describe(sel, held)}")[:140]
        text = comment or (f"Looking Glass decoded {n} beacon check-in{'s' if n != 1 else ''} ({describe(sel, held)}) from "
                           f"{len(hosts)} device{'s' if len(hosts) != 1 else ''} in {', '.join(reps)}. These requests need a "
                           f"serious look: what the devices are, and whether the records are filed under the right name.")
        user, role = me()
        item = f.create({"id": None, "text": text, "codes": []}, "infections", sel["name"], title, user, role, to, kind,
                        extra={"beacon": sel, "beacon_at_create": {"records": n, "devices": len(hosts), "at": round(time.time(), 3)}})
        ctx["audit"].add("finding_created", user=user, target=f"#{item['id']} {sel['name']}",
                         detail=f"decoded beacons · to {to} · " + item["title"][:120])
        return jsonify(finding={"id": item["id"], "number": f"#{item['id']}", "title": item["title"]})

    @app.route("/api/beacon/finding/<fid>")
    def api_beacon_finding_view(fid):
        """The beacons of a finding, at the viewer's level (records with hosts for analysts and admins, counts for the rest)."""
        user = me()[0]
        if not user:
            return jsonify(error="Sign in."), 403
        x = f.get(fid)
        if not x or not x.get("beacon") or not f.sees(x, user, hp("settings"), strict=not team()):
            return jsonify(error="No such finding."), 404
        # the Findings page shows no address until an analyst asks for the devices (records=1; logged, data_access.py)
        full = ctx["sees_hosts"]()
        out = bf.summary(x["beacon"], full, x.get("beacon_at_create"), records=request.args.get("records") == "1")
        out["can_records"] = bool(full)
        return jsonify(out)

    return bf
