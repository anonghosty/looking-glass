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

A selection also has a code, LG-B-XXXXXXXX, kept in the combination code book (combos.py) like the LG-C and LG-X
codes: a researcher moves it to a note ("Move to notes" on a "Beacon vs name" match), and a note sent on as a finding
carries the selection (notes.py), so that exact drill-down is worked on in Findings. Like every code it carries no
address, and a viewer who does not see hosts gets it only for a selection 5 or more devices carry (small_codes.py).

API: POST /api/beacon/finding {name, format, operator, version, os_family, kind: analyst|management, to, comment, title},
GET /api/beacon/finding/<id>, GET /api/beacon/code?name=&format=&operator=&version=&os_family=.
Installed from app.py: beacon_findings.install(app, ctx).
"""
import hashlib
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
        os_name = beacon_decode.OS_TITLE.get(sel["os_family"], sel["os_family"])
        if parts == "decoded beacons":        # the OS alone: "decoded beacons that say Windows, under android.badbox2"
            return f"decoded beacons that say {os_name}, under {sel['name']}"
        parts += f" ({os_name})"
    return f"{parts} under {sel['name']}"


def finding_title(sel, display="", held=False):
    """A finding's title people read at a glance: "BADBOX 2.0 beacons from Windows machines (android.badbox2)". The
    family's readable name (its definition's title) first, the infection name for reference; held: the parts are
    held back (fewer than 5 devices, a viewer who does not see hosts), so the title names none of them."""
    name = sel["name"]
    fam = display or name
    ref = f" ({name})" if display and display.lower() != name.lower() else ""
    if held:
        return f"{fam} decoded beacons{ref}"[:140]
    if sel.get("os_family"):
        what = f"beacons from {beacon_decode.OS_TITLE.get(sel['os_family'], sel['os_family'])} machines"
    elif sel.get("operator"):
        what = f"beacons from operator {sel['operator']}"
    elif sel.get("format") == "generic":
        what = "values found by generic decoding"
    elif sel.get("format"):
        what = f"{format_title(sel['format'])} beacons"
    else:
        what = "decoded beacons"
    return f"{fam} {what}{ref}"[:140]


def display_of(ctx, name):
    """The definition's title of an infection name ("BADBOX 2.0"), or "" when it has none."""
    try:
        return (ctx.get("defined") or (lambda: {}))().get(("infections", name.lower()), "") or ""
    except Exception:  # noqa: BLE001 - a title is a nicety: the finding is made without it
        return ""


def code_key(sel):
    """What a selection is, as the code book keys it: the name (any case) and its parts."""
    return "b|" + sel["name"].lower() + "|" + "|".join(f"{p}={sel[p]}" for p in PARTS if p in sel)


def beacon_code(book, sel, display=""):
    """The selection's LG-B code: made from the selection, so the same drill-down always has the same code; recorded in
    the code book (once a day at most) so notes and findings can read what it stands for."""
    key = code_key(sel)
    for n in range(1, 50):
        code = "LG-B-" + hashlib.sha256(f"{key}#{n}".encode() if n > 1 else key.encode()).hexdigest()[:8].upper()
        e = book.get(code)
        if e is None or e.get("key") == key:
            break
    if e is None or e.get("last") != time.strftime("%Y-%m-%d", time.gmtime()):
        book.put(code, {"kind": "b", "section": "infections", "name": sel["name"], "key": key, "text": describe(sel),
                        "title": finding_title(sel, display), "beacon": {p: sel[p] for p in PARTS if p in sel}})
    return code


def selection_of(book, code):
    """The selection an LG-B code stands for, or None."""
    e = book.get(code) if code.startswith("LG-B-") else None
    if not e or e.get("kind") != "b":
        return None
    return {"name": e["name"], **{p: v for p, v in (e.get("beacon") or {}).items() if p in PARTS}}


# set by install(): makes a finding's analyst selection (notes.py calls it for a note tracked as a finding)
_ATTACH = {"fn": None}


def attach_selection(fid):
    """The finding's records as an analyst selection (LG-A) on the finding, so management opens it in the Executive
    portal like every drill-down. None when it cannot be made (no records in memory, analyst codes not installed)."""
    fn = _ATTACH["fn"]
    try:
        return fn(fid) if fn else None
    except Exception:  # noqa: BLE001 - the finding stands without it; the Findings page still shows its beacons
        return None


class BeaconFindings:
    def __init__(self, ctx):
        self.ctx = ctx

    def events(self, sel):
        """Every record of the days in memory behind a selection (the analyst selection is made of exactly these)."""
        return [e for d in self.ctx["store"].days.values() for e in d.events if matches(e, sel)]

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

    def attach(fid):
        """Management's normal view of a beacon finding: an analyst code (LG-A) for exactly its records, added to the
        finding (its channel alone opens it, acodes.py), so "Show in Executive" filters the Executive portal to them."""
        x = f.get(fid)
        acodes = ctx.get("acodes")
        if not x or not x.get("beacon") or not acodes or x.get("beacon_selection"):
            return (x or {}).get("beacon_selection")
        sel = x["beacon"]
        evs = bf.events(sel)
        if not evs:
            return None
        # the label is read by everyone in the channel: the parts stay out of it while fewer than 5 devices carry them,
        # as in the finding's title and summary (security review of 3ba9e60)
        held = len({e.get("src_ip") for e in evs if e.get("src_ip")}) < MIN_HOSTS
        label = f"{finding_title(sel, display_of(ctx, sel['name']), held)}: the records behind finding #{fid}"
        code = acodes.make_selection("comms", evs, x.get("beacon_code") or "", label, {"beacon": sel})
        if not code:
            return None
        with f.lock:
            f._load()
            it = f.data["items"].get(fid)
            if it is not None:
                it.setdefault("codes", []).append(code)
                it["beacon_selection"] = code
                f._save()
        return code

    _ATTACH["fn"] = attach

    def visible(code):
        """May this viewer learn that an LG-B code stands for something? Viewers who see hosts always; everyone else only
        while 5 or more devices carry its selection, so a code worked out offline answers like an unknown one
        (security review of 373c1e2)."""
        if ctx["sees_hosts"]():
            return True
        sel = selection_of(ctx.get("book"), code) if ctx.get("book") else None
        return bool(sel) and len(bf.scan(sel, False)[1]) >= MIN_HOSTS

    if ctx.get("book") is not None:
        ctx["book"].beacon_visible = visible

    @app.route("/api/beacon/code")
    def api_beacon_code():
        """The LG-B code of a selection, for "Move to notes": researchers (5 or more devices), analysts and admins."""
        if not (hp("definitions") or hp("settings") or hp("unmasked")):
            return jsonify(error="Researchers, analysts and admins move decoded beacons to notes."), 403
        book = ctx.get("book")
        sel = selection(request.args)
        if not sel["name"] or not book:
            return jsonify(error="Name the infection the beacons are filed under."), 400
        n, hosts, _, _, _ = bf.scan(sel, False)
        if not ctx["sees_hosts"]() and len(hosts) < MIN_HOSTS:
            # the same answer as no record at all (security review of 5b232a7): a guess learns nothing
            return jsonify(error=f"No selection of {MIN_HOSTS} or more devices carries these beacons in the days in memory: "
                                 "an analyst can hand them over."), 404
        if not n:
            return jsonify(error="No record in the days in memory carries these beacons."), 404
        display = display_of(ctx, sel["name"])
        code = beacon_code(book, sel, display)
        return jsonify(code=code, text=describe(sel), title=finding_title(sel, display), records=n, devices=len(hosts))

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
        if not full and len(hosts) < MIN_HOSTS:
            # the researcher was never shown a selection fewer than 5 devices carry: it cannot come from their page. The
            # same answer as "no record at all", so guessing parts can't tell a held-back value from one that does not
            # exist (security review of 5b232a7)
            return jsonify(error=f"No selection of {MIN_HOSTS} or more devices carries these beacons in the days in memory: "
                                 "an analyst can hand them over."), 404
        if not n:
            return jsonify(error="No record in the days in memory carries these beacons."), 404
        comment = str(b.get("comment") or "").replace("\r", "").strip()[:1000]
        held = len(hosts) < MIN_HOSTS                  # the title is read by everyone in the channel
        title = (str(b.get("title") or "").strip()[:140] or finding_title(sel, display_of(ctx, sel["name"]), held))[:140]
        text = comment or (f"Looking Glass decoded {n} beacon check-in{'s' if n != 1 else ''} ({describe(sel, held)}) from "
                           f"{len(hosts)} device{'s' if len(hosts) != 1 else ''} in {', '.join(reps)}. These requests need a "
                           f"serious look: what the devices are, and whether the records are filed under the right name.")
        user, role = me()
        item = f.create({"id": None, "text": text, "codes": []}, "infections", sel["name"], title, user, role, to, kind,
                        extra={"beacon": sel, "beacon_at_create": {"records": n, "devices": len(hosts), "at": round(time.time(), 3)}})
        ctx["audit"].add("finding_created", user=user, target=f"#{item['id']} {sel['name']}",
                         detail=f"decoded beacons · to {to} · " + item["title"][:120])
        attach_selection(item["id"])
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
        if not x.get("beacon_selection"):
            # a beacon finding made before its analyst selection was (2026-11-16): made once, now, from the same records
            attach_selection(x["id"])
        # the Findings page shows no address until an analyst asks for the devices (records=1; logged, data_access.py)
        full = ctx["sees_hosts"]()
        out = bf.summary(x["beacon"], full, x.get("beacon_at_create"), records=request.args.get("records") == "1")
        out["can_records"] = bool(full)
        return jsonify(out)

    return bf
