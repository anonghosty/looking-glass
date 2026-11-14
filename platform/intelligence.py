"""The Intelligence portal (/intelligence, 2026-11-14): Shadowserver's Intelligence reports for analysts.

The report map (report_map.py) places 15 Shadowserver reports in its Intelligence section, in five groups: compromised
systems and victims, malicious content hosted in the constituency, reputation (listed or targeted), leaked accounts, and
attacker infrastructure. Until now only three of them (Compromised Website, Compromised IoT Device, Block Listed IP
Addresses) reached anyone, mixed into the services platform. This module reads them on their own:

* read-only queries on the reports' MongoDB collections, by report day (the date in the file name, the day Shadowserver
  sent it), the last 8 days; the file-name index makes each query cheap. Hosts outside the constituency (Settings) are
  left out, as on both platforms;
* per group: today against the median of the 7 days before, and "still arriving: N of the usual M" while the day's
  reports come in; per report a card in plain words, a detail view on its own fields with filters, a CSV export
  (export permission, written to the audit log), each host's cross-view (what else it carries: the other Intelligence
  reports of the week, and every category the services platform knows for it);
* reports never received are listed with why that may be, in plain words;
* reports without an IP address (Ransomware Victim, Compromised Account, Sandbox-DNS) are read like the others; leaked
  accounts are masked unless the analyst asks to see them (and that is written to the audit log);
* an analyst code and finding from a filtered view: the page sends the view's devices to /api/analyst-codes (acodes.py),
  which checks and keeps them as for any other selection;
* management gets the counts only (/api/intelligence/totals): totals and the 7-day trend per group, never a host.

API (analysts only): GET /api/intelligence, GET /api/intelligence/report,
GET /api/intelligence/export.csv, GET /api/intelligence/host; management: GET /api/intelligence/totals.
Installed from app.py: intelligence.install(app, ctx).
"""
import io
import ipaddress
import re
import statistics
import threading
import time
from collections import Counter, OrderedDict
from datetime import datetime, timedelta, timezone

from flask import Response, g, jsonify, render_template, request

import csvsafe

DAYS = 8                     # today and the 7 days it is compared with
ROW_CAP = 20000              # rows read per report and day at most (a report this size would be unusual)
SHOW_CAP = 500               # rows sent to the page per view (the export carries them all)
CODE_HOSTS = 150             # devices an analyst code may be made of from one view
TTL = 120                    # seconds the counts are kept
GROUP_ORDER = ["Compromised systems and victims", "Malicious content hosted in the constituency",
               "Reputation: listed or targeted", "Leaked accounts and credentials", "Attacker infrastructure found in the constituency"]
SKIP = {"_id", "line_hash", "filename", "category", "extracted_date", "logged_date"}
ACCOUNT_FIELDS = {"email", "username"}     # leaked accounts: masked, never filtered or searched unless revealed (audited)
# the fields each report's detail view filters on (the design agreed 2026-11-14), then what each shows in a row
FIELDS = {
    "compromised_website": ["url", "application", "tag", "detail", "sector", "server"],
    "compromised_website6": ["url", "application", "tag", "detail", "sector", "server"],
    "compromised_iot": ["device_vendor", "device_type", "device_model", "tag", "sector"],
    "compromised_iot6": ["device_vendor", "device_type", "device_model", "tag", "sector"],
    "blocklist": ["source", "reason"],
    "malware_url": ["url", "application", "tag", "source", "sector"],
    "sandbox_url": ["url", "method", "user_agent", "sector"],
    "sandbox_conn": ["protocol", "port", "sector"],
    "targeted_host": ["application", "tag", "detail", "device_vendor", "device_type", "sector"],
    "targeted_host6": ["application", "tag", "detail", "device_vendor", "device_type", "sector"],
    "scan_post_exploitation_framework": ["tag", "beacon_type", "beacon_host", "version"],
    "spam_url": ["url", "tag", "sector"],
    "ransomware_victim": ["entity_name", "website", "sector", "ransomware", "date_published"],
    "compromised_account": ["email", "username", "service", "tag", "public_source"],
    "sandbox_dns": ["request", "request_type", "response", "family", "source"],
}
NAMES = {"url": "URL", "application": "Application", "tag": "Tag", "detail": "Detail", "sector": "Sector", "server": "Server",
         "device_vendor": "Vendor", "device_type": "Device type", "device_model": "Model", "source": "Source", "reason": "Reason",
         "method": "Method", "user_agent": "User agent", "protocol": "Protocol", "port": "Port", "beacon_type": "Beacon type",
         "beacon_host": "Beacon host", "version": "Version", "entity_name": "Organisation", "website": "Website",
         "ransomware": "Ransomware", "date_published": "Published", "email": "E-mail", "username": "User name",
         "service": "Service", "public_source": "Public source", "request": "Domain asked", "request_type": "Record type",
         "response": "Answer", "family": "Malware family", "ip": "IP address", "hostname": "Host name", "asn": "Network",
         "region": "Region", "city": "City", "timestamp": "Seen", "severity": "Severity"}
# in plain words: what a record of each report means
MEANING = {
    "compromised_website": "A website in the constituency that has been broken into: defaced, serving malware or phishing, or carrying a backdoor.",
    "compromised_website6": "The same, for websites reached over IPv6.",
    "compromised_iot": "A device (router, camera, DVR…) that shows signs of being taken over, such as an implant or a known backdoor.",
    "compromised_iot6": "The same, for devices reached over IPv6.",
    "blocklist": "An address in the constituency that appears on a public block list, with the list and the reason it gives.",
    "malware_url": "A web address on a host in the constituency that serves malware.",
    "sandbox_url": "A web address on a host in the constituency that malware contacted when it ran in Shadowserver's sandbox.",
    "sandbox_conn": "A host in the constituency that malware connected to when it ran in the sandbox.",
    "targeted_host": "A host in the constituency seen being targeted by attacks (exploitation attempts aimed at it).",
    "targeted_host6": "The same, over IPv6.",
    "scan_post_exploitation_framework": "A command-and-control server of a post-exploitation framework (such as Cobalt Strike) found in the constituency.",
    "spam_url": "A host in the constituency sending spam that carries links, or hosting the linked pages.",
    "ransomware_victim": "An organisation in the constituency named on a ransomware group's leak site.",
    "compromised_account": "An account on a domain of the constituency whose credentials were found leaked or stolen.",
    "sandbox_dns": "A domain of the constituency that malware looked up when it ran in the sandbox.",
}
NO_IP = "The report names organisations, accounts or domains, not IP addresses: it reaches a CSIRT through a domain filter. Ask Shadowserver to add the constituency's domains."
NOT_RECEIVED = "Shadowserver sent no file of this report in the last {days} days: either nothing of this kind was seen in the constituency, or the subscription does not include it. Shadowserver can say which."


def _mask_email(v):
    v = str(v or "")
    if "@" not in v:
        return _mask_word(v)
    user, dom = v.split("@", 1)
    return f"{user[:1]}•••@{dom}"


def _mask_word(v):
    v = str(v or "")
    return f"{v[:1]}•••" if v else ""


def _s(v):
    if v is None:
        return ""
    if isinstance(v, datetime):
        return v.strftime("%Y-%m-%d %H:%M:%S")
    return str(v)


def _ip_ok(v):
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def install(app, ctx):
    """ctx: db, report_map (report_map.ReportMap), settings (settings.Settings), has_perm(p), is_demo(), audit,
    cross(hosts) -> every category the services platform knows for these hosts (services_intel.for_hosts),
    svc_reports() -> the report names the services platform holds."""
    db, hp = ctx["db"], ctx["has_perm"]
    lock, cache = threading.Lock(), {}

    def analyst():
        # analysts only (user, 2026-11-14): not administrators or other roles that also see addresses and export
        return (getattr(g, "user", None) or {}).get("role") == "analyst" and hp("unmasked") and hp("export")

    def me():
        return (getattr(g, "user", None) or {}).get("user", "")

    def today():
        return datetime.now(timezone.utc).date()

    def days():
        t = today()
        return [(t - timedelta(days=i)).isoformat() for i in range(DAYS)]          # today first

    def entries():
        """The Intelligence reports of the report map, in its group order."""
        try:
            rep = (ctx["report_map"].get() or {}).get("reports") or {}
        except Exception:                                   # noqa: BLE001 (the map is being rebuilt: the last copy)
            rep = {}
        out = [dict(e, name=k) for k, e in rep.items() if isinstance(e, dict) and e.get("section") == "Intelligence"]
        out.sort(key=lambda e: (GROUP_ORDER.index(e.get("group")) if e.get("group") in GROUP_ORDER else 9, e.get("title") or e["name"]))
        return out

    def scoped(rows):
        st = ctx["settings"]
        if not getattr(st, "restricted", False):
            return rows
        return [r for r in rows if not r.get("ip") or st.in_scope(r.get("asn"), r.get("ip"))]

    def read(name, day, cap=ROW_CAP):
        """The rows of a report sent on that day (file name date), in the constituency."""
        if name not in names():
            return []
        rows = list(db[name].find({"filename": {"$regex": "^" + re.escape(day)}}, {k: 0 for k in ("_id", "line_hash")}).limit(cap))
        return scoped(rows)

    def names():
        try:
            return set(db.list_collection_names())
        except Exception:                                   # noqa: BLE001
            return set()

    def counts():
        """{report: {day: rows}} for the 8 days, kept TTL seconds (the constituency's version in the key)."""
        key = (today().isoformat(), getattr(ctx["settings"], "version", 0))
        with lock:
            hit = cache.get("counts")
            if hit and hit[0] == key and time.time() - hit[1] < TTL:
                return hit[2]
        have = names()
        out = {}
        for e in entries():
            n = e["name"]
            if n not in have:
                continue
            per = {}
            restricted = getattr(ctx["settings"], "restricted", False)
            for d in days():
                q = {"filename": {"$regex": "^" + re.escape(d)}}
                if restricted:
                    per[d] = len(scoped(list(db[n].find(q, {"ip": 1, "asn": 1, "_id": 0}).limit(ROW_CAP))))
                else:
                    per[d] = db[n].count_documents(q)
            out[n] = per
        with lock:
            cache["counts"] = (key, time.time(), out)
        return out

    def ever(name):
        """Has this report ever been received (any row kept, any day)?"""
        try:
            return name in names() and db[name].estimated_document_count() > 0
        except Exception:                                   # noqa: BLE001
            return False

    def summary():
        ds, c = days(), counts()
        t, before = ds[0], ds[1:]
        groups, not_received, arrived_today, usual = OrderedDict(), [], 0, []
        for d in before:                                    # how many Intelligence reports usually arrive a day
            usual.append(sum(1 for per in c.values() if per.get(d)))
        for e in entries():
            n, per = e["name"], c.get(e["name"]) or {}
            no_ip = not e.get("has_ip", True)
            card = {"name": n, "title": e.get("title") or n, "group": e.get("group") or "", "meaning": MEANING.get(n, ""),
                    "affected": e.get("affected") or "", "severity": e.get("severity") or "", "url": e.get("url") or "",
                    "no_ip": no_ip, "fields": [{"key": f, "label": NAMES.get(f, f)} for f in FIELDS.get(n, [])],
                    "per_day": [{"day": d, "rows": per.get(d, 0)} for d in reversed(ds)],
                    "today": per.get(t, 0), "median": statistics.median([per.get(d, 0) for d in before]),
                    "received": any(per.values()), "kept": ever(n)}
            if per.get(t):
                arrived_today += 1
            gr = groups.setdefault(card["group"], {"group": card["group"], "reports": [], "today": 0, "per_day": Counter()})
            gr["reports"].append(card)
            gr["today"] += card["today"]
            for d in ds:
                gr["per_day"][d] += per.get(d, 0)
            if not card["received"]:
                not_received.append({"name": n, "title": card["title"], "group": card["group"], "kept": card["kept"],
                                     "why": NO_IP if no_ip else NOT_RECEIVED.format(days=DAYS)})
        out = []
        for gr in groups.values():
            gr["median"] = statistics.median([gr["per_day"][d] for d in before])
            gr["per_day"] = [{"day": d, "rows": gr["per_day"][d]} for d in reversed(ds)]
            gr["received"] = sum(1 for r in gr["reports"] if r["received"])
            out.append(gr)
        usual_n = int(statistics.median(usual)) if usual else 0
        return {"today": t, "days": list(reversed(ds)), "groups": out, "not_received": not_received,
                "arriving": {"in": arrived_today, "usual": usual_n, "still": arrived_today < usual_n},
                "generated": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")}

    def refuse():
        if not analyst():
            return jsonify(error="Abused or Compromised is for analysts."), 403
        if ctx["is_demo"]():
            return jsonify(error="Demo mode is on: the Intelligence portal shows real records. Switch demo mode off to open it."), 403
        return None

    def entry_of(name):
        return next((e for e in entries() if e["name"] == name), None)

    def view_rows(name, day, args, reveal):
        """The rows of one report on one day, filtered on its own fields (exact values) and a free text."""
        rows = read(name, day)
        fields = FIELDS.get(name, []) + ["ip", "asn", "region"]
        if name == "compromised_account" and not reveal:
            # leaked accounts: a filter or search on the account itself would confirm a leak without the reveal being
            # logged (review 2026-11-14), so masked views filter and search only the other fields
            fields = [f for f in fields if f not in ACCOUNT_FIELDS]
        flt = {f: args.getlist(f) for f in fields if args.getlist(f)}
        text = (args.get("q") or "").strip().lower()[:120]
        out = []
        for r in rows:
            if any(_s(r.get(f)) not in set(v) for f, v in flt.items()):
                continue
            if text and not any(text in _s(v).lower() for k, v in r.items() if k not in SKIP
                                and not (name == "compromised_account" and not reveal and k in ACCOUNT_FIELDS)):
                continue
            out.append(r)
        if name == "compromised_account" and not reveal:      # leaked accounts: masked unless asked for
            out = [dict(r, email=_mask_email(r.get("email")), username=_mask_word(r.get("username"))) for r in out]
        return out, flt, text

    def val(k, x):
        """A field as the page shows it: a network by its name and number, never a bare number."""
        v = _s(x.get(k))
        if k == "asn" and v:
            try:
                nm = ctx["network"](v)
            except Exception:                               # noqa: BLE001
                nm = ""
            return f"{nm} (AS{v})" if nm else f"AS{v}"
        return v

    def columns(name, rows):
        first = ["timestamp"] + (["ip", "hostname", "asn", "region", "city"] if any(r.get("ip") for r in rows[:50]) else [])
        cols = first + [f for f in FIELDS.get(name, []) if f not in first]
        seen = []
        for r in rows[:200]:
            for k in r:
                if k not in SKIP and k not in cols and k not in seen:
                    seen.append(k)
        return cols, seen

    @app.route("/intelligence")
    def intelligence_page():
        if not analyst():
            return render_template("denied.html", message="Abused or Compromised is for analysts."), 403
        return render_template("intelligence.html")

    @app.route("/api/intelligence")
    def api_intelligence():
        r = refuse()
        if r:
            return r
        return jsonify(summary())

    @app.route("/api/intelligence/report")
    def api_intelligence_report():
        r = refuse()
        if r:
            return r
        name, day = (request.args.get("name") or "").strip(), (request.args.get("day") or "").strip() or today().isoformat()
        e = entry_of(name)
        if not e:
            return jsonify(error="Not an Intelligence report."), 404
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", day) or day not in days():
            return jsonify(error=f"Choose one of the last {DAYS} days."), 400
        reveal = request.args.get("reveal") == "1" and name == "compromised_account"
        rows, flt, text = view_rows(name, day, request.args, reveal)
        rows.sort(key=lambda x: _s(x.get("timestamp")), reverse=True)        # the newest first
        if reveal:
            ctx["audit"].add("intelligence_reveal", user=me(), target=name, detail=f"{day} · {len(rows)} leaked account(s) shown unmasked")
        cols, extra = columns(name, rows)
        facets = []
        for f in FIELDS.get(name, []):
            if name == "compromised_account" and not reveal and f in ACCOUNT_FIELDS:
                continue                                 # masked accounts are not offered as filters
            c = Counter(_s(x.get(f)) for x in rows if _s(x.get(f)))
            if c:
                facets.append({"key": f, "label": NAMES.get(f, f), "values": [{"value": v, "rows": k} for v, k in c.most_common(12)],
                               "more": max(0, len(c) - 12)})
        # networks and regions too, as the platforms' analysis shows them (a network by its name; the filter is its number)
        if rows and any(x.get("ip") for x in rows[:50]):
            for f, lab in (("asn", "Networks"), ("region", "Regions")):
                c = Counter(_s(x.get(f)) for x in rows if _s(x.get(f)))
                if c:
                    facets.append({"key": f, "label": lab, "values": [{"value": v, "label": val(f, {f: v}), "rows": k} for v, k in c.most_common(12)],
                                   "more": max(0, len(c) - 12)})
        hosts = sorted({_s(x.get("ip")) for x in rows if _ip_ok(x.get("ip"))})
        stats = {"records": len(rows), "hosts": len(hosts),
                 "networks": len({_s(x.get("asn")) for x in rows if _s(x.get("asn"))}),
                 "regions": len({_s(x.get("region")) for x in rows if _s(x.get("region"))}),
                 "fields": [{"label": NAMES.get(f, f), "values": len({_s(x.get(f)) for x in rows if _s(x.get(f))})}
                            for f in FIELDS.get(name, [])[:3] if not (name == "compromised_account" and not reveal and f in ACCOUNT_FIELDS)]}
        # the records' own days (their time stamps): an analyst code is made on the day most of them were seen
        rec_days = Counter(_s(x.get("extracted_date") or x.get("timestamp"))[:10] for x in rows if x.get("extracted_date") or x.get("timestamp"))
        code = None
        # only a report the services platform holds: an analyst code stands for that platform's records (acodes.py)
        if hosts and e.get("has_ip") is not False and name in ctx["svc_reports"]():
            code = {"possible": len(hosts) <= CODE_HOSTS, "hosts": len(hosts), "max": CODE_HOSTS,
                    "query": "&".join([f"report={name}"] + [f"ip={h}" for h in hosts[:CODE_HOSTS]]),
                    "at": (rec_days.most_common(1)[0][0] + "T12:00:00Z") if rec_days else f"{day}T00:00:00Z"}
        return jsonify(name=name, title=e.get("title") or name, day=day, days=list(reversed(days())), total=len(rows), stats=stats,
                       hosts=len(hosts), shown=min(len(rows), SHOW_CAP), columns=[{"key": k, "label": NAMES.get(k, k.replace("_", " ").capitalize())} for k in cols],
                       extra=extra, rows=[{k: val(k, x) for k in cols + extra if x.get(k) not in (None, "")} for x in rows[:SHOW_CAP]],
                       facets=facets, filters={k: v for k, v in flt.items()}, q=text, masked=name == "compromised_account" and not reveal,
                       can_reveal=name == "compromised_account", code=code, no_ip=e.get("has_ip") is False, meaning=MEANING.get(name, ""))

    @app.route("/api/intelligence/export.csv")
    def api_intelligence_export():
        r = refuse()
        if r:
            return r
        name, day = (request.args.get("name") or "").strip(), (request.args.get("day") or "").strip()
        if not entry_of(name) or day not in days():
            return jsonify(error="Not an Intelligence report on one of the last days."), 400
        reveal = request.args.get("reveal") == "1" and name == "compromised_account"
        rows, flt, text = view_rows(name, day, request.args, reveal)
        cols, extra = columns(name, rows)
        buf = io.StringIO()
        w = csvsafe.writer(buf)          # a value starting with = + - @ never runs as a spreadsheet formula
        w.writerow(cols + extra)
        for x in rows:
            w.writerow([val(k, x) for k in cols + extra])
        ctx["audit"].add("intelligence_export", user=me(), target=name,
                         detail=f"{day} · {len(rows)} row(s)" + (" · filtered" if flt or text else "") + (" · accounts unmasked" if reveal else ""))
        fn = f"looking-glass_{name}_{day.replace('-', '')}.csv"
        return Response("﻿" + buf.getvalue(), mimetype="text/csv",
                        headers={"Content-Disposition": f'attachment; filename="{fn}"', "Cache-Control": "no-store"})

    @app.route("/api/intelligence/host")
    def api_intelligence_host():
        """One host across the week's Intelligence reports and every category the services platform knows for it."""
        r = refuse()
        if r:
            return r
        ip = (request.args.get("ip") or "").strip()
        if not _ip_ok(ip):
            return jsonify(error="Not an IP address."), 400
        seen = []
        have = names()
        for e in entries():
            if e["name"] not in have or e.get("has_ip") is False:
                continue
            rows = scoped(list(db[e["name"]].find({"ip": ip, "filename": {"$regex": "^(" + "|".join(re.escape(d) for d in days()) + ")"}},
                                                  {"_id": 0, "line_hash": 0}).limit(200)))
            if rows:
                ds = sorted({_s(x.get("filename"))[:10] for x in rows})
                facts = OrderedDict()
                for f in FIELDS.get(e["name"], []):
                    vals = sorted({_s(x.get(f)) for x in rows if _s(x.get(f))})
                    if vals:
                        facts[NAMES.get(f, f)] = vals[:6]
                seen.append({"name": e["name"], "title": e.get("title") or e["name"], "group": e.get("group") or "", "rows": len(rows),
                             "days": ds, "facts": facts})
        try:
            cross = ctx["cross"]([ip]) or {}
        except Exception:                                   # noqa: BLE001 (the services days are being loaded)
            cross = {}
        ctx["audit"].add("intelligence_host", user=me(), target=ip, detail=f"{len(seen)} Intelligence report(s)")
        return jsonify(ip=ip, intelligence=seen, services=cross.get("services") or [], issues=cross.get("issues") or [],
                       infections=cross.get("infections") or [])

    @app.route("/api/intelligence/totals")
    def api_intelligence_totals():
        """For the Executive portal (and anyone who may open the Intelligence portal): counts only, never a host."""
        if not (hp("management") or analyst()):
            return jsonify(error="Not for this role."), 403
        s = summary()
        return jsonify(today=s["today"], days=s["days"], arriving=s["arriving"],
                       groups=[{"group": gr["group"], "today": gr["today"], "median": gr["median"], "per_day": gr["per_day"],
                                "received": gr["received"], "reports": len(gr["reports"])} for gr in s["groups"]],
                       not_received=len(s["not_received"]))

    api = type("IntelligenceAPI", (), {})()
    api.summary, api.counts, api.read, api.entries = summary, counts, read, entries
    api.reset = lambda: cache.clear()
    return api
