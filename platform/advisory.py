"""Advisories: the advisor's part, after management decided. One advisory per organisation (network).

Management sends a decided finding to an advisor (findings.py: status "With the advisor"). On /advisory/<id> the advisor:

1. picks the organisation the advisory goes to: a network in the finding's kept search (combo_review.py), with how many
   of its devices (IP addresses) and records are in it;
2. sees that organisation's data: its IP addresses with their ports, reports, CVEs and issues, and the impact of
   those reports, so the advisory is drafted from what the PDF will carry;
3. writes the subject, the Description (on the impact) and the Recommended Actions (with bullets, numbering and bold:
   a light markup, **bold**, "- " bullets, "1. " numbers, kept as text and drawn in the PDF);
4. generates the report: the advisory's pages (organisation name and logo from Settings, organisation.py; the
   organisation's affected IP addresses, CVEs, issues and categories, only what holds something; the reports with
   their impact flags, data/report_impact.json; the Description with "See Technical Details for the definitions of the
   highlighted …"; the Recommended Actions; "See below for further insight into the activity"), then the analyst's
   report on that organisation's devices only, unchanged, with its definitions under Technical Details, then
   Shadowserver Report References (advisory_pdf.py). Each generated report is kept and listed with its download;
5. marks it as sent to its recipients (the organisation by default), and moves on to the next organisation.

Files are named as the CSIRT names them: <CSIRT>_<organisation>_<data title>_<yyyymmdd> (.pdf, .zip, _devices.csv …).
Each advisory is kept as JSON in data/advisories/<reference>.json (ADV-<year>-<number>) and exported as a self-describing
JSON (schema "looking-glass/advisory", version 2) without any address. The advisor's portal (/advisory) shows the
figures: waiting, drafts, sent, to which organisations, per month, the impacts most seen.

Access: the advisory permission (advisors; admins see all). Only the people in a finding's channel open its advisories.
Installed from app.py.
"""
import collections
import json
import os
import re
import threading
import time

from flask import Response, g, jsonify, render_template, request

import finding_rules
import issue_tags
import tlp

SCHEMA, VERSION = "looking-glass/advisory", 2
MAX_TEXT, MAX_SUBJECT, MAX_RECIPIENTS, MAX_RECIPIENT = 6000, 200, 30, 120
MAX_DEVICES_SHOWN = 500
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SINK = "Botnet sinkholes"                 # services_intel.SINK: the part of a code where the host calls a sinkhole
LEVELS = ["critical", "high", "medium", "low"]
ALL = ""                                  # the network of an advisory on a finding without a kept search: everything


def _now():
    return round(time.time(), 3)


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t)) if t else ""


STATUS_LABEL = {"draft": "Draft", "drafted": "Drafted", "sent": "Sent"}    # being written · ready to go out · sent
# A sent advisory is the record of what went to the organisation: its text and its report file stay exactly as they
# were sent (external review, 2026-11-11). Sending it on to more people still works, with the same file.
SENT_LOCKED = ("This advisory was sent on {day}: it can no longer be changed, so the record of what the organisation "
               "received stays exact. A correction goes out as a new message.")


def sent_day(adv):
    return _day(max((s["at"] for s in adv.get("sends") or []), default=0)) or "an earlier day"


def slug(text, n=60):
    """A file-name part: words joined by hyphens, letters and digits only."""
    return re.sub(r"[^A-Za-z0-9]+", "-", str(text or "")).strip("-")[:n].strip("-") or "x"


def _list(v):
    if isinstance(v, (list, tuple, set)):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


class Changed(Exception):
    """The advisory was changed by someone else (another tab or advisor) after it was read: nothing was written."""


CHANGED = ("This advisory was changed meanwhile (in another tab or by another advisor), so nothing was saved. "
           "Open it again to see the latest, then make your change.")


class Store:
    """The advisories, one JSON file each; the reports generated for them under files/<reference>/."""

    def __init__(self, folder):
        self.dir = folder
        self.lock = threading.Lock()

    def _all(self):
        out = []
        try:
            names = os.listdir(self.dir)
        except OSError:
            return out
        for n in names:
            if re.fullmatch(r"ADV-\d{4}-\d{3,6}\.json", n):
                try:
                    with open(os.path.join(self.dir, n), encoding="utf-8") as fh:
                        out.append(json.load(fh))
                except (OSError, ValueError):
                    continue
        return out

    def all(self):
        with self.lock:
            return self._all()

    def of(self, fid, network):
        return next((a for a in self.all() if a.get("finding") == str(fid) and a.get("network", ALL) == network), None)

    def of_finding(self, fid):
        return [a for a in self.all() if a.get("finding") == str(fid)]

    def new_ref(self):
        year = time.strftime("%Y", time.gmtime())
        nums = [int(a["ref"].rsplit("-", 1)[1]) for a in self._all() if a.get("ref", "").startswith(f"ADV-{year}-")]
        return f"ADV-{year}-{(max(nums) + 1 if nums else 1):03d}"

    def save(self, adv, create=False):
        """Write the advisory, only if nobody changed it since it was read (external review, 2026-11-12): every change
        is read, checked and written back, and a save that started before a send used to write its old copy over the
        sent one (status back to draft, the send gone). Each write raises "rev"; a write whose rev is no longer the
        stored one raises Changed and nothing is written."""
        with self.lock:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            if create:
                existing = next((a for a in self._all() if a.get("finding") == adv["finding"] and a.get("network", ALL) == adv["network"]), None)
                if existing:
                    raise Changed()
                adv["ref"] = self.new_ref()
                adv["rev"] = 1
            else:
                path = os.path.join(self.dir, f"{adv['ref']}.json")
                try:
                    with open(path, encoding="utf-8") as fh:
                        stored = json.load(fh)
                except (OSError, ValueError):
                    raise Changed()
                if int(stored.get("rev") or 0) != int(adv.get("rev") or 0):
                    raise Changed()
                adv["rev"] = int(adv.get("rev") or 0) + 1
            path = os.path.join(self.dir, f"{adv['ref']}.json")
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(adv, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, path)
            return adv

    def file_path(self, ref, n):
        if not re.fullmatch(r"ADV-\d{4}-\d{3,6}", str(ref)) or not re.fullmatch(r"\d{1,4}", str(n)):
            raise ValueError("bad file")
        return os.path.join(self.dir, "files", ref, f"{n}.zip")

    def keep_file(self, ref, n, data):
        """Keep a generated report as file n, or the next free number: a kept file is never written over (two
        generations at once each get their own). Returns the number used."""
        os.makedirs(os.path.dirname(self.file_path(ref, n)), mode=0o700, exist_ok=True)
        while True:
            try:
                fd = os.open(self.file_path(ref, n), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                break
            except FileExistsError:
                n += 1
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        return n

    def drop_file(self, ref, n):
        try:
            os.remove(self.file_path(ref, n))
        except (OSError, ValueError):
            pass


class Impact:
    """The Shadowserver reports (titles, places, addresses) and their impact flags."""

    def __init__(self, base_dir):
        self.base = base_dir
        self._c = {}

    def _json(self, name):
        p = os.path.join(self.base, "data", name)
        try:
            m = os.path.getmtime(p)
        except OSError:
            return {}
        if self._c.get(name, (None,))[0] != m:
            try:
                with open(p, encoding="utf-8") as fh:
                    self._c[name] = (m, json.load(fh))
            except (OSError, ValueError):
                self._c[name] = (m, {})
        return self._c[name][1]

    def reports(self):
        return self._json("report_map_snapshot.json").get("reports") or {}

    def entry(self, key):
        """(key, entry) of a report by its collection name or its title; (None, None)."""
        reps = self.reports()
        key = str(key or "")
        if key in reps:
            return key, reps[key]
        try:
            from report_map import sibling
            s = sibling(key)
        except Exception:                    # noqa: BLE001
            s = key
        if s in reps:
            return s, reps[s]
        for pre in ("scan_", "event4_", "scan6_"):  # the names the platforms use without their prefix
            if pre + key in reps:
                return pre + key, reps[pre + key]
        return next(((k, e) for k, e in reps.items() if e.get("title") == key), (None, None))

    def flags_of(self, key, e):
        d = self._json("report_impact.json")
        fl = (d.get("reports") or {}).get(key)
        if fl is None and e:
            sec, grp = e.get("section") or "", e.get("group") or ""
            fl = (d.get("groups") or {}).get(f"{sec}/{grp}") or (d.get("groups") or {}).get(sec) or []
        return list(fl or [])

    def flag(self, name):
        return ((self._json("report_impact.json").get("flags") or {}).get(name)) or None

    def sinkhole_reports(self):
        return [(k, e) for k, e in self.reports().items() if e.get("section") == "Infections" and "sinkhole" in k]


def install(app, ctx):
    """ctx: base_dir, findings (findings.Findings), book (combos.CodeBook, with review_report_of / review_records from
    combo_review), org (organisation.Organisation), network(asn) -> name, has_perm, csrf_ok, fresh, is_demo, audit,
    people_name(user), title_of(report), describe(code), scope_text()."""
    F, book, hp = ctx["findings"], ctx["book"], ctx["has_perm"]
    store = Store(os.path.join(ctx["base_dir"], "data", "advisories"))
    imp = Impact(ctx["base_dir"])
    name_of = ctx["people_name"]

    def me():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def allowed():
        return hp("advisory") or hp("settings")

    def finding(fid):
        if not re.fullmatch(r"\d{1,9}", str(fid)):
            return None
        x = F.get(fid)
        return x if x and F.sees(x, me()[0], hp("settings")) else None

    def ready(x):
        """An advisory can be written once management approved it and sent it to an advisor (a case: on each of its
        sub-findings, not on the case itself)."""
        if x.get("kind") == "case":
            return False
        if x.get("review"):
            return x["review"].get("decision") in ("both", "researcher")      # a rejected one has no advisory
        # with the advisor, AND management really approved it: having been "with the advisor" once is not enough
        # (anyone in the channel could set that before; external review, 2026-11-11, finding_rules.py)
        with_advisor = x["status"] in ("advisor", "advisory") or any(h.get("status") == "advisor" for h in x.get("history") or [])
        return with_advisor and finding_rules.management_approved(x)

    def kept(x):
        return bool(x.get("review") and hasattr(book, "review_kept") and book.review_kept(x["id"]))

    # ---------------- the kept search, per organisation (network)
    _cache = {}

    def records(x):
        """{entry, found, host(e), net(e), plat} of a finding's kept search, cached a minute; None without one."""
        if not kept(x):
            return None
        c = _cache.get(x["id"])
        if c and time.time() - c[0] < 60:
            return c[1]
        k, _ = book.review_records(x["id"])
        if not k:
            return None
        comms = k["entry"].get("section") == "infections"
        host = (lambda e: e.get("src_ip") or "") if comms else (lambda e: e.get("ip") or "")
        asn = (lambda e: e.get("src_asn")) if comms else (lambda e: e.get("asn"))
        names = {}

        def net(e):
            a = asn(e)
            if a not in names:
                names[a] = (ctx["network"](a) if a else "") or "Unknown"
            return names[a]
        out = dict(k, host=host, net=net, asn=asn, comms=comms)
        _cache[x["id"]] = (time.time(), out)
        return out

    def networks_of(x):
        """The organisations in the kept search: devices and records each, the most devices first."""
        k = records(x)
        if not k:
            return []
        per = {}
        for e in k["found"]:
            n = k["net"](e)
            if x.get("network") and n != x["network"]:   # a finding for one organisation: only that one
                continue
            p = per.setdefault(n, {"network": n, "devices": set(), "records": 0, "asns": set()})
            p["devices"].add(k["host"](e)); p["records"] += 1
            if k["asn"](e):
                p["asns"].add(str(k["asn"](e)))
        return sorted(({"network": p["network"], "devices": len(p["devices"]), "records": p["records"], "asns": sorted(p["asns"])}
                       for p in per.values()), key=lambda p: (-p["devices"], p["network"]))

    def report_key(e, comms):
        return str((e.get("source") if comms else e.get("report")) or "")

    def devices_of(x, network):
        """The organisation's IP addresses with what the records say about each (for the advisor and the PDF)."""
        k = records(x)
        if not k:
            return []
        devs = {}
        for e in k["found"]:
            if network != ALL and k["net"](e) != network:
                continue
            h = k["host"](e)
            d = devs.setdefault(h, {"ip": h, "network": k["net"](e), "asn": str(k["asn"](e) or ""), "ports": set(), "reports": set(),
                                    "cves": set(), "issues": set(), "labels": set(), "categories": set(), "hostname": "", "records": 0, "last": ""})
            d["records"] += 1
            port = e.get("dst_port") if k["comms"] else e.get("port")
            if port not in (None, ""):
                d["ports"].add(str(port))
            rk, re_ = imp.entry(report_key(e, k["comms"]))
            d["reports"].add((re_ or {}).get("title") or ctx["title_of"](report_key(e, k["comms"])) or report_key(e, k["comms"]))
            # CVEs; the issues (the platform's own issue names and the tags that are weaknesses, end of life included);
            # the tags that only say what the device is (product, protocol); and, on the network communications
            # platform, the infection (category) the device calls a sinkhole as
            for v in _list(e.get("issues")) + _list(e.get("tags")):
                m = CVE_RX.search(v)
                if m:
                    d["cves"].add(m.group(0).upper())
            named = [v for v in _list(e.get("issues")) if not CVE_RX.search(v)]
            tag_issues, labels = issue_tags.split(_list(e.get("tags")))
            d["issues"].update(named + tag_issues)
            d["labels"].update(labels)
            if k["comms"] and e.get("infection"):
                d["categories"].add(str(e["infection"]))
            if e.get("hostname") and not d["hostname"]:
                d["hostname"] = str(e["hostname"])
            t = str(e.get("timestamp") or e.get("extracted_date") or "")
            d["last"] = max(d["last"], t)
        def clean(d):
            iss = sorted(d["issues"])
            if "End of life" in iss and any(i.startswith("End of life (") for i in iss):
                iss.remove("End of life")
            return iss
        return sorted(({**d, "ports": sorted(d["ports"], key=lambda p: (len(p), p)), "reports": sorted(d["reports"]), "cves": sorted(d["cves"]),
                        "issues": clean(d), "labels": sorted(d["labels"]), "categories": sorted(d["categories"]),
                        "last": d["last"][:16].replace("T", " ")} for d in devs.values()),
                      key=lambda d: (-d["records"], d["ip"]))

    # ---------------- what fills in on its own, for one organisation
    def auto_of(x, network):
        rv = x.get("review") or {}
        k = records(x)
        cves, issues, cats, labels, reps = [], [], [], [], {}
        add = lambda lst, v: v and v not in lst and lst.append(v)
        devs = devices_of(x, network) if k else []
        ips = {d["ip"] for d in devs}
        entry = (k or {}).get("entry") or (book.resolve_any(rv.get("source") or ((x.get("codes") or [""])[0])) if hasattr(book, "resolve_any") else None) or {}
        if CVE_RX.fullmatch(str(entry.get("name") or "")):
            add(cves, entry["name"].upper())
        if entry.get("section") == "infections" and entry.get("name"):
            add(cats, entry["name"])
        if k:
            for e in k["found"]:
                if network != ALL and k["net"](e) != network:
                    continue
                rk, re_ = imp.entry(report_key(e, k["comms"]))
                if re_:
                    reps.setdefault(rk, (re_, None))
            for d in devs:
                for c in d["cves"]:
                    add(cves, c)
                for i in d["issues"]:
                    add(issues, i)
                for lb in d["labels"]:
                    add(labels, lb)
                for c in d["categories"]:
                    add(cats, c)
        else:                                     # no kept search: the combination's own parts
            for r, items in (entry.get("parts") or ([(entry.get("report"), entry.get("items") or [])] if entry.get("kind") == "r" else [])):
                rk, re_ = imp.entry(r)
                if re_:
                    reps.setdefault(rk, (re_, None))
                for it in items or []:
                    m = CVE_RX.search(str(it))
                    if m:
                        add(cves, m.group(0).upper())
                    elif str(it).lower().startswith("tag:"):
                        add(issues, issue_tags.issue_of(it)) if issue_tags.issue_of(it) else add(labels, str(it).split(":", 1)[1].strip().lower())
        if rv.get("decision") == "both":           # the analyst's views management added: this organisation's devices in them
            for p in rv.get("sent") or []:
                if network != ALL and not any(dv.get("ip") in ips for dv in p.get("devices") or []):
                    continue
                for q in p.get("parts") or []:
                    for it in q.get("items") or []:
                        it = str(it)
                        m = CVE_RX.search(it)
                        if m:
                            add(cves, m.group(0).upper())
                        elif it.startswith("Infection:"):
                            add(cats, it.split(":", 1)[1].strip())
                        elif it.lower().startswith("tag:"):
                            add(issues, issue_tags.issue_of(it)) if issue_tags.issue_of(it) else add(labels, it.split(":", 1)[1].strip().lower())
                    if q.get("report") == SINK:
                        for sk, se in imp.sinkhole_reports():
                            reps.setdefault(sk, (se, "the devices were seen calling a sinkhole in one of these reports"))
                        continue
                    rk, re_ = imp.entry(q.get("report") or q.get("title"))
                    if re_:
                        reps.setdefault(rk, (re_, None))
        reports, by_flag = [], collections.OrderedDict()
        for key, (e, note) in reps.items():
            fl = [f for f in imp.flags_of(key, e) if imp.flag(f)]
            title = e.get("title") or ctx["title_of"](key)
            reports.append({"key": key, "title": title, "section": e.get("section") or "", "group": e.get("group") or "",
                            "url": e.get("url") or "", "flags": fl, "note": note or ""})
            for f in fl:
                by_flag.setdefault(f, []).append(title)
        impact = [dict(imp.flag(f), flag=f, reports=rs) for f, rs in by_flag.items()]
        impact.sort(key=lambda z: LEVELS.index(z["level"]) if z.get("level") in LEVELS else 9)
        cves = sorted(set(cves))
        if "End of life" in issues and any(i.startswith("End of life (") for i in issues):
            issues.remove("End of life")
        kinds = [w for w, v in (("CVEs", cves), ("issues", issues), ("categories", cats)) if v]
        line = ("See Technical Details for the definitions of the highlighted "
                + (kinds[0] if len(kinds) == 1 else ", ".join(kinds[:-1]) + " and " + kinds[-1]) + ".") if kinds else ""
        return {"cves": cves, "issues": issues, "categories": cats, "labels": labels, "reports": reports, "impact": impact, "kinds_line": line,
                "devices": devs, "entry_name": entry.get("name") or "", "across": rv.get("decision") == "both" or entry.get("kind") == "x"}

    def org():
        return ctx["org"].get()["name"] or "Looking Glass"

    def data_title(x, auto):
        name = auto["entry_name"] or x["title"]
        if name and not CVE_RX.fullmatch(name):
            name = ctx["title_of"](name) or name
        return f"{name} across reports" if auto["across"] else name

    def file_base(x, auto, network):
        return "_".join([slug(org(), 40), slug(network or "All-networks", 50), slug(data_title(x, auto), 60), time.strftime("%Y%m%d", time.gmtime())])

    def blank(x, user, network):
        return {"finding": x["id"], "network": network, "ref": None, "subject": x["title"], "description": "", "actions": "",
                "recipients": [network] if network else [], "tlp": tlp.DEFAULT, "status": "draft", "created": _now(), "updated": _now(), "by": user,
                "sends": [], "reports": [], "source": (x.get("review") or {}).get("source") or ((x.get("codes") or [None])[0]),
                "decision": (x.get("review") or {}).get("decision") or "", "history": [{"at": _now(), "user": user, "what": "created"}]}

    def view(adv, x, auto=None, with_devices=False):
        """The advisory as the page and the export show it (addresses only with with_devices: never in the export)."""
        auto = auto or auto_of(x, adv.get("network", ALL))
        o = org()
        lv = tlp.of(adv.get("tlp")) or tlp.of(tlp.DEFAULT)
        out = {"ref": adv.get("ref"), "rev": int(adv.get("rev") or 0), "organisation": o, "title": adv.get("heading") or f"{o} Security Advisory",
               "heading": adv.get("heading") or "", "heading_default": f"{o} Security Advisory", "subject": adv["subject"],
               "tlp": lv["key"], "tlp_short": lv["short"], "tlp_text": lv["text"],
               "network": adv.get("network", ALL), "status": adv["status"], "status_label": STATUS_LABEL.get(adv["status"], adv["status"]),
               "created": _day(adv["created"]), "updated": _day(adv["updated"]), "by": name_of(adv["by"]),
               "finding": f"#{x['id']}", "finding_title": x["title"], "source_code": adv.get("source") or "",
               "decision": {"both": "The researcher's view and the analyst's across-report views",
                            "researcher": "The researcher's view"}.get(adv.get("decision"), ""),
               "data_title": data_title(x, auto),
               "affected": {"cves": auto["cves"], "issues": auto["issues"], "categories": auto["categories"], "labels": auto["labels"],
                            "devices": len(auto["devices"]), "records": sum(d["records"] for d in auto["devices"])},
               "reports": auto["reports"], "impact": auto["impact"], "kinds_line": auto["kinds_line"],
               "description": adv["description"], "recommended_actions": adv["actions"], "recipients": adv["recipients"],
               "sends": [{"to": s["to"], "at": _day(s["at"]), "by": name_of(s["by"]), "report": (s.get("report") or {}).get("name", "")}
                         for s in adv.get("sends") or []],
               "locked": adv.get("status") == "sent",    # sent: read-only, the record of what went out
               "generated": [{"n": r["n"], "name": r["name"], "at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(r["at"])), "by": name_of(r["by"]),
                              "size": r.get("size", 0)} for r in adv.get("reports") or []],
               "history": [{"at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(h["at"])), "by": name_of(h["user"]), "what": h["what"]}
                           for h in adv.get("history") or []]}
        if with_devices:
            out["devices"] = auto["devices"][:MAX_DEVICES_SHOWN]
        return out

    def pdf_input(v, auto, has_report):
        o = ctx["org"].get()
        ref = v["ref"] or "ADV (draft, not saved yet)"
        return {"ref": ref, "org": v["organisation"], "logo": o["logo"], "title": v["title"], "subject": v["subject"],
                "network": v["network"], "date": v["updated"], "status_label": v["status_label"], "by": v["organisation"],    # signed by the CSIRT
                "finding": v["finding"], "cves": v["affected"]["cves"], "issues": v["affected"]["issues"],
                "categories": v["affected"]["categories"], "labels": v["affected"]["labels"], "devices": auto["devices"], "reports": v["reports"], "impact": v["impact"],
                "kinds_line": v["kinds_line"], "description": v["description"], "actions": v["recommended_actions"],
                "recipients": v["recipients"], "has_report": has_report,
                "tlp": v["tlp"], "tlp_short": v["tlp_short"], "tlp_text": v["tlp_text"], "tlp_colour": (tlp.of(v["tlp"]) or {}).get("colour", "#FFC000"),
                "header": f"{v['tlp']} · {ref} · {v['network'] or 'all networks'}"[:80]}

    def clean_recipients(raw):
        if isinstance(raw, str):
            raw = re.split(r"[,;\n]", raw)
        out = []
        for r in raw or []:
            r = re.sub(r"\s+", " ", str(r)).strip()
            if r and r not in out:
                if len(r) > MAX_RECIPIENT or re.search(r"[<>\x00-\x1f]", r):
                    return None, f"A recipient: at most {MAX_RECIPIENT} characters, without < or >."
                out.append(r)
        if len(out) > MAX_RECIPIENTS:
            return None, f"At most {MAX_RECIPIENTS} recipients."
        return out, ""

    def guard_write():
        if not hp("advisory"):
            return "Only advisors write advisories."
        if ctx["is_demo"]():
            return "Demo mode is on: switch it off first."
        if not ctx["csrf_ok"]():
            return "Refused (the request did not come from this page)."
        if not ctx["fresh"]():
            return "Sign in again to make changes (your session is older than 12 hours)."
        return ""

    def open_finding(fid):
        """(finding, None) when this advisor may write its advisories; else (None, (response, status))."""
        x = finding(fid)
        if not x:
            return None, (jsonify(error="No such finding."), 404)
        if not ready(x):
            return None, (jsonify(error="Management has not approved this finding for an advisory."), 409)
        return x, None

    def all_sent(x):
        """True once every organisation of the finding has its advisory sent (external review, 2026-11-12: it used to
        close when the advisories that existed were sent, so the first one sent closed it while organisations nobody
        had started yet still waited). Without a kept search: the one advisory for all networks."""
        done = {a.get("network", ALL) for a in store.of_finding(x["id"]) if a["status"] == "sent"}
        nets = networks_of(x)
        return all(p["network"] in done for p in nets) if nets else ALL in done

    def network_arg(x, raw):
        """The organisation asked for, if it is one of the finding's (or ALL without a kept search); else None."""
        nets = networks_of(x)
        if not nets:
            return ALL
        n = str(raw or "").strip()
        return n if n in {p["network"] for p in nets} else None

    # ---------------- pages
    @app.route("/advisory")
    def advisory_portal():
        if not allowed():
            return render_template("denied.html", message="The advisory portal is for advisors (and admins)."), 403
        return render_template("advisory_portal.html")

    @app.route("/advisory/<fid>")
    def advisory_page(fid):
        if not allowed():
            return render_template("denied.html", message="Advisories are written by the advisor management chose."), 403
        return render_template("advisory.html", fid=str(fid)[:12])

    # ---------------- API
    @app.route("/api/advisory/dashboard")
    def api_advisory_dashboard():
        """The advisor's figures: their advisories (an admin's: everyone's), the findings waiting for them, to which
        organisations advisories went and when, and the impacts most seen. Counts and names only."""
        if not allowed():
            return jsonify(error="The advisory portal is for advisors (and admins)."), 403
        user, admin = me()[0], hp("settings")
        with F.lock:
            F._load()
            items = [x for x in F.data["items"].values() if F.sees(x, user, admin)]
        seen = {x["id"] for x in items}
        mine = [a for a in store.all() if admin or a.get("finding") in seen]
        by_f = collections.defaultdict(list)
        for a in mine:
            by_f[a["finding"]].append(a)
        waiting = [x for x in items if x["status"] == "advisor" and x.get("kind") != "case" and (admin or x.get("assignee") == user)]
        open_ = [x for x in items if x["status"] in ("new", "management", "approved", "researcher", "analyst", "advisor")]
        sent = [a for a in mine if a["status"] == "sent"]
        to_count, to_last, per_month = collections.Counter(), {}, collections.Counter()
        for a in mine:
            for s in a.get("sends") or []:
                per_month[time.strftime("%Y-%m", time.gmtime(s["at"]))] += 1
                for r in s["to"]:
                    to_count[r] += 1
                    to_last[r] = max(to_last.get(r, 0), s["at"])
        flags, reports, lead = collections.Counter(), collections.Counter(), []
        for a in sent:
            x = F.get(a["finding"])
            if not x:
                continue
            au = auto_of(x, a.get("network", ALL))
            for fl in au["impact"]:
                flags[(fl["label"], fl["level"])] += 1
            for r in au["reports"]:
                reports[r["title"]] += 1
            dec = (x.get("review") or {}).get("at") or next((h["at"] for h in x["history"] if h.get("status") == "advisor"), None)
            first = min((s["at"] for s in a.get("sends") or []), default=None)
            if dec and first and first >= dec:
                lead.append((first - dec) / 86400)
        row = lambda a: {"ref": a["ref"], "finding": f"#{a['finding']}", "fid": a["finding"], "network": a.get("network", ALL) or "All networks",
                         "subject": a["subject"], "tlp": a.get("tlp") or tlp.DEFAULT, "status": a["status"], "status_label": STATUS_LABEL.get(a["status"], a["status"]),
                         "updated": _day(a["updated"]), "by": name_of(a["by"]), "recipients": a.get("recipients") or [],
                         "reports": len(a.get("reports") or []), "sent": _day(max((s["at"] for s in a.get("sends") or []), default=0))}

        def fin(x):
            nets = networks_of(x) if x["status"] == "advisor" else []
            done = {a.get("network", ALL) for a in by_f.get(x["id"], []) if a["status"] == "sent"}
            return {"fid": x["id"], "number": f"#{x['id']}", "title": x["title"], "status_label": F.shown(x)["status_label"],
                    "since": _day(x["history"][-1]["at"]), "assignee": name_of(x["assignee"]) if x.get("assignee") else "",
                    "networks": len(nets), "sent_networks": len(done & {p["network"] for p in nets}) if nets else len(done),
                    "drafts": sum(1 for a in by_f.get(x["id"], []) if a["status"] == "draft"),
                    "drafted": sum(1 for a in by_f.get(x["id"], []) if a["status"] == "drafted"),
                    "case": x.get("parent") or "", "network": x.get("network") or ""}
        months = sorted(per_month)[-12:]
        return jsonify(
            kpis={"waiting": len(waiting), "drafts": sum(1 for a in mine if a["status"] == "draft"),
                  "drafted": sum(1 for a in mine if a["status"] == "drafted"), "sent": len(sent),
                  # closed by an advisory sent: the findings (sub-findings included) and the cases that closed with them
                  "closed_findings": sum(1 for x in items if x["status"] == "closed" and x.get("kind") != "case"
                                         and any(h.get("kind") == "advisory_sent" for h in x["history"])),
                  "closed_cases": sum(1 for x in items if x.get("kind") == "case" and x["status"] == "closed"),
                  "open_cases": sum(1 for x in items if x.get("kind") == "case" and x["status"] != "closed"),
                  "recipients": len(to_count), "sends": sum(len(a.get("sends") or []) for a in mine), "open_findings": len(open_),
                  "reports": sum(1 for a in mine if a.get("reports")),          # advisories with their report ready
                  "generations": sum(int(a.get("generated") or len(a.get("reports") or [])) for a in mine),
                  "days_to_send": round(sum(lead) / len(lead), 1) if lead else None},
            waiting=[fin(x) for x in sorted(waiting, key=lambda x: x["history"][-1]["at"])],
            advisories=[row(a) for a in sorted(mine, key=lambda a: -a["updated"])],
            recipients=[{"name": r, "advisories": n, "last": _day(to_last[r])} for r, n in to_count.most_common(20)],
            per_month=[{"month": m, "sent": per_month[m]} for m in months],
            impacts=[{"label": l, "level": lv, "advisories": n} for (l, lv), n in flags.most_common(10)],
            reports=[{"title": t, "advisories": n} for t, n in reports.most_common(10)],
            open_findings=[fin(x) for x in sorted(open_, key=lambda x: -x["history"][-1]["at"])][:30],
            admin=bool(admin), can_write=bool(hp("advisory")))

    @app.route("/api/advisory/<fid>")
    def api_advisory(fid):
        """The finding and its organisations (networks), each with its advisory's state: the advisor picks one first."""
        if not allowed():
            return jsonify(error="Advisories are written by the advisor management chose."), 403
        x0 = finding(fid)
        if x0 and x0.get("kind") == "case":           # a case: its advisories are on its sub-findings
            return jsonify(error="This is a case: open the advisory of each of its organisations (sub-findings).",
                           case=True, subs=[{"fid": k, "network": (F.get(k) or {}).get("network", "")} for k in x0.get("children") or []]), 409
        x, bad = open_finding(fid)
        if bad:
            return bad
        o = ctx["org"].get()
        advs = {a.get("network", ALL): a for a in store.of_finding(x["id"])}
        nets = networks_of(x) or [{"network": ALL, "devices": 0, "records": 0, "asns": []}]
        for p in nets:
            a = advs.get(p["network"])
            p.update(ref=(a or {}).get("ref"), status=(a or {}).get("status") or "", reports=len((a or {}).get("reports") or []),
                     sent=_day(max((s["at"] for s in (a or {}).get("sends") or []), default=0)))
        return jsonify(finding=F.shown(x, ctx.get("describe")), networks=nets, kept=kept(x), tlp_levels=tlp.LEVELS, tlp_url=tlp.URL,
                       has_logo=bool(o["logo"]), org_set=bool(o["name"]), organisation=org(), can_edit=bool(hp("advisory")),
                       limits={"text": MAX_TEXT, "subject": MAX_SUBJECT, "recipients": MAX_RECIPIENTS})

    @app.route("/api/advisory/<fid>/net")
    def api_advisory_net(fid):
        """One organisation's advisory with its data: its IP addresses (ports, reports, CVEs, issues), the impact."""
        if not allowed():
            return jsonify(error="Advisories are written by the advisor management chose."), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        network = network_arg(x, request.args.get("network"))
        if network is None:
            return jsonify(error="That network is not in this finding."), 404
        adv = store.of(x["id"], network) or blank(x, me()[0], network)
        auto = auto_of(x, network)
        return jsonify(advisory=view(adv, x, auto, with_devices=True), saved=bool(adv.get("ref")), has_report=kept(x),
                       file_base=file_base(x, auto, network), devices_total=len(auto["devices"]))

    @app.route("/api/advisory/<fid>/net", methods=["POST"])
    def api_advisory_save(fid):
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        network = network_arg(x, b.get("network"))
        if network is None:
            return jsonify(error="Choose the organisation (network) the advisory goes to."), 400
        subject = re.sub(r"\s+", " ", str(b.get("subject") or "")).strip()[:MAX_SUBJECT]
        if not subject:
            return jsonify(error="Give the advisory a subject."), 400
        rec, rerr = clean_recipients(b.get("recipients") or [])
        if rec is None:
            return jsonify(error=rerr), 400
        user = me()[0]
        adv = store.of(x["id"], network)
        if adv and adv["status"] == "sent":               # what went to the organisation stays as it was sent
            return jsonify(error=SENT_LOCKED.format(day=sent_day(adv))), 409
        # the revision the page opened (external review, 2026-11-12): a form left open while someone else saved is
        # refused, not written over theirs. A page without it (an older page, a script) is checked as before.
        if adv and b.get("rev") is not None:
            try:
                opened = int(b.get("rev"))
            except (TypeError, ValueError):
                return jsonify(error=CHANGED), 409
            if opened != int(adv.get("rev") or 0):
                return jsonify(error=CHANGED), 409
        create = adv is None
        adv = adv or blank(x, user, network)
        level = tlp.of(b.get("tlp") or adv.get("tlp") or tlp.DEFAULT)
        if not level:
            return jsonify(error="Choose a TLP level: TLP:RED, TLP:AMBER+STRICT, TLP:AMBER, TLP:GREEN or TLP:CLEAR."), 400
        heading = re.sub(r"\s+", " ", str(b.get("heading") or "")).strip()[:MAX_SUBJECT]
        adv.update(heading=heading, tlp=level["key"], subject=subject, description=str(b.get("description") or "").replace("\r", "").strip()[:MAX_TEXT],
                   actions=str(b.get("actions") or "").replace("\r", "").strip()[:MAX_TEXT], recipients=rec, updated=_now())
        if not create:
            if adv["status"] == "drafted":            # changed after it was marked as drafted: a draft again until marked again
                adv["status"] = "draft"
                adv["history"].append({"at": _now(), "user": user, "what": "edited after it was drafted: back to draft"})
            else:
                adv["history"].append({"at": _now(), "user": user, "what": "edited"})
        try:
            adv = store.save(adv, create=create)
        except Changed:
            return jsonify(error=CHANGED), 409
        ctx["audit"].add("advisory_saved", user=user, target=adv["ref"], detail=f"finding #{x['id']} · {network or 'all networks'}")
        return jsonify(ok=True, advisory=view(adv, x, with_devices=True), saved=True)

    def build(x, adv, network, as_pdf_only=False):
        """(file name, bytes, pdf name, pdf bytes) of the organisation's report; (None, error)."""
        auto = auto_of(x, network)
        v = view(adv, x, auto)
        has_report = kept(x)
        a = pdf_input(v, auto, has_report)
        base = file_base(x, auto, network)
        if has_report:
            out, err = book.review_report_of(x["id"], me()[0], a, network=network or None, file_base=base)
            if not out:
                return None, err
            zname, zbytes, pname, pbytes = out
            # the ZIP goes to the organisation: the PDF and the CSV files only. The advisor's download is a bundle that
            # holds that ZIP, untouched, and beside it the advisory's JSON for the CSIRT's records (never sent on)
            if adv.get("ref") and not as_pdf_only:
                import io
                import zipfile
                src = zipfile.ZipFile(io.BytesIO(zbytes))
                send = {f"{base}.pdf", f"{base}_devices.csv"}            # what is mailed: the PDF and its devices
                org = io.BytesIO()
                with zipfile.ZipFile(org, "w", zipfile.ZIP_DEFLATED) as zf:
                    for n in src.namelist():
                        if n in send:
                            zf.writestr(n, src.read(n))
                # just those two: the advisory's JSON is exported on its own (Export JSON), the rest stays in Looking Glass
                return (zname, org.getvalue(), pname, pbytes), ""
            return (zname, zbytes, pname, pbytes), ""
        import advisory_pdf
        pbytes = advisory_pdf.alone(a, {"platform_label": "Advisory", "scope": ctx["scope_text"](), "header": a["header"],
                                        "selection": v["subject"], "day": v["updated"], "generated_by": me()[0]})
        return (None, None, f"{base}.pdf", pbytes), ""

    def export_of(adv, x):
        v = view(adv, x)
        return {"schema": SCHEMA, "version": VERSION, "reference": v["ref"], "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "tlp": {"level": v["tlp"], "meaning": v["tlp_text"], "standard": "TLP 2.0 (FIRST)", "url": tlp.URL},
                **{k: v[k] for k in ("organisation", "title", "subject", "network", "data_title", "status", "created", "updated", "by",
                                     "finding", "finding_title", "decision", "affected", "kinds_line", "description",
                                     "recommended_actions", "recipients", "sends", "generated", "history")},
                "impact": [{"flag": f["flag"], "label": f["label"], "level": f["level"], "text": f["text"], "reports": f["reports"]} for f in v["impact"]],
                "shadowserver_reports": [{"report": r["key"], "title": r["title"], "section": r["section"], "group": r["group"],
                                          "url": r["url"], "impact": r["flags"]} for r in v["reports"]]}

    @app.route("/advisory/<fid>/preview")
    def advisory_preview(fid):
        """The PDF as it stands, to read in the browser (not recorded)."""
        if not allowed():
            return jsonify(error="The report is generated by the advisor management chose."), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        network = network_arg(x, request.args.get("network"))
        if network is None:
            return jsonify(error="That network is not in this finding."), 404
        adv = store.of(x["id"], network) or blank(x, me()[0], network)
        out, err = build(x, adv, network, as_pdf_only=True)
        if not out:
            return jsonify(error=err), 409
        r = Response(out[3], mimetype="application/pdf", headers={"Content-Disposition": f'inline; filename="{out[2]}"', "Cache-Control": "no-store"})
        r.headers["Content-Security-Policy"] = "default-src 'none'; object-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:"
        return r

    @app.route("/api/advisory/<fid>/generate", methods=["POST"])
    def api_advisory_generate(fid):
        """Generate the organisation's report and keep it with the advisory, listed with its download."""
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        network = network_arg(x, b.get("network"))
        if network is None:
            return jsonify(error="Choose the organisation (network) the advisory goes to."), 400
        adv = store.of(x["id"], network)
        if not adv:
            return jsonify(error="Save the advisory first."), 400
        if adv["status"] == "sent":                       # the file that went out is never replaced or deleted
            return jsonify(error=SENT_LOCKED.format(day=sent_day(adv))), 409
        if not adv["description"] or not adv["actions"]:
            return jsonify(error="Write the Description and the Recommended Actions first."), 400
        out, err = build(x, adv, network)
        if not out:
            return jsonify(error=err), 409
        zname, zbytes, pname, pbytes = out
        name, data = (zname, zbytes) if zbytes else (pname, pbytes)
        # one report per advisory: generating again replaces the previous one (every generation stays in the history,
        # and in the audit log); the number goes on, so a download link of an older one never gets the new file
        old = adv.get("reports") or []
        n = store.keep_file(adv["ref"], max([r["n"] for r in old] + [0]) + 1, data)
        user = me()[0]
        adv["reports"] = [{"n": n, "name": name, "at": _now(), "by": user, "size": len(data), "pdf": not zbytes}]
        adv["generated"] = int(adv.get("generated") or len(old)) + 1
        adv["history"].append({"at": _now(), "user": user,
                               "what": f"report generated: {name}" + (" (replaces the previous one)" if old else "")})
        try:
            store.save(adv)
        except Changed:                                   # changed meanwhile (sent, perhaps): its files stay as they are
            store.drop_file(adv["ref"], n)
            return jsonify(error=CHANGED), 409
        # only once the new one is recorded: the previous file goes (a sent file never: a sent advisory is locked above)
        sent_files = {s.get("report", {}).get("n") for s in adv.get("sends") or []}
        for r in old:
            if r["n"] not in sent_files:
                store.drop_file(adv["ref"], r["n"])
        ctx["audit"].add("advisory_report", user=user, target=adv["ref"], detail=f"{network or 'all networks'} · {name}")
        return jsonify(ok=True, advisory=view(adv, x, with_devices=True), file={"n": n, "name": name})

    @app.route("/advisory/<fid>/file/<ref>/<n>")
    def advisory_file(fid, ref, n):
        """A report generated for an advisory, as it was generated."""
        if not allowed():
            return jsonify(error="The report is generated by the advisor management chose."), 403
        x = finding(fid)
        adv = next((a for a in store.of_finding(x["id"]) if a.get("ref") == ref), None) if x else None
        rec = next((r for r in (adv or {}).get("reports") or [] if str(r["n"]) == str(n)), None)
        if not rec:
            return jsonify(error="No such report."), 404
        try:
            with open(store.file_path(ref, n), "rb") as fh:
                data = fh.read()
        except (OSError, ValueError):
            return jsonify(error="The file is no longer kept here."), 404
        ctx["audit"].add("advisory_download", user=me()[0], target=ref, detail=rec["name"])
        return Response(data, mimetype="application/pdf" if rec.get("pdf") else "application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{rec["name"]}"', "Cache-Control": "no-store"})

    @app.route("/api/advisory/<fid>/send", methods=["POST"])
    def api_advisory_send(fid):
        """Mark the organisation's advisory as sent to its recipients (the mail itself goes out as the team sends
        advisories): kept in the advisory; the finding moves to "Advisory sent"."""
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        network = network_arg(x, b.get("network"))
        adv = store.of(x["id"], network) if network is not None else None
        if not adv:
            return jsonify(error="Save the advisory first."), 404
        rec, rerr = clean_recipients(b.get("recipients") if b.get("recipients") is not None else adv["recipients"])
        if rec is None:
            return jsonify(error=rerr), 400
        if not rec:
            return jsonify(error="Name at least one recipient (the organisation, a team or a person) it goes to."), 400
        if not adv["description"] or not adv["actions"]:
            return jsonify(error="Write the Description and the Recommended Actions first."), 400
        if not adv.get("reports"):
            return jsonify(error="Generate the report first: it is what goes to them."), 400
        if adv["status"] not in ("drafted", "sent"):
            return jsonify(error="Mark the advisory as drafted first (on its page): then it is marked as sent here."), 400
        user, role = me()
        adv["recipients"] = list(dict.fromkeys(adv["recipients"] + rec))
        sent_file = adv["reports"][-1]                     # exactly which file went to them
        adv.setdefault("sends", []).append({"to": rec, "at": _now(), "by": user,
                                            "report": {"n": sent_file["n"], "name": sent_file["name"], "size": sent_file.get("size")}})
        adv["status"], adv["updated"] = "sent", _now()
        adv["history"].append({"at": _now(), "user": user, "what": "sent to " + ", ".join(rec) + f" (report {sent_file['name']})"})
        try:
            store.save(adv)
        except Changed:
            return jsonify(error=CHANGED), 409
        F.advisory_sent(x["id"], f"Advisory {adv['ref']} ({network or 'all networks'}, {adv.get('tlp') or tlp.DEFAULT}) sent to {', '.join(rec)}.",
                        all_sent(x), user, role)
        ctx["audit"].add("advisory_sent", user=user, target=adv["ref"], detail=f"finding #{x['id']} · {network} · to {len(rec)} recipient(s)")
        return jsonify(ok=True, advisory=view(adv, F.get(x["id"]), with_devices=True))

    @app.route("/api/advisory/<fid>/export")
    def api_advisory_export(fid):
        """An organisation's advisory as a self-describing JSON file, for other tools: no address in it."""
        if not allowed():
            return jsonify(error="Advisories are written by the advisor management chose."), 403
        x = finding(fid)
        network = network_arg(x, request.args.get("network")) if x else None
        adv = store.of(x["id"], network) if x and network is not None else None
        if not adv:
            return jsonify(error="No advisory saved for this organisation yet."), 404
        out = export_of(adv, x)
        auto = auto_of(x, network)
        ctx["audit"].add("advisory_export", user=me()[0], target=adv["ref"], detail="JSON")
        return Response(json.dumps(out, indent=2, ensure_ascii=False), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{file_base(x, auto, network)}_advisory.json"', "Cache-Control": "no-store"})

    @app.route("/api/advisory/<fid>/drafted", methods=["POST"])
    def api_advisory_drafted(fid):
        """The advisor has finished the advisory: its text written and its report generated. It waits to go out; the
        advisor marks it as sent on the Findings page once it has."""
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x, bad = open_finding(fid)
        if bad:
            return bad
        b = request.get_json(silent=True) or {}
        network = network_arg(x, b.get("network"))
        adv = store.of(x["id"], network) if network is not None else None
        if not adv:
            return jsonify(error="Save the advisory first."), 404
        if not adv["description"] or not adv["actions"]:
            return jsonify(error="Write the Description and the Recommended Actions first."), 400
        if not adv.get("reports"):
            return jsonify(error="Generate the report first: it is what goes out."), 400
        if adv["status"] == "sent":
            return jsonify(error="It was already sent."), 409
        user = me()[0]
        adv["status"], adv["updated"] = "drafted", _now()
        adv["history"].append({"at": _now(), "user": user, "what": f"marked as drafted (report {adv['reports'][-1]['name']})"})
        try:
            store.save(adv)
        except Changed:
            return jsonify(error=CHANGED), 409
        ctx["audit"].add("advisory_drafted", user=user, target=adv["ref"], detail=f"finding #{x['id']} · {network or 'all networks'}")
        return jsonify(ok=True, advisory=view(adv, x, with_devices=True))

    def advisories_of(fid):
        """A finding's advisories for the Findings page: reference, organisation, state, recipients, TLP, the last report."""
        out = []
        for a in sorted(store.of_finding(fid), key=lambda a: a.get("ref") or ""):
            last = (a.get("reports") or [None])[-1]
            out.append({"ref": a.get("ref"), "network": a.get("network", ALL), "status": a["status"],
                        "status_label": STATUS_LABEL.get(a["status"], a["status"]), "tlp": a.get("tlp") or tlp.DEFAULT,
                        "recipients": a.get("recipients") or [], "sent": _day(max((s["at"] for s in a.get("sends") or []), default=0)),
                        "report": {"n": last["n"], "name": last["name"]} if last else None})
        return out
    F.advisories_of = advisories_of

    store.slug = slug
    return store
