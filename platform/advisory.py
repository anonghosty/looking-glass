"""Advisories: the advisor's part, after management decided.

Management sends a decided finding to an advisor (findings.py: status "With the advisor"). The advisor writes the
advisory on /advisory/<id>:

* what is filled in on its own, and only when it holds something: the CVEs, issues and categories (infections) the
  finding's combinations carry, the Shadowserver reports behind them with their impact flags (data/report_impact.json:
  per report, else its group's), and the line "See Technical Details for the definitions of the highlighted CVEs,
  issues and categories" (only the kinds present, never their values);
* what the advisor writes: the subject, the Description (on the impact), the Recommended Actions, and to whom it goes.

The report (GET /advisory/<id>/report): the advisory's pages first (organisation name and logo from Settings,
organisation.py), then the analyst's report from exactly what was sent to management (combo_review.py), unchanged,
with its definitions under Technical Details, then Shadowserver Report References (advisory_pdf.py).

Each advisory is kept as JSON in data/advisories/<reference>.json (reference ADV-<year>-<number>), and exported as a
self-describing JSON (schema "looking-glass/advisory", version 1) without any address. Sending it ("Mark as sent",
with its recipients) moves the finding to "Advisory sent". The advisor's portal (/advisory) shows their advisories and
the figures: waiting, drafts, sent, to whom, per month, the impacts most seen.

Access: the advisory permission (advisors; admins see all). Only the people in a finding's channel open its advisory.
Installed from app.py.
"""
import collections
import json
import os
import re
import threading
import time

from flask import Response, g, jsonify, render_template, request

SCHEMA, VERSION = "looking-glass/advisory", 1
MAX_TEXT, MAX_SUBJECT, MAX_RECIPIENTS, MAX_RECIPIENT = 6000, 200, 30, 120
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
SINK = "Botnet sinkholes"                 # services_intel.SINK: the part of a code where the host calls a sinkhole
LEVELS = ["critical", "high", "medium", "low"]


def _now():
    return round(time.time(), 3)


def _day(t):
    return time.strftime("%Y-%m-%d", time.gmtime(t)) if t else ""


class Store:
    """The advisories, one JSON file each."""

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

    def of_finding(self, fid):
        return next((a for a in self.all() if a.get("finding") == str(fid)), None)

    def new_ref(self):
        year = time.strftime("%Y", time.gmtime())
        nums = [int(a["ref"].rsplit("-", 1)[1]) for a in self._all() if a.get("ref", "").startswith(f"ADV-{year}-")]
        return f"ADV-{year}-{(max(nums) + 1 if nums else 1):03d}"

    def save(self, adv, create=False):
        with self.lock:
            os.makedirs(self.dir, mode=0o700, exist_ok=True)
            if create:
                existing = next((a for a in self._all() if a.get("finding") == adv["finding"]), None)
                if existing:
                    return existing
                adv["ref"] = self.new_ref()
            path = os.path.join(self.dir, f"{adv['ref']}.json")
            tmp = path + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(adv, fh, indent=1, ensure_ascii=False)
            os.replace(tmp, path)
            return adv


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
        reps = self.reports()
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
        return None, None

    def by_title(self, title):
        return next(((k, e) for k, e in self.reports().items() if e.get("title") == title), (None, None))

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
    """ctx: base_dir, findings (findings.Findings), book (combos.CodeBook, with review_report_of from combo_review),
    org (organisation.Organisation), has_perm, csrf_ok, fresh, is_demo, audit, people_name(user), title_of(report),
    describe(code), scope_text()."""
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
        """An advisory can be written once management decided and sent it to an advisor."""
        if x.get("review"):
            return x["review"].get("decision") in ("both", "researcher")      # a rejected one has no advisory
        return x["status"] in ("advisor", "advisory") or any(h.get("status") == "advisor" for h in x.get("history") or [])

    # ---------------- what fills in on its own
    def parts_of(x):
        """(report or title, items, is_title) of every combination the advisory covers, plus the names of analyst codes."""
        out, names = [], []
        rv = x.get("review") or {}
        codes = [rv["source"]] if rv.get("source") else list(x.get("codes") or [])
        for code in codes:
            e = book.resolve_any(code) if hasattr(book, "resolve_any") else None
            if not e:
                continue
            if e.get("kind") == "a":
                names += [(e.get("platform"), n) for n in e.get("names") or []]
                continue
            if e.get("section") == "infections":
                names.append(("comms", e.get("name")))
            if e.get("kind") == "r":
                out.append((e.get("report") or e.get("name"), list(e.get("items") or []), False))
            for r, items in e.get("parts") or []:
                out.append((r, list(items or []), False))
        if rv.get("decision") == "both":       # the analyst's views management added: exactly what was sent
            sent = rv.get("sent")
            if sent:
                for p in sent:
                    for q in p.get("parts") or []:
                        out.append((q.get("report") or q.get("title"), list(q.get("items") or []), not q.get("report")))
            else:
                for p in (rv.get("analyst") or {}).get("patterns") or []:
                    for q in p.get("parts") or []:
                        out.append((q.get("title"), list(q.get("items") or []), True))
        return out, names

    def auto_of(x):
        parts, names = parts_of(x)
        cves, issues, cats, reps = [], [], [], {}
        add = lambda lst, v: v and v not in lst and lst.append(v)
        for plat, n in names:
            if plat == "comms":
                add(cats, n)
            else:
                k, e = imp.entry(n)
                if e:
                    reps.setdefault(k, (e, None))
        for rep, items, is_title in parts:
            for it in items:
                it = str(it)
                m = CVE_RX.search(it)
                if m:
                    add(cves, m.group(0).upper())
                elif it.startswith("Infection:"):
                    add(cats, it.split(":", 1)[1].strip())
                elif it.lower().startswith("tag:"):
                    add(issues, it.split(":", 1)[1].strip())
            if rep == SINK:
                for k, e in imp.sinkhole_reports():
                    reps.setdefault(k, (e, "the devices were seen calling a sinkhole in one of these reports"))
                continue
            k, e = imp.by_title(rep) if is_title else imp.entry(rep)
            if e:
                reps.setdefault(k, (e, None))
        reports, by_flag = [], collections.OrderedDict()
        for k, (e, note) in reps.items():
            fl = [f for f in imp.flags_of(k, e) if imp.flag(f)]
            title = e.get("title") or ctx["title_of"](k)
            reports.append({"key": k, "title": title, "section": e.get("section") or "", "group": e.get("group") or "",
                            "url": e.get("url") or "", "flags": fl, "note": note or ""})
            for f in fl:
                by_flag.setdefault(f, []).append(title)
        impact = [dict(imp.flag(f), flag=f, reports=rs) for f, rs in by_flag.items()]
        impact.sort(key=lambda z: LEVELS.index(z["level"]) if z.get("level") in LEVELS else 9)
        kinds = [w for w, v in (("CVEs", cves), ("issues", issues), ("categories", cats)) if v]
        line = ("See Technical Details for the definitions of the highlighted "
                + (kinds[0] if len(kinds) == 1 else ", ".join(kinds[:-1]) + " and " + kinds[-1]) + ".") if kinds else ""
        return {"cves": sorted(cves), "issues": issues, "categories": cats, "reports": reports, "impact": impact, "kinds_line": line}

    def org():
        o = ctx["org"].get()
        return o["name"] or "Looking Glass"

    def blank(x, user):
        return {"finding": x["id"], "ref": None, "subject": x["title"], "description": "", "actions": "", "recipients": [],
                "status": "draft", "created": _now(), "updated": _now(), "by": user, "sends": [],
                "source": (x.get("review") or {}).get("source") or ((x.get("codes") or [None])[0]),
                "decision": (x.get("review") or {}).get("decision") or "", "history": [{"at": _now(), "user": user, "what": "created"}]}

    def view(adv, x, auto=None):
        """The advisory as the page and the export show it: names in full, no address."""
        auto = auto or auto_of(x)
        o = org()
        return {"ref": adv.get("ref"), "organisation": o, "title": f"{o} Security Advisory", "subject": adv["subject"],
                "status": adv["status"], "status_label": "Sent" if adv["status"] == "sent" else "Draft",
                "created": _day(adv["created"]), "updated": _day(adv["updated"]), "by": name_of(adv["by"]),
                "finding": f"#{x['id']}", "finding_title": x["title"], "source_code": adv.get("source") or "",
                "decision": {"both": "The researcher's view and the analyst's across-report views",
                             "researcher": "The researcher's view only"}.get(adv.get("decision"), ""),
                "affected": {"cves": auto["cves"], "issues": auto["issues"], "categories": auto["categories"]},
                "reports": auto["reports"], "impact": auto["impact"], "kinds_line": auto["kinds_line"],
                "description": adv["description"], "recommended_actions": adv["actions"], "recipients": adv["recipients"],
                "sends": [{"to": s["to"], "at": _day(s["at"]), "by": name_of(s["by"])} for s in adv.get("sends") or []],
                "history": [{"at": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(h["at"])), "by": name_of(h["user"]), "what": h["what"]}
                            for h in adv.get("history") or []]}

    def pdf_input(v, has_report):
        o = ctx["org"].get()
        return {"ref": v["ref"] or "ADV (draft, not saved yet)", "org": v["organisation"], "logo": o["logo"], "title": v["title"],
                "subject": v["subject"], "date": v["updated"], "status_label": v["status_label"], "by": v["by"],
                "finding": v["finding"], "cves": v["affected"]["cves"], "issues": v["affected"]["issues"],
                "categories": v["affected"]["categories"], "reports": v["reports"], "impact": v["impact"],
                "kinds_line": v["kinds_line"], "description": v["description"], "actions": v["recommended_actions"],
                "recipients": v["recipients"], "has_report": has_report}

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
        """The advisor's figures: their advisories (an admin's: everyone's), the findings waiting for them, to whom
        advisories went and when, and the impacts most seen. Counts and names only."""
        if not allowed():
            return jsonify(error="The advisory portal is for advisors (and admins)."), 403
        user, admin = me()[0], hp("settings")
        with F.lock:
            F._load()
            items = [x for x in F.data["items"].values() if F.sees(x, user, admin)]
        advs = {a["finding"]: a for a in store.all()}
        mine = [a for a in advs.values() if admin or a.get("by") == user or (F.get(a["finding"]) and F.sees(F.get(a["finding"]), user, False))]
        waiting = [x for x in items if x["status"] == "advisor" and (admin or x.get("assignee") == user)]
        open_ = [x for x in items if x["status"] in ("new", "management", "approved", "researcher", "analyst", "advisor")]
        sent = [a for a in mine if a["status"] == "sent"]
        to_count, to_last = collections.Counter(), {}
        per_month = collections.Counter()
        for a in mine:
            for s in a.get("sends") or []:
                per_month[time.strftime("%Y-%m", time.gmtime(s["at"]))] += 1
                for r in s["to"]:
                    to_count[r] += 1
                    to_last[r] = max(to_last.get(r, 0), s["at"])
        flags, reports = collections.Counter(), collections.Counter()
        lead = []
        for a in sent:
            x = F.get(a["finding"])
            if not x:
                continue
            au = auto_of(x)
            for fl in au["impact"]:
                flags[(fl["label"], fl["level"])] += 1
            for r in au["reports"]:
                reports[r["title"]] += 1
            dec = (x.get("review") or {}).get("at") or next((h["at"] for h in x["history"] if h.get("status") == "advisor"), None)
            first = min((s["at"] for s in a.get("sends") or []), default=None)
            if dec and first and first >= dec:
                lead.append((first - dec) / 86400)
        row = lambda a: {"ref": a["ref"], "finding": f"#{a['finding']}", "fid": a["finding"], "subject": a["subject"], "status": a["status"],
                         "status_label": "Sent" if a["status"] == "sent" else "Draft", "updated": _day(a["updated"]),
                         "by": name_of(a["by"]), "recipients": a.get("recipients") or [],
                         "sent": _day(max((s["at"] for s in a.get("sends") or []), default=0))}
        fin = lambda x: {"fid": x["id"], "number": f"#{x['id']}", "title": x["title"], "status_label": F.shown(x)["status_label"],
                         "since": _day(x["history"][-1]["at"]), "assignee": name_of(x["assignee"]) if x.get("assignee") else "",
                         "has_advisory": x["id"] in advs, "ref": (advs.get(x["id"]) or {}).get("ref")}
        months = sorted(per_month)[-12:]
        return jsonify(
            kpis={"waiting": len(waiting), "drafts": sum(1 for a in mine if a["status"] != "sent"), "sent": len(sent),
                  "recipients": len(to_count), "sends": sum(len(a.get("sends") or []) for a in mine), "open_findings": len(open_),
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
        if not allowed():
            return jsonify(error="Advisories are written by the advisor management chose."), 403
        x = finding(fid)
        if not x:
            return jsonify(error="No such finding."), 404
        if not ready(x):
            return jsonify(error="Management has not decided on this finding yet: the advisory comes after."), 409
        adv = store.of_finding(x["id"]) or blank(x, me()[0])
        o = ctx["org"].get()
        has_report = bool(x.get("review") and hasattr(book, "review_kept") and book.review_kept(x["id"]))
        return jsonify(advisory=view(adv, x), saved=bool(adv.get("ref")), finding=F.shown(x, ctx.get("describe")),
                       has_logo=bool(o["logo"]), org_set=bool(o["name"]), has_report=has_report,
                       can_edit=bool(hp("advisory")), limits={"text": MAX_TEXT, "subject": MAX_SUBJECT, "recipients": MAX_RECIPIENTS})

    @app.route("/api/advisory/<fid>", methods=["POST"])
    def api_advisory_save(fid):
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x = finding(fid)
        if not x:
            return jsonify(error="No such finding."), 404
        if not ready(x):
            return jsonify(error="Management has not decided on this finding yet: the advisory comes after."), 409
        b = request.get_json(silent=True) or {}
        subject = re.sub(r"\s+", " ", str(b.get("subject") or "")).strip()[:MAX_SUBJECT]
        if not subject:
            return jsonify(error="Give the advisory a subject."), 400
        rec, rerr = clean_recipients(b.get("recipients") or [])
        if rec is None:
            return jsonify(error=rerr), 400
        user = me()[0]
        adv = store.of_finding(x["id"])
        create = adv is None
        adv = adv or blank(x, user)
        adv.update(subject=subject, description=str(b.get("description") or "").replace("\r", "").strip()[:MAX_TEXT],
                   actions=str(b.get("actions") or "").replace("\r", "").strip()[:MAX_TEXT], recipients=rec, updated=_now())
        if not create:
            adv["history"].append({"at": _now(), "user": user, "what": "edited"})
        adv = store.save(adv, create=create)
        ctx["audit"].add("advisory_saved", user=user, target=adv["ref"], detail=f"finding #{x['id']}")
        return jsonify(ok=True, advisory=view(adv, x), saved=True)

    @app.route("/api/advisory/<fid>/send", methods=["POST"])
    def api_advisory_send(fid):
        """Mark the advisory as sent to its recipients (the mail itself goes out as the team sends advisories): kept in
        the advisory, and the finding moves to "Advisory sent"."""
        err = guard_write()
        if err:
            return jsonify(error=err), 403
        x = finding(fid)
        adv = store.of_finding(x["id"]) if x else None
        if not adv:
            return jsonify(error="Save the advisory first."), 404
        b = request.get_json(silent=True) or {}
        rec, rerr = clean_recipients(b.get("recipients") if b.get("recipients") is not None else adv["recipients"])
        if rec is None:
            return jsonify(error=rerr), 400
        if not rec:
            return jsonify(error="Name at least one recipient (organisation, team or person) it goes to."), 400
        if not adv["description"] or not adv["actions"]:
            return jsonify(error="Write the Description and the Recommended Actions first."), 400
        user, role = me()
        adv["recipients"] = list(dict.fromkeys(adv["recipients"] + rec))
        adv.setdefault("sends", []).append({"to": rec, "at": _now(), "by": user})
        adv["status"], adv["updated"] = "sent", _now()
        adv["history"].append({"at": _now(), "user": user, "what": "sent to " + ", ".join(rec)})
        store.save(adv)
        F.set_status(x["id"], "advisory", f"Advisory {adv['ref']} sent to {', '.join(rec)}."[:1000], user, role)
        ctx["audit"].add("advisory_sent", user=user, target=adv["ref"], detail=f"finding #{x['id']} to {len(rec)} recipient(s)")
        return jsonify(ok=True, advisory=view(adv, F.get(x["id"])))

    @app.route("/api/advisory/<fid>/export")
    def api_advisory_export(fid):
        """The advisory as a self-describing JSON file, for other tools: no address in it."""
        if not allowed():
            return jsonify(error="Advisories are written by the advisor management chose."), 403
        x = finding(fid)
        adv = store.of_finding(x["id"]) if x else None
        if not adv:
            return jsonify(error="No advisory saved for this finding yet."), 404
        v = view(adv, x)
        out = {"schema": SCHEMA, "version": VERSION, "reference": v["ref"], "exported": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               **{k: v[k] for k in ("organisation", "title", "subject", "status", "created", "updated", "by", "finding", "finding_title",
                                    "source_code", "decision", "affected", "kinds_line", "description", "recommended_actions",
                                    "recipients", "sends", "history")},
               "impact": [{"flag": f["flag"], "label": f["label"], "level": f["level"], "text": f["text"], "reports": f["reports"]} for f in v["impact"]],
               "shadowserver_reports": [{"report": r["key"], "title": r["title"], "section": r["section"], "group": r["group"],
                                         "url": r["url"], "impact": r["flags"]} for r in v["reports"]]}
        ctx["audit"].add("advisory_export", user=me()[0], target=v["ref"], detail="JSON")
        return Response(json.dumps(out, indent=2, ensure_ascii=False), mimetype="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{v["ref"]}.json"', "Cache-Control": "no-store"})

    @app.route("/advisory/<fid>/report")
    def advisory_report(fid):
        """The advisory's report: its pages, then the analyst's report from exactly what was sent (when the search was
        kept), then Shadowserver Report References. ?as=pdf to read it in the browser; else the ZIP (PDF + CSV)."""
        if not allowed():
            return jsonify(error="The report is generated by the advisor management chose."), 403
        x = finding(fid)
        if not x:
            return jsonify(error="No such finding."), 404
        if not ready(x):
            return jsonify(error="Management has not decided on this finding yet."), 409
        adv = store.of_finding(x["id"]) or blank(x, me()[0])
        v = view(adv, x)
        has_report = bool(x.get("review") and hasattr(book, "review_kept") and book.review_kept(x["id"]))
        a = pdf_input(v, has_report)
        name = (v["ref"] or f"advisory_finding{x['id']}_draft")
        if has_report:
            out, err = book.review_report_of(x["id"], me()[0], a)
            if not out:
                return jsonify(error=err), 409
            zname, zbytes, pname, pbytes = out
            pname = f"{name}.pdf"
            import io
            import zipfile
            src = zipfile.ZipFile(io.BytesIO(zbytes))
            z = io.BytesIO()
            with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
                for n in src.namelist():
                    zf.writestr(pname if n.endswith(".pdf") else n, pbytes if n.endswith(".pdf") else src.read(n))
                if adv.get("ref"):
                    zf.writestr(f"{name}.json", api_advisory_export(fid).get_data())
            zbytes, zname = z.getvalue(), f"{name}.zip"
        else:
            import advisory_pdf
            pbytes = advisory_pdf.alone(a, {"platform_label": "Advisory", "scope": ctx["scope_text"](), "header": f"{v['title']} · {a['ref']}",
                                            "selection": v["subject"], "day": v["updated"], "generated_by": me()[0]})
            pname, zname, zbytes = f"{name}.pdf", None, None
        ctx["audit"].add("advisory_report", user=me()[0], target=v["ref"] or f"finding #{x['id']}", detail="PDF" if request.args.get("as") == "pdf" else "ZIP")
        if request.args.get("as") == "pdf" or zbytes is None:
            r = Response(pbytes, mimetype="application/pdf",
                         headers={"Content-Disposition": f'{"inline" if request.args.get("as") == "pdf" else "attachment"}; filename="{pname}"',
                                  "Cache-Control": "no-store"})
            r.headers["Content-Security-Policy"] = "default-src 'none'; object-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:"
            return r
        return Response(zbytes, mimetype="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{zname}"', "Cache-Control": "no-store"})

    return store
