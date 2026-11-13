"""Management decides which views an analyst's report carries.

The researcher's view is a combination (an LG-C / LG-X code): exactly the devices that carry it. When an analyst opens it
on the Combinations page, Looking Glass also follows those devices into every other report they are in, the
"across-report views": each exact pattern over every report (services reports with their pattern items, sinkhole
reports with the infections), with its LG-X code. When there are such patterns:

1. the analyst cannot download the report yet: they tick the patterns that matter and send them to a manager they name
   (a finding of kind "review", findings.py), with figures management can weigh: for the researcher's view, the
   devices, records, networks, regions and days (the Executive portal's breakdowns, counts only); for the analyst's view,
   per pattern how many hosts share exactly that infrastructure and in which reports;
2. management decides: add the analyst's views, or use the researcher's view only, with a comment; it goes back to the
   analyst who asked;
3. the analyst opens the code again and downloads the report: it carries the ticked patterns (summary points and a CSV)
   only when management added them.

No address ever leaves the search: the review holds counts, network and region names, codes and pattern values that
5 or more hosts share. Hooks: combos.py calls book.before_package(job) and book.review_gate(job); findings.py keeps the
review. API: POST /api/combos/search/<id>/review {codes, title, text, to}. Installed from app.py.
"""
import collections
import io
import json
import os
import re
import zipfile

from flask import Response, g, jsonify, render_template, request


def install(app, ctx):
    """ctx: book (combos.CodeBook: own_job, package, describe), findings (findings.Findings), cross(hosts) -> the views
    across every category (services_intel.for_hosts), has_perm, csrf_ok, fresh, is_demo, audit, labels()."""
    book, F, hp = ctx["book"], ctx["findings"], ctx["has_perm"]

    def user():
        u = getattr(g, "user", None) or {}
        return u.get("user", ""), u.get("role", "")

    def hosts_of(job):
        entry, found, m = job["inputs"][0], job["inputs"][1], job["inputs"][5]
        host = (m.host if m is not None else (lambda e: (e.get("src_ip") if entry.get("section") == "infections" else e.get("ip")) or ""))
        return {host(e) for e in found if host(e)}

    def apply(job, review):
        """The report follows management's decision, with exactly what was sent (nothing looked up again): the analyst's
        views (the ticked patterns, with the devices they had) or none."""
        prev = job.get("preview") or {}
        rv = (review or {}).get("review") or {}
        sent = rv.get("sent")
        if sent is None and rv.get("decision"):           # a review made before the copy was kept: the ticked codes, as found now
            keep = set(rv.get("codes") or [])
            sent = [x for x in prev.get("cross") or [] if x["code"] in keep]
        if review and rv.get("decision") == "both":
            an = rv.get("analyst") or {}
            job["enrich"] = {"cross": sent or [], "cross_total": len(sent or []), "multi_hosts": sum(x["hosts"] for x in sent or []),
                             "sources": an.get("sources") or [], "days": an.get("days") or prev.get("days") or [],
                             "issues": [], "infections": [], "services": [], "sent": True}
        else:
            job["enrich"] = None
        job["review_ok"] = bool(review and rv.get("decision"))
        job["review"] = ({"finding": f"#{review['id']}", "decision": rv.get("decision"), "status": review["status"],
                          "sent": (sent or []) if rv.get("decision") == "both" else [],
                          "days": (rv.get("analyst") or {}).get("days") or [],
                          "advisor": ctx["people_name"](review["assignee"]) if rv.get("decision") and review.get("assignee") else ""}
                         if review else None)

    def sent_review(job):
        """The review this analyst already sent on this combination (with or without across-report patterns), else None."""
        return F.review_for(job["inputs"][0]["code"], job["user"], False)

    def per_network(job):
        """{network: {ips, records}} of a search's devices: the organisations it can be sent for."""
        entry, found = job["inputs"][0], job["inputs"][1]
        comms = entry.get("section") == "infections" or entry.get("platform") == "comms"
        out, names = {}, {}
        for e in found:
            ip = (e.get("src_ip") if comms else e.get("ip")) or ""
            asn = e.get("src_asn") if comms else e.get("asn")
            if asn not in names:
                names[asn] = (ctx["network"](asn) if asn else "") or "Unknown"
            p = out.setdefault(names[asn], {"ips": set(), "records": 0, "asns": set()})
            p["ips"].add(ip); p["records"] += 1; p["asns"].add(str(asn or ""))
        return out

    def before_package(job):
        """After the search, before the report is made: the across-report views, and whether management decided."""
        entry = job["inputs"][0]
        if entry.get("kind") != "a":                     # the organisations the analyst can send it for
            job["networks"] = sorted(({"network": n, "devices": len(p["ips"]), "records": p["records"]} for n, p in per_network(job).items()),
                                     key=lambda p: (-p["devices"], p["network"]))
        rv0 = sent_review(job) if entry.get("kind") != "a" else None
        if rv0:                                          # already sent to management: the page shows where it stands
            apply(job, rv0)
        if entry.get("kind") == "a" or not ctx.get("cross"):
            return
        hs = hosts_of(job)
        if not hs:
            return
        job["preview"] = ctx["cross"](hs, True)
        # the analyst works with addresses: each pattern's devices, with the network they are on (from the search's records)
        found, section = job["inputs"][1], entry.get("section")
        asn_of = {}
        for e in found:
            ip = e.get("src_ip") if section == "infections" else e.get("ip")
            if ip and ip not in asn_of:
                asn_of[ip] = e.get("src_asn") if section == "infections" else e.get("asn")
        for x in (job["preview"] or {}).get("cross") or []:
            x["devices"] = [{"ip": ip, "asn": str(asn_of.get(ip) or ""), "network": ctx["network"](asn_of.get(ip)) if asn_of.get(ip) else ""}
                            for ip in x.pop("ips", [])]
        job["needs_review"] = bool((job["preview"] or {}).get("cross"))
        if job["needs_review"]:
            apply(job, F.review_for(entry["code"], job["user"], False))

    def review_gate(job):
        """(allowed, why) for a download: open until the combination is sent to management; then the report is the
        advisor's, once management decided (a rejected one opens again: there is no advisory)."""
        entry = job["inputs"][0]
        revs = F.reviews_for(entry["code"], user()[0], False)
        # rejected or withdrawn (closed by hand while undecided): no advisory comes, the report is the analyst's again
        # (a review closed undecided before this rule counts as withdrawn too)
        active = [r for r in revs if r["review"].get("decision") not in ("rejected", "withdrawn")
                  and not (r.get("status") == "closed" and not r["review"].get("decision"))]
        if not job.get("needs_review") and not revs:
            return True, ""
        if not revs:
            return False, "These devices also turn up in other reports: tick the across-report patterns that matter and send them to management first."
        if not active:                                   # every one rejected: no advisory, the download is the analyst's again
            return True, ""
        waiting = [r for r in active if not r["review"].get("decision")]
        if waiting:
            return False, f"Waiting for management's decision on finding{'s' if len(waiting) > 1 else ''} {', '.join('#' + r['id'] for r in waiting)}: the report follows it."
        rv = active[-1]
        # decided: the advisor management chose writes the advisory and generates the report (advisory.py), from
        # exactly what was sent; the analyst's part is done (their page shows what was sent and the decision)
        if not job.get("review_ok") or (job.get("review") or {}).get("finding") != f"#{rv['id']}":
            apply(job, rv)
        who = ctx["people_name"](rv.get("assignee")) if rv.get("assignee") else "the advisor"
        return False, (f"Management decided on finding #{rv['id']}: {who} writes the advisory and generates the report "
                       "from exactly what you sent.")

    book.before_package = before_package
    book.review_gate = review_gate

    # ---------------- the search behind a review, kept: the report is made from exactly its records, never a new search
    paths = {"store": os.path.join(ctx["base_dir"], "data", "review_searches")}     # tests point it elsewhere
    book.review_paths = paths

    def kept_path(fid):
        if not re.fullmatch(r"\d{1,9}", str(fid)):
            raise ValueError("not a finding number")
        # and the path stays inside the kept searches' folder (CodeQL py/path-injection, 2026-11-13: the number check
        # already allows nothing else; this makes it plain)
        base = os.path.realpath(paths["store"])
        p = os.path.realpath(os.path.join(base, f"{fid}.json"))
        if not p.startswith(base + os.sep):
            raise ValueError("not a finding number")
        return p

    def keep_search(fid, j):
        """The search's records (their ids, per day), so the report can be made from exactly them later (owner-only)."""
        entry, found, per_day, days, around = j["inputs"][:5]
        by_day = collections.defaultdict(lambda: {"found": [], "around": []})
        for key, evs in (("found", found), ("around", around)):
            for e in evs:
                d = str(e.get("extracted_date") or e.get("timestamp") or "")[:10]
                if e.get("id") and d:
                    by_day[d][key].append(e["id"])
        os.makedirs(paths["store"], mode=0o700, exist_ok=True)
        tmp = kept_path(fid) + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump({"code": entry["code"], "section": entry.get("section"), "per_day": per_day, "by_day": by_day}, fh)
        os.replace(tmp, kept_path(fid))

    def records_of(fid):
        """The kept search of a review, loaded again: {entry, found, around, per_day, m, plat}; (None, error)."""
        x = F.get(fid)
        rv = (x or {}).get("review") or {}
        if not rv:
            return None, "No such review."
        try:
            with open(kept_path(fid), encoding="utf-8") as fh:
                kept = json.load(fh)
        except (OSError, ValueError):
            return None, "This review was sent before its search was kept: open the combination and generate the report there."
        entry = book.resolve_any(rv["source"])
        if not entry:
            return None, "The combination is no longer known here."
        plat = "comms" if entry.get("section") == "infections" else "services"
        found, around = [], []
        for iso, ids in kept["by_day"].items():
            day = ctx["day"](plat, iso)
            if day is None:
                # a day that cannot be loaded now (MongoDB busy or down) is an error, never a quietly smaller search: an
                # overview with no records looked like one without a kept search and widened to every organisation
                # (review 2026-11-13)
                return None, f"The records of {iso} could not be loaded from the database just now: try again in a moment."
            fi, ai = set(ids["found"]), set(ids["around"])
            for e in day.events:
                if e.get("id") in fi:
                    found.append(e)
                if e.get("id") in ai:
                    around.append(e)
        m = ctx["svc_matcher"](entry) if entry.get("section") == "services" and ctx.get("svc_matcher") else None
        return {"entry": entry, "found": found, "around": around, "per_day": [tuple(p) for p in kept["per_day"]], "m": m, "plat": plat}, ""

    def org_asns(x, k):
        """A sub-finding's organisation as AS numbers: stored when it was made; for one made before that, the AS
        numbers whose network name is still its name (then stored, so a later rename cannot change it). An empty set:
        none of its devices are in the kept records any more. None for a finding not tied to one organisation."""
        if not x.get("network"):
            return None
        if isinstance(x.get("network_asns"), list):
            return {str(a) for a in x["network_asns"]}
        comms = k["entry"].get("section") == "infections"
        asn = (lambda e: e.get("src_asn")) if comms else (lambda e: e.get("asn"))
        found = {str(asn(e) or "") for e in k["found"] if ((ctx["network"](asn(e)) if asn(e) else "") or "Unknown") == x["network"]}
        if found:
            with F.lock:
                F._load()
                if x["id"] in F.data["items"]:
                    F.data["items"][x["id"]]["network_asns"] = sorted(found)
                    F._save()
        return found

    def org_records(x, k, asns):
        comms = k["entry"].get("section") == "infections"
        asn = (lambda e: e.get("src_asn")) if comms else (lambda e: e.get("asn"))
        return [e for e in k["found"] if str(asn(e) or "") in asns]

    book.review_org_asns = org_asns             # advisory.py scopes its pages with the same rule

    def report_of(fid, me, advisory=None, network=None, file_base=None, asns=None):
        """(zip name, zip bytes, pdf name, pdf bytes) of a decided review's report, from its kept records; (None, error).
        advisory: the advisory's pages go first (advisory.py), the report below them unchanged; network: the report for
        that organisation's devices only; asns: that organisation's AS numbers; file_base: the files' name (without
        extension). A sub-finding (one organisation) is ALWAYS scoped to its own AS numbers, whoever asks: never
        everyone's devices (external review, 2026-11-12), and refused when none of its devices are left."""
        x = F.get(fid)
        if not x or not x.get("review") or not F.sees(x, me, hp("settings")):
            return None, "No such review."
        rv = x["review"]
        if not rv.get("decision"):
            return None, "Management has not decided yet."
        if rv["decision"] in ("rejected", "withdrawn"):
            return None, ("Management rejected it" if rv["decision"] == "rejected" else "It was withdrawn") + \
                ": there is no report to generate."
        k, err = records_of(fid)
        if not k:
            return None, err
        own = org_asns(x, k)
        if own is not None:                              # one organisation's finding: only its devices, by AS number
            if asns is not None and not {str(a) for a in asns} <= own:
                return None, "That organisation is not this finding's."
            asns, network = own, x["network"]
        if asns is not None and not org_records(x, k, {str(a) for a in asns}):
            return None, (f"None of {network or 'this organisation'}'s devices are in the finding's records any more: "
                          "no report is made (it would not be about them).")
        job = {"id": f"review{fid}", "user": me, "log": [], "state": "done", "advisory": advisory, "file_base": file_base}
        apply(job, x)
        res = book.package(job, k["entry"], k["found"], k["per_day"], None, k["around"], k["m"], network=network or None,
                           asns=asns)
        z = zipfile.ZipFile(io.BytesIO(res["bytes"]))
        pdf = next(n for n in z.namelist() if n.endswith(".pdf"))
        return (res["name"], res["bytes"], pdf, z.read(pdf)), ""

    book.review_report_of = report_of            # advisory.py makes the advisory's report with it
    book.review_records = records_of             # …and lists the organisations (networks) in it
    book.review_kept = lambda fid: os.path.exists(kept_path(fid))

    @app.route("/review/<fid>/report")
    def review_report(fid):
        """The report on a decided review, made from the kept records and the decision, without the advisory's pages:
        the PDF to preview in the browser (?as=pdf), or the ZIP (PDF + CSV). For the advisor (and admins)."""
        if not (hp("advisory") or hp("settings")):
            return jsonify(error="The report is generated by the advisor management chose."), 403
        me = user()[0]
        try:
            out, err = report_of(str(fid), me)
        except ValueError:
            out, err = None, "No such review."
        if not out:
            return jsonify(error=err), 404 if "No such" in err else 409
        zname, zbytes, pname, pbytes = out
        ctx["audit"].add("combo_export", user=me, target=f"review #{fid}", detail="the report of a decided review")
        if request.args.get("as") == "pdf":
            r = Response(pbytes, mimetype="application/pdf",
                         headers={"Content-Disposition": f'inline; filename="{pname}"', "Cache-Control": "no-store"})
            # the browser's own PDF viewer shows it (the page policy would block its viewer)
            r.headers["Content-Security-Policy"] = "default-src 'none'; object-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:"
            return r
        return Response(zbytes, mimetype="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{zname}"', "Cache-Control": "no-store"})

    # ---------------- the review page (/review/<id>): management's final look, with the Executive portal's components
    def plat_of(code):
        e = book.resolve_any(code) if hasattr(book, "resolve_any") else None
        if not e:
            return "comms"
        if e.get("kind") == "a":
            return e.get("platform", "comms")
        return "comms" if e.get("section") == "infections" else "services"

    @app.route("/review/<fid>")
    def review_page(fid):
        if not (hp("management") or hp("settings")):
            return render_template("denied.html", message="The review page is for management (and admins)."), 403
        return render_template("review.html", fid=str(fid)[:12])

    @app.route("/api/review/<fid>")
    def api_review(fid):
        """A review finding with what the researcher says about its combination (their notes and finding), and on which
        platform each view lies; only for the people in its channel (and admins). Counts only: no address."""
        if not (hp("management") or hp("settings")):
            return jsonify(error="The review page is for management (and admins)."), 403
        x = F.get(fid)
        if not x or not x.get("review") or not F.sees(x, user()[0], hp("settings")):
            return jsonify(error="No such review."), 404
        rv = x["review"]
        src = book.resolve_any(rv["source"]) if hasattr(book, "resolve_any") else None
        notes, rf = [], None
        if src and src.get("kind") != "a" and ctx.get("notes"):
            notes = [{k: v for k, v in n.items() if k != "user"} for n in ctx["notes"].list(src["section"], src["name"])][:12]
            # the researcher's own finding on this combination, if any (the first that carries the code and is not a review)
            with F.lock:
                F._load()
                items = sorted(F.data["items"].values(), key=lambda y: y["at"])
            r0 = next((y for y in items if rv["source"] in (y.get("codes") or []) and not y.get("review")), None)
            if r0:
                rf = {"number": f"#{r0['id']}", "title": r0["title"], "text": r0["text"], "by": ctx["people_name"](r0["user"]), "status": r0["status"]}
        plat_r = plat_of(rv["source"])
        plat_a = plat_of(rv["codes"][0]) if rv.get("codes") else plat_r
        return jsonify(finding=F.shown(x, ctx.get("describe")), researcher={"notes": notes, "finding": rf,
                       "what": book.describe(rv["source"]) if hasattr(book, "describe") else rv["source"]},
                       plat_researcher=plat_r, plat_analyst=plat_a, can_decide=bool(hp("management") or hp("settings")),
                       can_search=bool(hp("unmasked") and hp("export")))

    @app.route("/api/combos/search/<jid>/review", methods=["POST"])
    def api_combo_review(jid):
        """Send the ticked across-report patterns to a manager, with the figures of both views (counts only)."""
        if not (hp("unmasked") and hp("export")):
            return jsonify(error="The combination search is for analysts."), 403
        if ctx["is_demo"]():
            return jsonify(error="Demo mode is on: switch it off first."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        if not ctx["fresh"]():
            return jsonify(error="Sign in again to make changes (your session is older than 12 hours)."), 403
        j = book.own_job(jid)
        if not j or not j.get("inputs"):
            return jsonify(error="This search has expired (finished searches are kept for an hour): run it again."), 404
        prev = j.get("preview") or {}
        avail = {x["code"]: x for x in prev.get("cross") or []}
        if j["inputs"][0].get("kind") == "a":
            return jsonify(error="An analyst code is already on its own finding."), 400
        prior = [r for r in F.reviews_for(j["inputs"][0]["code"], j["user"], False)
                 if r["review"].get("decision") not in ("rejected", "withdrawn")]
        if prior:
            return jsonify(error=f"This combination was already sent to management: see finding #{prior[-1].get('parent') or prior[-1]['id']}."), 409
        b = request.get_json(silent=True) or {}
        codes = [c for c in dict.fromkeys(str(c).strip().upper() for c in (b.get("codes") or [])) if c in avail][:20]
        if avail and not codes:
            return jsonify(error="Tick at least one across-report pattern to send."), 400
        # no across-report data: the combination goes to management as it is (the researcher's view), for the advisory
        title = str(b.get("title") or "").strip()[:140]
        text = str(b.get("text") or "").replace("\r", "").strip()[:2000]
        if not title:
            return jsonify(error="Give the finding a short title."), 400
        to, err = F.recipient("management", b.get("to"))
        if not to:
            return jsonify(error=err), 400
        entry, s = j["inputs"][0], j.get("summary") or {}
        # the researcher's view: the Executive portal's breakdowns of the combination, counts and names only
        researcher = {"code": entry["code"], "what": book.describe(entry["code"]) if hasattr(book, "describe") else entry["code"],
                      "devices": s.get("devices", 0), "records": s.get("records", 0), "repeat": s.get("repeat", 0),
                      "multi_day": s.get("multi_day", 0), "networks": s.get("networks", 0),
                      "top_networks": [{"label": n["label"], "devices": n["devices"]} for n in (s.get("top_networks") or [])[:8]],
                      "regions": [{"label": r["label"], "devices": r["devices"]} for r in (s.get("regions") or [])[:8]],
                      "cities": [{"label": c["label"], "devices": c["devices"]} for c in (s.get("top_cities") or [])[:6]],
                      "per_day": s.get("per_day") or [], "kinds": s.get("kinds") or [], "ports": s.get("ports") or []}
        # the analyst's view: each ticked pattern, how many hosts share exactly that infrastructure, in which reports
        analyst = {"patterns": [{"code": c, "hosts": avail[c]["hosts"], "parts": [{"title": p["title"], "items": p["items"]} for p in avail[c]["parts"]]}
                                for c in codes],
                   "multi_hosts": prev.get("multi_hosts", 0), "patterns_total": prev.get("cross_total", 0),
                   "sources": prev.get("sources") or [], "days": prev.get("days") or []}
        me, role = user()
        section = entry.get("section") or "infections"
        # exactly what was sent, with the devices' addresses: for the analyst's report later (never shown to management)
        sent = [{"code": c, "hosts": avail[c]["hosts"], "parts": avail[c]["parts"], "devices": avail[c].get("devices") or []} for c in codes]
        base = {"source": entry["code"], "codes": codes, "researcher": researcher, "analyst": analyst, "requested_by": me, "sent": sent}
        # the organisations (networks) it is for: none named = the whole combination (an overview, the advisor picks the
        # organisations later); one = a finding for that organisation; several = a case with one sub-finding each
        per_net = per_network(j)
        nets = [n for n in dict.fromkeys(str(x).strip() for x in (b.get("networks") or []) if str(x).strip())][:60]
        bad = [n for n in nets if n not in per_net]
        if bad:
            return jsonify(error=f"Not a network of this search: {bad[0]}."), 400

        def for_net(net):
            """The review narrowed to one organisation: its figures, and the ticked patterns its devices are in."""
            p = per_net[net]
            sent_n = []
            for x in sent:
                dv = [d for d in x["devices"] if d.get("ip") in p["ips"]]
                if dv:
                    sent_n.append(dict(x, devices=dv, hosts=len(dv)))
            pats = [dict(pt, hosts=next(s_["hosts"] for s_ in sent_n if s_["code"] == pt["code"]))
                    for pt in analyst["patterns"] if any(s_["code"] == pt["code"] for s_ in sent_n)]
            return dict(base, network=net, codes=[s_["code"] for s_ in sent_n], sent=sent_n,
                        researcher=dict(researcher, devices=len(p["ips"]), records=p["records"], networks=1,
                                        top_networks=[{"label": net, "devices": len(p["ips"])}]),
                        analyst=dict(analyst, patterns=pats, multi_hosts=sum(s_["hosts"] for s_ in sent_n)))
        if len(nets) > 1:
            case, kids = F.create_case(entry["code"], section, researcher["what"][:200], title, text, me, role, to,
                                       [(n, for_net(n)) for n in nets])
            with F.lock:                                   # each organisation by its AS numbers, not only its name
                F._load()
                for k in kids:
                    F.data["items"][k["id"]]["network_asns"] = sorted(per_net[k["network"]]["asns"])
                F._save()
            for k in kids:
                keep_search(k["id"], j)                    # each organisation's report is made later from these records
            j["review"] = {"finding": f"#{case['id']}", "decision": None, "status": case["status"]}
            ctx["audit"].add("combo_review_sent", user=me, target=entry["code"],
                             detail=f"case #{case['id']} to {to} · {len(kids)} organisations · {len(codes)} pattern(s)")
            return jsonify(finding=f"#{case['id']}", case=True, subs=[{"finding": f"#{k['id']}", "network": k["network"]} for k in kids],
                           to=ctx["people_name"](to), codes=codes)
        review = for_net(nets[0]) if nets else base
        item = F.create_review(entry["code"], section, researcher["what"][:200], (f"{title} · {nets[0]}" if nets else title)[:140], text, me, role, to, review)
        if nets:
            with F.lock:                                   # a finding for one organisation says so, and holds its AS numbers
                F._load()
                F.data["items"][item["id"]]["network"] = nets[0]
                F.data["items"][item["id"]]["network_asns"] = sorted(per_net[nets[0]]["asns"])
                F._save()
        j["review"] = {"finding": f"#{item['id']}", "decision": None, "status": item["status"]}
        keep_search(item["id"], j)                         # the report is made later from exactly these records
        ctx["audit"].add("combo_review_sent", user=me, target=entry["code"],
                         detail=f"#{item['id']} to {to} · {len(review['codes'])} pattern(s)" + (f" · {nets[0]}" if nets else ""))
        return jsonify(finding=f"#{item['id']}", to=ctx["people_name"](to), codes=review["codes"], network=nets[0] if nets else "")
