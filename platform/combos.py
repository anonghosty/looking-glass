"""Combination codes and the analyst's combination export.

A researcher sees, in Intel gathered, which exact combinations of indicators the devices of a name carry (the C2 domain
they call, the DNS name they look up, their user agent, the tags; for services the CVEs and tags together). Each
combination has a code:

  LG-C-XXXXXXXX   one exact combination in one report (the records that carry exactly these indicators)
  LG-X-XXXXXXXX   one cross-report pattern: the devices seen in several reports with, per report, exactly these indicators

The code carries no address: researchers and management pass it on in their notes and reports. An analyst (a role that
sees real addresses and may export) pastes it on the Combinations page and gets the devices that carry exactly that
combination: a ZIP with a PDF summary, the records (CSV) and one row per device (CSV), ready for enrichment (IntelMQ)
and dashboards (Elastic). The matching rule is intel.record_items, the one Intel gathered counts with, so the numbers
agree with what the researcher saw.

The search runs over the days in memory, or over a date range of the stored history (MongoDB, at most MAX_DAYS days):
then only the reports of that combination are read, one day at a time, in a background job.

Codes a researcher was shown are kept in data/combo_codes.json (run-time data, never shipped), so they still resolve when
the days that produced them have left memory.

API: GET /api/combo-codes/<code> (what a code means, no address: researchers, management, analysts, admins),
POST /api/combo-codes/new {section, name, report, items} (a researcher builds one for a note: researchers, admins),
POST /api/combos/search {code, from?, to?} (analysts, admins), GET /api/combos/search/<id>,
GET /api/combos/search/<id>/download. Page: /combinations. Installed from app.py: combos.install(app, ctx).
"""
import collections
import io
import json
import os
import re
import secrets
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone

from flask import Response, g, jsonify, render_template, request

import csvsafe
import issue_tags
import intel as I

CODE_RX = re.compile(r"^LG-[CX]-[0-9A-F]{8}$")          # the researchers' codes (this module)
ANY_RX = re.compile(r"^LG-[CXA]-[0-9A-F]{8}$")          # and the analysts' (acodes.py)
MAX_DAYS = 31                 # one history search reads at most this many days
KEEP_CODES = 20000            # codes kept in data/combo_codes.json (the least recently shown go first)
JOB_TTL = 3600                # a finished search can be downloaded for an hour
PDF_DEVICES = 40              # devices printed in the PDF (the CSV has all of them)


class CodeBook:
    """code -> what it means: {kind: r|x, section, name, report (r), items (r), parts (x), first, last}."""

    def __init__(self, path, logger=None):
        self.path, self.log = path, logger
        self.lock = threading.Lock()
        self.data, self.loaded = {}, False

    def _load(self):
        if self.loaded:
            return
        self.loaded = True
        try:
            with open(self.path, encoding="utf-8") as f:
                d = json.load(f)
            self.data = d if isinstance(d, dict) else {}
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            if self.log:
                self.log.warning("combination codes not read: %s", exc)

    def _save(self):
        if len(self.data) > KEEP_CODES:
            for k, _ in sorted(self.data.items(), key=lambda kv: kv[1].get("last", ""))[:len(self.data) - KEEP_CODES]:
                del self.data[k]
        tmp = f"{self.path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.data, f, ensure_ascii=False)
        os.replace(tmp, self.path)

    def record(self, section, name, report, combos):
        """Intel gathered showed these combinations (report=None: cross-report patterns as [(report, items)])."""
        today = time.strftime("%Y-%m-%d", time.gmtime())
        new = False
        with self.lock:
            self._load()
            for c in combos:
                if report is None:
                    parts = [[r, sorted(i)] for r, i in c]
                    code, entry = I.cross_code(section, name, parts), {"kind": "x", "section": section, "name": name, "parts": parts}
                else:
                    code, entry = I.combo_code(section, name, report, c), {"kind": "r", "section": section, "name": name,
                                                                            "report": report, "items": sorted(c)}
                old = self.data.get(code)
                if old is None:
                    self.data[code] = dict(entry, first=today, last=today)
                    new = True
                elif old.get("last") != today:
                    old["last"] = today
                    new = True
            if new:
                try:
                    self._save()
                except OSError as exc:
                    if self.log:
                        self.log.warning("combination codes not saved: %s", exc)

    def get(self, code):
        with self.lock:
            self._load()
            e = self.data.get(code)
            return dict(e, code=code) if e else None

    def put(self, code, entry):
        """An analyst code (acodes.py): what it stands for, kept like the researchers' codes."""
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with self.lock:
            self._load()
            old = self.data.get(code) or {}
            self.data[code] = dict(entry, first=old.get("first", today), last=today)
            try:
                self._save()
            except OSError as exc:
                if self.log:
                    self.log.warning("combination codes not saved: %s", exc)


_TITLE = {"of": lambda n: n}     # a services report's readable title (install: ctx title_of)


def items_of(m, section, e):
    """What a record carries for a code's matcher: a services matcher reads its pattern items (services_intel.py)."""
    return m.items(e) if hasattr(m, "items") else I.record_items(section, e, m.me)


class _SummaryOnly(Exception):
    """package(summary_only=True): skip the PDF."""


def describe(entry):
    """One line for people: what the code stands for."""
    if not entry:
        return ""
    if entry["kind"] == "a":
        days = entry.get("days") or [entry["day"]]
        on = days[0] if len(days) == 1 else f"{days[0]} to {days[-1]}"
        return f"Analyst selection on {on} ({'network communications' if entry['platform'] == 'comms' else 'services'}): {entry.get('label', '')}"
    if entry.get("section") == "services":                # a services report: its title, never the collection name
        t = _TITLE["of"]
        if entry["kind"] == "r":
            return f"{t(entry['report'])}: {' + '.join(entry['items']) or 'no pattern item'}"
        sink = [i for r, items in entry["parts"] if r == "Botnet sinkholes" for i in items]
        if sink:
            return f"{t(entry['name'])}: hosts also calling botnet sinkholes as {', '.join(s.split(': ', 1)[-1] for s in sink)}"
        return f"{t(entry['name'])} across " + "; ".join(f"{t(r)}: {' + '.join(i) or 'the report only'}" for r, i in entry["parts"])
    if entry["kind"] == "r":
        items = " + ".join(entry["items"]) or "no indicator (the name only)"
        return f"{entry['name']} in {entry['report']}: {items}"
    return f"{entry['name']} across " + "; ".join(f"{r}: {' + '.join(i) or 'the name only'}" for r, i in entry["parts"])


class Matcher:
    """The records of one code in a list of events (one day, or all days in memory together)."""

    def __init__(self, entry, labels):
        self.e, self.labels = entry, labels
        self.section, self.name = entry["section"], entry["name"]
        self.me, self.lname = I._norm(self.name), self.name.lower()
        self.reports = {entry["report"]} if entry["kind"] == "r" else {r for r, _ in entry["parts"]}

    def host(self, e):
        return (e.get("src_ip") if self.section == "infections" else e.get("ip")) or ""

    def report(self, e):
        if self.section == "infections":
            return self.labels.get(e.get("source"), e.get("source") or "")
        return e.get("report_label") or e.get("report") or ""

    def of_name(self, e):
        if self.section == "infections":
            return (e.get("infection") or "").lower() == self.lname
        return self.name in (e.get("issues") or [])

    def match(self, events):
        mine = [e for e in events if self.of_name(e) and self.host(e) and self.report(e) in self.reports]
        if self.e["kind"] == "r":
            want = tuple(self.e["items"])
            return [e for e in mine if I.record_items(self.section, e, self.me) == want]
        # cross-report: per device, per report, everything it carried; the device's pattern must be exactly this one
        want = tuple(sorted((r, tuple(sorted(i))) for r, i in self.e["parts"]))
        per = collections.defaultdict(lambda: collections.defaultdict(set))
        everything = [e for e in events if self.of_name(e) and self.host(e)]
        for e in everything:
            per[self.host(e)][self.report(e)].update(I.record_items(self.section, e, self.me))
        hit = {h for h, reps in per.items() if tuple(sorted((r, tuple(sorted(i))) for r, i in reps.items())) == want}
        return [e for e in everything if self.host(e) in hit]


class AMatcher(Matcher):
    """An analyst code's records come from its selection (acodes.py): every name and report in them belongs to it."""

    def __init__(self, entry, labels):
        self.e, self.labels = entry, labels
        self.section, self.name = entry["section"], entry["name"]
        self.me, self.lname, self.reports = "", "", set()

    def of_name(self, e):
        return True


# the CSV columns: stable snake_case names (IntelMQ and Logstash map them one to one; see docs/TECHNICAL_REFERENCE.md)
COMMS_COLS = [("time", "timestamp"), ("source_ip", "src_ip"), ("source_port", "src_port"), ("source_asn", "src_asn"),
              ("source_network", "_network"), ("source_country", "src_geo"), ("source_region", "src_region"),
              ("source_city", "src_city"), ("report", "_report"), ("infection", "infection"), ("family", "family"),
              ("tag", "tag"), ("c2_domain", "http_host"), ("destination_ip", "dst_ip"), ("destination_port", "dst_port"),
              ("destination_hostname", "dst_hostname"), ("tls_server_name", "ssl_servername"), ("dns_query", "x:query"),
              ("user_agent", "http_agent"), ("url", "http_url"), ("protocol", "protocol"), ("combination_code", "_code")]
SVC_COLS = [("time", "extracted_date"), ("ip", "ip"), ("port", "port"), ("protocol", "protocol"), ("asn", "asn"),
            ("network", "_network"), ("country", "geo"), ("region", "region"), ("city", "city"), ("hostname", "hostname"),
            ("report", "_report"), ("issue", "_issue"), ("issues", "issues"), ("tags", "tags"), ("vendor", "vendor"),
            ("product", "product"), ("version", "version"), ("severity", "severity"), ("combination_code", "_code")]


def _share(n, total):
    """A share people read correctly: "<0.1%" rather than "0%" when there is at least one."""
    s = (n or 0) / max(1, total or 0)
    return "0%" if not n else "<0.1%" if s < .001 else f"{100 * s:.1f}%" if s < .1 else f"{round(100 * s)}%"


def enrich_points(enr):
    """The analysis across every category, in the report's words (summary points of the PDF)."""
    out = []
    for s in enr.get("sources") or []:
        n = len(s["reports"])
        out.append(f"Seen in {n} {s['kind'].lower().replace(' reports', '')} report{'s' if n != 1 else ''}: "
                   + ", ".join(f"{r['title']} ({r['hosts']:,})" for r in s["reports"][:10]) + (f" and {n - 10} more" if n > 10 else "") + ".")
    xs = enr.get("cross") or []
    if xs:
        out.append(f"Across reports: {enr.get('multi_hosts', 0):,} of these devices are in two or more reports, in {enr.get('cross_total', len(xs)):,} exact patterns; "
                   + "; ".join(f"{x['code']} ({x['hosts']:,}): " + " + ".join(p["title"] for p in x["parts"]) for x in xs[:4]) + ".")
    iss = enr.get("issues") or []
    if iss:
        out.append("CVEs and issues found on them: " + ", ".join(f"{i['name']} ({i['hosts']:,})" for i in iss[:10])
                   + (f", and {enr.get('issues_total', len(iss)) - 10} more" if enr.get("issues_total", len(iss)) > 10 else "") + ".")
    inf = enr.get("infections") or []
    if inf:
        out.append(f"{enr.get('infections_hosts', 0):,} of them also call botnet sinkholes as " + ", ".join(f"{i['name']} ({i['hosts']:,})" for i in inf[:8]) + ".")
    if not out:
        out.append("Across every category: these devices show nothing more in the other categories in the days in memory.")
    return out


def enrich_rows(enr):
    """The analysis across every category as CSV rows: category, report, value, hosts, records, code."""
    rows = []
    for s in enr.get("services") or []:
        rows.append(["services", s["title"], "", s["hosts"], s.get("records", ""), ""])
    for x in enr.get("cross") or []:                   # the exact patterns across reports (LG-X)
        rows.append(["across reports", " | ".join(p["title"] for p in x["parts"]),
                     " | ".join(f"{p['title']}: {' + '.join(p['items']) or 'the report only'}" for p in x["parts"]), x["hosts"], "", x["code"]])
        for dv in x.get("devices") or []:             # each device of it, as it was sent to management
            rows.append(["across reports device", " | ".join(p["title"] for p in x["parts"]),
                         f"{dv['ip']}" + (f" ({dv['network']})" if dv.get("network") else ""), 1, "", x["code"]])
    for i in enr.get("issues") or []:
        rows.append(["cve / issue", "; ".join(f"{r['title']} ({r['hosts']})" for r in i.get("reports") or []), i["name"], i["hosts"], "", ""])
        for dv in i.get("devices") or []:             # ticked by the analyst: each device of it, as sent to management
            rows.append(["cve / issue device", i["name"], f"{dv['ip']}" + (f" ({dv['network']})" if dv.get("network") else ""), 1, "", ""])
    for i in enr.get("infections") or []:
        rows.append(["infection (calling sinkholes)", "", i["name"], i["hosts"], "", ""])
        for r in i.get("reports") or []:
            rows.append(["infection in a services report", r["title"], i["name"], r["hosts"], "", r.get("code", "")])
        for dv in i.get("devices") or []:
            rows.append(["infection device", i["name"], f"{dv['ip']}" + (f" ({dv['network']})" if dv.get("network") else ""), 1, "", ""])
    return rows


def _cell(e, key):
    v = (e.get("extras") or {}).get(key[2:]) if key.startswith("x:") else e.get(key)
    if isinstance(v, (list, tuple, set)):
        return ", ".join(str(x) for x in v)
    return "" if v is None else str(v)


def install(app, ctx):
    """ctx: intel (intel.Intel), store, svc_store, labels() -> {collection: report name}, fetch(section, collections, day)
    -> scoped events of those reports that day from MongoDB, network(asn) -> name, has_perm(p), csrf_ok(), is_demo(),
    audit, notes (notes.Notes), explain(section, name) -> card or None, build_pdf(spec), scope_text(), base_dir, logger."""
    book = CodeBook(os.path.join(ctx["base_dir"], "data", "combo_codes.json"), ctx.get("logger"))
    if ctx.get("title_of"):
        _TITLE["of"] = ctx["title_of"]
    ctx["intel"].on_codes = book.record
    jobs, jobs_lock = {}, threading.Lock()

    def user():
        return (getattr(g, "user", None) or {}).get("user", "")

    def can_export():
        return ctx["has_perm"]("unmasked") and ctx["has_perm"]("export")

    def can_read():
        return can_export() or ctx["has_perm"]("definitions") or ctx["has_perm"]("management")

    def resolve(code):
        """The code book first; a code never written there (shown before this feature) is looked for in memory."""
        entry = book.get(code)
        if entry:
            return entry
        data = ctx["intel"].index()
        if code.startswith("LG-C-"):
            for (section, name), reps in data["by"].items():
                for rep, slot in reps.items():
                    for items in slot["combos"]:
                        if I.combo_code(section, name, rep, items) == code:
                            book.record(section, name, rep, [items])
                            return book.get(code)
        else:
            for (section, name), pats in (data.get("xcombos") or {}).items():
                for pattern in pats:
                    if I.cross_code(section, name, pattern) == code:
                        book.record(section, name, None, [pattern])
                        return book.get(code)
        return None

    def collections_of(entry):
        labels = ctx["labels"]()
        wanted = {entry["report"]} if entry["kind"] == "r" else {r for r, _ in entry["parts"]}
        return {c for c, lbl in labels.items() if lbl in wanted}

    def public_entry(entry):
        e = {k: v for k, v in entry.items() if k in ("code", "kind", "section", "name", "report", "items", "parts", "first", "last")}
        e["text"] = describe(entry)
        return e

    @app.route("/api/combo-codes/<code>")
    def api_combo_code(code):
        if not can_read():
            return jsonify(error="Your role cannot look up combination codes."), 403
        code = (code or "").strip().upper()
        if not ANY_RX.match(code):
            return jsonify(error="A combination code looks like LG-C-1A2B3C4D or LG-X-1A2B3C4D (an analyst's: LG-A-…)."), 400
        entry = book.resolve_any(code)
        if entry and entry.get("kind") == "a" and hasattr(book, "acode_allowed") and not book.acode_allowed(code):
            entry = None                          # another channel's analyst code: as unknown as any other
        if not entry:
            return jsonify(error=f"{code} is not known here: it was never shown in Intel gathered on this platform."), 404
        if entry.get("kind") == "a":              # an analyst's selection: what it stands for, without an address
            return jsonify({"code": code, "kind": "a", "section": "issues" if entry["platform"] == "services" else "infections",
                            "platform": entry["platform"], "day": entry["day"], "text": describe(entry), "label": entry.get("label", ""),
                            "records": entry.get("records"), "hosts": entry.get("hosts"), "names": entry.get("names", []), "notes": []})
        out = public_entry(entry)
        out["notes"] = [{k: v for k, v in n.items() if k != "user"} for n in ctx["notes"].list(entry["section"], entry["name"])]
        mem = sorted(d.date().isoformat() for d in (ctx["store"] if entry["section"] == "infections" else ctx["svc_store"]).days)
        out["memory_days"] = mem
        return jsonify(out)

    @app.route("/api/combo-codes/new", methods=["POST"])
    def api_combo_code_new():
        """A researcher builds a combination for a note: one report of the name and the exact indicators, ticked from what
        Intel gathered saw there. Returns its code and how many records / devices carry exactly that in memory."""
        if not ctx["can_note"]():
            return jsonify(error="Only researchers and admins can make combination codes."), 403
        b = request.get_json(silent=True) or {}
        section = "issues" if b.get("section") == "issues" else "services" if b.get("section") == "services" else "infections"
        name = str(b.get("name") or "").strip()[:120]
        report = str(b.get("report") or "").strip()[:120]
        items = sorted({str(x).strip()[:300] for x in (b.get("items") or []) if str(x).strip()})[:20]
        if not name or not report:
            return jsonify(error="Pick a report first."), 400
        if section == "services":                            # the pattern items of a services report (services_intel.py)
            if not ctx.get("svc_new_code"):
                return jsonify(error="Services codes are not available here."), 404
            facts, err = ctx["svc_new_code"](report, items)
            if err:
                return jsonify(error=err), 400
            book.record("services", facts["report"], facts["report"], [tuple(facts["items"])])
            code = I.combo_code("services", facts["report"], facts["report"], facts["items"])
            ctx["audit"].add("combo_code", user=user(), target=code, detail=describe(book.get(code)))
            return jsonify(public_entry(book.get(code)) | {k: facts[k] for k in ("records", "devices", "repeat_devices", "days")})
        data = ctx["intel"].index()
        key = (section, name if section == "issues" else name.lower())
        slot = (data["by"].get(key) or {}).get(report)
        if slot is None:
            return jsonify(error=f"{name} is not in {report} in the days in memory."), 404
        kinds = I.COMMS_COMBO_KINDS if section == "infections" else I.COMBO_KINDS
        me = I._norm(name)
        allowed = {v for k, c in slot["kinds"].items() if k in kinds for v in c if I._norm(v) != me}
        bad = [x for x in items if x not in allowed]
        if bad:
            return jsonify(error=f"Not an indicator of {name} in {report}: {', '.join(bad[:3])}"), 400
        book.record(section, key[1], report, [tuple(items)])
        code = I.combo_code(section, key[1], report, items)
        records = slot["combos"].get(tuple(items), 0)
        h = I.hosts(slot["ch"].get(tuple(items)))
        ctx["audit"].add("combo_code", user=user(), target=code, detail=f"{name} in {report}: {' + '.join(items) or 'the name only'}")
        return jsonify(public_entry(book.get(code)) | {"records": records, "devices": h["hosts"], "repeat_devices": h["repeat_hosts"],
                                                       "days": data["days"]})

    # ------------------------------------------------------------------ the search (a background job)
    def run_acode(job, entry):
        """An analyst code: its selection on its own day (acodes.py), packaged like a combination for the analysts."""
        labels = ctx["labels"]()
        names = entry.get("names") or []
        entry = dict(entry, section="issues" if entry["platform"] == "services" else "infections",
                     name=names[0] if len(names) == 1 else "the analyst's selection")
        m = AMatcher(entry, labels)
        try:
            days = entry.get("days") or [entry["day"]]
            job["log"].append(f"Reading the selection on {', '.join(days)}")
            found = book.acode_records(entry)
            job["done"] = job["total"] = 1
            by_day = collections.Counter(str(e.get("extracted_date") or e.get("timestamp") or "")[:10] for e in found)
            per_day = [(dd, by_day.get(dd, 0)) for dd in days] if len(days) > 1 else [(days[0], len(found))]
            for dd, n in per_day:
                job["log"].append(f"{dd}: {n:,} records")
            job["result"] = package(job, entry, found, per_day, None, (), m)
            job["inputs"] = (entry, found, per_day, None, (), m)     # for one network's report later
            job["state"] = "done"
        except Exception as exc:                              # noqa: BLE001
            if ctx.get("logger"):
                ctx["logger"].exception("analyst code search failed")
            job["state"], job["error"] = "failed", "The search failed; the service log has the details."
            job["log"].append(f"Failed: {type(exc).__name__}")

    def run(job, entry, days):
        if entry.get("kind") == "a":
            return run_acode(job, entry)
        labels = ctx["labels"]()
        svc_code = entry["section"] == "services" and ctx.get("svc_matcher")
        m = ctx["svc_matcher"](entry) if svc_code else Matcher(entry, labels)
        store = ctx["store"] if entry["section"] == "infections" else ctx["svc_store"]
        if svc_code:                                          # services: the code's reports (services_intel.Matcher)
            cols = m.collections(labels)
        else:
            # every report the name turns up in (memory), so the devices found can be followed into the name's other reports
            key = (entry["section"], entry["name"] if entry["section"] == "issues" else entry["name"].lower())
            reps = set((ctx["intel"].index()["by"].get(key) or {}).keys()) | m.reports
            cols = {c for c, lbl in labels.items() if lbl in reps}
        found, around, per_day = [], [], []

        def keep(evs, hit):
            hs = {m.host(e) for e in hit}
            around.extend(e for e in evs if m.of_name(e) and m.host(e) in hs)
        try:
            if days is None:                                  # the days in memory, together (as Intel gathered counts)
                evs = [e for d in list(store.days.values()) for e in d.events]
                job["log"].append(f"Searching the {len(store.days)} days in memory")
                found = m.match(evs)
                keep(evs, found)
                by_day = collections.Counter(str(e.get("extracted_date") or "")[:10] for e in found)
                per_day = sorted(by_day.items())
                job["done"] = job["total"] = 1
            else:
                wset = job.get("_within_hosts")           # drilled down within an analyst's selection: only its devices
                if wset is not None:
                    job["log"].append(f"Within the analyst's selection {job['within']}: {len(wset):,} devices")
                for i, day in enumerate(days):
                    if job.get("cancel"):
                        job["log"].append("Stopped.")
                        break
                    mem = store.days.get(day)
                    evs = mem.events if mem is not None else ctx["fetch"](entry["section"], cols, day)
                    hit = m.match(evs)
                    if wset is not None:
                        hit = [e for e in hit if m.host(e) in wset]
                    found += hit
                    keep(evs, hit)
                    per_day.append((day.date().isoformat(), len(hit)))
                    job["done"] = i + 1
                    job["log"].append(f"{day.date()}: {len(hit):,} records" + (" (in memory)" if mem is not None else ""))
            job["inputs"] = (entry, found, per_day, days, around, m if svc_code else None)   # for one network's report later
            pre = getattr(book, "before_package", None)       # combo_review.py: across-report views, management's decision
            if pre:
                try:
                    pre(job)
                except Exception:                             # noqa: BLE001  (the search still finishes)
                    if ctx.get("logger"):
                        ctx["logger"].exception("across-report preview failed")
            job["result"] = package(job, entry, found, per_day, days, around, m if svc_code else None)
            job["state"] = "done"
        except Exception as exc:                              # noqa: BLE001  (reported to the analyst, logged in full)
            if ctx.get("logger"):
                ctx["logger"].exception("combination search failed")
            job["state"], job["error"] = "failed", "The search failed; the service log has the details."
            job["log"].append(f"Failed: {type(exc).__name__}")

    def across(entry, m, around):
        """What the devices found carried in each of the name's reports: the exact cross-report patterns (LG-X codes),
        and which sets of reports they were seen in. Counted per device over the whole period searched."""
        per = collections.defaultdict(lambda: collections.defaultdict(set))
        for e in around:
            per[m.host(e)][m.report(e)].update(items_of(m, entry["section"], e))
        sets = collections.Counter(tuple(sorted(r)) for r in per.values())
        pats = collections.Counter(tuple(sorted((r, tuple(sorted(i))) for r, i in reps.items())) for reps in per.values() if len(reps) > 1)
        top = pats.most_common(15)
        hosts_of = collections.defaultdict(list)          # each pattern's devices (analysts' report: an advisory names them)
        for h, reps in per.items():
            if len(reps) > 1:
                hosts_of[tuple(sorted((r, tuple(sorted(i))) for r, i in reps.items()))].append(h)
        if top:
            book.record(entry["section"], entry["name"], None, [p for p, _ in top])     # so the analyst can pass the codes on
        return {"devices": len(per), "multi": sum(n for r, n in sets.items() if len(r) > 1),
                "sets": [{"reports": list(r), "devices": n} for r, n in sets.most_common(10)],
                "patterns": [{"code": I.cross_code(entry["section"], entry["name"], p), "devices": n, "ips": sorted(hosts_of[p]),
                              "parts": [{"report": r, "items": list(i)} for r, i in p]} for p, n in top],
                "patterns_total": len(pats)}

    def geography(devs, section):
        """Devices per country, region and city (the region map and its cities, as in the Executive report)."""
        title = lambda s: " ".join(w.capitalize() for w in str(s or "").split()) or ""
        countries = collections.Counter(d["country"] or "Unknown" for d in devs)
        regions = collections.Counter(d["region"] or "Unknown region" for d in devs)
        cities = collections.defaultdict(collections.Counter)
        for d in devs:
            cities[d["region"] or "Unknown region"][title(d["city"]) or "Unknown city"] += 1
        tot = max(1, len(devs))
        rows = [{"value": r, "label": title(r) if r != "Unknown region" else r, "count": n, "hosts": n, "share": n / tot}
                for r, n in regions.most_common()]
        details = {r: {"city_devices": [(c, n) for c, n in cs.most_common(6)]} for r, cs in cities.items()}
        city_rows = collections.Counter()
        for r, cs in cities.items():
            for c, n in cs.items():
                city_rows[(c, title(r) if r != "Unknown region" else "")] += n
        return countries, rows, details, city_rows

    def package(job, entry, found, per_day, days, around=(), m=None, network=None, summary_only=False, asns=None):
        """The ZIP (PDF + devices CSV + records CSV). network: the report for one network provider only (an advisory to
        that operator): the same report on its devices and records; the search's own result and summary stay as they are.
        asns: that provider's AS numbers ("" for records without one). Given, the records are chosen by AS number and
        network is only its name in the report (external review, 2026-11-12: a renamed network matched nothing by name)."""
        section = entry["section"]
        T = _TITLE["of"] if section == "services" else (lambda n: n)       # what people read: a report's title
        cols = COMMS_COLS if section == "infections" else SVC_COLS
        labels = ctx["labels"]()
        m = m or Matcher(entry, labels)
        is_a = entry.get("kind") == "a"
        net = ctx["network"]
        if network or asns is not None:
            asn_of = (lambda e: e.get("src_asn")) if section == "infections" else (lambda e: e.get("asn"))
            if asns is not None:
                sel = {str(a) for a in asns}
                found = [e for e in found if str(asn_of(e) or "") in sel]
            else:
                found = [e for e in found if (net(asn_of(e)) or "Unknown") == network]
            hs = {m.host(e) for e in found}
            around = [e for e in around if m.host(e) in hs]
            n_by_day = collections.Counter(str(e.get("extracted_date") or "")[:10] for e in found)
            per_day = [(dd, n_by_day.get(dd, 0)) for dd, _ in per_day]
        rows, devices = [], {}
        for e in sorted(found, key=lambda e: e.get("_t") or 0):
            h = m.host(e)
            asn = e.get("src_asn") if section == "infections" else e.get("asn")
            extra = {"_network": net(asn), "_report": m.report(e), "_code": entry["code"],
                     "_issue": ", ".join(e.get("issues") or []) if is_a else entry["name"]}
            rows.append([extra[k] if k in extra else _cell(e, k) for _, k in cols])
            d = devices.setdefault(h, {"ip": h, "asn": asn or "", "network": extra["_network"], "records": 0, "first": None, "last": None,
                                       "reports": set(), "days": set(),
                                       "country": e.get("src_geo") if section == "infections" else e.get("geo"),
                                       "region": e.get("src_region") if section == "infections" else e.get("region"),
                                       "city": e.get("src_city") if section == "infections" else e.get("city")})
            t = str(e.get("timestamp") or e.get("extracted_date") or "")
            d["records"] += 1
            d["first"] = t if d["first"] is None or t < d["first"] else d["first"]
            d["last"] = t if d["last"] is None or t > d["last"] else d["last"]
            d["reports"].add(extra["_report"])
            d["days"].add(str(e.get("extracted_date") or "")[:10])
        devs = sorted(devices.values(), key=lambda d: (-d["records"], d["ip"]))
        # an analyst's selection has several names: no cross-report codes of one name for it
        x = ({"devices": 0, "multi": 0, "sets": [], "patterns": [], "patterns_total": 0} if is_a else across(entry, m, around))
        # per device: the other reports of the name it was seen in, and its cross-report pattern code
        per_dev = collections.defaultdict(lambda: collections.defaultdict(set))
        for e in ([] if is_a else around):
            per_dev[m.host(e)][m.report(e)].update(items_of(m, section, e))
        xcode = {h: I.cross_code(section, entry["name"], [(r, tuple(sorted(i))) for r, i in reps.items()])
                 for h, reps in per_dev.items() if len(reps) > 1}
        dev_cols = ["ip", "asn", "network", "country", "region", "city", "records", "days", "first_seen", "last_seen", "reports",
                    "also_seen_in", "combination_code", "cross_report_code"]
        dev_rows = [[d["ip"], d["asn"], d["network"], d["country"] or "", (d["region"] or "").title(), (d["city"] or "").title(), d["records"],
                     len(d["days"]), d["first"] or "", d["last"] or "", ", ".join(sorted(d["reports"])),
                     ", ".join(sorted(set(per_dev.get(d["ip"], {})) - d["reports"])), entry["code"], xcode.get(d["ip"], "")] for d in devs]
        countries, regions, details, city_rows = geography(devs, section)
        shapes = ctx["shapes"]() if devs else None

        def csv_text(head, body):
            buf = io.StringIO()
            w = csvsafe.writer(buf)
            w.writerow(head)
            w.writerows(body)
            return "﻿" + buf.getvalue()

        # the period, as dates: the days searched (history) or the days in memory
        if is_a:
            d0, d1 = (entry.get("days") or [entry["day"]])[0], (entry.get("days") or [entry["day"]])[-1]
        elif days:
            d0, d1 = days[0].date().isoformat(), days[-1].date().isoformat()
        else:
            mem = sorted(dd.date().isoformat() for dd in (ctx["store"] if section == "infections" else ctx["svc_store"]).days)
            d0, d1 = (mem[0], mem[-1]) if mem else ("", "")
        span = d0 if d0 == d1 else f"{d0} to {d1}"
        base = "looking-glass_" + entry["code"] + "_" + (d0 if is_a else f"{d0}_{d1}" if days else "memory")
        if network:
            base += "_" + (re.sub(r"[^\w.-]+", "-", network).strip("-")[:40] or "network")
        if job.get("file_base"):                  # an advisory names its files itself (advisory.py: CSIRT_network_title_date)
            base = job["file_base"]
        nets = collections.Counter(d["network"] or "Unknown" for d in devs)
        repeat = sum(1 for d in devs if d["records"] > 1)
        multi_day = sum(1 for d in devs if len(d["days"]) > 1)
        n_dev, n_rec = len(devs), len(rows)
        dv = lambda n: f"{n:,} device{'s' if n != 1 else ''}"
        first = (f"{dv(n_dev)} in the analyst's selection on {d0}" if is_a else
                 f"{dv(n_dev)} carried exactly this combination between {d0} and {d1}" if d0 != d1 else f"{dv(n_dev)} carried exactly this combination on {d0}")
        first += f", in {n_rec:,} record{'s' if n_rec != 1 else ''}."
        if repeat:
            first += f" {repeat:,} of them ({_share(repeat, n_dev)}) carried it more than once"
            first += f", and {multi_day:,} on more than one day." if multi_day else "."
        elif n_dev:
            first += " Each carried it once."
        if is_a:
            pts = [f"Analyst code {entry['code']}: {describe(entry)}.", first.replace("carried it more than once", "appear in more than one record"),
                   "The records are the analyst's selection on that day, exactly as the analysis window showed it"
                   + (f"; the names in it: {', '.join(entry.get('names', [])[:8])}." if entry.get("names") else ".")]
        else:
            pts = [f"Combination {entry['code']}: {describe(entry)}.", first,
                   "Exactly means that each record carries these indicators and no other indicator of the kinds compared ("
                   + ("C2 domain, DNS lookup, TLS name, user agent and tags)." if section == "infections" else
                      "the report's pattern fields, the values 5 or more hosts share)." if section == "services" else "associated tags and CVEs).")
                   + (" For a cross-report code, the device carried, in each of these reports, exactly what is listed." if entry["kind"] == "x" else "")]
        if network:                               # the report for one network provider says so first
            asn_n = next((d["asn"] for d in devs if d["asn"]), "")
            pts.insert(1, f"This report covers one network provider: {network}" + (f" (AS{asn_n})" if asn_n else "")
                       + ". Every figure, the map and both CSV files are limited to its devices and records.")
        top_r = [r for r in regions if r["value"] != "Unknown region"][:3]
        if top_r:
            if len(top_r) == 1 and len(regions) == 1:
                pts.append(f"All of them are in {top_r[0]['label']}" + (f" ({', '.join(c for c, _ in details[top_r[0]['value']]['city_devices'][:3])})."
                                                                          if details.get(top_r[0]["value"], {}).get("city_devices") else "."))
            else:
                pts.append("Most are in " + ", ".join(f"{r['label']} ({dv(r['count'])})" for r in top_r)
                           + (f"; {len(regions) - len(top_r)} more region{'s' if len(regions) - len(top_r) != 1 else ''} have the rest." if len(regions) > len(top_r) else "."))
        if x["multi"]:
            other = sorted({r for s_ in x["sets"] for r in s_["reports"]} - set(m.reports))
            who = ("All of these devices were" if x["multi"] == n_dev and n_dev > 1 else "This device was" if x["multi"] == n_dev
                   else f"{x['multi']:,} of these devices {'was' if x['multi'] == 1 else 'were'}")
            pts.append(f"{who} also seen in {', '.join(T(o) for o in other) if other else 'other reports'} for {T(entry['name'])}, in "
                       f"{x['patterns_total']:,} exact pattern{'s' if x['patterns_total'] != 1 else ''}, listed under Across reports with "
                       f"{'its code' if x['patterns_total'] == 1 else 'their codes'} for a follow-up search.")
        elif entry["kind"] == "r":
            pts.append(f"None of these devices was seen in another report of {T(entry['name'])} in this period.")
        # the researchers' notes on the name (an analyst code: on each of its names), the ones that point at this code first
        note_names = entry.get("names", [])[:8] if is_a else [entry["name"]]
        notes = sorted(({**n, "name": nm} for nm in note_names for n in ctx["notes"].list(section, nm)),
                       key=lambda n: not any(c["code"] == entry["code"] for c in n.get("codes") or []))
        if job.get("advisory"):                   # an advisory goes to an organisation: definitions and references only,
            notes = []                            # never the team's own notes
        note_rows = [[f"{n['role']}: {n['by']}", n.get("date", ""), n["text"][:600],
                      ", ".join(c["code"] for c in n.get("codes") or [])] for n in notes[:12]]
        if notes:
            pts.append(f"{len(notes)} researcher note{'s' if len(notes) != 1 else ''} on "
                       + (", ".join(sorted({n['name'] for n in notes})) if is_a else T(entry['name']))
                       + (f", {sum(1 for n in notes if any(c['code'] == entry['code'] for c in n.get('codes') or []))} of them on this combination"
                          if any(any(c["code"] == entry["code"] for c in n.get("codes") or []) for n in notes) else "")
                       + "; they are on the Explained page, with what the name"
                       + (" and its vulnerabilities are." if section == "issues" else " is."))
        # the analyst added the analysis across every category (enrich): what these devices show in the other categories
        if job.get("advisory"):
            # an advisory goes to an organisation: Looking Glass's codes stay out of its words (the patterns are named
            # by their devices' IP addresses, under Across reports)
            def no_codes(t):
                t = (t.replace(f"listed under Across reports with {'its code' if x['patterns_total'] == 1 else 'their codes'} for a follow-up search",
                               "listed under Across reports with their devices by IP address")
                     .replace("For a cross-report code,", "For a pattern across reports,")
                     .replace("both CSV files are limited to its devices and records", "the devices CSV is limited to its devices"))
                t = re.sub(r"\bLG-[ACX]-[0-9A-F]{8}\s*", "", t)
                return re.sub(r"\s{2,}", " ", t).strip()
            pts = [no_codes(p_) for p_ in pts]
        enr = job.get("enrich")
        if enr and network and (enr.get("cross") or (enr.get("sent") and (enr.get("infections") or enr.get("issues")))):
            # one organisation's report: only the across-report patterns, and the ticked infections and CVEs/issues, of
            # its own devices, with only those devices
            hs_net = {d["ip"] for d in devs}

            def own(items):
                out_ = []
                for p_ in items or []:
                    if "devices" not in p_:
                        out_.append(p_)
                        continue
                    dv_ = [d for d in p_.get("devices") or [] if d.get("ip") in hs_net]
                    if dv_:
                        out_.append(dict(p_, devices=dv_, hosts=len(dv_)))
                return out_
            cross_net = []                         # the patterns exactly as before: one without its devices is left out
            for p_ in enr.get("cross") or []:
                dv_ = [d for d in p_.get("devices") or [] if d.get("ip") in hs_net]
                if dv_:
                    cross_net.append(dict(p_, devices=dv_, hosts=len(dv_)))
            enr = dict(enr, cross=cross_net, cross_total=len(cross_net), multi_hosts=sum(p_["hosts"] for p_ in cross_net),
                       infections=own(enr.get("infections")), issues=own(enr.get("issues")))
        if enr:
            pts.extend([no_codes(p_) for p_ in enrich_points(enr)] if job.get("advisory") else enrich_points(enr))
        # activity by hour of the day (network communications carry the event time)
        hours = None
        if section == "infections":
            hours = [0] * 24
            for e in found:
                ts = str(e.get("timestamp") or "")
                if len(ts) >= 13 and ts[11:13].isdigit():
                    hours[int(ts[11:13]) % 24] += 1
            hours = hours if any(hours) else None
        # per network: AS number, devices and records
        per_net = collections.defaultdict(lambda: {"asn": "", "devices": 0, "records": 0})
        for d in devs:
            k = d["network"] or "Unknown"
            per_net[k]["asn"] = per_net[k]["asn"] or str(d["asn"] or "")
            per_net[k]["devices"] += 1
            per_net[k]["records"] += d["records"]
        net_rows = [[k, v["asn"], f"{v['devices']:,}", f"{v['records']:,}", f"{v['devices'] / max(1, len(devs)):.1%}"]
                    for k, v in sorted(per_net.items(), key=lambda kv: -kv[1]["devices"])[:20]]
        # what the devices are, and where they listen / call
        kind = collections.Counter()
        ports = collections.Counter()
        for e in found:
            if section == "infections":
                kind[" ".join(x for x in (e.get("device_vendor"), e.get("device_type"), e.get("device_model")) if x) or "Not given by the report"] += 1
                ports[f"{e.get('dst_port') or '?'}/{(e.get('protocol') or '').lower() or '?'}"] += 1
            else:
                kind[" ".join(x for x in (e.get("vendor"), e.get("product"), e.get("version")) if x) or "Not given by the report"] += 1
                ports[f"{e.get('port') or '?'}/{(e.get('protocol') or '').lower() or '?'}"] += 1
        kind_rows = [[k, f"{n:,}", f"{n / max(1, len(rows)):.1%}"] for k, n in kind.most_common(12)]
        port_rows = [[k, f"{n:,}", f"{n / max(1, len(rows)):.1%}"] for k, n in ports.most_common(10)]
        geo_rows = [[r["label"], f"{r['count']:,}", f"{r['share']:.1%}"] for r in regions[:15]]
        city_tab = [[c, r, f"{n:,}", f"{n / max(1, len(devs)):.1%}"] for (c, r), n in city_rows.most_common(15)]
        x_rows = [[" | ".join(f"{T(p['report'])}: {' + '.join(p['items']) or 'the name only'}" for p in pt["parts"]), f"{pt['devices']:,}", pt["code"]]
                  for pt in x["patterns"]]
        spec = {"platform_label": "Network communications" if section == "infections" else "Publicly accessible services",
                "title": f"Combination {entry['code']}", "selection": describe(entry)[:150], "day": span,
                "generated_by": job["user"], "scope": ctx["scope_text"](), "demo": False,
                "intro": (f"Every device that carried exactly the combination {entry['code']} of {T(entry['name'])}, found by the analyst's "
                          f"combination search over {span}. The researcher's code and this list use the same matching rule as Intel gathered."
                          + (f" Only the devices of the analyst's selection {job['within']} are included: the researcher drilled down to "
                             f"this combination within it." if job.get("within") else "")),
                "summary_points": pts,
                "kpis": [(f"{len(devs):,}", "devices"), (f"{len(rows):,}", "records"), (f"{repeat:,}", "devices repeating it"),
                         (f"{multi_day:,}", "devices on several days"), (f"{len(nets):,}", "networks"),
                         (f"{sum(1 for _, n in per_day if n):,}", "days with a record")],
                "hours": hours, "peak_hour": (max(range(24), key=lambda h: hours[h]) if hours else None),
                "priorities": (["IP address", "Network", "Region", "City", "Records", "Days", "First seen", "Last seen"],
                               [[d["ip"], d["network"], (d["region"] or "").title(), (d["city"] or "").title(), f"{d['records']:,}",
                                 str(len(d["days"])), (d["first"] or "")[:16].replace("T", " "), (d["last"] or "")[:16].replace("T", " ")]
                                for d in devs[:PDF_DEVICES]],
                               [0.13, 0.22, 0.11, 0.1, 0.07, 0.05, 0.16, 0.16]) if devs else None,
                "priorities_intro": f"The devices with the most records (the first {min(PDF_DEVICES, len(devs))} of {len(devs):,}; "
                                    f"all of them are in {base}_devices.csv).",
                "geo": {"title": "Where the devices are", "shapes": shapes, "regions": regions, "details": details,
                        "note": f"Devices per region (the country's first-level regions), with their cities. "
                                f"{len(countries)} countr{'y' if len(countries) == 1 else 'ies'}: "
                                + ", ".join(f"{k} ({n:,})" for k, n in countries.most_common(5)) + "."} if devs else None,
                "charts": [("Devices per region", regions[:10]),
                           ("Devices per network", [{"label": k, "value": k, "count": n, "share": n / max(1, len(devs))} for k, n in nets.most_common(10)]),
                           ("Records per day", [{"label": d, "value": d, "count": n, "share": n / max(1, len(rows))} for d, n in per_day])],
                "breakdowns": [b for b in [
                    ("Researchers' notes", ["Shared by", "Date", "Note", "Combinations"], note_rows, [0.18, 0.09, 0.55, 0.18]),
                    ("Across reports: what these devices carried in the name's other reports",
                     ["Exact pattern, report by report", "Devices", "Code"], x_rows, [0.7, 0.1, 0.2]),
                    ("Reports these devices were seen in", ["Reports", "Devices", "Share"],
                     [[" + ".join(T(r) for r in s["reports"]), f"{s['devices']:,}", f"{s['devices'] / max(1, x['devices']):.1%}"] for s in x["sets"]]),
                    ("Devices per network", ["Network", "AS number", "Devices", "Records", "Share of devices"], net_rows, [0.4, 0.14, 0.14, 0.14, 0.18]),
                    ("Devices per region", ["Region", "Devices", "Share"], geo_rows),
                    ("Devices per city", ["City", "Region", "Devices", "Share"], city_tab, [0.3, 0.3, 0.2, 0.2]),
                    ("What the devices are (as the reports name them)", ["Vendor, type / product", "Records", "Share"], kind_rows),
                    (("Destination ports" if section == "infections" else "Ports the services listen on"), ["Port / protocol", "Records", "Share"], port_rows),
                    ("Records per day", ["Day", "Records", "Share"], [[d, f"{n:,}", f"{n / max(1, len(rows)):.1%}"] for d, n in per_day])] if b[2]],
                "columns": [[c, c] for c in dev_cols], "rows": [], "total": len(devs), "csv_name": f"{base}_devices.csv",
                "sources": ["Data: the Shadowserver Foundation's daily reports for the constituency, as stored by Looking Glass.",
                            f"Two CSV files come with this PDF: {base}_devices.csv (one row per device) and {base}_records.csv "
                            "(every record).",
                            "Contains the addresses of affected devices: share only according to your organisation's information-sharing policy."]}
        # the report, drawn like the Executive report (combo_pdf.py); the plain layout only if that fails
        parts = ([("Selection", [entry.get("label", "")])] if is_a else
                 [(entry["report"], entry["items"])] if entry["kind"] == "r" else [(r, i) for r, i in entry["parts"]])
        cves = [] if is_a else sorted({i.upper() for _, items in parts for i in items if re.match(r"^CVE-\d{4}-\d{4,7}$", i, re.I)})
        explained, stats = [], {}
        heads = [(nm, section) for nm in entry.get("names", [])[:8]] if is_a else [(entry["name"], section)]
        if section == "services":
            # a services name is a report, not malware (Malpedia would call it "probably malware"): its issues (tags) and
            # the infections its devices call are defined instead, with the across-report views' when the report has them
            heads = []
            all_parts = list(parts) + ([(q["report"], q["items"]) for p_ in (enr or {}).get("cross") or [] for q in p_.get("parts") or []]
                                       if enr else [])
            for _, items in all_parts:
                for it in items:
                    it = str(it)
                    if it.lower().startswith("tag:") and not re.search(r"CVE-\d{4}-\d{4,7}", it, re.I):
                        if issue_tags.issue_of(it):           # an issue; a product / protocol tag is not defined here
                            heads.append((issue_tags.issue_of(it), "issues"))
                    elif it.startswith("Infection:"):
                        heads.append((it.split(":", 1)[1].strip(), "infections"))
                    elif re.search(r"CVE-\d{4}-\d{4,7}", it, re.I) and not is_a:
                        cves.append(re.search(r"CVE-\d{4}-\d{4,7}", it, re.I).group(0).upper())
            heads = list(dict.fromkeys(heads))[:12]
            cves = sorted(set(cves))
        for nm, sec in heads + [(c, "issues") for c in cves if c.lower() != entry["name"].lower()]:
            card = ctx["explain"](sec, nm)
            if card:
                explained.append((nm, card))
                stats[nm] = (f"Named in this selection of {len(devs):,} devices" if is_a and nm in entry.get("names", [])
                             else f"{len(devs):,} devices in this combination")
        data = {"section": section, "code": entry["code"], "name": entry["name"], "parts": parts,
                "headline": (f"{len(devs):,} device{'s' if len(devs) != 1 else ''} in the analyst's selection ({span})" if is_a else
                             f"{len(devs):,} device{'s' if len(devs) != 1 else ''} carried exactly this combination ({span})")
                            + (f" on {network}" if network else ""),
                "kpis": {"devices": len(devs), "records": len(rows), "repeat": repeat, "also": x["multi"],
                         "regions": len([r for r in regions if r["value"] != "Unknown region"]), "cities": sum(len(v) for v in details.values()),
                         "networks": len(nets)},
                "top_network": (nets.most_common(1)[0][0] if nets else ""), "hours": hours, "peak_hour": spec["peak_hour"],
                "findings": pts[1:] or pts, "shapes": shapes, "regions": regions,
                "region_details": {r: {"city_devices": v["city_devices"]} for r, v in details.items()},
                "networks": [{"label": k_, "hosts": v["devices"]} for k_, v in sorted(per_net.items(), key=lambda kv: -kv[1]["devices"])],
                "cities": [{"label": f"{c} · {r}" if r else c, "hosts": n} for (c, r), n in city_rows.most_common(20)],
                "devices": [{"ip": d["ip"], "network": d["network"], "asn": str(d["asn"] or ""), "region": (d["region"] or "").title(),
                             "city": (d["city"] or "").title(), "records": d["records"], "days": len(d["days"]),
                             "last": (d["last"] or "")[:16].replace("T", " "), "also": ", ".join(sorted(set(per_dev.get(d["ip"], {})) - d["reports"]))}
                            for d in devs[:60]],
                "csv_devices": f"{base}_devices.csv", "csv_records": f"{base}_records.csv",
                "across": {"multi": x["multi"], "patterns_total": x["patterns_total"],     # reports by their titles
                           "patterns": [dict(p, parts=[dict(q, title=T(q["report"])) for q in p["parts"]]) for p in x["patterns"][:8]]},
                "report_sets": [{"label": " + ".join(T(r) for r in s_["reports"]), "hosts": s_["devices"]} for s_ in x["sets"]],
                "kinds": [{"label": k_, "count": n} for k_, n in kind.most_common(10)],
                "ports": [{"label": k_, "count": n} for k_, n in ports.most_common(10)],
                "explained": explained, "stats": stats, "notes": notes}
        try:
            if summary_only:                                  # the page's figures for one network: no PDF needed
                raise _SummaryOnly()
            import combo_pdf
            pdf = combo_pdf.build(data, {"platform_label": spec["platform_label"], "scope": spec["scope"], "selection": describe(entry)[:120],
                                         "day": span, "header": ((job.get("advisory") or {}).get("header") or
                                                                 f"{'Analyst code' if is_a else 'Combination'} {entry['code']} · {span}"
                                                                 + (f" · {network}" if network else "")),
                                         # an advisory is signed by the CSIRT (the person is in the audit log)
                                         "generated_by": (job.get("advisory") or {}).get("org") or job["user"], "advisory": job.get("advisory")})
        except _SummaryOnly:
            pdf = b""
        except Exception as exc:                              # noqa: BLE001  (never leave the analyst without a report)
            if job.get("advisory"):                           # an advisory without its own pages would mislead: say so instead
                raise
            if ctx.get("logger"):
                ctx["logger"].warning("combination PDF (Executive design) failed, plain layout used: %s", exc)
            pdf = ctx["build_pdf"](spec)
        def without(head, body, drop):
            """An advisory's files go to an organisation: Looking Glass's own codes (combination, cross-report) stay out."""
            if not job.get("advisory"):
                return head, body
            keep = [i for i, h in enumerate(head) if h not in drop]
            return [head[i] for i in keep], [[r[i] for i in keep] for r in body]
        CODES = {"combination_code", "cross_report_code", "code"}
        z = io.BytesIO()
        with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(f"{base}.pdf", pdf)
            zf.writestr(f"{base}_devices.csv", csv_text(*without(dev_cols, dev_rows, CODES)))
            zf.writestr(f"{base}_records.csv", csv_text(*without([c for c, _ in cols], rows, CODES)))
            if enr:                                   # the analysis across every category, one row per finding
                zf.writestr(f"{base}_other_categories.csv",
                            csv_text(*without(["category", "report", "value", "hosts", "records", "code"], enrich_rows(enr), CODES)))
        # for the page: the key analytics, and per region what the map shows on hover (with the devices' addresses: this
        # page is for analysts only)
        reg_det = {}
        for d in devs:
            r = d["region"] or "Unknown region"
            x_ = reg_det.setdefault(r, {"devices": 0, "records": 0, "cities": collections.Counter(), "networks": collections.Counter(), "ips": []})
            x_["devices"] += 1; x_["records"] += d["records"]
            x_["cities"][(d["city"] or "").title() or "Unknown city"] += 1
            x_["networks"][d["network"] or "Unknown"] += 1
            if len(x_["ips"]) < 12:
                x_["ips"].append([d["ip"], d["records"]])
        tot = max(1, len(devs))
        if network and not summary_only:          # one network's report: a file of its own, nothing else changes
            ctx["audit"].add("combo_export", user=job["user"], target=entry["code"],
                             detail=f"{entry['name']} · {span} · network {network} · {len(devs)} devices, {len(rows)} records")
            return {"name": f"{base}.zip", "bytes": z.getvalue()}
        summ = {"devices": len(devs), "records": len(rows), "repeat": repeat, "multi_day": multi_day,
                          "networks_all": [{"label": k, "asn": v["asn"], "devices": v["devices"], "records": v["records"]}
                                           for k, v in sorted(per_net.items(), key=lambda kv: -kv[1]["devices"])],
                          "per_day": per_day, "networks": len(nets), "country": ctx["country"](),
                          "cities": sum(len(v["cities"]) for v in reg_det.values()), "peak_hour": spec["peak_hour"], "hours": hours,
                          "regions": [{"value": r["value"], "label": r["label"], "devices": r["count"], "share": r["share"]} for r in regions],
                          "region_details": {k: {"devices": v["devices"], "records": v["records"], "cities": v["cities"].most_common(5),
                                                 "networks": v["networks"].most_common(4), "ips": v["ips"]} for k, v in reg_det.items()},
                          "top_networks": [{"label": k, "asn": v["asn"], "devices": v["devices"], "records": v["records"], "share": v["devices"] / tot}
                                           for k, v in sorted(per_net.items(), key=lambda kv: -kv[1]["devices"])[:8]],
                          "top_cities": [{"label": c, "region": r, "devices": n} for (c, r), n in city_rows.most_common(8)],
                          "kinds": [{"label": k, "records": n} for k, n in kind.most_common(6)],
                          "ports": [{"label": k, "records": n} for k, n in ports.most_common(6)],
                          "top_devices": [{"ip": d["ip"], "network": d["network"], "region": (d["region"] or "").title(), "city": (d["city"] or "").title(),
                                           "records": d["records"], "days": len(d["days"]), "last": (d["last"] or "")[:16].replace("T", " "),
                                           "also": sorted(set(per_dev.get(d["ip"], {})) - d["reports"])} for d in devs[:15]],
                          "across": {"multi": x["multi"], "patterns": x["patterns"][:10], "patterns_total": x["patterns_total"], "sets": x["sets"][:6]},
                          "enrich": enr or None}
        if summary_only:                          # the figures only (the page filtered to one network)
            return {"summary": summ}
        job["summary"] = summ
        ctx["audit"].add("combo_export", user=job["user"], target=entry["code"],
                         detail=f"{entry['name']} · {span} · {len(devs)} devices, {len(rows)} records")
        # kept on disk for an hour (owner-only files), so a service restart between the search and the download loses nothing
        try:
            os.makedirs(exports["dir"], mode=0o700, exist_ok=True)
            for suffix, data in ((".zip", z.getvalue()), (".json", json.dumps({"user": job["user"], "name": f"{base}.zip",
                                                                                "at": time.time(), "summary": job["summary"],
                                                                                "gated": bool(job.get("needs_review") and not job.get("review_ok")),
                                                                                # the gate is asked again on a download from disk
                                                                                "code": entry.get("code", ""), "needs_review": bool(job.get("needs_review"))}).encode())):
                fd = os.open(os.path.join(exports["dir"], job["id"] + suffix), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
        except OSError as exc:
            if ctx.get("logger"):
                ctx["logger"].warning("combination export not kept on disk: %s", exc)
        return {"name": f"{base}.zip", "bytes": z.getvalue()}

    # where finished downloads are kept for an hour; a setting, so the checks keep theirs in a temporary folder and never
    # write to (or delete from) the installation's data/combo_exports (external review, 2026-11-11)
    exports = {"dir": os.path.join(ctx["base_dir"], "data", "combo_exports")}
    book.export_paths = exports

    def from_disk(jid):
        """A finished search after a restart: (meta, zip bytes) if it is still on disk and younger than an hour."""
        if not re.fullmatch(r"[0-9a-f]{16}", jid or ""):
            return None, None
        base = os.path.realpath(exports["dir"])
        meta_p = os.path.realpath(os.path.join(base, jid + ".json"))
        zip_p = os.path.realpath(os.path.join(base, jid + ".zip"))
        if not (meta_p.startswith(base + os.sep) and zip_p.startswith(base + os.sep)):
            return None, None                     # never outside data/combo_exports
        try:
            with open(meta_p, encoding="utf-8") as f:
                meta = json.load(f)
            if time.time() - meta.get("at", 0) > JOB_TTL:
                return None, None
            with open(zip_p, "rb") as f:
                return meta, f.read()
        except (OSError, ValueError):
            return None, None

    def _sweep():
        now = time.time()
        with jobs_lock:
            for k in [k for k, j in jobs.items() if j["state"] != "running" and now - j["at"] > JOB_TTL]:
                del jobs[k]
        try:
            for n in os.listdir(exports["dir"]):
                p = os.path.join(exports["dir"], n)
                if now - os.path.getmtime(p) > JOB_TTL:
                    os.remove(p)
        except OSError:
            pass

    @app.route("/api/combos/search", methods=["POST"])
    def api_combos_search():
        if not can_export():
            return jsonify(error="The combination search is for analysts (roles that see addresses and may export)."), 403
        if ctx["is_demo"]():
            return jsonify(error="Demo mode is on: the combination search lists real addresses, so it is off in demo mode."), 403
        if not ctx["csrf_ok"]():
            return jsonify(error="Refused (the request did not come from this page)."), 403
        b = request.get_json(silent=True) or {}
        code = str(b.get("code") or "").strip().upper()
        if not ANY_RX.match(code):
            return jsonify(error="A code looks like LG-C-1A2B3C4D or LG-X-1A2B3C4D (an analyst's: LG-A-1A2B3C4D)."), 400
        entry = book.resolve_any(code)
        if entry and entry.get("kind") == "a" and hasattr(book, "acode_allowed") and not book.acode_allowed(code):
            entry = None                          # another channel's analyst code
        if not entry:
            return jsonify(error=f"{code} is not known here: it was never shown in Intel gathered on this platform."), 404
        days = None
        if entry.get("kind") != "a" and (b.get("from") or b.get("to")):     # an analyst code is always its own day
            try:
                f = datetime.fromisoformat(str(b.get("from") or b.get("to"))[:10]).replace(tzinfo=timezone.utc)
                t = datetime.fromisoformat(str(b.get("to") or b.get("from"))[:10]).replace(tzinfo=timezone.utc)
            except ValueError:
                return jsonify(error="Dates as YYYY-MM-DD."), 400
            if t < f:
                f, t = t, f
            today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            t = min(t, today)
            n = (t - f).days + 1
            if n > MAX_DAYS:
                return jsonify(error=f"At most {MAX_DAYS} days at a time."), 400
            days = [f + timedelta(days=i) for i in range(n)]
        # within an analyst's selection (user, 2026-11-14): a researcher's reply code searched only among the devices of
        # the analyst code it answers, on that code's own days, so what the advisor gets is exactly what was drilled down to
        within, wset = str(b.get("within") or "").strip().upper(), None
        if within:
            if not re.fullmatch(r"LG-A-[0-9A-F]{8}", within) or entry.get("kind") == "a":
                return jsonify(error="Within: an analyst code (LG-A-…), for a researcher's code."), 400
            we = book.get(within)
            if not we or we.get("kind") != "a" or (hasattr(book, "acode_allowed") and not book.acode_allowed(within)):
                return jsonify(error=f"{within} is not an analyst code of your channels."), 404
            hk = "src_ip" if we.get("platform") == "comms" else "ip"
            wset = {e.get(hk) for e in (book.acode_records(we) or []) if e.get(hk)}
            if not wset:
                return jsonify(error=f"The analyst's selection {within} has no devices left in the records."), 409
            days = [datetime.fromisoformat(d).replace(tzinfo=timezone.utc) for d in (we.get("days") or [we["day"]])][:MAX_DAYS]
        _sweep()
        me = user()
        with jobs_lock:
            if any(j["user"] == me and j["state"] == "running" for j in jobs.values()):
                return jsonify(error="You already have a combination search running; wait for it to finish."), 429
            jid = secrets.token_hex(8)
            job = jobs[jid] = {"id": jid, "user": me, "code": code, "state": "running", "done": 0, "total": len(days) if days else 1,
                               "log": [], "at": time.time(), "result": None, "error": "", "summary": None}
            if wset is not None:
                job.update(within=within, _within_hosts=wset)
        def in_app():
            with app.app_context():           # the explanation look-ups and the PDF builder run as in a request
                run(job, entry, days)
        threading.Thread(target=in_app, daemon=True, name=f"combo-{jid}").start()
        return jsonify(id=jid, entry=public_entry(entry), within=within or None)

    def own(jid):
        with jobs_lock:
            j = jobs.get(jid)
        return j if j and j["user"] == user() else None

    @app.route("/api/combos/search/<jid>")
    def api_combos_status(jid):
        if not can_export():
            return jsonify(error="The combination search is for analysts."), 403
        j = own(jid)
        if not j:
            meta, _ = from_disk(jid)                  # finished before a restart: still downloadable
            if meta and meta.get("user") == user():
                return jsonify(id=jid, code="", state="done", done=1, total=1, log=["Finished before the service restarted."],
                               error="", summary=meta.get("summary"), file=meta["name"])
            return jsonify(error="No such search (finished searches are kept for an hour)."), 404
        return jsonify({k: v for k, v in j.items() if k not in ("result", "user", "at", "cancel", "inputs") and not k.startswith("_")} |
                       {"file": j["result"]["name"] if j["result"] else None})

    @app.route("/api/combos/search/<jid>/stop", methods=["POST"])
    def api_combos_stop(jid):
        if not can_export() or not ctx["csrf_ok"]():
            return jsonify(error="Refused."), 403
        j = own(jid)
        if not j:
            return jsonify(error="No such search."), 404
        j["cancel"] = True
        return jsonify(stopping=True)

    @app.route("/api/combos/search/<jid>/enrich", methods=["POST"])
    def api_combos_enrich(jid):
        """Add the analysis across every category to a finished search: what its devices show in the services reports
        (with their pattern codes), the CVEs and issues on them, and the infections they call sinkholes as. It goes into
        this search's report (PDF summary points and a CSV of its own) and onto the page."""
        if not can_export() or not ctx["csrf_ok"]():
            return jsonify(error="Refused."), 403
        j = own(jid)
        if not j or not j.get("inputs"):
            return jsonify(error="This search has expired (finished searches are kept for an hour): run it again."), 404
        if not ctx.get("cross"):
            return jsonify(error="The analysis across categories is not available here."), 404
        if j.get("needs_review"):                 # across-report data: management decides what the report carries
            return jsonify(error="These devices turn up in other reports: management decides which views the report carries.", needs_review=True), 409
        entry, found = j["inputs"][0], j["inputs"][1]
        m = j["inputs"][5] or Matcher(entry, ctx["labels"]())
        hosts = {m.host(e) for e in found if m.host(e)}
        if not hosts:
            return jsonify(error="The search found no device."), 400
        j["enrich"] = ctx["cross"](hosts)
        j["result"] = package(j, *j["inputs"][:5], m=j["inputs"][5])     # the report again, with the analysis in it
        ctx["audit"].add("combo_enrich", user=user(), target=entry.get("code", ""), detail=f"{len(hosts)} devices across every category")
        return jsonify(enrich=j["enrich"], summary=j.get("summary"), file=j["result"]["name"])

    @app.route("/api/combos/search/<jid>/summary")
    def api_combos_summary(jid):
        """The page's figures for one network (organisation) of a finished search: the same summary as the whole search
        (devices, records, map, networks, cities, the busiest devices, across reports), on that network's devices only."""
        if not can_export():
            return jsonify(error="The combination search is for analysts."), 403
        j = own(jid)
        if not j or not j.get("inputs"):
            return jsonify(error="This search has expired (finished searches are kept for an hour): run it again."), 404
        network = (request.args.get("network") or "").strip()[:120]
        if not network:
            return jsonify(summary=j.get("summary"), network="")
        s = package(j, *j["inputs"][:5], m=j["inputs"][5], network=network, summary_only=True)["summary"]
        if not s["devices"]:
            return jsonify(error=f"No device of this search is on {network}."), 404
        return jsonify(summary=s, network=network)

    @app.route("/api/combos/search/<jid>/download")
    def api_combos_download(jid):
        if not can_export():
            return jsonify(error="The combination search is for analysts."), 403
        _sweep()
        j = own(jid)
        # across-report data: management decides first which views the report carries (combo_review.py)
        gate = getattr(book, "review_gate", None)
        if gate and j and j.get("inputs"):
            allowed, why = gate(j)
            if not allowed:
                return jsonify(error=why, needs_review=True), 409
        network = (request.args.get("network") or "").strip()[:120]
        if network:
            # the report for one network provider: packaged now from the search's records (kept with the search)
            if not (j and j.get("inputs")):
                return jsonify(error="This search has expired (finished searches are kept for an hour): run it again."), 404
            res = package(j, *j["inputs"][:5], m=j["inputs"][5], network=network)
            name, data = res["name"], res["bytes"]
        elif j and j["result"]:
            name, data = j["result"]["name"], j["result"]["bytes"]
        else:
            meta, data = from_disk(jid)
            if not meta or meta.get("user") != user():
                return jsonify(error="This search has expired (finished searches are kept for an hour): run it again."), 404
            if meta.get("gated"):                     # kept before a restart, still waiting for management's decision
                return jsonify(error="This search has across-report data: run it again once management has decided.", needs_review=True), 409
            # the review gate as it stands NOW (review 2026-11-13: the flag kept with the file was a snapshot, so a
            # combination sent to management afterwards, or decided, still downloaded from disk after a restart)
            if gate:
                if not meta.get("code"):              # kept by an older version: the gate cannot be asked, so no download
                    return jsonify(error="This search was kept before a restart by an older version: run it again."), 409
                allowed, why = gate({"inputs": [{"code": meta["code"], "kind": "c"}], "needs_review": bool(meta.get("needs_review")),
                                     "user": user()})
                if not allowed:
                    return jsonify(error=why, needs_review=True), 409
            name = meta["name"]
        return Response(data, mimetype="application/zip",
                        headers={"Content-Disposition": f'attachment; filename="{name}"', "Content-Length": str(len(data)),
                                 "Cache-Control": "no-store"})

    @app.route("/combinations")
    def combinations_page():
        if not can_export():
            return render_template("denied.html", message="The combination search is for analysts and admins."), 403
        return render_template("combinations.html", max_days=MAX_DAYS)

    book.resolve = resolve
    book.own_job = own                    # acodes.py: an analyst's request made from a finished search
    book.jobs = jobs                      # tests: a service restart is the search gone from memory
    book.package = package                # combo_review.py: the report again, with the views management chose
    book.describe = lambda code: (describe(resolve(code)) if CODE_RX.match(code or "") else
                                  describe(book.get(code)) if ANY_RX.match(code or "") else "")
    book.resolve_any = lambda code: resolve(code) if CODE_RX.match(code or "") else book.get(code) if ANY_RX.match(code or "") else None
    return book
