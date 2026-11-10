"""Report map: where every Shadowserver report type belongs, kept up to date from Shadowserver's own schema.

Shadowserver publishes its report types in https://github.com/The-Shadowserver-Foundation/report_schema:
reports.json (for each type its classification, taxonomy / type from the CSIRT incident scheme, and its fields) and
types.md (title, current default severity, and the page on shadowserver.org that describes it). From those this module
works out, for every report type:

* the platform, by the shape of its records (the platforms' own rule): any source or destination field -> Network
  communications; one ip -> Publicly accessible services; no IP address -> none yet (e-mail accounts, victims);
* the researchers' section, by meaning: Infections, Attacks seen, Services or Intelligence, and a group inside the last
  two (data/report_map_rules.json: our own choices, applied after the classification; an administrator's moves in
  data/report_map_local.json win over both);
* the affected thing: a host, an e-mail account, an organisation, a URL.

Kept current (loop(), started by app.py when it serves):
* daily, one request for the schema repository's latest commit; only when it moved are the files downloaded, checked
  and the map rebuilt; a new report type is placed by the rules at once and flagged ("check its place"), a changed one
  (section, group, severity, title) is noted;
* every 30 minutes, the report collections in the database: one the map does not know is placed from its fields and
  flagged, so nothing that arrives stays invisible;
* each report's page on shadowserver.org (its description, last-updated date and field meanings), at most weekly per
  page, slowly, with conditional requests; a changed description is noted.
A failed or unreadable download keeps the last good copy. A fresh installation uses data/report_map_snapshot.json
(shipped: the map and the schema facts it was built from, no description text) until the first update.

Files: data/report_map_rules.json (shipped, curated), data/report_map_snapshot.json (shipped), data/report_map.json
(run time: the map, its status and the events), data/report_map_local.json (run time: administrators' moves),
data/report_schema/ (run time: the downloaded schema), data/shadowserver_reports.json (run time: the descriptions).

Command line (from the platform folder):
  .venv/bin/python report_map.py --update [--force] [--descriptions N] [--arrivals]   check now and print a summary
  .venv/bin/python report_map.py --snapshot                                        write the shipped snapshot
"""
import hashlib
import html as _html
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from email.utils import formatdate, parsedate_to_datetime

REPO = "The-Shadowserver-Foundation/report_schema"
API_COMMIT = f"https://api.github.com/repos/{REPO}/commits/main"
RAW = "https://raw.githubusercontent.com/" + REPO + "/{sha}/{file}"
SS_BASE = "https://www.shadowserver.org/what-we-do/network-reporting/"
UA = "LookingGlass-report-map/1 (+https://github.com/anonghosty/looking-glass)"
SCHEMA_FILES = ("reports.json", "types.md")
MAX_BYTES = 4_000_000                     # a schema file or page larger than this is not what we expect
MIN_REPORTS = 100                         # a reports.json with fewer types than this is refused
SCHEMA_EVERY = 24 * 3600
ARRIVALS_EVERY = 30 * 60
PAGE_EVERY = 7 * 24 * 3600                # each report page at most weekly
PAGES_PER_RUN = 30
PAGE_DELAY = 3.0                          # seconds between two page requests
EVENTS_KEPT = 300
NO_REPORT = ("files_", "discovered_fields_", "system.")
PLATFORM_COMMS, PLATFORM_SVC, PLATFORM_NONE = "Network communications", "Publicly accessible services", "none yet (no IP address)"
UNPLACED = "Not yet placed: check"


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False)
    os.replace(tmp, path)


def _get(url, headers=None, timeout=25):
    """(status, body bytes, response headers); 304 gives an empty body. Raises on network errors."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise ValueError(f"{url}: larger than {MAX_BYTES} bytes")
            return r.status, body, dict(r.headers)
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, b"", dict(e.headers or {})
        raise


# ------------------------------------------------------------------ the schema files

def parse_types_md(text):
    """types.md -> {report: {title, url, severity}}"""
    out = {}
    for ln in text.splitlines():
        m = re.match(r"\|\s*([a-z0-9_]+)\s*\|\s*\[([^\]]+)\]\(([^)\s]+)\)\s*\|\s*(\w+)\s*\|", ln.strip())
        if m:
            k, title, url, sev = m.groups()
            out[k] = {"title": title.strip(), "url": url.strip(), "severity": sev.strip().lower()}
    return out


def schema_facts(reports_json, types):
    """The facts the map is built from, per report: classification, fields, name, page; title and severity."""
    out = {}
    for k, r in reports_json.items():
        if not isinstance(r, dict) or not re.match(r"^[a-z0-9_]+$", k):
            continue
        t = types.get(k, {})
        out[k] = {"taxonomy": r.get("classification.taxonomy"), "type": r.get("classification.type"),
                  "fields": sorted(str(f) for f in r.get("fields") or []), "name": r.get("name") or "",
                  "url": t.get("url") or r.get("url") or "", "title": t.get("title") or r.get("name") or k,
                  "severity": t.get("severity") or ""}
    for k, t in types.items():                    # listed in types.md only: no fields known yet
        out.setdefault(k, {"taxonomy": None, "type": None, "fields": [], "name": "", "url": t["url"],
                           "title": t["title"], "severity": t["severity"]})
    return out


def check_schema(reports_json, types):
    """Problems that make a download unusable (the last good copy is kept)."""
    probs = []
    if not isinstance(reports_json, dict) or len(reports_json) < MIN_REPORTS:
        probs.append(f"reports.json has {len(reports_json) if isinstance(reports_json, dict) else 0} report types (expected at least {MIN_REPORTS})")
    elif sum(1 for r in reports_json.values() if isinstance(r, dict) and r.get("fields")) < MIN_REPORTS:
        probs.append("reports.json: too few report types with a field list")
    if len(types) < MIN_REPORTS:
        probs.append(f"types.md has {len(types)} report types (expected at least {MIN_REPORTS})")
    return probs


# ------------------------------------------------------------------ the placement logic

def sibling(k):
    """The IPv4 report an IPv6 one mirrors (scan6_rdp -> scan_rdp), or the name itself."""
    s = re.sub(r"^(scan|population)6_", r"\1_", k)
    s = re.sub(r"^event6_", "event4_", s).replace("device_id6", "device_id")
    return re.sub(r"^(compromised_\w+?|targeted_host)6$", r"\1", s)


def _shape(fields):
    f = set(fields)
    pair = any(x.startswith(("src_", "dst_")) for x in f) or "http_referer_ip" in f
    has_ip = "ip" in f or pair
    return pair, has_ip


def classify(k, facts):
    """(taxonomy, type, how): the report's own classification, else its IPv4 sibling's, else from its name."""
    a = facts.get(k) or {}
    if a.get("taxonomy"):
        return a["taxonomy"], a.get("type"), "schema"
    s = sibling(k)
    if s != k and (facts.get(s) or {}).get("taxonomy"):
        return facts[s]["taxonomy"], facts[s].get("type"), f"from {s}"
    if re.search(r"sinkhole", k):
        return "malicious-code", "infected-system", "name (sinkhole)"
    if re.search(r"vulnerable|exchange", k):
        return "vulnerable", "vulnerable-system", "name (vulnerable)"
    return None, None, "unclassified"


def place(k, facts, rules, local=None):
    """One report's entry in the map."""
    a = facts.get(k) or {}
    fields = a.get("fields") or []
    tax, typ, how = classify(k, facts)
    pair, has_ip = _shape(fields)
    platform = PLATFORM_COMMS if pair else PLATFORM_SVC if has_ip else PLATFORM_NONE
    f = set(fields)
    affected = ("host (source of the traffic)" if pair and "http_referer_ip" not in f
                else "website linking to a sinkholed domain" if "http_referer_ip" in f
                else "e-mail account" if "email" in f
                else "organisation / website" if "entity_name" in f
                else "host" if has_ip else "malware sample" if f & {"md5", "sha256"} else "unknown")
    section, group = None, ""
    intel = {(t, y): g for t, y, g in rules.get("intelligence_by_class", [])}
    if pair:
        section = "Infections" if (tax == "malicious-code" or re.search(r"sinkhole", k)) else "Attacks seen"
    elif (tax, typ) in intel:
        section, group = "Intelligence", intel[(tax, typ)]
    elif tax in ("intrusions", "information-content-security", "abusive-content", "malicious-code", "fraud"):
        section, group = "Intelligence", UNPLACED
    elif tax and any(t == tax and y in ("*", typ) for t, y in rules.get("services_by_class", [])):
        section = "Services"
    elif not tax and re.match(r"^(scan6?|population6?|device_id)", k):
        section = "Services"
    elif not tax:
        section, group = ("Intelligence" if not has_ip else "Services"), (UNPLACED if not has_ip else "")
    else:
        section, group = "Intelligence", UNPLACED
    if section == "Services" and not group:
        base = sibling(k)
        group = next((g["group"] for g in rules.get("service_groups", []) if re.search(g["pattern"], base)),
                     rules.get("service_default_group", "Services"))
    placed_by = "rules"
    for src, ov in (("ours", (rules.get("overrides") or {}).get(k) or (rules.get("overrides") or {}).get(sibling(k))),
                    ("administrator", ((local or {}).get("overrides") or {}).get(k))):
        if ov:
            section, group, placed_by = ov.get("section", section), ov.get("group", group), src
    url = a.get("url") or ""
    return {"report": k, "title": a.get("title") or k, "severity": a.get("severity") or "", "url": url,
            "taxonomy": tax, "type": typ, "classified": how, "platform": platform, "section": section, "group": group,
            "affected": affected, "has_ip": has_ip, "placed_by": placed_by,
            "in_schema": bool(a.get("fields") or a.get("taxonomy") or a.get("title") != k)}


def build(facts, rules, local=None):
    return {k: place(k, facts, rules, local) for k in sorted(facts)}


def diff(old, new, when):
    """Events between two maps: a report type that is new, and one whose place or rating changed."""
    ev = []
    for k, e in new.items():
        o = old.get(k)
        if o is None:
            ev.append({"at": when, "kind": "new_report", "report": k, "title": e["title"],
                       "text": f"New report type: {e['title']} ({k}), placed in {e['section']}"
                               + (f" → {e['group']}" if e["group"] else "") + ". Check its place."})
            continue
        ch = [f"{lbl} {o.get(f) or '–'} → {e.get(f) or '–'}" for f, lbl in
              (("section", "section"), ("group", "group"), ("severity", "severity"), ("title", "title"), ("platform", "platform"))
              if (o.get(f) or "") != (e.get(f) or "")]
        if ch:
            ev.append({"at": when, "kind": "changed", "report": k, "title": e["title"],
                       "text": f"{e['title']} ({k}): " + "; ".join(ch) + "."})
    return ev


# ------------------------------------------------------------------ report pages (descriptions)

def _text(fragment):
    s = re.sub(r"<br\s*/?>", "\n", fragment)
    s = _html.unescape(re.sub(r"<[^>]+>", "", s))
    return re.sub(r"[ \t\r\f\v ]+", " ", s).strip()


# standard lines at the end of most pages: kept apart from the description proper ("notes")
PAGE_NOTES = re.compile(r"(?i)^(severity levels are described|for more information on our scanning|you can (also )?(track|view)|"
                        r"this report (has|now comes in) (an )?ipv4|as of \d{4}-\d{2}-\d{2}, this report now comes|"
                        r"this report was (enabled|released) as part of|this report is released as part of|"
                        r"you can learn more (on|about) (the|our) report)")
BLOCK_RX = re.compile(r"<(p|li|h[2-5])[^>]*>(.*?)</\1>", re.S)


def parse_page(page):
    """A report page on shadowserver.org -> {title, blocks[{kind: h|p|li, text}], description[], notes[],
    last_updated, severity, filenames, fields{}}. The content block under the title, before the Fields list."""
    h1 = re.search(r"<h1[^>]*>(.*?)</h1>", page, re.S)
    start = page.find('<div class="content">', h1.end() if h1 else 0)
    end = page.find('<div class="fields-list">', start)
    if start < 0:
        return None
    block = page[start:end if end > start else start + 60000]
    out = {"title": re.sub(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO):\s*", "", _text(h1.group(1))) if h1 else "",
           "blocks": [], "description": [], "notes": [], "last_updated": "", "severity": "", "filenames": [], "fields": {}}
    for tag, inner in BLOCK_RX.findall(block):
        if tag == "p" and re.search(r"<(ul|ol)\b", inner):
            inner = re.sub(r"<(ul|ol)\b.*", "", inner, flags=re.S)      # the list's items come as their own blocks
        t = _text(inner)
        if not t:
            continue
        m = re.match(r"(?i)description last updated:\s*(\d{4}-\d{2}-\d{2})", t)
        if m:
            out["last_updated"] = m.group(1); continue
        m = re.match(r"(?i)default (severity|security) level:\s*(\w+)", t)
        if m:
            out["severity"] = m.group(2).lower(); continue
        m = re.match(r"(?i)filename(?:\(s\)|s)?(?: prefix(?:es)?)?:\s*(.+?)\.?$", t)
        if m:
            out["filenames"] = [x.strip() for x in re.split(r"[,\s]+", m.group(1)) if re.match(r"^[a-z0-9_]+$", x.strip())]; continue
        kind = "h" if tag.startswith("h") or (tag == "p" and re.fullmatch(r"<(strong|b)>[^<]{2,60}</\1>", inner.strip())
                                            and len(t) < 60 and not t.endswith(".")) else ("li" if tag == "li" else "p")
        if kind != "h" and PAGE_NOTES.match(t):
            if t not in out["notes"]:
                out["notes"].append(t[:400])
            continue
        if out["blocks"] and out["blocks"][-1]["text"] == t:
            continue                                                      # the same line twice in a row on the page
        out["blocks"].append({"kind": kind, "text": t[:2000]})
        if kind != "h":
            out["description"].append(("• " if kind == "li" else "") + t[:2000])
    # a heading left with nothing under it (its only line was a standard note) goes
    out["blocks"] = [b for i, b in enumerate(out["blocks"])
                     if b["kind"] != "h" or (i + 1 < len(out["blocks"]) and out["blocks"][i + 1]["kind"] != "h")]
    if end > start:
        flist = page[end:end + 200000]
        stop = re.search(r'<div class="(sample|c--sample)|<h2>\s*Sample', flist)
        flist = flist[:stop.start()] if stop else flist
        for name, desc in re.findall(r'<div class="name">(.*?)</div>\s*<div class="description">(.*?)</div>', flist, re.S):
            n = _text(name)
            if n and re.match(r"^[A-Za-z0-9_.\-]+$", n):
                out["fields"][n] = _text(desc)[:600]
    return out if (out["description"] or out["fields"]) else None


# ------------------------------------------------------------------ the map, kept up to date

class ReportMap:
    def __init__(self, base_dir, collections=None, fields_of=None, logger=None):
        d = os.path.join(base_dir, "data")
        self.paths = {"rules": os.path.join(d, "report_map_rules.json"), "snapshot": os.path.join(d, "report_map_snapshot.json"),
                      "map": os.path.join(d, "report_map.json"), "local": os.path.join(d, "report_map_local.json"),
                      "schema": os.path.join(d, "report_schema"), "pages": os.path.join(d, "shadowserver_reports.json"),
                      "lock": os.path.join(d, ".report_map.lock")}
        self.collections, self.fields_of, self.log = collections, fields_of, logger
        self.lock = threading.RLock()
        self._cache = {"mtime": None, "data": None}

    # ---- reading
    def rules(self):
        return _read(self.paths["rules"], {}) or {}

    def local(self):
        return _read(self.paths["local"], {}) or {}

    def get(self):
        """The current map: the run-time one, else the shipped snapshot. {reports, status, events}"""
        for key in ("map", "snapshot"):
            p = self.paths[key]
            try:
                m = (p, os.path.getmtime(p))
            except OSError:
                continue
            if self._cache["mtime"] != m:
                d = _read(p)
                if not d or not d.get("reports"):
                    continue
                d.setdefault("status", {}); d.setdefault("events", [])
                d["status"]["source"] = "updated here" if key == "map" else "shipped snapshot"
                self._cache = {"mtime": m, "data": d}
            return self._cache["data"]
        return {"reports": {}, "status": {"source": "none"}, "events": []}

    def entry(self, name):
        return self.get()["reports"].get(name)

    def descriptions(self):
        return _read(self.paths["pages"], {}) or {}

    def description(self, name):
        e = self.entry(name) or {}
        return (self.descriptions().get("pages") or {}).get(e.get("url") or "")

    # ---- writing
    def _base(self):
        """The facts to build from: the downloaded schema, else the snapshot's."""
        raw = {f: os.path.join(self.paths["schema"], f) for f in SCHEMA_FILES}
        try:
            rj = _read(raw["reports.json"])
            with open(raw["types.md"], encoding="utf-8") as f:
                types = parse_types_md(f.read())
            if rj and not check_schema(rj, types):
                return schema_facts(rj, types), _read(os.path.join(self.paths["schema"], "commit.json"), {}).get("sha", "")
        except OSError:
            pass
        snap = _read(self.paths["snapshot"], {}) or {}
        return snap.get("facts") or {}, (snap.get("status") or {}).get("schema_commit", "")

    def rebuild(self, facts=None, commit=None, note=None):
        """Build the map from the facts with the current rules and the administrators' moves; record what changed."""
        with self.lock:
            if facts is None:
                facts, commit = self._base()
            cur = self.get()
            extra = {k: v for k, v in (cur.get("facts_db") or {}).items() if k not in facts}   # seen only in the database
            reports = build({**facts, **extra}, self.rules(), self.local())
            for k in extra:
                reports[k]["in_schema"] = False
                reports[k]["flag"] = "not in Shadowserver's schema: placed from its fields"
            when = _now()
            ev = diff(cur.get("reports") or {}, reports, when) if cur.get("reports") else []
            status = dict(cur.get("status") or {}, schema_commit=commit or (cur.get("status") or {}).get("schema_commit", ""),
                          built=when, reports=len(reports))
            status.pop("source", None)
            if note:
                status["note"] = note
            data = {"status": status, "reports": reports, "facts_db": extra,
                    "events": (ev + (cur.get("events") or []))[:EVENTS_KEPT]}
            _write(self.paths["map"], data)
            self._cache = {"mtime": None, "data": None}
            return ev

    def update_schema(self, force=False):
        """Daily: has Shadowserver's schema changed? If so, download, check and rebuild. Returns a short summary."""
        cur = self.get()
        st = cur.get("status") or {}
        if not force and st.get("schema_checked") and \
                datetime.now(timezone.utc) - datetime.fromisoformat(st["schema_checked"].replace("Z", "+00:00")) < timedelta(seconds=SCHEMA_EVERY):
            return "schema checked recently"
        try:
            _, body, _ = _get(API_COMMIT, {"Accept": "application/vnd.github.sha"})
            sha = body.decode().strip()
            if not re.match(r"^[0-9a-f]{40}$", sha):
                raise ValueError("unexpected answer for the latest commit")
            if sha == st.get("schema_commit") and not force:
                self._status(schema_checked=_now(), schema_error="")
                return f"schema unchanged ({sha[:7]})"
            got = {}
            for fn in SCHEMA_FILES:
                _, b, _ = _get(RAW.format(sha=sha, file=fn))
                got[fn] = b.decode("utf-8")
            rj, types = json.loads(got["reports.json"]), parse_types_md(got["types.md"])
            probs = check_schema(rj, types)
            if probs:
                raise ValueError("; ".join(probs))
            os.makedirs(self.paths["schema"], exist_ok=True)
            for fn, txt in got.items():
                with open(os.path.join(self.paths["schema"], fn), "w", encoding="utf-8") as f:
                    f.write(txt)
            _write(os.path.join(self.paths["schema"], "commit.json"), {"sha": sha, "downloaded": _now()})
            ev = self.rebuild(schema_facts(rj, types), sha)
            self._status(schema_checked=_now(), schema_error="", schema_updated=_now())
            return f"schema {sha[:7]}: {len(rj)} report types, {len(ev)} change(s)"
        except Exception as exc:                                   # noqa: BLE001  (keep the last good copy)
            self._status(schema_checked=_now(), schema_error=f"{type(exc).__name__}: {str(exc)[:200]}")
            if self.log:
                self.log.warning("Report map: schema update failed, last good copy kept: %s", exc)
            return f"schema update failed, last good copy kept: {exc}"

    def check_arrivals(self):
        """The report collections in the database that the map does not know: placed from their fields and flagged."""
        if not self.collections:
            return "no database"
        known = self.get().get("reports") or {}
        new = {}
        for n in self.collections():
            if n.startswith(NO_REPORT) or n in known or not re.match(r"^[a-z0-9_]+$", n):
                continue
            fields = sorted(self.fields_of(n)) if self.fields_of else []
            new[n] = {"taxonomy": None, "type": None, "fields": [f for f in fields if f != "_id"], "name": "",
                      "url": "", "title": n, "severity": ""}
        if not new:
            return "every report collection is in the map"
        with self.lock:
            cur = self.get()
            data = dict(cur)
            data["facts_db"] = {**(cur.get("facts_db") or {}), **new}
            _write(self.paths["map"], {k: v for k, v in data.items()})
            self._cache = {"mtime": None, "data": None}
        ev = self.rebuild(note="placed report collections found only in the database")
        return f"{len(new)} report collection(s) not in the schema, placed and flagged: {', '.join(sorted(new))} ({len(ev)} event(s))"

    def update_pages(self, limit=PAGES_PER_RUN, delay=PAGE_DELAY):
        """Each report's page, at most weekly: description, last-updated date, field meanings. Conditional requests."""
        store = self.descriptions()
        pages = store.setdefault("pages", {})
        urls = sorted({e["url"] for e in (self.get().get("reports") or {}).values()
                       if (e.get("url") or "").startswith(SS_BASE)})
        due = [u for u in urls if time.time() - (pages.get(u) or {}).get("checked_ts", 0) > PAGE_EVERY]
        done, changed, failed, events = 0, 0, 0, []
        for u in due[:limit]:
            if done:
                time.sleep(delay)
            done += 1
            p = pages.get(u) or {}
            hdr = {"If-Modified-Since": p["last_modified"]} if p.get("last_modified") else {}
            try:
                code, body, h = _get(u, hdr)
                if code == 304:
                    p.update(checked_ts=time.time(), checked=_now(), error="")
                    pages[u] = p
                    continue
                parsed = parse_page(body.decode("utf-8", "replace"))
                if not parsed:
                    raise ValueError("no description found on the page")
                digest = hashlib.sha256(json.dumps([parsed["description"], parsed["fields"]], sort_keys=True).encode()).hexdigest()
                if p.get("hash") and p["hash"] != digest:
                    changed += 1
                    events.append({"at": _now(), "kind": "description_changed", "url": u, "title": parsed["title"],
                                   "text": f"Shadowserver updated the description of {parsed['title'] or u}."})
                pages[u] = dict(parsed, url=u, hash=digest, last_modified=h.get("Last-Modified") or h.get("last-modified") or "",
                                fetched=_now(), checked=_now(), checked_ts=time.time(), error="",
                                source="Shadowserver Foundation, " + u)
            except Exception as exc:                               # noqa: BLE001  (the last good copy stays)
                failed += 1
                p.update(checked_ts=time.time() - PAGE_EVERY + 6 * 3600, error=f"{type(exc).__name__}: {str(exc)[:160]}")
                pages[u] = p
        store["updated"] = _now()
        with self.lock:
            _write(self.paths["pages"], store)
            if events:
                cur = self.get()
                _write(self.paths["map"], dict(cur, events=(events + (cur.get("events") or []))[:EVENTS_KEPT]))
                self._cache = {"mtime": None, "data": None}
        return f"pages: {done} checked of {len(due)} due ({len(urls)} in all), {changed} changed, {failed} failed"

    def _status(self, **kw):
        with self.lock:
            cur = self.get()
            if cur.get("status", {}).get("source") == "shipped snapshot" and not os.path.exists(self.paths["map"]):
                self.rebuild()
                cur = self.get()
            st = dict(cur.get("status") or {}, **kw)
            st.pop("source", None)
            _write(self.paths["map"], dict(cur, status=st))
            self._cache = {"mtime": None, "data": None}

    def snapshot(self):
        """The shipped snapshot: the current map and the schema facts it was built from (no description text)."""
        facts, commit = self._base()
        reports = build(facts, self.rules())
        snap = {"_about": "Shipped with Looking Glass: where each Shadowserver report type belongs (report_map.py), and the "
                          "facts from Shadowserver's report_schema it was built from. Replaced on each installation by "
                          "data/report_map.json once the daily update has run.",
                "status": {"schema_commit": commit, "built": _now(), "reports": len(reports)},
                "facts": facts, "reports": reports, "events": []}
        _write(self.paths["snapshot"], snap)
        return f"snapshot: {len(reports)} report types, schema {commit[:7]}"

    # ---- background
    def loop(self):
        """Started by app.py when it serves: schema daily, arrivals every 30 minutes, pages a few at a time."""
        import fcntl
        time.sleep(150)
        while True:
            try:
                with open(self.paths["lock"], "w") as lf:
                    try:
                        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError:
                        lf = None
                    if lf and os.environ.get("REPORT_MAP_FETCH", "1") != "0":
                        self.update_schema()
                        self.check_arrivals()
                        self.update_pages()
                    elif lf:
                        self.check_arrivals()
            except Exception as exc:                               # never let the background job stop the platform
                if self.log:
                    self.log.warning("Report map: %s", exc)
            time.sleep(ARRIVALS_EVERY)


def _cli():
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Where each Shadowserver report type belongs (report_map.py).")
    ap.add_argument("--update", action="store_true", help="check Shadowserver's schema now")
    ap.add_argument("--force", action="store_true", help="download and rebuild even if the schema did not change")
    ap.add_argument("--descriptions", type=int, default=0, metavar="N", help="also check up to N report pages")
    ap.add_argument("--arrivals", action="store_true", help="also check the database for report collections the map does not know")
    ap.add_argument("--snapshot", action="store_true", help="write data/report_map_snapshot.json (maintainers, before a release)")
    a = ap.parse_args()
    base = os.path.dirname(os.path.abspath(__file__))
    cols = fields = None
    if a.arrivals:
        from dotenv import dotenv_values
        from pymongo import MongoClient
        env = dotenv_values(os.path.join(base, ".env"))
        db = MongoClient(host=env.get("MONGO_HOST", "127.0.0.1"), port=int(env.get("MONGO_PORT", 27017)), username=env.get("MONGO_USER"),
                         password=env.get("MONGO_PASSWORD"), authSource=env.get("MONGO_AUTH_SOURCE", "admin"),
                         serverSelectionTimeoutMS=8000)[env.get("MONGO_DB", "shadowserver")]
        cols = db.list_collection_names
        fields = lambda n: list((db[n].find_one(sort=[("_id", -1)]) or {}).keys())
    rm = ReportMap(base, cols, fields)
    if a.update:
        print(rm.update_schema(force=a.force))
    if a.arrivals:
        print(rm.check_arrivals())
    if a.descriptions:
        print(rm.update_pages(limit=a.descriptions))
    if a.snapshot:
        print(rm.snapshot())
    m = rm.get()
    st = m.get("status") or {}
    counts = {}
    for e in (m.get("reports") or {}).values():
        counts[(e["section"], e["group"])] = counts.get((e["section"], e["group"]), 0) + 1
    print(f"map: {len(m.get('reports') or {})} report types · source: {st.get('source')} · schema {str(st.get('schema_commit', ''))[:7]}"
          f" · checked {st.get('schema_checked', '–')}{' · error: ' + st['schema_error'] if st.get('schema_error') else ''}")
    for (s, g), n in sorted(counts.items(), key=lambda x: (str(x[0][0]), str(x[0][1]))):
        print(f"  {s:14s} {g or '':74s} {n:>4}")
    for e in (m.get("events") or [])[:10]:
        print("  event:", e["at"], e["text"])
    sys.exit(0)


if __name__ == "__main__":
    _cli()
