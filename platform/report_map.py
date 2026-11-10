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

Two roles, so that Shadowserver is asked once, not by every installation:

* The FEED BUILDER (FeedBuilder; run by the maintainer's own deployment, looking-glass-feed-builder): the only thing that contacts
  Shadowserver. Daily it asks their GitHub whether the schema changed (one request) and downloads it only then; it reads
  the report pages that are due (each at most weekly, slowly, conditional requests); it writes feed/report_feed.json in
  the Looking Glass repository, which the deployment commits and pushes when something changed. Shadowserver's
  description text stays in the builder's own state folder unless FEED_INCLUDE_TEXT=1 (their permission first).
* Every INSTALLATION (ReportMap; loop() started by app.py): once a day, after 06:30 GMT (the builder runs at 06:00),
  one conditional request for that file on GitHub; the map is rebuilt locally from its facts with this installation's rules. Every 30 minutes, the report
  collections in the database: one the map does not know is placed from its fields and flagged. An installation never
  contacts Shadowserver. A failed or unreadable feed keeps the last good copy; before the first one, the shipped
  data/report_map_snapshot.json is used.

Files (installation): data/report_map_rules.json and data/report_map_snapshot.json (shipped), data/report_map.json
(the map, its facts, status and events), data/report_map_local.json (administrators' moves),
data/shadowserver_reports.json (what the feed says about each report page).

Command line (from the platform folder):
  .venv/bin/python report_map.py --update [--force] [--arrivals]     pull the feed now (installation) and print a summary
  .venv/bin/python report_map.py --snapshot                          write the shipped snapshot (maintainers)
  python3 report_map.py --build-feed OUT_DIR --state STATE_DIR [--pages N] [--text]   the feed builder
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

REPO = "The-Shadowserver-Foundation/report_schema"
API_COMMIT = f"https://api.github.com/repos/{REPO}/commits/main"
RAW = "https://raw.githubusercontent.com/" + REPO + "/{sha}/{file}"
SS_BASE = "https://www.shadowserver.org/what-we-do/network-reporting/"
FEED_URL = "https://raw.githubusercontent.com/anonghosty/looking-glass/main/feed/report_feed.json"
FEED_FORMAT = 1
UA = "LookingGlass-report-map/1 (+https://github.com/anonghosty/looking-glass)"
SCHEMA_FILES = ("reports.json", "types.md")
MAX_BYTES = 4_000_000                     # a schema file, page or feed larger than this is not what we expect
MIN_REPORTS = 100                         # a schema or feed with fewer report types than this is refused
FEED_READ_AT = (6, 30)                    # installations: the feed once a day, after 06:30 GMT (the builder runs at 06:00)
ARRIVALS_EVERY = 30 * 60
PAGE_EVERY = 7 * 24 * 3600                # the builder: each report page at most weekly
PAGES_PER_RUN = 40
PAGE_DELAY = 3.0                          # seconds between two page requests
EVENTS_KEPT = 300
NO_REPORT = ("files_", "discovered_fields_", "system.")
PLATFORM_COMMS, PLATFORM_SVC, PLATFORM_NONE = "Network communications", "Publicly accessible services", "none yet (no IP address)"
UNPLACED = "Not yet placed: check"
PAGE_FACTS = ("title", "last_updated", "severity", "filenames", "field_names", "hash", "fetched")    # always in the feed
#  (no check times or errors: the feed changes, and is committed, only when what a page says changes)
PAGE_TEXT = ("blocks", "description", "notes", "fields")                                              # only with their OK


def _now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _age(stamp):
    try:
        return (datetime.now(timezone.utc) - datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return float("inf")


def _read(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, data):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=1, ensure_ascii=False, sort_keys=True)
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


def _h(headers, name):
    return next((v for k, v in (headers or {}).items() if k.lower() == name.lower()), "")


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


def check_facts(facts):
    ok = isinstance(facts, dict) and len(facts) >= MIN_REPORTS and \
        sum(1 for f in facts.values() if isinstance(f, dict) and f.get("fields")) >= MIN_REPORTS
    return [] if ok else [f"the facts hold {len(facts) if isinstance(facts, dict) else 0} report types (expected at least {MIN_REPORTS})"]


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
    return {"report": k, "title": a.get("title") or k, "severity": a.get("severity") or "", "url": a.get("url") or "",
            "taxonomy": tax, "type": typ, "classified": how, "platform": platform, "section": section, "group": group,
            "affected": affected, "has_ip": has_ip, "placed_by": placed_by, "in_schema": True}


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


def page_digest(p):
    return hashlib.sha256(json.dumps([p.get("description"), p.get("fields")], sort_keys=True).encode()).hexdigest()


# ------------------------------------------------------------------ the feed builder (the only one asking Shadowserver)

class FeedBuilder:
    """Builds feed/report_feed.json from Shadowserver's schema and report pages. state_dir is private (the downloaded
    schema, every page read, with their text); out_dir is the repository's feed/ folder (published)."""

    def __init__(self, out_dir, state_dir, include_text=False, logger=None):
        self.out, self.state, self.text, self.log = out_dir, state_dir, include_text, logger
        self.p = {"schema": os.path.join(state_dir, "schema"), "pages": os.path.join(state_dir, "pages.json"),
                  "status": os.path.join(state_dir, "status.json"), "feed": os.path.join(out_dir, "report_feed.json")}

    def schema(self, force=False):
        """(facts, commit, note): Shadowserver's schema, downloaded only when their repository moved."""
        st = _read(self.p["status"], {}) or {}
        cached = None
        try:
            rj = _read(os.path.join(self.p["schema"], "reports.json"))
            with open(os.path.join(self.p["schema"], "types.md"), encoding="utf-8") as f:
                types = parse_types_md(f.read())
            if rj and not check_schema(rj, types):
                cached = schema_facts(rj, types)
        except OSError:
            pass
        try:
            _, body, _ = _get(API_COMMIT, {"Accept": "application/vnd.github.sha"})
            sha = body.decode().strip()
            if not re.match(r"^[0-9a-f]{40}$", sha):
                raise ValueError("unexpected answer for the latest commit")
            if cached and sha == st.get("schema_commit") and not force:
                return cached, sha, f"schema unchanged ({sha[:7]})"
            got = {fn: _get(RAW.format(sha=sha, file=fn))[1].decode("utf-8") for fn in SCHEMA_FILES}
            rj, types = json.loads(got["reports.json"]), parse_types_md(got["types.md"])
            probs = check_schema(rj, types)
            if probs:
                raise ValueError("; ".join(probs))
            os.makedirs(self.p["schema"], exist_ok=True)
            for fn, txt in got.items():
                with open(os.path.join(self.p["schema"], fn), "w", encoding="utf-8") as f:
                    f.write(txt)
            _write(self.p["status"], dict(st, schema_commit=sha, schema_updated=_now(), schema_error=""))
            return schema_facts(rj, types), sha, f"schema {sha[:7]} downloaded: {len(rj)} report types"
        except Exception as exc:                                   # noqa: BLE001  (the last good copy is kept)
            _write(self.p["status"], dict(st, schema_error=f"{type(exc).__name__}: {str(exc)[:200]}", schema_failed=_now()))
            if cached:
                return cached, st.get("schema_commit", ""), f"schema check failed, last good copy kept: {exc}"
            raise

    def pages(self, facts, limit=PAGES_PER_RUN, delay=PAGE_DELAY):
        """The report pages that are due (each at most weekly), read slowly with conditional requests."""
        store = _read(self.p["pages"], {}) or {}
        urls = sorted({f["url"] for f in facts.values() if (f.get("url") or "").startswith(SS_BASE)})
        due = sorted((u for u in urls if _age((store.get(u) or {}).get("checked", "")) > PAGE_EVERY),
                     key=lambda u: (store.get(u) or {}).get("checked", ""))
        done = changed = failed = 0
        for u in due[:limit]:
            if done:
                time.sleep(delay)
            done += 1
            p = store.get(u) or {}
            hdr = {"If-Modified-Since": p["last_modified"]} if p.get("last_modified") else {}
            try:
                code, body, h = _get(u, hdr)
                if code == 304:
                    p.update(checked=_now(), error="")
                else:
                    parsed = parse_page(body.decode("utf-8", "replace"))
                    if not parsed:
                        raise ValueError("no description found on the page")
                    digest = page_digest(parsed)
                    if p.get("hash") and p["hash"] != digest:
                        changed += 1
                    p = dict(parsed, hash=digest, last_modified=_h(h, "Last-Modified"),
                             fetched=_now() if p.get("hash") != digest else p.get("fetched", _now()), checked=_now(), error="")
            except Exception as exc:                               # noqa: BLE001  (the last good copy stays; retried in 6 hours)
                failed += 1
                retry = datetime.now(timezone.utc) - timedelta(seconds=PAGE_EVERY - 6 * 3600)
                p.update(checked=retry.strftime("%Y-%m-%dT%H:%M:%SZ"), error=f"{type(exc).__name__}: {str(exc)[:160]}")
            store[u] = p
        _write(self.p["pages"], store)
        return store, f"pages: {done} read of {len(due)} due ({len(urls)} in all), {changed} changed, {failed} failed"

    def build(self, force=False, limit=PAGES_PER_RUN, delay=PAGE_DELAY):
        """Write feed/report_feed.json when something changed. Returns (changed?, summary)."""
        facts, commit, n1 = self.schema(force)
        store, n2 = self.pages(facts, limit, delay)
        keep = PAGE_FACTS + (PAGE_TEXT if self.text else ())
        pages = {u: {k: v for k, v in dict(p, field_names=sorted(p.get("fields") or {})).items() if k in keep}
                 for u, p in sorted(store.items()) if p.get("hash")}
        body = {"format": FEED_FORMAT, "schema_commit": commit, "text_included": bool(self.text), "facts": facts, "pages": pages}
        old = _read(self.p["feed"], {}) or {}
        same = {k: v for k, v in old.items() if k not in ("_about", "built")} == \
               {k: v for k, v in json.loads(json.dumps(body)).items()}
        if same and not force:
            return False, f"{n1}; {n2}; feed unchanged"
        feed = dict(body, built=_now(), _about=(
            "Looking Glass report feed: Shadowserver's report types (from github.com/" + REPO + ") and what each report "
            "page on shadowserver.org says, gathered once by the Looking Glass feed builder so that installations never "
            "need to ask Shadowserver. Source: The Shadowserver Foundation." +
            ("" if self.text else " Description text is not included; each page is linked.")))
        _write(self.p["feed"], feed)
        return True, f"{n1}; {n2}; feed written ({len(facts)} report types, {len(pages)} pages)"


# ------------------------------------------------------------------ an installation's map

class ReportMap:
    def __init__(self, base_dir, collections=None, fields_of=None, logger=None, feed_url=None):
        d = os.path.join(base_dir, "data")
        self.paths = {"rules": os.path.join(d, "report_map_rules.json"), "snapshot": os.path.join(d, "report_map_snapshot.json"),
                      "map": os.path.join(d, "report_map.json"), "local": os.path.join(d, "report_map_local.json"),
                      "pages": os.path.join(d, "shadowserver_reports.json"), "lock": os.path.join(d, ".report_map.lock")}
        self.collections, self.fields_of, self.log = collections, fields_of, logger
        self.feed_url = feed_url or os.environ.get("REPORT_MAP_FEED_URL") or FEED_URL
        self.lock = threading.RLock()
        self._cache = {"mtime": None, "data": None}
        self._rebuilding = False

    # ---- reading
    def rules(self):
        return _read(self.paths["rules"], {}) or {}

    def local(self):
        return _read(self.paths["local"], {}) or {}

    def rules_hash(self):
        try:
            with open(self.paths["rules"], "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()[:16]
        except OSError:
            return ""

    def get(self):
        """The current map: the run-time one, else the shipped snapshot. {reports, facts, status, events}
        A map built with other rules (an update shipped new ones) is rebuilt first, quietly: our own regrouping is not
        news from Shadowserver."""
        cur = self._get()
        if not self._rebuilding and os.path.exists(self.paths["map"]) and cur.get("reports") and \
                (cur.get("status") or {}).get("rules_hash") != self.rules_hash() and self.lock.acquire(blocking=False):
            # (a map from before rules were recorded has none: rebuilt once too)
            self._rebuilding = True
            try:
                self.rebuild(quiet=True, note="rebuilt with updated rules")
            finally:
                self._rebuilding = False
                self.lock.release()
            cur = self._get()
        return cur

    def _get(self):
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
        return {"reports": {}, "facts": {}, "status": {"source": "none"}, "events": []}

    def entry(self, name):
        return self.get()["reports"].get(name)

    def descriptions(self):
        return _read(self.paths["pages"], {}) or {}

    def description(self, name):
        e = self.entry(name) or {}
        return (self.descriptions().get("pages") or {}).get(e.get("url") or "")

    # ---- writing
    def _facts(self):
        cur = self._get()
        if cur.get("facts"):
            return cur["facts"], (cur.get("status") or {}).get("schema_commit", "")
        snap = _read(self.paths["snapshot"], {}) or {}
        return snap.get("facts") or {}, (snap.get("status") or {}).get("schema_commit", "")

    def _save(self, data):
        data = dict(data)
        data["status"] = {k: v for k, v in (data.get("status") or {}).items() if k != "source"}
        _write(self.paths["map"], data)
        self._cache = {"mtime": None, "data": None}

    def rebuild(self, facts=None, commit=None, note=None, events=None, quiet=False):
        """Build the map from the facts with the current rules and the administrators' moves; record what changed
        (not when quiet: a rebuild for new rules of our own)."""
        with self.lock:
            if facts is None:
                facts, commit = self._facts()
            cur = self._get()
            extra = {k: v for k, v in (cur.get("facts_db") or {}).items() if k not in facts}   # seen only in the database
            reports = build({**facts, **extra}, self.rules(), self.local())
            for k in extra:
                reports[k].update(in_schema=False, flag="not in Shadowserver's schema: placed from its fields")
            when = _now()
            ev = (events or []) + (diff(cur.get("reports") or {}, reports, when) if cur.get("reports") and not quiet else [])
            status = dict(cur.get("status") or {}, schema_commit=commit or (cur.get("status") or {}).get("schema_commit", ""),
                          built=when, reports=len(reports), rules_hash=self.rules_hash())
            if note:
                status["note"] = note
            self._save({"status": status, "reports": reports, "facts": facts, "facts_db": extra,
                        "events": (ev + (cur.get("events") or []))[:EVENTS_KEPT]})
            return ev

    def _status(self, **kw):
        with self.lock:
            if not os.path.exists(self.paths["map"]):
                self.rebuild()
            cur = self.get()
            self._save(dict(cur, status=dict(cur.get("status") or {}, **kw)))

    def update_feed(self, force=False):
        """Once a day: the feed on GitHub (one conditional request). The map is rebuilt from its facts; what it says
        about each report page is kept for the cards. A feed that cannot be read keeps the last good copy."""
        st = self.get().get("status") or {}
        now = datetime.now(timezone.utc)
        mark = now.replace(hour=FEED_READ_AT[0], minute=FEED_READ_AT[1], second=0, microsecond=0)
        if mark > now:
            mark -= timedelta(days=1)                  # the latest 06:30 GMT that has passed
        if not force and _age(st.get("feed_checked", "")) < (now - mark).total_seconds():
            return "feed already read since the last 06:30 GMT"
        try:
            hdr = {"If-None-Match": st["feed_etag"]} if st.get("feed_etag") and not force else {}
            code, body, h = _get(self.feed_url, hdr)
            if code == 304:
                self._status(feed_checked=_now(), feed_error="")
                return "feed unchanged"
            feed = json.loads(body.decode("utf-8"))
            if not isinstance(feed, dict) or feed.get("format") != FEED_FORMAT:
                raise ValueError(f"feed format {feed.get('format') if isinstance(feed, dict) else '?'} (this installation reads {FEED_FORMAT})")
            probs = check_facts(feed.get("facts"))
            if probs:
                raise ValueError("; ".join(probs))
            events = self._take_pages(feed.get("pages") or {}, bool(feed.get("text_included")))
            if feed.get("schema_commit") != st.get("schema_commit") or force or events or not os.path.exists(self.paths["map"]):
                self.rebuild(feed["facts"], feed.get("schema_commit", ""), events=events)
            self._status(feed_checked=_now(), feed_error="", feed_etag=_h(h, "ETag"), feed_built=feed.get("built", ""))
            return f"feed {str(feed.get('schema_commit', ''))[:7]} (built {feed.get('built', '?')}): {len(feed['facts'])} report types, {len(events)} change(s)"
        except Exception as exc:                                   # noqa: BLE001  (keep the last good copy)
            self._status(feed_checked=_now(), feed_error=f"{type(exc).__name__}: {str(exc)[:200]}")
            if self.log:
                self.log.warning("Report map: feed not read, last good copy kept: %s", exc)
            return f"feed not read, last good copy kept: {exc}"

    def _take_pages(self, pages, text):
        """Keep what the feed says about each report page; a changed description becomes an event."""
        store = self.descriptions()
        old = store.get("pages") or {}
        ev = [{"at": _now(), "kind": "description_changed", "url": u, "title": p.get("title", ""),
               "text": f"Shadowserver updated the description of {p.get('title') or u}."}
              for u, p in pages.items() if (old.get(u) or {}).get("hash") and p.get("hash") and old[u]["hash"] != p["hash"]]
        _write(self.paths["pages"], {"pages": pages, "text_included": text, "updated": _now()})
        return ev

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
            self._save(dict(cur, facts_db={**(cur.get("facts_db") or {}), **new}))
        ev = self.rebuild(note="placed report collections found only in the database")
        return f"{len(new)} report collection(s) not in the schema, placed and flagged: {', '.join(sorted(new))} ({len(ev)} event(s))"

    def snapshot(self):
        """The shipped snapshot: the map and the schema facts it was built from (no description text)."""
        facts, commit = self._facts()
        reports = build(facts, self.rules())
        _write(self.paths["snapshot"], {
            "_about": "Shipped with Looking Glass: where each Shadowserver report type belongs (report_map.py), and the "
                      "facts from Shadowserver's report_schema it was built from. Replaced on each installation by "
                      "data/report_map.json once the daily feed has been read.",
            "status": {"schema_commit": commit, "built": _now(), "reports": len(reports)},
            "facts": facts, "reports": reports, "events": []})
        return f"snapshot: {len(reports)} report types, schema {commit[:7]}"

    # ---- background
    def loop(self):
        """Started by app.py when it serves: the feed once a day, the database every 30 minutes."""
        import fcntl
        time.sleep(150)
        while True:
            try:
                with open(self.paths["lock"], "w") as lf:
                    try:
                        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except OSError:
                        lf = None
                    if lf:
                        if os.environ.get("REPORT_MAP_FETCH", "1") != "0":
                            self.update_feed()
                        self.check_arrivals()
            except Exception as exc:                               # never let the background job stop the platform
                if self.log:
                    self.log.warning("Report map: %s", exc)
            time.sleep(ARRIVALS_EVERY)


def _cli():
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Where each Shadowserver report type belongs (report_map.py).")
    ap.add_argument("--update", action="store_true", help="installation: read the feed now")
    ap.add_argument("--force", action="store_true", help="read / build even if nothing seems changed")
    ap.add_argument("--arrivals", action="store_true", help="installation: also check the database for unknown report collections")
    ap.add_argument("--snapshot", action="store_true", help="write data/report_map_snapshot.json (maintainers, before a release)")
    ap.add_argument("--build-feed", metavar="OUT_DIR", help="feed builder: write OUT_DIR/report_feed.json")
    ap.add_argument("--state", metavar="STATE_DIR", help="feed builder: private state folder (schema, pages with their text)")
    ap.add_argument("--pages", type=int, default=PAGES_PER_RUN, help="feed builder: at most this many report pages per run")
    ap.add_argument("--text", action="store_true", help="feed builder: include Shadowserver's description text (only with their OK)")
    a = ap.parse_args()
    if a.build_feed:
        if not a.state:
            ap.error("--build-feed needs --state")
        changed, summary = FeedBuilder(a.build_feed, a.state, include_text=a.text or os.environ.get("FEED_INCLUDE_TEXT") == "1").build(
            force=a.force, limit=a.pages)
        print(summary)
        sys.exit(0 if changed else 3)                              # 3: nothing to commit
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
        print(rm.update_feed(force=a.force))
    if a.arrivals:
        print(rm.check_arrivals())
    if a.snapshot:
        print(rm.snapshot())
    m = rm.get()
    st = m.get("status") or {}
    counts = {}
    for e in (m.get("reports") or {}).values():
        counts[(e["section"], e["group"])] = counts.get((e["section"], e["group"]), 0) + 1
    print(f"map: {len(m.get('reports') or {})} report types · source: {st.get('source')} · schema {str(st.get('schema_commit', ''))[:7]}"
          f" · feed checked {st.get('feed_checked', '–')}{' · error: ' + st['feed_error'] if st.get('feed_error') else ''}")
    for (s, g), n in sorted(counts.items(), key=lambda x: (str(x[0][0]), str(x[0][1]))):
        print(f"  {s:14s} {g or '':74s} {n:>4}")
    for e in (m.get("events") or [])[:8]:
        print("  event:", e["at"], e["text"])
    sys.exit(0)


if __name__ == "__main__":
    _cli()
