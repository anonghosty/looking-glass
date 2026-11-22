#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The report map (report_map.py) beyond tests/check_report_map.py: its command line, the background loop, the shipped
snapshot, downloads that are too big or refused, and the feed builder's failure paths. Offline: every request is
answered here with made-up report types (sample_*), and every file goes to a temporary folder (the command line is
pointed there), never this installation's data/.
- a download larger than the limit is refused; 304 is "unchanged"; any other HTTP error is raised
- a schema or feed that is too small, of another format, or not from a real commit is refused and the last good copy kept
- report pages: unchanged (304), changed (counted), unreadable (retried later, error kept)
- the command line: --update, --arrivals (the database's unknown collections placed and flagged), --snapshot, the
  summary; --build-feed and --pages-only need --state; nothing to commit is exit 3
- the loop reads the feed and the database, survives an error, and waits ARRIVALS_EVERY between rounds
No database needed. Run: .venv/bin/python tests/check_cov_report_map.py"""
import contextlib
import io
import json
import os
import shutil
import sys
import tempfile
import urllib.error

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
import report_map as RM  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


TMP = tempfile.mkdtemp(prefix="lg-cov-rmap-")
BASE = os.path.join(TMP, "platform")
os.makedirs(os.path.join(BASE, "data"))
shutil.copy(os.path.join(HERE, "data", "report_map_rules.json"), os.path.join(BASE, "data", "report_map_rules.json"))
N = RM.MIN_REPORTS + 5
FACTS = {f"sample_{i}": {"taxonomy": "vulnerable", "type": "vulnerable-system", "fields": ["ip", "port", "tag"], "name": f"Sample {i}",
                         "url": f"{RM.SS_BASE}sample-{i}/", "title": f"Sample report {i}", "severity": "medium"} for i in range(N)}
SNAP = {"status": {"schema_commit": "1" * 40}, "facts": FACTS, "reports": RM.build(FACTS, {}),
        "events": [{"at": "2026-11-17T00:00:00Z", "text": "New report type: Sample 0"}]}
with open(os.path.join(BASE, "data", "report_map_snapshot.json"), "w") as f:
    json.dump(SNAP, f)


# ---------------- the one way out, answered here
class Resp:
    def __init__(self, body, status=200, headers=None):
        self.body, self.status, self.headers = body, status, headers or {}

    def read(self, n=-1):
        return self.body if n < 0 else self.body[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


ROUTES = {}
SEEN = []


def fake_open(req, timeout=None):
    url = req.full_url if hasattr(req, "full_url") else req
    SEEN.append(url)
    a = ROUTES.get(url)
    if a is None:
        raise urllib.error.URLError(f"made-up: no answer for {url}")
    if isinstance(a, Exception):
        raise a
    return a


RM.https_only.open = fake_open

print("Downloads")
ROUTES["https://big.example.org/x"] = Resp(b"x" * (RM.MAX_BYTES + 10))
try:
    RM._get("https://big.example.org/x")
    ok("a download larger than the limit is refused", False)
except ValueError as e:
    ok("a download larger than the limit is refused", "larger than" in str(e))
ROUTES["https://same.example.org/x"] = urllib.error.HTTPError("https://same.example.org/x", 304, "Not Modified", {"ETag": "e1"}, None)
ok("304: unchanged, an empty body", RM._get("https://same.example.org/x")[:2] == (304, b""))
ROUTES["https://gone.example.org/x"] = urllib.error.HTTPError("https://gone.example.org/x", 404, "Not Found", {}, None)
try:
    RM._get("https://gone.example.org/x")
    ok("another HTTP error is raised", False)
except urllib.error.HTTPError as e:
    ok("another HTTP error is raised", e.code == 404)
ok("a header found whatever its case", RM._h({"etag": "v"}, "ETag") == "v" and RM._h(None, "x") == "")

print("Schema checks")
ok("reports.json with too few report types: refused", any("expected at least" in p for p in RM.check_schema({"a": {}}, {})))
few_fields = {f"r{i}": {"fields": []} for i in range(N)}
ok("…enough types but too few with a field list: refused", any("too few report types with a field list" in p for p in RM.check_schema(few_fields, {})))
ok("…types.md too short: refused", any("types.md has 0" in p for p in RM.check_schema({f"r{i}": {"fields": ["ip"]} for i in range(N)}, {})))
ok("schema facts skip what is not a report type", RM.schema_facts({"Bad Key!": {}, "x": "not a dict", "ok_one": {"fields": ["ip"]}}, {}) .keys() == {"ok_one"})
ok("a page without its content block: nothing", RM.parse_page("<h1>X</h1><p>no content</p>") is None)
page = ('<h1>HIGH: Sample</h1><div class="content"><p>Description last updated: 2026-01-02</p><p>Default severity level: High</p>'
        '<p>Filename(s): sample_one, sample_two.</p><p>What it is.</p><p>What it is.</p><p>You can learn more about the report here.</p>'
        '<p>You can learn more about the report here.</p><p>Intro<ul><li>x</li></ul></p><li>One item</li>'
        '<h3>Lonely</h3><p>Severity levels are described here.</p><h3>Next</h3><p>Under next.</p></div><div class="fields-list"><div class="name">ip</div>'
        '<div class="description">The address</div><div class="name">bad name!</div><div class="description">x</div>'
        '<h2>Sample</h2><div class="name">later</div><div class="description">not a field</div></div>')
p = RM.parse_page(page)
ok("a page: its title without the severity, date, severity, file names", p["title"] == "Sample" and p["last_updated"] == "2026-01-02"
   and p["severity"] == "high" and p["filenames"] == ["sample_one", "sample_two"], str(p))
ok("…the same line twice kept once, a standard note once, a heading with nothing under it dropped",
   [b["text"] for b in p["blocks"]].count("What it is.") == 1 and len(p["notes"]) == 2 and not any(b["text"] == "Lonely" for b in p["blocks"]), str(p))
ok("…a list item marked, the fields before the sample only, odd names left out", "• One item" in p["description"] and p["fields"] == {"ip": "The address"}, str(p["fields"]))

print("The feed builder's failure paths")
st = os.path.join(TMP, "state")
fb = RM.FeedBuilder(os.path.join(TMP, "out"), st)
log = []


class Log:
    def warning(self, *a):
        log.append(a)


fb.log = Log()
ROUTES[RM.SITEMAP] = Resp(b"<loc>https://www.example.org/posts-page-1.xml</loc>")
ROUTES["https://www.example.org/posts-page-1.xml"] = Resp(b"<loc>https://www.example.org/other/</loc><lastmod>2026-01-01</lastmod>")
RM.time.sleep = lambda s: None
ok("a sitemap without report pages: none, logged, weekly reading", fb.sitemap() is None and log and "weekly" in log[-1][0])
ROUTES[RM.API_COMMIT] = Resp(b"not-a-sha")
try:
    fb.schema()
    ok("an odd answer for the latest commit, nothing cached: raised", False)
except ValueError as e:
    ok("an odd answer for the latest commit, nothing cached: raised", "unexpected answer" in str(e))
ok("…and the error kept in the status", "schema_error" in json.load(open(os.path.join(st, "status.json"))))
sha = "a" * 40
ROUTES[RM.API_COMMIT] = Resp(sha.encode())
ROUTES[RM.RAW.format(sha=sha, file="reports.json")] = Resp(b"{}")
ROUTES[RM.RAW.format(sha=sha, file="types.md")] = Resp(b"")
try:
    fb.schema()
    ok("a schema that is too small is refused", False)
except ValueError as e:
    ok("a schema that is too small is refused", "expected at least" in str(e))
ok("the hourly run without a schema: says the daily run fetches it", "no schema downloaded yet" in fb.pages_only())
os.makedirs(os.path.join(st, "schema"), exist_ok=True)
json.dump({"a": {}}, open(os.path.join(st, "schema", "reports.json"), "w"))
open(os.path.join(st, "schema", "types.md"), "w").write("")
ok("…with an unusable schema: fetched again by the daily run", "not usable" in fb.pages_only())
U = [f["url"] for f in FACTS.values()][:3]
store = {U[0]: {"checked": "2000-01-01T00:00:00Z", "last_modified": "Mon", "hash": "old"},
         U[1]: {"checked": "2000-01-01T00:00:00Z", "hash": "old"}, U[2]: {}}
json.dump(store, open(os.path.join(st, "pages.json"), "w"))
ROUTES[U[0]] = urllib.error.HTTPError(U[0], 304, "Not Modified", {}, None)
ROUTES[U[1]] = Resp(page.encode(), headers={"Last-Modified": "Tue"})
ROUTES[U[2]] = Resp(b"<html>nothing here</html>")
three = {k: v for k, v in FACTS.items() if v["url"] in U}
got, summary = fb.pages(three, limit=10, delay=0, dates={fb._key(U[1]): "2026-11-01"})
ok("pages: unchanged (304), changed, unreadable", "3 read" in summary and "1 changed" in summary and "1 failed" in summary, summary)
ok("…the changed page's sitemap date kept; the unreadable one's error kept, due again", got[U[1]].get("lastmod") == "2026-11-01"
   and "no description" in got[U[2]].get("error", "") and "lastmod" not in got[U[2]])

print("An installation's map: files missing or broken")
rm = RM.ReportMap(BASE)
ok("the shipped snapshot until the feed was read", rm.get()["status"]["source"] == "shipped snapshot")
ok("its facts from the snapshot", len(rm._facts()[0]) == N)
os.rename(rm.paths["rules"], rm.paths["rules"] + ".away")
ok("no rules file: an empty hash", rm.rules_hash() == "")
os.rename(rm.paths["rules"] + ".away", rm.paths["rules"])
empty = RM.ReportMap(os.path.join(TMP, "nothing"))
ok("no map and no snapshot: an empty map", empty.get()["status"]["source"] == "none" and empty.get()["reports"] == {})
bad = os.path.join(TMP, "bad")
os.makedirs(os.path.join(bad, "data"))
open(os.path.join(bad, "data", "report_map.json"), "w").write("{}")
ok("a map file without reports is passed over", RM.ReportMap(bad).get()["status"]["source"] == "none")
ok("arrivals without a database: said so", rm.check_arrivals() == "no database")
rm2 = RM.ReportMap(BASE, collections=lambda: ["sample_1"], fields_of=lambda n: ["ip"])
ok("every collection known: said so", rm2.check_arrivals() == "every report collection is in the map")
rm3 = RM.ReportMap(BASE, logger=Log(), feed_url="https://feed.example.org/feed.json")
ROUTES["https://feed.example.org/feed.json"] = Resp(json.dumps({"format": 99}).encode())
out = rm3.update_feed(force=True)
ok("a feed of another format: not read, last good copy kept, logged", "feed format 99" in out and "last good copy kept" in out)
ok("…the error in the map's status (the map written from the snapshot first)", "feed_error" in rm3.get()["status"] and os.path.exists(rm3.paths["map"]))
ok("read again within the day: not asked again", "already read" in rm3.update_feed())

print("The command line (pointed at the temporary folder)")
real_file = RM.__file__
RM.__file__ = os.path.join(BASE, "report_map.py")


def cli(*args):
    old = sys.argv
    sys.argv = ["report_map.py", *args]
    buf, code = io.StringIO(), None
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            RM._cli()
    except SystemExit as e:
        code = e.code
    finally:
        sys.argv = old
    return code, buf.getvalue()


code, out = cli("--snapshot")
snap = json.load(open(os.path.join(BASE, "data", "report_map_snapshot.json")))
ok("--snapshot writes the shipped snapshot (no description text), and the summary", code == 0 and f"snapshot: {N} report types" in out
   and snap["events"] == [] and "_about" in snap, out[:200])
FEED = {"format": RM.FEED_FORMAT, "schema_commit": "b" * 40, "built": "2026-11-17", "text_included": False, "facts": FACTS,
        "pages": {U[0]: {"title": "Sample", "hash": "h2"}}}
ROUTES[RM.FEED_URL] = Resp(json.dumps(FEED).encode(), headers={"ETag": "etag-1"})
os.environ.pop("REPORT_MAP_FEED_URL", None)


class FakeDB:
    def list_collection_names(self):
        return ["sample_1", "sample_new_one", "files_x", "system.views", "Bad-Name"]

    def __getitem__(self, n):
        return type("Col", (), {"find_one": staticmethod(lambda sort=None: {"_id": 1, "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1"})})()


class FakeClient:
    def __init__(self, **kw):
        self.kw = kw

    def __getitem__(self, name):
        return FakeDB()


import pymongo  # noqa: E402
real_client = pymongo.MongoClient
pymongo.MongoClient = FakeClient
code, out = cli("--update", "--force", "--arrivals")
pymongo.MongoClient = real_client
m = json.load(open(os.path.join(BASE, "data", "report_map.json")))
ok("--update reads the feed: its commit and the number of report types", code == 0 and f"{N} report types" in out and m["status"]["schema_commit"] == "b" * 40, out[:300])
ok("…the feed's ETag kept for the next conditional request", m["status"].get("feed_etag") == "etag-1")
ok("--arrivals: the unknown collection placed from its fields and flagged (files_, system., odd names skipped)",
   "sample_new_one" in out and m["reports"]["sample_new_one"]["in_schema"] is False
   and m["reports"]["sample_new_one"]["platform"] == RM.PLATFORM_COMMS and "files_x" not in m["reports"], out[-400:])
ok("the summary: report types per section, the source, events", "source: updated here" in out and "event:" in out)
ROUTES[RM.FEED_URL] = urllib.error.HTTPError(RM.FEED_URL, 304, "Not Modified", {}, None)
code, out = cli("--update")
ok("--update again the same day: not asked", "already read" in out)
m["status"]["feed_checked"] = "2000-01-01T00:00:00Z"
json.dump(m, open(os.path.join(BASE, "data", "report_map.json"), "w"))
code, out = cli("--update")
ok("--update the next day, feed unchanged (304)", "feed unchanged" in out, out[:200])
for args, what in ((("--build-feed", os.path.join(TMP, "o")), "--build-feed without --state"),
                   (("--build-feed", os.path.join(TMP, "o"), "--pages-only"), "--pages-only without --state")):
    code, out = cli(*args)
    ok(f"{what}: refused (usage error)", code == 2)
code, out = cli("--build-feed", os.path.join(TMP, "o"), "--state", os.path.join(TMP, "st2"), "--pages-only")
ok("--pages-only: the hourly run, nothing to commit (exit 3)", code == 3 and "no schema downloaded yet" in out, out)
types_md = "\n".join(f"| sample_{i} | [Sample report {i}]({RM.SS_BASE}sample-{i}/) | medium |" for i in range(N))
reports = {f"sample_{i}": {"classification.taxonomy": "vulnerable", "classification.type": "vulnerable-system", "fields": ["ip", "port"]}
           for i in range(N)}
sha = "c" * 40
ROUTES[RM.API_COMMIT] = Resp(sha.encode())
ROUTES[RM.RAW.format(sha=sha, file="reports.json")] = Resp(json.dumps(reports).encode())
ROUTES[RM.RAW.format(sha=sha, file="types.md")] = Resp(types_md.encode())
code, out = cli("--build-feed", os.path.join(TMP, "o"), "--state", os.path.join(TMP, "st2"), "--pages", "0")
ok("--build-feed: the schema downloaded, the feed written (exit 0)", code == 0 and "feed written" in out, out)
code, out = cli("--build-feed", os.path.join(TMP, "o"), "--state", os.path.join(TMP, "st2"), "--pages", "0")
ok("…again with nothing new: nothing to commit (exit 3)", code == 3 and "feed unchanged" in out, out)
RM.__file__ = real_file

print("The background loop")
naps = []


class Stop(BaseException):
    pass


def nap(s):
    naps.append(s)
    if len(naps) >= 3:
        raise Stop


RM.time.sleep = nap
os.environ["REPORT_MAP_FETCH"] = "0"
llog = []
first = {"n": 0}


def cols():
    first["n"] += 1
    if first["n"] == 1:
        raise RuntimeError("database away")
    return []


loop_map = RM.ReportMap(BASE, collections=cols, logger=type("L", (), {"warning": lambda self, *a: llog.append(a)})())
try:
    loop_map.loop()
except Stop:
    pass
ok("the loop: waits for the service, an error logged and survived, then every ARRIVALS_EVERY",
   naps == [150, RM.ARRIVALS_EVERY, RM.ARRIVALS_EVERY] and llog and "database away" in str(llog[0]), str(naps))
os.environ.pop("REPORT_MAP_FETCH", None)
ok("nothing left this computer (every request answered here)", all(".example.org" in u or "shadowserver" in u or "github" in u for u in SEEN))

shutil.rmtree(TMP, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
