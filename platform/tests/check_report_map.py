#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The report map (report_map.py): where each Shadowserver report type belongs, and how it keeps itself up to date.
Runs in a throwaway folder with the shipped rules and snapshot, and no network (every request is simulated and logged).

1. The shipped snapshot: every report placed in a known section; it agrees with the rules (rebuilt from its own facts);
   the key reports are where the plan puts them.
2. The feed builder (the only one that asks Shadowserver): downloads the schema only when their repository moved;
   reads due report pages; leaves Shadowserver's description text out of the feed unless allowed; writes no new feed
   when nothing changed; keeps the last good copy when a download is bad.
3. An installation: reads only the feed on GitHub (never Shadowserver), once a day, with a conditional request;
   a new report type is placed and flagged, a reclassified one noted, a changed description noted; a bad feed, a feed
   of another format and no network keep the last good copy.
4. Our choices and the administrators': an override in the rules and an administrator's move win, and a rebuild keeps
   them.
5. What arrives: a report collection in the database that the map does not know is placed from its fields and flagged.
6. A report page: description, headings, lists, notes apart, last-updated date, severity, file names, field meanings.
Usage: tests/check_report_map.py"""
import json
import os
import re
import shutil
import sys
import tempfile

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
import report_map as rm  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg_reportmap_")
os.makedirs(os.path.join(tmp, "data"))
for f in ("report_map_rules.json", "report_map_snapshot.json"):
    shutil.copy(os.path.join(BASE_DIR, "data", f), os.path.join(tmp, "data", f))
SECTIONS = {"Infections", "Attacks seen", "Services", "Intelligence"}
NET, CALLS = {}, []


def fake_get(url, headers=None, timeout=25):
    """The network, simulated: answers from NET (url, or a prefix ending in *); every request is logged."""
    CALLS.append((url, dict(headers or {})))
    v = NET.get(url)
    if v is None:
        v = next((val for k, val in NET.items() if k.endswith("*") and url.startswith(k[:-1])), None)
    if isinstance(v, Exception) or v is None:
        raise v or OSError(f"no network for {url}")
    return v(headers) if callable(v) else v


rm._get = fake_get
PAGE = """<html><body><h1>HIGH: Accessible Example Report</h1>
<div class="content"><p>DESCRIPTION LAST UPDATED: 2026-01-02</p><p>DEFAULT SECURITY LEVEL: HIGH</p>
<p><strong>Introduction</strong></p><p>This report lists example services that answer on port 9/TCP.</p>
<p>Older versions have known flaws:</p><ul><li>CVE-2026-0001 (an example flaw)</li><li>CVE-2026-0002</li></ul>
<h3>Dashboard</h3><p>You can track example servers on our Dashboard.</p>
<p>Severity levels are described <a href="x">here</a>.</p><p><strong>Filename(s): scan_example, scan6_example</strong></p></div>
<div class="fields-list"><h2>Fields</h2><ul class="c--field-list"><li><div class="name">ip</div><div class="description">The IP address of the device</div></li>
<li><div class="name">port</div><div class="description">Port that the response came from</div></li></ul></div><h2>Sample</h2></body></html>"""
try:
    m = rm.ReportMap(os.path.join(tmp))
    snap = json.load(open(os.path.join(tmp, "data", "report_map_snapshot.json")))
    facts, reports = snap["facts"], snap["reports"]
    e = lambda k: m.entry(k) or {}

    print("1. The shipped snapshot")
    ok("the snapshot holds the report types", len(reports) >= rm.MIN_REPORTS, f"{len(reports)} types")
    ok("every report is placed in a known section", all(x["section"] in SECTIONS for x in reports.values()))
    ok("none is left unclassified", not [k for k, x in reports.items() if x["classified"] == "unclassified"])
    rebuilt = rm.build(facts, m.rules())
    ok("the snapshot agrees with the rules (rebuilt from its own facts)", rebuilt == reports,
       ", ".join(k for k in reports if rebuilt.get(k) != reports[k])[:200])
    ok("map in use before any update: the shipped snapshot", m.get()["status"].get("source") == "shipped snapshot")
    ok("Compromised Account: Intelligence, leaked accounts, no IP, an e-mail account",
       (e("compromised_account")["section"], e("compromised_account")["group"], e("compromised_account")["platform"], e("compromised_account")["affected"])
       == ("Intelligence", "Leaked accounts and credentials", rm.PLATFORM_NONE, "e-mail account"))
    ok("Ransomware Victim: Intelligence, no IP, an organisation", (e("ransomware_victim")["section"], e("ransomware_victim")["platform"],
       e("ransomware_victim")["affected"]) == ("Intelligence", rm.PLATFORM_NONE, "organisation / website"))
    ok("Spam URL: Intelligence, though drawn on the communications map (our override)",
       (e("spam_url")["section"], e("spam_url")["platform"], e("spam_url")["placed_by"]) == ("Intelligence", rm.PLATFORM_COMMS, "ours"))
    ok("Sinkhole DNS: Infections (communications)", (e("event4_sinkhole_dns")["section"], e("event4_sinkhole_dns")["platform"]) == ("Infections", rm.PLATFORM_COMMS))
    ok("Accessible RDP: Services, should not be open", e("scan_rdp")["section"] == "Services" and e("scan_rdp")["group"].startswith("Should not be open"))
    ok("IPv6 RDP like its IPv4 report", (e("scan6_rdp")["section"], e("scan6_rdp")["group"]) == (e("scan_rdp")["section"], e("scan_rdp")["group"])
       and e("scan6_rdp")["classified"].startswith("from "))
    ok("Vulnerable HTTP: known vulnerability; DNS open resolvers: can be abused",
       e("scan_http_vulnerable")["group"] == "Known vulnerability" and e("scan_dns")["group"].startswith("Can be abused"))
    ok("Blocklist and Compromised Website: Intelligence on the services platform",
       all(e(k)["section"] == "Intelligence" and e(k)["platform"] == rm.PLATFORM_SVC for k in ("blocklist", "compromised_website")))

    print("2. The feed builder")
    SHA1, SHA2 = "a" * 40, "b" * 40
    rj = {k: {"classification.taxonomy": f.get("taxonomy"), "classification.type": f.get("type"), "fields": f["fields"],
              "name": f.get("name"), "url": f.get("url")} for k, f in facts.items() if f.get("fields")}
    types_md = "".join(f"| {k} | [{f['title']}]({rm.SS_BASE}p-{k}/) | {f['severity'] or 'info'} |\n" for k, f in facts.items())
    NET.update({rm.API_COMMIT: (200, SHA1.encode(), {}),
                rm.RAW.format(sha=SHA1, file="reports.json"): (200, json.dumps(rj).encode(), {}),
                rm.RAW.format(sha=SHA1, file="types.md"): (200, types_md.encode(), {}),
                rm.SS_BASE + "*": (200, PAGE.encode(), {"Last-Modified": "Mon, 05 Jan 2026 00:00:00 GMT"})})
    out_dir, state = os.path.join(tmp, "feed"), os.path.join(tmp, "state")
    fb = rm.FeedBuilder(out_dir, state)
    changed, s = fb.build(limit=3, delay=0)
    feed = json.load(open(os.path.join(out_dir, "report_feed.json")))
    ok("first run: schema downloaded, pages read, feed written", changed and feed["schema_commit"] == SHA1 and len(feed["pages"]) == 3, s)
    pg = next(iter(feed["pages"].values()))
    ok("Shadowserver's text is not in the feed (facts, field names and the page link only)",
       not any(k in pg for k in rm.PAGE_TEXT) and pg.get("field_names") == ["ip", "port"] and feed["text_included"] is False
       and "This report lists example" not in json.dumps(feed))
    ok("…but the builder keeps it in its private state", "This report lists example" in open(os.path.join(state, "pages.json")).read())
    first = set(feed["pages"])
    n = len(CALLS)
    changed, s = fb.build(limit=3, delay=0)
    raws = [u for u, _ in CALLS[n:] if u.startswith("https://raw.githubusercontent.com/" + rm.REPO)]
    ok("schema unchanged: only the commit is asked, nothing downloaded", not raws, s)
    second = {u for u, _ in CALLS[n:] if u.startswith(rm.SS_BASE)}
    ok("…pages read this week are not read again: the next three are", len(second) == 3 and not (second & first), s)
    ok("…and a new feed is written only when something changed", changed is True and "3 read" in s)
    for _ in range(80):                                   # read every page, then nothing is left due
        changed, s = fb.build(limit=50, delay=0)
        if " 0 read" in s:
            break
    n = len(CALLS)
    changed, s = fb.build(limit=50, delay=0)
    ok("a quiet day: no page due, nothing changed, no new feed", changed is False and not [u for u, _ in CALLS[n:] if u.startswith(rm.SS_BASE)], s)
    NET[rm.API_COMMIT] = (200, SHA2.encode(), {})
    NET[rm.RAW.format(sha=SHA2, file="reports.json")] = (200, b"{not json", {})
    NET[rm.RAW.format(sha=SHA2, file="types.md")] = (200, types_md.encode(), {})
    before = open(os.path.join(out_dir, "report_feed.json")).read()
    changed, s = fb.build(limit=0, delay=0)
    ok("a broken schema download: the last good copy kept, the feed untouched", changed is False and "last good copy" in s
       and open(os.path.join(out_dir, "report_feed.json")).read() == before, s[:100])
    NET[rm.API_COMMIT] = OSError("network unreachable")
    changed, s = fb.build(limit=0, delay=0)
    ok("no network: the last good copy kept, the feed untouched", changed is False and open(os.path.join(out_dir, "report_feed.json")).read() == before)
    fbt = rm.FeedBuilder(os.path.join(tmp, "feed_text"), state, include_text=True)
    NET[rm.API_COMMIT] = (200, SHA1.encode(), {})
    changed, s = fbt.build(limit=0, delay=0)
    ok("with Shadowserver's OK (FEED_INCLUDE_TEXT=1) their text goes into the feed",
       "This report lists example" in open(os.path.join(tmp, "feed_text", "report_feed.json")).read())

    print("3. An installation")
    NET[rm.API_COMMIT] = OSError("an installation must never ask Shadowserver's GitHub")
    NET[rm.SS_BASE + "*"] = OSError("an installation must never ask shadowserver.org")
    feed = json.load(open(os.path.join(out_dir, "report_feed.json")))
    feed["facts"]["scan_newthing"] = {"taxonomy": "vulnerable", "type": "vulnerable-system", "fields": ["timestamp", "ip", "port", "geo"],
                                      "name": "", "url": rm.SS_BASE + "p-scan_newthing/", "title": "Accessible Newthing", "severity": "high"}
    feed["facts"]["scan_ftp"] = dict(feed["facts"]["scan_ftp"], taxonomy="intrusions", type="system-compromise")
    served = {"body": json.dumps(feed).encode(), "etag": '"v1"'}
    NET[rm.FEED_URL] = lambda h: (304, b"", {"ETag": served["etag"]}) if h.get("If-None-Match") == served["etag"] else (200, served["body"], {"ETag": served["etag"]})
    n = len(CALLS)
    s = m.update_feed()
    asked = {u for u, _ in CALLS[n:]}
    ok("the installation reads only the feed on GitHub", asked == {rm.FEED_URL}, ", ".join(asked))
    ok("…and the map is rebuilt from it", m.get()["status"].get("source") == "updated here" and e("scan_newthing").get("section") == "Services", s)
    ev = m.get()["events"]
    ok("a new report type is placed and flagged", any(x["kind"] == "new_report" and x["report"] == "scan_newthing" for x in ev))
    ok("a reclassified report follows, and the change is noted", e("scan_ftp")["section"] == "Intelligence"
       and any(x["kind"] == "changed" and x["report"] == "scan_ftp" for x in ev))
    ok("what the feed says about each page is kept for the cards", len(m.descriptions().get("pages") or {}) == len(feed["pages"]))
    n = len(CALLS)
    s = m.update_feed()
    ok("asked again the same day: no request at all", len(CALLS) == n, s)
    st = m.get()["status"]; m._status(feed_checked="2000-01-01T00:00:00Z")
    n = len(CALLS)
    s = m.update_feed()
    ok("next day: one conditional request, 'not changed'", len(CALLS) == n + 1 and CALLS[-1][1].get("If-None-Match") == '"v1"' and s == "feed unchanged", s)
    good = json.dumps(m.get()["reports"], sort_keys=True)
    url = next(iter(feed["pages"]))
    feed["pages"][url] = dict(feed["pages"][url], hash="0" * 64)
    served.update(body=json.dumps(feed).encode(), etag='"v2"')
    m._status(feed_checked="2000-01-01T00:00:00Z")
    m.update_feed()
    ok("a changed description is noted", any(x["kind"] == "description_changed" and x["url"] == url for x in m.get()["events"]))
    good = json.dumps(m.get()["reports"], sort_keys=True)
    for label, body in (("a broken feed", b"{not json"), ("a feed of another format", json.dumps(dict(feed, format=99)).encode()),
                        ("a feed with too few report types", json.dumps(dict(feed, facts={"scan_x": {"fields": ["ip"]}})).encode())):
        served.update(body=body, etag=f'"{label}"')
        m._status(feed_checked="2000-01-01T00:00:00Z")
        s = m.update_feed()
        ok(f"{label}: the last good copy kept, the error shown", json.dumps(m.get()["reports"], sort_keys=True) == good
           and m.get()["status"].get("feed_error"), s[:90])
    NET[rm.FEED_URL] = OSError("network unreachable")
    m._status(feed_checked="2000-01-01T00:00:00Z")
    m.update_feed()
    ok("no network: the last good copy kept", json.dumps(m.get()["reports"], sort_keys=True) == good and "unreachable" in m.get()["status"]["feed_error"])
    ok("in all of this the installation never asked Shadowserver",
       not [u for u, _ in CALLS[n:] if u.startswith((rm.SS_BASE, "https://api.github.com/repos/" + rm.REPO, "https://raw.githubusercontent.com/" + rm.REPO))])

    print("4. Our choices and the administrators'")
    json.dump({"overrides": {"scan_telnet": {"section": "Intelligence", "group": "Reputation: listed or targeted"}}},
              open(os.path.join(tmp, "data", "report_map_local.json"), "w"))
    m.rebuild()
    ok("an administrator's move wins", (e("scan_telnet")["section"], e("scan_telnet")["placed_by"]) == ("Intelligence", "administrator"))
    m.rebuild()
    ok("…and a rebuild keeps it, and ours", e("scan_telnet")["placed_by"] == "administrator" and e("spam_url")["placed_by"] == "ours")
    os.remove(os.path.join(tmp, "data", "report_map_local.json"))
    m.rebuild()
    ok("…until it is taken back", e("scan_telnet")["section"] == "Services")
    rules_p = os.path.join(tmp, "data", "report_map_rules.json")
    r0 = json.load(open(rules_p)); n_ev = len(m.get()["events"])
    r1 = dict(r0, overrides=dict(r0.get("overrides") or {}, scan_ssh={"section": "Services", "group": "Known vulnerability"}))
    json.dump(r1, open(rules_p, "w"))
    ok("an update with new rules regroups the map by itself", e("scan_ssh")["group"] == "Known vulnerability")
    ok("…quietly: our own regrouping is not news from Shadowserver", len(m.get()["events"]) == n_ev)
    json.dump(r0, open(rules_p, "w"))
    ok("…and back", e("scan_ssh")["group"] != "Known vulnerability")

    print("5. What arrives in the database")
    cols = list(m.get()["reports"]) + ["files_scan_rdp", "system.views", "scan_brandnew", "leak_mailboxes", "event4_honeypot_newscan"]
    flds = {"scan_brandnew": ["_id", "ip", "port", "geo", "asn", "tag"], "leak_mailboxes": ["_id", "email", "username", "source_url"],
            "event4_honeypot_newscan": ["_id", "src_ip", "dst_ip", "src_geo", "infection"]}
    m.collections, m.fields_of = (lambda: cols), (lambda n: flds.get(n, []))
    s = m.check_arrivals()
    ok("unknown report collections are placed and flagged (never the files_ or system ones)",
       all(e(k).get("flag") for k in flds) and not e("files_scan_rdp") and not e("system.views"), s[:110])
    ok("one IP → Services", (e("scan_brandnew")["section"], e("scan_brandnew")["platform"]) == ("Services", rm.PLATFORM_SVC))
    ok("an e-mail, no IP → Intelligence, an e-mail account, not yet placed",
       (e("leak_mailboxes")["section"], e("leak_mailboxes")["affected"], e("leak_mailboxes")["group"]) == ("Intelligence", "e-mail account", rm.UNPLACED))
    ok("a source and destination → communications, attacks seen", (e("event4_honeypot_newscan")["platform"], e("event4_honeypot_newscan")["section"]) == (rm.PLATFORM_COMMS, "Attacks seen"))
    ok("…flagged as new for a researcher to check", sum(1 for x in m.get()["events"] if x["kind"] == "new_report" and x["report"] in flds) == 3)
    ok("a second check finds nothing new", m.check_arrivals().startswith("every report"))
    served.update(body=json.dumps(feed).encode(), etag='"v3"')
    NET[rm.FEED_URL] = lambda h: (200, served["body"], {"ETag": served["etag"]})
    m._status(feed_checked="2000-01-01T00:00:00Z")
    m.update_feed(force=True)
    ok("…and a later feed keeps them", all(e(k).get("flag") for k in flds))

    print("6. A report page")
    p = rm.parse_page(PAGE)
    ok("title, last-updated date, severity (also when written 'security level'), file names",
       (p["title"], p["last_updated"], p["severity"], p["filenames"]) == ("Accessible Example Report", "2026-01-02", "high", ["scan_example", "scan6_example"]))
    ok("description with its heading and list; standard lines apart as notes",
       [b["kind"] for b in p["blocks"]] == ["h", "p", "p", "li", "li"] and len(p["notes"]) == 2, str([b["kind"] for b in p["blocks"]]))
    ok("a heading with nothing under it is dropped", not any(b["text"] == "Dashboard" for b in p["blocks"]))
    ok("field meanings", p["fields"] == {"ip": "The IP address of the device", "port": "Port that the response came from"})
    ok("a page that is not a report page gives nothing", rm.parse_page("<html><body><p>hello</p></body></html>") is None)
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
