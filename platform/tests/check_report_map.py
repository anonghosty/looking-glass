#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The report map (report_map.py): where each Shadowserver report type belongs, and how it keeps itself up to date.
Runs in a throwaway folder with the shipped rules and snapshot, and no network (downloads are simulated).

1. The shipped snapshot: every report placed in a known section; the snapshot agrees with the rules (rebuilt from its
   own facts); the key reports are where the plan puts them (Compromised Account: Intelligence, no IP; Spam URL:
   Intelligence on the communications map; Sinkhole DNS: Infections; IPv6 twins like their IPv4 report).
2. Keeping it current: a schema update with a new report type places it and flags it; a reclassified one is noted; a
   bad download (too few report types, broken JSON) and a network failure keep the last good copy; an unchanged
   schema downloads nothing.
3. Our choices and the administrators': an override in the rules and an administrator's move win, and a rebuild keeps
   them.
4. What arrives: a report collection in the database that the map does not know is placed from its fields and flagged.
5. A report page: description, headings, lists, notes apart, last-updated date, severity, file names, field meanings;
   a changed description is noted; a page that cannot be read keeps the last good copy.
Usage: tests/check_report_map.py"""
import json
import os
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

# the network, simulated: rm._get answers from this table (url -> (status, bytes, headers) or an exception)
NET = {}
CALLS = []


def fake_get(url, headers=None, timeout=25):
    CALLS.append(url)
    v = NET.get(url)
    if v is None:
        for k, val in NET.items():
            if k.endswith("*") and url.startswith(k[:-1]):
                v = val
    if isinstance(v, Exception) or v is None:
        raise v or OSError(f"no network for {url}")
    return v


rm._get = fake_get
try:
    m = rm.ReportMap(tmp)
    snap = json.load(open(os.path.join(tmp, "data", "report_map_snapshot.json")))
    facts, reports = snap["facts"], snap["reports"]

    print("1. The shipped snapshot")
    ok("the snapshot holds the report types", len(reports) >= rm.MIN_REPORTS, f"{len(reports)} types")
    ok("every report is placed in a known section", all(e["section"] in SECTIONS for e in reports.values()),
       ", ".join(sorted({e["section"] for e in reports.values()} - SECTIONS)))
    ok("none is left unclassified", not [k for k, e in reports.items() if e["classified"] == "unclassified"],
       ", ".join(k for k, e in reports.items() if e["classified"] == "unclassified"))
    rebuilt = rm.build(facts, m.rules())
    ok("the snapshot agrees with the rules (rebuilt from its own facts)", rebuilt == reports,
       ", ".join(k for k in reports if rebuilt.get(k) != reports[k])[:200])
    e = lambda k: m.entry(k) or {}
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
    ok("Vulnerable HTTP: Services, known vulnerability", e("scan_http_vulnerable")["group"] == "Known vulnerability")
    ok("DNS open resolvers: Services, can be abused", e("scan_dns")["group"].startswith("Can be abused"))
    ok("Blocklist and Compromised Website: Intelligence on the services platform",
       all(e(k)["section"] == "Intelligence" and e(k)["platform"] == rm.PLATFORM_SVC for k in ("blocklist", "compromised_website")))

    print("2. Keeping it current")
    SHA1, SHA2, SHA3 = "a" * 40, "b" * 40, "c" * 40
    base_rj = {k: {"classification.taxonomy": f.get("taxonomy"), "classification.type": f.get("type"), "fields": f["fields"],
                   "name": f.get("name"), "url": f.get("url")} for k, f in facts.items() if f.get("fields")}
    types_md = "| Report Type | Subject | Default Severity |\n| --- | --- | --- |\n" + "".join(
        f"| {k} | [{f['title']}]({f['url'] or rm.SS_BASE + k + '/'}) | {f['severity'] or 'info'} |\n" for k, f in facts.items())
    rj2 = dict(base_rj, scan_newthing={"classification.taxonomy": "vulnerable", "classification.type": "vulnerable-system",
                                       "fields": ["timestamp", "ip", "port", "asn", "geo", "tag"], "name": "Accessible-Newthing", "url": ""})
    rj2["scan_ftp"] = dict(rj2["scan_ftp"], **{"classification.taxonomy": "intrusions", "classification.type": "system-compromise"})
    NET.update({rm.API_COMMIT: (200, SHA2.encode(), {}),
                rm.RAW.format(sha=SHA2, file="reports.json"): (200, json.dumps(rj2).encode(), {}),
                rm.RAW.format(sha=SHA2, file="types.md"): (200, (types_md + "| scan_newthing | [Accessible Newthing](https://www.shadowserver.org/what-we-do/network-reporting/x/) | high |\n").encode(), {})})
    out = m.update_schema(force=True)
    ev = m.get()["events"]
    ok("a changed schema is downloaded and the map rebuilt", m.get()["status"].get("schema_commit") == SHA2, out)
    ok("a new report type is placed by the rules at once", (e("scan_newthing").get("section"), e("scan_newthing").get("platform")) == ("Services", rm.PLATFORM_SVC))
    ok("…and flagged: check its place", any(x["kind"] == "new_report" and x["report"] == "scan_newthing" for x in ev))
    ok("a reclassified report follows, and the change is noted", e("scan_ftp")["section"] == "Intelligence"
       and any(x["kind"] == "changed" and x["report"] == "scan_ftp" for x in ev))
    good = json.dumps(m.get()["reports"], sort_keys=True)
    n_calls = len(CALLS)
    out = m.update_schema()
    ok("checked again within a day: nothing is requested", len(CALLS) == n_calls, out)
    NET[rm.API_COMMIT] = (200, SHA2.encode(), {})
    st = m.get()["status"]; st["schema_checked"] = "2000-01-01T00:00:00Z"; m._status(**st)
    n_calls = len(CALLS)
    out = m.update_schema()
    ok("unchanged schema next day: only the commit is asked, nothing downloaded", len(CALLS) == n_calls + 1, out)
    NET.update({rm.API_COMMIT: (200, SHA3.encode(), {}),
                rm.RAW.format(sha=SHA3, file="reports.json"): (200, json.dumps({"scan_x": {"fields": ["ip"]}}).encode(), {}),
                rm.RAW.format(sha=SHA3, file="types.md"): (200, b"| scan_x | [X](u) | low |\n", {})})
    out = m.update_schema(force=True)
    ok("a download with too few report types is refused, the last good copy kept",
       json.dumps(m.get()["reports"], sort_keys=True) == good and "fail" in out and m.get()["status"].get("schema_error"), out[:90])
    NET[rm.RAW.format(sha=SHA3, file="reports.json")] = (200, b"{not json", {})
    out = m.update_schema(force=True)
    ok("broken JSON is refused, the last good copy kept", json.dumps(m.get()["reports"], sort_keys=True) == good and "fail" in out)
    NET[rm.API_COMMIT] = OSError("network unreachable")
    out = m.update_schema(force=True)
    ok("no network: the last good copy kept, the error shown", json.dumps(m.get()["reports"], sort_keys=True) == good
       and "unreachable" in m.get()["status"].get("schema_error", ""))

    print("3. Our choices and the administrators'")
    json.dump({"overrides": {"scan_telnet": {"section": "Intelligence", "group": "Reputation: listed or targeted"}}},
              open(os.path.join(tmp, "data", "report_map_local.json"), "w"))
    m.rebuild()
    ok("an administrator's move wins", (e("scan_telnet")["section"], e("scan_telnet")["placed_by"]) == ("Intelligence", "administrator"))
    m.rebuild()
    ok("…and a rebuild keeps it", e("scan_telnet")["placed_by"] == "administrator" and e("spam_url")["placed_by"] == "ours")
    os.remove(os.path.join(tmp, "data", "report_map_local.json"))
    m.rebuild()
    ok("…until it is taken back", e("scan_telnet")["section"] == "Services")

    print("4. What arrives in the database")
    cols = list(m.get()["reports"]) + ["files_scan_rdp", "system.views", "scan_brandnew", "leak_mailboxes", "event4_honeypot_newscan"]
    flds = {"scan_brandnew": ["_id", "ip", "port", "geo", "asn", "tag"], "leak_mailboxes": ["_id", "email", "username", "source_url"],
            "event4_honeypot_newscan": ["_id", "src_ip", "dst_ip", "src_geo", "infection"]}
    m.collections, m.fields_of = (lambda: cols), (lambda n: flds.get(n, []))
    out = m.check_arrivals()
    ok("unknown report collections are placed and flagged (never the files_ or system ones)",
       all(e(k).get("flag") for k in flds) and not e("files_scan_rdp") and not e("system.views"), out[:120])
    ok("one IP → Services, publicly accessible services", (e("scan_brandnew")["section"], e("scan_brandnew")["platform"]) == ("Services", rm.PLATFORM_SVC))
    ok("an e-mail, no IP → Intelligence, an e-mail account, not yet placed",
       (e("leak_mailboxes")["section"], e("leak_mailboxes")["affected"], e("leak_mailboxes")["group"]) == ("Intelligence", "e-mail account", rm.UNPLACED))
    ok("a source and destination → communications, attacks seen", (e("event4_honeypot_newscan")["platform"], e("event4_honeypot_newscan")["section"]) == (rm.PLATFORM_COMMS, "Attacks seen"))
    ok("…flagged as new for a researcher to check", sum(1 for x in m.get()["events"] if x["kind"] == "new_report" and x["report"] in flds) == 3)
    ok("a second check finds nothing new", m.check_arrivals().startswith("every report"))

    print("5. A report page")
    page = """<html><head><meta name="description" content="x"></head><body><h1>HIGH: Accessible Example Report</h1>
    <div class="content"><p>DESCRIPTION LAST UPDATED: 2026-01-02</p><p>DEFAULT SECURITY LEVEL: HIGH</p>
    <p><strong>Introduction</strong></p><p>This report lists example services that answer on port 9/TCP.</p>
    <p>Older versions have known flaws:</p><ul><li>CVE-2026-0001 (an example flaw)</li><li>CVE-2026-0002</li></ul>
    <h3>Dashboard</h3><p>You can track example servers on our Dashboard.</p>
    <p>Severity levels are described <a href="x">here</a>.</p><p><strong>Filename(s): scan_example, scan6_example</strong></p></div>
    <div class="fields-list"><h2>Fields</h2><ul class="c--field-list"><li><div class="name">ip</div><div class="description">The IP address of the device</div></li>
    <li><div class="name">port</div><div class="description">Port that the response came from</div></li></ul></div><h2>Sample</h2></body></html>"""
    p = rm.parse_page(page)
    ok("title, last-updated date, severity (also when written 'security level'), file names",
       (p["title"], p["last_updated"], p["severity"], p["filenames"]) == ("Accessible Example Report", "2026-01-02", "high", ["scan_example", "scan6_example"]), str(p and p["filenames"]))
    ok("description with its heading and list; standard lines apart as notes",
       [b["kind"] for b in p["blocks"]] == ["h", "p", "p", "li", "li"] and len(p["notes"]) == 2, str([b["kind"] for b in p["blocks"]]))
    ok("a heading with nothing under it is dropped", not any(b["text"] == "Dashboard" for b in p["blocks"]))
    ok("field meanings", p["fields"] == {"ip": "The IP address of the device", "port": "Port that the response came from"})
    ok("a page that is not a report page gives nothing", rm.parse_page("<html><body><p>hello</p></body></html>") is None)
    url = rm.SS_BASE + "x/"
    m.get()["reports"]  # the map now knows scan_newthing with page url .../x/
    NET[url] = (200, page.encode(), {"Last-Modified": "Mon, 01 Jan 2026 00:00:00 GMT"})
    NET[rm.SS_BASE + "*"] = OSError("not in this test")
    out = m.update_pages(limit=500, delay=0)
    d = (m.descriptions().get("pages") or {}).get(url) or {}
    ok("pages are read and stored, with the source named", d.get("title") == "Accessible Example Report" and "Shadowserver Foundation" in d.get("source", ""), out)
    import re
    nfail = int((re.search(r"(\d+) failed", out) or [0, 0])[1])
    ok("pages that fail keep trying later, the rest is not lost", nfail > 0 and d.get("hash")
       and all((v.get("error") and v.get("checked_ts", 0) > 0) for u, v in m.descriptions()["pages"].items() if u != url), f"{nfail} failed")
    pages = m.descriptions(); pages["pages"][url]["checked_ts"] = 0
    json.dump(pages, open(os.path.join(tmp, "data", "shadowserver_reports.json"), "w"))
    NET[url] = (200, page.replace("answer on port 9/TCP", "answer on port 9/TCP and 9/UDP").encode(), {})
    m.update_pages(limit=500, delay=0)
    ok("a changed description is noted", any(x["kind"] == "description_changed" and x["url"] == url for x in m.get()["events"]))
    pages = m.descriptions(); pages["pages"][url]["checked_ts"] = 0
    json.dump(pages, open(os.path.join(tmp, "data", "shadowserver_reports.json"), "w"))
    before = m.descriptions()["pages"][url]["description"]
    NET[url] = (200, b"<html>maintenance</html>", {})
    m.update_pages(limit=500, delay=0)
    d = m.descriptions()["pages"][url]
    ok("a page that cannot be read keeps the last good description", d["description"] == before and d.get("error"))
    NET[url] = (304, b"", {})
    d["checked_ts"] = 0; pages = m.descriptions(); pages["pages"][url] = d
    json.dump(pages, open(os.path.join(tmp, "data", "shadowserver_reports.json"), "w"))
    m.update_pages(limit=500, delay=0)
    ok("an unchanged page (304) keeps its description and clears the error", m.descriptions()["pages"][url]["description"] == before
       and not m.descriptions()["pages"][url].get("error"))
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
