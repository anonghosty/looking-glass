#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Services on the researchers' Definitions page (services_kb.py) and their pattern fields (svc_patterns.py), offline,
with made-up records and a temporary data folder (nothing of this installation is read or written):
- who may read (the Definitions permission) and who may change (researchers and admins, a recent sign-in); every
  refusal is a 403, an unknown report a 404, a field that names a host or is not in the records a 400
- an IPv6 report is shown with its IPv4 twin (counts added), CVEs ranked actively exploited first, no host address,
  host name or network in any answer
- what Looking Glass asks a researcher (no pattern fields, fields gone from the records, new fields from Shadowserver)
- choosing, resetting and auditing pattern fields; product rules (refused when short or naming a host)
- the suggestions say why a field may or may not be a pattern field; product + version read by the rules
No database needed. Run: .venv/bin/python tests/check_cov_services_kb.py"""
import json
import os
import sys
import tempfile
from datetime import date

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
from flask import Flask  # noqa: E402

import services_kb as SK  # noqa: E402
import svc_patterns as SP  # noqa: E402
from services_intel import ISSUE, SINK  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


TMP = tempfile.mkdtemp(prefix="lg-cov-skb-")
os.makedirs(os.path.join(TMP, "data"))
with open(os.path.join(TMP, "data", "pattern_fields.json"), "w") as f:
    json.dump({"reports": {"scan_rdp": [{"field": "rdp_protocol", "kind": "exact", "label": "RDP protocol"},
                                        {"field": "hostname", "kind": "exact"}, {"field": "bad", "kind": "nonsense"}]},
               "all_reports": [{"field": "tag", "kind": "tags", "label": "Tag"}],
               "never": ["hostname"], "never_patterns": ["^ip"], "noise": ["port"]}, f)
with open(os.path.join(TMP, "data", "product_rules.json"), "w") as f:
    json.dump({"rules": [{"contains": "MikroTik", "product": "RouterOS", "version": True},
                         {"contains": "ExampleSSH", "product": "", "version": False}]}, f)
PAT = SP.Patterns(TMP)


def rec(i, report, **kw):
    e = {"ip": f"192.0.2.{i}", "report": report, "product": "ExampleServer", "vendor": "Example Corp", "device_type": "router",
         "version": "1.2", "port": 3389, "protocol": "TCP", "severity": "high" if i % 2 else "", "issues": [],
         "tags": ["rdp", "CVE-2019-0708"], "extras": {"rdp_protocol": "rdp" if i < 8 else f"x{i}", "serial": f"S{i}",
                                                       "hostname": f"h{i}.example.org", "same": "one", "port": 3389}}
    e.update(kw)
    e["tag"] = "rdp;CVE-2019-0708"
    e["extras"]["serial"] = "S" + e["ip"].replace(".", "").replace(":", "")      # one value per host
    return e


EVS = [rec(i, "scan_rdp", issues=["CVE-2019-0708", "ssl-poodle"] if i < 3 else []) for i in range(1, 11)] + \
      [rec(i, "scan6_rdp", ip=f"2001:db8::{i}", issues=["CVE-2021-0001"] if i == 1 else []) for i in range(1, 4)] + \
      [rec(1, "scan6_ssh", port=None, product="", vendor="", device_type="", version="")]


class Day:
    def __init__(self, evs, serial):
        self.events, self.serial = evs, serial


class Store:
    days = {date(2026, 11, 16): Day(EVS[:8], 1), date(2026, 11, 17): Day(EVS[8:], 1)}


REPORTS = {"scan_rdp": {"section": "Services", "group": "Remote access", "title": "Accessible RDP", "severity": "high",
                        "url": "https://www.example.org/rdp/", "taxonomy": "vulnerable", "type": "exposed"},
           "scan6_rdp": {"section": "Services", "group": "Remote access", "title": "IPv6 Accessible RDP", "url": "https://www.example.org/rdp6/"},
           "scan6_ssh": {"section": "Services", "group": "Known vulnerability", "title": "IPv6 Accessible SSH"},
           "event4_sinkhole": {"section": "Infections", "title": "Sinkhole Events"},
           "event6_sinkhole": {"section": "Infections", "title": ""}}
STATE = {"text": True, "desc": {"https://www.example.org/rdp/": {"title": "Accessible RDP", "last_updated": "2026-01-02",
                                                                 "field_names": ["rdp_protocol", "brand_new_field"],
                                                                 "blocks": [{"kind": "p", "text": "What it is."}], "notes": ["n"],
                                                                 "fields": {"rdp_protocol": "the protocol"}, "fetched": "2026-11-01"}}}


class RMap:
    def get(self):
        return {"reports": REPORTS, "status": {"source": "shipped snapshot", "schema_commit": "abcdef1234567"},
                "events": [{"kind": "new_report", "report": "scan6_ssh", "text": "new"},
                           {"kind": "description_changed", "url": "https://www.example.org/rdp/", "text": "changed"},
                           {"kind": "changed", "report": "unrelated", "text": "x"}]}

    def description(self, n):
        return STATE["desc"].get((REPORTS.get(n) or {}).get("url") or "")

    def descriptions(self):
        return {"text_included": STATE["text"], "pages": STATE["desc"]}

    def rules(self):
        return {"group_order": {"Services": ["Known vulnerability", "Remote access"]}}


class Sintel:
    cache = {"key": "something"}
    title_of = kind_of = None
    broken = 0                     # how many of the next index() calls fail

    def index(self):
        if self.broken:
            self.broken -= 1
            raise RuntimeError("not ready")
        return {"vals": {"scan_rdp": {("Tag", "rdp"): 1}}}

    def sinkholes_of(self, base, sdata):
        return {"names": [{"name": "examplebot", "hosts": 5}] if base == "scan_rdp" else []}

    def gathered(self, base):
        return {"report": base, "patterns": []}

    def records_of(self, base):
        return [e for e in EVS if SK.sibling(e["report"]) == base]

    def intel_view(self, base, title_of, asks, kind_of):
        return {"base": base, "title": title_of(base), "asks": asks, "kind": kind_of(base)}


class Notes:
    def list(self, section, base):
        return [{"date": "2026-11-15", "text": "note"}] if base == "scan_rdp" else []


class Audit:
    rows = []

    def add(self, what, **kw):
        self.rows.append((what, kw))


PERM = {"allowed": True, "change": True, "fresh": True, "cols_fail": False, "load_fail": True}


def collections():
    if PERM["cols_fail"]:
        raise RuntimeError("no database")
    return ["scan_rdp"]


def load_day():
    if PERM["load_fail"]:
        raise RuntimeError("day not loaded")


def cve_card(name):
    if name == "CVE-2021-0001":
        raise KeyError(name)
    return {"exploited": True, "cvss": {"score": 9.8}, "epss": 0.97}


sintel = Sintel()
app = Flask("cov-skb")
ctx = {"report_map": RMap(), "svc_store": Store(), "load_day": load_day, "report_info": lambda n: {"def": "Definition.", "why": "Why.", "title": "Info title"} if n == "scan_rdp" else {},
       "notes": Notes(), "allowed": lambda: PERM["allowed"], "cve_card": cve_card,
       "issues_kb": lambda: {"ssl-poodle": {"description": "Old SSL."}}, "collections": collections,
       "patterns": PAT, "services_intel": sintel, "change_allowed": lambda: PERM["change"], "fresh": lambda: PERM["fresh"],
       "audit": Audit(), "user": lambda: {"user": "made-up-researcher"}}
api = SK.install(app, ctx)
c = app.test_client()


def no_host(obj):
    s = json.dumps(obj)
    return not any(x in s for x in ("192.0.2.", "2001:db8", ".example.org\"", "h1.example"))


print("Who may read")
PERM["allowed"] = False
ok("the list: 403 without the Definitions permission", c.get("/api/kb/services").status_code == 403)
ok("one report: 403", c.get("/api/kb/service?name=scan_rdp").status_code == 403)
ok("its gathered intel: 403", c.get("/api/kb/service/intel?name=scan_rdp").status_code == 403)
ok("its pattern fields: 403", c.get("/api/kb/service/fields?name=scan_rdp").status_code == 403)
ok("the product rules: 403", c.get("/api/kb/product-rules").status_code == 403)
PERM["allowed"] = True

print("The list of services reports")
r = c.get("/api/kb/services")
j = r.get_json()
rows = {x["name"]: x for x in j["reports"]}
ok("answers 200 although the day could not be loaded", r.status_code == 200, str(r.status_code))
ok("the IPv6 twin is folded into its IPv4 report", rows["scan_rdp"]["names"] == ["scan6_rdp", "scan_rdp"] and rows["scan_rdp"]["ipv6"] == ["scan6_rdp"])
ok("…its counts added: 10 + 3 hosts, 13 records", rows["scan_rdp"]["hosts"] == 13 and rows["scan_rdp"]["records"] == 13, str(rows["scan_rdp"]["hosts"]))
ok("an IPv6 report without its IPv4 twin stands alone, its title without 'IPv6 '", rows["scan6_ssh"]["title"] == "Accessible SSH")
ok("the groups in the rules' order (Known vulnerability first)", [x["name"] for x in j["reports"]] == ["scan6_ssh", "scan_rdp"])
iss = rows["scan_rdp"]["issues"]
ok("CVEs ranked actively exploited first, a CVE without its card still listed", iss[0]["name"] == "CVE-2019-0708" and iss[0]["exploited"]
   and any(x["name"] == "CVE-2021-0001" and "exploited" not in x for x in iss), str(iss))
ok("an issue that is not a CVE says whether it is defined", any(x["name"] == "ssl-poodle" and x["defined"] for x in iss))
ok("received: the report is in the database", rows["scan_rdp"]["received"] and not rows["scan6_ssh"]["received"])
ok("new: a report type new in the map", rows["scan6_ssh"]["new"] and not rows["scan_rdp"]["new"])
ok("the sinkholes its hosts call", rows["scan_rdp"]["infections"] == [{"name": "examplebot", "hosts": 5}])
ok("the notes counted, the newest date", rows["scan_rdp"]["notes"] == 1 and rows["scan_rdp"]["last_note"] == "2026-11-15")
ok("the page facts: last updated and how many fields", rows["scan_rdp"]["page"] == {"last_updated": "2026-01-02", "fetched": "2026-11-01", "fields": 2})
ok("the events of these reports only (the unrelated one left out)", len(j["events"]) == 2, str(j["events"]))
ok("the status: the schema commit shortened, text included", j["status"]["schema_commit"] == "abcdef1" and j["status"]["text_included"])
asks = rows["scan_rdp"]["pattern_asks"]
ok("Looking Glass asks: a pattern field no longer in the records", any("RDP protocol: no longer in the records" in a for a in asks), str(asks))
ok("…and an IPv6-only report with hosts and only tags: choose its pattern fields", any("Choose its pattern fields" in a for a in rows["scan6_ssh"]["pattern_asks"]))
ok("pattern fields: the researcher's choice or the shipped one, never a field that names a host, never an unknown kind",
   rows["scan_rdp"]["pattern_fields"] == ["RDP protocol", "Tag"], str(rows["scan_rdp"]["pattern_fields"]))
ok("no host address, host name or network anywhere in the list", no_host(j))
PERM["cols_fail"] = True
sintel.broken = 1
j2 = c.get("/api/kb/services").get_json()
ok("without the database or the sinkhole index the list still answers (not received, no sinkholes)",
   not any(x["received"] for x in j2["reports"]) and all(x["infections"] == [] for x in j2["reports"]))
# r91 fix: the per-report questions also survive a failing index (it was unguarded there and answered 500)
sintel.broken = 2
r3 = c.get("/api/kb/services")
ok("…and when the index fails twice in one answer (the questions too), still 200, no error", r3.status_code == 200, r3.status_code)
PERM["cols_fail"] = False
PERM["load_fail"] = False

print("One services report")
r = c.get("/api/kb/service?name=scan6_rdp")
j = r.get_json()
ok("asked by its IPv6 name: the IPv4 report answers", r.status_code == 200 and j["name"] == "scan_rdp", str(j.get("name")))
ok("the classification and the Looking Glass definition", j["classification"] == "vulnerable / exposed" and j["definition"]["def"] == "Definition.")
ok("Shadowserver's own text, attributed, when the feed carries it", j["shadowserver"].get("source") == "The Shadowserver Foundation"
   and j["shadowserver"]["blocks"])
ok("products, devices, versions, ports and severities counted", dict(j["ports"]).get("3389/tcp") == 13 and j["severity_counts"].get("unrated"))
ok("no host address or host name in the answer", no_host(j))
ok("an unknown report: 404", c.get("/api/kb/service?name=scan_nothing").status_code == 404)
STATE["text"] = False
j = c.get("/api/kb/service?name=scan_rdp").get_json()
ok("without the text: only the facts (no blocks)", "blocks" not in j["shadowserver"] and j["shadowserver"]["title"] == "Accessible RDP")
STATE["text"] = True

print("Gathered intel, pattern fields")
ok("gathered intel of a report", c.get("/api/kb/service/intel?name=scan_rdp").get_json() == {"report": "scan_rdp", "patterns": []})
ok("…of an unknown report: 404", c.get("/api/kb/service/intel?name=nope").status_code == 404)
r = c.get("/api/kb/service/fields?name=scan_rdp")
j = r.get_json()
sug = {s["field"]: s for s in j["suggestions"]}
ok("the fields of its records, with suggestions", r.status_code == 200 and j["records"] == 13 and j["min_hosts"] == SP.MIN_HOSTS)
ok("a field that names a host may not be chosen", sug["hostname"]["may"] is False and "names or locates a host" in sug["hostname"]["why"])
ok("a noisy field (the port) may, with a word of warning", sug["port"]["may"] and sug["port"]["noise"])
ok("almost one value per host: may not (it would point at hosts)", sug["serial"]["may"] is False and "one value per host" in sug["serial"]["why"])
ok("the same on every host: says nothing", "the same on every host" in sug["same"]["why"])
ok("a field with groups of 5+ hosts: how many hosts are in them", "groups of 5+ hosts" in sug["rdp_protocol"]["why"])
ok("the chosen fields first (the pattern field and the tag field)", {s["field"] for s in j["suggestions"][:2]} == {"rdp_protocol", "tag"}
   and all(s["chosen"] for s in j["suggestions"][:2]) and not any(s["chosen"] for s in j["suggestions"][2:]))
ok("…the shipped choice, not a researcher's yet", j["chosen_by"] is None and j["shipped"] is True)
ok("pattern fields of an unknown report: 404", c.get("/api/kb/service/fields?name=nope").status_code == 404)

H = {"Content-Type": "application/json"}
PERM["change"] = False
ok("choosing fields without the right: 403", c.post("/api/kb/service/fields", json={"name": "scan_rdp"}).status_code == 403)
PERM["change"], PERM["fresh"] = True, False
r = c.post("/api/kb/service/fields", json={"name": "scan_rdp"})
ok("…with an old sign-in: 403, sign in again", r.status_code == 403 and "Sign in again" in r.get_json()["error"])
PERM["fresh"] = True
ok("…an unknown report: 404", c.post("/api/kb/service/fields", json={"name": "nope", "fields": []}).status_code == 404)
ok("…more than 12 fields: 400", c.post("/api/kb/service/fields", json={"name": "scan_rdp", "fields": [{}] * 13}).status_code == 400)
ok("…fields that are not a list: 400", c.post("/api/kb/service/fields", json={"name": "scan_rdp", "fields": "rdp"}).status_code == 400)
r = c.post("/api/kb/service/fields", json={"name": "scan_rdp", "fields": [{"field": "not_there", "kind": "exact"}]})
ok("…a field not in the records: 400, named", r.status_code == 400 and "not_there" in r.get_json()["error"])
r = c.post("/api/kb/service/fields", json={"name": "scan_rdp", "fields": [{"field": "hostname", "kind": "exact"}]})
ok("…a field that names a host: 400, with why", r.status_code == 400 and "names or locates a host" in r.get_json()["error"])
r = c.post("/api/kb/service/fields", json={"name": "scan_rdp", "fields": [{"field": "same", "kind": "weird"}]})
ok("…a kind that does not exist: 400", r.status_code == 400 and "not a known kind" in r.get_json()["error"])
r = c.post("/api/kb/service/fields", json={"name": "scan6_rdp", "fields": [{"field": "rdp_protocol", "kind": "exact", "label": "Protocol"}]})
ok("a valid choice is saved (by the IPv6 name, for the IPv4 report)", r.status_code == 200 and r.get_json()["fields"][0]["label"] == "Protocol")
own = PAT.choice("scan_rdp")
ok("…signed and dated, with the fields known then (the feed's included)", own["by"] == "made-up-researcher" and "brand_new_field" in own["reviewed"])
ok("…the patterns are recounted", sintel.cache["key"] is None)
ok("…and audited", ctx["audit"].rows[-1][0] == "pattern_fields_set" and ctx["audit"].rows[-1][1]["target"] == "service:scan_rdp")
j = c.get("/api/kb/service/fields?name=scan_rdp").get_json()
ok("…now the researcher's choice", j["chosen_by"]["by"] == "made-up-researcher")
with open(PAT.paths["local"]) as f:
    d = json.load(f)
d["reports"]["scan_rdp"]["reviewed"] = ["rdp_protocol"]
with open(PAT.paths["local"], "w") as f:
    json.dump(d, f)
PAT._written("local")
asks = c.get("/api/kb/service?name=scan_rdp").get_json()["pattern_asks"]
ok("a field Shadowserver added after the choice: Looking Glass asks", any("Shadowserver added field brand_new_field" in a for a in asks), str(asks))
r = c.post("/api/kb/service/fields", json={"name": "scan_rdp", "reset": True})
ok("reset: back to the shipped fields, audited", r.status_code == 200 and PAT.choice("scan_rdp") is None
   and ctx["audit"].rows[-1][0] == "pattern_fields_reset")

print("Product rules")
ok("read with the Definitions permission", len(c.get("/api/kb/product-rules").get_json()["rules"]) == 2)
PERM["change"] = False
ok("adding without the right: 403", c.post("/api/kb/product-rules", json={}).status_code == 403)
PERM["change"], PERM["fresh"] = True, False
ok("…with an old sign-in: 403", c.post("/api/kb/product-rules", json={}).status_code == 403)
PERM["fresh"] = True
r = c.post("/api/kb/product-rules", json={"contains": "ab", "product": "X"})
ok("…text shorter than 3 characters: 400", r.status_code == 400 and "3 characters" in r.get_json()["error"])
r = c.post("/api/kb/product-rules", json={"contains": "192.0.2.7", "product": "X"})
ok("…text that is an address: 400", r.status_code == 400 and "host name, address" in r.get_json()["error"])
sintel.cache["key"] = "x"
r = c.post("/api/kb/product-rules", json={"contains": "Example-OS", "product": "ExampleOS", "version": 1})
ok("a valid rule is added first, audited, the patterns recounted", r.status_code == 200 and r.get_json()["rules"][0]["product"] == "ExampleOS"
   and sintel.cache["key"] is None and ctx["audit"].rows[-1][0] == "product_rule_added")

print("Titles, kinds and the Intel view")
ok("the sinkhole and issue parts keep their own names", api["title_of"](SINK) == SINK and api["title_of"](ISSUE) == ISSUE)
ok("a services report's title, 'IPv6 ' dropped", api["title_of"]("scan6_rdp") == "Accessible RDP" and api["title_of"]("scan6_ssh") == "Accessible SSH")
ok("a report of another section: its title from the map", api["title_of"]("event4_sinkhole") == "Sinkhole Events")
ok("…without a title in the map, the name itself", api["title_of"]("event6_sinkhole") == "event6_sinkhole")
ok("…an unknown name: itself", api["title_of"]("mystery_report") == "mystery_report")
ok("kinds: vulnerability, services, another section, other", (api["kind_of"]("scan6_ssh"), api["kind_of"]("scan_rdp"), api["kind_of"]("event4_sinkhole"),
                                                                api["kind_of"]("nope")) == ("Vulnerability reports", "Services reports", "Infections reports", "Other reports"))
v = api["view"]("scan6_rdp")
ok("the Intel view of a services report (through services_intel), its title and kind", v["base"] == "scan_rdp" and v["title"] == "Accessible RDP"
   and v["kind"] == "Services reports")
ok("…of an unknown one: nothing", api["view"]("nope") is None and api["base"]("nope") is None)
ok("services_intel gets the title and kind functions", sintel.title_of is api["title_of"] and sintel.kind_of is api["kind_of"])

print("Pattern values (svc_patterns)")
ok("product + version by a rule: '(MikroTik 7.24.4)' gives RouterOS 7.24.4", PAT.product("Welcome (MikroTik 7.24.4)") == "RouterOS 7.24.4")
ok("…a rule without a version, without a product name: the text looked for", PAT.product("banner ExampleSSH 2.0") == "ExampleSSH")
ok("…no rule matches: nothing", PAT.product("unknown banner") == "" and PAT.value("product", "unknown banner") == [])
ok("tags: lower case, CVEs left to Issues", PAT.value("tags", "RDP;CVE-2019-0708, Brute") == ["brute", "rdp"])
ok("exact: a value holding an address gives nothing", PAT.value("exact", "host 192.0.2.5") == [] and PAT.value("exact", "Example") == ["Example"])
ok("…an empty value or '-': nothing", PAT.value("exact", "-") == [] and PAT.value("exact", None) == [])
ok("template: a binary (hex) response stays as it is", PAT.value("template", "0xdeadbeef00") == ["0xdeadbeef00"])
ok("template: the address in a response masked", PAT.value("template", "Welcome to 192.0.2.5 server") and "192.0.2.5" not in PAT.value("template", "Welcome to 192.0.2.5 server")[0])
ok("an unknown kind: nothing", PAT.value("other", "x") == [])
ok("device_model: the product of a device_id record, else from its extras",
   SP.field_value({"report": "device_id", "product": "Cam X"}, "device_model") == "Cam X"
   and SP.field_value({"report": "scan_rdp", "extras": {"device_model": "M"}}, "device_model") == "M")
ok("items: label and value per pattern field", PAT.items("scan_rdp", EVS[0]) == [("RDP protocol", "rdp"), ("Tag", "rdp")], str(PAT.items("scan_rdp", EVS[0])))
s = {r_["field"]: r_ for r_ in PAT.suggest("device_id", [{"ip": "192.0.2.1", "report": "device_id", "product": "Cam", "extras": {"few": "v1"}},
                                                         {"ip": "192.0.2.2", "report": "device_id", "product": "Cam", "extras": {"few": "v1"}},
                                                         {"ip": "192.0.2.3", "report": "device_id", "product": "Cam", "extras": {"few": "v2"}}])}
ok("suggestions: a value shared by fewer than 5 hosts", "no value is shared by 5 hosts yet" in s["few"]["why"] and "device_model" in s)
try:
    PAT.save("scan_rdp", [{"field": "hostname", "kind": "exact"}], "u")
    ok("saving a field that names a host is refused", False)
except ValueError as e:
    ok("saving a field that names a host is refused", "names or locates a host" in str(e))
ok("the configuration is read again after it changes (mtime cache)", PAT.shipped()["noise"] == ["port"])

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
import shutil  # noqa: E402
shutil.rmtree(TMP, ignore_errors=True)
sys.exit(1 if fails else 0)
