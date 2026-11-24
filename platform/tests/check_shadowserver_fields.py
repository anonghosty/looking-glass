#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Shadowserver's fields put to use (2026-11-23). No database, no network; temporary folders only.
- readable labels: static/data/field_labels.json labels every field of every report the report map knows, short,
  no em dash; field_labels.label() and the pages' lg-fields.js read it, an unknown field falls back to plain words;
  the three pages that show report fields load lg-fields.js
- Shadowserver's own mapping of an event (ss_attack.py): techniques and tactics by ID (MITRE's names when the local
  copy has them), the CVE with its CVSS, the device targeted; nothing for a record without them; the map's events
  carry it (sources.normalise); the Definitions page's counts per report (Seen); MITRE tactics in the ATT&CK index
- certificate and TLS facts (tls_facts.py): expired, self-signed, valid, trusted, SSLv3, TLS 1.3; the masked view
  gives no dates and no browser error text (it can name the host)
- exports (export_fields.py): every pattern-analysis field of intel.py has a combination CSV column; the all-fields
  rows leave out Looking Glass's internals and say when they stop
Run: .venv/bin/python tests/check_shadowserver_fields.py"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import export_fields  # noqa: E402
import field_labels  # noqa: E402
import offline_names  # noqa: E402
import sources  # noqa: E402
import ss_attack  # noqa: E402
import tls_facts  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + (f"  [{str(info)[:300]}]" if info != "" else ""))
    if not cond:
        fails.append(label)


print("Readable labels")
doc = json.load(open(os.path.join(HERE, "static", "data", "field_labels.json"), encoding="utf-8"))
labels = doc.get("labels") or {}
ok("the label file has labels", len(labels) >= 700, len(labels))
rm = os.path.join(HERE, "data", "report_map.json")
if os.path.isfile(rm):
    facts = json.load(open(rm, encoding="utf-8")).get("facts") or {}
    fields = {f for v in facts.values() if isinstance(v, dict) for f in (v.get("fields") or [])}
    missing = sorted(fields - set(labels))
    ok("every field of every report in the report map has a label", not missing, missing[:12])
ok("labels are short names (32 characters at most), none empty", all(0 < len(v) <= 32 for v in labels.values()),
   [k for k, v in labels.items() if not 0 < len(v) <= 32][:5])
ok("no em or en dash in any label", not any(("—" in v or "–" in v) for v in labels.values()))
ok("label(): the file's words", field_labels.label("ip_header_urg") == labels.get("ip_header_urg") and "URG" in field_labels.label("ip_header_urg"))
ok("label(): x:name is looked up by its name", field_labels.label("x:jarm") == labels.get("jarm"))
ok("label(): an unknown field falls back to plain words", field_labels.label("made_up_new_field") == "Made up new field")
js = open(os.path.join(HERE, "static", "js", "lg-fields.js"), encoding="utf-8").read()
ok("lg-fields.js reads the same file and falls back the same way", "/static/data/field_labels.json" in js and 'replace(/_/g, " ")' in js)
for tpl in ("index.html", "services.html", "intelligence.html"):
    t = open(os.path.join(HERE, "templates", tpl), encoding="utf-8").read()
    ok(f"{tpl} loads lg-fields.js before its page script", "js/lg-fields.js" in t)
for f, needle in (("app.js", "LGFields.label"), ("services.js", "LGFields.label"), ("intelligence.js", "LGFields.label")):
    ok(f"{f} labels the report's fields with it", needle in open(os.path.join(HERE, "static", "js", f), encoding="utf-8").read())
src = open(os.path.join(HERE, "intelligence.py"), encoding="utf-8").read()
ok("Abused or Compromised: column labels and CSV headers in readable words", src.count("field_labels.label(k)") >= 2)

print("Shadowserver's own mapping of an event")
row = {"threat_framework": "MITRE ATT&CK", "threat_tactic_id": "TA0001;TA0002", "threat_technique_id": "T1190;T1059;bogus;T1190",
       "vulnerability_enum": "CVE", "vulnerability_id": "cve-2023-28771", "vulnerability_class": "CVSS", "vulnerability_score": "9.8",
       "vulnerability_severity": "CRITICAL", "vulnerability_version": "3.1", "target_vendor": "Zyxel", "target_product": "ZyWALL",
       "target_class": "router"}
m = ss_attack.for_row(row)
ok("techniques: valid IDs once each, in order", [t["id"] for t in m["techniques"]] == ["T1190", "T1059"], m["techniques"])
ok("…each with MITRE's link", all(t["url"].startswith("https://attack.mitre.org/techniques/") for t in m["techniques"]))
ok("tactics by ID, with MITRE's link", [t["id"] for t in m["tactics"]] == ["TA0001", "TA0002"]
   and m["tactics"][0]["url"] == "https://attack.mitre.org/tactics/TA0001/")
ok("the CVE in capitals, with its CVSS score and severity", m["vulnerability"]["id"] == "CVE-2023-28771" and m["vulnerability"]["is_cve"]
   and m["vulnerability"]["score"] == "9.8" and m["vulnerability"]["severity"] == "Critical")
ok("the device targeted", m["target"] == {"vendor": "Zyxel", "product": "ZyWALL", "class": "router"})
ok("a list as well as a ';' string", [t["id"] for t in ss_attack.for_row({"threat_technique_id": ["T1046", "t1595.002"]})["techniques"]] == ["T1046", "T1595.002"])
ok("a record without the fields: nothing", ss_attack.for_row({"tag": "http-scan"}) is None and ss_attack.for_row({"threat_technique_id": ""}) is None)
ok("one line for CSVs and PDFs", ss_attack.summary(m).startswith("T1190") and "CVE-2023-28771 (CVSS 9.8)" in ss_attack.summary(m)
   and ss_attack.summary(m).endswith("targets Zyxel ZyWALL (router)"), ss_attack.summary(m))
ok("…a target with a class only reads cleanly", ss_attack.summary(ss_attack.for_row({"target_class": "router"})) == "targets router")
names = os.path.join(HERE, "data", "names_attack.json")
if os.path.isfile(names):
    techs = json.load(open(names, encoding="utf-8")).get("techniques") or {}
    if "T1190" in techs:
        ok("MITRE's name from the local ATT&CK copy", m["techniques"][0]["name"] == techs["T1190"]["name"] and m["techniques"][0]["known"])
reg = {"name": "event4_honeypot_ikev2_scan", "label": "Honeypot IKEv2 Scan", "class": "Scanning", "layout": "standard"}
ev = sources.normalise(dict(row, src_ip="192.0.2.10", timestamp="2026-11-22T10:00:00", tag="ikev2-scan"), reg)
ok("the map's event carries it (sources.normalise)", (ev.get("ss_attack") or {}).get("vulnerability", {}).get("id") == "CVE-2023-28771")
ok("…and keeps the raw fields in extras", (ev.get("extras") or {}).get("threat_technique_id") == "T1190;T1059;bogus;T1190")
ev2 = sources.normalise({"src_ip": "192.0.2.11", "timestamp": "2026-11-22T10:00:00", "tag": "rdp-scan"}, reg)
ok("…an event without them carries none", "ss_attack" not in ev2)
app_js = open(os.path.join(HERE, "static", "js", "app.js"), encoding="utf-8").read()
ok("the map's detail window shows it as Shadowserver's, apart from Looking Glass's suggestion",
   "Shadowserver's mapping for this event" in app_js and "ssAttackSection" in app_js)


class Day:
    def __init__(self, by_src):
        self.by_src = by_src


class Store:
    def __init__(self, days):
        self.days = days


day = Day({"event4_honeypot_ikev2_scan": {"rows": [ev, ev, ev2]}, "event4_sinkhole": {"rows": [ev]}})
seen = ss_attack.Seen(Store({1: day}), lambda: {"event4_honeypot_ikev2_scan": {"fields": ["threat_technique_id"]},
                                               "event4_sinkhole": {"fields": ["src_ip"]}})
s = seen.get()
ok("Definitions: per report, the techniques Shadowserver tagged its events with, counted",
   [(t["id"], t["count"]) for t in s["techniques"]["event4_honeypot_ikev2_scan"]] == [("T1059", 2), ("T1190", 2)]
   and s["events"]["event4_honeypot_ikev2_scan"] == 2, s)
ok("…only reports whose schema has the field are read", "event4_sinkhole" not in s["techniques"])
am_src = open(os.path.join(HERE, "attack_map.py"), encoding="utf-8").read()
ok("…sent with GET /api/attack, never changing a mapping", "ss_seen=ss_seen" in am_src)
ok("…and drawn on the Definitions page", "data.ss_seen" in open(os.path.join(HERE, "static", "js", "attack-map.js"), encoding="utf-8").read())
bundle = {"objects": [{"type": "x-mitre-tactic", "name": "Initial Access",
                       "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001", "url": "https://attack.mitre.org/tactics/TA0001"}]},
                      {"type": "x-mitre-tactic", "name": "Old", "revoked": True,
                       "external_references": [{"source_name": "mitre-attack", "external_id": "TA0099", "url": "https://attack.mitre.org/tactics/TA0099"}]}]}
idx = offline_names.build_attack({"enterprise": bundle})
ok("the ATT&CK index keeps MITRE's tactics by ID (revoked ones left out)", idx.get("tactics", {}).get("TA0001", {}).get("name") == "Initial Access"
   and "TA0099" not in idx.get("tactics", {}), idx.get("tactics"))

print("Certificate and TLS facts")
ex = {"cert_expiration_date": "2025-01-02 10:00:00", "self_signed": "Y", "cert_valid": "N", "browser_trusted": "N",
      "browser_error": "x509: certificate is valid for a.example, not b.example", "sslv3_supported": "Y", "tlsv13_support": "N"}
f = {x["key"]: x for x in tls_facts.facts(ex, "2026-11-22T10:00:00")}
ok("expired before the scan, with the date", f["expires"]["value"].startswith("Expired on 2025-01-02") and f["expires"]["flag"])
ok("self-signed, not valid, not trusted, SSLv3 on: marked", all(f[k]["flag"] for k in ("self_signed", "valid", "trusted", "sslv3")))
ok("TLS 1.3 as a plain fact, not marked", f["tlsv13"]["value"] == "Not supported" and not f["tlsv13"]["flag"])
ok("the browser's reason (unmasked)", "browser_error" in f)
fm = {x["key"]: x for x in tls_facts.facts(ex, "2026-11-22T10:00:00", dates=False)}
ok("masked view: expired yes/no, no date", fm["expires"]["value"] == "Yes" and not re.search(r"\d{4}-\d{2}", json.dumps(list(fm.values()))))
ok("masked view: no browser error text (it can name the host)", "browser_error" not in fm)
ok("a certificate still valid when scanned", tls_facts.facts({"cert_expiration_date": "Mar  5 12:00:00 2027 GMT"}, "2026-11-22 10:00:00")[0]["value"]
   == "2027-03-05 (still valid when scanned)")
ok("no TLS fields: no facts", tls_facts.facts({"tag": "x"}, None) == [])
sa = open(os.path.join(HERE, "services_api.py"), encoding="utf-8").read()
ok("the services detail sends them, masked viewers without dates", "tls_facts.facts(ex," in sa and "dates=not demo" in sa)
ok("…and the window shows them", "Certificate and TLS" in open(os.path.join(HERE, "static", "js", "services.js"), encoding="utf-8").read())

print("Exports")
import intel  # noqa: E402
cols = {k for _, k in export_fields.COMMS_PATTERN_COLS + export_fields.SVC_PATTERN_COLS}
import combos  # noqa: E402
cols |= {k for _, k in combos.COMMS_COLS + combos.SVC_COLS}
want = {w for _, w in intel.COMMS_FIELDS + intel.SVC_FIELDS
        if not w.startswith(("beacon:", "tags:")) and w not in ("vp", "family", "application", "tag")}
ok("every pattern-analysis field of intel.py has a combination CSV column", want <= cols, sorted(want - cols))
names_ = [c for c, _ in export_fields.COMMS_PATTERN_COLS + export_fields.SVC_PATTERN_COLS]
ok("new column names are stable snake_case, none clashing with the old ones",
   all(re.match(r"^[a-z0-9_]+$", c) for c in names_) and not set(names_) & {c for c, _ in combos.COMMS_COLS + combos.SVC_COLS})
recs = [dict(ev, _t=1, _id="x", src_ref="r1", id="9"), dict(ev2, _t=2)]
rows, cut = export_fields.all_fields_rows(recs, "infections")
ok("all-fields: one line per field with its label", rows and len(rows[0]) == len(export_fields.ALL_FIELDS_HEAD) and not cut
   and any(r[4] == "threat_technique_id" and r[5] == field_labels.label("threat_technique_id") for r in rows))
ok("…no Looking Glass internals (_t, _id, id, references)", not any(r[4] in ("_t", "_id", "id", "src_ref", "ss_attack", "extras") for r in rows))
old = export_fields.ALL_FIELDS_MAX
export_fields.ALL_FIELDS_MAX = 5
rows, cut = export_fields.all_fields_rows(recs, "infections")
export_fields.ALL_FIELDS_MAX = old
ok("…stops at the limit and says so", cut and len(rows) == 5)
cs = open(os.path.join(HERE, "combos.py"), encoding="utf-8").read()
ok("the combination ZIP writes the all-fields file and says when it was cut", "_all_fields.csv" in cs and "Stopped at" in cs)

print(f"\n{checks - len(fails)} of {checks} Shadowserver field checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
