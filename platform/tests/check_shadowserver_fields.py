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
  CSV stays removed (2026-11-24)
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
# the page files that ship: the held copies in $LG_HELD_DIR when there are; node runs lg-fields.js on the same file
sys.path.insert(0, os.path.join(HERE, "tests"))
import html.parser  # noqa: E402

import jinja2  # noqa: E402
import page_harness as PH  # noqa: E402

sample = sorted(labels)[::max(1, len(labels) // 60)] + ["x:jarm", "made_up_new_field", "ip_header_urg", "x:made_up", "_lead", "plain", ""]
if PH.NODE:
    R, raw = PH.run(r"""
const DOC = JSON.parse(process.argv[1]).doc, asked = [];
const myFetch = async (url) => { asked.push(String(url)); return { ok: true, status: 200, json: async () => DOC }; };
((fetch) => {""" + PH.page_src("lg-fields.js") + r"""})(myFetch);
(async () => { const early = LGFields.label("ip_header_urg"); await LGFields.ready;
  console.log(JSON.stringify({ asked, early, got: JSON.parse(process.argv[1]).keys.map((k) => LGFields.label(k)) })); })();
""", {"doc": doc, "keys": sample})
    R = R or {}
    want = [field_labels.label(k) for k in sample]
    diff = [(k, g, w) for k, g, w in zip(sample, R.get("got") or [], want) if g != w]
    ok("lg-fields.js reads the same file (once)", R.get("asked") == ["/static/data/field_labels.json"], str(R.get("asked")) if R else raw[-300:])
    ok(f"...and labels every field as field_labels.label() does ({len(sample)} fields, unknown and x: names among them)",
       len(R.get("got") or []) == len(sample) and not diff, diff[:6])
    ok("...before the file has arrived: plain words, never the raw name", R.get("early") == "Ip header urg", str(R.get("early")))
else:
    PH.no_node(ok, "node is there to run the page")


def _held_tpl(name):
    p = os.path.join(PH.HELD, name + ".new") if PH.HELD else ""
    src = p if p and os.path.isfile(p) else os.path.join(HERE, "templates", name)
    return (open(src, encoding="utf-8").read(), src, lambda: True) if os.path.isfile(src) else None


class _Blank(jinja2.ChainableUndefined):          # what the app would fill in: empty, and callable like its helpers
    def __call__(self, *a, **k):
        return self


class _Scripts(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.srcs = []

    def handle_starttag(self, tag, attrs):
        if tag == "script" and dict(attrs).get("src"):
            self.srcs.append(dict(attrs)["src"].rsplit("/", 1)[-1].split("?")[0])


_env = jinja2.Environment(loader=jinja2.FunctionLoader(_held_tpl), undefined=_Blank, autoescape=True)
_env.globals.update(url_for=lambda ep, filename="", **k: f"/{ep}/{filename}", csrf_token=lambda: "t")
_env.filters["tojson"] = lambda v, *a, **k: jinja2.utils.markupsafe.Markup(json.dumps(None if isinstance(v, jinja2.Undefined) else v, default=str))
ALL_PERMS = {"view", "unmasked", "export", "malpedia", "services", "intelligence", "research", "analyst", "settings", "users"}
for tpl, script in (("index.html", "app.js"), ("services.html", "services.js"), ("intelligence.html", "intelligence.js")):
    try:
        p = _Scripts()
        p.feed(_env.get_template(tpl).render(lg_perms=ALL_PERMS))
        names, why = p.srcs, ""
    except Exception as e:      # noqa: BLE001 - a page that does not render is the failure itself
        names, why = [], f"{type(e).__name__}: {e}"
    ok(f"{tpl} (rendered) loads lg-fields.js before {script}", "lg-fields.js" in names and script in names
       and names.index("lg-fields.js") < names.index(script), why or names)
for f in ("app.js", "services.js", "intelligence.js"):
    ok(f"{f} (as it ships) labels the report's fields with it", "LGFields.label" in PH.page_src(f))
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
# the link is MITRE's own (from the local ATT&CK copy, which the installer downloads: no trailing slash) or, without
# that copy, the same page's address built by Looking Glass (with one); both open MITRE's page of that tactic
ok("tactics by ID, with MITRE's link", [t["id"] for t in m["tactics"]] == ["TA0001", "TA0002"]
   and m["tactics"][0]["url"].rstrip("/") == "https://attack.mitre.org/tactics/TA0001", m["tactics"][:1])
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
app_js = PH.page_src("app.js")
R = None
if PH.NODE:
    R, raw = PH.run(PH.extract(app_js, ["el", "ssAttackSection"]) + r"""
const s = ssAttackSection(JSON.parse(process.argv[1]));
console.log(JSON.stringify({ text: lines(s), links: s.querySelectorAll("a").map((a) => [a.textContent, a.href, a.rel]) }));
""", m)
if PH.NODE:
    R = R or {}
    txt = R.get("text") or []
    ok("the map's detail window (node runs ssAttackSection) shows it as Shadowserver's, apart from Looking Glass's suggestion",
       txt[:1] == ["Shadowserver's mapping for this event"] and any("Looking Glass's own suggestion" in t for t in txt), txt[:3])
    ok("...the techniques, tactics, CVE with its score and the device targeted, in words",
       {"ATT&CK techniques", "ATT&CK tactics", "Vulnerability", "Device targeted", "Zyxel ZyWALL · router"} <= set(txt)
       and any(t.startswith("CVSS") and "9.8" in t and "Critical" in t for t in txt), txt)
    links = R.get("links") or []
    ok("...each technique and the CVE open MITRE's and cve.org's own pages, in a new tab without the opener",
       any(h == "https://www.cve.org/CVERecord?id=CVE-2023-28771" for _t, h, _r in links)
       and any(h.startswith("https://attack.mitre.org/techniques/T1190") for _t, h, _r in links) and all(r == "noopener noreferrer" for *_x, r in links), links)
else:
    PH.no_node(ok, "node runs the map's detail window (ssAttackSection)")


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
ok("…and drawn on the Definitions page (as it ships)", "data.ss_seen" in PH.page_src("attack-map.js"))
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
ok("…and the window shows them (as it ships)", "Certificate and TLS" in PH.page_src("services.js"))

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
# the all-fields CSV was removed (2026-11-24): nothing writes it or reads its limit any more
cs = open(os.path.join(HERE, "combos.py"), encoding="utf-8").read()
ok("the all-fields CSV stays removed: no all-fields code, file or limit",
   not hasattr(export_fields, "all_fields_rows") and "_all_fields.csv" not in cs
   and "LG_ALL_FIELDS_MAX_LINES" not in open(os.path.join(HERE, "export_fields.py"), encoding="utf-8").read())

print(f"\n{checks - len(fails)} of {checks} Shadowserver field checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
