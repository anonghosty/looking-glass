#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Patterns for the services reports (svc_patterns.py, services_intel.py, the services_kb.py pattern APIs).

1. svc_patterns: products and versions read from responses (MikroTik, Cisco SSH, OpenSSH, brackets); templates mask
   host names but keep binary responses; tags are read as a set without CVEs; fields that name a host are never
   pattern fields; a researcher's choice wins and can be taken back; a product rule may not hold a host name; a
   researcher's rules come first. (In a throwaway folder.)
2. Against the days in memory: the hosts per report match; every pattern value, combination and cross-report pattern
   shown is shared by at least 5 hosts, and free text by hosts in at least 2 networks; the sinkhole figure matches a
   count made here from the communications records.
3. Researchers never see a host: no constituent address, host name or e-mail in any report's patterns.
4. Only the Definitions permission may read; choosing pattern fields needs the right to change them, and a field that
   names a host is refused.
Usage: tests/check_svc_patterns.py"""
import collections
import json
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import logging  # noqa: E402
logging.disable(logging.WARNING)
import hostmask  # noqa: E402
import svc_patterns as SP  # noqa: E402
from report_map import sibling  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print("1. svc_patterns")
tmp = tempfile.mkdtemp(prefix="lg_patterns_")
try:
    os.makedirs(os.path.join(tmp, "data"))
    for f in ("pattern_fields.json", "product_rules.json"):
        shutil.copy(os.path.join(BASE, "data", f), os.path.join(tmp, "data", f))
    P = SP.Patterns(tmp)
    cases = [("220 FTP server (MikroTik 7.24.4) ready", "MikroTik RouterOS 7.24.4"), ("SSH-2.0-Cisco-1.25", "Cisco SSH 1.25"),
             ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", "OpenSSH 9.6p1"), ("RouterOS RB5009UG+S+ 7.24.2 (stable)", "MikroTik RouterOS 7.24.2"),
             ("Cisco IOS Software, Version 15.5(3)S4b, RELEASE", "Cisco IOS 15.5(3)S4b"), ("Apache/2.4.52 (Ubuntu)", "Apache httpd 2.4.52"),
             ("220 mail.example.org ESMTP Postfix (Ubuntu)", "Postfix"), ("something unknown", ""),
             ("ntpd 4.2.8p15@1.3728-o Wed Jun 23 10:22:31 UTC 2021 (1)", "ntpd 4.2.8p15")]
    bad = [(t, P.product(t), w) for t, w in cases if P.product(t) != w]
    ok("products and versions read from responses", not bad, "; ".join(f"{t!r} -> {g!r}" for t, g, _ in bad[:3]))
    ok("a template masks the host name, keeps the software", P.value("template", "220 mail.example.org ESMTP Postfix") == ["220 <host> ESMTP Postfix"])
    ok("…a value that is only a host name gives nothing", P.value("template", "vpn.agency.example") == [])
    ok("…a binary (hex) response stays as it is", P.value("template", "32ff0004000000000000") == ["32ff0004000000000000"])
    ok("tags are a set, without the CVEs", P.value("tags", "iot;Mikrotik;cve-2023-1234;winbox;iot") == ["iot", "mikrotik", "winbox"])
    ok("fields that name or locate a host are never pattern fields", all(P.never(f) for f in ("ip", "hostname", "sysname", "mac_address", "cert_valid_from", "src_ip")))
    try:
        P.save("scan_snmp", [{"field": "sysname", "kind": "exact"}], "lg-selftest"); refused = False
    except ValueError:
        refused = True
    ok("…and saving one is refused", refused)
    P.save("scan6_snmp", [{"field": "community", "kind": "exact", "label": "Community"}], "lg-selftest", ["community", "sysdesc"])
    ok("a researcher's choice wins (made on the IPv6 report, kept for both)", [f["field"] for f in P.fields_for("scan_snmp")] == ["community", "tag"]
       and P.choice("scan6_snmp")["by"] == "lg-selftest")
    P.reset("scan_snmp")
    ok("…and can be taken back to the shipped one", "sysdesc" in [f["field"] for f in P.fields_for("scan_snmp")])
    try:
        P.add_rule("router.example.org", "X", True, "lg-selftest"); refused = False
    except ValueError:
        refused = True
    ok("a product rule may not hold a host name", refused)
    P.add_rule("Acme-OS", "Acme OS", True, "lg-selftest")
    ok("a researcher's rule is tried first", P.product("Acme-OS 2.1 Linux 5.4") == "Acme OS 2.1")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

import app as A  # noqa: E402
from flask import g  # noqa: E402


def call(path, perms, method="GET", body=None):
    kw = {"method": method}
    if body is not None:
        kw.update(data=json.dumps(body), content_type="application/json")
    with A.app.test_request_context(path, **kw):
        g.user = {"user": "lg-selftest-patterns", "role": "x", "perms": set(perms), "csrf": None}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        return code, r.get_data(as_text=True)


now = A.replay_now()
A.svc["store"].get(now); A.store.get(now)
sv = [e for d in A.svc["store"].days.values() for e in d.events]
cm = [e for d in A.store.days.values() for e in d.events]
if not sv:
    print("SKIPPED: no services records in memory"); sys.exit(77)
R = {"definitions"}
code, body = call("/api/kb/services", R)
reports = [r["name"] for r in json.loads(body)["reports"] if r["hosts"]]
print(f"2. Against the days in memory ({len(reports)} reports with hosts)")
per_hosts = collections.defaultdict(set)
for e in sv:
    per_hosts[sibling(e["report"])].add(e["ip"])
infected = {e["src_ip"] for e in cm if e.get("src_ip") and e.get("infection")}
low = lambda s: str(s or "").strip().lower().rstrip(".")
constituent = ({low(e.get("hostname")) for e in sv} | {low((e.get("extras") or {}).get(k)) for e in sv for k in ("subject_common_name", "issuer_common_name")})
threat = {low(e.get(k)) for e in cm for k in ("http_host", "dst_hostname", "ssl_servername")}
constituent = {x for x in constituent if x and "." in x} - threat
ips = {e["ip"] for e in sv} | {e.get("src_ip") for e in cm if e.get("src_ip")}
email_rx = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
bad_hosts, small, nets_bad, sink_bad, leaks = [], 0, 0, [], []
answers = {}
for name in reports:
    c, b = call(f"/api/kb/service/intel?name={name}", R)
    d = json.loads(b); answers[name] = d
    if d["hosts"] != len(per_hosts[name]):
        bad_hosts.append(name)
    for p in d["patterns"]:
        small += sum(1 for v in p["values"] if v["hosts"] < 5)
    small += sum(1 for x in d["combinations"] if x["hosts"] < 5) + sum(1 for x in d["across"]["cross_patterns"] if x["hosts"] < 5)
    want_sink = len(per_hosts[name] & infected)
    if d["sinkholes"]["hosts"] != want_sink:
        sink_bad.append(f"{name}: {d['sinkholes']['hosts']} vs {want_sink}")
    # free text in two networks: recount the networks of each template value shown
    tmpl = {p["label"]: {v["value"] for v in p["values"]} for p in d["patterns"] if p["kind"] == "template"}
    if tmpl:
        seen = collections.defaultdict(set)
        for e in sv:
            if sibling(e["report"]) != name:
                continue
            for lbl, v in A.PATTERNS.items(name, e):
                if v in tmpl.get(lbl, ()):
                    seen[(lbl, v)].add(e.get("asn"))
        nets_bad += sum(1 for k, s in seen.items() if len(s - {None, ""}) < 2)
    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, str):
            t = low(v)
            if (t in constituent and hostmask.mask(t) != t) or t in ips or email_rx.search(v):
                leaks.append(name)
    walk(d)
ok("hosts per report match the records in memory", not bad_hosts, ", ".join(bad_hosts[:5]))
ok("every value, combination and cross-report pattern shown is shared by at least 5 hosts", small == 0, f"{small} on fewer")
ok("free text shown is seen in at least 2 networks", nets_bad == 0, f"{nets_bad} value(s) in one network")
ok("the hosts also calling botnet sinkholes are counted right", not sink_bad, "; ".join(sink_bad[:3]))
print("3. Researchers never see a host")
ok(f"no constituent address, host name or e-mail in the patterns of {len(answers)} reports", not leaks, ", ".join(sorted(set(leaks))[:5]))
ok("…checked against the records in memory", len(ips) > 0, f"{len(ips):,} addresses, {len(constituent):,} host / certificate names")
print("4. Who may read and choose")
for label, perms in (("a viewer", {"view"}), ("management", {"management"})):
    c1 = call(f"/api/kb/service/intel?name={reports[0]}", perms)[0]; c2 = call(f"/api/kb/service/fields?name={reports[0]}", perms)[0]
    ok(f"{label} is refused", c1 == 403 and c2 == 403, f"{c1}/{c2}")
c, b = call("/api/kb/service/fields", {"view"}, "POST", {"name": "scan_snmp", "fields": [{"field": "sysdesc", "kind": "template"}]})
ok("choosing pattern fields needs the right to change them", c == 403, f"HTTP {c}")
c, b = call("/api/kb/service/fields?name=scan_snmp", R)
sug = {s["field"]: s for s in json.loads(b)["suggestions"]} if c == 200 else {}
ok("the suggestions grey out fields that name a host", (not sug.get("sysname")) or not sug["sysname"]["may"], "sysname")

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
