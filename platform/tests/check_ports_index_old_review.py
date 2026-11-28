#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Reviewers' findings, production release 2026-11-26, on made-up records in memory (tests/madeup_days.py; no
database, nothing of the installation read or written):

1. The ports index (services_intel host_ports / ports_text, the devices CSVs' "all ports and services"): a host's
   ports gathered across all its services records are every one (47 here, none cut, nothing "..."), each once, the
   lowest first (tcp before udp on one number), each with every report that found it; records without a port count
   none; the text holds no address, so a masked viewer gets none with it.
2. An old review (a combination review kept before 2026-11-19, its stored device flags without "ports"; and one kept
   before 2026-11-18, without "levels" either): combos.device_flags, as the review page, its PDF and its CSV call it,
   fills in what is missing without failing, and every figure equals a freshly made review's for the same devices.
Run: .venv/bin/python tests/check_ports_index_old_review.py"""
import os
import re
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "tests"))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


import app as A  # noqa: E402
import madeup_days as M  # noqa: E402
import services_intel as SI  # noqa: E402

IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])|2001:db8:[0-9a-f:]*", re.I)
http, ssl, misc = M.svc_source("scan_http", "HTTP"), M.svc_source("scan_ssl", "SSL/TLS", "Vulnerable"), M.svc_source("scan_misc", "Misc")
H1, H2, H3 = "192.0.2.80", "192.0.2.81", "2001:db8::81"
base = {"asn": "64500", "geo": "GH", "region": "GREATER ACCRA", "city": "ACCRA", "severity": "high"}
svc, want = [], {}
for n in range(45):                                   # 45 ports on one host, given in a mixed order, two cases of protocol
    port = 5000 - n * 97
    proto = "UDP" if n % 3 == 0 else "tcp"
    svc.append((misc, dict(base, ip=H1, port=port, protocol=proto, tag="vulnerable")))
    want.setdefault(f"{port}/{proto.lower()}", set()).add("scan_misc")
for src in (http, ssl):                               # one port found by two reports, and the same number on udp
    svc.append((src, dict(base, ip=H1, port=443, protocol="tcp", tag="cve-2024-0001")))
want["443/tcp"] = {"scan_http", "scan_ssl"}
svc.append((http, dict(base, ip=H1, port=443, protocol="udp")))
want["443/udp"] = {"scan_http"}
svc.append((http, dict(base, ip=H1, port="", protocol="tcp")))      # no port: counts none
svc.append((http, dict(base, ip=H1, port="0", protocol="tcp")))
for ip in (H2, H3):
    svc.append((ssl, dict(base, ip=ip, port=443, protocol="tcp", tag="ssl-freak;cve-2015-0204", severity="medium")))
    svc.append((http, dict(base, ip=ip, port=8080, protocol="tcp", tag="vulnerable")))
sink = M.comms_source("event4_sinkhole_http", "Sinkhole HTTP")
comms = [(sink, {"src_ip": H2, "src_asn": "64500", "src_geo": "GH", "dst_ip": "198.51.100.7", "dst_port": 80,
                 "infection": "examplebot", "severity": "critical", "protocol": "tcp"})]
info = M.install(A, comms=comms, svc=svc)
day = info["start"].date().isoformat()
SV = A.SVC_INTEL

print("1. The ports index")
flags = SV.host_flags([H1, H2, H3], day)
text = flags[H1]["ports"]
parts = [p for p in text.split("; ") if p]
got = {}
for p in parts:
    port, _, titles = p.partition(" ")
    got[port] = set(titles.split(", "))
titled = {p: {SV.title_of(SI.sibling(r)) for r in rs} for p, rs in want.items()}
ok(f"every port of the host is named ({len(want)}), each once, none cut", len(parts) == len(want) == len(got) and set(got) == set(want)
   and "…" not in text and "..." not in text, (len(parts), len(want), sorted(set(want) - set(got))[:4]))
order = [(int(p.split("/")[0]), p.split("/")[1]) for p in got]
ok("…the lowest port first, tcp before udp on one number", [k.split(" ")[0] for k in parts] == [f"{a}/{b}" for a, b in sorted(order)], parts[:5])
ok("…each with every report that found it (443/tcp: HTTP and SSL/TLS)", got == titled, {k: (got.get(k), v) for k, v in titled.items() if got.get(k) != v})
ok("…records without a port count none", not any(p.startswith(("0/", "/")) for p in got))
ok("the ports text holds no address (nothing of a host for a masked viewer)", not any(IP.search(f[h]["ports"]) for f in (flags,) for h in f),
   [f for f in flags.values() if IP.search(f["ports"])][:1])
ok("…another host's own ports only", flags[H2]["ports"].startswith("443/tcp") and "8080/tcp" in flags[H2]["ports"]
   and "5000" not in flags[H2]["ports"], flags[H2]["ports"])

print("2. An old review: kept before the ports (2026-11-19) and before the levels (2026-11-18)")
days_of = {h: [day] for h in (H1, H2, H3)}
fresh = A.COMBOS.device_flags("services", days_of, day)
ok("a fresh review works out every figure, ports included", all(fresh[h].get("ports") for h in days_of) and fresh[H2]["infections"] == ["examplebot"],
   {h: sorted(v) for h, v in fresh.items()})
before_ports = {h: {k: v for k, v in fresh[h].items() if k != "ports"} for h in (H1, H2)}          # H3: none kept at all
before_levels = {h: {k: fresh[h][k] for k in ("infections", "issues", "cves")} for h in (H1, H2, H3)}
for name, kept in (("kept before the ports", before_ports), ("kept before the levels too", before_levels)):
    try:
        out, err = A.COMBOS.device_flags("services", days_of, day, kept), ""
    except Exception as e:                                       # noqa: BLE001
        out, err = {}, f"{type(e).__name__}: {e}"
    ok(f"{name}: opened without failing", not err and set(out) == set(days_of), err)
    diff = {h: {k: (out.get(h, {}).get(k), fresh[h].get(k)) for k in fresh[h] if (out.get(h) or {}).get(k) != fresh[h].get(k)}
            for h in days_of if (out.get(h) or {}) != fresh[h]}
    ok(f"{name}: every figure (ports, levels, infections, issues, CVEs) equals a fresh review's", not diff, diff)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
