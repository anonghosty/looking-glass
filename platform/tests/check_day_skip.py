#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The fields a day load leaves out (2026-11-17: app.DayStore._fetch_collection skips sources.INTERNAL, services._fetch
skips services.SKIP) must be fields the platform throws away anyway. Made-up records carrying every skipped field and
the usual ones are normalised whole and without the skipped fields: the results must be identical, for every report
layout. If a change starts reading or showing one of them, this fails: take it off the skip list.
No database. Run: .venv/bin/python tests/check_day_skip.py"""
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import services as SV  # noqa: E402
import sources as SO  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


T = datetime(2026, 11, 16, 8, tzinfo=timezone.utc)
COMMON = {"_id": "row1", "extracted_date": T, "filename": "2026-11-16-example.csv", "timestamp": T, "logged_date": T,
          "line_hash": "a" * 64, "hostname_source": "ptr", "sic": "1234", "src_sic": "5678", "dst_sic": "9012"}
COMMS = {**COMMON, "src_ip": "192.0.2.10", "src_geo": "ZZ", "src_city": "Example City", "src_asn": "64500", "dst_ip": "198.51.100.7",
         "dst_geo": "YY", "dst_port": "443", "infection": "example-bot", "tag": "example", "severity": "high",
         "http_url": "/a/b", "http_agent": "Example/1.0", "ip": "192.0.2.11", "geo": "ZZ", "type": "example-type",
         "http_referer_ip": "203.0.113.5", "something_else": "kept as an extra"}
SERVICE = {**COMMON, "ip": "192.0.2.20", "port": "8080", "protocol": "tcp", "asn": "64501", "geo": "ZZ", "city": "Example City",
           "severity": "critical", "tag": "cve-2026-0001;vulnerable", "device_vendor": "Example", "device_type": "router",
           "device_model": "X1", "version": "1.2", "ssl_poodle": "Y", "server": "example-httpd", "banner": "kept as an extra"}

skip_comms = {k for k in SO.INTERNAL if k != "_id"}
print("Communications (sources.normalise), every layout")
for layout in ("standard", "legacy", "referer", "inbound", "target"):
    src = {"name": "event4_example", "label": "Example", "layout": layout, "class": "Example", "family": "Example"}
    whole = SO.normalise(dict(COMMS), src)
    trimmed = SO.normalise({k: v for k, v in COMMS.items() if k not in skip_comms}, src)
    ok(f"{layout}: the same record without {', '.join(sorted(skip_comms))}", whole == trimmed)

print("Services (services.normalise_service)")
for fam in ("Vulnerable", "Compromised"):
    src = {"name": "scan_example", "label": "Example", "family": fam}
    whole = SV.normalise_service(dict(SERVICE), src)
    trimmed = SV.normalise_service({k: v for k, v in SERVICE.items() if k not in SV.SKIP}, src)
    ok(f"{fam}: the same record without {', '.join(sorted(SV.SKIP))}", whole == trimmed)
ok("_id and extracted_date are never skipped (row id, event time)",
   not ({"_id", "extracted_date"} & (set(SV.SKIP) | skip_comms)))
ok("... and the extras are still there (nothing else left out)",
   SV.normalise_service(dict(SERVICE), {"name": "s", "label": "S", "family": "Vulnerable"})["extras"].get("banner") == "kept as an extra")

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
