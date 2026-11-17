#!/usr/bin/env python3
"""What masked viewers (role external, demo mode) receive for each record (privacy.py; security test of v2026.11.17.4).
Made-up records only, no database needed:
1. the report's file name: its date and report type only; the part naming the organisation and filters is gone
2. the record id: one per record and the same on every request, but not the database record
3. the map's events (mask_event) and the services platform (services_api) both apply it; the services details
   request takes the masked id back; analysts (unmasked) keep both as they are
Run: .venv/bin/python tests/check_masked_ids.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import privacy as P  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


class Asns:
    def alias(self, a):
        return "Telco 3"


print("1. The report's file name")
for name, want in [("2026-11-16-event4_sinkhole_http-123-ghana-geo.csv", "2026-11-16-event4_sinkhole_http"),
                   ("2026-11-16-scan_http-lakeside-asn.csv", "2026-11-16-scan_http"),
                   ("2024-07-04-dns_openresolver-123-sample-asn.csv", "2024-07-04-dns_openresolver"),
                   ("2020-04-03-scan_ics-sample-asn-delayed.csv", "2020-04-03-scan_ics"),
                   ("not a report file name", ""), ("", ""), (None, "")]:
    got = P.masked_filename(name)
    ok(f"{name!r} -> {want!r}", got == want, got)

print("2. The record id")
a, b = P.masked_id("event4_sinkhole_http:6af057df07deb331a94d6915"), P.masked_id("event4_sinkhole_http:6af057df07deb331a94d6916")
ok("not the database record, nor any part of it", a.startswith("ev-") and "6af057df" not in a and "sinkhole" not in a, a)
ok("one per record (two records, two ids)", a != b)
ok("the same on every request (the page keys its list, pins and highlight on it)", a == P.masked_id("event4_sinkhole_http:6af057df07deb331a94d6915"))
ok("an empty id stays empty", P.masked_id("") == "" and P.masked_id(None) == "")
P.HostRefs("a-test-secret")
ok("made under the server's REF_SECRET, like the host labels (another secret, another id)",
   P.masked_id("event4_sinkhole_http:6af057df07deb331a94d6915") != a)

print("3. Where it is applied")
ev = {"id": "event4_sinkhole_http:6af057df07deb331a94d6915", "filename": "2026-11-16-event4_sinkhole_http-lakeside-asn.csv",
      "src_ip": "192.0.2.7", "dst_ip": "198.51.100.9", "src_asn": "64501", "dst_asn": "64502", "http_url": "", "_id": "x",
      "event_id": "y", "line_hash": "z"}
mv = P.mask_event(ev, Asns())
ok("the map's masked event: file name and id masked", mv["filename"] == "2026-11-16-event4_sinkhole_http"
   and mv["id"] == P.masked_id(ev["id"]) and "lakeside" not in str(mv) and "6af057df" not in str(mv), str({k: mv[k] for k in ("id", "filename")}))
ok("... the other ids still removed", not any(k in mv for k in ("_id", "event_id", "line_hash")))
ok("an analyst's (unmasked) event is untouched by masking", ev["filename"].endswith("lakeside-asn.csv") and ev["id"].startswith("event4_"))
src = open(os.path.join(HERE, "services_api.py"), encoding="utf-8").read()
ok("the services platform masks the id for masked viewers", 'out["id"] = masked_id(e["id"])' in src)
ok("... and its details request takes the masked id back", 'masked_id(x["id"]) == eid' in src)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
