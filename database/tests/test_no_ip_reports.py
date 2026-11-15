"""Reports without an IP address (2026-11-14): Compromised Account, Ransomware Victim and Sandbox-DNS carry no address,
and may reach a CSIRT through a domain filter (file names ending -domain, not -geo). Their files must be recognised,
sorted under their own report name and read row by row like any other report; the ordinary -geo names are unchanged.
The sample rows are made up, with the field names of Shadowserver's published schema. Run: python3 tests/test_no_ip_reports.py"""
import csv, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import shadowserver_pipeline as sp  # noqa: E402

fails, n = [], 0


def ok(label, cond, info=""):
    global n
    n += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


SAMPLES = {
    "compromised_account": (["timestamp", "severity", "email", "username", "service", "status", "public_source", "source_url", "detail", "infection", "tag"],
                            ["2026-11-13 04:00:00", "critical", "someone@example.org", "someone", "webmail", "", "leak-1", "", "", "", "stealer"]),
    "ransomware_victim": (["timestamp", "severity", "entity_name", "website", "sector", "geo", "region", "ransomware", "leak_site_url", "date_published",
                           "actor_geo_stats_30d", "actor_total_stats_30d"],
                          ["2026-11-13 05:00:00", "info", "Example Ltd", "example.org", "Manufacturing", "XX", "", "examplelocker", "", "2026-11-12", "1", "40"]),
    "sandbox_dns": (["timestamp", "severity", "request", "request_type", "response", "family", "md5", "sha1", "sha256", "source", "tag"],
                    ["2026-11-13 06:00:00", "", "bad.example.org", "A", "192.0.2.1", "examplebot", "0" * 32, "0" * 40, "0" * 64, "sandbox", ""]),
}

print("File names")
for name in ("2026-11-13-compromised_account-ghana-domain.csv", "2026-11-13-compromised_account-123-ghana-domain.csv",
             "2026-11-13-ransomware_victim-ghana-geo.csv", "2026-11-13-sandbox_dns-ghana-domain.csv",
             "2026-11-13-sandbox_dns-ghana-asn.csv", "2026-11-13-sandbox_dns-ghana-netblock.csv"):
    m = sp.SERVICE_RE.match(name)
    want = name.split("-")[3]
    ok(f"{name} is sorted as {want}", bool(m) and m.group(1) == want, m.group(1) if m else "no match")
for name, want in (("2026-11-10-scan_http-ghana-geo.csv", "scan_http"), ("2026-11-10-scan_http-123-south-africa-geo.csv", "scan_http"),
                   ("2026-11-10-event4_sinkhole_http-ghana-geo_as1234.csv", "event4_sinkhole_http"),
                   ("2026-11-10-special-badbox-ghana-geo.csv", "special")):
    m = sp.SERVICE_RE.match(name)
    ok(f"unchanged: {name} -> {want}", bool(m) and m.group(1) == want, m.group(1) if m else "no match")
for name in ("2026-11-13-sandbox_dns-ghana.csv", "notes.csv", "2026-11-13-sandbox_dns-ghana-domainx.csv"):
    ok(f"still not a report file: {name}", not sp.SERVICE_RE.match(name))

print("Rows")
tmp = tempfile.mkdtemp(prefix="noip-")
for rep, (head, row) in SAMPLES.items():
    p = os.path.join(tmp, f"2026-11-13-{rep}-ghana-domain.csv")
    with open(p, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(head); w.writerow(row); w.writerow(row)
    info = {}
    docs = list(sp.iter_csv_docs(p, os.path.basename(p), rep, info=info))
    ok(f"{rep}: its rows are read (no IP needed), duplicates dropped", len(docs) == 1 and docs[0]["category"] == rep and "ip" not in docs[0],
       f"{len(docs)} doc(s)")
    ok(f"{rep}: dated from its timestamp, like every report", docs and docs[0].get("extracted_date") is not None and info.get("headers") == head)
import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{n - len(fails)} of {n} no-IP report checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
