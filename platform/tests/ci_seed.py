#!/usr/bin/env python3
"""A made-up week of reports for the checks that need report data (the GitHub checks' throwaway MongoDB; review of
d82a436: check_combos, check_combo_review, check_acodes, check_management and check_ticked_names ran only on servers).

Documentation addresses only (RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), private AS numbers (RFC 6996:
64500-64511), made-up names. Nothing here is real data. For each of the last 8 days: three communications reports
(devices calling sinkholes, an HTTP sinkhole, a honeypot) and four services reports (HTTP, RDP, SSH, Telnet), with
devices seen in several reports, several infections on a device, and CVEs on hosts; the indexes the pipeline makes.

It writes into MONGO_DB (default shadowserver) on the server of tests/_throwaway_mongo.py, and refuses a database that
already holds report rows (never on a real installation's data).
Usage: python tests/ci_seed.py [--days 8]"""
import datetime as dt
import hashlib
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _throwaway_mongo  # noqa: E402

DAYS = int(sys.argv[sys.argv.index("--days") + 1]) if "--days" in sys.argv else 8
COMMS = ("event4_sinkhole", "event4_sinkhole_http", "event4_honeypot_brute_force")
SERVICES = ("scan_http", "scan_rdp", "scan_ssh", "scan_telnet")
INFECTIONS = ("examplebot", "samplerat", "demoloader", "testworm", "mockminer")
REGIONS = (("GREATER ACCRA", "ACCRA"), ("ASHANTI", "KUMASI"), ("NORTHERN", "TAMALE"), ("WESTERN", "TAKORADI"), ("VOLTA", "HO"))
CVES = ("CVE-2023-44487", "CVE-2021-44228", "CVE-2024-3400", "CVE-2022-1388")
ROW_INDEX = [("filename", 1), ("category", 1), ("line_hash", 1)]


def hosts():
    out = [f"192.0.2.{i}" for i in range(1, 255)] + [f"203.0.113.{i}" for i in range(1, 255)]
    return out


def main():
    if os.environ.get("LG_CI_SEED") != "1":                 # never by accident on an installation
        print("REFUSED: ci_seed.py writes made-up reports; it runs only with LG_CI_SEED=1 (the GitHub checks set it)")
        return 2
    client = _throwaway_mongo.client(os.environ.get("MONGO_HOST", "127.0.0.1"), os.environ.get("MONGO_PORT", 27017))
    if client is None:
        print("SKIPPED: no MongoDB account that may write (tests/_throwaway_mongo.py)")
        return 77
    db = client[os.environ.get("MONGO_DB", "shadowserver")]
    if any(db[c].estimated_document_count() for c in COMMS + SERVICES if c in db.list_collection_names()):
        print("REFUSED: this database already holds report rows; ci_seed.py writes only into an empty one")
        return 2
    rnd = random.Random(20261115)
    H = hosts()
    today = dt.datetime.now(dt.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    total = 0
    for back in range(DAYS, -1, -1):
        day = today - dt.timedelta(days=back)
        ds = day.strftime("%Y-%m-%d")
        per = {c: [] for c in COMMS + SERVICES}
        for i, ip in enumerate(H[:300]):
            region, city = REGIONS[i % len(REGIONS)]
            # not i % 12: the CVEs go to every sixth device, so each CVE pair fell in ONE network and the checks of
            # several organisations (check_combo_review) had one to pick from (2026-11-17)
            asn = 64500 + (i // 3) % 12
            infections = [INFECTIONS[i % 5]] + ([INFECTIONS[(i + 2) % 5]] if i % 4 == 0 else [])
            reports = [COMMS[0]] + ([COMMS[1]] if i % 3 == 0 else []) + ([COMMS[2]] if i % 7 == 0 else [])
            for rep in reports:
                for inf in infections:
                    t = day + dt.timedelta(seconds=rnd.randint(0, 86399))
                    # what a device keeps doing varies, so each name has several combinations, each shared by 5+ devices:
                    # the C2 it calls (RFC 2606 example domains), its client, its tags
                    c2 = ("c2-a.example.com", "c2-b.example.net", "c2-c.example.org")[i % 3]
                    per[rep].append({"timestamp": t.strftime("%Y-%m-%d %H:%M:%S"), "extracted_date": t.replace(tzinfo=None),
                                     "src_ip": ip, "src_port": rnd.randint(1024, 65000), "src_asn": asn, "src_geo": "GH",
                                     "src_region": region, "src_city": city, "dst_ip": f"198.51.100.{1 + i % 250}",
                                     "dst_port": (80, 8080, 443)[i % 3] if rep != COMMS[2] else 22, "dst_asn": 64511, "dst_geo": "US",
                                     "infection": inf if rep != COMMS[2] else "",
                                     "tag": "ssh-brute-force" if rep == COMMS[2] else ("botnet" if i % 2 else "botnet;loader"),
                                     "severity": "medium" if rep != COMMS[2] else "high", "protocol": "tcp",
                                     "http_host": c2 if rep == COMMS[1] else "", "dst_hostname": c2 if rep == COMMS[0] else "",
                                     "http_url": "/gate.php" if rep == COMMS[1] else "",
                                     "http_agent": ("Mozilla/5.0 (made-up A)", "Mozilla/5.0 (made-up B)")[i % 2] if rep == COMMS[1] else "",
                                     "family": inf if rep != COMMS[2] else ""})
            if i % 2 == 0:                                          # every other device also exposes services
                for j, rep in enumerate(SERVICES):
                    if (i + j) % 3:
                        continue
                    t = day + dt.timedelta(seconds=rnd.randint(0, 86399))
                    tags = [rep.split("_")[1]] + ([CVES[i % len(CVES)], CVES[(i + 1) % len(CVES)]] if i % 6 == 0 else []) \
                        + (["openssl"] if i % 4 == 0 else [])
                    per[rep].append({"timestamp": t.strftime("%Y-%m-%d %H:%M:%S"), "extracted_date": t.replace(tzinfo=None),
                                     "ip": ip, "port": {"scan_http": 80, "scan_rdp": 3389, "scan_ssh": 22, "scan_telnet": 23}[rep],
                                     "asn": asn, "geo": "GH", "region": region, "city": city, "protocol": "tcp",
                                     "hostname": "", "sector": "Communications", "severity": "high" if len(tags) > 1 else "medium",
                                     "tag": ";".join(tags), "http_server": "ExampleServer/1.0" if rep == "scan_http" else ""})
        for rep, rows in per.items():
            if not rows:
                continue
            fn = f"{ds}-{rep}-example-geo.csv"
            for k, r in enumerate(rows):
                r.update(filename=fn, category=rep, line_hash=hashlib.sha256(f"{fn}|{k}".encode()).hexdigest())
            db[rep].insert_many(rows, ordered=False)
            total += len(rows)
    for rep in COMMS + SERVICES:
        db[rep].create_index(ROW_INDEX, unique=True)
        db[rep].create_index([("ip", 1), ("filename", 1)], name="ip_filename", partialFilterExpression={"ip": {"$exists": True}})
    print(f"made-up rows written: {total} in {len(COMMS + SERVICES)} reports, {DAYS + 1} days, into {db.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
