#!/usr/bin/env python3
"""Shadowserver's one-off Special Reports (special_reports.py; review, 2026-11-13): both platforms' report discovery
skips them, so their placeholder timestamps (all rows at 00:00 of the day they were shared) never become a false spike
in the replay, the day's totals or the Executive 7-day comparison; the Overview lists them apart, counts only; and the
pipeline loads a "special-<name>" file into special_<name> instead of quarantining it.
Uses a throwaway mongod in a scratch folder (skipped where mongod is not installed); never touches the real database.
Run: .venv/bin/python tests/check_special_reports.py"""
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import special_reports as SR  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


print("Which collections are Special Reports")
for n, want in (("special", True), ("special_vmware_vcenter", True), ("special-loop-dos", True), ("Special", True),
                ("scan_http", False), ("event4_sinkhole_http", False), ("specialised", False), ("", False)):
    ok(f"{n!r} {'is' if want else 'is not'} special", SR.is_special(n) is want)
ok("a readable title: 'Special report: vmware vcenter'", SR.title("special_vmware_vcenter") == "Special report: vmware vcenter")

print("The pipeline names them, never quarantines them")
for d in ("../database", "../shadowserver"):
    p = os.path.abspath(os.path.join(HERE, d))
    if os.path.exists(os.path.join(p, "report_names.py")):
        sys.path.insert(0, p)
        import report_names as RN  # noqa: E402
        ok("special-vmware-vcenter -> special_vmware_vcenter, a valid report name",
           RN.canonical("special-vmware-vcenter") == "special_vmware_vcenter" and RN.valid(RN.canonical("special-vmware-vcenter")))
        ok("'special' itself stays 'special'", RN.canonical("special") == "special" and RN.valid("special"))
        ok("every other report name is unchanged", all(RN.canonical(x) == x for x in ("scan_http", "event4_sinkhole_http", "population_http")))
        break
else:
    print("  skip  the pipeline folder is not beside the platform")

mongod = shutil.which("mongod")
try:
    from pymongo import MongoClient
except ImportError:
    MongoClient = None
if not mongod or MongoClient is None:
    print("  skip  the registry and listing checks (no mongod or pymongo here)")
else:
    from services import ServiceRegistry  # noqa: E402
    from sources import Registry  # noqa: E402
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]
    tmp = tempfile.mkdtemp()
    proc = subprocess.Popen([mongod, "--dbpath", tmp, "--port", str(port), "--bind_ip", "127.0.0.1", "--quiet",
                             "--logpath", os.path.join(tmp, "mongod.log")], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        c = MongoClient(host="127.0.0.1", port=port, serverSelectionTimeoutMS=20000)
        c.admin.command("ping")
        db = c["lg_special_test"]
        # a Special Report: 300 rows, 120 hosts, every row at the placeholder midnight of the day it was shared
        db["special"].insert_many([{"filename": "2026-06-26-special-ghana-geo.csv", "ip": f"192.0.2.{i % 120}",
                                    "timestamp": "2026-06-26 00:00:00", "port": "443", "tag": "x"} for i in range(300)])
        db["special_loop_dos"].insert_many([{"filename": "2026-03-04-special-loop-dos-ghana-geo.csv", "ip": f"198.51.100.{i}",
                                             "timestamp": "2026-03-04 00:00:00"} for i in range(7)])
        # a normal daily services report and a communications report, as the platforms load them
        db["scan_http"].insert_many([{"filename": "2026-11-11-scan_http-ghana-geo.csv", "ip": f"203.0.113.{i}", "port": "80",
                                      "timestamp": f"2026-11-11 {i % 24:02d}:10:00"} for i in range(20)])
        db["special_comms"].insert_one({"filename": "2026-06-26-special-comms-ghana-geo.csv", "src_ip": "192.0.2.9",
                                        "dst_ip": "203.0.113.9", "timestamp": "2026-06-26 00:00:00"})
        sreg = ServiceRegistry(db)
        # discovered = supported or "not supported yet" (a test record has few fields); skipped = never looked at
        names = {e["name"] for e in sreg._build()} | {e["name"] for e in getattr(sreg, "_unsupported_next", [])}
        ok("services platform: a normal report is discovered", "scan_http" in names, str(names))
        ok("services platform: Special Reports are not (no replay, totals or baseline)", not any(SR.is_special(n) for n in names), str(names))
        creg = Registry(db)
        cnames = {e["name"] for e in creg._build()} | {e["name"] for e in getattr(creg, "_unsupported_next", [])}
        ok("map platform: a special report with source and destination is not discovered either", "special_comms" not in cnames, str(cnames))
        rows = {r["report"]: r for r in SR.listing(db, force=True)}
        sp = rows.get("special", {})
        ok("the Overview listing counts the special report's rows and distinct hosts (300, 120)", (sp.get("rows"), sp.get("hosts")) == (300, 120), str(sp))
        ok("…dated by the day it was shared (the file prefix)", sp.get("shared") == "2026-06-26", str(sp))
        ok("…and shows the placeholder: the same time on every row", sp.get("first") == sp.get("last") == "2026-06-26 00:00:00", str(sp))
        ok("every special collection is listed (special, special_loop_dos, special_comms)", {"special", "special_loop_dos", "special_comms"} <= set(rows), str(set(rows)))
        ok("the listing holds counts only, never an address", all("192.0.2" not in str(v) and "198.51" not in str(v) for v in rows.values()))
        ok("normal reports are not in the special listing", "scan_http" not in rows)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            proc.kill()
        time.sleep(0.5)
        shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
