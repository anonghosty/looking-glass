#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Agentic AI attack frameworks in the Device Identification report (the user, 2026-11-17; Shadowserver began reporting
them on 2026-11-16 as device type ai-attack-framework, severity high). Made-up records only, no database needed:
1. a device_id row of that type is an issue, "AI attack framework", on the services platform (flagged, filterable)
2. an ordinary device (a router) is not; the tags' issues are unchanged; the type is matched however it is written
3. the issue has its definition (data/issues.json), the report's description names it, and the live checks' own
   copies of the issue rules (tests/mongo_derive.py, tests/verify_svc_stats.py) know it too
Run: .venv/bin/python tests/check_ai_framework.py"""
import json
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import issue_tags  # noqa: E402
import services  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


SRC = {"name": "device_id", "label": "Device identification", "family": "Identified device"}


def row(**k):
    base = {"ip": "192.0.2.10", "port": "443", "protocol": "tcp", "asn": "64500", "geo": "ZZ", "severity": "high",
            "tag": "", "device_vendor": "ExampleVendor", "device_type": "ai-attack-framework", "device_model": "ExampleFramework",
            "timestamp": "2026-11-17 01:00:00"}
    base.update(k)
    return services.normalise_service(base, SRC)


print("1. The issue")
r = row()
ok("an ai-attack-framework device is the issue 'AI attack framework', flagged", r["issues"] == ["AI attack framework"] and r["vulnerable"], str(r["issues"]))
ok("... with its severity, vendor and framework (the model) kept as the report gives them",
   (r["severity"], r["vendor"], r["product"], r["device_type"]) == ("high", "ExampleVendor", "ExampleFramework", "ai-attack-framework"))
ok("... matched however the type is written", row(device_type=" AI-Attack-Framework ")["issues"] == ["AI attack framework"])
ok("... once, beside the tags' own issues", row(tag="exposed-admin-panel")["issues"] == ["Exposed admin panel", "AI attack framework"])

print("2. Nothing else changes")
ok("an ordinary device (a router) is no issue", row(device_type="router", severity="info")["issues"] == [])
ok("a device with no type is no issue", row(device_type="")["issues"] == [])
ok("the type is not taken for a tag", issue_tags.issue_of("ai-attack-framework") == "" and issue_tags.device_type_issue("router") == "")

print("3. Definitions and the live checks")
issues = json.load(open(os.path.join(HERE, "data", "issues.json"), encoding="utf-8"))["issues"]
d = issues.get("AI attack framework") or {}
ok("the issue has its definition, with what to do and Shadowserver's report as the reference",
   d.get("description") and d.get("action") and any("device-identification-report" in u for u in d.get("references", [])))
ok("... which never calls the host a victim or its network's owner its operator",
   "not a victim" in d.get("description", "") and "owner" not in d.get("description", "").lower())
rep = json.load(open(os.path.join(HERE, "data", "service_reports.json"), encoding="utf-8"))
rep = rep.get("reports", rep)
ok("the Device Identification report's description names the new type", "ai-attack-framework" in rep["device_id"]["def"])
for f in ("mongo_derive.py", "verify_svc_stats.py"):
    src = open(os.path.join(HERE, "tests", f), encoding="utf-8").read()
    ok(f"the live check's own issue rules know it ({f})", '"ai-attack-framework"' in src and '"AI attack framework"' in src)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
