#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A CVE's description shown as a title is its first sentence WHOLE, never cut mid-word (cves.short_title; the user's
rule: text in full. 2026-11-15 the Executive portal showed "...found in OpenSSH before 9.6 an" from a 90-character cut).
Abbreviations and version numbers do not end the sentence; a description with no sentence end is given whole. The
Executive portal and the insight panel use it. No database needed. Run: .venv/bin/python tests/check_cve_titles.py"""
import os
import sys

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
from cves import short_title  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


ssh = ("The SSH transport protocol with certain OpenSSH extensions, found in OpenSSH before 9.6 and other products, allows "
       "remote attackers to bypass integrity checks such that some packets are omitted. This is the Terrapin attack.")
t = short_title(ssh)
ok("the first sentence, whole (never '...before 9.6 an')", t.endswith("some packets are omitted.") and "9.6 and other products" in t, t)
ok("…and nothing of the second sentence", "Terrapin" not in t)
vm = "VMware ESXi, Workstation, and Fusion contain a heap-overflow vulnerability in the PVSCSI (paravirtualized SCSI) controller that allows an out-of-bounds write. A malicious actor with local administrative privileges on a virtual machine may exploit it."
ok("brackets inside the sentence are kept: '...the PVSCSI (paravirtualized SCSI) controller...'",
   short_title(vm).endswith("an out-of-bounds write.") and "(paravirtualized SCSI)" in short_title(vm), short_title(vm))
ok("'e.g.' does not end the sentence", short_title("Some servers, e.g. Apache HTTP Server, mishandle headers. More text.")
   == "Some servers, e.g. Apache HTTP Server, mishandle headers.")
ok("'Inc.' does not end it either", short_title("A flaw in Example Inc. Router firmware lets anyone in. Second.") == "A flaw in Example Inc. Router firmware lets anyone in.")
ok("a version number ('2.4.58') does not end it", short_title("Apache before 2.4.58 crashes on long headers. Fixed later.") == "Apache before 2.4.58 crashes on long headers.")
long_one = "word " * 120 + "end"
ok("no sentence end at all: the whole description, however long (the page wraps it)", short_title(long_one) == long_one.strip())
ok("empty or missing: empty", short_title(None) == "" and short_title("   ") == "")
ok("spaces and line breaks are tidied", short_title("Two   spaces\nand a break.") == "Two spaces and a break.")
# app.py's code includes the parts moved into their own modules (2026-11-24), read as written there (no _A. prefix)
APP_PARTS = ("app.py", "analytics_api.py", "report_downloads.py", "infection_kb.py", "lookup_jobs.py", "card_notes.py",
             "name_definitions.py", "intel_match_api.py")
for f, needle in (("management.py", "short_title(c.get(\"description\"))"), ("app.py", "short_title(x.get(\"description\"))")):
    parts = APP_PARTS if f == "app.py" else (f,)
    src = "\n".join(open(os.path.join(HERE, p), encoding="utf-8").read().replace("_A.", "") for p in parts
                    if os.path.exists(os.path.join(HERE, p)))
    ok(f"{f} uses it instead of a 90-character cut", needle in src and '(c.get("description") or "")[:90]' not in src
       and '(x.get("description") or "")[:90]' not in src)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
