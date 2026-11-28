#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The constituency's AS numbers and addresses in one form on both sides (settings.py, count audit 2026-11-26):
"AS064500" was accepted and stored as "064500", which never matches the "64500" the reports write, with no error, so
that network's hosts were silently out of scope. Proved with Settings.validate and in_scope on made-up values; a
throwaway settings file only. Run: .venv/bin/python tests/check_scope_normalise.py"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for k in ("CONSTITUENT_ASNS", "CONSTITUENT_CIDRS"):
    os.environ.pop(k, None)
import settings as S  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


print("validate: AS numbers stored as the reports write them")
clean, errs = S.Settings.validate({"country": "GH", "networks": ["AS064500", "as 64501", " 64502 ", "0064502", 64503],
                                   "cidrs": []})
ok("'AS064500' -> '64500', 'as 64501' -> '64501', copies once, no error",
   clean["networks"] == ["64500", "64501", "64502", "64503"] and errs == [], (clean["networks"], errs))
clean, errs = S.Settings.validate({"country": "GH", "networks": ["AS-1", "4294967296", "²"], "cidrs": []})
ok("not AS numbers are refused, each named (also one beyond 32 bits, or a superscript digit)",
   clean["networks"] == [] and len(errs) == 3, (clean["networks"], errs))
clean, errs = S.Settings.validate({"country": "GH", "networks": [], "cidrs": ["::ffff:10.0.0.0/104", " 192.0.2.0/24 "]})
ok("an IPv4 range written as IPv6 is stored as the IPv4 range", clean["cidrs"] == ["10.0.0.0/8", "192.0.2.0/24"] and not errs,
   (clean["cidrs"], errs))

print("in_scope: either side's spelling matches")
d = tempfile.mkdtemp(prefix="lg-scope-")
path = os.path.join(d, "settings.json")
# a file saved by an earlier version, with the zero-padded number it stored
json.dump({"country": "GH", "networks": ["064500"], "cidrs": ["192.0.2.0/24", "::ffff:198.51.100.0/120"]}, open(path, "w"))
st = S.Settings(path)
for asn in ("64500", 64500, "AS64500", "as64500", " 64500", "064500", "AS 64500"):
    ok(f"AS number {asn!r} is in the constituency", st.in_scope(asn, ""), repr(st.asns))
ok("another AS number is not", not st.in_scope("64501", "") and not st.in_scope("AS64501", ""))
for ip in ("192.0.2.7", " 192.0.2.7 ", "::ffff:192.0.2.7", "198.51.100.9", "::ffff:198.51.100.9"):
    ok(f"address {ip!r} is in the constituency", st.in_scope("", ip))
ok("an address outside is not, nor something that is not an address",
   not st.in_scope("", "203.0.113.1") and not st.in_scope("", "::ffff:203.0.113.1") and not st.in_scope("", "x"))
st.save({"country": "GH", "timezone": st.data["timezone"], "networks": ["AS064501"], "cidrs": []})
ok("saved through validate's output or not: the stored form still matches '64501'", st.in_scope("64501", ""))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
