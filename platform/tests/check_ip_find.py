#!/usr/bin/env python3
"""One address finder for every masker (ip_find.py; external review, 2026-11-12). The reviewer's five spellings that
escaped one masker or the other must be masked by BOTH: the researchers' (hostmask.mask, privacy.partial_mask_text)
and the masked viewers' (host_label.label_text); things that are not addresses must stay.
Run: .venv/bin/python tests/check_ip_find.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import host_label  # noqa: E402
import hostmask  # noqa: E402
import ip_find  # noqa: E402
import privacy  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""))


LEAKS = [("v41.66.1.2", "41.66.1.2"), ("ip:2001:db8::1", "2001:db8::1"), ("id_41.66.1.2", "41.66.1.2"),
         ("041.066.001.002", "41.66.1.2"), ("app.41.66.1.2.nip.io", "41.66.1.2"),
         ("GET http://41.66.1.2:8080/x", "41.66.1.2"), ("from 41.66.1.2.", "41.66.1.2"),
         ("[2001:db8::7]:443", "2001:db8::7"), ("::ffff:41.66.1.2", "::ffff:2942:102")]
print("The reviewer's spellings, and a few more, through every masker")
for text, ip in LEAKS:
    found = [s[2] for s in ip_find.spans(text)]
    ok(f"found in {text!r}", ip in found or (ip.startswith("::ffff") and found), str(found))
    hm, lab, part = hostmask.mask(text), host_label.label_text(text), privacy.partial_mask_text(text)
    raw_parts = ["41.66.1.2", "041.066", "2001:db8::1", "2001:db8::7", "41.66.1"]
    ok(f"…masked for researchers (hostmask): {hm!r}", not any(p in hm for p in raw_parts))
    ok(f"…masked for masked viewers (label): {lab!r}", "Host " in lab and not any(p in lab for p in raw_parts))
    ok(f"…partly masked in threat values: {part!r}", not any(p in part for p in raw_parts))
print("Leading zeros are the same host")
ok("041.066.001.002 and 41.66.1.2 get the same label", host_label.label_text("041.066.001.002") == host_label.label_text("41.66.1.2"))
print("Not addresses: left alone")
for text in ("nginx/1.18.0", "version 1.2.3.4.5", "10:22:31", "ratio 3:2:1", "999.1.1.1", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"):
    ok(f"{text!r} has no address", not ip_find.spans(text), str(ip_find.spans(text)))
print("Four-part versions the text names as versions: kept by every masker (review follow-up)")
for text in ("version 2.0.1.3", "Build: 1.2.3.4", "firmware=10.4.0.12", "Server: Apache/2.0.1.3 (Unix)",
             "RouterOS/6.49.10.1", "rev. 3.1.0.2"):
    ok(f"{text!r} has no address", not ip_find.spans(text), str(ip_find.spans(text)))
    ok(f"…and stays for researchers: {hostmask.mask(text)!r}", hostmask.mask(text) == text)
    ok(f"…and for masked viewers: {host_label.label_text(text)!r}", "Host " not in host_label.label_text(text))
print("…but an address near such words is still masked")
for text, ip in (("/api/41.66.1.2", "41.66.1.2"), ("version41.66.1.2", "41.66.1.2"), ("x/41.66.1.2", "41.66.1.2"),
                 ("GET http://41.66.1.2/", "41.66.1.2"), ("http://example.org/41.66.1.2", "41.66.1.2"),
                 ("host 41.66.1.2 version 2.0.1.3", "41.66.1.2"), ("v41.66.1.2", "41.66.1.2")):
    found = [s[2] for s in ip_find.spans(text)]
    ok(f"found in {text!r}", found == [ip], str(found))
print("A five-part number: one rule in both maskers (left alone)")
for text in ("1.2.3.4.5", "build 1.2.3.4.5 ok"):
    ok(f"researchers keep {text!r}: {hostmask.mask(text)!r}", hostmask.mask(text) == text)
    ok(f"masked viewers keep {text!r}: {host_label.label_text(text)!r}", host_label.label_text(text) == text)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
