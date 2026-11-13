#!/usr/bin/env python3
"""One address finder for every masker (ip_find.py; external review, 2026-11-12). The reviewer's five spellings that
escaped one masker or the other must be masked by BOTH: the researchers' (hostmask.mask, privacy.partial_mask_text)
and the masked viewers' (host_label.label_text); things that are not addresses must stay.
Run: .venv/bin/python tests/check_ip_find.py"""
import os
import re
import sys
import time

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
         ("[2001:db8::7]:443", "2001:db8::7"),
         # IPv4-mapped IPv6 (review 2026-11-13: only "::ffff:41" was masked, ".66.1.2" was left): the IPv4 host itself
         ("::ffff:41.66.1.2", "41.66.1.2"), ("x ::FFFF:41.66.1.2 y", "41.66.1.2"), ("[::ffff:41.66.1.2]:80", "41.66.1.2"),
         ("ip:::ffff:41.66.1.2:443", "41.66.1.2"), ("0:0:0:0:0:ffff:41.66.1.2", "41.66.1.2"),
         ("::ffff:041.066.001.002", "41.66.1.2"), ("fe80::41.66.1.2", "41.66.1.2")]
# what may be left after masking: never a run of three dotted numbers (an address, or most of one), never a piece of
# the IPv6 addresses (the test fails on any leftover, not only when nothing was found)
DOTTED = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}")
RAW6 = ("2001:db8", "db8::")
print("The reviewer's spellings, and a few more, through every masker")
for text, ip in LEAKS:
    found = [s[2] for s in ip_find.spans(text)]
    ok(f"found in {text!r}", ip in found, str(found))
    hm, lab, part = hostmask.mask(text), host_label.label_text(text), privacy.partial_mask_text(text)
    for who, out in (("researchers (hostmask)", hm), ("masked viewers (label)", lab), ("threat values (partial)", part)):
        left = DOTTED.findall(out) + [p for p in RAW6 if p in out]
        ok(f"…nothing left for {who}: {out!r}", not left, str(left))
    ok(f"…masked viewers see a host label: {lab!r}", "Host " in lab)
print("IPv4-mapped is the same host as the IPv4")
ok("::ffff:41.66.1.2 and 41.66.1.2 get the same label",
   host_label.label_text("::ffff:41.66.1.2") == host_label.label_text("41.66.1.2"))
print("Long runs of colons cost little (review 2026-11-13: 3,000 colons took 6.9 s)")
for name, s in (("8,000 colons", ":" * 8000), ("value= and 8,000 colons", "value=" + ":" * 8000 + "1"),
                ("4,000 '1:'", "1:" * 4000), ("2,000 '::ffff:'", "::ffff:" * 2000), ("2,000 '1.1:'", "1.1:" * 2000),
                # long runs of dots too (CodeQL py/polynomial-redos, 2026-11-13: these took time with the square of the length)
                ("50,000 dots", "." * 50000), ("25,000 'a.'", "a." * 25000), ("25,000 '1.'", "1." * 25000)):
    t0 = time.perf_counter()
    ip_find.spans(s); hostmask.mask(s); host_label.label_text(s)
    took = time.perf_counter() - t0
    ok(f"{name}: {took:.3f} s, under 0.5 s for all three maskers", took < 0.5)
print("Leading zeros are the same host")
ok("041.066.001.002 and 41.66.1.2 get the same label", host_label.label_text("041.066.001.002") == host_label.label_text("41.66.1.2"))
print("Not addresses: left alone")
for text in ("nginx/1.18.0", "version 1.2.3.4.5", "10:22:31", "ratio 3:2:1", "999.1.1.1", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"):
    ok(f"{text!r} has no address", not ip_find.spans(text), str(ip_find.spans(text)))
print("Four-part versions the text names as versions: kept by every masker (review follow-up)")
for text in ("version 2.0.1.3", "Build: 1.2.3.4", "firmware=10.4.0.12", "Server: Apache/2.0.1.3 (Unix)",
             "RouterOS/6.49.10.1", "rev. 3.1.0.2", "nginx/1.18.0.1", "(OpenSSH/8.9.1.1)"):
    ok(f"{text!r} has no address", not ip_find.spans(text), str(ip_find.spans(text)))
    ok(f"…and stays for researchers: {hostmask.mask(text)!r}", hostmask.mask(text) == text)
    ok(f"…and for masked viewers: {host_label.label_text(text)!r}", "Host " not in host_label.label_text(text))
print("…but an address near such words is still masked")
for text, ip in (("/api/41.66.1.2", "41.66.1.2"), ("version41.66.1.2", "41.66.1.2"), ("x/41.66.1.2", "41.66.1.2"),
                 ("GET http://41.66.1.2/", "41.66.1.2"), ("http://example.org/41.66.1.2", "41.66.1.2"),
                 ("host 41.66.1.2 version 2.0.1.3", "41.66.1.2"), ("v41.66.1.2", "41.66.1.2")):
    found = [s[2] for s in ip_find.spans(text)]
    ok(f"found in {text!r}", found == [ip], str(found))
print("…and after a word and a slash in a value, with a port, or too large to be a version (review 2026-11-13)")
for text, ip in (("url=word/203.0.113.7", "203.0.113.7"), ("q=path/203.0.113.7:80", "203.0.113.7"),
                 ("u=x?y=word/203.0.113.7", "203.0.113.7"), ("word/203.0.113.7", "203.0.113.7"),
                 ("proxy/41.66.1.2 up", "41.66.1.2"), ("word/203.0.113.7:8080", "203.0.113.7"), ("a@b/41.66.1.2", "41.66.1.2"),
                 # re-check 2026-11-13: low first numbers are addresses too (Amazon 3.x, private 10.x, Google 8.8.8.8)
                 ("Location: proxy/3.120.4.5", "3.120.4.5"), ("gw/10.0.0.1", "10.0.0.1"), ("relay/8.8.8.8", "8.8.8.8"),
                 ("via cdn/13.107.4.52", "13.107.4.52")):
    found = [s[2] for s in ip_find.spans(text)]
    ok(f"found in {text!r}", found == [ip], str(found))
    ok(f"…masked for researchers: {hostmask.mask(text)!r}", ip not in hostmask.mask(text))
    ok(f"…and for masked viewers: {host_label.label_text(text)!r}", ip not in host_label.label_text(text))
print("A five-part number: one rule in both maskers (left alone)")
for text in ("1.2.3.4.5", "build 1.2.3.4.5 ok"):
    ok(f"researchers keep {text!r}: {hostmask.mask(text)!r}", hostmask.mask(text) == text)
    ok(f"masked viewers keep {text!r}: {host_label.label_text(text)!r}", host_label.label_text(text) == text)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
