#!/usr/bin/env python3
"""Addresses inside free text (banners, requests, extra fields) become "Host <reference>" in masked views, also at the
end of a sentence ("from 41.66.1.2.") and next to an underscore ("ip_41.66.1.2"), which were left unmasked before
2026-11-11 (external review). Numbers that only look like part of an address (versions, times, ratios) stay as they are.
Run: .venv/bin/python tests/check_host_label_text.py"""
import os, re, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import host_label  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


L = host_label.label
MASKED = [   # (text, the address in it)
    ("Connection from 41.66.1.2.", "41.66.1.2"),
    ("Connection from 41.66.1.2. Closing.", "41.66.1.2"),
    ("ip_41.66.1.2", "41.66.1.2"),
    ("41.66.1.2_backup", "41.66.1.2"),
    ("banner from 41.66.1.2:80", "41.66.1.2"),
    ("(41.66.1.2)", "41.66.1.2"),
    ("hosts 41.66.1.2, 41.66.1.3", "41.66.1.2"),
    ("x=41.66.1.2;y=1", "41.66.1.2"),
    ("41.66.1.2", "41.66.1.2"),
    ("Host: 41.66.1.2\r\nUser-Agent: x", "41.66.1.2"),
    ("reached 2001:db8::1.", "2001:db8::1"),
    ("addr_2001:db8::1", "2001:db8::1"),
    ("[2001:db8::1]:443", "2001:db8::1"),
    ("from fe80::1ff:fe23:4567:890a done", "fe80::1ff:fe23:4567:890a"),
    # a letter glued on does not make it a version (external review, 2026-11-12: v41.66.1.2 leaked); over-masking a
    # four-part version number is the price
    ("v41.66.1.2", "41.66.1.2"), ("build 41.66.1.2a", "41.66.1.2"), ("app.41.66.1.2.nip.io", "41.66.1.2"),
    ("ip:2001:db8::1", "2001:db8::1"),
]
LEFT = [     # nothing in these is an address
    "OpenSSH 1.2.3.4.5", "OpenSSH_8.2p1", "Date 10:22:31 GMT", "ratio 3:2",
    "MikroTik 7.24.4", "999.1.1.1", "port 8291", "id 4f9a1c2b3d4e5f60", "version 2.4.6.10.12",
]

print("Addresses in text are labelled")
for text, ip in MASKED:
    out = host_label.label_text(text)
    ok(f"{text!r}", ip not in out and L(ip) in out, out)
print("Numbers that are not addresses stay")
for text in LEFT:
    out = host_label.label_text(text)
    ok(f"{text!r}", out == text, out)
print("Nothing of a masked address is left")
blob = host_label.label_text(" ".join(t for t, _ in MASKED))
ok("no address, whole or in part, after masking every example", not re.search(r"\b41\.66\.|2001:db8|fe80::", blob))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
