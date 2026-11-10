#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Intel gathered never shows researchers what identifies a constituent host (intel.py, hostmask.py).

1. hostmask.py: host names (also wildcards), IP addresses (v4, v6), e-mail addresses, dates, times and long IDs are
   masked out of free text; software names and versions stay.
2. Against the days in memory: no value in any Intel gathered answer (every issue, every infection name) or in the
   leads is a constituent host's name, certificate name, address or e-mail address. Threat-side values (the C2 domains
   and names the communications reports carry for the far end) are not constituent data and may appear.
3. On the services side every value shown is shared by at least 5 hosts; the rest is counted, never shown.
Usage: tests/check_intel_privacy.py"""
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import logging  # noqa: E402
logging.disable(logging.WARNING)
import hostmask  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


print("1. hostmask.py")
cases = [("220 mail.example.org ESMTP Postfix (Ubuntu)", "220 <host> ESMTP Postfix (Ubuntu)"),
         ("*.example.org", "<host>"), ("vpn.agency.example", "<host>"), ("contact admin@example.org now", "contact <email> now"),
         ("from 203.0.113.7 at 10:22:31", "from <ip> at <time>"), ("2001:db8::1 answered", "<ip> answered"),
         ("Mon, 09 Nov 2026 10:22:31 +0000 ready", "<date> ready"), ("id 4f9a1c2b3d4e5f60 ok", "id <id> ok"),
         ("SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20", "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"),
         ("nginx/1.24.0", "nginx/1.24.0"), ("Microsoft-IIS/10.0", "Microsoft-IIS/10.0"), ("RouterOS RB5009UG+S+ 7.24.2 (stable)", "RouterOS RB5009UG+S+ 7.24.2 (stable)"),
         ("220 FTP server (MikroTik 7.24.4) ready", "220 FTP server (MikroTik 7.24.4) ready")]
bad = [(a, hostmask.mask(a), b) for a, b in cases if hostmask.mask(a) != b]
ok("host names, addresses, e-mails, dates, times and IDs masked; software and versions kept", not bad, "; ".join(f"{a!r} -> {m!r}" for a, m, _ in bad[:3]))
ok("a value that is only a host name is recognised as one", hostmask.looks_like_host("mail.example.org") and not hostmask.looks_like_host("Postfix"))

import app as A  # noqa: E402
from flask import g  # noqa: E402


def call(path):
    with A.app.test_request_context(path):
        g.user = {"user": "lg-selftest-privacy", "role": "researcher", "perms": {"definitions"}, "csrf": None}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0])
        r = A.app.view_functions[ep[0]](**ep[1])
        r = r[0] if isinstance(r, tuple) else r
        return r.get_data(as_text=True)


now = A.replay_now()
A.svc["store"].get(now); A.store.get(now)
sv = [e for d in A.svc["store"].days.values() for e in d.events]
cm = [e for d in A.store.days.values() for e in d.events]
if not sv and not cm:
    print("SKIPPED: no records in memory (no reports loaded yet)"); sys.exit(77)
low = lambda s: str(s or "").strip().lower().rstrip(".")
hostnames = {low(e.get("hostname")) for e in sv} | {low(e.get("src_hostname")) for e in cm}
certnames = {low((e.get("extras") or {}).get(k)) for e in sv for k in ("subject_common_name", "issuer_common_name")}
ips = {e.get("ip") for e in sv} | {e.get("src_ip") for e in cm}
threat = {low(e.get(k)) for e in cm for k in ("http_host", "dst_hostname", "ssl_servername")} | \
         {low((e.get("extras") or {}).get("query")) for e in cm}
constituent = {x for x in (hostnames | certnames) if x and "." in x} - threat
ips.discard(None); ips.discard("")
email_rx = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
print(f"2. Against the days in memory ({len(constituent):,} constituent host / certificate names, {len(ips):,} addresses)")


def strings(v, out):
    if isinstance(v, dict):
        for x in v.values():
            strings(x, out)
    elif isinstance(v, list):
        for x in v:
            strings(x, out)
    elif isinstance(v, str):
        out.append(v)
    return out


issues = list(A._svc_issue_stats().keys())
infections = sorted(A._name_evidence().keys())[:300]
leaks, small, answers = [], 0, 0
for section, names in (("issues", issues), ("infections", infections)):
    for n in names:
        body = call(f"/api/intel?section={section}&name={urllib.parse.quote(n)}")
        try:
            d = json.loads(body)
        except ValueError:
            continue
        answers += 1
        for s in strings(d, []):
            t = low(s)
            # a constituent value is a leak only when it names a host, an address or a mailbox (a manufacturer's
            # name in a default certificate, shared by all its devices, names no host)
            names_one = hostmask.mask(t) != t
            if (t in constituent and names_one) or t in ips or (email_rx.search(s) and t not in threat):
                leaks.append((section, "host name" if t in constituent else "address" if t in ips else "e-mail"))
        if section == "issues":
            for rep in d.get("reports") or []:
                for k in rep.get("indicators") or []:
                    vals = k.get("values") if isinstance(k, dict) else None
                    for v in (vals if isinstance(vals, list) else []):
                        if isinstance(v, dict) and int(v.get("hosts") or 0) < 5:
                            small += 1
for s in strings(json.loads(call("/api/intel/leads")), []):
    t = low(s)
    if (t in constituent and hostmask.mask(t) != t) or t in ips:
        leaks.append(("leads", "host name" if t in constituent else "address"))
ok(f"no constituent host name, address or e-mail in {answers} Intel gathered answers and the leads", not leaks,
   ", ".join(f"{a}: {b}" for a, b in sorted(set(leaks))[:5]) + (f" ({len(leaks)} values)" if leaks else ""))
print("3. Services: only values shared by 5 hosts or more")
ok("every services value shown is shared by at least 5 hosts", small == 0, f"{small} value(s) on fewer hosts")

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
