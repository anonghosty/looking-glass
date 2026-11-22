#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The sender check's key look-up over HTTPS (dns_https.py, mail_auth.Checker._lookup, 2026-11-15): asked only when
the system's resolver does not answer; Cloudflare's and Google's answer shapes; a missing key is never retried
elsewhere. Offline: nothing is sent anywhere (the HTTPS answers are made up here).
Run: python3 tests/test_dns_https.py"""
import io
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dns.resolver  # noqa: E402
import dns_https  # noqa: E402
import mail_auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


KEY = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDWdcPi"
asked = []
answers = {}


class Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def fake_urlopen(req, timeout=None, context=None):
    url = req.full_url
    asked.append(url)
    ip = url.split("/")[2]
    a = answers.get(ip)
    if a is None or isinstance(a, Exception):
        raise a or OSError("unreachable")
    return Resp(json.dumps(a).encode())


dns_https.urllib.request.urlopen = fake_urlopen
N = "mail._domainkey.shadowserver.org"

print("Which resolvers")
ok("the default: Cloudflare and Google, in order", dns_https.servers({}) == ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"])
ok("MAIL_AUTH_DNS_SERVERS=none turns it off", dns_https.servers({"MAIL_AUTH_DNS_SERVERS": "none"}) == [])
ok("only IP addresses are taken (a name or a URL is ignored)",
   dns_https.servers({"MAIL_AUTH_DNS_SERVERS": "9.9.9.9, evil.example, https://x/, 2606:4700:4700::1111"}) == ["9.9.9.9", "2606:4700:4700::1111"])

print("Answers")
answers.update({"1.1.1.1": {"Status": 0, "Answer": [{"type": 16, "data": f'"{KEY[:20]}" "{KEY[20:]}"'}]}})
ok("Cloudflare's quoted strings are joined into the record", dns_https.txt(N, servers_=["1.1.1.1"]) == KEY.encode())
ok("…asked at its JSON endpoint, by IP address, for the key's name and TXT only",
   asked[-1] == f"https://1.1.1.1/dns-query?name={N}&type=TXT", asked[-1])
answers["8.8.8.8"] = {"Status": 0, "Answer": [{"type": 16, "data": KEY}]}
ok("Google's unquoted answer is read as it is, at /resolve", dns_https.txt(N, servers_=["8.8.8.8"]) == KEY.encode()
   and "/resolve?" in asked[-1])
answers["1.1.1.1"] = OSError("reset")
n = len(asked)
ok("a resolver that does not answer: the next one is asked", dns_https.txt(N, servers_=["1.1.1.1", "8.8.8.8"]) == KEY.encode()
   and len(asked) == n + 2)
answers["8.8.8.8"] = {"Status": 3}
try:
    dns_https.txt(N, servers_=["8.8.8.8"]); ok("a name that does not exist: LookupError (no key published)", False)
except LookupError:
    ok("a name that does not exist: LookupError (no key published)", True)
answers["8.8.8.8"] = OSError("down")
try:
    dns_https.txt(N, servers_=["1.1.1.1", "8.8.8.8"]); ok("none answers: OSError (the check is then 'not checked')", False)
except OSError:
    ok("none answers: OSError (the check is then 'not checked')", True)
try:
    dns_https.txt("a b/../x", servers_=["8.8.8.8"]); ok("a name that is not a DNS name is never sent", False)
except LookupError:
    ok("a name that is not a DNS name is never sent", True)

print("In the sender check (mail_auth.Checker)")
real_resolve = dns.resolver.Resolver.resolve


def system(exc):
    def resolve(self, *a, **k):
        raise exc
    dns.resolver.Resolver.resolve = resolve


answers.update({"1.1.1.1": {"Status": 0, "Answer": [{"type": 16, "data": f'"{KEY}"'}]}})
os.environ.pop("MAIL_AUTH_DNS_SERVERS", None)
system(dns.resolver.LifetimeTimeout(timeout=5, errors=[]))
n = len(asked)
c = mail_auth.Checker()
key, err = c._key("mail", "shadowserver.org")
ok("the system's DNS times out: the key comes over HTTPS, and it says how", err is None or "cannot be read" in str(err),
   str(err))
ok("…via the first resolver", c.via.get(N) == "HTTPS via 1.1.1.1" and len(asked) == n + 1, str(c.via))
n = len(asked)
c._key("mail", "shadowserver.org")
ok("…looked up once per run", len(asked) == n)
system(dns.resolver.NXDOMAIN())
n = len(asked)
_, err = mail_auth.Checker()._key("nosuch", "shadowserver.org")
ok("the system's DNS says the key does not exist: not asked again over HTTPS, 'no key published'",
   len(asked) == n and err and err[0] == "permerror", str(err))
os.environ["MAIL_AUTH_DNS_SERVERS"] = "none"
system(dns.resolver.LifetimeTimeout(timeout=5, errors=[]))
n = len(asked)
_, err = mail_auth.Checker()._key("mail", "shadowserver.org")
ok("HTTPS switched off: nothing asked over HTTPS, 'DNS did not answer' as before", len(asked) == n and err and err[0] == "temperror", str(err))
dns.resolver.Resolver.resolve = real_resolve
os.environ.pop("MAIL_AUTH_DNS_SERVERS", None)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
