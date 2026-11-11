#!/usr/bin/env python3
"""Masked viewers (the external role, demo mode, any account without 'unmasked') see only allowlisted report fields
(masked_fields.py), and those with host names, addresses, e-mails, dates and IDs masked. The field names below are
the real ones that reached masked viewers before the allowlist (external review, 2026-11-11), with made-up values.
Run: .venv/bin/python tests/check_masked_fields.py"""
import json, os, re, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import masked_fields as M  # noqa: E402
import privacy as P  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  ({info})" if info and not cond else ""))


HOST = "CORE-RTR-01.bank.example.gh"
LEAKED = {   # every one of these reached a masked viewer before
    "sysname": HOST, "sysdesc": f"RouterOS on {HOST}", "domain": "bank.example.gh", "workgroup": "BANKHQ",
    "nb_name": "CORE-RTR-01", "dns_name": HOST, "ldap_dnsHostName": HOST, "mac_address": "00:11:22:33:44:55",
    "available_mac_hw": "00:11:22:33:44:55", "mac": "00:11:22:33:44:55", "username": "j.mensah", "usernames": "admin,j.mensah",
    "workstation_name": "FIN-PC-07", "machine_name": "FIN-PC-07", "dns_host_name": HOST, "ldap_service_name": f"bank.example.gh:{HOST}$@BANK",
    "location": "Server room, 2nd floor, Head Office", "radioname": "HQ-Roof-Link", "name": "Head office router",
    "cluster_name": "bank-prod", "instance_name": "BANKDB", "utf8_servername": HOST, "servername": "BANKSRV01",
    "community": "s3cret", "badsecret_secret": "hunter2", "printer_wifi_ssid": "BANK-STAFF", "essid": "BANK-STAFF",
    "uptime": "4123456", "systime": "2026-11-10 10:22:31", "banner": f"220 {HOST} ESMTP", "cert_serial_number": "0a1b2c3d4e5f6071",
    "sha256_fingerprint": "ab" * 32, "rsa_modulus": "00c3" * 20, "ntrip_latitude": "5.6037", "visible_databases": "payroll,customers",
    "a_field_a_report_adds_tomorrow": HOST,
}
SAFE = {"ssl_version": "TLSv1.2", "selected_cipher": "aes128-ctr", "client_ssl": "1", "product": f"RouterOS 6.49 at {HOST}",
        "build_date": "2026-01-02", "available_kex": "curve25519-sha256", "rsa_length": 2048}

print("1. Services: the leaked fields are hidden")
shown, hidden = M.service_extras({**LEAKED, **SAFE})
blob = json.dumps(shown)
for k in LEAKED:
    ok(f"hidden: {k}", k not in shown)
ok("no host name, MAC address or user name anywhere in what is shown",
   not re.search(r"(?i)bank\.example|CORE-RTR|FIN-PC|00:11:22|j\.mensah|BANKHQ|s3cret|hunter2", blob), blob[:160])
ok("the hidden fields are counted", hidden == len(LEAKED), str(hidden))

print("\n2. Services: technical fields stay, masked")
ok("versions, ciphers and capability flags shown", shown.get("ssl_version") == "TLSv1.2" and shown.get("selected_cipher") == "aes128-ctr"
   and shown.get("client_ssl") == "1" and shown.get("available_kex") == "curve25519-sha256")
ok("a host name inside an allowed field is masked", shown.get("product") == "RouterOS 6.49 at <host>", str(shown.get("product")))
ok("dates in allowed fields are masked", shown.get("build_date") == "<date>")
ok("numbers stay numbers", shown.get("rsa_length") == 2048)
ok("nothing to hide gives an empty result", M.service_extras({}) == ({}, 0) and M.service_extras(None) == ({}, 0))

print("\n3. Network map events")
ev_extras = {"username": "root", "password": "admin123", "banner": f"SSH-2.0 {HOST}", "command": "wget http://203.0.113.9/x",
             "cookie": "sid=abc", "request_raw": f"GET / HTTP/1.1\r\nHost: {HOST}", "path": "/home/j.mensah", "query": HOST,
             "count": 4, "url_scheme": "https", "md5": "d41d8cd98f00b204e9800998ecf8427e", "family": "mirai"}
ev = {"src_ip": "198.51.100.23", "dst_ip": "203.0.113.9", "src_asn": "", "dst_asn": "", "extras": ev_extras}
R = P.AsnRegistry(os.path.join(ROOT, "tests", "does-not-exist.json"))
mv = P.mask_event(ev, R)
eb = json.dumps(mv["extras"])
ok("user names, passwords, banners, commands, cookies, paths hidden",
   not any(k in mv["extras"] for k in ("username", "password", "banner", "command", "cookie", "request_raw", "path", "query")))
ok("no host name or secret in the shown fields", not re.search(r"(?i)bank\.example|admin123|j\.mensah|203\.0\.113", eb), eb)
ok("counts, schemes, malware names kept", mv["extras"].get("count") == 4 and mv["extras"].get("url_scheme") == "https" and mv["extras"].get("family") == "mirai")
ok("a malware sample hash is kept whole (Malpedia look-up)", mv["extras"].get("md5") == "d41d8cd98f00b204e9800998ecf8427e")
ok("a host name in a hash field is still masked", M.event_extras({"md5": HOST})[0]["md5"] == "<host>")
ok("hidden fields counted", mv["extras_hidden"] == 8, str(mv["extras_hidden"]))

print("\n4. The services platform uses the allowlist for masked viewers")
src = open(os.path.join(ROOT, "services_api.py"), encoding="utf-8").read()
pub = src[src.index("def public("):src.index("def day_for(")]
ok("public() masks extras with masked_fields.service_extras", "masked_fields.service_extras(ex)" in pub)
ok("no blocklist left", "HIDE_EXTRA" not in src)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
