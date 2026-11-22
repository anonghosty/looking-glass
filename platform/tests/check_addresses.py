#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Network changes (net_drift.py, the user 2026-11-19).
1. the rules, on made-up addresses and a made-up certificate in a scratch folder: a self-signed certificate that names
   another address is reported (with the fix), one that names this computer's address is not, a CA's never; MongoDB told
   to listen on an address this computer no longer has is reported, loopback and 0.0.0.0 never; "this computer only"
   needs no certificate check;
2. this installation, now: every mismatch printed as a WARNING with how to fix it (the installation check); a warning,
   not a failure, since only the administrator can change the address or make the certificate again.
Usage: tests/check_addresses.py"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
import net_drift as N  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def make_cert(folder, ips, self_signed=True):
    """A made-up certificate as deploy/make_tls_cert.sh makes one (openssl); not self-signed: signed by a made-up CA."""
    d = os.path.join(folder, "data", "tls")
    os.makedirs(d, exist_ok=True)
    san = ",".join(["DNS:localhost"] + [f"IP:{i}" for i in ips])
    run = lambda *a: subprocess.run(list(a), capture_output=True, check=True, cwd=d)  # noqa: E731
    if self_signed:
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
            "-keyout", "key.pem", "-out", "cert.pem", "-subj", "/CN=made-up", "-addext", f"subjectAltName={san}")
    else:
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-days", "30",
            "-keyout", "ca.key", "-out", "ca.pem", "-subj", "/CN=Made-up CA")
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "key.pem",
            "-out", "req.pem", "-subj", "/CN=made-up", "-addext", f"subjectAltName={san}")
        run("openssl", "x509", "-req", "-in", "req.pem", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-days", "30",
            "-copy_extensions", "copy", "-out", "cert.pem")


print("1. The rules (made-up addresses)")
t = tempfile.mkdtemp()
make_cert(t, ["127.0.0.1", "192.0.2.10"])
d = N.drift(t, mine={"192.0.2.20"}, env={"ACCESS_MODE": "private"})
ok("a self-signed certificate naming the old address: reported, with the fix", len(d) == 1 and "make_tls_cert.sh" in d[0]["text"]
   and "192.0.2.20" in d[0]["text"], d)
ok("…the certificate still names this computer's address: nothing", N.drift(t, mine={"192.0.2.10"}, env={"ACCESS_MODE": "private"}) == [])
ok("…this computer only (ACCESS_MODE=local): nothing to check", N.drift(t, mine={"192.0.2.20"}, env={"ACCESS_MODE": "local"}) == [])
t2 = tempfile.mkdtemp()
make_cert(t2, ["192.0.2.10"], self_signed=False)
ok("a certificate from a CA: never reported (it names the domain people use)", N.drift(t2, mine={"192.0.2.20"}, env={"ACCESS_MODE": "public"}) == [])
real_env = N._pipeline_env
try:
    N._pipeline_env = lambda base: {"MONGO_BIND": "127.0.0.1,192.0.2.10"}
    d = N.drift(tempfile.mkdtemp(), mine={"192.0.2.20"}, env={})
    ok("MongoDB told to listen on an address that is gone: reported, with the fix", len(d) == 1 and "MONGO_BIND" in d[0]["text"]
       and "192.0.2.10" in d[0]["text"], d)
    ok("…an address this computer has: nothing", N.drift(tempfile.mkdtemp(), mine={"192.0.2.10"}, env={}) == [])
    N._pipeline_env = lambda base: {"MONGO_BIND": "127.0.0.1"}
    ok("…this computer only (127.0.0.1): nothing", N.drift(tempfile.mkdtemp(), mine={"192.0.2.20"}, env={}) == [])
    N._pipeline_env = lambda base: {"MONGO_BIND": "0.0.0.0"}
    ok("…every address (0.0.0.0): nothing", N.drift(tempfile.mkdtemp(), mine={"192.0.2.20"}, env={}) == [])
finally:
    N._pipeline_env = real_env
ok("no address known (no network): nothing reported", N.drift(t, mine=set(), env={"ACCESS_MODE": "private"}) == [])
import system_alerts as SA  # noqa: E402
ok("the bell shows them to administrators (system_alerts)", "_addresses" in SA.Alerts.__dict__)

print("2. This installation, now")
try:
    from dotenv import dotenv_values
    env = {k: v or "" for k, v in dotenv_values(os.path.join(HERE, ".env")).items()}
except Exception:                                        # noqa: BLE001
    env = dict(os.environ)
found = N.drift(HERE, env=env)
for x in found:
    print(f"  WARNING {x['title']}: {x['text']}")
print("  " + ("everything matches this computer's addresses" if not found else f"{len(found)} warning(s) above: they need the administrator"))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
