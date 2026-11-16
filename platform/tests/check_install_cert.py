#!/usr/bin/env python3
"""A bought certificate, checked and installed (deploy/install_cert.py, review follow-up item 5, 2026-11-15), against a
throwaway test certificate authority (root, intermediate, server certificates for lg.test.example: a reserved name,
never a real domain): a good one installs (chain completed from the intermediate, key owner-only, previous kept,
recorded in the audit log); a key that is not the certificate's, the wrong domain, an expired or passphrase-protected
one, a weak key, a missing intermediate and an untrusted root are refused with the reason; a wildcard covers one
label. The installer offers it, never "No HTTPS" to the internet, and asks a typed confirmation for a public self-signed
site; the bell warns before expiry. Needs openssl. Run: .venv/bin/python tests/check_install_cert.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "deploy"))
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


if not shutil.which("openssl"):
    print("openssl not found: skipped"); sys.exit(77)
import install_cert as ic  # noqa: E402

T = tempfile.mkdtemp(prefix="lg-cert-")
P = lambda n: os.path.join(T, n)   # noqa: E731


def ossl(*a, check=True):
    r = subprocess.run(["openssl", *a], capture_output=True, text=True, cwd=T)
    if check and r.returncode:
        raise SystemExit(f"openssl {' '.join(a[:3])}: {r.stderr[-300:]}")
    return r


def ext(name, text):
    open(P(name), "w").write(text)
    return P(name)


# the test CA: root -> intermediate -> server certificates
ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "30", "-subj", "/CN=LG Test Root",
     "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
ossl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "int.key", "-out", "int.csr", "-subj", "/CN=LG Test Intermediate")
ossl("x509", "-req", "-in", "int.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial", "-out", "int.pem", "-days", "30",
     "-extfile", ext("int.ext", "basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n"))


def leaf(name, sans, days=20, bits=2048, extra=()):
    ossl("req", "-newkey", f"rsa:{bits}", "-nodes", "-keyout", f"{name}.key", "-out", f"{name}.csr", "-subj", f"/CN={sans[0]}")
    e = ext(f"{name}.ext", "basicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\nsubjectAltName=" + ",".join(f"DNS:{s}" for s in sans) + "\n")
    ossl("x509", "-req", "-in", f"{name}.csr", "-CA", "int.pem", "-CAkey", "int.key", "-CAcreateserial", "-out", f"{name}.pem",
         "-days", str(days), "-extfile", e, *extra)
    return P(f"{name}.pem"), P(f"{name}.key")


D = "lg.test.example"
good_c, good_k = leaf("good", [D])
CA = P("root.pem")

print("A good certificate")
r = ic.check(D, good_c, good_k, P("int.pem"), CA)
ok("it passes every check", r["ok"], json.dumps(r["problems"]))
ok("…its names, expiry and fingerprint are read", r["info"]["sans"] == [D] and r["info"]["days_left"] in (18, 19, 20)
   and r["info"]["fingerprint"].startswith("SHA256:"), json.dumps(r["info"])[:200])
ok("…the chain served is the certificate then the intermediate", r["fullchain"].count("BEGIN CERTIFICATE") == 2)
ok("…fewer than 30 days left: said, not refused", any("expires in" in w for w in r["warnings"]))
bundle = P("bundle.pem"); open(bundle, "w").write(open(good_c).read() + open(P("int.pem")).read())
ok("the intermediate inside the certificate file works too", ic.check(D, bundle, good_k, None, CA)["ok"])

print("What is refused, and why")
other_c, other_k = leaf("other", [D])
r = ic.check(D, good_c, other_k, P("int.pem"), CA)
ok("a key that is not the certificate's", not r["ok"] and any("does not belong" in p for p in r["problems"]), json.dumps(r["problems"]))
r = ic.check("other.test.example", good_c, good_k, P("int.pem"), CA)
ok("another domain", not r["ok"] and any("does not name other.test.example" in p for p in r["problems"]), json.dumps(r["problems"]))
r = ic.check(D, good_c, good_k, None, CA)
ok("no intermediate: the chain does not verify, and it says to add the chain file", not r["ok"]
   and any("chain does not verify" in p and "chain file" in p for p in r["problems"]), json.dumps(r["problems"]))
r = ic.check(D, good_c, good_k, P("int.pem"), None)
ok("a root the system does not trust (no --ca-bundle)", not r["ok"] and any("chain does not verify" in p for p in r["problems"]))
ossl("pkey", "-in", good_k, "-aes256", "-passout", "pass:test-only", "-out", "enc.key")
r = ic.check(D, good_c, P("enc.key"), P("int.pem"), CA)
ok("a key protected by a passphrase (the service starts unattended)", not r["ok"] and any("passphrase" in p for p in r["problems"]))
weak_c, weak_k = leaf("weak", [D], bits=1024)
r = ic.check(D, weak_c, weak_k, P("int.pem"), CA)
ok("a weak key (RSA 1024)", not r["ok"] and any("too weak" in p for p in r["problems"]), json.dumps(r["problems"]))
exp = ossl("x509", "-help", check=False)
if "not_after" in (exp.stdout + exp.stderr):
    old_c, old_k = leaf("old", [D], extra=("-not_before", "20200101000000Z", "-not_after", "20200201000000Z"))
    r = ic.check(D, old_c, old_k, P("int.pem"), CA)
    ok("an expired certificate", not r["ok"] and any("expired" in p for p in r["problems"]), json.dumps(r["problems"]))
else:
    print("  (this openssl cannot back-date a certificate: the expired case is checked by its date logic only)")
    ok("an expired date is read as expired", ic._date("Feb  1 00:00:00 2020 GMT") < time.time())
r = ic.check("not a domain", good_c, good_k, None, CA)
ok("something that is not a domain name", not r["ok"] and "not a domain name" in r["problems"][0])
r = ic.check(D, P("missing.pem"), good_k, None, CA)
ok("a file that does not exist", not r["ok"] and "does not exist" in r["problems"][0])

print("Wildcards")
wc_c, wc_k = leaf("wild", ["*.test.example"])
ok("*.test.example covers lg.test.example", ic.check(D, wc_c, wc_k, P("int.pem"), CA)["ok"])
ok("…but not a.b.test.example (one label only)", not ic._covers(["*.test.example"], "a.b.test.example")
   and not ic._covers(["*.test.example"], "test.example"))

print("Installing")
proj = P("proj"); os.makedirs(os.path.join(proj, "data", "tls"))
shutil.copy(os.path.join(HERE, "audit_chain.py"), proj); shutil.copy(os.path.join(HERE, "audit_verifier.py"), proj)
os.makedirs(os.path.join(proj, "deploy")); shutil.copy(os.path.join(HERE, "deploy", "install_cert.py"), os.path.join(proj, "deploy"))
open(os.path.join(proj, "data", "tls", "cert.pem"), "w").write("old certificate\n")
open(os.path.join(proj, "data", "tls", "key.pem"), "w").write("old key\n")
r = ic.check(D, good_c, good_k, P("int.pem"), CA)
kept = ic.install(proj, r, good_k, by="tester")
tls = os.path.join(proj, "data", "tls")
ok("the certificate and its chain are installed, the key owner-only", open(os.path.join(tls, "cert.pem")).read() == r["fullchain"]
   and oct(os.stat(os.path.join(tls, "key.pem")).st_mode & 0o777) == "0o600" and oct(os.stat(tls).st_mode & 0o777) == "0o700")
ok("…the previous pair is kept, not overwritten", kept and open(os.path.join(kept, "cert.pem")).read() == "old certificate\n")
meta = json.load(open(os.path.join(tls, "meta.json")))
ok("…its domain, expiry and fingerprint are noted for the bell", meta["domain"] == D and meta["fingerprint"] == r["info"]["fingerprint"])
log = open(os.path.join(proj, "data", "audit.log")).read()
ok("…and the installation is in the audit log, chained", '"tls_certificate_installed"' in log and '"prev"' in log and D in log)
ok("…with no key material anywhere in the log or the notes", "PRIVATE KEY" not in log and "PRIVATE KEY" not in json.dumps(meta))
st = ic.status(proj)
ok("status reads it back (domain, days left)", st and st["domain"] == D and st["days_left"] in (18, 19, 20), json.dumps(st))

print("The bell before it expires")
import system_alerts  # noqa: E402
a = system_alerts.Alerts(proj, env={})
al = [x for x in a.current() if x["key"].startswith("tls-expiry")]
ok("19 days left: an alert (the 30-day step)", len(al) == 1 and "expires" in al[0]["title"].lower() and al[0]["problem"], json.dumps(al)[:200])
short_c, short_k = leaf("short", [D], days=2)
time.sleep(1.1)                                  # a new file time: the bell reads the certificate again
ic.install(proj, ic.check(D, short_c, short_k, P("int.pem"), CA), short_k, by="tester")
al2 = [x for x in a.current() if x["key"].startswith("tls-expiry")]
t2 = al2[0]["title"] if al2 else ""
ok("a renewal that has 2 days left: a new alert (the 3-day step), so it shows even if the first was cleared",
   len(al2) == 1 and al2[0]["key"] != al[0]["key"] and ("1 day" in t2 or "2 day" in t2), json.dumps(al2)[:200])
long_c, long_k = leaf("long", [D], days=200)
time.sleep(1.1)
ic.install(proj, ic.check(D, long_c, long_k, P("int.pem"), CA), long_k, by="tester")
ok("a certificate with 200 days left: no alert", not [x for x in a.current() if x["key"].startswith("tls-expiry")])
_strf = ic.time.strftime
ic.time.strftime = lambda fmt, t=None: "20261115-234900"     # two installs within one second (or a clock that steps back)
try:
    ic.install(proj, ic.check(D, long_c, long_k, P("int.pem"), CA), long_k, by="tester")
    ic.install(proj, ic.check(D, long_c, long_k, P("int.pem"), CA), long_k, by="tester")
    kept = sorted(n for n in os.listdir(os.path.join(proj, "data", "tls")) if n.startswith("previous-20261115-234900"))
    ok("two installs in the same second: each previous pair kept in its own folder, no error", len(kept) == 2 and kept[1].endswith("-2"), str(kept))
except Exception as e:  # noqa: BLE001
    ok("two installs in the same second: each previous pair kept in its own folder, no error", False, repr(e))
finally:
    ic.time.strftime = _strf

print("The installer")
inst = next((p for p in (os.path.join(HERE, "..", "install.sh"), os.path.join(HERE, "tools", "release_root", "install.sh")) if os.path.isfile(p)))
s = open(inst, encoding="utf-8").read()
ok("it offers a certificate bought for a domain", 'domain     "A certificate bought for a domain name' in s and "install_cert.py" in s)
ok("an internet-facing site is never offered No HTTPS", 'if [ "$ACCESS_MODE" = public ]' in s and "PUBLIC_HTTPS" in s)
ok("a public self-signed site needs a typed confirmation", "CONFIRM_SELF_SIGNED" in s and "v_confirm_self_signed" in s)
ok("port 443 gets only the one capability it needs", "CAP_NET_BIND_SERVICE" in open(os.path.join(HERE, "deploy", "install.sh")).read())
# a service named otherwise than looking-glass (the installer asks): reload.sh, and with it a renewal, reloads the right
# one (2026-11-15 on lg-fresh: "no Looking Glass service installed", so the renewed certificate was not served)
ok("deploy/install.sh notes the service's name in .env, and reload.sh reads it",
   "LG_SERVICE=%s" in open(os.path.join(HERE, "deploy", "install.sh")).read()
   and "^LG_SERVICE=" in open(os.path.join(HERE, "deploy", "reload.sh")).read())
ok("the renewal reloads the service and checks the site with the new certificate",
   all(x in open(os.path.join(HERE, "manage", "install_cert.sh")).read() for x in ("deploy/reload.sh", "--resolve", "previous-")))
ok("it checks itself over real HTTPS for the domain (no -k)", "--resolve" in s and "SELF_CHECK_HTTPS" in s)
ok("it recommends Block for the sender check in production", "Recommended: No at first, Yes in production" in s)
# the security retest and the checks talk to this server over HTTPS: they must accept a bought certificate's chain too,
# not only a self-signed one (2026-11-15, the fresh install on lg-fresh: every retest check failed "unable to get issuer")
for f in ("security_testing/security_retest.py", "tests/lgauth.py"):
    src = open(os.path.join(HERE, f), encoding="utf-8").read()
    ok(f"{f} trusts the server's own certificate with its chain (partial chain), not only a self-signed one",
       src.count("create_default_context(cafile=") == src.count("VERIFY_X509_PARTIAL_CHAIN") >= 1)

shutil.rmtree(T, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
