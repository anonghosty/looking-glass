#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""deploy/caddy_front.sh's other commands and deploy/make_tls_cert.sh, RUN offline and without root on a made-up
machine (the harness of tests/check_caddy_adopt_run.py: a copy of the script whose /etc and /usr/share paths point into
a temporary folder, stand-ins on PATH that record what they are asked). The production check of 2026-11-26 found that
no test ran these paths. What is proved, by running them:

  1. setup (a domain, and --internal): every file it writes, and a Caddyfile with the cap on Caddy's connections to
     Looking Glass (max_conns_per_host and keepalive_idle_conns_per_host 6) and tls_trust_pool file, never the old
     tls_trusted_ca_certs; a step that fails puts every file back as it was (none of ours left, the package's sample
     Caddyfile byte for byte); the caddy package's untouched sample is kept aside, any other Caddyfile is refused;
  2. sync: a Caddyfile written by an older version is written again (a renewal brings the cap); an internal
     certificate made again for a new name changes the site's name; when Caddy then does not answer, its certificate
     copy and Caddyfile are put back as they were;
  3. update: the key is checked first (a wrong one: nothing updated); the Caddyfile is written again; restart on a
     new version;
  4. status: where it points, the versions, the automatic updates;
  5. remove: none of Looking Glass's files left behind except the automatic-updates file (kept on purpose: the caddy
     package stays, so its security updates go on); the package's sample put back;
  6. make_tls_cert.sh: the certificate and its names; the service reloaded under its own name (LG_SERVICE); without
     LG_PORT in .env it still finishes; a failing openssl leaves the certificate in use where it was.
Nothing outside the temporary folders is read or written. Run: .venv/bin/python tests/check_caddy_paths_run.py"""
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_caddy_adopt_run as H  # noqa: E402  (its harness; its own runs stay in its main())

ok, read = H.ok, H.read
KEY_FP = re.search(r'^KEY_FP="([0-9A-F]+)"', open(os.path.join(H.PF, "deploy", "caddy_front.sh"), encoding="utf-8").read(), re.M).group(1)

# stand-ins added to the harness's: caddy "active", dpkg-query from files in $T, gpg's fingerprint, apt-cache's
# candidate, apt-get install that "updates", sleep that does not wait, curl that fails on FAIL_CURL
EXTRA = {
    "systemctl": H.STUBS["systemctl"].replace('  *) exit 0 ;;', '  is-active) echo active; exit 0 ;;\n  *) exit 0 ;;'),
    "dpkg-query": r'''case "$*" in
  *Conffiles*) [ -f "$T/sample.md5" ] && echo " $T/etc/caddy/Caddyfile $(cat "$T/sample.md5")"; exit 0 ;;
  *Version*) [ -f "$T/caddy.ver" ] && { cat "$T/caddy.ver"; exit 0; }; exit 1 ;;
  *Status*) echo "install ok installed"; exit 0 ;;
esac; exit 1''',
    "gpg": r'''echo "fpr:::::::::${GPG_FP}:"''',
    "apt-cache": r'''echo "caddy:"; echo "  Installed: x"; echo "  Candidate: ${CAND:-(none)}"''',
    "apt-get": r'''echo "apt-get $*" >> "$T/calls.log"; case "$*" in *only-upgrade*) [ -n "${NEW_VER:-}" ] && echo "$NEW_VER" > "$T/caddy.ver" ;; esac; exit 0''',
    "sleep": "exit 0",
    "curl": r'''echo "curl $*" >> "$T/calls.log"; [ -n "${FAIL_CURL:-}" ] && exit 7; exit 0''',
}


def box(env_lines=("ACCESS_MODE=public",), cert="DNS:lg.example.org", ca=True):
    T, P, s, unit = H.machine(list(env_lines), cert=cert, ca=ca)
    for name, body in EXTRA.items():
        p = os.path.join(T, "stub", name)
        with open(p, "w") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, 0o755)
    return T, P, s


def run(T, s, *args, **extra):
    env = {**os.environ, "PATH": os.path.join(T, "stub") + ":" + os.environ.get("PATH", ""), "T": T, "GPG_FP": KEY_FP, **extra}
    r = subprocess.run(["bash", s, *args], capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, r.stdout + r.stderr


def paths(T):
    e = os.path.join(T, "etc")
    return {"conf": os.path.join(e, "caddy", "Caddyfile"), "certs": os.path.join(e, "caddy", "looking-glass"),
            "dropin": os.path.join(e, "systemd", "system", "caddy.service.d", "looking-glass.conf"),
            "nft": os.path.join(e, "systemd", "system", "nftables.service.d", "looking-glass-caddy.conf"),
            "autoupd": os.path.join(e, "apt", "apt.conf.d", "52looking-glass-caddy"),
            "sample": os.path.join(e, "caddy", "Caddyfile.package-sample")}


def ours_left(T):
    """Looking Glass's files that are there (the automatic-updates file apart: see 5)."""
    p = paths(T)
    left = [k for k in ("conf", "certs", "dropin", "nft", "sample") if os.path.exists(p[k])]
    left += [d for d in (os.path.dirname(p["dropin"]), os.path.dirname(p["nft"])) if os.path.isdir(d)]
    return left


def setup_args(P, domain="lg.example.org", ca_bundle=None):
    a = ["setup", "--public-port", "8443", "--backend-port", "5000", "--project", P]
    a += ["--internal"] if domain is None else ["--domain", domain]
    return a + (["--ca-bundle", ca_bundle] if ca_bundle else [])


def bundle(T):
    p = os.path.join(T, "chain.pem")
    shutil.copy(os.path.join(T, "platform", "data", "tls", "cert.pem"), p)
    return p


OLD_STYLE = """{mark}
{{
	admin off
	auto_https off
}}

https://lg.example.org:8443 {{
	tls {certs}/cert.pem {certs}/key.pem
	reverse_proxy https://127.0.0.1:5000 {{
		header_up Host {{host}}
		transport http {{
			tls_server_name lg.example.org
			tls_trusted_ca_certs {certs}/ca-bundle.pem
		}}
	}}
}}
"""


def old_site(T, P):
    """An installation set up by an older version: our Caddyfile without the cap, with tls_trusted_ca_certs."""
    p = paths(T)
    mark = re.search(r'^MARK="([^"]+)"', open(os.path.join(H.PF, "deploy", "caddy_front.sh"), encoding="utf-8").read(), re.M).group(1)
    os.makedirs(p["certs"], exist_ok=True)
    for f in ("cert.pem", "key.pem"):
        shutil.copy(os.path.join(P, "data", "tls", f), os.path.join(p["certs"], f))
    shutil.copy(os.path.join(P, "data", "tls", "cert.pem"), os.path.join(p["certs"], "ca-bundle.pem"))
    with open(p["conf"], "w") as f:
        f.write(OLD_STYLE.format(mark=mark, certs=p["certs"]))
    os.makedirs(os.path.dirname(p["dropin"]), exist_ok=True)
    open(p["dropin"], "w").write("[Service]\n")


def capped(conf, pool=True):
    """The cap on Caddy's connections to Looking Glass, and (pool) Looking Glass checked with tls_trust_pool file; never
    the old tls_trusted_ca_certs. A domain without a CA bundle is checked against the system's authorities (no pool)."""
    return bool(conf) and "max_conns_per_host 6" in conf and "keepalive_idle_conns_per_host 6" in conf \
        and (("tls_trust_pool file " in conf) == pool) and "tls_trusted_ca_certs" not in conf


def main():
    cleanup = []
    try:
        print("1. setup")
        T, P, s = box(); cleanup.append(T); p = paths(T)
        rc, out = run(T, s, *setup_args(P, ca_bundle=bundle(T)))
        conf = read(p["conf"]) or ""
        ok("a domain: it finishes (exit 0, answers through Caddy)", rc == 0 and "answers through Caddy" in out, out[-700:])
        ok("…the Caddyfile: the cap on Caddy's connections (6 and 6) and tls_trust_pool file, never tls_trusted_ca_certs",
           capped(conf) and f"tls_trust_pool file {p['certs']}/ca-bundle.pem" in conf, conf[-900:])
        ok("…the site, the name Looking Glass is checked under, the backend",
           "https://lg.example.org:8443 {" in conf and "tls_server_name lg.example.org" in conf and "reverse_proxy https://127.0.0.1:5000 {" in conf)
        ok("…the certificate copy, the CA bundle and the firewall (the public port, the connection limit)",
           all(os.path.isfile(os.path.join(p["certs"], f)) for f in ("cert.pem", "key.pem", "ca-bundle.pem"))
           and "tcp dport 8443" in (read(os.path.join(p["certs"], "firewall.nft")) or "")
           and "ct count over 100" in (read(os.path.join(p["certs"], "firewall.nft")) or ""))
        ok("…the hardening drop-in, the firewall drop-in and the automatic-updates file",
           "NoNewPrivileges=true" in (read(p["dropin"]) or "") and "ExecStartPost=-/usr/sbin/nft" in (read(p["nft"]) or "")
           and "cloudsmith/caddy/stable" in (read(p["autoupd"]) or ""))
        ok("…Caddy restarted", "systemctl restart caddy" in (read(os.path.join(T, "calls.log")) or ""))

        T, P, s = box(["ACCESS_MODE=private"], cert="DNS:lg.internal,IP:10.0.0.5", ca=False); cleanup.append(T); p = paths(T)
        rc, out = run(T, s, *setup_args(P, domain=None))
        conf = read(p["conf"]) or ""
        ok("--internal: any name on the port, the certificate's own name, Looking Glass checked against that certificate",
           rc == 0 and "https://:8443 {" in conf and "# internal: lg.internal" in conf and "default_sni lg.internal" in conf
           and f"tls_trust_pool file {p['certs']}/cert.pem" in conf and capped(conf), out[-500:] if rc else conf[-600:])

        T, P, s = box(); cleanup.append(T); p = paths(T)
        rc, out = run(T, s, *setup_args(P), FAIL_INSTALL_MATCH="nftables.service.d")      # after the Caddyfile and certificates
        ok("a step that fails (the firewall drop-in's folder): it stops, says so", rc != 0 and "could not be set up" in out, out[-600:])
        ok("…and none of its files is left (no Caddyfile, certificate or key copy, drop-in)", not ours_left(T), ours_left(T))

        T, P, s = box(); cleanup.append(T); p = paths(T)
        sample = ":80 {\n\troot * /usr/share/caddy\n\tfile_server\n}\n"
        open(p["conf"], "w").write(sample)
        open(os.path.join(T, "sample.md5"), "w").write(hashlib.md5(sample.encode()).hexdigest())   # noqa: S324 (dpkg's own)
        rc, out = run(T, s, *setup_args(P), FAIL_INSTALL_MATCH="nftables.service.d")
        ok("…over the package's sample Caddyfile: the sample is back, byte for byte, and nothing else of ours",
           rc != 0 and read(p["conf"]) == sample and not [k for k in ours_left(T) if k != "conf"], ours_left(T))
        rc, out = run(T, s, *setup_args(P))
        ok("the package's untouched sample (dpkg's checksum): kept aside, ours written", rc == 0 and read(p["sample"]) == sample
           and capped(read(p["conf"]), pool=False), out[-400:])
        rc, out = run(T, s, "remove", "--project", P)
        ok("remove: the package's sample is put back", rc == 0 and read(p["conf"]) == sample and not os.path.exists(p["sample"]), out[-300:])

        T, P, s = box(); cleanup.append(T); p = paths(T)
        mine = "example.org {\n\trespond hello\n}\n"
        open(p["conf"], "w").write(mine)
        open(os.path.join(T, "sample.md5"), "w").write("0" * 32)
        rc, out = run(T, s, *setup_args(P))
        ok("a Caddyfile someone else wrote: refused, left as it was", rc != 0 and "was not written by Looking Glass" in out
           and read(p["conf"]) == mine, out[-300:])

        print("2. sync")
        T, P, s = box(); cleanup.append(T); p = paths(T)
        old_site(T, P)
        H.make_cert(os.path.join(P, "data", "tls"), "DNS:lg.example.org", ca=True)           # the renewed certificate
        rc, out = run(T, s, "sync", "--project", P)
        conf = read(p["conf"]) or ""
        ok("a renewal: the new certificate copied to Caddy, Caddy restarted",
           rc == 0 and read(os.path.join(p["certs"], "cert.pem")) == read(os.path.join(P, "data", "tls", "cert.pem"))
           and "systemctl restart caddy" in (read(os.path.join(T, "calls.log")) or ""), out[-500:])
        ok("…a Caddyfile from an older version is written again: the cap and tls_trust_pool (with the CA bundle kept)",
           capped(conf) and "https://lg.example.org:8443 {" in conf and "reverse_proxy https://127.0.0.1:5000 {" in conf
           and f"tls_trust_pool file {p['certs']}/ca-bundle.pem" in conf, conf[-700:])

        T, P, s = box(["ACCESS_MODE=private"], cert="DNS:old.internal", ca=False); cleanup.append(T); p = paths(T)
        rc, out = run(T, s, *setup_args(P, domain=None))
        H.make_cert(os.path.join(P, "data", "tls"), "DNS:new.internal,IP:10.0.0.9")          # made again for a new name
        rc, out = run(T, s, "sync", "--project", P)
        conf = read(p["conf"]) or ""
        ok("an internal certificate made again for a new name: the site and Looking Glass's check follow it",
           rc == 0 and "# internal: new.internal" in conf and "default_sni new.internal" in conf and "tls_server_name new.internal" in conf
           and "reverse_proxy https://127.0.0.1:5000 {" in conf, out[-500:])
        before = {f: read(os.path.join(p["certs"], f)) for f in ("cert.pem", "key.pem")}
        conf0 = read(p["conf"])
        H.make_cert(os.path.join(P, "data", "tls"), "DNS:third.internal")
        rc, out = run(T, s, "sync", "--project", P, FAIL_CURL="1")
        ok("Caddy does not answer with the new certificate: it says so, and puts Caddy's copy and Caddyfile back",
           rc != 0 and "put back" in out and read(p["conf"]) == conf0
           and all(read(os.path.join(p["certs"], f)) == v for f, v in before.items()), out[-500:])

        print("3. update")
        T, P, s = box(); cleanup.append(T); p = paths(T)
        old_site(T, P)
        open(os.path.join(T, "usr", "share", "keyrings", "caddy-stable-archive-keyring.gpg"), "w").write("key")
        open(os.path.join(T, "caddy.ver"), "w").write("2.10.0\n")
        conf0 = read(p["conf"])
        rc, out = run(T, s, "update", GPG_FP="0" * 40, NEW_VER="2.11.9")
        ok("a repository key with another fingerprint: refused, nothing updated",
           rc != 0 and "unexpected fingerprint" in out and "apt-get" not in (read(os.path.join(T, "calls.log")) or "")
           and read(p["conf"]) == conf0, out[-300:])
        rc, out = run(T, s, "update", NEW_VER="2.11.9")
        ok("the right key: Caddy updated (says from which version to which), restarted",
           rc == 0 and "Caddy updated: 2.10.0 -> 2.11.9" in out and "systemctl restart caddy" in (read(os.path.join(T, "calls.log")) or ""), out[-500:])
        ok("…and the Caddyfile written again as this version writes it (the cap, tls_trust_pool)", capped(read(p["conf"])), (read(p["conf"]) or "")[-500:])
        ok("…and the automatic-updates file it had not (status's advice for 'OFF' is to run update)", os.path.isfile(p["autoupd"]))

        print("4. status")
        rc, out = run(T, s, "status", CAND="2.12.0")
        ok("where it points, the versions, the automatic updates",
           rc == 0 and "Caddy in front: https://lg.example.org:8443 -> https://127.0.0.1:5000" in out
           and "Caddy 2.11.9 installed, 2.12.0 available" in out and "automatic updates: on" in out, out[-500:])

        print("5. remove")
        T, P, s = box(); cleanup.append(T); p = paths(T)
        rc, out = run(T, s, *setup_args(P, ca_bundle=bundle(T)))
        rc, out = run(T, s, "remove", "--project", P)
        calls = read(os.path.join(T, "calls.log")) or ""
        ok("none of Looking Glass's files left: Caddyfile, certificate and key copies, firewall, drop-ins and their folders",
           rc == 0 and not ours_left(T), ours_left(T))
        ok("…its firewall table deleted, Caddy stopped and switched off",
           "nft delete table inet lg_caddy" in calls and "systemctl stop caddy" in calls and "systemctl disable caddy" in calls)
        ok("…the automatic-updates file stays on purpose (the caddy package stays, so its security updates go on)",
           os.path.isfile(p["autoupd"]))
        rc, out = run(T, s, "status")
        ok("…and status then says no Caddy is set up by Looking Glass", "no Caddy set up by Looking Glass here" in out, out[-200:])

        print("6. make_tls_cert.sh")
        tls_checks(cleanup)
    finally:
        for t in cleanup:
            shutil.rmtree(t, ignore_errors=True)
    print()
    print(f"{H.passed}/{H.passed + H.failed} runs checked" + (f"; {H.failed} FAILED" if H.failed else ""))
    sys.exit(1 if H.failed else 0)


TLS_STUBS = {
    "id": r'''case "$1" in -u) echo 1000 ;; -un) echo lguser ;; *) command -p id "$@" ;; esac''',
    "hostname": r'''case "$1" in -f) echo lg-host.example.lan ;; -I) echo "10.0.0.5 172.17.0.1 fd00::5" ;; *) echo lg-host ;; esac''',
    "systemctl": r'''echo "systemctl $*" >> "$T/calls.log"; [ "$1" = is-active ] && [ "${@: -1}" = "${ACTIVE:-}" ] && exit 0; exit 3''',
    "openssl": r'''[ -n "${FAIL_OPENSSL:-}" ] && [ "$1" = req ] && { : > data/tls/new-cert.pem 2>/dev/null; exit 1; }; exec /usr/bin/openssl "$@"''',
}


def tls_machine(env_lines):
    T = tempfile.mkdtemp(prefix="lg-tls-")
    P = os.path.join(T, "platform")
    os.makedirs(os.path.join(P, "deploy")); os.makedirs(os.path.join(T, "stub")); os.makedirs(os.path.join(T, "etc", "caddy"))
    src = open(os.path.join(H.PF, "deploy", "make_tls_cert.sh"), encoding="utf-8").read().replace("/etc/caddy/", T + "/etc/caddy/")
    with open(os.path.join(P, "deploy", "make_tls_cert.sh"), "w") as f:
        f.write(src)
    with open(os.path.join(P, "deploy", "reload.sh"), "w") as f:
        f.write('echo "reload $(grep -E ^LG_SERVICE= .env | cut -d= -f2)" >> "$T/calls.log"\n')
    with open(os.path.join(P, ".env"), "w") as f:
        f.write("\n".join(env_lines) + "\n")
    for name, body in TLS_STUBS.items():
        p = os.path.join(T, "stub", name)
        with open(p, "w") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, 0o755)
    return T, P


def tls_run(T, P, *args, **extra):
    env = {**os.environ, "PATH": os.path.join(T, "stub") + ":" + os.environ.get("PATH", ""), "T": T, **extra}
    r = subprocess.run(["bash", os.path.join(P, "deploy", "make_tls_cert.sh"), *args], capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, r.stdout + r.stderr


def tls_checks(cleanup):
    T, P = tls_machine(["ACCESS_MODE=private", "LG_SERVICE=lgx"]); cleanup.append(T)       # no LG_PORT line
    tls = os.path.join(P, "data", "tls")
    rc, out = tls_run(T, P, "lg.internal", ACTIVE="lgx")
    txt = subprocess.run(["openssl", "x509", "-in", os.path.join(tls, "cert.pem"), "-noout", "-subject", "-ext", "subjectAltName"],
                         capture_output=True, text=True).stdout if os.path.isfile(os.path.join(tls, "cert.pem")) else ""
    ok("a certificate is made, named after the first name given (never the product)", rc == 0 and "CN=lg.internal" in txt.replace(" ", ""), out[-400:])
    ok("…for localhost, this machine's names and addresses (not the docker bridge) and the name given",
       all(n in txt for n in ("DNS:localhost", "IP Address:127.0.0.1", "DNS:lg-host", "DNS:lg-host.example.lan", "IP Address:10.0.0.5", "DNS:lg.internal"))
       and "172.17.0.1" not in txt, txt)
    ok("…its key readable by the service's user only", os.path.isfile(os.path.join(tls, "key.pem")) and oct(os.stat(os.path.join(tls, "key.pem")).st_mode & 0o777) == "0o600")
    ok("…the service reloaded under its own name (LG_SERVICE=lgx), though .env has no LG_PORT",
       "reload lgx" in (read(os.path.join(T, "calls.log")) or "") and "Open https://localhost:5000" in out, out[-400:])
    cert0, key0 = read(os.path.join(tls, "cert.pem")), read(os.path.join(tls, "key.pem"))
    rc, out = tls_run(T, P, "lg.internal", FAIL_OPENSSL="1")
    ok("openssl fails: it says so, and the certificate in use stays where it was, byte for byte",
       rc != 0 and "could not be made" in out and read(os.path.join(tls, "cert.pem")) == cert0 and read(os.path.join(tls, "key.pem")) == key0, out[-300:])
    ok("…no half-made file and no 'previous' copy left", not [n for n in os.listdir(tls) if n.startswith(("new-", "previous-"))], os.listdir(tls))
    mark = re.search(r'^MARK="([^"]+)"', open(os.path.join(H.PF, "deploy", "caddy_front.sh"), encoding="utf-8").read(), re.M).group(1)
    with open(os.path.join(T, "etc", "caddy", "Caddyfile"), "w") as f:
        f.write(f"{mark}\n# internal: lg.internal\nhttps://:8443 {{\n}}\n")
    rc, out = tls_run(T, P)
    kept = [n for n in os.listdir(tls) if n.startswith("previous-")]
    # exit 3: made, but Caddy (internal, in front) could not be handed it here (no caddy_front.sh in this test folder)
    ok("made again: the previous one is kept aside, the new one is in use", rc == 3 and len(kept) == 1
       and read(os.path.join(tls, kept[0], "cert.pem")) == cert0 and read(os.path.join(tls, "cert.pem")) != cert0, out[-300:])
    ok("…Caddy in front: it says to give Caddy the new certificate, and the port people use is Caddy's",
       "caddy_front.sh sync" in out and "https://localhost:8443" in out, out[-400:])


if __name__ == "__main__":
    main()
