#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Caddy in front of a public installation (deploy/caddy_front.sh), checked without Caddy or root (as on GitHub):
- the Caddyfile it writes: no admin endpoint, no automatic certificates (no outside connection), strict time limits
  for slow connections (headers within 10 s), HTTP/1.1 and HTTP/2 over TCP only, no Server header, the certificate copy
  it serves, Looking Glass reached on 127.0.0.1 over HTTPS with its certificate checked for the domain (never "skip
  verification"), a private CA only when given; bad input refused
- Caddy's signing key accepted only with its pinned fingerprint, and the repository pinned
- the installer puts Caddy in front for a bought certificate (Looking Glass on 127.0.0.1, TRUST_PROXY=1, the public
  port for Caddy, the firewall and the self-check on that port), renewals copy the certificate to Caddy, and the
  uninstaller removes only what Looking Glass wrote
Run: .venv/bin/python tests/check_caddy_front.py"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "deploy", "caddy_front.sh")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


def run(*args):
    r = subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout, r.stderr


def find(*names):
    for n in names:
        p = os.path.join(ROOT, n)
        if os.path.exists(p):
            return open(p, encoding="utf-8").read()
    return ""


print("The Caddyfile")
rc, conf, err = run("render", "--domain", "LookingGlass.Example.org", "--public-port", "443", "--backend-port", "5000")
ok("it renders", rc == 0 and conf, err)
ok("marked as Looking Glass's own (a Caddyfile someone else wrote is never replaced)", conf.startswith("# Managed by Looking Glass"))
ok("no admin endpoint, no automatic certificates (nothing fetched from outside)", re.search(r"^\s*admin off$", conf, re.M)
   and re.search(r"^\s*auto_https off$", conf, re.M))
ok("no OCSP stapling (Caddy never calls the certificate authority)", re.search(r"^\s*ocsp_stapling off$", conf, re.M))
ok("slow connections: headers within 10 s, body within 30 s, idle 2 min", "read_header 10s" in conf and "read_body 30s" in conf
   and "idle 2m" in conf)
ok("HTTP/1.1 and HTTP/2 over TCP only (no HTTP/3 over UDP)", re.search(r"^\s*protocols h1 h2$", conf, re.M))
ok("the site is the domain (lower case) on the public port", "https://lookingglass.example.org:443 {" in conf)
ok("it serves its own copy of the certificate", "tls /etc/caddy/looking-glass/cert.pem /etc/caddy/looking-glass/key.pem" in conf)
hdr = re.search(r"^\s*header \{\n((?:\s*-[A-Za-z-]+\n)+)\s*\}", conf, re.M)
removed = set(re.findall(r"-([A-Za-z-]+)", hdr.group(1))) if hdr else set()
ok("no fingerprint: the Server, Via and Alt-Svc headers are removed (nothing names Caddy)", {"Server", "Via", "Alt-Svc"} <= removed, removed)
err = conf.split("handle_errors {", 1)[1] if "handle_errors {" in conf else ""
ok("…also on Caddy's own error answers (Looking Glass down): the same headers removed, a plain status line",
   all(f"-{h}" in err for h in ("Server", "Via", "Alt-Svc")) and 'respond "{err.status_code} {err.status_text}"' in err)
ok("…and the word Caddy appears in no directive that answers a visitor", not re.search(r"(?im)^\s*(respond|header\s+\+|error)\b.*caddy", conf))
ok("only the caddy package's untouched sample Caddyfile may be replaced (kept aside)", "package_default" in open(SCRIPT, encoding="utf-8").read())
ok("Looking Glass reached on this computer only, over HTTPS", "reverse_proxy https://127.0.0.1:5000 {" in conf)
ok("…its certificate checked for the domain, never skipped", "tls_server_name lookingglass.example.org" in conf
   and "insecure" not in conf.lower())
ok("…no private CA unless one is given", "tls_trusted_ca_certs" not in conf)
rc, conf2, _ = run("render", "--domain", "lg.example.org", "--public-port", "8443", "--backend-port", "5001",
                   "--ca-bundle", __file__)
ok("a private CA (test installations) is trusted from Caddy's own copy", rc == 0
   and "tls_trusted_ca_certs /etc/caddy/looking-glass/ca-bundle.pem" in conf2)
for args, why in ((["--domain", "bad domain", "--public-port", "443", "--backend-port", "5000"], "a name that is not a domain"),
                  (["--domain", "x.example.org", "--public-port", "443", "--backend-port", "443"], "the same port twice"),
                  (["--domain", "x.example.org", "--public-port", "99999", "--backend-port", "5000"], "a port out of range"),
                  (["--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000", "--ca-bundle", "/no/such"], "a missing CA file")):
    rc, out, _ = run("render", *args)
    ok(f"refused: {why}", rc != 0 and not out)
rc, out, err = run("setup", "--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000")
ok("setup needs root (nothing is changed without sudo)", (rc != 0 and "sudo" in err) or os.geteuid() == 0, err)

print("Caddy's service, locked down (a drop-in over the package's unit)")
rc, unit, _ = run("hardening")
lines = set(unit.split("\n"))
ok("only the right to listen on a low port (the package's CAP_NET_ADMIN taken away)",
   {"AmbientCapabilities=", "AmbientCapabilities=CAP_NET_BIND_SERVICE", "CapabilityBoundingSet=CAP_NET_BIND_SERVICE"} <= lines
   and "NET_ADMIN" not in unit)
ok("its environment is not written to the log (--environ dropped)", "ExecStart=\nExecStart=/usr/bin/caddy run --config /etc/caddy/Caddyfile" in unit
   and "--environ" not in unit)
ok("nothing writable but its own state folder; no homes, devices, kernel settings or new privileges",
   {"ProtectSystem=strict", "ReadWritePaths=/var/lib/caddy", "ProtectHome=true", "PrivateDevices=true", "NoNewPrivileges=true",
    "ProtectKernelTunables=true", "ProtectKernelModules=true", "ProtectControlGroups=true"} <= lines)
ok("the usual system calls only, no namespaces, no writable-and-runnable memory",
   {"SystemCallFilter=@system-service", "SystemCallFilter=~@privileged @resources", "RestrictNamespaces=true",
    "MemoryDenyWriteExecute=true", "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"} <= lines)
ok("within bounds: memory and process limits", {"MemoryMax=1G", "TasksMax=512"} <= lines)
ok("the firewall rules loaded (as root) before every start", "ExecStartPre=+/usr/sbin/nft -f /etc/caddy/looking-glass/firewall.nft" in lines)
rc, fw, _ = run("firewall", "--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000")
ok("firewall: a table of Looking Glass's own, replaced whole on every load", rc == 0 and "table inet lg_caddy\ndelete table inet lg_caddy\n" in fw)
ok("…Caddy may send only to this computer and answer open connections; anything else it sends is dropped",
   'meta skuid "caddy" ip daddr 127.0.0.0/8 accept' in fw and 'meta skuid "caddy" ip6 daddr ::1 accept' in fw
   and 'meta skuid "caddy" ct state established,related accept' in fw
   and 'meta skuid "caddy" counter drop' in fw and fw.index("ip daddr 127.0.0.0/8 accept") < fw.index("counter drop"))
ok("…one address: at most 100 connections at once to the public port (IPv4 and IPv6), this computer not counted",
   "tcp dport 443 ct state new add @conn4 { ip saddr ct count over 100 }" in fw
   and "tcp dport 443 ct state new add @conn6 { ip6 saddr ct count over 100 }" in fw
   and fw.index("ip saddr 127.0.0.0/8 accept") < fw.index("@conn4"))
rc, fw2, _ = run("firewall", "--domain", "x.example.org", "--public-port", "8443", "--backend-port", "5000", "--conn-limit", "250")
ok("…the limit can be set (--conn-limit)", rc == 0 and "ct count over 250" in fw2 and "tcp dport 8443" in fw2)
rc, _, _ = run("firewall", "--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000", "--conn-limit", "3")
ok("…a limit under 10 is refused (it would lock out a normal browser)", rc != 0)
src0 = open(SCRIPT, encoding="utf-8").read()
ok("Caddy's security updates install by themselves (its repository added to Ubuntu's automatic updates)",
   'Unattended-Upgrade::Origins-Pattern { "origin=cloudsmith/caddy/stable"; };' in src0 and 'AUTOUPD="/etc/apt/apt.conf.d/52looking-glass-caddy"' in src0)
ok("the firewall table is loaded again whenever the nftables service starts or reloads (its conf flushes everything)",
   '"ExecStartPost=-/usr/sbin/nft -f $CERTS/firewall.nft" "ExecReload=-/usr/sbin/nft -f $CERTS/firewall.nft"' in src0
   and 'NFT_DROPIN="/etc/systemd/system/nftables.service.d/looking-glass-caddy.conf"' in src0 and 'rm -f "$DROPIN" "$NFT_DROPIN"' in src0)
ok("setup checks the rules with nftables first; remove deletes the table", 'nft -c -f "$CERTS/firewall.nft"' in src0
   and "nft delete table inet lg_caddy" in src0)
ok("setup installs it and reloads systemd; remove takes it away", 'hardening > "$DROPIN"' in src0 and 'rm -f "$DROPIN"' in src0)

print("Caddy's package source")
src = open(SCRIPT, encoding="utf-8").read()
ok("the signing key is pinned by its full fingerprint", 'KEY_FP="65760C51EDEA2017CEA2CA15155B6D79CA56EA34"' in src)
ok("…and refused when the downloaded key differs", '[ "$fp" = "$KEY_FP" ] ||' in src)
ok("the repository is Caddy's stable one, signed-by that keyring, and preferred for the caddy package",
   "signed-by=$KEYRING" in src and "dl.cloudsmith.io/public/caddy/stable/deb/debian" in src and "Pin-Priority: 900" in src)

print("The installer, renewals and the uninstaller")
inst = find("tools/release_root/install.sh", "install.sh", "../install.sh")
ok("a bought certificate puts Caddy in front on the public port", 'PUBLIC_PORT="$LG_PORT"; TRUST_PROXY=1' in inst
   and 'caddy_front.sh" "${cfargs[@]}"' in inst)
ok("…Looking Glass itself not on the network then (no --network)", '[ "$HTTPS" != domain ] && iargs+=(--network)' in inst)
ok("…the firewall and the self-check use Caddy's port", 'sudo ufw allow "$PUBLIC_PORT/tcp"' in inst
   and '--resolve "$TLS_DOMAIN:$PUBLIC_PORT:127.0.0.1"' in inst)
ok("…a re-run keeps the port Caddy already holds", "grep -qE \"^https://[^ ]*:$1 \\{\" /etc/caddy/Caddyfile" in inst)
ren = find("manage/install_cert.sh")
ok("a renewal copies the certificate to Caddy and checks Caddy's port", "caddy_front.sh sync" in ren)
un = find("tools/release_root/uninstall.sh", "uninstall.sh", "../uninstall.sh")
ok("the uninstaller removes only Looking Glass's Caddy configuration", "caddy_front.sh\" remove" in un)
if not inst:
    print("  (the installer is not in this tree: its checks counted as failed)")

print(f"\n{checks - len(fails)} of {checks} Caddy front checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
