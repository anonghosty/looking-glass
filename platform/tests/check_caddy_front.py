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
import shutil
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
ok("…no private CA unless one is given", "tls_trust_pool" not in conf and "tls_trusted_ca_certs" not in conf)
rc, conf2, _ = run("render", "--domain", "lg.example.org", "--public-port", "8443", "--backend-port", "5001",
                   "--ca-bundle", __file__)
ok("a private CA (test installations) is trusted from Caddy's own copy", rc == 0
   and "tls_trust_pool file /etc/caddy/looking-glass/ca-bundle.pem" in conf2)
for args, why in ((["--domain", "bad domain", "--public-port", "443", "--backend-port", "5000"], "a name that is not a domain"),
                  (["--domain", "x.example.org", "--public-port", "443", "--backend-port", "443"], "the same port twice"),
                  (["--domain", "x.example.org", "--public-port", "99999", "--backend-port", "5000"], "a port out of range"),
                  (["--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000", "--ca-bundle", "/no/such"], "a missing CA file")):
    rc, out, _ = run("render", *args)
    ok(f"refused: {why}", rc != 0 and not out)
rc, out, err = run("setup", "--domain", "x.example.org", "--public-port", "443", "--backend-port", "5000")
ok("setup needs root (nothing is changed without sudo)", (rc != 0 and "sudo" in err) or os.geteuid() == 0, err)

print("Internal installations (ACCESS_MODE=private): Caddy in front too, with the installation's own certificate")
import tempfile  # noqa: E402
for san, first in (("IP:10.20.0.5,DNS:lg-ops", "lg-ops"), ("IP:10.20.0.5", "10.20.0.5"),
                   ("DNS:localhost,IP:127.0.0.1,DNS:lg-ops,IP:10.20.0.5", "lg-ops"),   # make_tls_cert.sh's order
                   ("DNS:localhost,IP:127.0.0.1,IP:10.20.0.5", "10.20.0.5"), ("DNS:localhost,IP:127.0.0.1", "localhost")):
    proj = tempfile.mkdtemp(prefix="lg-caddy-int-")
    os.makedirs(os.path.join(proj, "data", "tls"))
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=lg-made-up",
                    "-addext", f"subjectAltName={san}", "-keyout", os.path.join(proj, "data", "tls", "key.pem"),
                    "-out", os.path.join(proj, "data", "tls", "cert.pem")], capture_output=True, check=True)
    rc, ci, err = run("render", "--internal", "--project", proj, "--public-port", "8443", "--backend-port", "5001")
    ok(f"it renders from the certificate ({san})", rc == 0 and ci, err)
    ok("…any name or address people use, on the network port", "https://:8443 {" in ci)
    ok(f"…the certificate's first name offered to visitors that send none, and remembered ({first})",
       re.search(rf"^\s*default_sni {re.escape(first)}$", ci, re.M) and f"# internal: {first}" in ci)
    ok("…Looking Glass behind it checked under that name, against that certificate only, never skipped",
       f"tls_server_name {first}" in ci and "tls_trust_pool file /etc/caddy/looking-glass/cert.pem" in ci and "insecure" not in ci.lower())
    ok("…the same strict time limits and no fingerprint", "read_header 10s" in ci and "-Server" in ci and "admin off" in ci)
import time  # noqa: E402

sys.path.insert(0, ROOT)
import system_alerts  # noqa: E402
bd = tempfile.mkdtemp(prefix="lg-caddy-bell-")
os.makedirs(os.path.join(bd, "data"), exist_ok=True)
cf = os.path.join(bd, "Caddyfile")
system_alerts.Alerts.CADDYFILE = cf
al = system_alerts.Alerts(bd, env={"ACCESS_MODE": "private"})._no_caddy_internal(time.time())
ok("an internal installation with no Caddy in front: the administrators' bell says so", al and al[0]["problem"]
   and "no Caddy in front" in al[0]["title"] and "sudo deploy/caddy_front.sh adopt" in al[0]["text"]
   and al[0]["link"] == "/settings#monitor", al)
ok("…again every day (one alert per day)", al and al[0]["key"].startswith("no-caddy-internal:" + time.strftime("%Y-%m-%d", time.gmtime())))
with open(cf, "w") as f:
    f.write("# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced by the next setup or renewal.\n")
ok("…and not once Looking Glass's Caddy is in front", system_alerts.Alerts(bd, env={"ACCESS_MODE": "private"})._no_caddy_internal(time.time()) == [])
with open(cf, "w") as f:
    f.write("example.org {\n}\n")
ok("…a Caddyfile someone else wrote does not count", system_alerts.Alerts(bd, env={"ACCESS_MODE": "private"})._no_caddy_internal(time.time()) != [])
ok("…a local installation (this computer only): no reminder",
   system_alerts.Alerts(bd, env={"ACCESS_MODE": "local"})._no_caddy_internal(time.time()) == [])
pub = system_alerts.Alerts(bd, env={"ACCESS_MODE": "public"})._no_caddy_internal(time.time())
ok("…a public installation without Caddy (an office network from before the internal choice): reminded too, with the command",
   pub and pub[0]["title"] == "This installation has no Caddy in front" and "caddy_front.sh adopt" in pub[0]["text"], pub)
# adopt: an installation already running (the end-to-end proof is big_release/caddy_adopt_proof.sh on lg-test)
src = open(os.path.join(ROOT, "deploy", "caddy_front.sh"), encoding="utf-8").read()
# 2026-11-26: setup, sync, update and adopt's Caddy step run in in_step (a snapshot of our files, put back on failure);
# what they do is RUN by tests/check_caddy_paths_run.py and tests/check_caddy_adopt_run.py
ok("adopt: a command of its own, reusing setup's steps (one place); RUN end to end by tests/check_caddy_adopt_run.py",
   "  adopt) adopt ;;" in src and "do_setup() {" in src and "in_step() {" in src and "in_step do_setup" in src)
ok("…root only; a Caddyfile someone else wrote, a local installation, a public one without its domain's certificate: refused",
   all(w in src for w in ('need_root\n  [ -f "$project/.env" ]', "was not written by Looking Glass: not replaced",
                          "ACCESS_MODE is local", "not a self-signed one")))
ok("…says what will change and asks once (--yes only for the checks and scripts)", 'read -r -p "Go ahead? Type yes: "' in src
   and "not asked on a terminal: run it again with --yes" in src)
ok("…keeps copies first (backups/ owned by the service's user), puts everything back if a step fails",
   'cp -p "$unit" "$keep/$svc.service"; cp -p "$project/.env" "$keep/env"' in src and "rollback() {" in src
   and 'install -d -m 700 -o "$owner" -g "$grp" "$project/backups"' in src)
ok("…Looking Glass to 127.0.0.1 through the one service-file writer; TRUST_PROXY=1 and LG_PORT in .env",
   'service_unit.py" render --user "$owner" --project "$project" --bind "127.0.0.1:$bport"' in src
   and "env_set TRUST_PROXY 1 && env_set LG_PORT" in src)
ok("…without LG_SERVICE in .env, the service that runs this folder is found by its WorkingDirectory (an older install's own name)",
   'systemctl show -p WorkingDirectory --value "$u"' in src and 'svc="${u%.service}"' in src)
_loop = re.search(r'\n(    for u in \$\(systemctl list-units.*?\n    done)\n', src, re.S)
_found = ""
if _loop and shutil.which("bash"):
    # a server without LG_SERVICE (2026-11-26): the unusual-activity job, in the same folder, is listed before the web
    # service; a fake systemctl answers as that server's did
    _fake = r'''systemctl() {
  case "$*" in
    *list-units*) printf 'looking-glass-unusual.service loaded inactive dead x\nlooking-glass.service loaded active running y\n' ;;
    *"ExecStart --value looking-glass-unusual.service"*) echo '{ path=/p/.venv/bin/python ; argv[]=/p/.venv/bin/python manage/unusual_run.py ; }' ;;
    *"ExecStart --value looking-glass.service"*) echo '{ path=/p/.venv/bin/gunicorn ; argv[]=/p/.venv/bin/gunicorn --bind 0.0.0.0:443 app:app ; }' ;;
    *WorkingDirectory*) echo /srv/lg/platform ;;
  esac
}
project=/srv/lg/platform; svc=""
'''
    _found = subprocess.run(["bash", "-c", _fake + _loop.group(1) + '\nprintf "%s" "$svc"'], capture_output=True,
                            text=True, timeout=20).stdout.strip()
ok("…without LG_SERVICE, the WEB service (the one running gunicorn) is found, never a helper job in the same folder "
   "(2026-11-26: looking-glass-unusual was taken, and adopt stopped)", _found == "looking-glass", repr(_found))
ok("…the audit log written as the service's own user, never as root", 'runuser -u "$owner"' in src and "audit_chain.Chain" in src)
# Caddy never opens more connections to Looking Glass than its threads (2026-11-26: a page's HTTP/2 burst opened
# about 25; those not used at once each held a thread and new connections went unanswered for 3.5 minutes). The
# thread count is read from the service file the installer writes, so a change to either is compared, not assumed.
_tpl = open(os.path.join(ROOT, "deploy", "looking-glass.service.template"), encoding="utf-8").read()
_threads = int((re.search(r"--threads (\d+)", _tpl) or [0, "0"])[1]) * int((re.search(r"--workers (\d+)", _tpl) or [0, "1"])[1])
_cap = int((re.search(r"^UPSTREAM_CONNS=(\d+)", src, re.M) or [0, "0"])[1])
_site = subprocess.run(["bash", os.path.join(ROOT, "deploy", "caddy_front.sh"), "render", "--domain", "lg.example.org",
                        "--public-port", "443", "--backend-port", "5000"], capture_output=True, text=True, timeout=20).stdout \
    if shutil.which("bash") else ""
ok(f"Caddy's site caps its connections to Looking Glass ({_cap}) below the service's threads ({_threads}): "
   "max_conns_per_host and keepalive_idle_conns_per_host, in the site it really writes",
   0 < _cap < _threads and f"max_conns_per_host {_cap}" in _site and f"keepalive_idle_conns_per_host {_cap}" in _site,
   (_cap, _threads, _site[-400:]))
# never a silent stop (2026-11-26: adopt answered a server's administrator with nothing at all)
ok("…any step that fails says where and what (an ERR trap, inherited by every function: set -E), said once",
   "set -Eeuo pipefail" in src and "trap 'on_err $? $LINENO \"$BASH_COMMAND\"' ERR" in src
   and '[ "$BASHPID" = "$$" ] || [ -n "${LG_IN_STEP:-}" ] || return 0' in src)
_fn = re.search(r"^  (bind_of\(\) \{.*\})$", src, re.M)
_bind = {}
if _fn and shutil.which("bash"):
    for s_ in ("argv[]=/x/gunicorn --workers 1 --bind 0.0.0.0:8000 app:app ; }", "/x/gunicorn --bind=0.0.0.0:443 app:app",
               "/x/gunicorn -b 10.0.0.5:5000 app:app", "/x/gunicorn -b[::]:443 app:app", "/x/gunicorn -c gunicorn.conf.py app:app",
               # a "-b" or "--bind" inside a path is not the option (2026-11-26: /tmp/lg-adopt-b... was read as one)
               "argv[]=/srv/lg-backup/.venv/bin/gunicorn --bind 0.0.0.0:8443 app:app ; }",
               "argv[]=/home/x/a-bind-test/gunicorn -c conf.py app:app ; }"):
        _bind[s_] = subprocess.run(["bash", "-c", _fn.group(1) + '; printf "%s" "$1" | bind_of || true', "_", s_],
                                   capture_output=True, text=True, timeout=20).stdout.strip()
ok("…the address the service listens on, in every form gunicorn takes (--bind A, --bind=A, -b A, -bA); none: said in words",
   list(_bind.values()) == ["0.0.0.0:8000", "0.0.0.0:443", "10.0.0.5:5000", "[::]:443", "", "0.0.0.0:8443", ""]
   and "names no --bind or -b" in src and "not HOST:PORT" in src, _bind)
_help = subprocess.run(["bash", os.path.join(ROOT, "deploy", "caddy_front.sh")], capture_output=True, text=True, timeout=20) \
    if shutil.which("bash") else None
ok("…with no command: the whole help, its commands included (it stopped mid-sentence before them)",
   _help is not None and _help.returncode == 2 and "deploy/caddy_front.sh adopt" in _help.stdout
   and "deploy/caddy_front.sh remove" in _help.stdout and "set -" not in _help.stdout,
   (_help.returncode, _help.stdout[-200:]) if _help else "no bash")
_done = src[src.index('echo "DONE: Caddy answers on port'):src.index("The administrators' daily reminder stops")]
_trust = _done.index("go on trusting it")
ok("…the last words match what happened: a certificate made now means https:// and one 'trust it' question per "
   "browser; 'the same certificate' is said only when there was one before",
   "made_cert=1" in src and 'if [ "$made_cert" = 1 ]; then' in _done and "now with https://" in _done
   and "asks once to trust the new certificate" in _done
   and _done.index('if [ "$made_cert" = 1 ]') < _done.index('elif [ "$internal" = 1 ]') < _trust)
import task_monitor  # noqa: E402
task_monitor.CADDYFILE = cf
os.environ["ACCESS_MODE"] = "private"
fr = task_monitor._front()
ok("Settings -> Task monitor knows whether Caddy is in front, and shows the command when not",
   fr["needed"] is True and fr["caddy"] is False and fr["command"] == "sudo deploy/caddy_front.sh adopt", fr)
os.environ.pop("ACCESS_MODE", None)
rc, out, err = run("render", "--internal", "--project", tempfile.mkdtemp(), "--public-port", "8443", "--backend-port", "5001")
ok("refused: an internal installation without its certificate", rc != 0 and not out and "make_tls_cert" in err, err)
rc, out, _ = run("render", "--internal", "--domain", "x.example.org", "--project", proj, "--public-port", "8443", "--backend-port", "5001")
ok("refused: --internal and --domain together", rc != 0 and not out)

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

print("Keeping Caddy up to date (update, status, the administrators' bell)")
rc, out, err = run("update")
ok("update needs root (nothing is changed without sudo)", (rc != 0 and "sudo" in err) or os.geteuid() == 0, err)
upd = src.split("  update)", 1)[1].split(";;", 1)[0] if "  update)" in src else ""
ok("update: only where Looking Glass set Caddy up", 'grep -qF "$MARK" || die "Caddy is not set up by Looking Glass here' in upd)
ok("…the repository key checked against the pinned fingerprint before anything is fetched",
   "key_ok" in upd and upd.index("key_ok") < upd.index("apt-get update") and 'gpg --show-keys --with-colons "$KEYRING"' in src
   and '[ "$fp" = "$KEY_FP" ] || die "Caddy\'s repository key has an unexpected fingerprint' in src)
ok("…Caddy only, from its own repository list, keeping our Caddyfile",
   "--only-upgrade -o Dpkg::Options::=--force-confold caddy" in upd and '-o Dir::Etc::sourcelist="$LIST"' in upd)
ok("…our Caddyfile and hardening checked afterwards, then the site through Caddy",
   'die "$CONF was replaced during the update' in upd and '[ -f "$DROPIN" ]' in upd and upd.rstrip().find("check_front") > upd.find("apt-get install"))
ok("…restarted only when the version or our Caddyfile changed, and it says which",
   'if [ "$before" != "$after" ] || [ "$old" != "$(cat "$CONF")" ]; then' in upd and "Caddy updated: $before -> $after" in upd)
# setup's steps are one function since 2026-11-25 (adopt uses them too): read its body
setup_part = src.split("do_setup() {", 1)[1].split("\n}\n", 1)[0]
ok("setup and update make sure Ubuntu's automatic updates are there", "auto_updates || true" in setup_part and "auto_updates || true" in upd
   and "apt-get install -y -qq unattended-upgrades" in src)
ok("…an administrator who switched them off is not overruled: said plainly, with what to do",
   "APT::Periodic::Unattended-Upgrade" in src and 'APT::Periodic::Unattended-Upgrade "1"' not in src
   and "dpkg-reconfigure -plow unattended-upgrades" in src)
st_part = src.split("  status)", 1)[1].split(";;", 1)[0]
ok("status: the installed and the newest version, and whether automatic updates are on", "versions" in st_part
   and "available: sudo deploy/caddy_front.sh update" in st_part and "automatic updates: OFF for Caddy" in st_part)

sys.path.insert(0, ROOT)
import tempfile  # noqa: E402

import caddy_watch  # noqa: E402
tmp = tempfile.mkdtemp()
mine, other, auto = (os.path.join(tmp, n) for n in ("Caddyfile", "Caddyfile.other", "52looking-glass-caddy"))
open(mine, "w").write(caddy_watch.MARK + ": changes here are replaced\n{\n}\n")
open(other, "w").write("example.org {\n}\n")
open(auto, "w").write("x\n")


def fake(installed="2.10.0", candidate="2.10.2", uu="install ok installed", periodic='APT::Periodic::Unattended-Upgrade "1";\n'):
    def run_(args):
        if args[:2] == ["dpkg-query", "-W"] and args[-1] == "caddy":
            return 0, installed
        if args[:2] == ["apt-cache", "policy"]:
            return 0, f"caddy:\n  Installed: {installed}\n  Candidate: {candidate}\n"
        if args[0] == "dpkg" and args[1] == "--compare-versions":
            a, b = args[2], args[4]
            return (0 if tuple(map(int, a.split("."))) < tuple(map(int, b.split("."))) else 1), ""
        if args[:2] == ["dpkg-query", "-W"] and args[-1] == "unattended-upgrades":
            return 0, uu
        if args[:2] == ["apt-config", "dump"]:
            return 0, periodic
        return 1, ""
    return run_


ok("the bell: nothing where Looking Glass did not set Caddy up", caddy_watch.state(conf=other, autoupd=auto, run=fake()) is None
   and caddy_watch.bell(conf=other, autoupd=auto, run=fake()) == [])
b = caddy_watch.bell(conf=mine, autoupd=auto, run=fake())
ok("…a newer Caddy in its repository: one alert, for administrators, saying the command", len(b) == 1 and b[0]["key"] == "caddy-behind:2.10.2"
   and b[0]["perms"] == ("settings",) and "caddy_front.sh update" in b[0]["text"], b)
ok("…up to date and automatic updates on: no alert", caddy_watch.bell(conf=mine, autoupd=auto, run=fake(candidate="2.10.0")) == [])
b = caddy_watch.bell(conf=mine, autoupd=auto, run=fake(candidate="2.10.0", periodic='APT::Periodic::Unattended-Upgrade "0";\n'))
ok("…automatic updates switched off: said, with how to switch them on", len(b) == 1 and b[0]["key"].startswith("caddy-autoupdates:")
   and "switched off" in b[0]["text"] and "dpkg-reconfigure" in b[0]["text"], b)
b = caddy_watch.bell(conf=mine, autoupd=os.path.join(tmp, "missing"), run=fake(candidate="2.10.0", uu="unknown ok not-installed"))
ok("…the package missing and Caddy's repository not among them: both reasons", len(b) == 1 and "not installed" in b[0]["text"]
   and "is missing" in b[0]["text"], b)
sa = open(os.path.join(ROOT, "system_alerts.py"), encoding="utf-8").read()
ok("…on the administrators' bell, never breaking it", "out += self._caddy(now)" in sa and "caddy_watch.bell(self.base_dir, now)" in sa)

print("The installer, renewals and the uninstaller")
inst = find("tools/release_root/install.sh", "install.sh", "../install.sh")
ok("a bought certificate puts Caddy in front on the public port", 'PUBLIC_PORT="$LG_PORT"; TRUST_PROXY=1' in inst
   and 'caddy_front.sh" "${cfargs[@]}"' in inst)
ok("…Looking Glass itself never on the network (no --network for any choice: Caddy is in front)",
   'iargs+=(--network)' not in inst and 'iargs=(--port "$LG_PORT" --name "$SERVICE_NAME" --no-sources)' in inst)
ok("an internal installation puts Caddy in front too, with its own certificate (--internal)",
   '[ "$HTTPS" = domain ] || [ "$HTTPS" = selfsigned ]; then' in inst and '--internal --public-port "$PUBLIC_PORT"' in inst)
priv = inst.split('elif [ "$ACCESS_MODE" != local ]; then', 1)[1].split("HTTPS=\"$REPLY\"", 1)[0] if 'elif [ "$ACCESS_MODE" != local ]; then' in inst else ""
ok("…and offers no proxy of your own and no 'No HTTPS' there (Caddy could not be guaranteed in front)",
   priv and not re.search(r'^\s+(proxy|none)\s+"', priv, re.M) and re.search(r'^\s+selfsigned\s+"', priv, re.M)
   and re.search(r'^\s+domain\s+"', priv, re.M), priv[-400:])
ok("…the firewall and the self-check use Caddy's port", 'sudo ufw allow "$PUBLIC_PORT/tcp"' in inst
   and '--resolve "$TLS_DOMAIN:$PUBLIC_PORT:127.0.0.1"' in inst)
ok("…a re-run keeps the port Caddy already holds (a domain's site or an internal one)",
   "grep -qE \"^https://[^ ]*:$1 \\{|^https://:$1 \\{\" /etc/caddy/Caddyfile" in inst)
ren = find("manage/install_cert.sh")
ok("a renewal copies the certificate to Caddy and checks Caddy's port", "caddy_front.sh sync" in ren)
un = find("tools/release_root/uninstall.sh", "uninstall.sh", "../uninstall.sh")
ok("the uninstaller removes only Looking Glass's Caddy configuration", "caddy_front.sh\" remove" in un)
if not inst:
    print("  (the installer is not in this tree: its checks counted as failed)")

print(f"\n{checks - len(fails)} of {checks} Caddy front checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
