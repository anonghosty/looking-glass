#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""deploy/caddy_front.sh adopt RUN end to end, offline and without root, on a made-up machine (2026-11-26: a check of
the script's text let a real server's adopt pick the wrong service and stop without a word; a review then found steps
that stopped with nothing put back). What is proved, by running it:

  1. a working adopt: Caddy's site written, Looking Glass moved to 127.0.0.1, TRUST_PROXY and LG_PORT set, DONE;
  2. a step inside the Caddy setup that fails (not one that calls die: a plain command) stops it, and EVERYTHING is
     put back: the service file and .env byte for byte, and no DONE (bash ignores set -e inside "( ... ) || rollback");
  3. a public installation whose certificate names a wildcard first is refused BEFORE anything changes;
  4. an internal installation without a certificate: adopt makes one; when a later step fails, the certificate it made
     goes too (moved into the kept copies), so the service does not start serving HTTPS on its old port;
  5. ACCESS_MODE is read as Looking Glass reads it: "public  # a comment" is public; an unknown value is local.

The machine: a copy of the script whose /etc and /usr/share paths point into a temporary folder, a made-up platform
folder (its .env, service file, certificate, security.py and service_unit.py), and stand-ins on PATH for id, systemctl,
runuser, ss, curl, caddy, nft, getent, install, chown, dpkg-query, apt-config and apt-get that record what they are
asked. Nothing outside the temporary folder is read or written. Run: .venv/bin/python tests/check_caddy_adopt_run.py"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
passed = failed = 0


def ok(name, cond, detail=""):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok   {name}")
    else:
        failed += 1
        print(f"  FAIL {name}" + (f": {str(detail)[:600]}" if detail else ""))


for tool in ("bash", "openssl", "sed"):
    if not shutil.which(tool):
        print(f"SKIPPED: {tool} is not installed here")
        sys.exit(77)

STUBS = {
    "id": r'''case "$1" in -u) echo 0 ;; -gn) id_real=$(command -p id -gn "${2:-}" 2>/dev/null); echo "${id_real:-users}" ;; *) command -p id "$@" ;; esac''',
    # systemctl: answers from the made-up unit file; records every call; FAIL_RESTART makes a restart of that unit fail
    "systemctl": r'''echo "systemctl $*" >> "$T/calls.log"
case "$1" in
  show) u="${@: -1}"; u="${u%.service}"; f="$T/etc/systemd/system/$u.service"
        case "$*" in *ExecStart*) [ -f "$f" ] && sed -n 's/^ExecStart=/{ path=x ; argv[]=/p' "$f" | sed 's/$/ ; }/' ;;
                     *WorkingDirectory*) [ -f "$f" ] && sed -n 's/^WorkingDirectory=//p' "$f" ;;
                     *MainPID*) echo 1 ;; esac; exit 0 ;;
  list-units|list-unit-files) for f in "$T"/etc/systemd/system/*.service; do [ -f "$f" ] && echo "$(basename "$f") loaded active running x"; done; exit 0 ;;
  restart) [ -n "${FAIL_RESTART:-}" ] && [ "$2" = "$FAIL_RESTART" ] && exit 1; exit 0 ;;
  *) exit 0 ;;
esac''',
    "runuser": r'''while [ "$1" != "--" ]; do shift; done; shift; exec "$@"''',
    "ss": "exit 0",
    "curl": r'''echo "curl $*" >> "$T/calls.log"; exit 0''',
    "caddy": r'''case "$1" in version) echo "v2.11.9 test" ;; esac; exit 0''',
    "nft": r'''echo "nft $*" >> "$T/calls.log"; exit 0''',
    "getent": "exit 0",
    "chown": "exit 0",
    "dpkg-query": "exit 1",
    "apt-config": r'''echo 'APT::Periodic::Unattended-Upgrade "1";' ''',
    "apt-get": "exit 0",
    # install: the real one, without owners (no root here); FAIL_INSTALL_MATCH makes one target fail (a plain step)
    "install": r'''a=(); while [ $# -gt 0 ]; do case "$1" in -o|-g) shift 2 ;; *) a+=("$1"); shift ;; esac; done
[ -n "${FAIL_INSTALL_MATCH:-}" ] && [[ "${a[*]}" == *"$FAIL_INSTALL_MATCH"* ]] && exit 1
exec /usr/bin/install "${a[@]}"''',
}


def make_cert(d, san, ca=False):
    """A certificate in d/cert.pem, key.pem with this subjectAltName; signed by a made-up CA when ca (not self-signed)."""
    os.makedirs(d, exist_ok=True)
    run = lambda *a: subprocess.run(a, cwd=d, capture_output=True, text=True, check=True)  # noqa: E731
    if not ca:
        run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "cert.pem",
            "-days", "2", "-subj", "/CN=lg-test", "-addext", f"subjectAltName={san}")
        return
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2",
        "-subj", "/CN=Made-up CA")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", "key.pem", "-out", "req.csr", "-subj", "/CN=site")
    with open(os.path.join(d, "ext.cnf"), "w") as f:
        f.write(f"subjectAltName={san}\n")
    run("openssl", "x509", "-req", "-in", "req.csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-CAcreateserial", "-out",
        "cert.pem", "-days", "2", "-extfile", "ext.cnf")
    for x in ("ca.key", "ca.pem", "req.csr", "ext.cnf", "ca.srl"):
        try:
            os.remove(os.path.join(d, x))
        except OSError:
            pass


def machine(env_lines, cert=None, ca=False, svc="lgx"):
    """A fresh made-up machine: (T, project, script, unit path)."""
    # the folder always holds "-bind-" and "-b": an option's letters inside a path must not be read as the option
    T = tempfile.mkdtemp(prefix="lg-adopt-bind-b")
    P = os.path.join(T, "platform")
    os.makedirs(os.path.join(P, "deploy")); os.makedirs(os.path.join(P, "data"))
    for f in ("security.py",):
        shutil.copy(os.path.join(PF, f), P)
    for f in ("service_unit.py", "looking-glass.service.template"):
        shutil.copy(os.path.join(PF, "deploy", f), os.path.join(P, "deploy"))
    # the platform's whole virtual environment, not its python alone: a python linked by itself into a folder without
    # pyvenv.cfg runs as the bare system Python, without the platform's packages (2026-11-26: passed here, where the
    # system Python happens to have them, and failed 13 of 19 on lg-test, a clean installation like a customer's)
    venv = os.path.dirname(os.path.dirname(os.path.abspath(sys.executable)))
    os.symlink(os.path.realpath(venv) if os.path.isfile(os.path.join(venv, "pyvenv.cfg")) else venv, os.path.join(P, ".venv"))
    with open(os.path.join(P, ".env"), "w") as f:
        f.write("\n".join(env_lines + [f"LG_SERVICE={svc}"]) + "\n")
    # make_tls_cert.sh stand-in: a self-signed certificate for lg.example (the real one is checked elsewhere)
    with open(os.path.join(P, "deploy", "make_tls_cert.sh"), "w") as f:
        f.write("#!/bin/bash\nset -e\nmkdir -p data/tls\nopenssl req -x509 -newkey rsa:2048 -nodes -keyout data/tls/key.pem "
                "-out data/tls/cert.pem -days 2 -subj /CN=lg -addext subjectAltName=DNS:lg.example >/dev/null 2>&1\n")
    os.chmod(os.path.join(P, "deploy", "make_tls_cert.sh"), 0o755)
    if cert:
        make_cert(os.path.join(P, "data", "tls"), cert, ca=ca)
    for d in ("etc/systemd/system", "etc/caddy", "etc/apt/sources.list.d", "etc/apt/preferences.d", "etc/apt/apt.conf.d",
              "usr/share/keyrings", "stub"):
        os.makedirs(os.path.join(T, d), exist_ok=True)
    # the installed service file, written as the installer writes it, listening on the network
    unit = os.path.join(T, "etc", "systemd", "system", f"{svc}.service")
    subprocess.run([sys.executable, os.path.join(P, "deploy", "service_unit.py"), "render", "--user", os.environ.get("USER") or "lg",
                    "--project", P, "--bind", "0.0.0.0:8443", "--out", unit], check=True, capture_output=True)
    # Caddy is already installed from its repository (install_caddy skips the download)
    src = open(os.path.join(PF, "deploy", "caddy_front.sh"), encoding="utf-8").read()
    repo = re.search(r'^REPO="([^"]+)"', src, re.M).group(1)
    with open(os.path.join(T, "etc", "apt", "sources.list.d", "caddy-stable.list"), "w") as f:
        f.write(f"deb [signed-by=x] {repo} any-version main\n")
    script = os.path.join(T, "caddy_front.sh")
    with open(script, "w", encoding="utf-8") as f:
        f.write(src.replace("/etc/", T + "/etc/").replace("/usr/share/keyrings", T + "/usr/share/keyrings"))
    os.chmod(script, 0o755)
    for name, body in STUBS.items():
        p = os.path.join(T, "stub", name)
        with open(p, "w") as f:
            f.write("#!/bin/bash\n" + body + "\n")
        os.chmod(p, 0o755)
    return T, P, script, unit


def adopt(T, P, script, **extra):
    env = {**os.environ, "PATH": os.path.join(T, "stub") + ":" + os.environ.get("PATH", ""), "T": T, **extra}
    r = subprocess.run(["bash", script, "adopt", "--yes", "--project", P], capture_output=True, text=True, env=env, timeout=120)
    return r.returncode, r.stdout + r.stderr


def read(p):
    try:
        with open(p, encoding="utf-8") as f:
            return f.read()
    except OSError:
        return None


def main():
    """The adopt runs (the harness above is shared: tests/check_caddy_paths_run.py runs the other commands with it)."""
    cleanup = []
    try:
        print("1. A working adopt (internal, with its own certificate)")
        T, P, s, unit = machine(["ACCESS_MODE=private", "VIEWER_NETWORKS=internal"], cert="DNS:lg.example,IP:10.0.0.5")
        cleanup.append(T)
        rc, out = adopt(T, P, s)
        env1, unit1 = read(os.path.join(P, ".env")), read(unit)
        ok("it says DONE and exits 0", rc == 0 and "DONE: Caddy answers on port 8443" in out, out[-800:])
        ok("…Looking Glass now listens on 127.0.0.1 only", "--bind 127.0.0.1:50" in (unit1 or ""), unit1)
        ok("…TRUST_PROXY=1 and LG_PORT in .env", "TRUST_PROXY=1" in env1 and re.search(r"^LG_PORT=50\d\d$", env1, re.M), env1)
        ok("…Caddy's site file written (Looking Glass's mark, the internal name)",
           "Managed by Looking Glass" in (read(os.path.join(T, "etc", "caddy", "Caddyfile")) or "")
           and "# internal: lg.example" in (read(os.path.join(T, "etc", "caddy", "Caddyfile")) or ""))
        ok("…its site caps Caddy's connections to Looking Glass (max_conns_per_host)",
           "max_conns_per_host 6" in (read(os.path.join(T, "etc", "caddy", "Caddyfile")) or ""))
        ok("…and the hardening and firewall drop-ins", os.path.isfile(os.path.join(T, "etc", "systemd", "system", "caddy.service.d", "looking-glass.conf"))
           and os.path.isfile(os.path.join(T, "etc", "systemd", "system", "nftables.service.d", "looking-glass-caddy.conf")))

        print("2. A plain step inside the Caddy setup fails: it stops, and everything is put back")
        T, P, s, unit = machine(["ACCESS_MODE=private", "VIEWER_NETWORKS=internal"], cert="DNS:lg.example")
        cleanup.append(T)
        env0, unit0 = read(os.path.join(P, ".env")), read(unit)
        rc, out = adopt(T, P, s, FAIL_INSTALL_MATCH="caddy.service.d")      # install -d of the hardening drop-in's folder
        ok("it does NOT say DONE and exits non-zero", rc != 0 and "DONE" not in out, out[-900:])
        ok("…it says which step stopped it (no silent stop)", "stopped at line" in out or "Caddy could not be set up" in out, out[-600:])
        ok("…it puts everything back", "putting everything back" in out, out[-600:])
        ok("…the service file is byte for byte as before", read(unit) == unit0)
        ok("…and so is .env", read(os.path.join(P, ".env")) == env0)

        print("3. A public installation whose certificate names a wildcard first: refused before anything changes")
        T, P, s, unit = machine(["ACCESS_MODE=public"], cert="DNS:*.example.org,DNS:lg.example.org", ca=True)
        cleanup.append(T)
        env0, unit0 = read(os.path.join(P, ".env")), read(unit)
        rc, out = adopt(T, P, s)
        ok("refused, with the reason", rc != 0 and "not a domain name" in out and "nothing was changed" in out, out[-600:])
        ok("…nothing changed: service file, .env, no copies taken, no restart",
           read(unit) == unit0 and read(os.path.join(P, ".env")) == env0 and not os.path.isdir(os.path.join(P, "backups"))
           and "systemctl restart" not in (read(os.path.join(T, "calls.log")) or ""))

        print("4. An internal installation without a certificate, then a later step fails: the certificate it made goes too")
        T, P, s, unit = machine(["ACCESS_MODE=private", "VIEWER_NETWORKS=internal"])
        cleanup.append(T)
        env0, unit0 = read(os.path.join(P, ".env")), read(unit)
        rc, out = adopt(T, P, s, LG_ADOPT_FAIL_STEP="caddy")
        ok("it stops and puts everything back", rc != 0 and "putting everything back" in out and "DONE" not in out, out[-600:])
        ok("…the certificate it made is no longer where the service would use it",
           not os.path.exists(os.path.join(P, "data", "tls", "cert.pem")), os.listdir(os.path.join(P, "data", "tls")) if os.path.isdir(os.path.join(P, "data", "tls")) else "")
        ok("…it is kept with the copies, not deleted", any(os.path.isfile(os.path.join(dp, "cert.pem")) and "made-certificate" in dp
                                                            for dp, _, _ in os.walk(os.path.join(P, "backups"))))
        ok("…service file and .env as before", read(unit) == unit0 and read(os.path.join(P, ".env")) == env0)

        print("5. ACCESS_MODE as Looking Glass reads it")
        T, P, s, unit = machine(["ACCESS_MODE=public   # the internet"], cert="DNS:lg.example")
        cleanup.append(T)
        rc, out = adopt(T, P, s)
        ok("'public  # a comment' is public (a self-signed certificate is then refused, as for public)",
           rc != 0 and "not a self-signed one" in out, out[-500:])
        T, P, s, unit = machine(["ACCESS_MODE=internal"], cert="DNS:lg.example")
        cleanup.append(T)
        rc, out = adopt(T, P, s)
        ok("an unknown value ('internal') is local to Looking Glass, so adopt says Caddy is not needed",
           rc != 0 and "ACCESS_MODE is local" in out, out[-500:])
    finally:
        for t in cleanup:
            shutil.rmtree(t, ignore_errors=True)

    print()
    print(f"{passed}/{passed + failed} adopt runs checked" + (f"; {failed} FAILED" if failed else ""))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
