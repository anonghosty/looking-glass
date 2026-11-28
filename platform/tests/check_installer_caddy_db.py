#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The guided installer (install.sh) on its own functions, RUN in a scratch folder with stand-ins for systemctl and ss
(nothing is installed, no service touched; the production check of 2026-11-26 found these branches ran in no test):
1. the port question on a re-run: Looking Glass's own port is accepted under the service's own name (LG_SERVICE in
   .env, else the service running gunicorn in this folder), also behind Caddy on 127.0.0.1; another program's is not;
2. behind Caddy, Looking Glass keeps its backend port on a re-run under that name (it was "looking-glass" only);
3. "Not a Looking Glass database": with no person to answer (an answers file, no terminal) the same database refused
   twice stops the installer with what to do, never a loop for ever; bad answers then the end of the input stop it too;
   a person is asked for the new name even when the answers file named the refused one.
Usage: tests/check_installer_caddy_db.py"""
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = next((p for p in (os.path.join(HERE, "..", "install.sh"), os.path.join(HERE, "tools", "release_root", "install.sh"))
            if os.path.exists(p)), None)
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:300]}]" if info else ""), flush=True)


if not SRC:
    # an honest skip (77), never a pass that tried nothing; LG_NO_SKIP=1 (every release run) makes it a failure
    print("SKIPPED: install.sh is not next to this platform (an installation without the installer)")
    sys.exit(77)
src = open(SRC, encoding="utf-8").read()


def section(start, end, keep_end=True):
    a = src.index(start)
    b = src.index(end, a)
    return src[a:b + (len(end) if keep_end else 0)]


T = tempfile.mkdtemp(prefix="lg-inst-")
try:
    PF = os.path.join(T, "platform"); os.makedirs(PF)
    stub = os.path.join(T, "stub"); os.makedirs(stub)
    # systemctl: one gunicorn service "lgx" in PF bound to $BIND; ss: the ports in $USED are taken
    with open(os.path.join(stub, "systemctl"), "w") as f:
        f.write('#!/bin/bash\ncase "$1" in\n  list-units) echo "lgx.service loaded active running x"; echo "lgx-unusual.service loaded active running x" ;;\n'
                '  show) u="${@: -1}"; u="${u%.service}"; case "$*" in\n'
                '    *ExecStart*) [ "$u" = lgx ] && echo "{ path=/x/gunicorn ; argv[]=/x/gunicorn --bind $BIND -w 1 ; }"; [ "$u" = lgx-unusual ] && echo "{ argv[]=/x/python unusual.py ; }" ;;\n'
                f'    *WorkingDirectory*) echo "{PF}" ;; esac ;;\nesac\nexit 0\n')
    with open(os.path.join(stub, "ss"), "w") as f:
        f.write('#!/bin/bash\nfor p in $USED; do case "$*" in *":$p"*) echo "LISTEN 0 0 x:$p"; exit 0 ;; esac; done\nexit 0\n')
    for n in ("systemctl", "ss"):
        os.chmod(os.path.join(stub, n), 0o755)
    env0 = {**os.environ, "PATH": stub + ":" + os.environ.get("PATH", "")}
    caddyfile = os.path.join(T, "Caddyfile")
    fns = "\n".join([
        f'PF_DIR="{PF}"; IS_WSL=0',
        section("env_get() {", "\n"), section("v_port() {", "\n"), section("in_use() {", "\n"),
        section("BROWSER_BLOCKED=", "\n"), section("safe_free_port() {", "\n"),
        *([section("lg_service() {", "\n}\n"), section("lg_binds() {", "\n}\n")] if "lg_service() {" in src else []),
        section("v_lg_port() {", "\n}\n").replace("/etc/caddy/Caddyfile", caddyfile)])
    loop = section('    for q in $(seq 5000 5099); do\n      [ "$q" = "$PUBLIC_PORT" ]', "    done\n")

    def sh(code, **env):
        r = subprocess.run(["bash", "-c", "set -Eeuo pipefail\n" + fns + "\n" + code], capture_output=True, text=True,
                           env={**env0, **env}, timeout=60)
        return r.returncode, r.stdout + r.stderr

    print("1. The port question on a re-run")
    with open(os.path.join(PF, ".env"), "w") as f:
        f.write("LG_SERVICE=lgx\n")
    rc, out = sh('v_lg_port 8443', USED="8443", BIND="0.0.0.0:8443")
    ok("Looking Glass's own port, under its own service name (lgx): accepted", rc == 0, out)
    rc, out = sh('v_lg_port 5000', USED="5000 8443", BIND="127.0.0.1:5000")
    ok("…behind Caddy, on its backend port on 127.0.0.1: accepted", rc == 0, out)
    os.remove(os.path.join(PF, ".env"))
    rc, out = sh('v_lg_port 8443', USED="8443", BIND="0.0.0.0:8443")
    ok("…no LG_SERVICE in .env: the service running gunicorn in this folder is found (not its helper job)", rc == 0, out)
    rc, out = sh('v_lg_port 9443', USED="9443", BIND="0.0.0.0:8443")
    ok("a port another program uses: refused, saying so", rc != 0 and "already used by another program" in out, out)
    with open(caddyfile, "w") as f:
        f.write("# Managed by Looking Glass (deploy/caddy_front.sh)\n\nhttps://:8443 {\n}\n")
    rc, out = sh('v_lg_port 8443', USED="8443", BIND="127.0.0.1:5000")
    ok("Caddy in front, set up by Looking Glass, on the public port: accepted (a re-run keeps it)", rc == 0, out)

    print("2. Behind Caddy, Looking Glass keeps its backend port")
    with open(os.path.join(PF, ".env"), "w") as f:
        f.write("LG_SERVICE=lgx\n")
    rc, out = sh('PUBLIC_PORT=8443; LG_PORT=""\nfail() { echo "STOPPED: $1"; exit 1; }\n' + loop + 'echo "LG_PORT=$LG_PORT"',
                 USED="5000 8443", BIND="127.0.0.1:5000")
    ok("its own 127.0.0.1:5000 is kept (not moved to the next free port)", "LG_PORT=5000" in out, out)

    print("3. 'Not a Looking Glass database'")
    dialogs = section("# ------------------------------------------------------------------------------------------------------"
                      "---- dialogs", "# ------------------------------------------------------------------------------------"
                      "---------------------- progress", keep_end=False)
    block = section("    if [ $rc = 3 ]; then\n", "\n      esac\n    fi\n")
    head = '''set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"; LOG="$ROOT/run.log"; : > "$LOG"; ORIG_ARGS=()
UI=text; TITLE=t; B=; R=; D=; MAG=; CYN=; RED=; GRN=; YEL=
declare -A ANS=()
log() { printf '%s\\n' "$*" >> "$LOG"; }
fail() { echo "STOPPED: $1"; exit 1; }
'''
    vuser = section("v_user() {", "\n")
    flow = '''
MONGO_HOST=10.0.0.5; MONGO_PORT=27017; MONGO_DB=shadowserver; MONGO_MODE=remote; SWITCH_LOCAL=0; n=0
while :; do
  n=$((n + 1)); [ $n -gt 40 ] && { echo "LOOPED FOR EVER"; exit 3; }
  if [ "$MONGO_DB" = lg_new ]; then rc=0; else rc=3; fi
  reason="'$MONGO_DB' holds something else"
  [ $rc = 0 ] && break
''' + block + '''
  break
done
echo "END MONGO_DB=$MONGO_DB SWITCH_LOCAL=$SWITCH_LOCAL"
'''
    os.makedirs(os.path.join(T, "inst", "install-logs"))
    script = os.path.join(T, "inst", "install.sh")

    def inst(pre, typed=""):
        with open(script, "w") as f:
            f.write(head + pre + "\n" + vuser + "\n" + dialogs + flow)
        with open(os.path.join(T, "in.txt"), "w") as f:
            f.write(typed)
        with open(os.path.join(T, "in.txt")) as fin:
            r = subprocess.run(["bash", script], stdin=fin, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr

    rc, out = inst('INTERACTIVE=0; ASSUME_YES=0; ANS[DB_MISMATCH]=newdb; ANS[MONGO_DB]=other_db')
    ok("an answers file naming a database that is refused again: it stops, saying what to do (never a loop)",
       rc != 0 and "STOPPED" in out and "MONGO_DB" in out and "LOOPED" not in out, out[-300:])
    rc, out = inst('INTERACTIVE=0; ASSUME_YES=0; ANS[DB_MISMATCH]=retry')
    ok("…'retry' from the answers file (the same answers each time): it stops", rc != 0 and "STOPPED" in out and "LOOPED" not in out, out[-300:])
    rc, out = inst('INTERACTIVE=0; ASSUME_YES=0')
    ok("…no terminal and no answers file (the defaults each time): it stops", rc != 0 and "STOPPED" in out and "LOOPED" not in out, out[-300:])
    rc, out = inst('INTERACTIVE=1; ASSUME_YES=0', "9\nnot-a-choice\n")
    ok("a person's bad answers, then the end of the input: it stops (no loop)", rc != 0 and "LOOPED" not in out and "END" not in out, out[-300:])
    rc, out = inst('INTERACTIVE=1; ASSUME_YES=0; ANS[MONGO_DB]=shadowserver', "1\nlg_new\n")
    ok("a person choosing a new database is asked its name, even when the answers file named the refused one",
       rc == 0 and "END MONGO_DB=lg_new" in out, out[-300:])
    rc, out = inst('INTERACTIVE=1; ASSUME_YES=0', "2\n")
    ok("…or MongoDB on this computer instead", rc == 0 and "SWITCH_LOCAL=1" in out, out[-300:])
finally:
    shutil.rmtree(T, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
