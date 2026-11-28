#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""The guided installer's questions (install.sh; the user, 2026-11-19), on its own functions in a scratch folder: nothing
is installed, no package or service is touched.
1. Back: every question can go back to the one before (text mode: "<"); the answers before it are kept, in order;
   passwords travel in memory only, never to a file; Back on the first question stays there;
2. allowed networks: "internal" (any computer on the internal network) accepted; 0.0.0.0 (nobody) and 0.0.0.0/0 or
   ::/0 (the whole internet) refused, saying what to type instead;
3. ports that browsers refuse to open (6000: ERR_UNSAFE_PORT) refused, a safe free one suggested;
4. the questions say what they mean: sign-up No (invites; the first administrator always uses the setup code), the
   network names (No by default; what No means for the checks), fixed addresses;
5. waiting for the package manager (database/apt_wait.sh): shown, never "systemctl stop" (it hangs on a stalled update).
Usage: tests/check_installer_questions.py"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# install.sh: beside platform/ in a release; in tools/release_root/ while developing
SRC = next((p for p in (os.path.join(HERE, "..", "install.sh"), os.path.join(HERE, "tools", "release_root", "install.sh"))
            if os.path.exists(p)), None)
APT = next((p for p in (os.path.join(HERE, "..", "database", "apt_wait.sh"), os.path.expanduser("~/shadowserver/apt_wait.sh"))
            if os.path.exists(p)), None)
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:200]}]" if info else ""), flush=True)


if not SRC:
    # an honest skip (77), never a pass that tried nothing; LG_NO_SKIP=1 (every release run) makes it a failure
    print("SKIPPED: install.sh is not next to this platform (an installation without the installer)")
    sys.exit(77)
src = open(SRC, encoding="utf-8").read()


def section(start, end):
    a = src.index(start)
    return src[a:src.index(end, a)]


print("1. Back")
dialogs = section("# -------------------------------------------------------------------------------------------------------"
                  "--- dialogs", "# -------------------------------------------------------------------------------------------------"
                  "--------- progress")
t = tempfile.mkdtemp()
os.makedirs(os.path.join(t, "install-logs"))
head = '''#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
ORIG_ARGS=("$@")
if [ -n "${LG_BACK_LOG:-}" ]; then LOG="$LG_BACK_LOG"; else LOG="$ROOT/run.log"; : > "$LOG"; fi; unset LG_BACK_LOG
UI=text; INTERACTIVE=1; ASSUME_YES=0; TITLE=t; B=; R=; D=; MAG=; CYN=; RED=; GRN=; YEL=
declare -A ANS=()
log() { printf '%s\\n' "$*" >> "$LOG"; }
'''
flow = '''
echo "run (replaying to ${REPLAY_TO})" >> "$ROOT/out"
ask_input NAME "Q1" "a name" first; NAME="$REPLY"
ask_menu PICK "Q2" "a choice" x x "X" y "Y"; PICK="$REPLY"
ask_secret PASSWORD "Q3" "a password"; PASSWORD="$REPLY"
ask_yesno GO "Q4" "go on?" yes; GO="$REPLY"
echo "FINAL NAME=$NAME PICK=$PICK PASSWORD_IS_PW2=$([ "$PASSWORD" = pw2 ] && echo yes || echo no) GO=$GO" >> "$ROOT/out"
'''
open(os.path.join(t, "install.sh"), "w").write(head + dialogs + flow)
os.chmod(os.path.join(t, "install.sh"), 0o755)
typed = "\n".join(["<", "", "alice", "2", "pw1", "pw1", "<", "pw2", "pw2", "no"]) + "\n"
subprocess.run(["bash", os.path.join(t, "install.sh")], input=typed, text=True, capture_output=True, timeout=60)
out = open(os.path.join(t, "out")).read() if os.path.exists(os.path.join(t, "out")) else ""
logtxt = open(os.path.join(t, "run.log")).read() if os.path.exists(os.path.join(t, "run.log")) else ""
ok("Back at question 4 goes to question 3; questions 1 and 2 keep their answers; the new answers are used",
   "FINAL NAME=alice PICK=y PASSWORD_IS_PW2=yes GO=no" in out and out.count("run (") == 2, out)
ok("…the log says so", "back: from question 4 to question 3" in logtxt)
ok("Back on the first question stays there (nothing before it)", out.startswith("run (replaying to 0)") and "first question" not in out)
# what the installer writes: its log and the saved answers (install.sh and out are this test's own files)
leaked = [n for n in os.listdir(t) for x in ("pw1", "pw2") if n not in ("install.sh", "out") and os.path.isfile(os.path.join(t, n))
          and x in open(os.path.join(t, n), errors="replace").read()]
leaked += [n for n in os.listdir(os.path.join(t, "install-logs")) if "pw" in open(os.path.join(t, "install-logs", n), errors="replace").read()]
ok("passwords are never written to a file (they travel in memory only)", not leaked, leaked)
ok("the windows have a Back button and Esc still stops", src.count("--cancel-button Back") >= 5 and "BACK_HINT" in src)

print("2. Allowed networks")
fn = section("v_networks() {", "\n}\n") + "\n}\n"
for v, want, why in (("internal", True, ""), ("10.0.0.0/8, 192.168.1.40", True, ""), ("0.0.0.0", False, "lets nobody in"),
                     ("0.0.0.0/0", False, "every address in the world"), ("::/0", False, "every address in the world"),
                     ("not-a-range", False, "not an address")):
    r = subprocess.run(["bash", "-c", fn + 'v_networks "$1"', "_", v], capture_output=True, text=True)
    ok(f"{v!r}: {'accepted' if want else 'refused, saying why'}", (r.returncode == 0) == want and (want or why in r.stdout), r.stdout.strip())
ok("option 2 offers 'Any computer on our internal network' (VIEWER_NETWORKS=internal)",
   "Any computer on our internal network" in src and "VIEWER_NETWORKS=internal" in src)

print("3. Ports browsers refuse")
blocked = section("BROWSER_BLOCKED=", "\n")
pre = "in_use() { return 1; }; v_port() { [[ $1 =~ ^[0-9]+$ ]]; }; IS_WSL=0; PF_DIR=/tmp\n" + blocked + "\n" \
    + section("safe_free_port() {", "\n") + "\n" + section("v_lg_port() {", "\n}\n") + "\n}\n"
for port, want in (("6000", False), ("6667", False), ("5060", False), ("8443", True), ("5000", True)):
    r = subprocess.run(["bash", "-c", pre + 'v_lg_port "$1"', "_", port], capture_output=True, text=True)
    ok(f"port {port}: {'accepted' if want else 'refused, a safe one suggested'}", (r.returncode == 0) == want
       and (want or "ERR_UNSAFE_PORT" in r.stdout and "for example" in r.stdout), r.stdout.strip())

print("4. What the questions say")
ok("sign-up No: invited people only; the first administrator always uses the setup code",
   "only people an administrator invites" in src and "first administrator signs up with the one-time setup code" in src)
ok("network names: asked, No by default, saying what No means for the checks",
   # what No means for the checks (2026-11-26: the demo masking check is no longer skipped without names, it checks
   # that every network reads "Unlisted network"), and never a claim that a check is skipped
   'ask_yesno NAMES_LOOKUP' in src and "the demo masking check checks exactly that" in src and "is SKIPPED until" not in src
   and src[src.index("ask_yesno NAMES_LOOKUP"):].split("\n  NAMES_LOOKUP")[0].rstrip().endswith('" no'))
ok("…the final screen repeats it when No was chosen", "network names were not looked up" in src)
ok("fixed addresses advised: a split installation, and the self-signed certificate", "Keep this address fixed" in src
   and "give the\nserver a fixed address or a name" in src)

print("5. Waiting for the package manager")
ok("install.sh uses the shared wait (database/apt_wait.sh) before installing packages", ". \"$DB_DIR/apt_wait.sh\"" in src
   and "wait_for_apt" in src)
if APT:
    a = open(APT, encoding="utf-8").read()
    ok("…it says what holds it, and never 'systemctl stop unattended-upgrades' (it waits for ever on a stalled update)",
       "Waiting for $words to finish" in a and "systemctl stop" not in a.replace('never "systemctl stop', ""), "")
    r = subprocess.run(["bash", "-c", f". '{APT}'; apt_lock_holder >/dev/null || wait_for_apt; echo rc=$?"], capture_output=True, text=True, timeout=30)
    ok("…when nothing holds the package manager, it goes on at once", "rc=0" in r.stdout, r.stdout + r.stderr)
else:
    ok("database/apt_wait.sh is next to this platform (the installer sources it)", False)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
