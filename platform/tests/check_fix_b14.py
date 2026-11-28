#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase audit of 2026-11-27, batch 14 (installer, uninstaller, deploy and manage shell scripts), checked
by RUNNING the scripts or their functions in temporary folders with stand-ins on PATH (sudo, systemctl, ufw, gpg, curl,
tar, age...). Nothing on this computer is changed, nothing runs as root, no stand-in for sudo runs what it is given
unless it is a file in the temporary folder.

  14-1   env_set: a value with " #" or "${" is read the same by python-dotenv, the pipeline's loader and the shell
         readers; a secret with a single quote or a line break is refused when it is typed, with the reason
  14-2   uninstall.sh: the timers and the path unit of this folder's services are stopped and removed too
  14-3   caddy_front.sh: Caddy's signing key file must hold exactly one key, the pinned one
  14-4   make_tls_cert.sh behind Caddy (internal): the new certificate is given to Caddy (sync) at once
  14-5   backup.sh: tar's exit 1 (a file changed while read) keeps the archive, its checksum (and signature)
  14-6   verify_backup.sh / restore_check.sh: a missing .sha256 is a stated failure, with a result
  14-7   install.sh: the Mapbox note is added to the earlier notes, never in their place
  14-8   uninstall.sh: the installer's ufw rule for Caddy's port is removed
  14-9   run_admin_db_tests.sh: a skipped part, or pipeline tests that cannot run, fail
  14-10  install_cert.sh: no LG_PORT in .env still goes on to Caddy's sync and the check
  14-11  unusual_timer.sh / connectors_timer.sh: the unit files written into deploy/ belong to the folder's user
  14-12  quotes: a folder with a quote reaches deploy/install.sh; LG_SERVICE='x' names the timer x-unusual
  14-13  envcheck.sh: MONGO_HOST from .env is never run as a command
  14-14  temporary folders: Caddy's key download folder goes when the download fails
  14-15  decrypted backups: verify_backup.sh never writes one to disk; restore_check.sh removes its copy when stopped

LG_FIX_B14_ROOT points the checks at another copy of the platform (the old code, to see them fail); install.sh and
uninstall.sh are looked for in tools/release_root/ and next to the platform. Run: .venv/bin/python tests/check_fix_b14.py"""
import ast
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.abspath(os.environ.get("LG_FIX_B14_ROOT") or HERE)
checks, fails = 0, []
CLEAN = []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info and not cond else ""), flush=True)


def tmpdir(prefix="lg-b14-"):
    d = tempfile.mkdtemp(prefix=prefix)
    CLEAN.append(d)
    return d


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def write(p, text, mode=None):
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(text)
    if mode is not None:
        os.chmod(p, mode)


def stub(d, name, body):
    write(os.path.join(d, name), "#!/bin/bash\n" + body + "\n", 0o755)


def first(*paths):
    return next((p for p in paths if p and os.path.isfile(p)), None)


def fn(src, name):
    """A shell function's text: one line, or up to its closing } or ) on a line of its own."""
    lines = src.split("\n")
    for i, ln in enumerate(lines):
        if re.match(rf"^{re.escape(name)}\(\) *[{{(]", ln):
            if ln.count("{") + ln.count("(") <= ln.count("}") + ln.count(")"):   # opened and closed on its line
                return ln
            for j in range(i + 1, len(lines)):
                if lines[j] in ("}", ")"):
                    return "\n".join(lines[i:j + 1])
    return ""


def bash(script, *args, env=None, cwd=None, stdin=None, timeout=60):
    r = subprocess.run(["bash", "-c", script, "_", *args], capture_output=True, text=True, env=env, cwd=cwd,
                       input=stdin, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


INSTALL = first(os.path.join(ROOT, "tools", "release_root", "install.sh"), os.path.join(ROOT, "..", "install.sh"))
UNINSTALL = first(os.path.join(ROOT, "tools", "release_root", "uninstall.sh"), os.path.join(ROOT, "..", "uninstall.sh"))
INST = read(INSTALL) if INSTALL else ""
print(f"platform: {ROOT}\ninstall.sh: {INSTALL}\nuninstall.sh: {UNINSTALL}")
if os.geteuid() == 0:
    print("run as an ordinary user: the uninstaller refuses root, and nothing here may run as root")
    sys.exit(1)

try:
    # ------------------------------------------------------------------------------------------------ 14-1
    print("14-1  .env values: one value for every reader")
    PIPE_SRC = first(os.path.join(os.environ.get("LG_HELD_DIR", ""), "shadowserver_pipeline.py.new") if os.environ.get("LG_HELD_DIR") else None,
                     os.path.join(os.environ.get("LG_TEST_PIPELINE_SRC", ""), "shadowserver_pipeline.py") if os.environ.get("LG_TEST_PIPELINE_SRC") else None,
                     os.path.join(ROOT, "..", "database", "shadowserver_pipeline.py"), os.path.join(HERE, "..", "database", "shadowserver_pipeline.py"),
                     os.path.join(HERE, "..", "shadowserver", "shadowserver_pipeline.py"),
                     os.path.expanduser("~/looking-glass-release/database/shadowserver_pipeline.py"))
    ok("the pipeline's own loader is found (shadowserver_pipeline.py)", PIPE_SRC is not None)
    pipe_load = None
    if PIPE_SRC:
        tree = ast.parse(read(PIPE_SRC))
        node = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "load_env_file"), None)
        ok("…its load_env_file is there", node is not None)
        if node is not None:
            ns = {"os": os, "Path": __import__("pathlib").Path, "compile_service_re": lambda: None}
            exec(compile(ast.Module(body=[node], type_ignores=[]), PIPE_SRC, "exec"), ns)  # noqa: S102 (the shipped function)
            pipe_load = ns["load_env_file"]
    DEPLOY_SH = first(*[os.path.join(os.path.dirname(p), "deploy.sh") for p in
                        (os.path.join(ROOT, "..", "database", "x"), os.path.join(HERE, "..", "database", "x"),
                         os.path.expanduser("~/looking-glass-release/database/x"))])
    deploy_get = fn(read(DEPLOY_SH), "env_get") if DEPLOY_SH else ""
    from dotenv import dotenv_values

    env_py, env_set, env_get, v_sec = (fn(INST, n) for n in ("_env_py", "env_set", "env_get", "v_env_secret"))
    lib = "\n".join(x for x in (env_py, env_set, env_get, v_sec) if x) + "\n"
    ok("install.sh's env_set and env_get are there", bool(env_set) and bool(env_get))
    VALUES = ["plain", "p #x", "a$b", "$HOME", "x$(id)y", "with space", " lead", "trail ", 'a"b', "a\\b", "a\\\\b", "x`id`y",
              "#start", "a#b", '"quoted"', "p=q", "pässwörd ü", "tab\there", "Bob's", "end'", "e\\nd", "sp a\\b"]
    T = tmpdir()
    bad = []
    for v in VALUES:
        f = os.path.join(T, "env")
        write(f, "# Looking Glass\nOTHER=1\nSECRET=old\nSECRET=older\n")
        rc, out, err = bash(lib + 'env_set "$1" SECRET "$2"; echo "rc=$?"; printf "%s" "$(env_get "$1" SECRET)"', f, v)
        got = {"dotenv": dotenv_values(f).get("SECRET")}
        if pipe_load:
            saved = {k: os.environ.pop(k, None) for k in ("SECRET", "OTHER")}
            pipe_load(__import__("pathlib").Path(f))
            got["pipeline"] = os.environ.pop("SECRET", None)
            os.environ.pop("OTHER", None)
            os.environ.update({k: v for k, v in saved.items() if v is not None})
        got["install.sh env_get"] = out.split("rc=0\n", 1)[1] if "rc=0\n" in out else None
        if deploy_get:
            d = os.path.join(T, "deploydir")
            os.makedirs(d, exist_ok=True)
            shutil.copy(f, os.path.join(d, ".env"))
            got["deploy.sh env_get"] = bash(deploy_get + '\nenv_get SECRET', cwd=d)[1]
        others = dotenv_values(f).get("OTHER")
        if any(x != v for x in got.values()) or others != "1" or read(f).count("SECRET=") != 1:
            bad.append((v, got, read(f)))
    ok(f"{len(VALUES)} values (' #', $, $(...), quotes, backslashes, spaces at either end, a tab, a backtick): every "
       f"reader ({'python-dotenv, the pipeline, install.sh and deploy.sh' if deploy_get else 'python-dotenv, the pipeline, install.sh'}) "
       "reads exactly the value written; one SECRET line, the others kept", not bad, bad[:3])
    f = os.path.join(T, "env")
    write(f, "SECRET=old\n")
    refused = {}
    for v in ("a b'c", "'lead", "two\nlines", "cr\rhere", "sp #\\", "x $\\\\y", "p${HOME}x", "x${PATH:-y}"):
        rc, out, err = bash(lib + 'env_set "$1" SECRET "$2"', f, v)
        refused[repr(v)] = (rc, err.strip()[:160])
    ok("a value no form keeps whole (a quote with a space or at the start, a line break, a backslash at the end or two "
       "with a $, '${' which python-dotenv expands even in quotes): refused, with the reason, and the file left as it was",
       all(rc != 0 and "cannot contain" in e for rc, e in refused.values()) and read(f) == "SECRET=old\n", refused)
    sec = {}
    for v, good in (("pw'1", False), ("a\nb", False), ("p${X}", False), ("p #x", True), ("Str0ng-pass!", True)):
        rc, out, err = bash(lib + 'v_env_secret "$1"', v)
        sec[repr(v)] = (rc == 0) == good and (good or "cannot contain" in out)
    ok("a secret with a single quote or a line break is refused (v_env_secret says why); ' #' is fine", v_sec and all(sec.values()), sec)
    # typed at the question: refused there, asked again (before anything is installed)
    if INST and "--- dialogs" in INST and "--- progress" in INST:
        a = INST.index("--- dialogs")
        dialogs = INST[INST.rindex("\n", 0, a) + 1:INST.index("--- progress", a)]
        dialogs = dialogs[:dialogs.rindex("\n")]
        t = tmpdir()
        head = ('set -Eeuo pipefail\nROOT="$1"; ORIG_ARGS=(); LOG="$ROOT/run.log"; : > "$LOG"\nUI=text; INTERACTIVE=1; ASSUME_YES=0; TITLE=t; '
                'B=; R=; D=; MAG=; CYN=; RED=; GRN=; YEL=\ndeclare -A ANS=()\nlog() { printf \'%s\\n\' "$*" >> "$LOG"; }\n')
        flow = '\nask_secret PASSWORD "Q" "a password"; printf "GOT=%s\\n" "$REPLY" > "$ROOT/out"\n'
        r = subprocess.run(["bash", "-c", head + dialogs + flow, "_", t], input="it's\n\ngood pw\ngood pw\n", text=True,
                           capture_output=True, timeout=60)
        ok("…typed at the question: refused there with the reason, asked again, the next one taken",
           read(os.path.join(t, "out")) == "GOT=good pw\n" and "single quote" in r.stdout, (r.returncode, r.stdout[-300:], r.stderr[-300:]))
    else:
        ok("…typed at the question (the installer's dialogs section)", False, "no dialogs section")
    ok("…the mail test writes its temporary file the same way (env_set's rule), not with printf",
       "IMAP_PASSWORD=%s" not in INST and '_env_py write "$tmp"' in INST)

    # ------------------------------------------------------------------------------------------------ 14-3 / 14-14
    print("14-3  Caddy's signing key: exactly one key, the pinned one")
    CF = read(os.path.join(ROOT, "deploy", "caddy_front.sh"))
    KEY_FP = (re.search(r'^KEY_FP="([0-9A-F]+)"', CF, re.M) or [None, ""])[1]
    T = tmpdir()
    stub(os.path.join(T, "bin"), "gpg", 'case "$*" in *--show-keys*) printf "%b" "$GPG_OUT" ;; *--dearmor*) cat ;; esac')
    harness = (f'KEY_FP="{KEY_FP}"; KEYRING="$1"; die() {{ echo "DIE: $*" >&2; exit 1; }}\n'
               + fn(CF, "key_fps") + "\n" + fn(CF, "key_ok") + "\nkey_ok && echo ACCEPTED\n")
    write(os.path.join(T, "keyring.gpg"), "k")
    other = "1" * 40
    cases = {
        "the pinned key with its subkey": (f"pub:-:4096:1:X:::::::::\nfpr:::::::::{KEY_FP}:\nuid:::::\nsub:-:4096:1:Y:::::::::\nfpr:::::::::{'2' * 40}:\n", True),
        "a gpg listing with the fingerprint only (the paths check's stand-in)": (f"fpr:::::::::{KEY_FP}:\n", True),
        "the pinned key and a second key after it": (f"pub:-:1:1:X:::::::::\nfpr:::::::::{KEY_FP}:\npub:-:1:1:Z:::::::::\nfpr:::::::::{other}:\n", False),
        "another key first, the pinned one second": (f"pub:-:1:1:Z:::::::::\nfpr:::::::::{other}:\npub:-:1:1:X:::::::::\nfpr:::::::::{KEY_FP}:\n", False),
        "another key only": (f"pub:-:1:1:Z:::::::::\nfpr:::::::::{other}:\n", False),
    }
    res = {}
    for label, (listing, good) in cases.items():
        env = dict(os.environ, PATH=os.path.join(T, "bin") + ":" + os.environ["PATH"], GPG_OUT=listing.replace("\\", "\\\\"))
        rc, out, err = bash(harness, os.path.join(T, "keyring.gpg"), env=env)
        res[label] = ("ACCEPTED" in out) == good and (good or "unexpected fingerprint" in err)
    ok("update's key check (key_ok): one key, the pinned one, accepted; a second key beside it, before it, or another: refused",
       KEY_FP and all(res.values()), res)
    # setup's download: the same rule, and its temporary folder goes on every way out
    tmpd = os.path.join(T, "tmp")
    os.makedirs(tmpd)
    stub(os.path.join(T, "bin"), "curl", '[ -n "${FAIL_CURL:-}" ] && exit 22; o=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && o="$2"; shift; done; echo key > "$o"')
    for n in ("apt-get", "caddy"):      # never reached by the code that refuses; stand-ins all the same
        stub(os.path.join(T, "bin"), n, "echo stand-in")
    inst_h = (f'set -Eeuo pipefail\nKEY_FP="{KEY_FP}"; KEY_URL=https://example.invalid/k; REPO=x; LIST="$1/none.list"; KEYRING="$1/kr.gpg"; PIN="$1/pin"\n'
              'die() { echo "DIE: $*" >&2; exit 1; }\n' + fn(CF, "key_fps") + "\n" + fn(CF, "install_caddy") + "\ninstall_caddy\n")
    res = {}
    for label, extra in (("two keys", {"GPG_OUT": cases["the pinned key and a second key after it"][0]}),
                         ("the download fails", {"FAIL_CURL": "1", "GPG_OUT": cases["the pinned key with its subkey"][0]})):
        env = dict(os.environ, PATH=os.path.join(T, "bin") + ":" + os.environ["PATH"], TMPDIR=tmpd, **extra)
        rc, out, err = bash(inst_h, T, env=env)
        res[label] = (rc, err.strip()[-400:], os.listdir(tmpd), os.path.exists(os.path.join(T, "kr.gpg")))
    ok("setup's download of the key: two keys in it refused, nothing installed", res["two keys"][0] != 0
       and "unexpected fingerprint" in res["two keys"][1] and not res["two keys"][3], res["two keys"])
    print("14-14 temporary folders")
    ok("…its temporary folder removed also when it is refused or the download fails (none left in TMPDIR)",
       all(r[2] == [] for r in res.values()) and res["the download fails"][0] != 0, res)

    # ------------------------------------------------------------------------------------------------ 14-5
    print("14-5  backup.sh: a file that changed while it was read")

    def project(tag):
        t = tmpdir(f"lg-b14-{tag}-")
        p = os.path.join(t, "lgp")
        for f in ("backup.sh", "backup_crypt.sh", "verify_backup.sh", "restore_check.sh", "install_cert.sh"):
            if os.path.isfile(os.path.join(ROOT, "manage", f)):
                write(os.path.join(p, "manage", f), read(os.path.join(ROOT, "manage", f)), 0o755)
        write(os.path.join(p, ".env"), "SECRET_KEY=abc\nLG_SERVICE=lg\n")
        os.makedirs(os.path.join(p, "data"))
        return t, p

    t, p = project("bk")
    stub(os.path.join(t, "bin"), "tar", 'o=""; prev=""; for a in "$@"; do [ "$prev" = -czf ] && o="$a"; prev="$a"; done\n'
         'case " $* " in *" -czf "*) if [ "$o" = - ]; then printf archive; else printf archive > "$o"; fi; exit "${TAR_RC:-1}" ;; esac; exit 0')
    stub(os.path.join(t, "bin"), "age", "cat")
    env = dict(os.environ, PATH=os.path.join(t, "bin") + ":" + os.environ["PATH"], HOME=t)
    res = {}
    for kind in ("plain", "encrypted"):
        dest = os.path.join(t, "out-" + kind)
        if kind == "encrypted":
            write(os.path.join(p, "data", "backup_public_key"), "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq\n")
        r = subprocess.run(["bash", os.path.join(p, "manage", "backup.sh"), *(["--unencrypted"] if kind == "plain" else []), dest],
                           env=env, capture_output=True, text=True, timeout=60)
        files = sorted(os.listdir(dest)) if os.path.isdir(dest) else []
        res[kind] = (r.returncode, files, r.stdout + r.stderr)
    ok("tar exit 1: the unencrypted backup is kept with its checksum, and it says a file changed while read",
       res["plain"][0] == 0 and any(f.endswith(".tar.gz") for f in res["plain"][1]) and any(f.endswith(".tar.gz.sha256") for f in res["plain"][1])
       and "changed while it was being read" in res["plain"][2], res["plain"])
    ok("…the encrypted backup is kept (not deleted), with its checksum", res["encrypted"][0] == 0
       and any(f.endswith(".tar.gz.age") for f in res["encrypted"][1]) and any(f.endswith(".age.sha256") for f in res["encrypted"][1]), res["encrypted"])
    dest = os.path.join(t, "out-fatal")
    r = subprocess.run(["bash", os.path.join(p, "manage", "backup.sh"), dest], env=dict(env, TAR_RC="2"), capture_output=True, text=True, timeout=60)
    ok("…a real tar failure (exit 2) still stops it: NOT BACKED UP, exit 3, no archive left",
       r.returncode == 3 and "NOT BACKED UP" in r.stderr and not [f for f in os.listdir(dest) if ".tar.gz" in f], (r.returncode, r.stderr[-200:]))

    # ------------------------------------------------------------------------------------------------ 14-6 / 14-15
    print("14-6  a backup without its .sha256")
    t, p = project("vb")
    src = os.path.join(t, "src", "lgp")
    write(os.path.join(src, ".env"), read(os.path.join(p, ".env")))
    write(os.path.join(src, "data", "users.json"), "{}")
    arch = os.path.join(t, "backups", "lgp-20261127-000000UTC.tar.gz")
    os.makedirs(os.path.dirname(arch))
    subprocess.run(["tar", "-C", os.path.join(t, "src"), "-czf", arch, "lgp"], check=True)
    env = dict(os.environ, HOME=t, PATH=os.environ["PATH"])
    r = subprocess.run(["bash", os.path.join(p, "manage", "verify_backup.sh"), "--allow-unsigned", arch], env=env,
                       capture_output=True, text=True, timeout=60)
    o = r.stdout + r.stderr
    ok("verify_backup.sh: says the checksum file is missing and fails, never 'unbound variable'",
       r.returncode != 0 and "NO CHECKSUM FILE" in o and "unbound variable" not in o, o[-400:])
    r = subprocess.run(["bash", os.path.join(p, "manage", "restore_check.sh"), "--allow-unsigned", arch], env=env,
                       capture_output=True, text=True, timeout=60)
    o = r.stdout + r.stderr
    ok("restore_check.sh: a FAIL row for the checksum, and a RESULT (not restorable)",
       r.returncode != 0 and "no checksum file" in o and "RESULT: NOT restorable" in o and "unbound variable" not in o, o[-400:])
    print("14-15 a decrypted backup is never left in /tmp")
    enc = arch + ".age"
    shutil.copy(arch, enc)
    subprocess.run(["bash", "-c", 'cd "$(dirname "$1")" && sha256sum "$(basename "$1")" > "$1.sha256"', "_", enc], check=True)
    tmpd = os.path.join(t, "tmp")
    os.makedirs(tmpd)
    probe = os.path.join(t, "probe.log")
    # the stand-in age "decrypts" (cat), then looks for any file in TMPDIR that holds the gzip archive (the old copy)
    stub(os.path.join(t, "bin"), "age", f'f="${{@: -1}}"; cat "$f"; for x in "$TMPDIR"/* "$TMPDIR"/.[!.]*; do '
         f'[ -f "$x" ] && [ "$(head -c2 "$x" | od -An -tx1 | tr -d " ")" = 1f8b ] && echo "PLAIN COPY: $x" >> "{probe}"; done; exit 0')
    idf = os.path.join(t, "id.txt")
    write(idf, "AGE-SECRET-KEY-1QQQ\n")
    env = dict(os.environ, HOME=t, TMPDIR=tmpd, PATH=os.path.join(t, "bin") + ":" + os.environ["PATH"])
    r = subprocess.run(["bash", os.path.join(p, "manage", "verify_backup.sh"), "--allow-unsigned", "--identity", idf, enc], env=env,
                       capture_output=True, text=True, timeout=60)
    o = r.stdout + r.stderr
    ok("verify_backup.sh --identity: .env compared and the files counted as it decrypts",
       ".env: included and identical" in o and re.search(r"^files: 2$", o, re.M) is not None, o[-400:])
    ok("…and no readable copy of the backup was on disk while it did (none in TMPDIR), none left after", not read(probe)
       and os.listdir(tmpd) == [], (read(probe), os.listdir(tmpd)))
    # restore_check stopped while it checks the unpacked copy: the copy goes
    write(os.path.join(p, ".venv", "bin", "python"), '#!/bin/bash\ncase "$*" in *backup-age*) echo "not checked"; exit 0 ;; esac\n'
          '[ "$1" = - ] && exec sleep 30\nexec python3 "$@"\n', 0o755)
    shutil.copy(arch, arch.replace("000000UTC", "000001UTC"))
    a2 = arch.replace("000000UTC", "000001UTC")
    subprocess.run(["bash", "-c", 'cd "$(dirname "$1")" && sha256sum "$(basename "$1")" > "$1.sha256"', "_", a2], check=True)
    pr = subprocess.Popen(["bash", os.path.join(p, "manage", "restore_check.sh"), "--allow-unsigned", a2], env=env,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    seen = False
    for _ in range(100):
        if any(os.path.isdir(os.path.join(tmpd, n, "lgp")) for n in os.listdir(tmpd)):
            seen = True
            break
        time.sleep(0.1)
    time.sleep(0.3)
    os.killpg(pr.pid, signal.SIGTERM)
    try:
        pr.wait(timeout=20)
    except subprocess.TimeoutExpired:
        os.killpg(pr.pid, signal.SIGKILL)
        pr.wait()
    ok("restore_check.sh stopped (SIGTERM) while it checks: its unpacked copy of the backup is removed", seen and os.listdir(tmpd) == [],
       (seen, os.listdir(tmpd)))
    bcd = fn(read(os.path.join(ROOT, "manage", "backup_crypt.sh")), "bc_decrypt")
    ok("…and bc_decrypt's temporary copy of the private key goes on every way out too (a subshell with its own traps)",
       bcd.startswith("bc_decrypt() (") and "trap 'exit 130' INT TERM HUP" in bcd, bcd[:200])

    # ------------------------------------------------------------------------------------------------ 14-7
    print("14-7  install.sh: the Mapbox note with the others")
    m = re.search(r'\n(  gauge 81 "Setting up unusual activity.*?\n  \[ -n "\$SOURCES_WARN" \][^\n]*)\n', INST, re.S)
    out = ""
    if m:
        rc, out, err = bash('gauge() { :; }; log() { :; }; bg_wait() { return 1; }; PF_DIR=/x; PF_WARN=""; MAPBOX_TOKEN=""; SOURCES_WARN=""\n'
                            + m.group(1) + '\nprintf "%s" "$PF_WARN"')
    ok("no Mapbox token and both helpers failed: all three notes are shown", m and "unusual_timer.sh install" in out
       and "update_helper.sh install" in out and "No Mapbox token yet" in out, out)

    # ------------------------------------------------------------------------------------------------ 14-2 / 14-8
    print("14-2  uninstall.sh: timers and the path unit;  14-8  the installer's ufw rule")
    t = tmpdir()
    root = os.path.join(t, "looking-glass")
    pf = os.path.join(root, "platform")
    for d in ("database", "platform", "sys/systemd", "sys/etc-lg", "sys/bin", "stubs"):
        os.makedirs(os.path.join(t if d.startswith(("sys", "stubs")) else root, d), exist_ok=True)
    shutil.copy(UNINSTALL or "/dev/null", os.path.join(root, "uninstall.sh"))
    write(os.path.join(root, "install.sh"), "#!/bin/sh\n")
    write(os.path.join(root, "database", ".env"), "MONGO_DB=shadowserver\n")
    sysd = os.path.join(t, "sys", "systemd")
    for n in ("looking-glass", "looking-glass-unusual", "looking-glass-connectors", "looking-glass-update"):
        write(os.path.join(sysd, n + ".service"), f"[Service]\nWorkingDirectory={pf}\n")
    write(os.path.join(sysd, "looking-glass-unusual.timer"), "[Timer]\nOnUnitActiveSec=1h\n")
    write(os.path.join(sysd, "looking-glass-connectors.timer"), "[Timer]\nOnUnitActiveSec=15min\n")
    write(os.path.join(sysd, "looking-glass-update.path"), "[Path]\nUnit=looking-glass-update.service\n")
    write(os.path.join(sysd, "other-app.timer"), "[Timer]\n")
    caddyfile = os.path.join(t, "sys", "Caddyfile")
    write(caddyfile, "# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced by the next setup or renewal.\n"
                     "{\n}\n\nhttps://lg.example.org:8443 {\n\treverse_proxy https://127.0.0.1:5001 {\n\t}\n}\n")
    write(os.path.join(pf, ".env"), "LG_PORT=5001\n")     # this folder's installation is the one behind that Caddy (r3-4)
    st, log = os.path.join(t, "stubs"), os.path.join(t, "calls.log")
    stub(st, "sudo", f'echo "sudo $*" >> "{log}"; [ "$1" = -n ] && shift; [ "$1" = -v ] && exit 0; '
                     'for a in "$@"; do case "$a" in /var/*|/etc/*|/usr/*|/lib/*|/opt/*|/boot/*) '
                     f'echo "refused (real system path): $*" >> "{log}"; exit 0;; esac; done; "$@"')
    stub(st, "systemctl", f'echo "systemctl $*" >> "{log}"')
    stub(st, "ufw", f'echo "ufw $*" >> "{log}"; [ "$1" = status ] && printf "Status: active\\n\\nTo  Action  From\\n--  ------  ----\\n'
                    '22/tcp                     ALLOW       Anywhere\\n8443/tcp                   ALLOW       Anywhere                   # Looking Glass HTTPS\\n'
                    '8443/tcp (v6)              ALLOW       Anywhere (v6)              # Looking Glass HTTPS\\n"; exit 0')
    for n in ("mandb", "pgrep"):
        stub(st, n, "exit 1" if n == "pgrep" else "true")
    stub(st, "crontab", 'exit 1')
    env = dict(os.environ, PATH=f"{st}:/usr/bin:/bin", HOME=t, LG_UNINSTALL_SYSTEMD_DIR=sysd,
               LG_UNINSTALL_ETC_DIR=os.path.join(t, "sys", "etc-lg"), LG_UNINSTALL_BIN=os.path.join(t, "sys", "bin", "shadowserver"),
               LG_UNINSTALL_MAN=os.path.join(t, "sys", "man1"), LG_UNINSTALL_COMPLETION=os.path.join(t, "sys", "compl"),
               LG_UNINSTALL_MONGOD_CONF=os.path.join(t, "sys", "mongod.conf"), LG_UNINSTALL_CADDYFILE=caddyfile)
    r = subprocess.run(["bash", os.path.join(root, "uninstall.sh"), "--dry-run"], env=env, cwd=root, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)
    ok("dry run: names the timers, the path unit and the firewall rule, and runs nothing",
       r.returncode == 0 and "looking-glass-unusual.timer" in r.stdout and "looking-glass-update.path" in r.stdout
       and "8443/tcp" in r.stdout and not os.path.exists(log), (r.stdout[-500:], read(log)))
    r = subprocess.run(["bash", os.path.join(root, "uninstall.sh"), "--yes"], env=env, cwd=root, stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=120)
    calls = read(log)
    left = sorted(os.listdir(sysd))
    ok("the hourly and 15-minute timers and the update path unit: stopped, disabled and removed (before their services)",
       r.returncode == 0 and all(f"systemctl disable --now {u}" in calls for u in
                                 ("looking-glass-unusual.timer", "looking-glass-connectors.timer", "looking-glass-update.path"))
       and left == ["other-app.timer"]
       and calls.index("disable --now looking-glass-unusual.timer") < calls.index("disable --now looking-glass-unusual.service"),
       (r.returncode, left, calls[-600:], r.stderr[-300:]))
    ok("the installer's firewall rule for Caddy's port (8443/tcp, 'Looking Glass HTTPS') removed; port 22 untouched",
       "ufw delete allow 8443/tcp" in calls and "22/tcp" not in calls.replace("8443/tcp", ""), calls[-500:])

    # ------------------------------------------------------------------------------------------------ 14-9
    print("14-9  run_admin_db_tests.sh: a check that does not run fails the run")
    RADT = os.path.join(ROOT, "tests", "run_admin_db_tests.sh")

    def admin_tree(platform_rc=0, pipeline=None):
        t = tmpdir()
        p = os.path.join(t, "platform")
        write(os.path.join(p, "tests", "run_admin_db_tests.sh"), read(RADT), 0o755)
        write(os.path.join(p, ".venv", "bin", "python"), '#!/bin/bash\nexec python3 "$@"\n', 0o755)
        for n in ("test_new_collections.py", "test_new_service_collections.py", "check_quarterly.py", "check_quarterly_purge_e2e.py"):
            write(os.path.join(p, "tests", n), f"import sys\nsys.exit({platform_rc if n == 'check_quarterly.py' else 0})\n")
        if pipeline is not None:
            d = os.path.join(t, "database")
            write(os.path.join(d, ".venv", "bin", "python"), '#!/bin/bash\nexec python3 "$@"\n', 0o755)
            write(os.path.join(d, "tests", "test_report_names.py"), f"print({pipeline!r})\n")
        stub(os.path.join(t, "bin"), "sudo", 'echo "MONGO_USER=admin"')
        stub(os.path.join(t, "bin"), "shred", 'rm -f "${@: -1}"')
        env = dict(os.environ, PATH=os.path.join(t, "bin") + ":" + os.environ["PATH"])
        r = subprocess.run(["bash", os.path.join(p, "tests", "run_admin_db_tests.sh")], env=env, capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout

    res = {"all passed": admin_tree(0, "Ran 5 tests\nOK"), "a platform test skipped (77)": admin_tree(77, "OK"),
           "a pipeline test skipped": admin_tree(0, "Ran 5 tests\nOK (skipped=1)"), "no pipeline to run its tests in": admin_tree(0, None)}
    ok("everything ran and passed: exit 0", res["all passed"][0] == 0, res["all passed"])
    ok("…a platform test that skips (exit 77): exit 1", res["a platform test skipped (77)"][0] == 1, res["a platform test skipped (77)"])
    ok("…a pipeline test that skips: exit 1 (it was 0)", res["a pipeline test skipped"][0] == 1, res["a pipeline test skipped"])
    ok("…no pipeline found to run its tests in: exit 1, said (it was 0, silently)", res["no pipeline to run its tests in"][0] == 1
       and "not run" in res["no pipeline to run its tests in"][1], res["no pipeline to run its tests in"])

    # ------------------------------------------------------------------------------------------------ 14-4
    print("14-4  make_tls_cert.sh behind Caddy (internal): the new certificate to Caddy at once")

    def tls_box(sudo_ok=True):
        t = tmpdir()
        p = os.path.join(t, "platform")
        write(os.path.join(p, "deploy", "make_tls_cert.sh"),
              read(os.path.join(ROOT, "deploy", "make_tls_cert.sh")).replace("/etc/caddy/", t + "/etc/caddy/"), 0o755)
        write(os.path.join(p, "deploy", "reload.sh"), f'echo reload >> "{t}/calls.log"\n')
        write(os.path.join(p, "deploy", "caddy_front.sh"), f'echo "caddy_front $*" >> "{t}/calls.log"\n')
        write(os.path.join(p, ".env"), "ACCESS_MODE=private\nLG_SERVICE=lgx\n")
        write(os.path.join(t, "etc", "caddy", "Caddyfile"),
              "# Managed by Looking Glass (deploy/caddy_front.sh): x\n# internal: lg.internal\nhttps://:8443 {\n}\n")
        b = os.path.join(t, "bin")
        stub(b, "id", 'case "$1" in -u) echo 1000 ;; -un) echo lguser ;; *) command -p id "$@" ;; esac')
        stub(b, "hostname", 'case "$1" in -f) echo lg-host.lan ;; -I) echo 10.0.0.5 ;; *) echo lg-host ;; esac')
        stub(b, "systemctl", 'exit 0')    # the service is running: make_tls_cert.sh reloads it
        # sudo: -n true answers as configured; anything else runs only the temporary folder's stand-in
        stub(b, "sudo", f'echo "sudo $*" >> "{t}/calls.log"; if [ "$1" = -n ]; then [ "{1 if sudo_ok else 0}" = 1 ]; exit; fi; '
                        f'[ "$1" = bash ] && [ "$2" = deploy/caddy_front.sh ] && exec bash "$2" "${{@:3}}"; exit 1')
        env = dict(os.environ, PATH=b + ":" + os.environ["PATH"])
        r = subprocess.run(["bash", os.path.join(p, "deploy", "make_tls_cert.sh")], env=env, cwd=p, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr, read(os.path.join(t, "calls.log")), p

    rc, out, calls, p = tls_box()
    ok("the new certificate is given to Caddy right after the reload (caddy_front.sh sync --project <the folder>)",
       rc == 0 and f"caddy_front sync --project {p}" in calls and calls.index("reload") < calls.index("caddy_front sync")
       and "Caddy has the new certificate" in out, (rc, calls, out[-400:]))
    rc, out, calls, p = tls_box(sudo_ok=False)
    ok("…no sudo without a password and no terminal: it says what to run and that visitors get an error until then",
       rc == 3 and "caddy_front" not in calls.replace("sudo -n", "") and "sudo deploy/caddy_front.sh sync" in out and "502" in out, (rc, calls, out[-300:]))

    # ------------------------------------------------------------------------------------------------ 14-10
    print("14-10 install_cert.sh without LG_PORT in .env")
    t = tmpdir()
    p = os.path.join(t, "platform")
    write(os.path.join(p, "manage", "install_cert.sh"),
          read(os.path.join(ROOT, "manage", "install_cert.sh")).replace("/etc/caddy/", t + "/etc/caddy/"), 0o755)
    write(os.path.join(p, "deploy", "install_cert.py"), "import sys\nsys.exit(0)\n")
    write(os.path.join(p, "deploy", "reload.sh"), f'echo reload >> "{t}/calls.log"\n')
    write(os.path.join(p, ".env"), "ACCESS_MODE=public\n")
    write(os.path.join(t, "etc", "caddy", "Caddyfile"), "# Managed by Looking Glass (deploy/caddy_front.sh): x\nhttps://lg.example.org:8443 {\n}\n")
    b = os.path.join(t, "bin")
    stub(b, "sudo", f'echo "sudo $*" >> "{t}/calls.log"; exit 0')
    stub(b, "curl", f'echo "curl $*" >> "{t}/calls.log"; exit 0')
    r = subprocess.run(["bash", os.path.join(p, "manage", "install_cert.sh"), "lg.example.org", "/c.pem", "/k.pem"],
                       env=dict(os.environ, PATH=b + ":" + os.environ["PATH"]), cwd=p, capture_output=True, text=True, timeout=120)
    calls = read(os.path.join(t, "calls.log"))
    ok("no LG_PORT: it goes on to Caddy's sync and checks the site on Caddy's port (it stopped silently after the reload)",
       r.returncode == 0 and "sudo bash deploy/caddy_front.sh sync" in calls and "lg.example.org:8443:127.0.0.1" in calls,
       (r.returncode, calls, (r.stdout + r.stderr)[-300:]))

    # ------------------------------------------------------------------------------------------------ 14-11 / 14-12
    print("14-11 the timers' unit files belong to the folder's user;  14-12 quotes")
    for script, tmpl in (("unusual_timer.sh", "looking-glass-unusual"), ("connectors_timer.sh", "looking-glass-connectors")):
        t = tmpdir()
        p = os.path.join(t, "platform")
        write(os.path.join(p, "deploy", script), read(os.path.join(ROOT, "deploy", script)), 0o755)
        for x in ("service", "timer"):
            shutil.copy(os.path.join(ROOT, "deploy", f"{tmpl}.{x}.template"), os.path.join(p, "deploy", f"{tmpl}.{x}.template"))
        write(os.path.join(p, ".env"), "LG_SERVICE='lgq'\nCONNECTOR_KEY_SECRET=" + "a" * 64 + "\n")
        b = os.path.join(t, "bin")
        stub(b, "sudo", f'echo "sudo $*" >> "{t}/calls.log"; exit 0')
        stub(b, "chown", f'echo "chown $*" >> "{t}/calls.log"; exit 0')
        r = subprocess.run(["bash", os.path.join(p, "deploy", script), "install"], env=dict(os.environ, PATH=b + ":" + os.environ["PATH"]),
                           capture_output=True, text=True, timeout=60)
        calls = read(os.path.join(t, "calls.log"))
        suffix = tmpl.split("-")[-1]
        me = subprocess.run(["id", "-un"], capture_output=True, text=True).stdout.strip()
        ok(f"{script}: deploy/lgq-{suffix}.service and .timer handed to the folder's user ({me}) after they are written",
           r.returncode == 0 and f"chown {me}: {p}/deploy/lgq-{suffix}.service {p}/deploy/lgq-{suffix}.timer" in calls, (calls, r.stderr[-300:]))
        ok(f"…LG_SERVICE='lgq' (quoted): the unit is lgq-{suffix}, never a name with quotes in it",
           f"/etc/systemd/system/lgq-{suffix}.timer" in calls and "'" not in calls, calls[-300:])
    line = re.search(r'^\s*run "platform install \(deploy/install.sh\)".*$', INST, re.M)
    t = tmpdir()
    pfq = os.path.join(t, "it's here", "platform")
    write(os.path.join(pfq, "deploy", "install.sh"), f'#!/bin/bash\nprintf "%s|" "$PWD" "$@" > "{t}/got"\n', 0o755)
    if line:
        bash('run() { shift; "$@"; }; PF_DIR="$1"; iargs=(--port 5000 --name lg --no-sources)\n' + line.group(0).strip(), pfq)
    ok("a folder with a single quote in its name: deploy/install.sh is reached, in that folder, with its arguments",
       read(os.path.join(t, "got")) == f"{pfq}|--port|5000|--name|lg|--no-sources|", read(os.path.join(t, "got")))
    ok("…and no folder is pasted into a bash -c command anywhere in install.sh", INST and not re.search(r"""bash -c "cd '\$""", INST))

    # ------------------------------------------------------------------------------------------------ 14-13
    print("14-13 envcheck.sh: .env values are data")
    t = tmpdir()
    p = os.path.join(t, "platform")
    write(os.path.join(p, "tools", "envcheck.sh"), read(os.path.join(ROOT, "tools", "envcheck.sh")), 0o755)
    pw = os.path.join(t, "pwned")
    write(os.path.join(p, ".env"), f"MONGO_HOST=127.0.0.1;touch {pw};true\nMONGO_PORT=1\n")
    r = subprocess.run(["bash", os.path.join(p, "tools", "envcheck.sh")], capture_output=True, text=True, timeout=60)
    ok("MONGO_HOST='127.0.0.1;touch ...' is never run (refused as not a host name)", not os.path.exists(pw)
       and "not a host name" in r.stdout, (os.path.exists(pw), r.stdout[-200:]))
    write(os.path.join(p, ".env"), "MONGO_HOST=127.0.0.1\nMONGO_PORT=1\n")
    r = subprocess.run(["bash", os.path.join(p, "tools", "envcheck.sh")], capture_output=True, text=True, timeout=60)
    ok("…a plain host and port are still checked", "MongoDB 127.0.0.1:1: NOT reachable" in r.stdout, r.stdout[-200:])
finally:
    for d in CLEAN:
        shutil.rmtree(d, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
