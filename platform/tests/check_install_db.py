#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The installer's database check (install.sh check_mongo, 2026-11-14), run as the installer runs it: a public address
is refused before any connection, an internal one without TLS is refused unless the trusted-link answer was given, the
database is called internal, and the Looking Glass structure check is there with its own exit code (3). No database
is needed: every case here stops before connecting. Run: .venv/bin/python tests/check_install_db.py"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def _release_file(name):
    """A file of the release's top level: beside platform/ in an installation or the GitHub repository, or in
    tools/release_root/ in the development tree."""
    for p in (os.path.join(HERE, "..", name), os.path.join(HERE, "tools", "release_root", name)):
        if os.path.isfile(p):
            return os.path.abspath(p)
    return os.path.join(HERE, "..", name)

INSTALL = _release_file("install.sh")
checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""))


src = open(INSTALL, encoding="utf-8").read()
m = re.search(r"^check_mongo\(\).*?chk_py \"\$@\" <<'EOF'\n(.*?)\nEOF\n", src, re.S | re.M)
ok("install.sh has its database check", m is not None)
code = m.group(1) if m else ""
tmp = tempfile.mkdtemp()
py = os.path.join(tmp, "chk.py")
open(py, "w").write(code)


def run(host, tls="0", plain="0", ca=""):
    env = dict(os.environ, MPW="x", MTLS=tls, MCA=ca, MPLAIN=plain, MDBPATH=HERE)
    r = subprocess.run([sys.executable, py, host, "27017", "someone", "admin", "shadowserver", "no", "yes"],
                       env=env, capture_output=True, text=True, timeout=60)
    return r.returncode, (r.stdout + r.stderr).strip()


print("Where the database may be")
rc, out = run("8.8.8.8", tls="1")
ok("a public address: refused before connecting, even with TLS", rc == 1 and "public address" in out, out[:160])
rc, out = run("10.20.30.40")
ok("an internal address without TLS: refused, saying why", rc == 1 and "MONGO_TLS" in out, out[:160])
rc, out = run("10.20.30.40", tls="1", ca=os.path.join(tmp, "missing.pem"))
ok("…with TLS and a CA file that does not exist: refused", rc == 1 and "does not exist" in out, out[:160])

print("What the installer says and does")
ok("the database on another server is called internal", "Use an internal MongoDB on another server of your network" in src
   and "Internal MongoDB server" in src)
ok("its address is checked: loopback or internal only", "v_internal_host" in src and src.count("v_internal_host") >= 3)
ok("TLS is asked for, and a plain connection only on an explicit trusted-link answer",
   "MONGO_TLS_ON" in src and "MONGO_PLAINTEXT" in src and "MONGO_ALLOW_PLAINTEXT=1" in src)
ok("the Looking Glass structure is checked (exit 3: not a Looking Glass database)", "sys.exit(3)" in code and "line_hash" in code)
ok("…and then: a new database there, or MongoDB on this computer", "DB_MISMATCH" in src and "newdb" in src and "SWITCH_LOCAL=1" in src)
ok("a failed check never ends the installer (set -e)", 'then rc=0; else rc=$?; fi' in src)
ok("both .env files get the TLS settings", src.count('"MONGO_TLS=$MONGO_TLS"') == 2)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
