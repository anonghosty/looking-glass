#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Review of the installer and scripts, 2026-11-28 (round 3), checked by RUNNING the functions and scripts in temporary
folders with stand-ins (a stand-in pymongo, sudo, systemctl, ufw, tar, caddy_front.sh...). Nothing on this computer is
changed, nothing runs as root, nothing connects anywhere.

  r3-0a  install.sh env_precheck: a value the .env rule refuses stops the installation before .env is replaced
  r3-0b  install.sh re-install: a stored MongoDB password the rule refuses (a ') is dropped, with the reason, and asked for
  r3-1   install.sh check_mongo: the pipeline's own role (lookingglass_pipeline_on_<db>@admin) is accepted by what
         MongoDB says the account may do (find, insert, update on the database); too few rights still refused
  r3-2   uninstall.sh --remove-database: the role lookingglass_pipeline_on_<db> is dropped too ("not found" ignored)
  r3-3   install.sh env_get reads .env as deploy.sh does (spaces around = and the value, CR); still one line
  r3-4   uninstall.sh: Caddy's configuration and its ufw rule go only when that Caddy is this folder's (its
         reverse_proxy port = platform/.env LG_PORT); otherwise left, and said why
  r3-5   install.sh env_set: an empty value is written K= (never K='')
  r3-6   install.sh env_set: every line break str.splitlines() knows is refused; other lines written back as they were
  r3-7   make_tls_cert.sh behind an internal Caddy: exit 3 (said why) when Caddy could not be given the certificate
  r3-8   backup.sh: tar's exit 1 names the files it reported, "may be incomplete for these files", the backup kept

LG_FIX_R3_ROOT points the checks at another copy of the platform (the old code, to see them fail); install.sh and
uninstall.sh are looked for in tools/release_root/ and next to the platform. Run: .venv/bin/python tests/check_fix_r3.py"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.abspath(os.environ.get("LG_FIX_R3_ROOT") or HERE)
checks, fails = 0, []
CLEAN = []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:700]}]" if info and not cond else ""), flush=True)


def tmpdir(prefix="lg-r3-"):
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
    with open(p, "w", encoding="utf-8", newline="") as f:
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
            if ln.count("{") + ln.count("(") <= ln.count("}") + ln.count(")"):
                return ln
            for j in range(i + 1, len(lines)):
                if lines[j] in ("}", ")"):
                    return "\n".join(lines[i:j + 1])
    return ""


def heredoc(src, after):
    """The text of the first <<'EOF' document after the marker `after`."""
    if after not in src:
        return ""
    a = src.index(after)
    a = src.index("\n", src.index("<<'EOF'", a)) + 1
    return src[a:src.index("\nEOF\n", a) + 1]


def bash(script, *args, env=None, cwd=None, stdin=None, timeout=60):
    r = subprocess.run(["bash", "-c", script, "_", *args], capture_output=True, text=True, env=env, cwd=cwd,
                       input=stdin, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


INSTALL = first(os.path.join(ROOT, "tools", "release_root", "install.sh"), os.path.join(ROOT, "..", "install.sh"))
UNINSTALL = first(os.path.join(ROOT, "tools", "release_root", "uninstall.sh"), os.path.join(ROOT, "..", "uninstall.sh"))
INST = read(INSTALL) if INSTALL else ""
UNINST = read(UNINSTALL) if UNINSTALL else ""
print(f"platform: {ROOT}\ninstall.sh: {INSTALL}\nuninstall.sh: {UNINSTALL}")
if os.geteuid() == 0:
    print("run as an ordinary user: the uninstaller refuses root, and nothing here may run as root")
    sys.exit(1)
LIB = "\n".join(x for x in (fn(INST, n) for n in ("_env_py", "env_set", "env_get", "v_env_secret")) if x) + "\n"

# a stand-in pymongo (and db_connect): answers from FAKE_* in the environment, records the commands in FAKE_LOG
FAKE = tmpdir("lg-r3-fake-")
write(os.path.join(FAKE, "pymongo", "errors.py"), '''
class PyMongoError(Exception):
    pass


class OperationFailure(PyMongoError):
    def __init__(self, msg, code=None, details=None):
        super().__init__(msg)
        self.code = code
        self.details = details or {"errmsg": msg}
''')
write(os.path.join(FAKE, "pymongo", "__init__.py"), '''
import json
import os
from pymongo.errors import OperationFailure, PyMongoError  # noqa: F401


def _log(*a):
    if os.environ.get("FAKE_LOG"):
        with open(os.environ["FAKE_LOG"], "a") as f:
            f.write(" ".join(map(str, a)) + "\\n")


class _DB:
    def __init__(self, name):
        self.name = name

    def command(self, cmd, *args, **kw):
        _log("command", self.name, cmd, *args)
        if cmd == "connectionStatus":
            info = {"authenticatedUserRoles": json.loads(os.environ.get("FAKE_ROLES", "[]"))}
            if kw.get("showPrivileges"):
                info["authenticatedUserPrivileges"] = json.loads(os.environ.get("FAKE_PRIVS", "[]"))
            return {"authInfo": info}
        fails = json.loads(os.environ.get("FAKE_FAIL", "{}"))
        if cmd in fails:
            raise OperationFailure(f"{cmd} failed", code=fails[cmd])
        return {"ok": 1}

    def list_collection_names(self):
        return []


class MongoClient:
    def __init__(self, **kw):
        self.kw = kw

    def server_info(self):
        return {"version": "7.0.0"}

    @property
    def admin(self):
        return _DB("admin")

    def __getitem__(self, n):
        return _DB(n)

    def list_database_names(self):
        if not self.kw.get("username"):
            raise OperationFailure("requires authentication", code=13)
        return ["admin", "shadowserver"]

    def drop_database(self, n):
        _log("drop_database", n)
''')
write(os.path.join(FAKE, "db_connect.py"), '''
class Refused(Exception):
    pass


def kwargs(get):
    return {"host": get("MONGO_HOST"), "port": int(get("MONGO_PORT"))}


def describe(get):
    return f"{get('MONGO_HOST')}:{get('MONGO_PORT')}"
''')

try:
    # ------------------------------------------------------------------------------------------------ r3-0a
    print("r3-0a env_precheck: a refused value stops the installation before .env is replaced")
    pre = fn(INST, "env_precheck")
    ok("install.sh has env_precheck", bool(pre))
    # the installer's own write steps for database/.env and platform/.env, run as they are (env_set records the keys)
    m_db = re.search(r'\n(  gauge 10 "Writing database/\.env\.\.\."\n.*?)\n  if declare -F wait_for_apt', INST, re.S)
    m_pf = re.search(r'\n(  gauge 55 "Writing platform/\.env\.\.\."\n.*?)\n  gauge 60 ', INST, re.S)
    ok("…the installer's write steps for both .env files are there", m_db is not None and m_pf is not None)
    names = ("M_PROVIDER IMAP_SERVER IMAP_USER IMAP_FOLDER IMAP_VERIFY_TLS GMAIL_USER GMAIL_LABEL MS_TENANT_ID MS_CLIENT_ID "
             "MS_MAILBOX MS_FOLDER EMAIL_DAYS MAIL_AUTH REPORT_SOURCE MONGO_HOST MONGO_PORT MONGO_ADMIN_USER MONGO_AUTH_SOURCE "
             "MONGO_DB MONGO_MODE MONGO_BIND MONGO_TLS MONGO_TLS_CA_FILE MONGO_ALLOW_PLAINTEXT IMAP_PASSWORD MS_CLIENT_SECRET "
             "MONGO_ADMIN_PASSWORD SS_API_KEY SS_API_SECRET COUNTRY ACCESS_MODE VIEWER_NETWORKS ALLOWED_HOSTS TRUST_PROXY "
             "INSECURE REGISTRATION LG_PORT MAPBOX_TOKEN MALPEDIA_TOKEN").split()
    env_py = fn(INST, "_env_py")
    # _env_py under another name, and a wrapper that records which keys are checked (check / check-secret)
    CHECK_LIB = (env_py.replace("_env_py() {", "_env_py_real() {", 1) + "\n"
                 + '_env_py() { [ "$1" = write ] || printf "%s\\n" "$K" >> "$T/checked"; _env_py_real "$@"; }\n'
                 + "\n".join(x for x in (fn(INST, n) for n in ("env_set", "env_get", "v_env_secret")) if x) + "\n")

    def precheck(keep_db="no", run_writes=True, **vals):
        t = tmpdir()
        for d in ("db", "pf"):
            write(os.path.join(t, d, ".env"), "OLD=1\n")
            write(os.path.join(t, d, ".env.example"), "EXAMPLE=1\n")
        defaults = {n: "x" for n in names}
        defaults.update({"M_PROVIDER": "imap", "MONGO_MODE": "local", "IMAP_FOLDER": "INBOX", **vals})
        # the installer runs under set -Eeuo pipefail: so does this (an unset variable is a failure here too)
        head = ('set -Eeuo pipefail\nT="$1"; DB_DIR="$T/db"; PF_DIR="$T/pf"; : > "$T/checked"\nlog() { :; }\ngauge() { :; }\n'
                "fail() { printf 'STOPPED: %s\\n' \"$1\" >&2; exit 1; }\n"
                f"WANT_DB=1; WANT_PF=1; KEEP_DB_ENV={keep_db}; KEEP_PF_ENV=no\n"
                + "".join(f'{n}="$R3_{n}"\n' for n in names))
        writes = ""
        if run_writes:
            writes = ('\nenv_set() { printf "%s\\n" "$2" >> "$T/written.$(basename "$(dirname "$1")")"; }\n'
                      + "if [ $WANT_DB = 1 ]; then\n" + (m_db.group(1) if m_db else "false") + "\nfi\n"
                      + "if [ $WANT_PF = 1 ]; then\n" + (m_pf.group(1) if m_pf else "false") + "\nfi\n")
        flow = "\n" + "\n".join(x for x in (fn(INST, "env_lists"),) if x) + "\n" + pre + "\nenv_precheck\necho CHECKED\n" + writes
        env = dict(os.environ, **{f"R3_{k}": v for k, v in defaults.items()})
        rc, out, err = bash(head + CHECK_LIB + flow, t, env=env)
        keys = {f: set(read(os.path.join(t, f)).split()) for f in ("checked", "written.db", "written.pf")}
        return rc, out + err, read(os.path.join(t, "db", ".env")), keys

    GENERATED = {"REF_SECRET", "CONNECTOR_KEY_SECRET"}     # made by the installer (random hexadecimal), never typed
    rc, out, envtxt, keys = precheck()
    written = (keys["written.db"] | keys["written.pf"]) - GENERATED
    ok("…all values fine: it goes on, under set -Eeuo pipefail", bool(pre) and rc == 0 and "CHECKED" in out, (rc, out[-400:]))
    ok("…every key the write steps put into either .env (bar the two generated secrets) is one the check checked",
       rc == 0 and written and written <= keys["checked"], sorted(written - keys["checked"]))
    rc, out, envtxt, keys = precheck(keep_db="yes", SS_API_KEY="k1", SS_API_SECRET="s1")
    ok("…database/.env kept: what is still written there (EMAIL_DAYS, MAIL_AUTH, REPORT_SOURCE, the API key and secret) is checked too",
       rc == 0 and {"SHADOWSERVER_API_KEY", "SHADOWSERVER_API_SECRET", "EMAIL_DAYS"} <= keys["written.db"]
       and keys["written.db"] <= keys["checked"], (rc, sorted(keys["written.db"] - keys["checked"]), out[-300:]))
    rc, out, envtxt, keys = precheck(IMAP_FOLDER="INBOX${X}", MS_CLIENT_SECRET="it's")
    ok("…a folder name with ${ and a secret with a ': stopped with both reasons, .env NOT replaced, nothing after it ran",
       bool(pre) and rc == 1 and "CHECKED" not in out and envtxt == "OLD=1\n" and "IMAP_FOLDER" in out
       and "MS_CLIENT_SECRET" in out and "nothing was installed" in out, (rc, out[-400:], envtxt))
    rc, out, envtxt, keys = precheck(MONGO_AUTH_SOURCE="adm${x}")
    ok("…MONGO_AUTH_SOURCE=adm${x} (typed at a free-form question): stopped before database/.env is replaced, named once",
       rc == 1 and "CHECKED" not in out and envtxt == "OLD=1\n" and out.count("MONGO_AUTH_SOURCE:") == 1, (rc, out[-400:], envtxt))
    a = INST.find("\nenv_precheck\n")
    b = INST.find('install -m 600 "$DB_DIR/.env.example" "$DB_DIR/.env"')
    c = INST.find('install -m 600 "$PF_DIR/.env.example" "$PF_DIR/.env"')
    s = INST.find('S="Install:')
    ok("…and in install.sh it runs before the summary and before either .env is replaced", 0 < a < s < b and a < c,
       (a, s, b, c))

    # ------------------------------------------------------------------------------------------------ r3-0b
    print("r3-0b re-install: a stored MongoDB password the .env rule refuses is asked for")
    m = re.search(r'\n(    OLD_MUSER="\$\(env_get "\$ADMIN_ENV" MONGO_USER\)".*?\n    unset OLD_MPW OLD_MUSER ADMIN_FROM)\n', INST, re.S)
    ok("install.sh's re-install block (stored administrator password) is there", m is not None)

    def stored(pw, ui="text"):
        t = tmpdir()
        write(os.path.join(t, "admin.env"), f"MONGO_USER=shadowserver_admin\nMONGO_PASSWORD={pw}\n")
        head = (f'set -Eeuo pipefail\nROOT="$1"; ADMIN_ENV="$2"; ETC_TMP=""; UI={ui}; declare -A ANS=()\nlog() {{ :; }}\n'
                'ask_input() { REPLY="$4"; }\nask_secret() { echo ASKED >> "$ROOT/asked"; REPLY="typed-new"; }\n'
                'msg() { printf "%s|%s\\n" "$1" "$2" >> "$ROOT/msg"; }\n')
        flow = '\nprintf "%s" "$MONGO_ADMIN_PASSWORD" > "$ROOT/pw"\n'
        rc, out, err = bash(head + LIB + (m.group(1) if m else "false") + flow, t, os.path.join(t, "admin.env"))
        if ui == "dialog":
            err = ("MSG:" + read(os.path.join(t, "msg"))) if read(os.path.join(t, "msg")) else "STDERR:" + err
        return rc, read(os.path.join(t, "pw")), os.path.exists(os.path.join(t, "asked")), err

    rc, pw, asked, err = stored("it'sold")
    ok("…a stored password with a ': not kept, asked for, and it says why", rc == 0 and asked and pw == "typed-new"
       and "cannot be kept" in err and "single quote" in err, (rc, pw, asked, err[-300:]))
    rc, pw, asked, err = stored("it'sold", ui="dialog")
    ok("…in the dialog interface the reason is shown in a window of its own (msg), not on stderr behind the password box",
       rc == 0 and asked and err.startswith("MSG:") and "cannot be kept" in err and "single quote" in err, (rc, asked, err[-300:]))
    rc, pw, asked, err = stored("Good-pass_1")
    ok("…a stored password the rule accepts: kept, not asked", rc == 0 and not asked and pw == "Good-pass_1", (rc, pw, asked, err[-300:]))

    # ------------------------------------------------------------------------------------------------ r3-1
    print("r3-1  check_mongo: the pipeline's own role on an external MongoDB")
    chk = heredoc(INST, "check_mongo() {")
    ok("install.sh's check_mongo is there", bool(chk))
    ROLE_ACTIONS = ["collStats", "createCollection", "createIndex", "dbStats", "find", "insert", "killCursors",
                    "listCollections", "listIndexes", "remove", "update"]

    def check_mongo(roles, privs, need_write="yes", mdbpath=FAKE):
        env = dict(os.environ, MPW="pw", MDBPATH=mdbpath, FAKE_ROLES=json.dumps(roles), FAKE_PRIVS=json.dumps(privs))
        r = subprocess.run([sys.executable, "-", "db.internal", "27017", "lookingglass_pipeline", "admin", "shadowserver",
                            "no", need_write], input=chk, capture_output=True, text=True, env=env, timeout=60)
        return r.returncode, r.stdout + r.stderr

    own = [{"role": "lookingglass_pipeline_on_shadowserver", "db": "admin"}, {"role": "clusterMonitor", "db": "admin"}]
    own_p = [{"resource": {"db": "shadowserver", "collection": ""}, "actions": ROLE_ACTIONS},
             {"resource": {"cluster": True}, "actions": ["serverStatus"]}]
    rc, out = check_mongo(own, own_p)
    ok("lookingglass_pipeline_on_shadowserver@admin (create_pipeline_db_user.py --print's role): accepted", rc == 0
       and "MongoDB 7.0.0" in out, (rc, out[-400:]))
    rc, out = check_mongo([{"role": "readWrite", "db": "shadowserver"}], [])
    ok("…readWrite on the database: still accepted", rc == 0, (rc, out[-300:]))
    rc, out = check_mongo([{"role": "read", "db": "shadowserver"}],
                          [{"resource": {"db": "shadowserver", "collection": ""}, "actions": ["find", "listCollections"]}])
    ok("…read only (no insert, update): refused, naming the role it needs", rc == 1 and "cannot write" in out
       and "lookingglass_pipeline_on_shadowserver" in out, (rc, out[-300:]))
    rc, out = check_mongo([{"role": "custom", "db": "admin"}],
                          [{"resource": {"db": "shadowserver", "collection": ""}, "actions": ["find", "insert", "update"]}])
    ok("…a role with only find, insert and update: refused, naming what is missing (remove, createIndex, createCollection, "
       "listCollections)", rc == 1 and "cannot write" in out
       and all(a in out for a in ("remove", "createIndex", "createCollection", "listCollections")), (rc, out[-400:]))
    # the list is read from database/create_pipeline_db_user.py (WRITE_ACTIONS) when it is there
    pdir = tmpdir()
    write(os.path.join(pdir, "create_pipeline_db_user.py"),
          'WRITE_ACTIONS = {"find", "insert", "update", "remove", "createIndex", "createCollection", "listCollections", "r3Probe"}\n')
    rc, out = check_mongo(own, own_p, mdbpath=FAKE + ":" + pdir)
    ok("…the rights are those of create_pipeline_db_user.py's WRITE_ACTIONS (one more there: the role without it is refused, "
       "naming it)", rc == 1 and "r3Probe" in out, (rc, out[-300:]))
    real = first(os.path.join(os.environ.get("LG_HELD_DIR", "/nonexistent"), "pipe_new", "create_pipeline_db_user.py"),
                 os.path.join(ROOT, "..", "database", "create_pipeline_db_user.py"),
                 os.path.expanduser("~/looking-glass-release/database/create_pipeline_db_user.py"))
    if real:
        rc, out = check_mongo(own, own_p, mdbpath=FAKE + ":" + os.path.dirname(real))
        ok(f"…with the pipeline's own create_pipeline_db_user.py ({real}): the role it makes is accepted", rc == 0, (rc, out[-300:]))
    rc, out = check_mongo([{"role": "lookingglass_pipeline_on_other", "db": "admin"}],
                          [{"resource": {"db": "other", "collection": ""}, "actions": ROLE_ACTIONS}])
    ok("…the same rights on another database: refused", rc == 1 and "cannot write" in out, (rc, out[-300:]))
    rc, out = check_mongo([{"role": "x", "db": "admin"}],
                          [{"resource": {"db": "shadowserver", "collection": "one"}, "actions": ROLE_ACTIONS}])
    ok("…rights on one collection only: refused", rc == 1 and "cannot write" in out, (rc, out[-300:]))

    # ------------------------------------------------------------------------------------------------ r3-2
    print("r3-2  uninstall --remove-database: the pipeline's role too")
    drop = heredoc(UNINST, '"$PY" -I - <<')
    ok("uninstall.sh's database step is there", bool(drop))

    def uninstall_db(fail):
        t = tmpdir()
        write(os.path.join(t, "admin.env"), "MONGO_USER=shadowserver_admin\nMONGO_PASSWORD=pw\n")
        log = os.path.join(t, "calls.log")
        env = dict(os.environ, LGU_ENV=os.path.join(t, "admin.env"), LGU_DB="shadowserver", LGU_HOST="127.0.0.1",
                   LGU_PORT="27017", FAKE_LOG=log, FAKE_FAIL=json.dumps(fail),
                   PYTHONPATH=FAKE + os.pathsep + os.environ.get("PYTHONPATH", ""))
        r = subprocess.run([sys.executable, "-"], input=drop, capture_output=True, text=True, env=env, timeout=60)
        return r.returncode, r.stdout + r.stderr, read(log)

    rc, out, calls = uninstall_db({})
    ok("the role lookingglass_pipeline_on_shadowserver is dropped in admin, with the two accounts and the database",
       rc == 0 and "command admin dropRole lookingglass_pipeline_on_shadowserver" in calls
       and "dropUser lookingglass_pipeline" in calls and "drop_database shadowserver" in calls, (rc, calls, out[-300:]))
    rc, out, calls = uninstall_db({"dropRole": 31})
    ok("…no such role (an older installation): ignored, the database still deleted", rc == 0 and "drop_database shadowserver" in calls,
       (rc, calls, out[-300:]))
    rc, out, calls = uninstall_db({"dropRole": 13})
    ok("…any other refusal (not allowed): it stops, the database NOT deleted", rc != 0 and "drop_database" not in calls,
       (rc, calls, out[-300:]))
    ok("…the plan and the dry run name the role", "lookingglass_pipeline_on_$MONGO_DB" in UNINST)

    # ------------------------------------------------------------------------------------------------ r3-3
    print("r3-3  install.sh env_get reads .env as deploy.sh does")
    eg = fn(INST, "env_get")
    ok("env_get is one line (check_installer_caddy_db takes it up to the end of its line)", eg.startswith("env_get() {") and "\n" not in eg, eg[:80])
    t = tmpdir()
    f = os.path.join(t, ".env")
    write(f, "  MONGO_HOST = db.internal  \nSPACED= 'a b' \nCRLF=v1\r\nPLAIN=x\nPLAIN_X=no\nTAB\t=\ttabbed\n")
    expect = {"MONGO_HOST": "db.internal", "SPACED": "a b", "CRLF": "v1", "PLAIN": "x", "TAB": "tabbed", "MISSING": ""}
    got = {k: bash(eg + '\nprintf "%s" "$(env_get "$1" "$2")"', f, k)[1] for k in expect}
    DEPLOY_SH = first(os.path.join(ROOT, "..", "database", "deploy.sh"), os.path.join(HERE, "..", "database", "deploy.sh"),
                      os.path.expanduser("~/looking-glass-release/database/deploy.sh"))
    dget = fn(read(DEPLOY_SH), "env_get") if DEPLOY_SH else ""
    dep = {k: bash(dget + '\nenv_get "$1"', k, cwd=t)[1] for k in expect} if dget else {}
    ok("'  KEY = value  ', \"KEY= 'a b' \", a CR, a tab around =, a longer key beside it: the value deploy.sh reads",
       got == expect and (not dep or dep == expect), {"install.sh": got, "deploy.sh": dep})

    # ------------------------------------------------------------------------------------------------ r3-5 / r3-6
    print("r3-5  an empty value;  r3-6  every line break splitlines() knows")
    t = tmpdir()
    f = os.path.join(t, "env")
    write(f, "A=1\n")
    rc, out, err = bash(LIB + 'env_set "$1" MAPBOX_TOKEN ""', f)
    ok("an empty value is written MAPBOX_TOKEN= (never MAPBOX_TOKEN=''), so typing after the = gives the token", rc == 0
       and read(f) == "A=1\nMAPBOX_TOKEN=\n", repr(read(f)))
    from dotenv import dotenv_values
    write(f, read(f).replace("MAPBOX_TOKEN=", "MAPBOX_TOKEN=pk.abc"))
    ok("…and after a person types after it, every reader sees pk.abc", dotenv_values(f).get("MAPBOX_TOKEN") == "pk.abc"
       and bash(LIB + 'printf "%s" "$(env_get "$1" MAPBOX_TOKEN)"', f)[1] == "pk.abc", read(f))
    breaks = {"\\v": "\v", "\\f": "\f", "\\x1c": "\x1c", "\\x1d": "\x1d", "\\x1e": "\x1e", "\\x85": "\x85",
              "U+2028": "\u2028", "U+2029": "\u2029", "\\n": "\n", "\\r": "\r"}
    write(f, "SECRET=old\n")
    res = {}
    for label, ch in breaks.items():
        for mode in ("write", "secret"):
            if mode == "write":
                rc, out, err = bash(LIB + 'env_set "$1" SECRET "$2"', f, f"a{ch}b")
                res[f"{label} env_set"] = rc != 0 and "cannot contain" in err and read(f) == "SECRET=old\n"
            else:
                rc, out, err = bash(LIB + 'v_env_secret "$1"', f"a{ch}b")
                res[f"{label} v_env_secret"] = rc != 0 and "cannot contain" in out
    ok("a value with \\v, \\f, \\x1c-\\x1e, \\x85, U+2028 or U+2029 (lines for str.splitlines()): refused with the reason, "
       "the file left as it was", all(res.values()), {k: v for k, v in res.items() if not v})
    ok("…install.sh spells U+2028 and U+2029 as \\u escapes, never as the characters themselves (invisible in an editor)",
       bool(INST) and "\u2028" not in INST and "\u2029" not in INST and "\\u2028" in INST)
    other = "OTHER=a\x85b\u2028c\nSECRET=old\nLAST=1\n"
    with open(f, "w", encoding="utf-8", newline="") as fh:
        fh.write(other)
    rc, out, err = bash(LIB + 'env_set "$1" SECRET new', f)
    with open(f, encoding="utf-8", newline="") as fh:
        now = fh.read()
    ok("…writing one key leaves another line holding \\x85 or U+2028 exactly as it was (split at \\n only)",
       rc == 0 and now == "OTHER=a\x85b\u2028c\nSECRET=new\nLAST=1\n", repr(now))

    # ------------------------------------------------------------------------------------------------ r3-4
    print("r3-4  uninstall.sh: Caddy and its firewall rule only when that Caddy is this folder's")

    def uninstall_box(lg_port):
        t = tmpdir()
        root = os.path.join(t, "looking-glass")
        pf = os.path.join(root, "platform")
        for d in ("database", "platform/deploy"):
            os.makedirs(os.path.join(root, d), exist_ok=True)
        for d in ("sys/systemd", "sys/etc-lg", "sys/bin", "stubs"):
            os.makedirs(os.path.join(t, d), exist_ok=True)
        shutil.copy(UNINSTALL or "/dev/null", os.path.join(root, "uninstall.sh"))
        write(os.path.join(root, "install.sh"), "#!/bin/sh\n")
        write(os.path.join(root, "database", ".env"), "MONGO_DB=shadowserver\n")
        log = os.path.join(t, "calls.log")
        write(os.path.join(pf, "deploy", "caddy_front.sh"), f'echo "caddy_front $*" >> "{log}"\n')
        if lg_port:
            write(os.path.join(pf, ".env"), f"LG_SERVICE=lgx\nLG_PORT={lg_port}\n")
        caddyfile = os.path.join(t, "sys", "Caddyfile")
        write(caddyfile, "# Managed by Looking Glass (deploy/caddy_front.sh): changes here are replaced by the next setup or renewal.\n"
                         "{\n}\n\nhttps://lg.example.org:8443 {\n\treverse_proxy https://127.0.0.1:5001 {\n\t}\n}\n")
        st = os.path.join(t, "stubs")
        stub(st, "sudo", f'echo "sudo $*" >> "{log}"; [ "$1" = -n ] && shift; [ "$1" = -v ] && exit 0; '
                         'for a in "$@"; do case "$a" in /var/*|/etc/*|/usr/*|/lib/*|/opt/*|/boot/*) '
                         f'echo "refused (real system path): $*" >> "{log}"; exit 0;; esac; done; "$@"')
        stub(st, "systemctl", f'echo "systemctl $*" >> "{log}"')
        stub(st, "ufw", f'echo "ufw $*" >> "{log}"; [ "$1" = status ] && printf "Status: active\\n\\nTo  Action  From\\n--  ------  ----\\n'
                        '8443/tcp                   ALLOW       Anywhere                   # Looking Glass HTTPS\\n"; exit 0')
        stub(st, "mandb", "true")
        stub(st, "pgrep", "exit 1")
        stub(st, "crontab", "exit 1")
        env = dict(os.environ, PATH=f"{st}:/usr/bin:/bin", HOME=t, LG_UNINSTALL_SYSTEMD_DIR=os.path.join(t, "sys", "systemd"),
                   LG_UNINSTALL_ETC_DIR=os.path.join(t, "sys", "etc-lg"), LG_UNINSTALL_BIN=os.path.join(t, "sys", "bin", "shadowserver"),
                   LG_UNINSTALL_MAN=os.path.join(t, "sys", "man1"), LG_UNINSTALL_COMPLETION=os.path.join(t, "sys", "compl"),
                   LG_UNINSTALL_MONGOD_CONF=os.path.join(t, "sys", "mongod.conf"), LG_UNINSTALL_CADDYFILE=caddyfile)
        r = subprocess.run(["bash", os.path.join(root, "uninstall.sh"), "--yes"], env=env, cwd=root, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr, read(log)

    rc, out, calls = uninstall_box("5001")
    ok("Caddy hands visitors to 127.0.0.1:5001 and this folder's LG_PORT is 5001: its configuration and the 8443 rule go",
       rc == 0 and "caddy_front remove" in calls and "ufw delete allow 8443/tcp" in calls, (rc, calls[-400:], out[-300:]))
    rc, out, calls = uninstall_box("5002")
    ok("…this folder's LG_PORT is 5002 (another installation's Caddy): neither touched, and it says what was left and why",
       rc == 0 and "caddy_front" not in calls and "ufw delete" not in calls and "another installation's" in out
       and "5001" in out and "5002" in out, (rc, calls[-400:], out[-500:]))
    rc, out, calls = uninstall_box("")
    ok("…no LG_PORT in platform/.env: neither touched; it says it cannot tell whose Caddy it is and how to remove it "
       "(never 'another installation's')", rc == 0 and "caddy_front" not in calls and "ufw delete" not in calls
       and "cannot tell whose Caddy it is" in out and "sudo platform/deploy/caddy_front.sh remove" in out
       and "another installation's" not in out, (rc, calls[-400:], out[-400:]))

    # ------------------------------------------------------------------------------------------------ r3-7
    print("r3-7  make_tls_cert.sh behind an internal Caddy: not given to Caddy = not a success")

    def tls_box(sudo_ok=True, sync_rc=0):
        t = tmpdir()
        p = os.path.join(t, "platform")
        write(os.path.join(p, "deploy", "make_tls_cert.sh"),
              read(os.path.join(ROOT, "deploy", "make_tls_cert.sh")).replace("/etc/caddy/", t + "/etc/caddy/"), 0o755)
        write(os.path.join(p, "deploy", "reload.sh"), f'echo reload >> "{t}/calls.log"\n')
        write(os.path.join(p, "deploy", "caddy_front.sh"), f'echo "caddy_front $*" >> "{t}/calls.log"; exit {sync_rc}\n')
        write(os.path.join(p, ".env"), "ACCESS_MODE=private\nLG_SERVICE=lgx\n")
        write(os.path.join(t, "etc", "caddy", "Caddyfile"),
              "# Managed by Looking Glass (deploy/caddy_front.sh): x\n# internal: lg.internal\nhttps://:8443 {\n}\n")
        b = os.path.join(t, "bin")
        stub(b, "id", 'case "$1" in -u) echo 1000 ;; -un) echo lguser ;; *) command -p id "$@" ;; esac')
        stub(b, "hostname", 'case "$1" in -f) echo lg-host.lan ;; -I) echo 10.0.0.5 ;; *) echo lg-host ;; esac')
        stub(b, "systemctl", 'exit 0')
        stub(b, "sudo", f'echo "sudo $*" >> "{t}/calls.log"; if [ "$1" = -n ]; then [ "{1 if sudo_ok else 0}" = 1 ]; exit; fi; '
                        f'[ "$1" = bash ] && [ "$2" = deploy/caddy_front.sh ] && exec bash "$2" "${{@:3}}"; exit 1')
        r = subprocess.run(["bash", os.path.join(p, "deploy", "make_tls_cert.sh")], env=dict(os.environ, PATH=b + ":" + os.environ["PATH"]),
                           cwd=p, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)
        return r.returncode, r.stdout + r.stderr, read(os.path.join(t, "calls.log"))

    rc, out, calls = tls_box()
    ok("the sync works: exit 0", rc == 0 and "caddy_front sync" in calls and "Caddy has the new certificate" in out, (rc, out[-300:]))
    rc, out, calls = tls_box(sudo_ok=False)
    ok("…sudo needs a password and there is no terminal: exit 3, it says why and what to run (visitors get a 502)",
       rc == 3 and "NOT FINISHED" in out and "no terminal" in out and "sudo deploy/caddy_front.sh sync" in out and "502" in out,
       (rc, out[-400:]))
    rc, out, calls = tls_box(sync_rc=1)
    ok("…the sync fails: exit 3, said", rc == 3 and "NOT FINISHED" in out and "the sync failed" in out, (rc, out[-400:]))
    ok("…install.sh accepts that 3 only when it sets Caddy up right after (it then gives Caddy the certificate)",
       "deploy/make_tls_cert.sh || [ $? = 3 ]" in INST and re.search(r'if \[ -n "\$PUBLIC_PORT" \]; then\n(?:\s*#[^\n]*\n)*\s*run "HTTPS certificate"', INST) is not None)

    # ------------------------------------------------------------------------------------------------ r3-8
    print("r3-8  backup.sh: tar's exit 1 names the files")
    t = tmpdir()
    p = os.path.join(t, "lgp")
    for name in ("backup.sh", "backup_crypt.sh"):
        write(os.path.join(p, "manage", name), read(os.path.join(ROOT, "manage", name)), 0o755)
    write(os.path.join(p, ".env"), "SECRET_KEY=abc\nLG_SERVICE=lg\n")
    os.makedirs(os.path.join(p, "data"))
    stub(os.path.join(t, "bin"), "tar", 'o=""; prev=""; for a in "$@"; do [ "$prev" = -czf ] && o="$a"; prev="$a"; done\n'
         'case " $* " in *" -czf "*) if [ "$o" = - ]; then printf archive; else printf archive > "$o"; fi\n'
         '  echo "tar: lgp/data/audit.log: file changed as we read it" >&2\n'
         '  echo "tar: lgp/data/sessions/s1: File shrank by 12 bytes; padding with zeros" >&2\n  exit 1 ;; esac; exit 0')
    dest = os.path.join(t, "out")
    tmpd = os.path.join(t, "tmp")
    os.makedirs(tmpd)
    r = subprocess.run(["bash", os.path.join(p, "manage", "backup.sh"), "--unencrypted", dest],
                       env=dict(os.environ, PATH=os.path.join(t, "bin") + ":" + os.environ["PATH"], HOME=t, TMPDIR=tmpd),
                       capture_output=True, text=True, timeout=60)
    o = r.stdout + r.stderr
    files = sorted(os.listdir(dest)) if os.path.isdir(dest) else []
    ok("tar exit 1: 'may be incomplete for these files: lgp/data/audit.log, lgp/data/sessions/s1', the backup kept with its checksum",
       r.returncode == 0 and "may be incomplete for these files" in o and "lgp/data/audit.log" in o.split("may be incomplete", 1)[-1]
       and "lgp/data/sessions/s1" in o.split("may be incomplete", 1)[-1] and "The backup is kept" in o
       and any(x.endswith(".tar.gz") for x in files) and any(x.endswith(".tar.gz.sha256") for x in files), (r.returncode, files, o[-500:]))
    ok("…tar's own messages are still shown, and no temporary file of them is left (TMPDIR empty)",
       "file changed as we read it" in o and os.listdir(tmpd) == [], (os.listdir(tmpd), o[-300:]))
finally:
    for d in CLEAN:
        shutil.rmtree(d, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
