#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""No answer of the app gives away a secret (API leaks), for every role and signed out.

Every route that answers GET is called in-process, once signed out and once as a made-up account of each built-in role,
and every answer (pages, JSON, downloads) is searched for:
- the made-up accounts' password hashes, authenticator secrets and recovery codes (planted in a temporary account
  store), the other sessions' tokens and form tokens;
- this installation's own secrets: the automation key and every key, secret, password or token in the platform's and
  the pipeline's .env (the Shadowserver API key and secret, the database and mail passwords, the Malpedia token...);
- anything shaped like a password hash (pbkdf2:/scrypt:) or a private key.
A finding names the route, the role and the kind of secret, never its value.

Nothing is written: the account, session, counter and role stores are temporary files, the audit log is a list, and while
the routes run every file write outside the temporary folder, every database write and every new process is refused
(and counted). Answers that need the reports database are skipped where there is none (as on GitHub).
Run: .venv/bin/python tests/check_api_no_secrets.py"""
import base64, builtins, json, os, re, secrets, shutil, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # called in-process (proxy_guard.py)
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import app as A  # noqa: E402
import auth  # noqa: E402
import pipeline_link  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lg_no_db_fast  # noqa: E402

if lg_no_db_fast.apply(BASE):
    print("no database answers here: database calls fail at once (each route still runs its own checks first)")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:900]}]" if info and not cond else ""), flush=True)


# ------------------------------------------------------------------ the secrets to look for (values stay in memory)
SECRETS = {}                     # value -> kind (the kind is what a finding prints)


def secret(value, kind):
    v = str(value or "").strip().strip("'\"")
    if len(v) >= 8 and v.lower() not in ("change-me", "changeme", "password", "user@example.org", "mail.example.org"):
        SECRETS[v] = kind


try:
    with open(os.path.join(BASE, "data", "automation.key")) as fh:
        secret(fh.read(), "the automation key")
except OSError:
    pass
SECRET_NAME = re.compile(r"(KEY|SECRET|PASSWORD|PASSWD|TOKEN|PASS)$", re.I)
pdir = None
try:
    pdir = pipeline_link.find_dir(BASE)
except Exception:                                   # noqa: BLE001 (no pipeline here, as on GitHub)
    pass
for where, path in (("the platform's .env", os.path.join(BASE, ".env")), ("the pipeline's .env", os.path.join(str(pdir or ""), ".env"))):
    if pdir is None and "pipeline" in where:
        continue
    try:
        env = pipeline_link.read_env(path) or {}
    except Exception:                               # noqa: BLE001
        env = {}
    for k, v in env.items():
        if SECRET_NAME.search(k) and not k.endswith(("_FILE", "_PATH")):
            secret(v, f"{k} from {where}")
SHAPES = [(re.compile(r"(pbkdf2|scrypt):[a-z0-9]+[:$]"), "a password hash"), (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "a private key")]

# ------------------------------------------------------------------ made-up accounts with planted secrets
tmp = tempfile.mkdtemp(prefix="lg-api-secrets-")
AU = A.AUTH
users, sessions, throttle, audit, roles = AU["users"], AU["sessions"], AU["throttle"], AU["audit"], AU["roles"]
logged = []
audit.add = lambda ev, **k: logged.append(ev)
sessions.path, throttle.path, roles.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
AU["setup"].path = os.path.join(tmp, "setup_code")      # the first-run code: never the installation's own
sessions.s.clear(); throttle.fail.clear()
ROLES = sorted(set(auth.DEFAULT_ROLES) | set(auth.FIXED_ROLES))
b32 = lambda: base64.b32encode(os.urandom(20)).decode().rstrip("=")
ACC = {}
for r in ROLES:
    pw = "lgcanary-" + secrets.token_hex(12)
    h, totp, rec = generate_password_hash(pw), b32(), [generate_password_hash(secrets.token_hex(6)) for _ in range(3)]
    secret(pw, "a made-up account's password"); secret(h, "a password hash"); secret(totp, "an authenticator secret")
    for x in rec:
        secret(x, "a recovery code hash")
    ACC["lgsec-" + r] = {"hash": h, "role": r, "status": "active", "totp": totp, "totp_last": 0, "recovery": rec, "changed": 0,
                        "created": 1, "pw_set_at": int(time.time()), "approved_by": "lgsec-admin", "approved_at": 1,
                        "profile": {"full_name": f"Sec {r.title()}", "organisation": "Made-up CSIRT", "email": f"sec-{r}@csirt-made-up.org", "country": "GH"}}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": ACC}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-api-secrets"
CLIENTS, OWN = {}, {}
for name, a in ACC.items():
    tok = sessions.create(name, "127.0.0.1", UA)
    csrf = sessions.s[auth._h(tok)]["csrf"]
    secret(tok, "a session token"); secret(csrf, "a form (CSRF) token")
    c = A.app.test_client(); c.set_cookie("lg_session", tok)
    CLIENTS[a["role"]], OWN[a["role"]] = c, {tok, csrf}     # a session's own form token is its own to see
CLIENTS["signed out"], OWN["signed out"] = A.app.test_client(), set()
ok("secrets to look for: planted ones and this installation's own", len(SECRETS) >= 6 * len(ROLES), len(SECRETS))

# ------------------------------------------------------------------ nothing may be written while the routes run
refused = []
real_open, tmp_real = builtins.open, os.path.realpath(tmp)


def guarded_open(file, mode="r", *a, **k):
    if any(c in str(mode) for c in "wax+") and isinstance(file, (str, bytes, os.PathLike)):
        p = os.path.realpath(os.fsdecode(file))
        if not p.startswith(tmp_real + os.sep):
            refused.append(f"write {p}")
            raise PermissionError("check_api_no_secrets: no writes")
    return real_open(file, mode, *a, **k)


def refuse(what):
    def f(*a, **k):
        refused.append(what)
        raise PermissionError("check_api_no_secrets: " + what)
    return f


builtins.open = guarded_open
for fn in ("replace", "rename", "remove", "unlink", "rmdir", "makedirs", "mkdir", "chmod"):
    setattr(os, fn, refuse("os." + fn))
shutil.rmtree, shutil.move, shutil.copy, shutil.copy2, shutil.copyfile = (refuse("shutil") for _ in range(5))
subprocess.Popen = refuse("a new process")
try:
    import pymongo.collection as PC
    for m in ("insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many",
              "bulk_write", "drop", "create_index", "find_one_and_update", "find_one_and_delete", "find_one_and_replace"):
        setattr(PC.Collection, m, refuse("a database write"))
except ImportError:
    pass

# ------------------------------------------------------------------ every GET route, every role
rules = sorted({r.rule for r in A.app.url_map.iter_rules() if "GET" in (r.methods or ()) and not r.rule.startswith("/static/")})
paths = [re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", r) for r in rules]
found, answered, slow = [], {}, []
for who, c in CLIENTS.items():
    look = {v: k for v, k in SECRETS.items() if v not in OWN[who]}
    n = 0
    for p in paths:
        t0 = time.time()
        try:
            r = c.get(p, headers={"User-Agent": UA})
        except Exception:                           # noqa: BLE001 (a refused write or no database: not an answer)
            continue
        if time.time() - t0 > 20:
            slow.append(f"{who} {p} {time.time() - t0:.0f}s")
        if r.status_code >= 400:
            continue
        n += 1
        body = r.get_data()
        text = body.decode("utf-8", "replace") if not body[:4] == b"%PDF" else body.decode("latin-1")
        text += "\n" + "\n".join(f"{k}: {v}" for k, v in r.headers.items() if k.lower() != "set-cookie")
        kinds = sorted({k for v, k in look.items() if v in text} | {k for rx, k in SHAPES if rx.search(text)})
        if kinds:
            found.append(f"{who}: GET {p} carries {', '.join(kinds)}")
    answered[who] = n
print("answers searched per role:", ", ".join(f"{k} {v}" for k, v in answered.items()))
if slow:
    print("slow answers:", "; ".join(slow[:10]))
ok(f"{len(paths)} GET routes x {len(CLIENTS)} (each role and signed out): no answer carries a secret", not found, found[:20])
ok("…the routes really answered (not refused everywhere)", answered.get("admin", 0) >= 40 and answered.get("analyst", 0) >= 20, answered)
if refused:      # refused safely; a GET that writes (a cache, a log) is not a leak, so it is shown, not failed
    print(f"writes refused while the routes ran: {len(refused)} ({', '.join(sorted(set(refused))[:6])})")

print(f"\n{checks - len(fails)} of {checks} API secret checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.stdout.flush(); sys.stderr.flush()
os._exit(1 if fails else 0)                 # the guards stay on: background threads cannot write on the way out
