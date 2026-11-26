#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""No page or answer holds a sign-in name (person_code.py): a sign-in name is half of what signs someone in.

Every GET route of the app is called in-process as each built-in role (administrators aside: they manage the accounts
by sign-in name), with a colleague account in every role. No answer may contain the viewer's own sign-in name or any
colleague's: not in the page source, a data- attribute, a script or a JSON answer. Allowed: the person's own Account
page, and the audit portal for the auditor (the audit trail names accounts by sign-in name on purpose). Pages are the
held copies in LG_HELD_DIR when there are any (the release that ships next), then templates/.

Nothing is written: the account, session, counter and role stores are temporary files, the audit log is a list, and
while the routes run every file write outside the temporary folder, every database write, every new process and every
connection to another computer is refused. Routes that need the reports database answer from none where there is none.
Run: .venv/bin/python tests/check_no_signin_names.py"""
import base64, builtins, json, os, re, shutil, socket, subprocess, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
HERE = os.path.dirname(os.path.abspath(__file__))
import app as A  # noqa: E402
import auth  # noqa: E402
import person_code  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

sys.path.insert(0, HERE)
import lg_no_db_fast  # noqa: E402

if lg_no_db_fast.apply(os.path.dirname(HERE)):
    print("no database answers here: database calls fail at once")

HELD = os.environ.get("LG_HELD_DIR", "")
if HELD:                                      # the templates that ship next (<name>.new), the rest from templates/
    from jinja2 import ChoiceLoader, FunctionLoader

    def _held(name):
        p = os.path.join(HELD, name + ".new")
        return open(p, encoding="utf-8").read() if os.path.exists(p) else None
    A.app.jinja_env.loader = ChoiceLoader([FunctionLoader(_held), A.app.jinja_env.loader])

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:2000]}]" if info and not cond else ""), flush=True)


print("1. The code")
import hashlib, hmac, stat, threading  # noqa: E401,E402
kdir = tempfile.mkdtemp(prefix="lg-person-code-")
person_code.configure(kdir)
a, b = person_code.code("lgsnq-one"), person_code.code("lgsnq-two")
kf = os.path.join(kdir, person_code.KEY_FILE)
ok("the installation's own key is made once, 32 random bytes, owner-only", os.path.getsize(kf) == 32
   and stat.S_IMODE(os.stat(kf).st_mode) == 0o600)
ok("one account, one code; two accounts, two codes", a == person_code.code("lgsnq-one") and a != b and a.startswith("p-"), (a, b))
ok("the code does not hold the sign-in name", "lgsnq" not in a)
ok("…and is not the hash of the name without the key (a guessed name gives nothing)",
   a[2:] not in (hashlib.sha256(b"lg-person:lgsnq-one").hexdigest(), hmac.new(b"", b"lg-person:lgsnq-one", hashlib.sha256).hexdigest()))
person_code.configure(kdir)
ok("the same key after a restart (read back from the file), so the same code", person_code.code("lgsnq-one") == a)
ok("a code turns back into its account only among the accounts offered",
   person_code.user_of(a, ["lgsnq-two", "lgsnq-one"]) == "lgsnq-one" and person_code.user_of(a, ["lgsnq-two"]) is None
   and person_code.user_of("lgsnq-one", ["lgsnq-one"]) is None and person_code.user_of("", ["x"]) is None)
k2 = tempfile.mkdtemp(prefix="lg-person-code-")
person_code.configure(k2)
ok("another installation (another key) gives another code", person_code.code("lgsnq-one") != a)
k3 = tempfile.mkdtemp(prefix="lg-person-code-")
got = []


def _start():
    person_code.configure(k3)                  # each "worker" reads the key itself
    got.append(open(os.path.join(k3, person_code.KEY_FILE), "rb").read() if person_code.code("x") else b"")


ts = [threading.Thread(target=_start) for _ in range(8)]
[t.start() for t in ts]; [t.join() for t in ts]  # noqa: E702
ok("workers starting together agree on one whole key", len(set(got)) == 1 and len(got[0]) == 32
   and not [n for n in os.listdir(k3) if n.endswith(".tmp")], [len(x) for x in got])
open(os.path.join(k2, person_code.KEY_FILE), "wb").close()
person_code.configure(k2)
try:
    person_code.code("x"); weak = True       # noqa: E702
except RuntimeError:
    weak = False
ok("an empty key file is refused, never used as a weak key", not weak)
ENV_DIR = os.environ.get("LG_PERSON_CODE_DIR")
os.environ["LG_PERSON_CODE_DIR"] = k2
dmg = person_code.bell("/nonexistent", 1.0)
ok("…and the administrators' bell says the key is damaged and what to do", any(x["key"] == "person-code-damaged"
   and "remove that file" in x["text"] for x in dmg), dmg)

print("   a new key where one had been: the audit log and the bell")
k4 = tempfile.mkdtemp(prefix="lg-person-code-")
heard = []
person_code.on_new = lambda at: heard.append(at)
person_code.configure(k4)
person_code.code("x")
os.environ["LG_PERSON_CODE_DIR"] = k4
ok("the first key on an installation is silent (the update that brings it)", not heard and not person_code.bell("/x", 1.0)
   and os.path.exists(os.path.join(k4, person_code.MADE_FILE)))
first_code = person_code.code("lgsnq-one")
os.remove(os.path.join(k4, person_code.KEY_FILE))
person_code.configure(k4)
second = person_code.code("lgsnq-one")
alerts = person_code.bell("/x", 2.0)
ok("the key removed: a new one is made, the codes change", second != first_code)
ok("…the audit hook is told once", len(heard) == 1, heard)
ok("…and the administrators' bell says a new key was made, that nobody can do it from the website, and where to look",
   len(alerts) == 1 and alerts[0]["key"].startswith("person-code-new:") and "Nobody can do this from the website" in alerts[0]["text"]
   and alerts[0]["link"] == "/audit", alerts)
person_code.configure(k4)
person_code.code("y")
ok("reading the key again (a restart) is not a new key", len(heard) == 1)
k5 = tempfile.mkdtemp(prefix="lg-person-code-")
with open(os.path.join(k5, person_code.KEY_FILE), "wb") as fh:
    fh.write(os.urandom(32))
person_code.configure(k5)
person_code.code("x")
ok("a key from before the record existed is adopted silently (and recorded)", len(heard) == 1
   and os.path.exists(os.path.join(k5, person_code.MADE_FILE)))
import features  # noqa: E402
src_f = open(features.__file__, encoding="utf-8").read()
ok("the app sends a new key to the audit log (person_code_key_new)", "person_code.on_new = _code_key_new" in src_f
   and '"person_code_key_new"' in src_f)
import system_alerts  # noqa: E402
ok("the bell asks person_code for its alerts", "person_code.bell(self.base_dir, now)" in open(system_alerts.__file__, encoding="utf-8").read())
person_code.on_new = None
if ENV_DIR is None:
    os.environ.pop("LG_PERSON_CODE_DIR", None)
else:
    os.environ["LG_PERSON_CODE_DIR"] = ENV_DIR
person_code.configure(kdir)

print("2. The pages and answers, per role")
tmp = tempfile.mkdtemp(prefix="lg-no-signin-names-")
AU = A.AUTH
users, sessions, throttle, audit, roles = AU["users"], AU["sessions"], AU["throttle"], AU["audit"], AU["roles"]
audit.add = lambda ev, **k: None
sessions.path, throttle.path, roles.path = (os.path.join(tmp, n) for n in ("sessions.json", "login_counters.json", "roles.json"))
AU["setup"].path = os.path.join(tmp, "setup_code")
sessions.s.clear(); throttle.fail.clear()
ROLES = sorted((set(auth.DEFAULT_ROLES) | set(auth.FIXED_ROLES)) - {"admin"})
H = generate_password_hash("Steady-Harbour-Lantern-63!")
TAG = "lgsnq"                                  # every sign-in name below holds it; no other text does
ACC = {}
for i, role in enumerate(ROLES):
    for j in ("a", "b"):                       # the viewer and a colleague in the same role
        ACC[f"{TAG}{i}{j}"] = {"hash": H, "role": role, "status": "active", "totp": base64.b32encode(os.urandom(20)).decode().rstrip("="),
                               "changed": 0, "created": 1, "pw_set_at": int(time.time()),
                               "profile": {"full_name": f"Person {chr(65 + i)}{j.upper()}"}}
with open(os.path.join(tmp, "users.json"), "w") as fh:
    json.dump({"users": ACC}, fh)
users.path, users.mtime = os.path.join(tmp, "users.json"), None
UA = "lg-check-no-signin-names"
CL = {}
for i, role in enumerate(ROLES):
    name = f"{TAG}{i}a"
    tok = sessions.create(name, "127.0.0.1", UA)
    c = A.app.test_client(); c.set_cookie("lg_session", tok)
    CL[role] = (c, name)

tmp_real, real_open, refused = os.path.realpath(tmp), builtins.open, []


def guarded_open(file, mode="r", *a, **k):
    # a write outside the temporary folder goes nowhere (os.devnull), so pages that keep a little state as they are
    # shown (the first-visit greeting, the geocoder's cache) still answer, and nothing is written
    if any(ch in str(mode) for ch in "wax+") and isinstance(file, (str, bytes, os.PathLike)):
        p = os.path.realpath(os.fsdecode(file))
        if not p.startswith(tmp_real + os.sep):
            refused.append("write")
            return real_open(os.devnull, "w" if "b" not in str(mode) else "wb")
    return real_open(file, mode, *a, **k)


def refuse(what):
    def f(*a, **k):
        refused.append(what)
        raise PermissionError("check_no_signin_names: " + what)
    return f


builtins.open = guarded_open
real_fdopen = os.fdopen
for fn in ("rename", "remove", "unlink", "rmdir", "mkdir", "chmod"):
    setattr(os, fn, refuse("os." + fn))
# moving a written file into place: a no-op outside the temporary folder (the file went to os.devnull)
os.replace = lambda src, dst, *a, **k: refused.append("os.replace")
os.open = (lambda real: lambda p, flags, *a, **k: real(os.devnull, os.O_WRONLY) if (flags & (os.O_WRONLY | os.O_RDWR))
           and not os.path.realpath(os.fsdecode(p)).startswith(tmp_real + os.sep) else real(p, flags, *a, **k))(os.open)
os.makedirs = lambda p, *a, **k: None if os.path.isdir(p) else refuse("os.makedirs")()
shutil.rmtree, shutil.move, shutil.copy, shutil.copy2, shutil.copyfile = (refuse("shutil") for _ in range(5))
subprocess.Popen = refuse("a new process")
real_connect = socket.socket.connect


def local_only(self, addr, *a, **k):
    host = addr[0] if isinstance(addr, tuple) else addr
    if isinstance(host, str) and (host.startswith("127.") or host in ("::1", "localhost") or host.startswith("/")):
        return real_connect(self, addr, *a, **k)
    refused.append("a connection to another computer")
    raise PermissionError("check_no_signin_names: no outside connections")


socket.socket.connect = local_only
try:
    import pymongo.collection as PC
    for m in ("insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many",
              "bulk_write", "drop", "create_index", "find_one_and_update", "find_one_and_delete", "find_one_and_replace"):
        setattr(PC.Collection, m, refuse("a database write"))
except ImportError:
    pass

OWN = ("/account", "/api/account", "/api/me")  # the person's own account (page, and "who am I" for scripts)
AUDIT = ("/audit", "/api/audit", "/api/admin/sessions")   # the audit trail names accounts by sign-in name, for the auditor
NAME_RX = re.compile(TAG + r"\d+[ab]")
rules = sorted(A.app.url_map.iter_rules(), key=lambda r: r.rule)
paths = sorted({re.sub(r"<(?:[^:>]+:)?[^>]+>", "1", r.rule) for r in rules if "GET" in (r.methods or ())
                and not r.rule.startswith("/static/") and not r.rule.startswith(("/logout",))})
t0, hits, seen, errors, broken = time.time(), [], 0, [], set()
for role, (c, me) in CL.items():
    for path in paths:
        try:
            r = c.get(path, headers={"User-Agent": UA})
        except Exception as e:                  # noqa: BLE001 (a refused write, no database)
            errors.append(f"{role} {path}: {type(e).__name__}")
            continue
        if r.status_code >= 500:
            broken.add(path)
        if r.status_code in (401, 403) or r.status_code >= 500:
            continue
        seen += 1
        body = r.get_data(as_text=True) if r.mimetype and (r.mimetype.startswith("text/") or "json" in r.mimetype
                                                           or "javascript" in r.mimetype) else ""
        names = set(NAME_RX.findall(body))
        if path.startswith(OWN):
            names.discard(me)
        if role == getattr(auth, "AUDITOR_ROLE", "auditor") and path.startswith(AUDIT):
            names = set()
        if names:
            hits.append(f"{role} GET {path}: {sorted(names)} ({'own' if me in names else 'a colleague'})")
# answers that name colleagues: whom a finding can go to (every kind), and a colleague's note (temporary notes file)
notes_file = os.path.join(tmp, "notes.json")
with real_open(notes_file, "w", encoding="utf-8") as fh:
    json.dump({"infections": {"lg-check-family": [{"id": "abc123abc123", "text": "A colleague's note.", "user": f"{TAG}0b",
                                                    "role": "researcher", "name": "Person AB", "at": 1.0, "date": "2026-11-25"}]}}, fh)
A.NOTES.path, A.NOTES.mtime = notes_file, None
extra = [f"/api/findings/people?kind={k}" for k in ("management", "researcher", "analyst", "advisor")] + \
        ["/api/notes?section=infections&name=lg-check-family"]
got_note = got_people = False
for role, (c, me) in CL.items():
    for path in extra:
        r = c.get(path, headers={"User-Agent": UA})
        if r.status_code != 200:
            continue
        seen += 1
        got_note = got_note or "A colleague's note." in r.get_data(as_text=True)
        got_people = got_people or (path.startswith("/api/findings/people") and bool((r.get_json(silent=True) or {}).get("people")))
        names = set(NAME_RX.findall(r.get_data(as_text=True)))
        if names:
            hits.append(f"{role} GET {path}: {sorted(names)}")
print(f"   {seen} answers read in {time.time() - t0:.0f}s ({len(paths)} GET routes x {len(CL)} roles; errors past the check: {len(errors)})")
ok("no page or answer holds the viewer's or a colleague's sign-in name (own Account page and the auditor's audit trail aside)",
   not hits, "\n    " + "\n    ".join(hits[:40]))
ok("the walk read pages for every role", seen >= len(CL) * 5, seen)
ok("…including a colleague's note and the people a finding can go to (so those checks are not empty)", got_note and got_people,
   (got_note, got_people))
print(f"   not read (an error without the reports database or a refused write): {sorted(broken)}")

print("3. The page sources")
tdir = os.path.join(os.path.dirname(HERE), "templates")
names = sorted(set(os.listdir(tdir)) | ({n[:-4] for n in os.listdir(HELD) if n.endswith(".html.new")} if HELD else set()))
uses = []
for n in names:
    if not n.endswith(".html") or n == "admin.html":      # admin: account management, by sign-in name
        continue
    p = os.path.join(HELD, n + ".new") if HELD and os.path.exists(os.path.join(HELD, n + ".new")) else os.path.join(tdir, n)
    if os.path.exists(p) and "lg_user" in real_open(p, encoding="utf-8").read():
        uses.append(n)
ok("no page template prints lg_user (pages use lg_me, the code, or lg_name, the full name)", not uses, uses)

print(f"\n{checks - len(fails)} of {checks} sign-in name checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.stdout.flush(); sys.stderr.flush()
os._exit(1 if fails else 0)
