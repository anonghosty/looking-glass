#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Review of the sign-in and audit code (2026-11-28), in-process on made-up accounts and temporary folders only: the
installation's accounts, sessions, sign-in counters and audit log are never read or written (each store of the app is
pointed at a temporary folder for the checks and put back after; the other routes run on small apps of their own).
 r4-1 a typed name that is no account (often a password) is never kept: not in the counters file, not in the Admin's
      list of locked sign-ins, not in the audit entry of an unlock; 5 wrong tries still lock it; real accounts as before
 r4-2 a written-out date inside a host name does not let the rest of the name escape the host rule
 r4-3 a damaged people-codes key: people are named "an account" (never the sign-in name), the bell keeps working
 r4-4 a JSON body that is a list or a number is never an error 500 (one shared helper, reqjson.body)
 r4-5 Settings > Code check records who decided by full name or person code, never the sign-in name
 r4-6 a CSRF token (or authenticator code, or automation key) that is not ASCII is refused, never an error 500
 r4-7 the live sessions name accounts by sign-in name only to accounts with the 'users' permission
 r4-8 a host reference is read under the lock that writes it (an eviction in between was a KeyError)
LG_R4_ROOT may name another copy of the platform (the old code, to show these checks fail there).
Run: .venv/bin/python tests/check_fix_r4.py"""
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import types
from pathlib import Path

ROOT = os.environ.get("LG_R4_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.setdefault("ACCESS_MODE", "private")
os.environ["LG_STEPUP_TESTS_OFF"] = "1"

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info and not cond else ""), flush=True)


def safely(fn):
    """(result, error text): an exception is a finding, never the end of the check."""
    try:
        return fn(), ""
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


TMP = tempfile.mkdtemp(prefix="lg-fix-r4-")
SECRET = "Quiet-Orchard-Kettle-R4!"            # a password typed into the name box
IP = "127.0.0.1"

from flask import Flask, g  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

import auth  # noqa: E402

# ------------------------------------------------------------------ r4-1, the throttle itself
print("r4-1: the sign-in counters never keep a typed name that is no account")
cp = os.path.join(TMP, "counters.json")
T, err = safely(lambda: auth.Throttle(cp, known=lambda n: n.lower() == "r4-real"))
ok("the throttle is told which names are accounts", T is not None, err)
if T is not None:
    for _ in range(5):
        T.failed("10.9.0.1", SECRET)
    ok("5 wrong tries with an unknown name still lock it", T.locked("10.9.0.1", SECRET) and T.left("10.9.0.1", SECRET) == 0)
    text = open(cp, encoding="utf-8").read()
    ok("…the counters file holds neither the value nor its lower case", SECRET not in text and SECRET.lower() not in text, text[:200])
    L = T.lockouts()
    row = next((x for x in L if x["kind"] == "account" and x["ip"] == "10.9.0.1"), {})
    ok("the locked list names it 'an unknown name', with a key '?' + 12 hex", row.get("name") == "an unknown name"
       and re.fullmatch(r"\?[0-9a-f]{12}", row.get("key", "")) and SECRET.lower() not in json.dumps(L).lower(), str(L))
    ok("…unlock takes that key", T.unlock("10.9.0.1", row.get("key")) == 1 and not T.locked("10.9.0.1", SECRET))
    for _ in range(5):
        T.failed("10.9.0.2", "R4-Real")
    L = T.lockouts()
    ok("a real account is listed by its name, as before", any(x["name"] == "r4-real" and x["ip"] == "10.9.0.2" for x in L), str(L))
    ok("…and unlocked by its name", T.unlock("10.9.0.2", "r4-real") == 1 and not T.locked("10.9.0.2", "R4-Real"))
    p2 = os.path.join(TMP, "old-counters.json")
    with open(p2, "w", encoding="utf-8") as f:
        json.dump({"fail": [["10.9.0.3", SECRET.lower(), [time.time()] * 3], ["10.9.0.3", None, [time.time()] * 3]]}, f)
    T2, err = safely(lambda: auth.Throttle(p2, known=lambda n: n.lower() == "r4-real"))
    before = open(p2, encoding="utf-8").read()
    ok("…reading them back (a check that only imports the app) never writes the file", T2 is not None
       and open(p2, encoding="utf-8").read() == before, err)
    if T2 is not None:
        T2.locked("10.9.0.9", "r4-real")
    ok("counters an older version kept as typed are read back under the key, the file rewritten without the value at the next sign-in",
       T2 is not None and SECRET.lower() not in open(p2, encoding="utf-8").read(), err)
    if T2 is not None:
        T2.failed("10.9.0.3", SECRET); T2.failed("10.9.0.3", SECRET)
        ok("…and still count: 3 kept + 2 new lock it", T2.locked("10.9.0.3", SECRET))
T0 = auth.Throttle()
T0.failed("10.9.0.4", "Bob")
ok("without the accounts (scripts, checks) a name is counted as typed, lower-cased, as before", ("10.9.0.4", "bob") in T0.fail)

# ------------------------------------------------------------------ r4-2
print("r4-2: dates inside host names")
import hostmask  # noqa: E402
for host in ("srv-1-jan-2024.corp.example.gh", "mail-27-nov-2026.example.org", "db.27-Nov-2026.example.net"):
    m = hostmask.mask(host)
    ok(f"{host} -> <host>", m == "<host>", m)
for text, want in (("valid until 27 Nov 2026", "valid until <date>"), ("issued Nov 27, 2026; renewed", "issued <date>; renewed"),
                   ("Not After : Nov 27 10:22:31 2026 GMT", "Not After : <date>"), ("on 3rd March 2025.", "on <date>."),
                   ("27-Nov-2026 backup", "<date> backup"), ("seen 1 jan 2024, again", "seen <date>, again"),
                   ("valid 1 Jan 2024-2 Feb 2025", "valid <date>-<date>"), ("from 27 Nov 2026/28 Nov 2026", "from <date>/<date>"),
                   ("Nov 1, 2024-Dec 2, 2025 only", "<date>-<date> only")):
    m = hostmask.mask(text)
    ok(f"a real date still masks: {text!r}", m == want, m)

# ------------------------------------------------------------------ r4-3
print("r4-3: a damaged people-codes key")
import people  # noqa: E402
import person_code  # noqa: E402
import system_alerts  # noqa: E402
keep_dir = person_code._state["dir"]
bad = os.path.join(TMP, "badkey")
os.makedirs(bad)
with open(os.path.join(bad, person_code.KEY_FILE), "wb") as f:
    f.write(b"short")
person_code.configure(bad)
try:
    v, err = safely(lambda: people.person_label("r4-person"))
    ok("person_label: 'an account', no error", v == "an account", err or str(v))
    v, err = safely(lambda: system_alerts._who("r4-person", {}))
    ok("the bell's alerts name the person 'an account', no error", v == "an account", err or str(v))
    v, err = safely(lambda: people.signed_by("r4-person"))
    ok("…and never by the sign-in name", not err and "r4-person" not in str(v), err or str(v))
    Tk, err = safely(lambda: auth.Throttle(os.path.join(TMP, "c3.json"), known=lambda n: False))
    if Tk is not None:
        _, err = safely(lambda: [Tk.failed("10.9.0.5", SECRET) for _ in range(5)])
        ok("the sign-in counters still work (a key of their own), never keeping the value",
           not err and Tk.locked("10.9.0.5", SECRET) and SECRET not in open(os.path.join(TMP, "c3.json")).read(), err)
    else:
        ok("the sign-in counters still work (a key of their own), never keeping the value", False, err)
    v, err = safely(lambda: __import__("insider").stamp_who("r4-person", ""))
    ok("a download's stamp: 'an account', no error", v == "an account", err or str(v))
    v, err = safely(lambda: __import__("passkeys").user_handle("r4-person"))
    ok("a new passkey's handle: made, without the sign-in name", isinstance(v, bytes) and b"r4-person" not in v, err or str(v))
finally:
    person_code.configure(keep_dir)

print("r4-3b: a person code from the request that is not ASCII")
v, err = safely(lambda: person_code.user_of("p-\u00e9", ["r4-a", "r4-b"]))
ok("user_of('p-é'): no account, no error", v is None and not err, err or str(v))
pc_a = person_code.code("r4-a")
ok("…a real code still finds its account", person_code.user_of(pc_a, ["r4-b", "r4-a"]) == "r4-a")

print("r4-4b: the shared helper itself")
reqjson, err = safely(lambda: __import__("reqjson"))        # the old code has none: these fail there
ok("the shared helper exists (reqjson.py)", reqjson is not None, err)
_hf = Flask("r4-helper")
for raw, ctype in (("[1]", "application/json"), ("5", "application/json"), ('"x"', "application/json"),
                   ("[1]", "application/merge-patch+json"), ('{"a": 1}', "application/json")):
    with _hf.test_request_context("/", method="POST", data=raw, content_type=ctype):
        want = {"a": 1} if raw.startswith("{") else {}
        ok(f"reqjson.body() for {raw} as {ctype}: {want}", reqjson is not None and reqjson.body() == want)


# ------------------------------------------------------------------ small apps for the routes of r4-4 and r4-5
class Audit:
    def __init__(self):
        self.rows = []

    def add(self, event, user="", target="", detail="", **_k):
        self.rows.append((event, user, target, detail))


PW = "Amber-Lighthouse-Seventy-4!"
HASH = generate_password_hash(PW)
ME = "r4-signin"


def small_app():
    a = Flask("r4")
    a.config["TESTING"] = True

    @a.before_request
    def _who():
        g.user = {"user": ME, "csrf": "tok", "role": "admin", "perms": set(auth.PERMS)}
    return a


def base_ctx(audit, base):
    os.makedirs(os.path.join(base, "data"), exist_ok=True)
    return {"base_dir": base, "data_dir": os.path.join(base, "data"), "has_perm": lambda p: True,
            "csrf_ok": lambda: True, "fresh": lambda: True, "audit": audit, "serving": False,
            "users": types.SimpleNamespace(get=lambda n: {"hash": HASH} if n == ME else None, all=lambda: {}),
            "throttle": auth.Throttle(), "client": lambda: (IP, "lg-check-fix-r4"), "people_name": lambda u: ""}


def status(c, path, body):
    r, err = safely(lambda: c.post(path, data=json.dumps(body), content_type="application/json"))
    return r.status_code if r is not None else f"error {err}"


print("r4-4: a JSON body that is not an object")
import password_policy as PP  # noqa: E402
aud = Audit()
app4 = small_app()
ctx = base_ctx(aud, os.path.join(TMP, "pp"))
ctx["policy"] = PP.Policy(ctx["data_dir"])
PP.install(app4, ctx)
c = app4.test_client()
for body in ([1], 5, "x"):
    s = status(c, "/api/password-policy", body)
    ok(f"password policy, body {body!r}: refused, not 500", isinstance(s, int) and 400 <= s < 500, str(s))

import pipeline_settings as PS  # noqa: E402
import pipeline_link  # noqa: E402
pipe = Path(TMP) / "pipe"
pipe.mkdir()
(pipe / ".env").write_text("MAIL_PROVIDER=imap\n")


class FakeWS:
    SPEC = {}

    @staticmethod
    def validate(values, provider):
        return ({}, []) if isinstance(values, dict) else ({}, ["values: send the settings"])

    @staticmethod
    def valid_api(key, secret):
        return bool(key and secret)

    @staticmethod
    def pending(d):
        return []


keep_pl = (pipeline_link.find_dir, pipeline_link.worker_settings, pipeline_link.mail_auth)
pipeline_link.find_dir = lambda base: pipe
pipeline_link.worker_settings = lambda d: FakeWS
pipeline_link.mail_auth = lambda d: None
try:
    app4 = small_app()
    PS.install(app4, base_ctx(aud, os.path.join(TMP, "ps")))
    c = app4.test_client()
    s = status(c, "/api/pipeline/unlock", {"password": PW})
    ok("Settings > Workers unlocked with the password (to reach the routes)", s == 200, str(s))
    for path in ("/api/pipeline/settings", "/api/pipeline/apikey", "/api/pipeline/release"):
        for body in ([1], 7):
            s = status(c, path, body)
            ok(f"{path}, body {body!r}: refused, not 500", isinstance(s, int) and 400 <= s < 500, str(s))
finally:
    pipeline_link.find_dir, pipeline_link.worker_settings, pipeline_link.mail_auth = keep_pl

import insider  # noqa: E402
app4 = small_app()
insider.install(app4, base_ctx(aud, os.path.join(TMP, "ins")))
c = app4.test_client()
for path in ("/api/copy/record", "/api/audit/trace"):
    s = status(c, path, [1])
    ok(f"{path}, body [1]: refused, not 500", isinstance(s, int) and 400 <= s < 500, str(s))

import notifications  # noqa: E402
app4 = small_app()
nctx = base_ctx(aud, os.path.join(TMP, "notes"))
nctx.update(findings=types.SimpleNamespace(lock=threading.Lock(), _load=lambda: None, data={"items": {}}), labels=lambda s: s)
notifications.install(app4, nctx)
s = status(app4.test_client(), "/api/notifications/clear", [1])
ok("/api/notifications/clear, body [1]: answered, not 500", isinstance(s, int) and s < 500, str(s))

import code_integrity as CI  # noqa: E402
cbase = os.path.join(TMP, "ci")
FIND = {"key": "platform/tools/r4.py", "sha256": "ab" * 32, "kind": "unknown", "part": "platform", "rel": "tools/r4.py"}
keep_ci = (CI.check, CI.folders, CI.quarantine_command)
CI.check = lambda base, audit, now=None: {"checked": True, "at": time.time(), "findings": [dict(FIND)]}
CI.folders = lambda base: [("platform", base)]
CI.quarantine_command = lambda base, part, folder, rel: "verify_install.py --quarantine tools/r4.py"
try:
    app4 = small_app()
    aud5 = Audit()
    CI.install(app4, base_ctx(aud5, cbase))
    c = app4.test_client()
    for path in ("/api/admin/code-check/approve", "/api/admin/code-check/quarantine"):
        s = status(c, path, [1])
        ok(f"{path}, body [1]: refused, not 500", isinstance(s, int) and 400 <= s < 500, str(s))

    print("r4-5: who decided, on Settings > Code check")
    s = status(c, "/api/admin/code-check/quarantine", {"key": FIND["key"], "sha256": FIND["sha256"], "password": PW})
    dec = ((CI.state(cbase).get("decided") or {}).get(FIND["key"]) or {})
    code = people.person_label(ME)
    ok("'not ours' is recorded by the person code, not the sign-in name", s == 200 and dec.get("by") == code and ME not in json.dumps(dec),
       f"{s} {dec}")
    s = status(c, "/api/admin/code-check/approve", {"key": FIND["key"], "sha256": FIND["sha256"], "password": PW})
    ap = [x for x in aud5.rows if x[0] == "code_integrity_approved"]
    ok("'ours, keep it': the audit entry's words name the person code (who is in its user field)",
       s == 200 and ap and f"by {code}" in ap[-1][3] and ME not in ap[-1][3], f"{s} {ap}")
finally:
    CI.check, CI.folders, CI.quarantine_command = keep_ci

src = {n: open(os.path.join(ROOT, n), encoding="utf-8").read() for n in
       ("password_policy.py", "pipeline_settings.py", "insider.py", "notifications.py", "code_integrity.py", "lockouts.py")}
left = [n for n, t in src.items() if re.search(r"get_json\(silent=True\)\s*or\s*\{\}", t)]
ok("no route of these files reads `get_json(silent=True) or {}` any more (one helper)", not left, str(left))

# ------------------------------------------------------------------ r4-8
print("r4-8: host references read under the lock")
import privacy  # noqa: E402
refs = privacy.HostRefs("r4-secret")
seen_locked = []


class Evicting(dict):
    """A table whose entry another thread evicts right after "in" said it is there."""

    def __contains__(self, k):
        hit = dict.__contains__(self, k)
        if hit:
            dict.pop(self, k, None)
        return hit

    def get(self, k, default=None):
        seen_locked.append(refs._lock.locked())
        return dict.get(self, k, default)


refs.to_ip = Evicting()
r = refs.ref("192.0.2.10")
v, err = safely(lambda: refs.resolve(r))
ok("an entry evicted in between: no KeyError", not err, err)
ok("…the table is read while the lock is held", seen_locked and all(seen_locked), str(seen_locked))
refs.to_ip = {}
r = refs.ref("192.0.2.11")
ok("a reference still resolves, also as a copied 'Host' label", refs.resolve(r) == "192.0.2.11" and refs.resolve("Host " + r) == "192.0.2.11")
ok("an unknown value comes back as it is (not strict)", refs.resolve("198.51.100.1") == "198.51.100.1")

# ------------------------------------------------------------------ r4-6 (unit)
print("r4-6: tokens that are not ASCII")
secret = auth.totp_new_secret()
v, err = safely(lambda: auth.totp_check(secret, "١٢٣٤٥٦"))
ok("an authenticator code in another script's digits: not accepted, no error", v is None and not err, err or str(v))

# ------------------------------------------------------------------ r4-1, r4-4, r4-6, r4-7 on the platform itself
print("r4-1 / r4-6 / r4-7: the platform's own routes")
import app as A  # noqa: E402
AU = A.AUTH
users, sessions, throttle, audit = AU["users"], AU["sessions"], AU["throttle"], AU["audit"]
saved = dict(users=(users.path, users.mtime, users.data), sessions=(sessions.path, dict(sessions.s)),
             throttle=(throttle.path, dict(throttle.fail)), add=audit.add)
tokens = []
try:
    H = generate_password_hash(PW)
    TOTP = __import__("base64").b32encode(os.urandom(10)).decode()     # a throwaway authenticator key, made per run
    acc = lambda role, full: {"hash": H, "role": role, "status": "active", "totp": TOTP, "changed": 0, "created": 1,  # noqa: E731
                              "pw_set_at": int(time.time()), "profile": {"full_name": full}}
    with open(os.path.join(TMP, "users.json"), "w") as f:
        json.dump({"users": {"r4-admin": acc("admin", "R4 Admin"), "r4-known": acc("analyst", "R4 Known"),
                             "r4-auditor": acc(auth.AUDITOR_ROLE, "R4 Auditor")}}, f)
    users.path, users.mtime = os.path.join(TMP, "users.json"), None
    sessions.path, throttle.path = os.path.join(TMP, "sessions.json"), os.path.join(TMP, "login_counters.json")
    sessions.s.clear(); throttle.fail.clear()
    logged = []
    audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("target", ""), k.get("detail", "")))
    HD = {"User-Agent": "lg-check-fix-r4"}

    def client(user):
        tok = sessions.create(user, IP, HD["User-Agent"]); tokens.append(tok)
        csrf = max((s for s in sessions.s.values() if s["user"] == user and s.get("csrf")), key=lambda s: s["created"])["csrf"]
        cl = A.app.test_client(); cl.set_cookie("lg_session", tok)
        return cl, dict(HD, **{"X-CSRF-Token": csrf}), tok

    ca, HA, tok_a = client("r4-admin")
    codes = [A.app.test_client().post("/login", data={"username": SECRET, "password": "x"}, headers=HD).status_code for _ in range(6)]
    ok("signing in with a password in the name box: 5 refusals, then locked", codes == [401] * 5 + [429], str(codes))
    text = open(throttle.path, encoding="utf-8").read() if os.path.exists(throttle.path) else ""
    ok("…the counters file (data/login_counters.json) never holds the value", text and SECRET.lower() not in text.lower(), text[:300])
    r = ca.get("/api/admin/lockouts", headers=HA)
    rows = [x for x in (r.json or {}).get("locked", []) if x["kind"] == "account" and x["ip"] == IP]
    ok("the Admin's locked sign-ins: listed, as 'an unknown name', never the value", r.status_code == 200 and rows
       and rows[0]["name"] == "an unknown name" and SECRET.lower() not in r.get_data(as_text=True).lower(), r.get_data(as_text=True)[:300])
    logged.clear()
    key = (rows[0].get("key") or rows[0]["name"]) if rows else ""
    r = ca.post("/api/admin/lockouts/unlock", json={"ip": IP, "name": key}, headers=HA)
    un = [x for x in logged if x[0] == "login_unlocked"]
    ok("unlocking it by its key: lifted", r.status_code == 200 and (r.json or {}).get("cleared") == 1
       and not throttle.locked(IP, SECRET), f"{r.status_code} {r.get_data(as_text=True)[:200]}")
    ok("…the audit entry says 'an unknown name', never the value", un and all(SECRET.lower() not in json.dumps(x).lower() for x in un)
       and "an unknown name" in un[-1][3], str(un))
    for _ in range(5):
        throttle.failed(IP, SECRET)
    logged.clear()
    r = ca.post("/api/admin/lockouts/unlock", json={"ip": IP, "name": SECRET}, headers=HA)
    un = [x for x in logged if x[0] == "login_unlocked"]
    ok("an admin typing the value to unlock it: lifted, and the audit entry still never holds it",
       r.status_code == 200 and not throttle.locked(IP, SECRET) and un and all(SECRET.lower() not in json.dumps(x).lower() for x in un), str(un))
    throttle.fail.clear()
    codes = [A.app.test_client().post("/login", data={"username": "r4-known", "password": "wrong"}, headers=HD).status_code for _ in range(6)]
    r = ca.get("/api/admin/lockouts", headers=HA)
    ok("a real account: locked after 5 wrong passwords and listed by its name, as before", codes[-1] == 429
       and any(x["name"] == "r4-known" for x in (r.json or {}).get("locked", [])), f"{codes} {r.get_data(as_text=True)[:200]}")
    logged.clear()
    r = ca.post("/api/admin/lockouts/unlock", json={"ip": IP, "name": "r4-known"}, headers=HA)
    un = [x for x in logged if x[0] == "login_unlocked"]
    ok("…unlocked by its name, the audit entry names the account", r.status_code == 200 and not throttle.locked(IP, "r4-known")
       and un and un[-1][2] == "r4-known" and f"account r4-known from {IP}" in un[-1][3], str(un))
    throttle.fail.clear()

    print("r4-4 on the platform: the global guard, for every JSON type")
    for path in ("/api/peace", "/api/notes/delete", "/api/admin/lockouts/unlock"):
        r = ca.post(path, data="[1]", content_type="application/merge-patch+json", headers=HA)
        ok(f"{path}, body [1] as application/merge-patch+json: 400, not 500", r.status_code == 400, str(r.status_code))
    import lockouts  # noqa: E402   (the route itself, without the platform's guard in front)
    _la = Flask("r4-lockouts")

    @_la.before_request
    def _la_who():
        g.user = {"user": "r4-admin"}
    lockouts.install(_la, {"throttle": auth.Throttle(), "audit": Audit(), "has_perm": lambda p: True, "csrf_ok": lambda: True,
                           "fresh": lambda: True})
    r = _la.test_client().post("/api/admin/lockouts/unlock", data="[1]", content_type="application/json")
    ok("the unlock route alone, body [1]: 400, not 500", r.status_code == 400, str(r.status_code))

    print("r4-5b: a failed sign-in never sends a typed name that is no account back into the page")
    r = A.app.test_client().post("/login", data={"username": SECRET, "password": "x"}, headers=HD)
    ok("an unknown name (a password in the name box): not in the page", r.status_code in (401, 429)
       and SECRET not in r.get_data(as_text=True), str(r.status_code))
    throttle.fail.clear()
    r = A.app.test_client().post("/login", data={"username": "r4-known", "password": "wrong"}, headers=HD)
    ok("…an account's name is filled in again, as before", r.status_code == 401 and 'value="r4-known"' in r.get_data(as_text=True),
       str(r.status_code))
    throttle.fail.clear()

    print("r4-3c: a damaged people-codes key, signed in")
    keep_dir2 = person_code._state["dir"]
    person_code.configure(bad)
    try:
        r, err = safely(lambda: ca.get("/admin", headers=HA))
        ok("a page still opens for a signed-in person (200)", r is not None and r.status_code == 200, err or (r and str(r.status_code)))
        r, err = safely(lambda: ca.get("/api/findings/people?kind=analyst", headers=HA))
        ok("whom a finding can go to: answered, not 500, no sign-in name", r is not None and r.status_code < 500
           and "r4-known" not in r.get_data(as_text=True), err or (r and f"{r.status_code} {r.get_data(as_text=True)[:200]}"))
    finally:
        person_code.configure(keep_dir2)

    print("r4-6 on the platform")
    r = ca.post("/api/admin/lockouts/unlock", json={"ip": IP}, headers=dict(HD, **{"X-CSRF-Token": "é"}))
    ok("a CSRF token 'é': refused (403), not 500", r.status_code == 403, str(r.status_code))
    cl, _h, tok_l = client("r4-known")
    r = cl.post("/logout", data={"csrf_token": "é"}, headers=HD)
    ok("sign-out with a token 'é': refused, the session kept, not 500", r.status_code in (301, 302, 303)
       and r.headers.get("Location", "").rstrip("/") in ("", "http://localhost") and sessions.s.get(auth._h(tok_l)) is not None,
       f"{r.status_code} {r.headers.get('Location')}")
    r = A.app.test_client().get("/api/me", headers=dict(HD, **{"X-LG-Automation": "é"}))
    ok("an automation key 'é': not let in, not 500", r.status_code in (302, 401, 403), str(r.status_code))

    print("r4-7: live sessions")
    cu, HU, _t = client("r4-auditor")
    r = cu.get("/api/admin/sessions", headers=HU)
    ss = (r.json or {}).get("sessions") or []
    body = r.get_data(as_text=True)
    ok("an account with only 'audit': the sessions without the sign-in name", r.status_code == 200 and ss
       and all("user" not in s for s in ss) and not any(n in body for n in ("r4-admin", "r4-known", "r4-auditor")), body[:300])
    ok("…still with what the Audit portal shows (user_label, person_code)", ss and all(s.get("user_label") and s.get("person_code") for s in ss))
    r = ca.get("/api/admin/sessions", headers=HA)
    ok("an administrator ('users'): the sign-in name is there for the Admin page", r.status_code == 200
       and any(s.get("user") == "r4-admin" for s in (r.json or {}).get("sessions") or []))
finally:
    audit.add = saved["add"]
    for t in tokens:
        try:
            sessions.end(t)
        except Exception:  # noqa: BLE001
            pass
    users.path, users.mtime, users.data = saved["users"]
    sessions.path = saved["sessions"][0]; sessions.s.clear(); sessions.s.update(saved["sessions"][1])
    throttle.path = saved["throttle"][0]; throttle.fail.clear(); throttle.fail.update(saved["throttle"][1])
    shutil.rmtree(TMP, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
