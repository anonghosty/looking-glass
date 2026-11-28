#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Whole-codebase audit 2026-11-27, batch 02 (attack_map, audit_chain, audit_checkpoint, audit_portal, audit_proof,
audit_report, audit_verifier, auth, beacon_decode), in-process on made-up accounts and temporary folders only: the
installation's accounts, sessions, counters, seals and audit log are never read or written (each store is pointed at a
temporary folder for the checks and put back after).
 2-1  the proof package an auditor (not the self-test) downloads still verifies with its own verifier; stamped, it would not
 2-2  a name typed at sign-in that is no account (often a password) is never written to the audit log; the lock still works
 2-3  the Audit portal looks each account up once per list, not twice per entry
 2-4  the evidence PDF says "N of M" beside its two cut lists
 2-5  passkey resets, sign-in check changes and sign-up links are privileged, on their tab, named
 2-6  a line of valid JSON that is not an object never crashes the chain, the check, the start or a sign-in
 2-7  an encoded value longer than MAX_BLOB is masked too
 2-8  an admin lifting a sign-in lock is not an alert
 2-9  the evidence PDF's "None" row for failed sign-ins shows
 2-10 the head's entry number counts the entries the retention removed, also when audit.head must be rebuilt
 2-11 two workers never make two daily checkpoints
 2-12 the beacon caches are keyed by a hash, not the whole request line
 2-13 the ATT&CK copy is read once per technique list, not twice per technique
LG_B02_ROOT may name another copy of the platform (the old code, to show these checks fail there).
Run: .venv/bin/python tests/check_fix_b02.py"""
import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import zipfile

ROOT = os.environ.get("LG_B02_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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


TMP = tempfile.mkdtemp(prefix="lg-fix-b02-")

# ------------------------------------------------------------------ 2-6
print("2-6: valid JSON that is not an entry")
import audit_chain  # noqa: E402
import audit_verifier  # noqa: E402
d6 = os.path.join(TMP, "log6")
os.makedirs(d6)
p6 = os.path.join(d6, "audit.log")
with open(p6, "w") as f:
    f.write("5\n")                                  # before the chain started
ch = audit_chain.Chain(p6)
ch.append({"t": time.time(), "event": "login", "user": "a", "target": "", "detail": "", "ip": "", "location": "", "ua": ""})
with open(p6, "a") as f:
    f.write('"audit_retention_set"\n"audit_archived"\n["audit_sealed", 1]\n')
_, err = safely(lambda: ch.append({"t": time.time(), "event": "login", "user": "b", "target": "", "detail": "", "ip": "",
                                   "location": "", "ua": ""}))
ok("a sign-in's entry is still written", not err, err)
_, err = safely(ch.record_retention_setting)
ok("the start (recording the retention setting) does not crash", not err, err)
r6, err = safely(lambda: audit_verifier.check(d6))
ok("the check does not crash, and reports the lines as a break", not err and r6 and not r6["ok"], err or str((r6 or {}).get("break")))
_, err = safely(lambda: audit_verifier.check(d6, (audit_chain.sha("5"), None)))
ok("an earlier head that is such a line: no crash", not err, err)
_, err = safely(lambda: audit_chain.archived_record("x.log.gz", ["5", "[1]"]))
ok("a rotation over such lines: no crash", not err, err)
arch = os.path.join(d6, "audit_archive")
os.makedirs(arch, exist_ok=True)
with gzip.open(os.path.join(arch, "audit-20000101-000000.log.gz"), "wt") as f:
    f.write('{"t": 1}\n5\n')
_, err = safely(lambda: audit_chain.Chain(p6).prune())
ok("the retention over an archive ending in such a line: no crash", not err, err)
import auth  # noqa: E402
recs, err = safely(lambda: auth.Audit(p6).records())
ok("the portal's records are entries only", not err and recs and all(isinstance(r, dict) for r in recs), err)

# ------------------------------------------------------------------ 2-7
print("2-7: a long encoded value is masked at any length")
import beacon_decode as BD  # noqa: E402
long_v = "QUJD" * 2300                              # 9,200 characters, longer than MAX_BLOB
masked, err = safely(lambda: BD.mask_url(f"GET /gate.php?d={long_v} HTTP/1.1"))
ok("over MAX_BLOB: not shown", not err and long_v not in str(masked), err or str(masked)[:80])
ok("…and a short one still is", BD.mask_url("GET /a.php?d=QUJD HTTP/1.1") == "GET /a.php?d=QUJD HTTP/1.1")

# ------------------------------------------------------------------ 2-5, 2-8
print("2-5 / 2-8: what the Audit portal counts")
import audit_portal as AP  # noqa: E402
for e, tab in (("passkeys_reset", "accounts"), ("signin_check_changed", "config"), ("invite_made", "accounts"),
               ("invite_revoked", "accounts")):
    ok(f"{e}: privileged, on its tab, named", e in AP.PRIVILEGED and AP.TAB_OF.get(e) == tab and e in AP.LABEL,
       f"{e in AP.PRIVILEGED} {AP.TAB_OF.get(e)}")
ok("a lock lifted by an admin is not an alert; a lockout still is",
   not AP.ALERT.search("login_unlocked") and AP.ALERT.search("login_locked"))

# ------------------------------------------------------------------ 2-4, 2-9
print("2-4 / 2-9: the evidence PDF's lists")
import audit_report as AR  # noqa: E402
said = []
_real_p = AR._p
AR._p = lambda text, st: (said.append(str(text)), _real_p(text, st))[1]


def evidence(priv, srcs, totals):
    said.clear()
    d = {"from": "2026-11-01", "to": "2026-11-27", "generated": "now", "by": "B02 Checker",
         "integrity": {"ok": True, "break": None, "entries": 3, "chained": 3, "before_chain": 0, "archives": 0,
                       "removed_archives": 0, "retention_days": 400, "head": "0" * 64, "head_entry": 3},
         "kpis": {"events": 1, "signins": 1, "failed": 0, "failure_rate": "0.0", "lockouts": 0, "privileged": 0, "exports": 0,
                  "people": 1, "after_hours": 0},
         "first": "", "last": "", "checks": [], "accounts": [], "privileged": priv, "fail_sources": srcs, "totals": totals}
    return safely(lambda: AR.build(d))


row = {"when": "2026-11-27 10:00 UTC", "label": "Role changed", "user_label": "B02 Admin", "target_label": "B02 Analyst", "detail": "x"}
src = {"ip": "203.0.113.5", "location": "Test", "n": 3}
pdf, err = evidence([row] * 15, [src] * 8, {"privileged_recent": 40, "fail_sources": 23})
ok("the PDF is made", not err and pdf and pdf[:4] == b"%PDF", err)
ok("privileged changes: '15 most recent of 40'", any("15 most recent of 40" in s for s in said))
ok("failed sign-ins by address: '8 … of 23'", any("8 addresses with the most of 23" in s for s in said))
pdf, err = evidence([], [], {"privileged_recent": 0, "fail_sources": 0})
ok("no failed sign-ins: the 'None' row shows", not err and said.count("None") >= 1, err or str(said[-6:]))
ok("…and nothing says 'of' when nothing is cut", not any("most recent of" in s or "with the most of" in s for s in said))
AR._p = _real_p

# ------------------------------------------------------------------ 2-10
print("2-10: the head counts the entries the retention removed")
d10 = os.path.join(TMP, "log10")
os.makedirs(os.path.join(d10, "audit_archive"))
p10 = os.path.join(d10, "audit.log")
with open(os.path.join(d10, "audit_archive", "removed.jsonl"), "w") as f:
    f.write(json.dumps({"archive": "audit-20000101-000000.log.gz", "last_hash": "a" * 64, "entries": 5, "oldest": 1.0,
                        "newest": 2.0, "removed_at": 3.0, "retention_days": 400}) + "\n")
c10 = audit_chain.Chain(p10)
c10.append({"t": time.time(), "event": "login", "user": "a", "target": "", "detail": "", "ip": "", "location": "", "ua": ""})
os.remove(os.path.join(d10, "audit.head"))           # lost: rebuilt with the next entry
c10.append({"t": time.time(), "event": "login", "user": "b", "target": "", "detail": "", "ip": "", "location": "", "ua": ""})
with open(os.path.join(d10, "audit.head")) as f:
    head = json.load(f)
ok("audit.head rebuilt: the entries kept plus the 5 removed", head["entries"] == len(c10.lines()) + 5, f"{head['entries']} vs {len(c10.lines())}+5")
ok("…the check agrees", audit_verifier.check(d10)["head_file"] == "matches", audit_verifier.check(d10)["head_file"])

# ------------------------------------------------------------------ 2-11
print("2-11: one daily checkpoint, however many workers")
import audit_checkpoint as AC  # noqa: E402
d11 = os.path.join(TMP, "data11")
os.makedirs(d11)
aud11 = AC._CliAudit(d11)
aud11.add("login", user="a")


class _Stop(Exception):
    pass


def _sleep(s):
    if s >= 3600:
        raise _Stop()


real_time = AC.time
AC.time = types.SimpleNamespace(sleep=_sleep, time=time.time, strftime=time.strftime, gmtime=time.gmtime)
try:
    sA = AC.Signer(d11)
    try:
        AC.loop(sA, aud11)
    except _Stop:
        pass
    for i in range(3):                                # a busy log: more entries after the first checkpoint
        aud11.add("login", user=f"u{i}")
    sB = AC.Signer(d11)
    stale = {"n": 0}

    def stale_last(_s=sB):
        stale["n"] += 1
        return (None, None) if stale["n"] == 1 else AC.Signer.last(_s)   # it looked before the other one wrote
    sB.last = stale_last
    _, err = safely(lambda: AC.loop(sB, aud11))
    ok("the second worker's loop runs", err in ("", "_Stop: "), err)
finally:
    AC.time = real_time
n_ck = len(AC.Signer(d11).checkpoints())
ok("one checkpoint, not two", n_ck == 1, str(n_ck))

# ------------------------------------------------------------------ 2-12
print("2-12: the beacon caches keep a hash of the request line")
BD._decode_cached.cache_clear(); BD._summary.cache_clear()
url = "GET /a.php?zz=" + "Q" * 120 + " HTTP/1.1"
BD.decode(url)
BD.field({"http_url": url}, "format")
ok("decode's cache: no request line kept as its key", BD._CACHE and all(len(str(k)) == 64 and k != url for k in BD._CACHE),
   str([str(k)[:30] for k in BD._CACHE]))
ok("the summaries' cache: neither", BD._SUMMARY and all(len(str(k[0])) == 64 for k in BD._SUMMARY), str([str(k)[:30] for k in BD._SUMMARY]))
ok("…a finished decode is still known", BD.decode_finished(url))

# ------------------------------------------------------------------ 2-13
print("2-13: the ATT&CK copy read once per list")
import attack_map  # noqa: E402
DOC = {"techniques": {t: {"name": f"Tech {t}", "tactics": ["x"], "state": "active", "mitigations": [["M1", "do this"]]}
                      for t in ("T1001", "T1002", "T1003")},
       "mitigations": {"M1": {"name": "Mitigation one"}}}


class Offline:
    loads = 0

    def _load(self, name):
        Offline.loads += 1
        return DOC, {}


am = attack_map.AttackMap(os.path.join(TMP, "attack"), Offline())
Offline.loads = 0
t = am.tech("T1001")
ok("one technique: one read", Offline.loads == 1 and t["defend"][0]["name"] == "Mitigation one", str(Offline.loads))
Offline.loads = 0
items = am._items(["T1001", "T1002", "T1003"], "possible", "exposure", "suggested")
ok("three techniques: one read", Offline.loads == 1 and len(items) == 3 and items[2]["defend"][0]["name"] == "Mitigation one", str(Offline.loads))

# ------------------------------------------------------------------ 2-3
print("2-3: the Audit portal looks each account up once per list")
from flask import Flask  # noqa: E402
from people import People  # noqa: E402


class Users:
    calls = 0
    acc = {"b02-grace": {"profile": {"full_name": "Grace B02"}}, "b02-rachel": {"profile": {"full_name": "Rachel B02"}}}

    def all(self):
        Users.calls += 1
        return dict(self.acc)

    def get(self, n):
        return self.all().get(n)


d3 = os.path.join(TMP, "log3")
os.makedirs(d3)
aud3 = auth.Audit(os.path.join(d3, "audit.log"))
for i in range(60):
    aud3.add("login" if i % 2 else "user_role", user="b02-grace" if i % 3 else "b02-rachel", target="b02-rachel", ip="", ua="")
app3 = Flask("b02-portal")
_u3 = Users()
AP.install(app3, {"has_perm": lambda p: True, "users": _u3, "roles": types.SimpleNamespace(perms=lambda r: set(), roles={}),
                  "sessions": types.SimpleNamespace(list=lambda: []), "audit": aud3, "people": People(_u3),
                  "perms_catalog": {}, "auditor_role": "auditor", "tls": lambda: True, "access_mode": lambda: "private"})
Users.calls = 0
day = time.strftime("%Y-%m-%d", time.gmtime())
r3 = app3.test_client().get(f"/api/audit/events?tab=all&from={day}&to={day}&limit=1000")
ok("the list answers with every entry, people by name", r3.status_code == 200 and r3.json["total"] >= 60
   and any(x["user_label"] == "Grace B02 (b02-grace)" for x in r3.json["rows"]), str(r3.status_code))
ok("…with a handful of account look-ups, not two per entry", Users.calls <= 5, f"{Users.calls} look-ups for {r3.json['total']} entries")

# ------------------------------------------------------------------ 2-2 and 2-1: the platform itself
print("2-2: names that are no account are never written down")
import app as A  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402
AU = A.AUTH
users, sessions, throttle, audit = AU["users"], AU["sessions"], AU["throttle"], AU["audit"]
sealer = (getattr(A, "FEATURES", {}) or {}).get("insider", {}).get("sealer")
saved = dict(users=(users.path, users.mtime, users.data), sessions=(sessions.path, dict(sessions.s)),
             throttle=(throttle.path, dict(throttle.fail)), add=audit.add, chain=(audit.chain, audit.path),
             sealer=sealer.path if sealer else None)
tokens = []
try:
    PW = "Steady-Harbour-Lantern-63!"
    H = generate_password_hash(PW)
    TOTP = __import__("base64").b32encode(os.urandom(10)).decode()     # a throwaway authenticator key, made per run
    acc = lambda role: {"hash": H, "role": role, "status": "active", "totp": TOTP, "changed": 0, "created": 1,  # noqa: E731
                        "pw_set_at": int(time.time()), "profile": {"full_name": f"B02 {role.title()}"}}
    with open(os.path.join(TMP, "users.json"), "w") as f:
        json.dump({"users": {"b02-known": acc("analyst"), "b02-auditor": acc("auditor")}}, f)
    users.path, users.mtime = os.path.join(TMP, "users.json"), None
    sessions.path, throttle.path = os.path.join(TMP, "sessions.json"), os.path.join(TMP, "login_counters.json")
    sessions.s.clear(); throttle.fail.clear()
    audit.path = os.path.join(TMP, "audit2", "audit.log")
    os.makedirs(os.path.dirname(audit.path))
    audit.chain = audit_chain.Chain(audit.path)
    if sealer:
        sealer.path = os.path.join(TMP, "copy_seals.jsonl")
    logged = []
    audit.add = lambda ev, **k: logged.append((ev, k.get("user", ""), k.get("detail", "")))
    HD = {"User-Agent": "lg-check-fix-b02"}
    SECRET = "Correct-Horse-Battery-B02"            # a password typed into the name box
    c = A.app.test_client()
    r = c.post("/login", data={"username": SECRET, "password": "x"}, headers=HD)
    lf = [x for x in logged if x[0] == "login_failed"]
    ok("a failed sign-in with an unknown name: logged, without the name", r.status_code == 401 and lf
       and all(SECRET not in x[2] and x[1] == "" for x in lf), str(lf))
    for _ in range(throttle.account_fails):
        throttle.failed("127.0.0.1", SECRET)
    r = A.app.test_client().post("/login", data={"username": SECRET, "password": "x"}, headers=HD)
    ll = [x for x in logged if x[0] == "login_locked"]
    ok("…locked after too many tries (the throttle still counts the name)", r.status_code == 429, str(r.status_code))
    ok("…the lockout is logged, without the name", ll and all(SECRET not in x[1] + x[2] for x in ll), str(ll))
    for _ in range(throttle.account_fails):
        throttle.failed("127.0.0.1", "b02-known")
    A.app.test_client().post("/login", data={"username": "b02-known", "password": "x"}, headers=HD)
    ok("…a real account's lockout still names the account", any(x[0] == "login_locked" and x[1] == "b02-known" for x in logged))
    throttle.fail.clear()
    A.app.test_client().post("/forgot", data={"mode": "ask", "username": SECRET + "-ask"}, headers=HD)
    rr = [x for x in logged if x[0] == "reset_requested"]
    ok("asking an administrator for an unknown name: logged without it", rr and all(SECRET not in x[1] + x[2] for x in rr), str(rr))
    A.app.test_client().post("/forgot", data={"mode": "self", "username": SECRET + "-self", "password": "x", "password2": "x",
                                              "code": "123456", "recovery": ""}, headers=HD)
    rf = [x for x in logged if x[0] == "reset_failed"]
    ok("a failed reset for an unknown name: logged without it", rf and all(SECRET not in x[1] + x[2] for x in rf), str(rf))
    ok("nothing logged anywhere holds the value", not any(SECRET in json.dumps(x) for x in logged))
    audit.add = saved["add"]
    throttle.fail.clear()

    print("2-1: the proof package an auditor downloads verifies")
    tok = sessions.create("b02-auditor", "127.0.0.1", HD["User-Agent"]); tokens.append(tok)
    ca = A.app.test_client(); ca.set_cookie("lg_session", tok)

    def verify_download():
        r = ca.get("/api/audit/proof.zip", headers=HD)
        if r.status_code != 200:
            return r, f"HTTP {r.status_code}"
        out = tempfile.mkdtemp(dir=TMP)
        with zipfile.ZipFile(io.BytesIO(r.data)) as z:
            z.extractall(out)
        p = subprocess.run([sys.executable, "-I", os.path.join(out, "verify_audit_log.py"), out], capture_output=True,
                           text=True, timeout=120)
        return r, p.stdout.strip().splitlines()[-1] if p.stdout.strip() else p.stderr[-200:]

    r, res = verify_download()
    ok("downloaded by an auditor (not the self-test): RESULT: verified", res == "RESULT: verified", res)
    ok("…the internal mark never reaches the browser", "X-LG-No-Stamp" not in r.headers)
    ok("…and the download was sealed (Trace a leak finds it)", sealer is None or (os.path.exists(sealer.path)
       and "b02-auditor" in open(sealer.path).read()))
    view = A.app.view_functions["api_audit_proof"]

    def without_mark(*a, **k):
        resp = view(*a, **k)
        resp.headers.pop("X-LG-No-Stamp", None)
        return resp
    A.app.view_functions["api_audit_proof"] = without_mark
    try:
        _, res = verify_download()
    finally:
        A.app.view_functions["api_audit_proof"] = view
    ok("without X-LG-No-Stamp the stamped package does NOT verify (what the mark prevents)", res == "RESULT: NOT verified", res)
finally:
    audit.add = saved["add"]
    audit.chain, audit.path = saved["chain"]
    if sealer:
        sealer.path = saved["sealer"]
    for t in tokens:
        try:
            sessions.end(token=t)
        except Exception:  # noqa: BLE001
            pass
    users.path, users.mtime, users.data = saved["users"]
    sessions.path = saved["sessions"][0]; sessions.s.clear(); sessions.s.update(saved["sessions"][1])
    throttle.path = saved["throttle"][0]; throttle.fail.clear(); throttle.fail.update(saved["throttle"][1])
    shutil.rmtree(TMP, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
