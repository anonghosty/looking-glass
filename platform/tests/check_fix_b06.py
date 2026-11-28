#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Audit 2026-11-27, batch 06, kept fixed (in-process, temporary folders, made-up data):
  6-1  name_sources: the last refresh's "by" never the sign-in name;
  6-6  password_policy / quarterly: who changed it named by full name or person code, never the sign-in name;
  6-2/6-3 quarterly guards and figures: linear, not O(n^2) (timed on a made-up large quarter);
  6-4  pdf_refs: two threads writing the names files lose nothing and leave no cut file.
LG_FIX_B06_SRC: the code folder to test (default: this tree)."""
import collections
import json
import os
import sys
import tempfile
import threading
import time

ROOT = os.environ.get("LG_FIX_B06_SRC") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_PERSON_CODE_DIR", tempfile.mkdtemp())
import person_code  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{info}]"))
    if not cond:
        fails.append(label)


SIGNIN = "ada.admin"
CODE = person_code.code(SIGNIN)

print("6-1 name_sources: the last refresh")
import name_sources  # noqa: E402
from flask import Flask  # noqa: E402

tmp = tempfile.mkdtemp()
os.makedirs(os.path.join(tmp, "data"))
with open(os.path.join(tmp, "data", name_sources.REFRESH_STATUS), "w") as f:
    json.dump({"at": "2026-11-27T10:00:00+00:00", "by": SIGNIN, "ok": True, "message": "done"}, f)


class _Off:
    def status(self):
        s = {"installed": True, "entries": 1, "fetched": "", "versions": {}}
        return {"misp-galaxy": s, "mitre-attack": s}


app = Flask("b06")
api = name_sources.install(app, {"base_dir": tmp, "offline": _Off(), "allowed": lambda: True, "can_refresh": lambda: False,
                                 "csrf_ok": lambda: True, "fresh": lambda: True, "audit": None})
last = api["status"]()["last"]
ok("the refresh's 'by' is not the sign-in name", last.get("by") and SIGNIN not in json.dumps(last), last)
ok("...it is the person code", CODE in str(last.get("by")), last)

print("6-6 password_policy and quarterly: who changed it")
import password_policy  # noqa: E402
import quarterly  # noqa: E402


class _Users:
    def __init__(self, full):
        self.full = full

    def get(self, n):
        return {"profile": {"full_name": self.full}} if n == SIGNIN else None

    def all(self):
        return {}


pol = password_policy.Policy(tmp)
pol.force_all(SIGNIN)
app2 = Flask("b06pp")
password_policy.install(app2, {"policy": pol, "has_perm": lambda p: True, "csrf_ok": lambda: True, "fresh": lambda: True,
                               "audit": None, "users": _Users(""), "throttle": None, "client": lambda: ("", "")})
with app2.test_request_context():
    j = app2.view_functions["api_password_policy"]().get_json()
ok("password policy: no full name -> the person code, not the sign-in name", j["by"] == CODE, j.get("by"))
ok("password policy: still stored with the sign-in name", pol.get()["by"] == SIGNIN)
rec, _ = quarterly.set_purge(tmp, False, SIGNIN, SIGNIN, {})
ok("quarterly purge switch: by_name is never the sign-in name", rec["by_name"] == CODE and rec["by"] == SIGNIN, rec)

print("6-2/6-3 quarterly: guards and figures on a large quarter")
N = 6000
months = ["2026-07", "2026-08", "2026-09"]
R = {"months": months, "rep_recs": collections.Counter(), "rep_total": collections.Counter(),
     "net_month": collections.Counter(), "net_total": collections.Counter(), "rep_hosts": {}, "net_hosts": {}}
for i in range(N):
    n, a = f"r{i % 300}", str(64500 + i)
    R["rep_recs"][(n, months[0], a)] += 2
    R["rep_total"][n] += 2
    R["net_month"][(a, months[0])] += 2
    R["net_total"][a] += 2
    R["rep_hosts"][(n, a)] = {f"h{i}": 1}
    R["net_hosts"][a] = {f"h{i}": 1}
calls = {"n": 0}
real_sum = sum


def counting_sum(it, *x):
    calls["n"] += 1
    return real_sum(it, *x)


quarterly.sum = counting_sum
try:
    t0 = time.time()
    try:
        quarterly.guards(None, dict(R, lo=quarterly.date(2026, 7, 1), hi=quarterly.date(2026, 10, 1)), {}, {}, {}, {})
    except Exception:                     # noqa: BLE001  (guards 3+ need a database: only 1 and 2 are timed)
        pass
    dt = time.time() - t0
finally:
    del quarterly.sum
ok(f"guards 1 and 2: linear in the rows ({calls['n']} sums, {dt:.2f}s for {N} report networks)", dt < 2.0, dt)

print("6-4 pdf_refs: two writers at once")
import pdf_refs  # noqa: E402

pdf_refs.KNOWN.update(path=os.path.join(tmp, "data", "name_levels.json"), mtime=None, levels={})
pdf_refs.SEEN.update(path=os.path.join(tmp, "data", "name_kinds.json"), mtime=None, kinds={})
errs = []


def writer(k):
    try:
        for j in range(40):
            pdf_refs.remember({f"name-{k}-{j}": "high"})
            pdf_refs.remember_kinds({f"name-{k}-{j}": "Infection"})
    except Exception as e:               # noqa: BLE001
        errs.append(repr(e))


ts = [threading.Thread(target=writer, args=(k,)) for k in range(4)]
[t.start() for t in ts]
[t.join() for t in ts]
with open(pdf_refs.KNOWN["path"]) as f:
    lv = json.load(f)
with open(pdf_refs.SEEN["path"]) as f:
    kd = json.load(f)
ok("no writer failed", not errs, errs[:2])
ok("every name's level kept (4 threads x 40)", len(lv) == 160, len(lv))
ok("every name's kind kept (4 threads x 40)", len(kd) == 160, len(kd))
ok("no temporary file left", not [x for x in os.listdir(os.path.join(tmp, "data")) if x.endswith(".tmp")])

print("6-11 pdf_refs: the cap")
saved_max = pdf_refs.KNOWN_MAX
pdf_refs.KNOWN_MAX = 5
try:
    full = {f"cap-{k}": "low" for k in range(6)}            # a file the old code let grow one batch past the cap
    with open(pdf_refs.KNOWN["path"], "w") as f:
        json.dump(full, f)
    pdf_refs.KNOWN.update(mtime=None, levels={})
    pdf_refs.remember({"cap-0": "critical", "cap-new": "high"})
    with open(pdf_refs.KNOWN["path"]) as f:
        lv = json.load(f)
    ok("at the cap a known name's level still rises", lv.get("cap-0") == "critical", lv.get("cap-0"))
    ok("...and no new name is added past it", "cap-new" not in lv, sorted(lv))
finally:
    pdf_refs.KNOWN_MAX = saved_max

print("6-3 quarterly figures() on a large quarter")
N3 = 2000
base3 = tempfile.mkdtemp()
os.makedirs(os.path.join(base3, "data"))
with open(os.path.join(base3, "data", "asns.json"), "w") as f:
    json.dump({"asns": {str(64500 + i): {"name": f"Company {i}", "demo_alias": f"Network {i}"} for i in range(N3)}}, f)
R3 = {"months": months, "rep_recs": collections.Counter(), "rep_total": collections.Counter(), "all_hosts": {},
      "net_month": collections.Counter(), "net_total": collections.Counter(), "rep_hosts": {}, "net_hosts": {},
      "rep_noaddr": {}, "reports": {}, "region": {}, "region_recs": {}, "kev_hosts": set(), "kev_recs": 0, "cve_hosts": {},
      "issue_hosts": {}, "issue_recs": {}, "inf_hosts": {}, "inf_recs": {}}
for i in range(N3):
    n, a = f"r{i % 200}", str(64500 + i)
    R3["reports"][n] = {"label": n, "family": "Scans"}
    R3["rep_recs"][(n, months[0], a)] += 2
    R3["rep_total"][n] += 2
    R3["net_month"][(a, months[0])] += 2
    R3["net_total"][a] += 2
    R3["rep_hosts"][(n, a)] = {f"h{i}": 1}
    R3["net_hosts"][a] = {f"h{i}": 1}
    R3["all_hosts"][f"h{i}"] = 1
t0 = time.time()
try:
    X3 = quarterly.figures(R3, None, base3, quarterly.date(2026, 7, 31), None)
    err3 = ""
except Exception as e:                    # noqa: BLE001
    X3, err3 = {}, repr(e)
dt3 = time.time() - t0
ok("figures() ran on the made-up quarter", not err3, err3)
ok(f"figures(): linear in the networks ({dt3:.2f}s for {N3} companies)", not err3 and dt3 < 3.0, dt3)
ok("...and still counts every network as recurring", len(X3.get("recurring") or []) == N3, len(X3.get("recurring") or []))

print("6-6 quarterly purge_view: an older switch saved with the sign-in name")
import flask  # noqa: E402

base6 = tempfile.mkdtemp()
os.makedirs(os.path.join(base6, "data", "quarterly"))
with open(quarterly.confirm_path(base6), "w") as f:
    json.dump({"enabled": True, "by": SIGNIN, "by_name": SIGNIN, "at": "2026-11-20T10:00:00+00:00", "at_ts": 1}, f)
app6 = Flask("b06q")
quarterly.install(app6, {"base_dir": base6, "db": None, "has_perm": lambda p: True, "csrf_ok": lambda: True, "audit": None,
                         "people_name": lambda u: "", "serving": False})
with app6.test_request_context():
    flask.g.user = {"user": "someone", "role": "admin"}
    try:
        r6 = app6.view_functions["api_quarterly_admin"]()
        p6 = (r6[0] if isinstance(r6, tuple) else r6).get_json().get("purge") or {}
        e6 = ""
    except Exception as e:                # noqa: BLE001
        p6, e6 = {}, repr(e)
ok("Settings → Quarterly answered", not e6 and p6, e6)
ok("purge_view never carries the sign-in name", p6 and SIGNIN not in json.dumps(p6), {k: p6.get(k) for k in ("by", "by_name", "changed_by_name")})
ok("...it names the person code", p6.get("by_name") == CODE and p6.get("by") == CODE, p6.get("by_name"))

print("6-7 notifications: the whole comment")
import notifications  # noqa: E402

LONG = " ".join(f"word{k}" for k in range(120))


class _F:
    lock = threading.Lock()
    data = {"items": {"1": {"id": "1", "participants": ["me"], "status": "open", "title": "A finding",
                            "history": [{"user": "other", "at": time.time(), "kind": "reply", "comment": LONG}]}}}

    def _load(self):
        pass


app7 = Flask("b06n")
notifications.install(app7, {"base_dir": tempfile.mkdtemp(), "findings": _F(), "has_perm": lambda p: False,
                             "csrf_ok": lambda: True, "people_name": lambda u: "Other Person", "labels": lambda s: s})
with app7.test_request_context():
    flask.g.user = {"user": "me"}
    items7 = app7.view_functions["api_notifications"]().get_json()["items"]
t7 = items7[0]["text"] if items7 else ""
ok("the bell carries the whole comment", LONG in t7, t7[-60:])
ok("...never cut with '…'", "…" not in t7)

print("6-8 / 6-9 the quarterly PDF: a long Read me card, the network named once")
import quarterly_pdf as qp  # noqa: E402

meta = {"quarter": "2026Q3", "platform_label": "Quarterly report", "audience": "management", "status": ("VALID", ""),
        "selection": "01 Jul 2026 to 30 Sep 2026", "made": "made by Looking Glass", "generated": "2026-10-01 00:00 UTC"}


def drawn_ys(doc):
    ys = []
    real = doc.text

    def rec(x, y, text, *a, **k):
        ys.append((doc.page, y, str(text)))
        return real(x, y, text, *a, **k)
    doc.text = rec
    return ys


d8 = qp.QDoc(meta)
y8 = d8.new_page("The quarter at a glance") - 260
ys8 = drawn_ys(d8)
notes8 = [f"Sentence {k}: " + " ".join(f"longer-words-{k}-{j}" for j in range(40)) + "." for k in range(14)]
d8.notes(y8, "Read me", notes8)
foot8 = f"{d8.meta['made'][:1].upper()}{d8.meta['made'][1:]}, {d8.meta['generated']}."     # the footer: who and when only (2026-11-28)
body8 = [(p, y, t) for p, y, t in ys8 if not t.startswith(("Addresses are counted", "Page ")) and t != foot8]
ok("every line of the Read me card is above the footer", body8 and min(y for _, y, _ in body8) >= 40,
   min((y for _, y, _ in body8), default=None))
ok("...the card carried on to the next page", max(p for p, _, _ in ys8) > 1)
ok("...every sentence drawn", all(any(t.startswith(f"Sentence {k}:") for _, _, t in ys8) for k in range(14)))
pdf8 = d8.done()
out8 = os.environ.get("LG_FIX_B06_PDF")
if out8:
    with open(out8, "wb") as f:
        f.write(pdf8)

d9 = qp.QDoc(meta)
y9 = d9.new_page("Issues per network")
ys9 = drawn_ys(d9)
rows9 = [[f"Company {n} (AS{64500 + n}): 5 of 9 issues", f"issue {k}", "no", "3"] for n in range(30) for k in range(5)]
try:
    d9.table(y9, "Issues per network", "Top issues", None, [("Network", 190, "start"), ("Issue or CVE", 0, "start"),
             ("CISA KEV", 60, "start"), ("Unique addresses", 100, "end")], rows9, group=0)
    e9 = ""
except TypeError as e:
    e9 = repr(e)
labels9 = [t for _, _, t in ys9 if t.startswith("Company 3 (AS64503)")]
pages9 = {p for p, _, t in ys9 if t.startswith("issue ")}
ok("the network's label is drawn once for its five issues", not e9 and len(labels9) == 1, e9 or len(labels9))
ok("...and every continued card starts with its network named", not e9 and len(pages9) > 1 and all(
    any(pp == p and t.startswith("Company ") for pp, _, t in ys9) for p in pages9), pages9)

print("6-12 passkeys: the user handle")
import base64  # noqa: E402
import hashlib  # noqa: E402

import cbor2  # noqa: E402
import passkeys  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


def b64(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


class Authenticator:
    """A software passkey (as tests/check_stepup.py): ES256, attestation "none", user present and verified."""

    def __init__(self):
        self.key, self.cid, self.count = ec.generate_private_key(ec.SECP256R1()), os.urandom(16), 0

    def _client(self, typ, challenge):
        return json.dumps({"type": typ, "challenge": challenge, "origin": "http://localhost", "crossOrigin": False}).encode()

    def create(self, opts):
        nums = self.key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")})
        ad = hashlib.sha256(opts["rp"]["id"].encode()).digest() + bytes([0x45]) + (0).to_bytes(4, "big") \
            + bytes(16) + len(self.cid).to_bytes(2, "big") + self.cid + cose
        att = cbor2.dumps({"fmt": "none", "attStmt": {}, "authData": ad})
        return {"id": b64(self.cid), "rawId": b64(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64(self._client("webauthn.create", opts["challenge"])),
                             "attestationObject": b64(att), "transports": ["internal"]}}

    def get(self, opts, handle):
        self.count += 1
        ad = hashlib.sha256(opts["rpId"].encode()).digest() + bytes([0x05]) + self.count.to_bytes(4, "big")
        cd = self._client("webauthn.get", opts["challenge"])
        sig = self.key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": b64(self.cid), "rawId": b64(self.cid), "type": "public-key", "clientExtensionResults": {},
                "response": {"clientDataJSON": b64(cd), "authenticatorData": b64(ad), "signature": b64(sig),
                             "userHandle": handle}}


store = passkeys.Store(os.path.join(tempfile.mkdtemp(), "passkeys.json"))
chs = passkeys.Challenges()
opts = passkeys.registration_options(store, chs, "b", SIGNIN, "Ada Admin", "localhost")
ok("a new passkey's user handle is not the sign-in name", opts["user"]["id"] != b64(SIGNIN.encode()), opts["user"]["id"])
ok("...it is the person code", opts["user"]["id"] == b64(CODE.encode()), opts["user"]["id"])
old = Authenticator()                     # a passkey registered before: its authenticator holds the OLD handle
old_opts = dict(opts, user=dict(opts["user"], id=b64(SIGNIN.encode())))
passkeys.register(store, chs, "b", SIGNIN, old.create(old_opts), "Old laptop", "localhost", "http://localhost")
aopts = passkeys.authentication_options(store, chs, "a", SIGNIN, "localhost")
try:
    signed = passkeys.authenticate(store, chs, "a", SIGNIN, old.get(aopts, b64(SIGNIN.encode())), "localhost", "http://localhost")
except Exception as e:                    # noqa: BLE001
    signed = repr(e)
ok("a passkey registered under the old handle still signs in", signed is True, signed)
new = Authenticator()
opts2 = passkeys.registration_options(store, chs, "b2", SIGNIN, "Ada Admin", "localhost")
passkeys.register(store, chs, "b2", SIGNIN, new.create(opts2), "New phone", "localhost", "http://localhost")
aopts = passkeys.authentication_options(store, chs, "a2", SIGNIN, "localhost")
try:
    signed = passkeys.authenticate(store, chs, "a2", SIGNIN, new.get(aopts, opts2["user"]["id"]), "localhost", "http://localhost")
except Exception as e:                    # noqa: BLE001
    signed = repr(e)
ok("...and a new one (person-code handle) signs in", signed is True, signed)

print("6-13 privacy: the reference tables are never cleared at once")
import privacy  # noqa: E402

refs = privacy.HostRefs("b06-secret")
refs.strict = lambda: True
issued = [refs.ref(f"10.{(k >> 16) & 255}.{(k >> 8) & 255}.{k & 255}") for k in range(500010)]
ok("a reference issued just before the table was full still resolves", refs.resolve(issued[499000]).startswith("10."),
   refs.resolve(issued[499000]))
ok("...the newest too", refs.resolve(issued[-1]).startswith("10."))
ok("...the table stays bounded", len(refs.to_ip) <= 500001, len(refs.to_ip))
del issued, refs

print(f"{checks - len(fails)}/{checks} checks passed")
sys.exit(1 if fails else 0)
