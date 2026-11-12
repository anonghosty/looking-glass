#!/usr/bin/env python3
"""Five workflow fixes from the external review (2026-11-12), each tried the way it went wrong. Nothing real is touched:
advisories go to a temporary folder, accounts to a temporary users file, the audit log is not written, and no DNS
look-up leaves the computer (the look-up is counted instead).
1. advisories: every change is read, checked and written back; a write over a copy that changed meanwhile (a save that
   started before a send) is refused, and a kept report file is never written over;
2. a finding closes only when every organisation has its advisory sent (tests/check_combo_review.py, end to end);
3. approve works only on an account waiting for approval, so it can never demote the last administrator;
4. /register counts every sign-up whose e-mail domain is looked up, and stops looking up after the limit;
5. the advisory page drops an organisation's data that arrives after another was picked, and its buttons work on the
   organisation their form was drawn for.
Run: .venv/bin/python tests/check_workflow_fixes.py"""
import json, os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"                    # the app is called in-process (proxy_guard.py)
os.environ["REGISTRATION"] = "1"                   # sign-up open for this check only
import app as A  # noqa: E402
import advisory as AV  # noqa: E402
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def refused(fn):
    try:
        fn()
        return False
    except AV.Changed:
        return True


tmp = tempfile.mkdtemp(prefix="lg-workflow-")
audit = A.AUTH["audit"]; real_add = audit.add; audited = []
audit.add = lambda *a, **k: audited.append((a[0] if a else "", k.get("detail", "")))
users, sessions, throttle = A.AUTH["users"], A.AUTH["sessions"], A.AUTH["throttle"]
real_users = (users.path, users.mtime, users.data)
real_lookup = auth.email_domain_problem
MADE, IP = [], "127.0.0.77"
try:
    print("1. Advisories: read, checked, written back")
    S = AV.Store(os.path.join(tmp, "advisories"))
    a = S.save({"finding": "9", "network": "Net A", "status": "drafted", "history": [], "sends": []}, create=True)
    ok("a new advisory gets its reference and revision 1", a.get("ref") and a.get("rev") == 1, f"{a.get('ref')} rev {a.get('rev')}")
    ok("…a second one for the same organisation is refused, not silently replaced",
       refused(lambda: S.save({"finding": "9", "network": "Net A", "status": "draft", "history": []}, create=True)))
    editing = S.of("9", "Net A")                       # an advisor's save reads it …
    sending = S.of("9", "Net A")                       # … the send reads it too
    sending.update(status="sent", sends=[{"to": ["Net A"], "at": 1}]); S.save(sending)
    editing.update(status="draft", subject="edited after the send started")
    ok("a save that read the advisory before the send is refused", refused(lambda: S.save(editing)))
    now = S.of("9", "Net A")
    ok("…the advisory stays sent, with its send recorded", now["status"] == "sent" and len(now["sends"]) == 1 and "subject" not in now,
       f"{now['status']}, {len(now['sends'])} send(s), rev {now.get('rev')}")
    fresh = S.of("9", "Net A"); fresh["recipients"] = ["Team B"]; S.save(fresh)
    ok("a change made on the latest copy goes through", S.of("9", "Net A").get("recipients") == ["Team B"])
    with open(os.path.join(S.dir, "ADV-2025-001.json"), "w", encoding="utf-8") as fh:     # saved before this fix: no revision
        json.dump({"ref": "ADV-2025-001", "finding": "8", "network": "Net B", "status": "draft", "history": []}, fh)
    old = S.of("8", "Net B"); old["subject"] = "kept"; S.save(old)
    ok("an advisory saved before this fix (no revision) is changed as before", S.of("8", "Net B").get("subject") == "kept"
       and S.of("8", "Net B").get("rev") == 1)
    ref = a["ref"]
    n1 = S.keep_file(ref, 1, b"first")
    n2 = S.keep_file(ref, 1, b"second")                # two generations at once ask for the same number
    with open(S.file_path(ref, 1), "rb") as fh:
        first = fh.read()
    ok("a kept report file is never written over: the second generation gets the next number", (n1, n2) == (1, 2) and first == b"first",
       f"{n1}, {n2}, file 1 holds {first!r}")

    print("3. Approve: only an account waiting for approval")
    upath = os.path.join(tmp, "users.json")
    with open(upath, "w", encoding="utf-8") as fh:
        json.dump({"users": {"chk-admin": {"status": "active", "role": "admin", "totp": "x", "changed": 0},
                             "chk-waiting": {"status": "pending", "role": "external", "totp": "x"}}}, fh)
    users.path, users.mtime = upath, None
    token = sessions.create("chk-admin", "127.0.0.1", "lg-check-workflow"); MADE.append(token)
    csrf = next(s["csrf"] for s in sessions.s.values() if s["user"] == "chk-admin")
    c = A.app.test_client(); c.set_cookie("lg_session", token)
    H = {"User-Agent": "lg-check-workflow", "X-CSRF-Token": csrf}
    r = c.post("/api/admin/users/chk-admin", json={"action": "approve", "role": "external"}, headers=H)
    ok("the only administrator cannot be 'approved' as an external", r.status_code == 400 and users.get("chk-admin")["role"] == "admin",
       f"{r.status_code} {(r.json or {}).get('error', '')}")
    r = c.post("/api/admin/users/chk-waiting", json={"action": "approve", "role": "analyst"}, headers=H)
    ok("an account waiting for approval is approved with its role", r.status_code == 200 and users.get("chk-waiting")["status"] == "active"
       and users.get("chk-waiting")["role"] == "analyst", f"{r.status_code} {(r.json or {}).get('error', '')}")
    r = c.post("/api/admin/users/chk-waiting", json={"action": "approve", "role": "admin"}, headers=H)
    ok("…approving it again (an active account) is refused: roles change with Role", r.status_code == 400
       and users.get("chk-waiting")["role"] == "analyst", str(r.status_code))
    r = c.post("/api/admin/users/chk-admin", json={"action": "role", "role": "external"}, headers=H)
    ok("…and Role still keeps the last administrator", r.status_code == 400 and users.get("chk-admin")["role"] == "admin", str(r.status_code))

    print("4. /register: every e-mail domain look-up counts")
    looked = []
    auth.email_domain_problem = lambda email: (looked.append(email), "The domain made-up.example-nx does not exist.")[1]
    throttle.clear_address(IP)
    reg = A.app.test_client()
    form = {"username": "newperson", "full_name": "New Person", "organisation": "Example Org", "country": "GH",
            "password": "a long enough pass phrase 42", "password2": "a long enough pass phrase 42"}
    codes = []
    for i in range(auth.REGISTER_DNS_PER_HOUR + 5):
        r = reg.post("/register", data=dict(form, email=f"p{i}@made-up-{i}.org"), base_url="https://localhost",
                     environ_base={"REMOTE_ADDR": IP}, headers={"User-Agent": "lg-check-workflow"})
        codes.append(r.status_code)
    ok(f"made-up domains are looked up {auth.REGISTER_DNS_PER_HOUR} times an hour from one address, then refused",
       len(looked) == auth.REGISTER_DNS_PER_HOUR and codes[:auth.REGISTER_DNS_PER_HOUR] == [400] * auth.REGISTER_DNS_PER_HOUR
       and set(codes[auth.REGISTER_DNS_PER_HOUR:]) == {429}, f"{len(looked)} look-ups; answers {sorted(set(codes))}")
    ok("…the limit is written to the audit log once, not for every refusal",
       sum(1 for e, d in audited if e == "register_limited" and "look-ups" in d) == 1)
    r = reg.post("/register", data=dict(form, email="p@other.org"), base_url="https://localhost",
                 environ_base={"REMOTE_ADDR": "127.0.0.78"}, headers={"User-Agent": "lg-check-workflow"})
    ok("…another address is not held back by it", r.status_code == 400 and len(looked) == auth.REGISTER_DNS_PER_HOUR + 1, str(r.status_code))

    print("5. The advisory page: quick switching between organisations")
    root = os.path.dirname(A.__file__)
    js = open(os.environ.get("LG_ADVISORY_JS") or os.path.join(root, "static/js/advisory.js"), encoding="utf-8").read()
    ok("an organisation's data that arrives after another was picked is dropped", "const my = ++SEQ;" in js and "if (my !== SEQ) return;" in js)
    ok("every button sends the organisation its form was drawn for", "const net = NET, seq = SEQ, here = D;" in js
       and "{ network: net }" in js and "network: NET" not in js)
    ok("the organisation cannot be switched while a save or generation is under way", "if (BUSY) return;" in js and "if (BUSY) { sel.value" in js)
finally:
    audit.add = real_add
    auth.email_domain_problem = real_lookup
    users.path, users.mtime, users.data = real_users
    for t in MADE:
        sessions.end(token=t)
    for ip in (IP, "127.0.0.78"):
        throttle.clear_address(ip)
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
