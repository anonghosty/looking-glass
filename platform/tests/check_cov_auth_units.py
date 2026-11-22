#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The sign-in building blocks of auth.py on their own, with made-up values in a temporary folder (r91 coverage):
- one-time codes: the format, the window of 30 seconds either side, a code used once is refused again
- the e-mail domain check: reserved example domains, no such domain, a domain that takes no mail, no MX but an address,
  DNS that does not answer (never held against the person); the country list when the system list is missing
- profile and password rules: each reason a name, organisation, address, country or password is refused
- where an address is (this computer, local network, the Internet; never an online look-up)
- the stores: accounts, roles (fixed and exclusive permissions), sessions (idle, maximum age, another address or
  browser, a new id, ending one), the failed sign-in counters (locks, minutes left, what is locked, lifting a lock,
  kept across a restart without old or broken rows) and the audit log (a write that fails is counted, then the gap is
  the first entry once it works; search, names and self-test entries)
No database, no server, nothing of the installation touched. Run: .venv/bin/python tests/check_cov_auth_units.py"""
import json, os, shutil, sys, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("LG_QUIET", "1")
import auth  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    # the label only: these checks handle made-up secrets and codes, which are never printed, even on a failure
    # (CodeQL py/clear-text-logging-sensitive-data, #42)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}", flush=True)


tmp = tempfile.mkdtemp(prefix="lg-cov-auth-")
try:
    print("One-time codes (RFC 6238)")
    sec = auth.totp_new_secret()
    now = 1_800_000_000
    c = now // 30
    ok("a new secret is base32 without padding", len(sec) == 32 and "=" not in sec, sec)
    ok("the code of this step is accepted, and that step returned", auth.totp_check(sec, auth.totp_at(sec, c), now=now) == c)
    ok("…with spaces typed in it too", auth.totp_check(sec, auth.totp_at(sec, c)[:3] + " " + auth.totp_at(sec, c)[3:], now=now) == c)
    ok("the step before and the step after are accepted (clock drift)",
       auth.totp_check(sec, auth.totp_at(sec, c - 1), now=now) == c - 1 and auth.totp_check(sec, auth.totp_at(sec, c + 1), now=now) == c + 1)
    ok("two steps away: refused", auth.totp_check(sec, auth.totp_at(sec, c + 2), now=now) is None
       or auth.totp_at(sec, c + 2) in (auth.totp_at(sec, c), auth.totp_at(sec, c - 1), auth.totp_at(sec, c + 1)))
    ok("a code already used (its step not after the last one): refused", auth.totp_check(sec, auth.totp_at(sec, c), last_counter=c, now=now) is None)
    ok("five digits, letters, or no secret: refused",
       auth.totp_check(sec, "12345", now=now) is None and auth.totp_check(sec, "12a456", now=now) is None
       and auth.totp_check("", auth.totp_at(sec, c), now=now) is None and auth.totp_check(sec, None, now=now) is None)
    uri = auth.totp_uri(sec, "grace mensah")
    ok("the authenticator link names the issuer and the account, escaped", uri.startswith("otpauth://totp/Looking%20Glass:grace%20mensah?secret=" + sec)
       and "digits=6" in uri and "period=30" in uri, uri)
    codes, hashes = auth.new_recovery_codes(3)
    ok("recovery codes: xxxx-xxxx-xxxx, stored only as hashes that match them",
       len(codes) == 3 and all(len(x) == 14 and x.count("-") == 2 for x in codes)
       and all(auth.check_password_hash(h, x) for h, x in zip(hashes, codes)) and not any(x in h for h, x in zip(hashes, codes)))

    print("The e-mail domain check")
    for d in ("example.org", "mail.example.com", "csirt.test", "host.invalid", "box.localhost", "x.local", "a.example"):
        ok(f"{d}: reserved for examples, refused without a look-up", "reserved" in (auth.email_domain_problem(f"grace@{d}") or ""))
    import dns.exception
    import dns.resolver

    class _MX:
        def __init__(self, ex):
            self.exchange = ex
    real_resolver = dns.resolver.Resolver
    answers = {}

    class FakeResolver:
        def __init__(self, *a, **k):
            pass

        def resolve(self, domain, rr):
            a = answers.get(rr)
            if isinstance(a, type) and issubclass(a, Exception):
                raise a()
            if isinstance(a, Exception):
                raise a
            return a
    dns.resolver.Resolver = FakeResolver
    try:
        answers.clear(); answers["MX"] = [_MX("mx1.mail.org.")]
        ok("a domain with a mail server: accepted", auth.email_domain_problem("grace@mail.org") is None)
        answers.clear(); answers["MX"] = [_MX(".")]
        ok("a 'null MX' domain (RFC 7505): it takes no mail", "does not accept email" in (auth.email_domain_problem("grace@nomail.org") or ""))
        answers.clear(); answers["MX"] = dns.resolver.NXDOMAIN
        ok("no such domain: refused", "does not exist" in (auth.email_domain_problem("grace@nowhere-made-up.org") or ""))
        answers.clear(); answers.update(MX=dns.resolver.NoAnswer, A=["192.0.2.10"])
        ok("no MX, but an address record (the fallback MX): accepted", auth.email_domain_problem("grace@a-only.org") is None)
        answers.clear(); answers.update(MX=dns.resolver.NoAnswer, A=dns.resolver.NoAnswer, AAAA=dns.resolver.NoAnswer)
        ok("no MX and no address: cannot receive email", "cannot receive email" in (auth.email_domain_problem("grace@bare.org") or ""))
        answers.clear(); answers.update(MX=dns.resolver.NoNameservers, A=dns.resolver.NXDOMAIN)
        ok("no name servers for MX, then no such domain: refused", "does not exist" in (auth.email_domain_problem("grace@gone.org") or ""))
        answers.clear(); answers.update(MX=dns.resolver.NoAnswer, A=dns.exception.Timeout)
        ok("the address look-up times out: not held against the person", auth.email_domain_problem("grace@slow.org") is None)
        answers.clear(); answers["MX"] = dns.exception.Timeout
        ok("DNS does not answer at all (offline server): not held against the person", auth.email_domain_problem("grace@offline.org") is None)
    finally:
        dns.resolver.Resolver = real_resolver

    print("The country list")
    real_open = open

    def no_iso(p, *a, **k):
        if "iso_3166" in str(p):
            raise OSError("no iso-codes")
        return real_open(p, *a, **k)
    auth.open = no_iso
    try:
        cs = auth.load_countries()
        ok("without the system's iso-codes: the countries of the platform's own map index, sorted by name",
           len(cs) > 10 and ("GH", "Ghana") in cs and [n for _, n in cs] == sorted(n for _, n in cs), str(cs[:3]))

        def nothing(p, *a, **k):
            raise OSError("nothing")
        auth.open = nothing
        ok("…and without that either: Ghana alone", auth.load_countries() == [("GH", "Ghana")])
    finally:
        del auth.open

    print("Profile rules")
    C = {"GH", "KE"}
    pp = auth.profile_problem
    ok("a good profile (domain not looked up): accepted", pp("Grace Mensah", "Example CSIRT", "grace@csirt.org", "GH", C, check_domain=False) is None)
    ok("a name without two letters: refused", "full name" in pp("1 2", "Example CSIRT", "grace@csirt.org", "GH", C, False))
    ok("a name with < or >: refused", "full name" in pp("Grace <b>", "Example CSIRT", "grace@csirt.org", "GH", C, False))
    ok("an organisation of one letter: refused", "organisation" in pp("Grace Mensah", "X", "grace@csirt.org", "GH", C, False))
    ok("an address without a domain: refused", "valid email" in pp("Grace Mensah", "Example CSIRT", "grace@csirt", "GH", C, False))
    ok("a reserved example domain (checked): refused", "reserved" in pp("Grace Mensah", "Example CSIRT", "grace@example.org", "GH", C))
    ok("a country not on the list: refused", pp("Grace Mensah", "Example CSIRT", "grace@csirt.org", "ZZ", C, False) == "Choose your country.")

    print("Password rules")
    pw = auth.password_problem
    ok("short: refused with the length", "at least 12" in pw("grace", "Ab1!"))
    ok("over 200 characters: refused", pw("grace", "Aa1!" * 60) == "That password is too long.")
    ok("no upper case and no symbol: both named", "an upper-case letter and a symbol" in pw("grace", "lowercase12345"))
    ok("only a number missing: named alone", pw("grace", "Lower-Upper-Only!").startswith("Add a number."))
    ok("one character four times in a row: refused", "four times" in pw("grace", "Rivers-1111-Stone!"))
    ok("the user name inside: refused", "your name" in pw("kwame", "Blue-Kwame-River-7!"))
    ok("a part of the person's name (avoid=): refused", "your name" in pw("gm1", "River-Mensah-Lake-7!", avoid=("Grace Mensah",)))
    ok("a common word, even written with digits (p4ssw0rd → password): refused", "common word" in pw("grace", "My-P4ssw0rd-Is-9!"))
    ok("two different passwords: refused", pw("grace", "Steady-Harbour-63!", "Steady-Harbour-64!") == "The two passwords differ.")
    ok("a good password typed twice the same: accepted", pw("grace", "Steady-Harbour-63!", "Steady-Harbour-63!") is None)

    print("Where an address is (offline only)")
    ok("not an address: Unknown", auth.location("not-an-ip") == "Unknown" and auth.location(None) == "Unknown")
    ok("loopback: This computer", auth.location("127.0.0.1") == "This computer" and auth.location("::1") == "This computer")
    ok("private and link-local: Local network", auth.location("10.1.2.3") == "Local network" and auth.location("169.254.1.1") == "Local network")
    real_geo = dict(auth._GEO)

    class Reader:
        def get(self, ip):
            if ip == "198.51.100.66":
                raise ValueError("broken record")
            return {"192.0.2.7": {"city": {"names": {"en": "Accra"}}, "country": {"names": {"en": "Ghana"}}},
                    "203.0.113.9": {"country": {"names": {"en": "Kenya"}}}}.get(ip)
    # the documentation ranges (RFC 5737) count as private in Python: here they stand for Internet addresses
    import ipaddress as _ip
    import types

    class _Global:
        def __init__(self, a):
            self.a = a
        is_loopback = is_private = is_link_local = False

        def __str__(self):
            return str(self.a)
    real_ipmod = auth.ipaddress
    auth.ipaddress = types.SimpleNamespace(ip_address=lambda v: _Global(_ip.ip_address(v)))
    auth._GEO.update(tried=True, reader=Reader())
    ok("with a city database: Internet · city, country", auth.location("192.0.2.7") == "Internet · Accra, Ghana", auth.location("192.0.2.7"))
    ok("…country only", auth.location("203.0.113.9") == "Internet · Kenya")
    ok("…an address it does not know: Internet", auth.location("198.51.100.5") == "Internet")
    ok("…a record that fails to read: Internet, no error", auth.location("198.51.100.66") == "Internet")
    auth._GEO.update(tried=False, reader=None)
    ok("without a database (first look tries to open it): Internet", auth.location("198.51.100.5") == "Internet")
    auth._GEO.clear(); auth._GEO.update(real_geo)
    auth.ipaddress = real_ipmod

    print("Small helpers")
    ok("next= keeps same-site paths only", auth._safe_next("/findings?x=1") == "/findings?x=1" and auth._safe_next("//evil.example") == "/"
       and auth._safe_next("/\\evil.example") == "/" and auth._safe_next("https://evil.example/") == "/" and auth._safe_next("") == "/")
    os.environ["LG_COV_INT"] = "not-a-number"
    ok("a .env number that is not a number: the default", auth._env_int("LG_COV_INT", 7, 1, 10) == 7)
    os.environ["LG_COV_INT"] = "999"
    ok("…a number above the bound: the bound", auth._env_int("LG_COV_INT", 7, 1, 10) == 10)
    del os.environ["LG_COV_INT"]
    ok("an IPv4-mapped loopback is loopback; nonsense is not", auth._is_loopback("::ffff:127.0.0.1") and not auth._is_loopback("x"))
    ok("_is_ip", auth._is_ip("192.0.2.1") and not auth._is_ip("register"))

    print("Accounts file")
    up = os.path.join(tmp, "users.json")
    U = auth.Users(up)
    ok("no file yet: no accounts", U.all() == {} and U.get("grace") is None)
    with open(up, "w") as fh:
        fh.write("{not json")
    ok("a broken file: still no accounts, no error", U.all() == {})
    U.set_password("grace", "Steady-Harbour-63!", role="analyst", status="pending")
    g_ = U.get("grace")
    ok("set_password: a hash, the role and status given, the time the password was set",
       g_ and g_["role"] == "analyst" and g_["status"] == "pending" and g_.get("pw_set_at") and auth.check_password_hash(g_["hash"], "Steady-Harbour-63!"))
    ok("…the file is private (0600)", oct(os.stat(up).st_mode & 0o777) == "0o600")
    U.set_password("kwame", "Another-Harbour-63!")
    ok("…without a role: the lowest role, active", U.get("kwame")["role"] == auth.LOWEST_ROLE and U.get("kwame")["status"] == "active")

    print("Roles")
    rp = os.path.join(tmp, "roles.json")
    with open(rp, "w") as fh:
        json.dump({"researcher": ["definitions"], "analyst": ["view", "management", "users", "export"], "management": ["view"]}, fh)
    R = auth.Roles(rp)
    ok("researchers get 'networks' once (marker file written)", "networks" in R.roles["researcher"]
       and os.path.exists(os.path.join(tmp, ".roles_networks_added")))
    ok("exclusive permissions (management, users) taken off another role", R.perms("analyst") == {"view", "export"}, str(R.perms("analyst")))
    ok("a fixed role keeps exactly its permissions, whatever the file says", R.perms("management") == {"management"})
    ok("admin has every permission; an unknown role none", R.perms("admin") == set(auth.PERMS) and R.perms("nobody") == set())
    R.save({"analyst": ["view", "advisory", "not-a-perm"], "admin": [], "custom": ["view"]})
    saved = json.load(open(rp))
    ok("saving: unknown and exclusive permissions dropped, admin full, fixed roles always there",
       saved["analyst"] == ["view"] and saved["admin"] == list(auth.PERMS) and saved["auditor"] == ["audit"] and saved["custom"] == ["view"], str(saved))
    R2 = auth.Roles(os.path.join(tmp, "missing", "roles.json"))
    ok("no roles file: the defaults", R2.perms("analyst") == set(auth.DEFAULT_ROLES["analyst"]))

    print("Sessions")
    sp = os.path.join(tmp, "sessions.json")
    S = auth.Sessions(sp, idle=60, maximum=3600)
    tok = S.create("grace", "192.0.2.5", "UA-1")
    s, why = S.check(tok, "192.0.2.5", "UA-1")
    ok("a new session checks out, with its CSRF token", s and s["user"] == "grace" and s.get("csrf") and why is None)
    ok("no token, or an unknown one: no session, no reason", S.check("", "x", "y") == (None, None) and S.check("nope", "x", "y") == (None, None))
    s, why = S.check(tok, "192.0.2.6", "UA-1")
    ok("used from another address: ended, with the reason", s is None and why[0] == "used from another address")
    ok("…and gone afterwards", S.check(tok, "192.0.2.5", "UA-1") == (None, None))
    tok = S.create("grace", "192.0.2.5", "UA-1")
    ok("used from another browser: ended", S.check(tok, "192.0.2.5", "UA-2")[1][0] == "used from another browser")
    tok = S.create("grace", "192.0.2.5", "UA-1")
    S.s[auth._h(tok)]["seen"] -= 120
    ok("idle longer than allowed: ended", S.check(tok, "192.0.2.5", "UA-1")[1][0] == "idle timeout")
    tok = S.create("grace", "192.0.2.5", "UA-1")
    S.s[auth._h(tok)]["created"] -= 7200
    ok("older than the maximum: ended", S.check(tok, "192.0.2.5", "UA-1")[1][0] == "maximum age")
    tok = S.create("grace", "192.0.2.5", "UA-1", persist=True)
    S.s[auth._h(tok)]["seen"] -= 120
    ok("stay signed in: 5 days, not the idle setting", S.check(tok, "192.0.2.5", "UA-1")[0] is not None
       and S.limits({"persist": True}) == (auth.Sessions.PERSIST_MAX, auth.Sessions.PERSIST_MAX))
    new = S.rotate(auth._h(tok))
    ok("a new id: the old one stops working, the new one works",
       new and S.check(tok, "192.0.2.5", "UA-1") == (None, None) and S.check(new, "192.0.2.5", "UA-1")[0]["user"] == "grace")
    ok("rotating an unknown session: nothing", S.rotate("no-such-key") is None)
    lst = S.list()
    ok("the list: short id, place, expiry; no token", len(lst) == 1 and len(lst[0]["id"]) == 16 and lst[0]["location"] == "Local network"
       and lst[0]["persist"] and lst[0]["expires"] > time.time())
    ok("ending by the short id", S.end_id(lst[0]["id"])["user"] == "grace" and S.list() == [])
    ok("ending an unknown short id: nothing", S.end_id("0123456789abcdef") is None)
    t1, t2 = S.create("kwame", "192.0.2.5", "UA"), S.create("kwame", "192.0.2.5", "UA")
    ok("ending every session of a person: their count", S.end_user("kwame") == 2 and S.end(token=t1) is None)
    t3 = S.create("ama", "192.0.2.5", "UA")
    S.s[auth._h(t3)]["seen"] -= 3600
    S.prune()
    ok("pruning drops the expired sessions", S.list() == [])
    S2 = auth.Sessions(sp, 60, 3600)
    ok("the sessions file is read back at start (0600)", isinstance(S2.s, dict) and oct(os.stat(sp).st_mode & 0o777) == "0o600")
    with open(sp, "w") as fh:
        fh.write("[broken")
    ok("a broken sessions file: none, no error", auth.Sessions(sp, 60, 3600).s == {})

    print("Failed sign-in counters")
    for k in ("LOGIN_ACCOUNT_FAILS", "LOGIN_ACCOUNT_LOCK_MIN", "LOGIN_ADDRESS_FAILS", "LOGIN_ADDRESS_WINDOW_MIN"):
        os.environ.pop(k, None)
    cp = os.path.join(tmp, "login_counters.json")
    old_t, now_t = time.time() - 10 * 86400, time.time() - 5
    with open(cp, "w") as fh:
        json.dump({"fail": [["192.0.2.9", "grace", [now_t, old_t]], ["bad-row"], ["192.0.2.9", None, ["x"]], ["192.0.2.8", "ama", [old_t]]]}, fh)
    T = auth.Throttle(cp)
    ok("kept counters read back; failures older than the longest window and broken rows dropped",
       T.fail == {("192.0.2.9", "grace"): [now_t]}, str(T.fail))
    with open(cp, "w") as fh:
        fh.write("nope")
    ok("a broken counters file: nothing read, no error", auth.Throttle(cp).fail == {})
    T = auth.Throttle(cp)
    ip = "198.51.100.20"
    ok("nothing locked: the configured lock time; 5 tries left", T.wait_minutes(ip, "grace") == 15 and T.left(ip, "grace") == 5)
    for _ in range(5):
        T.failed(ip, "Grace")
    ok("5 wrong tries for one name: that name is locked from that address (names in any case)", T.locked(ip, "grace") and T.left(ip, "GRACE") == 0)
    ok("…another name from the same address is not", not T.locked(ip, "kwame"))
    w = T.wait_minutes(ip, "grace")
    ok("…minutes left: about the 15-minute lock", 14 <= w <= 15, str(w))
    lo = T.lockouts()
    ok("what is locked: the account from the address", [(x["kind"], x["ip"], x["name"], x["failures"]) for x in lo] == [("account", ip, "grace", 5)], str(lo))
    ok("the counters are kept on disk", json.load(open(cp))["fail"])
    ok("lifting the account lock: one counter cleared", T.unlock(ip, "grace") == 1 and not T.locked(ip, "grace"))
    ok("…lifting it again: nothing to clear", T.unlock(ip, "grace") == 0)
    for i in range(20):
        T.failed(ip, f"name{i}")
    ok("20 failures from one address: the whole address is locked", T.locked(ip, "someone-new"))
    ok("…listed as an address lock", any(x["kind"] == "address" and x["ip"] == ip for x in T.lockouts()))
    ok("…minutes left with no name: the address lock (an hour)", 59 <= T.wait_minutes(ip) <= 60, str(T.wait_minutes(ip)))
    T.count(("register", ip), 3600, add=True)
    ok("registration counters are not sign-in locks", not any(x["ip"] == "register" for x in T.lockouts()))
    ok("lifting the address lock clears every counter of that address", T.unlock(ip) >= 21 and not T.locked(ip, "someone-new"))
    ok("…but not the registration counter", T.count(("register", ip), 3600) == 1)
    T.failed(ip, "grace"); T.ok(ip, "grace")
    ok("a good sign-in clears that name's counter", (ip, "grace") not in T.fail)
    ok("clear_address forgets every key with that address", T.clear_address(ip) >= 1 and T.count(("register", ip), 3600) == 0)
    os.environ["LOGIN_ACCOUNT_FAILS"] = "1"
    ok("a limit below the bound: the bound (3)", auth.Throttle().account_fails == 3)
    del os.environ["LOGIN_ACCOUNT_FAILS"]
    Tm = auth.Throttle()
    Tm.failed(ip, "x")
    ok("without a path nothing is written, and it still counts", Tm.left(ip, "x") == 4)

    print("The audit log")
    ap = os.path.join(tmp, "audit.log")
    with open(os.path.join(tmp, "audit_write_failed.json"), "w") as fh:
        json.dump({"since": 1000.0, "last": 1100.0, "count": 2, "error": "OSError: disk full"}, fh)
    Au = auth.Audit(ap)
    ok("a gap left before a restart is read back, the restart counted", Au.failing and Au.failing["count"] == 2 and Au.failing["restarts"] == 1)
    Au.add("login", user="grace", ip="192.0.2.5", ua="UA")
    rows = Au.records()
    ok("the first entry after it is the gap itself, then the entry", [r["event"] for r in rows] == ["audit_write_failed", "login"]
       and "2 audit entries could not be written" in rows[0]["detail"] and "restarted 1 time" in rows[0]["detail"], str(rows[:1]))
    ok("…the gap file is removed", not os.path.exists(os.path.join(tmp, "audit_write_failed.json")) and Au.failing is None)
    real_append = Au.chain.append

    def broken(rec):
        raise OSError(28, "No space left on device")
    Au.chain.append = broken
    Au.add("logout", user="grace", ip="192.0.2.5", ua="UA")
    Au.add("logout", user="grace", ip="192.0.2.5", ua="UA")
    ok("a write that fails: counted in memory and in the gap file", Au.failing["count"] == 2
       and json.load(open(os.path.join(tmp, "audit_write_failed.json")))["count"] == 2)
    Au.chain.append = real_append
    Au.add("login", user=auth.TEST_PREFIX + "x", ip="127.0.0.1", ua="UA")
    Au.add("view", user="kwame", target="grace", ip="127.0.0.1", ua="LookingGlass-retest/1")
    Au.add("view", user="ama", ip="203.0.113.5", ua="LookingGlass-retest/1")
    rows = Au.records()
    ok("once it works: one gap entry for the 2 lost, then the new entries", [r["event"] for r in rows][2:4] == ["audit_write_failed", "login"]
       and "2 audit entries" in rows[2]["detail"] and "restarted" not in rows[2]["detail"])
    total, shown, hidden = Au.read(selftests=False)
    ok("self-test entries (the reserved prefix, or the retest's client from this computer) hidden on request",
       hidden == 2 and all(not (r.get("user") or "").startswith(auth.TEST_PREFIX) for r in shown), f"{hidden} {total}")
    ok("…the retest's client name from another address is NOT a self-test", any(r["user"] == "ama" for r in shown))
    total, shown, _ = Au.read(q="KWAME", label=lambda n: {"kwame": "Kwame Asante (kwame)"}.get(n, n))
    ok("search ignores case; names are labelled 'Full Name (username)'", total == 1 and shown[0].get("user_label") == "Kwame Asante (kwame)"
       and shown[0].get("selftest") is True, str(shown))
    total, shown, _ = Au.read(limit=1, offset=1)
    ok("limit and offset: one row, the second newest", len(shown) == 1 and shown[0]["user"] == "kwame")
    with open(ap, "a") as fh:
        fh.write("not json\n")
    ok("a line that is not JSON is skipped when reading", len(Au.records()) == len(rows))
    with open(os.path.join(tmp, "audit_write_failed.json"), "w") as fh:
        fh.write("{\"since\": 1}")
    ok("an incomplete gap file is ignored", auth.Audit(ap).failing is None)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
