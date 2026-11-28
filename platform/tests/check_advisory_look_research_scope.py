#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""Reviewers' findings, production release 2026-11-26, on made-up data in a temporary folder (no database, nothing of
the installation read or written):

1. An advisory's look and page name (POST /api/advisory/<fid>/net, advisory.py on a small app of its own): a value
   that is not offered (a made-up look, a list, a number) answers 400 and nothing is written; the history keeps every
   entry it had (insights added / left out, the look chosen) and gains one per real change.
2. can_research (/api/findings): true exactly for the roles that hold the Definitions or Settings permission
   (researcher, admin), false for every other built-in role.
3. Settings → Constituency (/api/settings/address-blocks): every saved range and every saved network is in the answer
   the Settings page reads, also ranges with no records today and more ranges than a list shows.
Run: .venv/bin/python tests/check_advisory_look_research_scope.py"""
import glob
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
os.environ["TRUST_PROXY"] = "0"
os.environ.setdefault("LG_STEPUP_TESTS_OFF", "1")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:400]}]" if info and not cond else ""), flush=True)


tmp = tempfile.mkdtemp(prefix="lg-check-advlook-")
try:
    # ------------------------------------------------------------------ 1. look and brand
    print("1. An advisory's look and page name: only the offered values")
    from flask import Flask, g
    import advisory

    X = {"id": "7", "title": "Made-up finding", "status": "advisor", "kind": "finding", "review": {"decision": "both"},
         "history": [], "codes": ["c0ffee01"], "network": ""}

    class F:
        get = staticmethod(lambda fid: X if str(fid) == "7" else None)
        sees = staticmethod(lambda x, user, admin: True)
        shown = staticmethod(lambda x: {"status_label": "With the advisor"})

    class Org:
        get = staticmethod(lambda: {"name": "Made-up CSIRT", "logo": None})

    fapp = Flask("advlook")
    perms = {"advisory", "view"}
    advisory.install(fapp, {"base_dir": tmp, "findings": F(), "book": object(), "org": Org(), "has_perm": lambda p: p in perms,
                            "csrf_ok": lambda: True, "fresh": lambda: True, "is_demo": lambda: False,
                            "audit": type("Au", (), {"add": lambda self, *a, **k: None})(), "people_name": lambda u: u,
                            "title_of": lambda n: n, "describe": lambda c: {}, "network": lambda a: "", "scope_text": lambda: "Made-up",
                            "attack": None})

    @fapp.before_request
    def _who():
        g.user = {"user": "made-up-advisor", "role": "advisor", "perms": perms}
    c = fapp.test_client()
    base = {"subject": "Made-up advisory", "network": "", "recipients": []}

    def stored():
        files = glob.glob(os.path.join(tmp, "data", "advisories", "ADV-*.json"))
        return json.load(open(files[0], encoding="utf-8")) if files else None

    def save(**kw):
        a = stored()
        return c.post("/api/advisory/7/net", json=dict(base, **({"rev": a["rev"]} if a else {}), **kw))
    r = save(insights=True)
    ok("a new advisory is saved", r.status_code == 200 and stored(), (r.status_code, r.get_data(as_text=True)[:200]))
    r = save(insights=False)
    r = save(insights=True, look="plain")
    a0 = stored() or {}
    hist0 = [h["what"] for h in a0.get("history") or []]
    ok("…its history holds the insights changes and the look chosen", r.status_code == 200 and "insights left out" in hist0
       and "insights added" in hist0 and "look: plain (white pages)" in hist0, hist0)
    bad = []
    for key, val in (("look", "neon"), ("look", ["plain"]), ("look", 3), ("look", None), ("brand", "someone-else"),
                     ("brand", {"x": 1}), ("brand", "")):
        r = save(insights=False, **{key: val})
        a = stored() or {}
        if r.status_code != 400 or a.get("rev") != a0.get("rev") or [h["what"] for h in a.get("history") or []] != hist0 \
                or a.get("insights") is not True or a.get(key) != a0.get(key):
            bad.append(f"{key}={val!r}: {r.status_code}, rev {a.get('rev')}, insights {a.get('insights')}")
    ok("a look or page name not offered: 400, nothing written, the history and insights as they were", not bad, bad)
    r = save(insights=True, look="plain", brand="none")
    a = stored() or {}
    hist = [h["what"] for h in a.get("history") or []]
    ok("a real change after them: saved, every earlier entry kept, the new name entry added",
       r.status_code == 200 and hist[:len(hist0)] == hist0 and "name on its pages: no name" in hist and a.get("brand") == "none", hist)

    # ------------------------------------------------------------------ 2. can_research, per role
    print("2. can_research: exactly the roles that research")
    import app as A
    import auth
    AU = A.AUTH
    users, roles, sessions, audit = AU["users"], AU["roles"], AU["sessions"], AU["audit"]
    saved = dict(get=users.get, spath=sessions.path, s=dict(sessions.s), add=audit.add)
    sessions.path = os.path.join(tmp, "sessions.json")
    sessions.s.clear()
    audit.add = lambda *a, **k: None
    try:
        UA = "lg-check-advlook"
        got, refused = {}, []
        for role in sorted(auth.DEFAULT_ROLES):
            name = auth.TEST_PREFIX + "role-" + role
            users.get = (lambda n, _n=name, _r=role: {"status": "active", "role": _r, "changed": 0} if n == _n else saved["get"](n))
            tok = sessions.create(name, "127.0.0.1", UA)
            cl = A.app.test_client()
            cl.set_cookie("lg_session", tok)
            r = cl.get("/api/findings", headers={"User-Agent": UA})
            if r.status_code == 200:
                got[role] = bool((r.json or {}).get("can_research"))
            else:
                refused.append(role)
            sessions.end(tok)
        perms_of = {r: set(roles.perms(r)) for r in auth.DEFAULT_ROLES}
        want = {r: bool(p & {"definitions", "settings"}) for r, p in perms_of.items() if r in got}
        ok("every role that opens the findings gets can_research exactly when it researches (Definitions or Settings)",
           got == want and got.get("researcher") is True and got.get("admin") is True, (got, want))
        ok("…no other role (analyst, management, advisor, auditor, external)",
           not any(v for r, v in got.items() if r not in ("researcher", "admin")), got)
        ok("…roles kept out of the findings are refused there, never told they research", all(r not in got for r in refused))
    finally:
        users.get, audit.add = saved["get"], saved["add"]
        sessions.path = saved["spath"]
        sessions.s.clear()
        sessions.s.update(saved["s"])

    # ------------------------------------------------------------------ 3. the constituency payload
    print("3. Settings → Constituency: every saved range and network in what the Settings page reads")
    st = A.settings
    keep = (dict(st.data), st.asns, st.nets, st.restricted)
    # made-up AS numbers far from any real network (not in the registry, no records), and documentation ranges
    reg = A.asn_registry.all()
    nets = [str(a) for a in range(4200000100, 4200000400) if str(a) not in reg][:300]
    ranges = [f"198.51.100.{n * 4}/30" for n in range(60)] + ["203.0.113.0/26", "2001:db8:100::/48"]
    sessions.path = os.path.join(tmp, "sessions.json")
    adm = auth.TEST_PREFIX + "scope-admin"
    users.get = lambda n: {"status": "active", "role": "admin", "changed": 0} if n == adm else saved["get"](n)
    audit.add = lambda *a, **k: None
    tok = sessions.create(adm, "127.0.0.1", "lg-check-advlook")
    try:
        st.data = dict(st.data, networks=list(nets), cidrs=list(ranges))        # in memory only: nothing is saved
        st._compile()
        cl = A.app.test_client()
        cl.set_cookie("lg_session", tok)
        r = cl.get("/api/settings", headers={"User-Agent": "lg-check-advlook"})
        d = r.json or {}
        sv = d.get("settings") or {}
        ok("the saved settings carry every range and network", r.status_code == 200 and sv.get("cidrs") == ranges
           and sv.get("networks") == nets, r.status_code)
        listed = {a for c in d.get("networks") or [] for a in c.get("asns") or []}
        missing = [a for a in nets if a not in listed]
        ok(f"all {len(nets)} saved networks are in the networks the page lists (none in the registry, none with records)",
           not missing, f"{len(missing)} missing, e.g. {missing[:3]}")
        r = cl.get("/api/settings/address-blocks?summary=1", headers={"User-Agent": "lg-check-advlook"})
        info = (r.json or {}).get("info") or {}
        ok(f"all {len(ranges)} saved ranges have their row in the constituency summary (none with records today)",
           r.status_code == 200 and all(x in info for x in ranges), [x for x in ranges if x not in info][:4])
    finally:
        st.data, st.asns, st.nets, st.restricted = keep
        sessions.end(tok)
        users.get, audit.add = saved["get"], saved["add"]
        sessions.path = saved["spath"]
        sessions.s.clear()
        sessions.s.update(saved["s"])
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {'; '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
