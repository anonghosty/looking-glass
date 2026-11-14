#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""ATT&CK on CVE and issue cards, and in advisories (2026-11-14), from MITRE CTID's KEV mappings, with made-up fixtures
and throwaway files (no database, no network):
  - the KEV index keeps CTID's technique name (the ATT&CK it mapped with), its comment and the weakness group;
  - a CVE card: each technique with what the mapping means in plain words; renamed since -> the old name noted; revoked
    since -> MITRE's named replacement shown, noted; deprecated -> noted; MITRE's "what it is / how to defend";
  - an issue card gets the techniques of the CVEs it names; one that names none gets none;
  - advisories: a CVE's techniques are suggestions (they hold up the report until the advisor decides) unless an admin
    trusts CTID; that setting is admins only, the security token, audited, off by default;
  - documents: the plain-words mapping and the version note in the PDF / CSV text.
Usage: tests/check_cve_attack.py"""
import json
import os
import re
import shutil
import socket
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
FIX = os.path.join(HERE, "fixtures", "attack_map")

import advisory_attack as AA  # noqa: E402
import attack_map as AM  # noqa: E402
import offline_names as ON  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


OUT = []
_rc, _rcc = socket.socket.connect, socket.create_connection
_loc = lambda a: not isinstance(a, tuple) or str(a[0]).startswith(("127.", "::1", "localhost", "0.0.0.0"))
socket.socket.connect = lambda s, a, *x, **k: _rc(s, a, *x, **k) if _loc(a) else (OUT.append(a), (_ for _ in ()).throw(OSError("refused")))[1]
socket.create_connection = lambda a, *x, **k: _rcc(a, *x, **k) if _loc(a) else (OUT.append(a), (_ for _ in ()).throw(OSError("refused")))[1]

tmp = tempfile.mkdtemp(prefix="lg-cveatt-")
try:
    print("the KEV index")
    kev = AM.build_kev(json.load(open(os.path.join(FIX, "kev_v2.json"), encoding="utf-8")), "mappings/kev/x.json")
    c1 = kev["cves"]["CVE-2099-1001"]
    ok("CTID's technique name, comment and the weakness group are kept", c1["group"] == "code_execution"
       and c1["maps"][0] == ["T1190", "exploitation_technique", "Exploit Public-Facing Application", "Fixture: exploited by sending a crafted request to the web interface."]
       and kev["groups"]["code_execution"] == "Code Execution", c1)
    v2 = ON.build_attack({"enterprise": json.load(open(os.path.join(FIX, "attack_v2.json"), encoding="utf-8"))})
    v2.pop("full", None)
    json.dump(dict(v2, fetched="2026-11-14T00:00:00+00:00"), open(os.path.join(tmp, ON.ATTACK_FILE), "w", encoding="utf-8"))
    json.dump(kev, open(os.path.join(tmp, AM.KEV_FILE), "w", encoding="utf-8"))
    shutil.copy(os.path.join(ROOT, "data", AM.RULES_FILE), os.path.join(tmp, AM.RULES_FILE))
    rm = {"scan_rdp": {"type": "vulnerable-system", "section": "Services", "title": "Accessible RDP Report", "group": ""}}
    am = AM.AttackMap(tmp, ON.OfflineNames(tmp), report_map=lambda: rm, report_defs=lambda: {})

    print("a CVE card (installed ATT&CK v2.0, CTID mapped with v1.0)")
    a = am.cve_attack("cve-2099-1001")
    by = {t["mapped_id"] or t["id"]: t for t in a["techniques"]}
    t1190 = by["T1190"]
    ok("plain words for the mapping type", [t["kind"] for t in a["techniques"]] == ["how attackers exploit it", "what attackers gain first", "what attackers can do next"])
    ok("renamed since: the current name, the old one noted", t1190["name"] == "Exploit Internet-Facing Application"
       and t1190["note"] == "renamed since ATT&CK v1.0 (was “Exploit Public-Facing Application”)", t1190["note"])
    rev = by["T9001"]
    ok("revoked since: MITRE's named replacement is shown, with a note naming both", rev["id"] == "T1071.001" and rev["mapped_id"] == "T9001"
       and "names T1071.001 as its replacement" in rev["note"] and "T9001 Old Fixture Channel" in rev["note"], rev)
    dep = by["T9002"]
    ok("deprecated with no replacement: noted", "deprecated by MITRE since ATT&CK v1.0" in dep["note"])
    ok("CTID's comment and MITRE's what-it-is / how-to-defend travel with it", t1190["comment"].startswith("Fixture: exploited")
       and rev["desc"] and rev["defend"] and rev["defend"][0]["id"] in ("M1031", "M1037"))
    ok("the weakness in readable words, the source line with CTID's ATT&CK version", a["weakness"] == "Code Execution"
       and a["source"] == "CTID Mappings Explorer, KEV mappings (ATT&CK 1.0)" and "Apache License 2.0" in a["licence"])
    ok("an index written before the names were kept still reads", am.cve_attack("CVE-2099-0404") is None)
    old = dict(kev, cves={"CVE-2099-2000": [["T1133", "exploitation_technique"]]})
    json.dump(old, open(os.path.join(tmp, "old_kev.json"), "w"))
    am_old = AM.AttackMap(tmp, ON.OfflineNames(tmp), report_map=lambda: rm, report_defs=lambda: {})
    am_old.kev = lambda: old
    ok("...an old-format entry gives its techniques without notes", [t["id"] for t in am_old.cve_attack("CVE-2099-2000")["techniques"]] == ["T1133"])

    print("issue cards")
    iss = am.issue_attack({"kind": "issue", "title": "Fixture appliance flaw", "description": "Tracked as CVE-2099-1002 and cve-2099-1001."}, "Fixture flaw")
    ok("an issue card gets the techniques of the CVEs it names, each marked", iss and iss["cves"] == ["CVE-2099-1002", "CVE-2099-1001"]
       and {t["cve"] for t in iss["techniques"]} == {"CVE-2099-1001", "CVE-2099-1002"}, iss and iss.get("cves"))
    ok("an issue that names no mapped CVE gets none", am.issue_attack({"kind": "issue", "title": "Expired certificate"}, "Expired certificate") is None)
    lines = AM.attack_lines(iss)
    ok("PDF / CSV text: the CVE, the plain-words mapping, the version note", any("CVE-2099-1001: T1071.001 Web Protocols (what attackers gain first; CTID mapped T9001" in ln for ln in lines), lines[:1])

    print("advisories: CVE techniques under the reviewed-only rule")
    devices = [{"ip": "192.0.2.5", "cves": ["CVE-2099-1002"], "reports": [], "labels": [], "categories": []}]
    auto = {"reports": [], "categories": [], "cves": ["CVE-2099-1002"], "devices": devices}
    att = AA.build(am, auto, {})
    ok("not trusted (the default): the CVE's techniques wait for the advisor", not att["techniques"] and [t["id"] for t in att["pending"]] == ["T1133"]
       and AA.pending_text(att), att)
    w = att["pending"][0]["why_here"]
    ok("why it is here: CTID's mapping in plain words, the host count, no address", w.startswith("MITRE CTID maps CVE-2099-1002 to this technique (how attackers exploit it)")
       and "1 host in this advisory has it" in w and not IP_RX.search(json.dumps(att)), w)
    ok("its key names the CVE and the mapping", att["pending"][0]["key"] == "T1133|cve:CVE-2099-1002:exploitation_technique")

    import app as A
    from flask import g
    aud = A.AUTH["audit"]; audited = []
    aud.add = lambda event, **k: audited.append((event, k.get("detail")))
    keep = {k: getattr(A.ATTACK, k) for k in ("dir", "offline", "report_map", "audit")}
    A.ATTACK.dir, A.ATTACK.offline, A.ATTACK.report_map, A.ATTACK.audit = tmp, ON.OfflineNames(tmp), (lambda: rm), aud

    def call(path, perms, method="GET", body=None, token="good", user="lg-t-x", role="admin"):
        with A.app.test_request_context(path, method=method, json=body, headers={"X-CSRF-Token": token}):
            g.user = {"user": user, "role": role, "perms": set(perms), "csrf": "good", "created": 9e9}
            ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
            r = A.app.view_functions[ep[0]](**ep[1])
            code = r[1] if isinstance(r, tuple) else r.status_code
            r = r[0] if isinstance(r, tuple) else r
            return code, json.loads(r.get_data(as_text=True) or "{}")
    try:
        cv = A._with_attack({"kind": "issue", "title": "Fixture flaw", "description": "see CVE-2099-1002"}, "Fixture flaw")
        ok("services cards: an issue naming a CVE gets its techniques (app hook)", [t["id"] for t in cv["attack"]["techniques"]] == ["T1133"])
        s, j = call("/api/attack", {"definitions"}, role="researcher")
        ok("the setting is off by default; researchers see it, without the switch", s == 200 and j["summary"]["ctid_trust"]["on"] is False and j["can_admin"] is False)
        s, j = call("/api/attack/ctid-trust", {"definitions"}, "POST", {"trust": True}, role="researcher")
        ok("a researcher cannot change it (403)", s == 403)
        s, j = call("/api/attack/ctid-trust", {"settings"}, "POST", {"trust": True}, token="forged")
        ok("an admin without the security token: refused (403)", s == 403 and A.ATTACK.ctid_trust()["on"] is False)
        s, j = call("/api/attack/ctid-trust", {"settings"}, "POST", {"trust": "yes"})
        ok("a wrong type: refused (400)", s == 400)
        s, j = call("/api/attack/ctid-trust", {"settings"}, "POST", {"trust": True}, user="lg-t-admin")
        ok("an admin trusts CTID; audited", s == 200 and j["ctid_trust"]["on"] and j["ctid_trust"]["by"] == "lg-t-admin"
           and audited and audited[-1][0] == "attack_ctid_trust", audited[-1:])
        att2 = AA.build(A.ATTACK, auto, {})
        ok("trusted: the CVE's techniques go out as reviewed, marked trusted", [t["id"] for t in att2["techniques"]] == ["T1133"] and not att2["pending"]
           and att2["techniques"][0]["trusted"] and "administrators trust CTID" in att2["techniques"][0]["why_here"])
        snap = AA.snapshot(att2)
        ok("the generated report keeps the CVE, the mapping, CTID's comment", snap["techniques"][0]["cve"] == "CVE-2099-1002"
           and snap["techniques"][0]["comment"] == "Fixture: logs in without a password." and snap["techniques"][0]["kind"] == "how attackers exploit it")
        s, j = call("/api/attack/ctid-trust", {"settings"}, "POST", {"trust": False})
        ok("switched off again: suggestions once more", s == 200 and AA.build(A.ATTACK, auto, {})["pending"])
        import advisory_pdf  # noqa: F401  (the advisory PDF's CVE lines are rendered by check_advisory_attack's flow)
    finally:
        for k, v in keep.items():
            setattr(A.ATTACK, k, v)
        del aud.add
    ok("nothing left the server", not OUT, OUT[:3])
finally:
    socket.socket.connect, socket.create_connection = _rc, _rcc
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
