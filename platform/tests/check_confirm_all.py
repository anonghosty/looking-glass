#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
""""Confirm all" (2026-11-14), with made-up fixtures and throwaway files (no database, no network):
  Definitions page, POST /api/attack/mapping/bulk:
  - confirms exactly the reports sent, as they were shown; a suggestion that changed meanwhile is skipped and named;
  - only Suggested: Not mapped yet / Please check / reviewed are skipped;
  - the same rules as a single confirm: researchers and admins only (403), the security token (403), a cap (400), and
    nothing half-applied when an entry is malformed; one audit entry per report confirmed;
  Advisory editor, POST /api/advisory/<fid>/attack {action: confirm_all}:
  - confirms only the techniques still pending in that advisory (only those shown, when given), never the researchers'
    mappings; advisors only, the security token, one audit entry per technique; the report can then be generated.
Usage: tests/check_confirm_all.py"""
import json
import os
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

RM = {"event4_sinkhole_http": {"type": "infected-system", "section": "Infections", "title": "Sinkhole HTTP Events", "group": ""},
      "event4_sinkhole_dns": {"type": "other", "section": "Infections", "title": "Sinkhole DNS Events", "group": ""},
      "event4_honeypot_brute_force": {"type": "brute-force", "section": "Attacks seen", "title": "Honeypot Brute Force Events", "group": ""},
      "scan_rdp": {"type": "vulnerable-system", "section": "Services", "title": "Accessible RDP Report", "group": ""},
      "scan_fixture_new": {"type": "other", "section": "Services", "title": "A report no rule knows", "group": ""}}

tmp = tempfile.mkdtemp(prefix="lg-confirmall-")
try:
    v2 = ON.build_attack({"enterprise": json.load(open(os.path.join(FIX, "attack_v2.json"), encoding="utf-8"))})
    v2.pop("full", None)
    # the sinkhole DNS rule's T1071.004 and the brute force rule's T1110.001 are in the fixture; add nothing else
    json.dump(dict(v2, fetched="2026-11-14T00:00:00+00:00"), open(os.path.join(tmp, ON.ATTACK_FILE), "w", encoding="utf-8"))
    shutil.copy(os.path.join(ROOT, "data", AM.RULES_FILE), os.path.join(tmp, AM.RULES_FILE))
    rm = {k: dict(v) for k, v in RM.items()}

    import app as A
    import advisory as ADV
    from flask import g
    aud = A.AUTH["audit"]; audited = []
    aud.add = lambda event, **k: audited.append((event, k.get("target"), k.get("detail")))
    keep = {k: getattr(A.ATTACK, k) for k in ("dir", "offline", "report_map", "audit")}
    A.ATTACK.dir, A.ATTACK.offline, A.ATTACK.report_map, A.ATTACK.audit = tmp, ON.OfflineNames(tmp), (lambda: rm), aud
    am = A.ATTACK
    am.sync()

    def call(path, perms, method="GET", body=None, token="good", user="lg-t-x", role="researcher"):
        with A.app.test_request_context(path, method=method, json=body, headers={"X-CSRF-Token": token}):
            g.user = {"user": user, "role": role, "perms": set(perms), "csrf": "good", "created": 9e9}
            ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
            r = A.app.view_functions[ep[0]](**ep[1])
            code = r[1] if isinstance(r, tuple) else r.status_code
            r = r[0] if isinstance(r, tuple) else r
            return code, json.loads(r.get_data(as_text=True) or "{}")

    def shown(*keys):                                    # as the page sends them: each report with the techniques it showed
        return [{"report": k, "techniques": list(am.mapping(k)["techniques"])} for k in keys]

    status = lambda k: (am.mapping(k) or {}).get("status")
    RES = {"definitions"}
    try:
        print("Definitions page: Confirm all")
        ok("the reports start as suggested (and one not mapped yet)", [status(k) for k in ("event4_sinkhole_http", "event4_sinkhole_dns",
           "event4_honeypot_brute_force", "scan_rdp", "scan_fixture_new")] == ["suggested"] * 4 + ["none"])
        st, j = call("/api/attack/mapping/bulk", {"view", "malpedia"}, "POST", {"items": shown("event4_sinkhole_http")})
        ok("an analyst cannot (403)", st == 403 and status("event4_sinkhole_http") == "suggested")
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": shown("event4_sinkhole_http")}, token="forged")
        ok("without the security token: refused (403), nothing changed", st == 403 and status("event4_sinkhole_http") == "suggested")
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": [{"report": f"r{i}", "techniques": ["T1133"]} for i in range(AM.MAX_BULK + 1)]})
        ok(f"more than {AM.MAX_BULK} at once: refused (400)", st == 400 and "At most" in j.get("error", ""))
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": shown("event4_sinkhole_http") + [{"report": "scan_rdp", "techniques": "T1133"}]})
        ok("one malformed entry: refused (400) and nothing half-applied", st == 400 and status("event4_sinkhole_http") == "suggested", j.get("error"))
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": shown("event4_sinkhole_http") * 2})
        ok("a report listed twice: refused (400)", st == 400 and status("event4_sinkhole_http") == "suggested")
        audited.clear()
        sent = shown("event4_sinkhole_http", "event4_honeypot_brute_force") + [{"report": "scan_rdp", "techniques": ["T1133"]},
                                                                              {"report": "scan_fixture_new", "techniques": ["T1133"]}]
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": sent}, user="lg-t-res")
        ok("confirms exactly the reports sent, as shown", st == 200 and sorted(j["confirmed"]) == ["event4_honeypot_brute_force", "event4_sinkhole_http"]
           and status("event4_sinkhole_http") == "reviewed" and status("event4_honeypot_brute_force") == "reviewed", j)
        ok("...a report not sent stays suggested", status("event4_sinkhole_dns") == "suggested")
        sk = {s["report"]: s for s in j.get("skipped", [])}
        ok("a changed suggestion is skipped and named (readable name, the reason)", status("scan_rdp") == "suggested"
           and sk.get("scan_rdp", {}).get("title") == "Accessible RDP Report" and "changed" in sk["scan_rdp"]["reason"], sk.get("scan_rdp"))
        ok("Not mapped yet is never confirmed by Confirm all", status("scan_fixture_new") == "none" and "scan_fixture_new" in sk)
        ok("one audit entry per report confirmed, the same event as a single confirm",
           sorted(t for e, t, _ in audited if e == "attack_mapping_reviewed") == ["event4_honeypot_brute_force", "event4_sinkhole_http"]
           and all("Confirm all" in (d or "") for _, _, d in audited), audited)
        m = am.mapping("event4_sinkhole_http")
        ok("recorded like a single confirm: who, when, the ATT&CK version", m["by"] == "lg-t-res" and m["at"] and m["version"] == "2.0" and not m.get("nofit"))
        st, j = call("/api/attack/mapping/bulk", RES, "POST", {"items": [{"report": "event4_sinkhole_http", "techniques": m["techniques"]}]})
        ok("a reviewed one sent again is skipped (no longer a suggestion)", st == 200 and not j["confirmed"] and j["skipped"][0]["report"] == "event4_sinkhole_http")
        st, j = call("/api/attack/mapping", RES, "POST", {"report": "event4_sinkhole_http", "techniques": ["T1071"]})
        ok("each mapping can still be changed one by one afterwards", st == 200 and am.mapping("event4_sinkhole_http")["techniques"] == ["T1071"])

        print("Advisory editor: Confirm all for this advisory")
        F = A.FINDINGS
        x1 = {"id": "1", "kind": "finding", "status": "advisor", "title": "Fixture finding", "review": {"decision": "researcher"},
              "history": [], "codes": [], "assignee": "lg-t-adv"}
        fkeep = {"get": F.get, "sees": F.sees, "advisory_sent": getattr(F, "advisory_sent", None)}
        F.get = lambda fid: x1 if str(fid) == "1" else None
        F.sees = lambda *a, **k: True
        real_dir, real_org = A.ADVISORIES.dir, A.ORG.path
        A.ADVISORIES.dir, A.ORG.path = os.path.join(tmp, "advisories"), os.path.join(tmp, "organisation.json")
        auto = {"reports": [{"key": k, "title": rm[k]["title"]} for k in ("event4_sinkhole_dns", "scan_rdp", "event4_honeypot_brute_force")],
                "categories": [], "devices": [{"ip": "192.0.2.1", "reports": ["Accessible RDP Report"], "labels": ["windows"], "categories": []}]}
        real_build = AA.build
        ADV.advisory_attack.build = lambda _am, _auto, adv: real_build(am, auto, adv)
        ADVP = {"advisory"}
        try:
            NET = ADV.ALL
            st, j = call("/api/advisory/1/net", ADVP, "POST", {"network": NET, "subject": "Fixture", "description": "d", "actions": "a",
                                                               "recipients": ["Team A"]}, user="lg-t-adv", role="advisor")
            att = j["advisory"]["attack"]
            pend = [t["key"] for t in att["pending"]]
            ok("the advisory has suggested techniques waiting", st == 200 and len(pend) >= 3, pend)
            st, j = call("/api/advisory/1/attack", ADVP, "POST", {"network": NET, "action": "confirm_all"}, token="forged", user="lg-t-adv", role="advisor")
            ok("without the security token: refused (403)", st == 403)
            st, j = call("/api/advisory/1/attack", RES, "POST", {"network": NET, "action": "confirm_all"})
            ok("a researcher cannot confirm for an advisory (403)", st == 403)
            audited.clear()
            st, j = call("/api/advisory/1/attack", ADVP, "POST", {"network": NET, "action": "confirm_all", "keys": pend[:2]}, user="lg-t-adv", role="advisor")
            left = [t["key"] for t in j["advisory"]["attack"]["pending"]]
            ok("confirms only the techniques shown (keys given), the rest stay pending", st == 200 and j["confirmed"] == 2 and left == pend[2:], left)
            ok("one audit entry per technique", [t for e, t, d in audited if e == "advisory_attack_confirm"] and len([1 for e, _, _ in audited if e == "advisory_attack_confirm"]) == 2)
            st, j = call("/api/advisory/1/attack", ADVP, "POST", {"network": NET, "action": "confirm_all"}, user="lg-t-adv", role="advisor")
            ok("then all still pending", st == 200 and not j["advisory"]["attack"]["pending"]
               and all(t["status"] in AA.REVIEWED for t in j["advisory"]["attack"]["techniques"]))
            st, j = call("/api/advisory/1/attack", ADVP, "POST", {"network": NET, "action": "confirm_all"}, user="lg-t-adv", role="advisor")
            ok("nothing left: a clear refusal (400)", st == 400 and "Nothing left" in j.get("error", ""))
            ok("the researchers' mappings are untouched (still suggested globally)", status("event4_sinkhole_dns") == "suggested" and status("scan_rdp") == "suggested")
            st, j = call("/api/advisory/1/generate", ADVP, "POST", {"network": NET}, user="lg-t-adv", role="advisor")
            ok("the report can then be generated", st == 200, j.get("error", ""))
        finally:
            F.get, F.sees = fkeep["get"], fkeep["sees"]
            A.ADVISORIES.dir, A.ORG.path = real_dir, real_org
            ADV.advisory_attack.build = real_build
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
