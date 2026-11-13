#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""MITRE ATT&CK in advisories (advisory_attack.py), with made-up fixtures and throwaway files (no database, no network):
  - the index keeps MITRE's short definition (whole sentences, citations and links removed), the detection text, and
    each technique's mitigations (deprecated ones left out); the full text goes to its own file;
  - "How to defend" puts the mitigations that suit the kind of report first (M1035 for an exposed service, network
    filtering for C2); "Why it is in this advisory" is Looking Glass's own text, with counts and products, no address;
  - ONLY REVIEWED MAPPINGS GO TO RECIPIENTS: through the real advisory routes, a suggested mapping blocks generating the
    report until the advisor confirms or removes it (server side), the choice is audited and changes the content
    fingerprint, the generated report keeps what it carried, and a sent advisory shows exactly that;
  - the routes: advisors only, the security token, MITRE's full text for readers only.
Usage: tests/check_advisory_attack.py"""
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

tmp = tempfile.mkdtemp(prefix="lg-advatt-")
try:
    print("the index: MITRE's definitions and mitigations")
    v2 = ON.build_attack({"enterprise": json.load(open(os.path.join(FIX, "attack_v2.json"), encoding="utf-8"))})
    t = v2["techniques"]
    d = t["T1071.001"]["desc"]
    ok("short definition: citations and links removed, whole sentences, at most about 300 characters",
       d.startswith("Fixture: adversaries may talk to their servers over web protocols to blend in. A second fixture sentence")
       and "Citation" not in d and "](" not in d and len(d) <= 300 and "third" not in d, d)
    ok("the detection text, when MITRE gives one", t["T1133"].get("detect") == "Fixture: watch logins to remote services from unusual places.")
    ok("mitigations per technique, with what each means there; deprecated ones left out",
       [m[0] for m in t["T1133"]["mitigations"]] == ["M1042", "M1035"] and "Citation" not in t["T1133"]["mitigations"][0][1], t["T1133"]["mitigations"])
    ok("the mitigations' names kept once, compactly", v2["mitigations"]["M1035"]["name"] == "Limit Access to Resource Over Network" and "M1999" not in v2["mitigations"])
    ok("the full text kept apart (its own file)", "full" in v2 and "third fixture sentence" in v2["full"]["T1071.001"])
    full = v2.pop("full")
    json.dump(dict(v2, fetched="2026-11-13T00:00:00+00:00"), open(os.path.join(tmp, ON.ATTACK_FILE), "w", encoding="utf-8"))
    json.dump({"versions": v2["versions"], "descriptions": full}, open(os.path.join(tmp, ON.FULL_FILE), "w", encoding="utf-8"))
    shutil.copy(os.path.join(ROOT, "data", AM.RULES_FILE), os.path.join(tmp, AM.RULES_FILE))
    rm = {"scan_rdp": {"type": "vulnerable-system", "section": "Services", "title": "Accessible RDP Report", "group": ""},
          "event4_sinkhole_http": {"type": "infected-system", "section": "Infections", "title": "Sinkhole HTTP Events", "group": ""}}
    am = AM.AttackMap(tmp, ON.OfflineNames(tmp), report_map=lambda: rm, report_defs=lambda: {})
    am.sync()
    am.review("scan_rdp", ["T1133"], False, "", "lg-t-res")              # reviewed; the sinkhole one stays suggested
    ok("How to defend, exposed service: M1035 Limit Access to Resource Over Network first",
       [m["id"] for m in am.tech("T1133", role="exposure")["defend"]] == ["M1035", "M1042"])
    ok("How to defend, C2: network filtering / prevention first", [m["id"] for m in am.tech("T1071.001", role="used")["defend"]] == ["M1031", "M1037"])
    ok("MITRE's full text on request", "third fixture sentence" in am.full_description("T1071.001")["description"] and am.full_description("../x") is None)

    print("the advisory's techniques")
    devices = [{"ip": "192.0.2.10", "reports": ["Accessible RDP Report"], "labels": ["windows", "rdp"], "categories": []},
               {"ip": "192.0.2.11", "reports": ["Accessible RDP Report"], "labels": ["windows"], "categories": []},
               {"ip": "192.0.2.12", "reports": ["Sinkhole HTTP Events"], "labels": [], "categories": ["quietbot"]}]
    auto = {"reports": [{"key": "scan_rdp", "title": "Accessible RDP Report"}, {"key": "event4_sinkhole_http", "title": "Sinkhole HTTP Events"}],
            "categories": [], "devices": devices}
    att = AA.build(am, auto, {})
    out = {x["id"]: x for x in att["techniques"]}
    ok("reviewed mappings go out; suggested ones wait for the advisor", list(out) == ["T1133"] and [x["id"] for x in att["pending"]] == ["T1071.001"])
    w = out["T1133"]["why_here"]
    ok("Why it is in this advisory: Looking Glass's words, the role, counts and products", w.startswith("Looking Glass maps the report “Accessible RDP Report”")
       and "2 hosts in this advisory are in it (most often: windows, rdp)" in w, w)
    ok("...never an address", not IP_RX.search(json.dumps(att)))
    ok("What it is and How to defend travel with each technique", out["T1133"]["desc"].startswith("Fixture: adversaries may use remote services")
       and out["T1133"]["defend"][0]["id"] == "M1035")
    ok("for recipients: nothing pending", [x["id"] for x in AA.for_recipients(att)["techniques"]] == ["T1133"])
    ok("the refusal names what waits, each once", "only suggested, not reviewed (T1071.001 Web Protocols)" in AA.pending_text(att), AA.pending_text(att))
    nover = AM.AttackMap(tmp, None, report_map=lambda: rm, report_defs=lambda: {})
    ok("without a downloaded ATT&CK copy an advisory has no ATT&CK section (nothing to hold up)", AA.build(nover, auto, {}) is None)

    print("the real advisory routes (throwaway finding and advisory store)")
    import app as A
    import advisory as ADV
    from flask import g
    F = A.FINDINGS
    x1 = {"id": "1", "kind": "finding", "status": "advisor", "title": "Fixture finding", "review": {"decision": "researcher"},
          "history": [], "codes": [], "assignee": "lg-t-adv"}
    keep = {"get": F.get, "sees": F.sees, "advisory_sent": getattr(F, "advisory_sent", None)}
    F.get = lambda fid: x1 if str(fid) == "1" else None
    F.sees = lambda *a, **k: True
    F.advisory_sent = lambda *a, **k: None
    real_dir, real_org = A.ADVISORIES.dir, A.ORG.path
    A.ADVISORIES.dir, A.ORG.path = os.path.join(tmp, "advisories"), os.path.join(tmp, "organisation.json")
    real_build = AA.build
    ADV.advisory_attack.build = lambda _am, _auto, adv: real_build(am, auto, adv)    # the fixture ATT&CK and devices
    aud = A.AUTH["audit"]; audited = []
    aud.add = lambda *a, **k: audited.append(a[0] if a else "")

    def call(path, perms=("advisory",), method="GET", body=None, token="good", raw=False):
        with A.app.test_request_context(path, method=method, json=body, headers={"X-CSRF-Token": token}):
            g.user = {"user": "lg-t-adv", "role": "advisor", "perms": set(perms), "csrf": "good", "created": 9e9}
            ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
            r = A.app.view_functions[ep[0]](**ep[1])
            code = r[1] if isinstance(r, tuple) else r.status_code
            r = r[0] if isinstance(r, tuple) else r
            return (code, r.get_data()) if raw else (code, json.loads(r.get_data(as_text=True) or "{}"))
    try:
        NET = ADV.ALL
        st, j = call("/api/advisory/1/net", method="POST", body={"network": NET, "subject": "Fixture advisory", "description": "d", "actions": "a",
                                                                   "recipients": ["Team A"]})
        ok("the advisor saves the advisory", st == 200, j.get("error", ""))
        a = j["advisory"]["attack"]
        ok("the advisor sees the suggested mapping flagged", [x["id"] for x in a["pending"]] == ["T1071.001"] and [x["id"] for x in a["techniques"]] == ["T1133"])
        st, j = call("/api/advisory/1/generate", method="POST", body={"network": NET})
        ok("SERVER: generating the report is refused while a mapping is only suggested (409)", st == 409 and "only suggested, not reviewed" in j.get("error", ""), j)
        key = a["pending"][0]["key"]
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": key, "action": "confirm"}, token="forged")
        ok("a decision without the security token is refused (403)", st == 403)
        st, j = call("/api/advisory/1/attack", ("view", "malpedia"), "POST", {"network": NET, "key": key, "action": "confirm"})
        ok("only advisors decide (403 for an analyst)", st == 403)
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": "T9999|nowhere", "action": "confirm"})
        ok("a technique that is not in the advisory is refused (400)", st == 400)
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": key, "action": "sneak"})
        ok("an unknown action is refused (400)", st == 400)
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": key, "action": "confirm"})
        ok("the advisor confirms it for this advisory", st == 200 and [x["status"] for x in j["advisory"]["attack"]["techniques"]] == ["reviewed", "confirmed for this advisory"]
           and not j["advisory"]["attack"]["pending"] and "advisory_attack_confirm" in audited, j.get("error", ""))
        st, j = call("/api/advisory/1/generate", method="POST", body={"network": NET})
        ok("then the report is generated", st == 200, j.get("error", ""))
        store = A.ADVISORIES
        adv = store.of("1", NET)
        snap = adv["reports"][-1]["attack"]
        ok("the report keeps what it carried: reviewed and confirmed ones, with MITRE's texts and the version",
           snap["version"] == "2.0" and [x["id"] for x in snap["techniques"]] == ["T1133", "T1071.001"]
           and all(x["status"] in AA.REVIEWED and x.get("desc") and x.get("why_here") for x in snap["techniques"])
           and adv["reports"][-1]["attack_version"] == "2.0", snap)
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": key, "action": "remove"})
        ok("removing it after generating makes the report out of date", st == 200 and ADV.report_stale(store.of("1", NET)))
        st, j = call("/api/advisory/1/drafted", method="POST", body={"network": NET})
        ok("...so it cannot be marked drafted until generated again", st == 409)
        st, j = call("/api/advisory/1/generate", method="POST", body={"network": NET})
        snap = store.of("1", NET)["reports"][-1]["attack"]
        ok("generated again: the removed technique is not in it", st == 200 and [x["id"] for x in snap["techniques"]] == ["T1133"])
        st, j = call("/api/advisory/1/export?network=")
        ok("the JSON export carries only reviewed mappings, with MITRE's texts", [x["id"] for x in (j.get("mitre_attack") or {}).get("techniques", [])] == ["T1133"]
           and j["mitre_attack"]["techniques"][0]["defend"][0]["id"] == "M1035" and not IP_RX.search(json.dumps(j.get("mitre_attack"))), j.get("mitre_attack"))
        st, j = call("/api/advisory/1/drafted", method="POST", body={"network": NET})
        ok("marked drafted", st == 200, j.get("error", ""))
        a2 = store.of("1", NET)                            # a report that somehow carries an unreviewed mapping is never sent
        a2["reports"][-1]["attack"]["techniques"][0]["status"] = "suggested"
        store.save(a2)
        st, j = call("/api/advisory/1/send", method="POST", body={"network": NET, "recipients": ["Team A"]})
        ok("SERVER: a report carrying an unreviewed mapping is never sent (409)", st == 409 and "not reviewed" in j.get("error", ""), j)
        a2 = store.of("1", NET); a2["reports"][-1]["attack"]["techniques"][0]["status"] = "reviewed"; store.save(a2)
        st, j = call("/api/advisory/1/send", method="POST", body={"network": NET, "recipients": ["Team A"]})
        ok("sent", st == 200, j.get("error", ""))
        am.review("event4_sinkhole_http", ["T1071.004"], False, "", "lg-t-res")     # mappings change after sending...
        st, j = call("/api/advisory/1/net?network=")
        ok("a sent advisory shows what went out, not today's mappings", [x["id"] for x in j["advisory"]["attack"]["techniques"]] == ["T1133"]
           and j["advisory"]["attack"]["version"] == "2.0", j["advisory"].get("attack"))
        st, j = call("/api/advisory/1/attack", method="POST", body={"network": NET, "key": key, "action": "restore"})
        ok("a sent advisory's choices cannot change (409)", st == 409)
        print("MITRE's full text")
        keep_full = A.ATTACK.dir
        A.ATTACK.dir = tmp
        try:
            st, j = call("/api/attack/technique/T1071.001", ("advisory",))
            ok("readers (an advisor) get MITRE's full description, with the notice", st == 200 and "third fixture sentence" in j["description"]
               and "MITRE Corporation" in j["notice"])
            st, j = call("/api/attack/technique/T1071.001", ("audit",))
            ok("other roles do not (403)", st == 403)
        finally:
            A.ATTACK.dir = keep_full
        import auth
        ok("advisors and management reach it through the path gate", any("/api/attack/technique/T1133".startswith(p) for p in auth.ADVISORY_PATHS)
           and any("/api/attack/technique/T1133".startswith(p) for p in auth.MANAGEMENT_PATHS))
    finally:
        F.get, F.sees = keep["get"], keep["sees"]
        if keep["advisory_sent"]:
            F.advisory_sent = keep["advisory_sent"]
        A.ADVISORIES.dir, A.ORG.path = real_dir, real_org
        ADV.advisory_attack.build = real_build
        del aud.add
    ok("nothing left the server", not OUT, OUT[:3])
finally:
    socket.socket.connect, socket.create_connection = _rc, _rcc
    shutil.rmtree(tmp, ignore_errors=True)

print("The PDF keeps each technique on one page")
# a render on 2026-11-13 showed a technique's "How to defend" on the page after its other lines (advisory_pdf.py)
import advisory_pdf as APDF  # noqa: E402
_para, drawn = APDF.Flow.para, []


def _rec(self, text, *a, **k):
    p0 = self.doc.page
    _para(self, text, *a, **k)
    drawn.append((p0, self.doc.page, str(text)))


APDF.Flow.para = _rec
try:
    long = "Adversaries may leverage external-facing remote services to get in. " * 3
    techs = [{"id": f"T90{i:02d}", "name": f"Keep {i}", "tactics": ["Initial Access"], "certainty": "possible",
              "certainty_label": "Possible", "role": "attackers can use this exposure for it", "report": f"R{i}", "desc": long,
              "why_here": f"Looking Glass maps the report R{i} to this technique. {i + 2} hosts in this advisory are in it.",
              "defend": [{"id": f"M10{j}", "name": f"Mitigation {j}", "text": "Limit access to the service from the internet."} for j in range(3)],
              "url": f"https://attack.mitre.org/techniques/T90{i:02d}"} for i in range(9)]
    adv = {"logo": None, "title": "Keep", "ref": "ADV-T", "recipients": "", "labels": [], "reports": [], "description": "d",
           "kinds_line": "", "impact": [], "actions": "a", "header": "h", "tlp": "TLP:AMBER", "attack": {"version": "20.1", "techniques": techs}}
    APDF.alone(adv, {"platform_label": "Advisory", "scope": "s", "header": "h", "selection": "s", "day": "2026-11-13", "generated_by": "t"})
    split = []
    for t in techs:
        mine = [i for i, (_, _, s) in enumerate(drawn) if s.startswith(f"{t['id']} ")]
        end = [i for i, (_, _, s) in enumerate(drawn) if s.endswith(f"/techniques/{t['id']}")]
        block = drawn[mine[0]:end[0] + 1] if mine and end else []
        if len({p for p0, p1, _ in block for p in (p0, p1)}) != 1:
            split.append(t["id"])
    ok("every technique's lines, from its heading to its MITRE link, are on one page", techs and not split, split)
    ok("…and the PDF spans several pages, so page breaks were really tested", max(p1 for _, p1, _ in drawn) >= 3)
except Exception as e:      # noqa: BLE001
    ok("every technique's lines, from its heading to its MITRE link, are on one page", False, f"{type(e).__name__}: {e}")
finally:
    APDF.Flow.para = _para

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
