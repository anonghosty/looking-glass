#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""MITRE ATT&CK mapping (attack_map.py), with small made-up fixtures (tests/fixtures/attack_map: two ATT&CK versions
and a KEV mapping file) and no network (every connection leaving the machine is refused and counted):
  - the index: techniques with tactics and state, MITRE's named replacement of a revoked technique, software links, groups;
  - the shipped rule table: the suggested technique, certainty and role for the report kinds the design names;
  - mappings: suggested on first arrival, reviewed by a researcher (checked input, audited), never overwritten by a
    suggestion, back to "please check" when Shadowserver changes the report;
  - a new ATT&CK version: revoked -> replacement suggested and "retired in vN"; deprecated -> check; split -> the new
    sub-techniques; renamed -> no review; software links updated; one notice; one audit entry from the refresh;
  - cards (observed / known for this malware / possible), CVEs (CTID KEV), documents (version written, nothing cut);
  - the routes: researchers and admins only, CSRF and a fresh sign-in for changes, the researcher's path gate.
Usage: tests/check_attack_map.py"""
import importlib.util
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

import attack_map as AM  # noqa: E402
import offline_names as ON  # noqa: E402

fails, checks = [], 0


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


def fx(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


OUT = []
_real_connect, _real_create = socket.socket.connect, socket.create_connection
_local = lambda a: not isinstance(a, tuple) or str(a[0]).startswith(("127.", "::1", "localhost", "0.0.0.0"))


def _nc(self, addr, *a, **k):
    if _local(addr):
        return _real_connect(self, addr, *a, **k)
    OUT.append(addr); raise OSError("network refused by the test")


def _cc(addr, *a, **k):
    if _local(addr):
        return _real_create(addr, *a, **k)
    OUT.append(addr); raise OSError("network refused by the test")


socket.socket.connect, socket.create_connection = _nc, _cc


class Audit:
    def __init__(self):
        self.rows = []

    def add(self, event, **k):
        self.rows.append((event, k))


REPORTS = {
    "event4_sinkhole_http": {"type": "infected-system", "group": "", "section": "Infections", "title": "Sinkhole HTTP Events"},
    "scan_rdp": {"type": "vulnerable-system", "group": "Should not be open to the internet (remote access, databases, management)",
                 "section": "Services", "title": "Accessible RDP Report"},
    "scan_fixture_new": {"type": "other", "group": "", "section": "Services", "title": "A new report with no rule"},
    "scan_old_c2": {"type": "other", "group": "", "section": "Intelligence", "title": "Uses the old technique"},
    "scan_goaway": {"type": "other", "group": "", "section": "Intelligence", "title": "Uses the deprecated one"},
    "scan_scanny": {"type": "other", "group": "", "section": "Intelligence", "title": "Uses the one that is split"},
}

tmp = tempfile.mkdtemp(prefix="lg-attack-")
try:
    print("the ATT&CK index")
    v1, v2 = ON.build_attack({"enterprise": fx("attack_v1.json")}), ON.build_attack({"enterprise": fx("attack_v2.json")})
    t1, t2 = v1["techniques"], v2["techniques"]
    ok("techniques with tactics (plain words)", t1["T1071.001"]["tactics"] == ["Command and Control"] and t1["T1133"]["tactics"] == ["Initial Access", "Persistence"])
    ok("states: active, revoked, deprecated", t2["T9001"]["state"] == "revoked" and t2["T9002"]["state"] == "deprecated" and t2["T1071"]["state"] == "active")
    ok("MITRE's named replacement of a revoked technique (revoked-by)", t2["T9001"].get("revoked_by") == "T1071.001", t2["T9001"])
    q2 = next(e for e in v2["entries"] if e["name"] == "Quietbot")
    ok("software: the techniques MITRE links to it, and its groups", q2["techniques"] == ["T1071.001", "T1110.001"] and q2["groups"] == ["Fixture Group"], q2)
    ok("the version", AM.version_of(v1) == "1.0" and AM.version_of(v2) == "2.0")

    print("the shipped rule table")
    am0 = AM.AttackMap(os.path.join(ROOT, "data"), None, report_map=lambda: {})
    want = {("event4_sinkhole_http", "infected-system", ""): (["T1071.001"], "observed", "used"),
            ("event4_sinkhole_dns", "other", ""): (["T1071.004"], "observed", "used"),
            ("event4_honeypot_brute_force", "brute-force", ""): (["T1110.001"], "observed", "used"),
            ("event4_honeypot_rdp_scan", "scanner", ""): (["T1595"], "observed", "used"),
            ("event4_honeypot_ddos_amp", "ddos", ""): (["T1498.002"], "observed", "target"),
            ("scan_dns", "vulnerable-system", "Can be abused for attacks (amplification, tunnels)"): (["T1498.002"], "possible", "exposure"),
            ("scan_ntp", "vulnerable-system", ""): (["T1498.002"], "possible", "exposure"),
            ("scan_http_proxy", "vulnerable-system", "Can be abused for attacks (amplification, tunnels)"): (["T1090"], "possible", "exposure"),
            ("malware_url", "malware-distribution", ""): (["T1189"], "observed", "host"),
            ("spam_url", "spam", ""): (["T1566.002"], "observed", "host"),
            ("scan_rdp", "vulnerable-system", ""): (["T1133", "T1021"], "possible", "exposure"),
            ("scan_http_vulnerable", "vulnerable-system", "Known vulnerability"): (["T1190"], "possible", "exposure"),
            ("scan_elasticsearch", "vulnerable-system", ""): (["T1530", "T1213"], "possible", "exposure")}
    bad = []
    for (k, ty, gr), (tech, cert, role) in want.items():
        r = am0.suggest(k, {"type": ty, "group": gr}) or {}
        if (r.get("techniques"), r.get("certainty"), r.get("role")) != (tech, cert, role):
            bad.append((k, r.get("id"), r.get("techniques")))
    ok("every report kind in the design gets its technique, certainty and role", not bad, bad)
    ok("a report no rule knows: not mapped yet", am0.suggest("blocklist", {"type": "blocklist"}) is None)
    ok("DGA family names: T1568.002 observed", [t["id"] for t in AM.AttackMap(os.path.join(ROOT, "data"), None).name_items("tinba-dga")] == ["T1568.002"])

    print("mappings")
    for fname, doc in ((ON.ATTACK_FILE, v1),):
        doc["fetched"] = "2026-11-13T00:00:00+00:00"
        json.dump(doc, open(os.path.join(tmp, fname), "w", encoding="utf-8"))
    shutil.copy(os.path.join(ROOT, "data", AM.RULES_FILE), os.path.join(tmp, AM.RULES_FILE))
    rm = {k: dict(v) for k, v in REPORTS.items()}
    aud = Audit()
    off = ON.OfflineNames(tmp)
    am = AM.AttackMap(tmp, off, report_map=lambda: rm, report_defs=lambda: {}, audit=aud)
    ok("first arrival: every report gets an entry", am.sync() == len(rm) and am.sync() == 0)
    ok("a report with a rule: suggested", am.mapping("event4_sinkhole_http")["status"] == "suggested"
       and am.mapping("event4_sinkhole_http")["techniques"] == ["T1071.001"])
    ok("a report with no rule: not mapped yet, asked about", am.mapping("scan_fixture_new")["status"] == "none"
       and "scan_fixture_new" in [x["report"] for x in am.todo()])
    m, err = am.review("scan_rdp", ["T1133", "javascript:alert(1)"], False, "", "lg-t-res")
    ok("a made-up technique is refused", m is None and "Not a current ATT&CK technique" in err, err)
    m, err = am.review("scan_rdp", ["T9003"], False, "", "lg-t-res")
    ok("a revoked technique is refused", m is None and err, err)
    m, err = am.review("scan_rdp", ["T1133"], True, "", "lg-t-res")
    ok("techniques and 'none fits' together are refused", m is None and err)
    m, err = am.review("scan_rdp", [], False, "", "lg-t-res")
    ok("nothing chosen is refused", m is None and err)
    m, err = am.review("no_such_report", ["T1133"], False, "", "lg-t-res")
    ok("an unknown report is refused", m is None and err)
    m, err = am.review("scan_rdp", ["t1133", "T1021", "T1133"], False, "  remote <b>desktop</b>  ", "lg-t-res", "Grace")
    ok("a researcher's choice is saved: several techniques, no duplicates", m and m["status"] == "reviewed" and m["techniques"] == ["T1133", "T1021"]
       and m["by_name"] == "Grace" and m["version"] == "1.0", m)
    ok("...the note kept as plain text", m and m["note"] == "remote <b>desktop</b>")
    ok("...and audited", aud.rows and aud.rows[-1][0] == "attack_mapping_reviewed" and aud.rows[-1][1]["target"] == "scan_rdp")
    m, err = am.review("scan_fixture_new", [], True, "inventory only", "lg-t-res")
    ok("'No ATT&CK technique fits' is a valid, recorded choice", m and m["nofit"] and m["status"] == "reviewed"
       and am.report_items("scan_fixture_new") == [])
    am.sync()
    ok("a reviewed mapping is never replaced by a suggestion", am.mapping("scan_rdp")["techniques"] == ["T1133", "T1021"]
       and am.mapping("scan_rdp")["status"] == "reviewed")
    rm["scan_rdp"]["type"] = "potentially-unwanted-accessible"            # Shadowserver changes the report
    rm["event4_sinkhole_http"]["title"] = "Sinkhole HTTP Events (renamed)"
    am.sync()
    mr = am.mapping("scan_rdp")
    ok("Shadowserver changed a reviewed report: please check, the old mapping kept", mr["status"] == "check"
       and mr["previous"]["techniques"] == ["T1133", "T1021"] and "Shadowserver changed" in mr["check_reason"], mr.get("check_reason"))
    ok("...shown meanwhile, marked", [t["status"] for t in am.report_items("scan_rdp")] == ["please check", "please check"])
    ok("a suggested one simply gets the new suggestion", am.mapping("event4_sinkhole_http")["status"] == "suggested")

    print("search and the short list")
    ok("search by ID, word and tactic; retired ones hidden",
       [t["id"] for t in am.search("T1071")] == ["T1071", "T1071.001", "T1071.004"] and [t["id"] for t in am.search("password")] == ["T1110.001"]
       and "T1133" in [t["id"] for t in am.search("persistence")] and am.search("long revoked") == [])
    sl = am.shortlist("scan_rdp")
    ok("short list: 1-10 current techniques, the current ones first", 1 <= len(sl) <= 10 and sl[0]["id"] == "T1133"
       and all(t["state"] == "active" for t in sl), [t["id"] for t in sl])

    print("a new ATT&CK version")
    for key, tids in (("scan_old_c2", ["T9001"]), ("scan_goaway", ["T9002"]), ("scan_scanny", ["T1595"]), ("event4_sinkhole_http", ["T1071.001"])):
        am.review(key, tids, False, "", "lg-t-res")
    ok("same version: nothing to do", AM.apply_update(tmp, v1, v1) is None)
    n = AM.apply_update(tmp, v1, v2)
    ok("one notice with the counts", n and n["text"] == "ATT&CK v1.0 → v2.0: 3 mappings to check, 2 new techniques, 1 malware family updated, 1 renamed", n and n["text"])
    mo = am.mapping("scan_old_c2")
    ok("revoked: MITRE's replacement is the suggestion; old one shown, 'retired in v2.0'", mo["status"] == "check"
       and mo["check_suggest"] == ["T1071.001"] and mo["retired"] == {"T9001": "v2.0"} and mo["previous"]["techniques"] == ["T9001"], mo)
    mg = am.mapping("scan_goaway")
    ok("deprecated with no replacement: please check (short list)", mg["status"] == "check" and "no replacement" in mg["check_reason"] and mg["check_suggest"] == [])
    ms = am.mapping("scan_scanny")
    ok("split: please check, offering the new sub-techniques", ms["status"] == "check" and ms["check_offer"] == ["T1595.001"], ms)
    ok("untouched reviewed mappings stay reviewed", am.mapping("event4_sinkhole_http")["status"] == "reviewed")
    json.dump(dict(v2, fetched="2026-11-13T00:00:00+00:00"), open(os.path.join(tmp, ON.ATTACK_FILE), "w", encoding="utf-8"))
    ok("...and the picker's short list offers them", "T1595.001" in [t["id"] for t in am.shortlist("scan_scanny")])
    ok("...a revoked one's replacement is offered first", am.shortlist("scan_old_c2")[0]["id"] == "T1071.001")
    ok("renamed (same ID): the new name, no review", am.tech("T1190")["name"] == "Exploit Internet-Facing Application")
    ok("new techniques: in the picker at once", [t["id"] for t in am.search("T1498")] == ["T1498"])
    ok("the notice is the page's latest", am.summary()["notice"]["to"] == "2.0" and am.summary()["counts"]["check"] >= 3)

    print("cards and documents")
    card = {"source": "mitre-attack", "name": "Quietbot", "techniques": ["T1071.001", "T1110.001"], "groups": ["Fixture Group"],
            "seen_in": ["Sinkhole HTTP Events (renamed)"], "also": []}
    att = am.card_attack("quietbot", card)
    obs = [t for t in att["techniques"] if t["certainty"] == "observed"]
    kn = [t for t in att["techniques"] if t["certainty"] == "known"]
    ok("observed: the reports' reviewed mapping, with the constituent's role", [t["id"] for t in obs] == ["T1071.001"]
       and obs[0]["role"] == "this device was used for it" and obs[0]["status"] == "reviewed", obs)
    ok("known for this malware: MITRE's links, and its groups", [t["id"] for t in kn] == ["T1071.001", "T1110.001"] and att["groups"] == ["Fixture Group"])
    ok("the card carries the ATT&CK version", att["version"] == "2.0")
    lines = AM.attack_lines(att)
    ok("document text: version first, every technique, nothing cut", lines[0].startswith("MITRE ATT&CK v2.0: T1071.001 Web Protocols (observed")
       and "Credential Access: T1110.001 Password Guessing" in lines[1] and not any("…" in x or "..." in x for x in lines), lines)
    ok("CSV cell: IDs and the version", AM.ids_text(att) == "T1071.001; 2 known for this malware (ATT&CK v2.0)", AM.ids_text(att))
    am.labels = lambda: {"Sinkhole HTTP (our label)": "event4_sinkhole_http"}
    via = am.card_attack("quietbot", {**card, "seen_in": ["Sinkhole HTTP (our label)"]})
    ok("'Seen in' labels from the platform's registry find the report", [t["id"] for t in via["techniques"] if t["certainty"] == "observed"] == ["T1071.001"])
    att_none = am.card_attack("nothing", {"source": "misp-galaxy", "also": [], "seen_in": []})
    ok("a card with nothing to say: no ATT&CK block", att_none is None)
    exp = am.report_items("scan_rdp")
    ok("exposure wording: 'attackers can use this exposure for it'", exp and exp[0]["role"] == "attackers can use this exposure for it" and exp[0]["certainty"] == "possible")

    print("CVEs (CTID KEV mappings)")
    kev = AM.build_kev(fx("kev.json"), "mappings/kev/x.json")
    ok("KEV file: CVEs and techniques, duplicates and junk dropped", kev["cves"] == {"CVE-2099-0001": [["T1190", "exploitation_technique"], ["T1071.001", "primary_impact"]]}
       and kev["attack_version"] == "1.0", kev["cves"])
    json.dump(kev, open(os.path.join(tmp, AM.KEV_FILE), "w", encoding="utf-8"))
    ca = am.cve_attack("cve-2099-0001")
    ok("a CVE card: its techniques, what each is, the source and its licence",
       [(t["id"], t["kind"]) for t in ca["techniques"]] == [("T1190", "how it is exploited"), ("T1071.001", "main impact")]
       and "Apache License 2.0" in ca["licence"] and ca["mapped_with"] == "1.0", ca)
    ok("a CVE with no mapping: nothing", am.cve_attack("CVE-2099-0009") is None)
    tree = {"tree": [{"path": "mappings/kev/attack-15.1/kev-02.13.2025/enterprise/a.json"}, {"path": "mappings/kev/attack-16.1/kev-07.28.2025/enterprise/b.json"},
                     {"path": "mappings/kev/attack-16.1/kev-01.02.2025/enterprise/c.json"}, {"path": "mappings/kev/attack-16.1/kev-07.28.2025/mobile/d.json"},
                     {"path": "../../etc/passwd"}]}
    ok("the newest KEV file is chosen (ATT&CK version, then date; enterprise only)", AM.latest_kev_path(tree).endswith("/b.json"))

    print("platform: routes, path gate, PDFs")
    import app as A
    from flask import g
    import auth
    ok("researchers can reach the ATT&CK and name-source APIs (path gate)", all(any(p.startswith(x) for x in auth.DEFINITIONS_PATHS)
                                                                                for p in ("/api/attack", "/api/attack/mapping", "/api/name-sources")))
    ok("closed in Peace of mind like the other researcher work", any("/api/attack".startswith(x) for x in auth.PEACE_CLOSED))
    keep = {k: getattr(A.ATTACK, k) for k in ("dir", "offline", "report_map", "audit")}
    A.ATTACK.dir, A.ATTACK.offline, A.ATTACK.report_map, A.ATTACK.audit = tmp, off, (lambda: rm), aud
    real_add = None
    try:
        def call(view, path, perms, method="GET", body=None, token="good"):
            with A.app.test_request_context(path, method=method, json=body, headers={"X-CSRF-Token": token}):
                g.user = {"user": "lg-t-x", "role": "x", "perms": perms, "csrf": "good", "created": 1.0}
                rv = A.app.view_functions[view]()
                return (rv[1], rv[0].get_json()) if isinstance(rv, tuple) else (rv.status_code, rv.get_json())
        ok("other roles cannot see the mappings (403)", call("api_attack", "/api/attack", {"view"})[0] == 403)
        s, j = call("api_attack", "/api/attack", {"definitions"})
        ok("researchers see the summary, the to-do and the reviewed", s == 200 and j["summary"]["version"] == "2.0" and isinstance(j["todo"], list))
        ok("search for researchers", call("api_attack_search", "/api/attack/search?q=web", {"definitions"})[1]["results"][0]["id"] == "T1071.001")
        s, j = call("api_attack_mapping", "/api/attack/mapping", {"definitions"}, "POST", {"report": "scan_rdp", "techniques": ["T1133"]}, token="forged")
        ok("a change without the security token is refused (403)", s == 403)
        s, j = call("api_attack_mapping", "/api/attack/mapping", {"view", "malpedia"}, "POST", {"report": "scan_rdp", "techniques": ["T1133"]})
        ok("an analyst cannot change mappings (403)", s == 403)
        s, j = call("api_attack_mapping", "/api/attack/mapping", {"definitions"}, "POST", {"report": "scan_rdp", "techniques": "T1133"})
        ok("a wrong type is refused, never a 500 (400)", s == 400)
        s, j = call("api_attack_mapping", "/api/attack/mapping", {"definitions"}, "POST", {"report": "scan_rdp", "techniques": ["T1133"]})
        ok("a researcher with the token confirms a mapping", s == 200 and j["mapping"]["status"] == "reviewed" and j["mapping"]["techniques"] == ["T1133"])
        import reports_pdf as RP
        x = {"found": False, "curated": True, "title": "Quietbot", "description": "d", "attack": att}
        head, rest = RP.enrichment_block("quietbot", x, "", RP.styles(), 400)
        txt = " ".join(getattr(f, "text", "") for f in rest)
        ok("analysis PDF: the ATT&CK lines with the version", "MITRE ATT&amp;CK v2.0" in txt or "MITRE ATT&CK v2.0" in txt, txt[:200])
        cv = A._with_attack({"kind": "cve", "found": True}, "CVE-2099-0001")
        ok("CVE cards on the services platform get the KEV techniques", [t["id"] for t in cv["attack"]["techniques"]] == ["T1190", "T1071.001"])
    finally:
        for k, v in keep.items():
            setattr(A.ATTACK, k, v)

    print("the refresh: one audit entry per ATT&CK update")
    os.environ["LG_OFFLINE_NAMES_DIR"] = tmp
    spec = importlib.util.spec_from_file_location("fetch_offline_names", os.path.join(ROOT, "manage", "fetch_offline_names.py"))
    FN = importlib.util.module_from_spec(spec); spec.loader.exec_module(FN)
    FN.MIN_ENTRIES, FN.MIN_KEV, FN.MIN_SHARE = 1, 1, 0
    json.dump(dict(v1, fetched="2026-11-13T00:00:00+00:00"), open(os.path.join(tmp, ON.ATTACK_FILE), "w", encoding="utf-8"))
    FN.download = lambda url: fx("attack_v2.json") if "enterprise-attack" in url else {"type": "bundle", "objects": []}
    rc = FN.main(["--force", "--only", "attack", "--by", "schedule"])
    rows = [json.loads(x) for x in open(os.path.join(tmp, "audit.log"), encoding="utf-8").read().splitlines()]
    up = [r for r in rows if r["event"] == "attack_version_update"]
    ok("the refresh writes one 'attack_version_update' entry with old and new version and the counts",
       rc == 0 and len(up) == 1 and up[0]["target"] == "ATT&CK v1.0 → v2.0" and "to check" in up[0]["detail"], up)
    ok("nothing left the server", not OUT, OUT[:3])
finally:
    socket.socket.connect, socket.create_connection = _real_connect, _real_create
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
