#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Offline name sources (offline_names.py, manage/fetch_offline_names.py) behind Malpedia, with small made-up fixtures
in tests/fixtures/offline_names and no network at all (every outgoing connection is refused and counted):
  - the indexes: MISP Galaxy clusters (malpedia, botnet, tool) and ATT&CK malware / tools (no revoked, deprecated or
    technique objects), plain text, only http(s) references, markup kept as text;
  - matching by name and synonym, case-insensitive, Shadowserver-style names (android.badbox2), Malpedia's cluster
    before botnet before tool, a MISP entry without a description giving way to ATT&CK;
  - the card names its source and carries the licence (CC BY-NC-SA 3.0 for Malpedia's content, MITRE's notice);
  - mp_resolve's order: researchers' definition > Malpedia > MISP Galaxy > ATT&CK > not found, with and without a token;
  - nothing leaves the server during a look-up; the fetch script refreshes at most once a week.
Usage: tests/check_offline_names.py"""
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
FIX = os.path.join(HERE, "fixtures", "offline_names")

import offline_names as ON  # noqa: E402
from malpedia import Malpedia  # noqa: E402

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


# ---- no network: any connection leaving this machine is refused and counted (the local database may still be reached,
# as the platform's own import may start its client)
OUT = []
_real_connect = socket.socket.connect
_real_create = socket.create_connection
LOCAL = ("127.", "::1", "localhost", "0.0.0.0")


def _local(addr):
    return not isinstance(addr, tuple) or str(addr[0]).startswith(LOCAL)


def _no_net(self, addr, *a, **k):
    if _local(addr):
        return _real_connect(self, addr, *a, **k)
    OUT.append(addr)
    raise OSError("network refused by the test")


def _no_create(addr, *a, **k):
    if _local(addr):
        return _real_create(addr, *a, **k)
    OUT.append(addr)
    raise OSError("network refused by the test")


socket.socket.connect = _no_net
socket.create_connection = _no_create

tmp = tempfile.mkdtemp(prefix="lg-offnames-")
try:
    print("indexes")
    misp = ON.build_misp({"malpedia": fx("misp_malpedia.json"), "botnet": fx("misp_botnet.json"), "tool": fx("misp_tool.json")})
    att = ON.build_attack({"enterprise": fx("attack_enterprise.json")})
    misp["fetched"] = att["fetched"] = "2026-11-13T00:00:00+00:00"
    for fname, doc in ((ON.MISP_FILE, misp), (ON.ATTACK_FILE, att)):
        with open(os.path.join(tmp, fname), "w", encoding="utf-8") as f:
            json.dump(doc, f)
    names = {e["name"] for e in att["entries"]}
    ok("ATT&CK: malware and tools indexed", names == {"Quietbot", "Sweeper", "Herdbot"}, sorted(names))
    ok("ATT&CK: the version in use is kept", att.get("versions") == {"enterprise": "99.1"}, att.get("versions"))
    q = next(e for e in att["entries"] if e["name"] == "Quietbot")
    ok("ATT&CK: Markdown links and citations removed", "](" not in q["description"] and "Citation" not in q["description"]
       and q["description"].startswith("Quietbot is a made-up banking trojan used by Fixture Group."), q["description"])
    ok("ATT&CK: own page kept apart from references", q["url"] == "https://attack.mitre.org/software/S9001" and q["id"] == "S9001"
       and q["references"] == ["https://example.org/quietbot-report"], q)
    ok("ATT&CK: MITRE's notice read from the bundle", "The MITRE Corporation" in att["notice"])
    fl = next(e for e in misp["entries"] if e["name"] == "Fixtureloader")
    ok("MISP: only http(s) references, no duplicates", fl["references"] == ["https://example.org/fixtureloader"], fl["references"])
    ok("MISP: entries from all three clusters", {e["cluster"] for e in misp["entries"]} == {"malpedia", "botnet", "tool"})

    print("look-ups")
    names_ = ON.OfflineNames(tmp, needles=Malpedia.needles)
    st = names_.status()
    ok("status: both sources installed", st["misp-galaxy"]["installed"] and st["mitre-attack"]["installed"] and names_.available, st)
    c = names_.lookup("FIXTURELOADER")
    ok("name match, case-insensitive", c and c["name"] == "Fixtureloader" and c["source"] == "misp-galaxy", c and c["name"])
    ok("card says which source answered", c and c["source_label"] == "MISP Galaxy · Malpedia cluster" and c["reference"] and not c["found"])
    ok("Malpedia content carries CC BY-NC-SA 3.0", c and "CC BY-NC-SA 3.0" in c["licence"] and "Malpedia" in c["licence"]
       and "CC BY-NC-SA 3.0" in c["licence_short"])
    c = names_.lookup("fxload")
    ok("synonym match", c and c["name"] == "Fixtureloader" and "FxLoad" in c["matched_by"], c and c["matched_by"])
    c = names_.lookup("fixture-loader")
    ok("synonym match ignores - _ and case", c and c["name"] == "Fixtureloader", c and c["name"])
    c = names_.lookup("android.badbox2")
    ok("Shadowserver-style name (android.badbox2)", c and c["name"] == "Badbox2", c and c["matched_by"])
    c = names_.lookup("herdbot-botnet")
    ok("botnet cluster answers, suffix dropped", c and c["name"] == "Herdbot" and c["cluster"] == "botnet"
       and "CC0" in c["licence"], c and (c["cluster"], c["matched_by"]))
    c = names_.lookup("sharedname")
    ok("Malpedia cluster before botnet", c and c["cluster"] == "malpedia" and "Malpedia-cluster text" in c["description"], c and c["cluster"])
    c = names_.lookup("pk-tool")
    ok("tool cluster by synonym", c and c["name"] == "Pokekit" and c["cluster"] == "tool")
    c = names_.lookup("quietbot")
    ok("MISP entry without a description gives way to ATT&CK", c and c["source"] == "mitre-attack" and c["id"] == "S9001", c and c["source"])
    ok("ATT&CK card keeps MITRE's notice", c and "The MITRE Corporation" in c["licence"] and "permission of The MITRE Corporation" in c["licence"],
       c and c["licence"])
    c = names_.lookup("sweeper")
    ok("ATT&CK tool when MISP has nothing", c and c["source"] == "mitre-attack" and c["type"] == "ATT&CK tool" and c["platforms"] == ["Linux", "Windows"])
    ok("an entry without a description never answers", names_.lookup("oldvideo") is None)
    c = names_.lookup("elf.herdbot")
    ok("a name match beats another family's synonym", c and c["name"] == "Herdbot", c and (c["name"], c["matched_by"]))
    ok("revoked / deprecated never answer", names_.lookup("oldthing") is None and names_.lookup("gonething") is None)
    ok("unknown name: None", names_.lookup("no-such-name-anywhere") is None)
    ok("empty or over-long name: None", names_.lookup("") is None and names_.lookup("x" * 101) is None)
    c = names_.lookup("<b>markup</b>")
    ok("markup stays plain data (rendered as text by the page)", c and c["description"].startswith("<script>"), c and c["name"])
    ok("no files: nothing installed, no answer", ON.OfflineNames(os.path.join(tmp, "none")).lookup("fxload") is None
       and not ON.OfflineNames(os.path.join(tmp, "none")).available)
    print("real cross-listings (MISP Galaxy, 13 Nov 2026): a synonym never answers for another family")
    xl = fx("cross_listings.json")
    xdir = tempfile.mkdtemp(prefix="lg-offnames-x-")
    with open(os.path.join(xdir, ON.MISP_FILE), "w", encoding="utf-8") as f:
        json.dump(ON.build_misp({k: xl[k] for k in ON.MISP_CLUSTERS}), f)
    xo = ON.OfflineNames(xdir, needles=Malpedia.needles)
    hit = lambda n: (lambda c: c and (c["cluster"], c["name"], c["matched_by"]))(xo.lookup(n))
    ok("'Mirai (ELF)' is the Malpedia entry, never katana (whose synonym it is)", hit("Mirai (ELF)") == ("malpedia", "Mirai (ELF)", "name Mirai (ELF)"), hit("Mirai (ELF)"))
    ok("'elf.mirai' is Mirai by name, not katana by synonym", (hit("elf.mirai") or ("", ""))[1] == "Mirai" and "name" in hit("elf.mirai")[2], hit("elf.mirai"))
    ok("'android.badbox2' is BADBOX by name", (hit("android.badbox2") or ("", ""))[1].lower() == "badbox" and hit("android.badbox2")[2].startswith("name"), hit("android.badbox2"))
    ok("'Hydra' is the Hydra entry: the synonym listed by BianLian and Nitro answers for neither", hit("hydra") == ("malpedia", "Hydra", "name Hydra"), hit("hydra"))
    ok("a synonym listed by two differently named families answers for none", xo.lookup("fixshare") is None)
    ok("a synonym only one family lists still answers", hit("Mirai Sora") == ("botnet", "Sora", "alternative name Mirai Sora"), hit("Mirai Sora"))
    ok("katana keeps answering for its own name", (hit("katana") or ("", ""))[1] == "katana")
    shutil.rmtree(xdir, ignore_errors=True)
    bad = tempfile.mkdtemp(prefix="lg-offnames-bad-")
    with open(os.path.join(bad, ON.MISP_FILE), "w") as f:
        f.write("{not json")
    ok("damaged file: no answer, no crash", ON.OfflineNames(bad).lookup("fxload") is None)
    shutil.rmtree(bad, ignore_errors=True)

    print("mp_resolve order (app.py)")
    import app as A  # noqa: E402
    real = {k: getattr(A, k) for k in ("OFFLINE_NAMES", "malpedia_explain", "_record_check", "knowledge_base")}
    real_token, real_lookup, real_off = A.malpedia.token, A.malpedia.lookup, A.NAME_SOURCES.offline
    A.OFFLINE_NAMES = A.NAME_SOURCES.offline = names_
    A.malpedia_explain = lambda n: {"verdict": "unlisted", "title": "Probably malware", "text": "t", "advice": "a", "seen_in": []}
    A._record_check = lambda *a, **k: None
    KB = {}
    A.knowledge_base = lambda: KB
    try:
        A.malpedia.token = ""
        card = A.mp_resolve("fxload")[0]
        ok("no token: MISP Galaxy answers", card.get("reference") and card.get("name") == "Fixtureloader" and card.get("offline"), card.get("source"))
        card = A.mp_resolve("sweeper")[0]
        ok("no token: ATT&CK answers after MISP", card.get("source") == "mitre-attack")
        card = A.mp_resolve("no-such-name-anywhere")[0]
        ok("no token: nothing anywhere -> not found", not card.get("found") and not card.get("reference") and card.get("verdict") == "unlisted")
        KB["fxload"] = {"title": "Our own words", "description": "Defined by a researcher.", "references": ["https://example.org/ours"]}
        card = A.mp_resolve("fxload")[0]
        ok("no token: researchers' definition beats MISP", card.get("curated") and card.get("title") == "Our own words")
        KB.clear()
        A.malpedia_explain = lambda n: {"verdict": "activity", "title": "Not malware: an activity", "text": "t", "advice": "a", "seen_in": []}
        card = A.mp_resolve("sweeper")[0]
        ok("an activity name (honeypots) is never matched to a malware list", card.get("verdict") == "activity" and not card.get("reference"))
        A.malpedia_explain = lambda n: {"verdict": "unlisted", "title": "Probably malware", "text": "t", "advice": "a", "seen_in": []}
        KB.clear()
        A.malpedia.token = "test-token"
        A.malpedia.lookup = lambda field, value: {"field": field, "value": value, "kind": "family", "matches": [], "family": None}
        card = A.mp_resolve("fxload")[0]
        ok("token, Malpedia has nothing: MISP Galaxy answers", card.get("reference") and card.get("source") == "misp-galaxy" and not card.get("offline"))
        KB["fxload"] = {"title": "Our own words", "description": "Defined by a researcher.", "references": ["https://example.org/ours"]}
        card = A.mp_resolve("fxload")[0]
        ok("token: researchers' definition beats MISP", card.get("curated") and card.get("title") == "Our own words")
        KB.clear()
        A.malpedia.lookup = lambda field, value: {"field": field, "value": value, "kind": "family",
                                                  "matches": [{"id": "win.fixtureloader", "matched_by": "family name win.fixtureloader"}],
                                                  "family": {"id": "win.fixtureloader", "name": "Fixtureloader", "url": "https://example.org/mp",
                                                             "description": "From Malpedia.", "references": []}}
        card = A.mp_resolve("fxload")[0]
        ok("token: Malpedia beats MISP Galaxy", card.get("found") and card.get("family") == "win.fixtureloader" and not card.get("reference"))
        print("one card, every source side by side (name_sources.py)")
        card = A.mp_resolve("fxload")[0]
        ok("token: Malpedia headline, MISP Galaxy under 'Also described by'",
           card.get("found") and [a.get("source_label") for a in card.get("also") or []] == ["MISP Galaxy · Malpedia cluster"],
           [a.get("source_label") for a in card.get("also") or []])
        ok("the card lists every source that knows the name, headline first",
           card.get("sources") == ["Malpedia", "MISP Galaxy · Malpedia cluster"], card.get("sources"))
        ok("Malpedia's card carries its licence (CC BY-NC-SA 3.0)", "CC BY-NC-SA 3.0" in (card.get("licence") or ""))
        ok("each folded source keeps its own licence", "CC BY-NC-SA 3.0" in ((card.get("also") or [{}])[0].get("licence") or ""))
        KB["fxload"] = {"title": "Our own words", "description": "Defined by a researcher.", "references": ["https://example.org/ours"]}
        card = A.mp_resolve("fxload")[0]
        ok("researchers' definition is the headline even when Malpedia knows the name (never overwritten)",
           card.get("curated") and card.get("title") == "Our own words" and not card.get("found"))
        ok("...with Malpedia and MISP Galaxy below it",
           [a.get("source") for a in card.get("also") or []] == ["malpedia", "misp-galaxy"], [a.get("source") for a in card.get("also") or []])
        KB.clear()
        A.malpedia.token = ""
        card = A.mp_resolve("herdbot")[0]
        ok("no token: MISP Galaxy headline, ATT&CK under it",
           card.get("source") == "misp-galaxy" and [a.get("source") for a in card.get("also") or []] == ["mitre-attack"]
           and "The MITRE Corporation" in card["also"][0].get("licence", ""), card.get("also"))
        card = A.mp_resolve("no-such-name-anywhere")[0]
        ok("nothing knows it: 'No source knows this name'", card.get("nosource") and card.get("sources") == []
           and A._short(card).startswith("no source knows this name"), A._short(card))
        import name_sources as NS
        c2 = A.mp_resolve("herdbot")[0]
        ok("PDF/CSV text: the source and its licence", NS.source_text(c2).startswith("Source: MISP Galaxy, Botnet cluster"), NS.source_text(c2))
        ok("PDF/CSV text: also described by, with MITRE's short notice",
           NS.also_text(c2) == "Also described by: MITRE ATT&CK as Herdbot (https://attack.mitre.org/software/S9003) [MITRE ATT&CK, © The MITRE Corporation].",
           NS.also_text(c2))
        import reports_pdf as RP
        S = RP.styles()
        head, rest = RP.enrichment_block("herdbot", c2, "", S, 400)
        txt = " ".join(getattr(f, "text", "") for f in rest)
        ok("analysis PDF card prints the source line and the other sources", "Also described by" in txt and "CC0 1.0" in txt, txt[:160])
        ok("Definitions: which sources know a name", A.NAME_SOURCES.known_by("herdbot") == ["MISP Galaxy · Botnet cluster", "MITRE ATT&CK"]
           and A.NAME_SOURCES.known_by("x", "win.x") == ["Malpedia"] and A.NAME_SOURCES.known_by("no-such-name-anywhere") == [])
        ok("Definitions editor: the other sources' text and links", [c["source"] for c in A.NAME_SOURCES.other_sources("herdbot")]
           == ["misp-galaxy", "mitre-attack"] and A.NAME_SOURCES.other_sources("herdbot")[1].get("url") == "https://attack.mitre.org/software/S9003")
        # the to-do list ("No source knows") leaves out names an offline source explains
        from flask import g as _g
        keep = {k: getattr(A, k) for k in ("_read_names", "_name_evidence", "_svc_issue_stats", "_unchecked_names")}
        A._read_names = lambda: {"herdbot": {"family": "", "count": 3}, "no-such-name-anywhere": {"family": "", "count": 2}}
        A._name_evidence, A._svc_issue_stats, A._unchecked_names = (lambda: {}), (lambda: {}), (lambda: [])   # no database needed
        try:
            with A.app.test_request_context("/api/kb/unresolved"):
                _g.user = {"user": "lg-t-res", "role": "researcher", "perms": {"definitions"}, "csrf": "t", "created": 1.0}
                todo = [r["name"] for r in A.api_kb_unresolved().get_json()["unresolved"]]
        finally:
            for k, v in keep.items():
                setattr(A, k, v)
        ok("'No source knows' lists only names none of the sources explain", todo == ["no-such-name-anywhere"], todo)

        print("Refresh sources button (admins only)")
        import name_sources as _ns
        started, audits = [], []
        real_popen, real_gap, aud = _ns.subprocess.Popen, _ns.MANUAL_GAP, A.AUTH["audit"]
        _ns.subprocess.Popen = lambda *a, **k: started.append(a[0]) or type("P", (), {"poll": lambda self: None})()
        _ns.MANUAL_GAP = 0                          # the hourly limit is not what this checks
        aud.add = lambda *a, **k: audits.append((a, k))   # the real audit log is left alone
        view = A.app.view_functions["api_name_sources_refresh"]
        try:
            def call(perms, token):
                with A.app.test_request_context("/api/name-sources/refresh", method="POST", headers={"X-CSRF-Token": token}):
                    _g.user = {"user": "lg-t-adm", "role": "admin", "perms": perms, "csrf": "good", "created": 1.0}
                    rv = view()
                    return rv[1] if isinstance(rv, tuple) else rv.status_code
            ok("a researcher cannot refresh (403)", call({"definitions"}, "good") == 403 and not started)
            ok("an admin without the security token cannot (403)", call({"settings"}, "forged") == 403 and not started)
            ok("an admin with the token starts it, in the background", call({"settings"}, "good") == 200 and len(started) == 1
               and "--force" in started[0] and "--by" in started[0] and "lg-t-adm" in started[0], started)
            ok("a second click while it runs is refused (409)", call({"settings"}, "good") == 409 and len(started) == 1)
            ok("the start is in the audit log", [a[0][0] for a in audits] == ["name_sources_refresh_started"], audits)
        finally:
            _ns.subprocess.Popen, _ns.MANUAL_GAP = real_popen, real_gap
            del aud.add                             # back to the class's own method
        with A.app.test_request_context("/api/name-sources"):
            _g.user = {"user": "lg-t-res", "role": "researcher", "perms": {"definitions"}, "csrf": "t", "created": 1.0}
            st = A.app.view_functions["api_name_sources"]().get_json()
        ok("status for researchers: both sources listed, no button", [s["key"] for s in st["sources"]] == ["misp-galaxy", "mitre-attack"]
           and all("entries" in s and "fetched" in s for s in st["sources"]) and st["can_refresh"] is False, st)
        with A.app.test_request_context("/api/name-sources"):
            _g.user = {"user": "lg-t-ext", "role": "external", "perms": {"view"}, "csrf": "t", "created": 1.0}
            rv = A.app.view_functions["api_name_sources"]()
        ok("status refused to other roles (403)", (rv[1] if isinstance(rv, tuple) else rv.status_code) == 403)
        ok("short text names the source (PDF lists)", A._short(names_.lookup("fxload")) == "Fixtureloader (MISP Galaxy · Malpedia cluster)",
           A._short(names_.lookup("fxload")))
    finally:
        A.malpedia.token, A.malpedia.lookup, A.NAME_SOURCES.offline = real_token, real_lookup, real_off
        for k, v in real.items():
            setattr(A, k, v)

    ok("nothing left the server during the look-ups", not OUT, OUT[:3])

    print("fetch script (no download)")
    os.environ["LG_OFFLINE_NAMES_DIR"] = tmp
    spec = importlib.util.spec_from_file_location("fetch_offline_names", os.path.join(ROOT, "manage", "fetch_offline_names.py"))
    FN = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(FN)
    from datetime import datetime, timezone
    import attack_map as AMAP
    with open(os.path.join(tmp, AMAP.KEV_FILE), "w", encoding="utf-8") as f:     # the KEV mappings (step 2), present too
        json.dump({"count": 1, "cves": {}}, f)
    for fname in (ON.MISP_FILE, ON.ATTACK_FILE, AMAP.KEV_FILE):   # downloaded "just now"
        p = os.path.join(tmp, fname)
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        d["fetched"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        with open(p, "w", encoding="utf-8") as f:
            json.dump(d, f)
    called = []
    FN.download = lambda url: called.append(url) or (_ for _ in ()).throw(RuntimeError("no network in the test"))
    rc = FN.main([])
    ok("refreshed at most once a week (fresh files: no download)", rc == 0 and not called, called)
    rc = FN.main(["--force", "--only", "misp"])
    ok("--force tries again, a failure keeps the old file", rc == 1 and called and all("misp-galaxy" in u for u in called)
       and ON.OfflineNames(tmp).lookup("fxload") is not None, called)
    # a refresh with fixture "downloads": checked, audited, status written; a much smaller download is refused
    FIXDL = {ON.MISP_URL.format("malpedia"): "misp_malpedia.json", ON.MISP_URL.format("botnet"): "misp_botnet.json",
             ON.MISP_URL.format("tool"): "misp_tool.json", ON.ATTACK_URLS["enterprise"]: "attack_enterprise.json"}
    shrink = {"on": False}

    KEVP = "mappings/kev/attack-1.0/kev-01.01.2026/enterprise/k.json"

    def fake_dl(url):
        if url == AMAP.KEV_TREE:
            return {"tree": [{"path": KEVP}]}
        if url == AMAP.KEV_RAW + KEVP:
            with open(os.path.join(HERE, "fixtures", "attack_map", "kev.json"), encoding="utf-8") as f:
                return json.load(f)
        if url not in FIXDL:
            return {"type": "bundle", "objects": []}          # mobile / ICS: empty in the fixture
        doc = fx(FIXDL[url])
        if shrink["on"] and "misp-galaxy" in url and not url.endswith("tool.json"):
            doc["values"] = []                                # MISP suddenly has almost nothing
        return doc
    FN.download, FN.MIN_ENTRIES, FN.MIN_KEV = fake_dl, 1, 1
    rc = FN.main(["--force", "--by", "lg-test-admin"])
    alog = os.path.join(tmp, "audit.log")
    lines = open(alog, encoding="utf-8").read().splitlines() if os.path.exists(alog) else []
    last = json.loads(lines[-1]) if lines else {}
    ok("a good refresh is saved and in the audit log, with counts and the ATT&CK version",
       rc == 0 and last.get("event") == "name_sources_refreshed" and last.get("user") == "lg-test-admin"
       and "ATT&CK version in use 99.1" in last.get("detail", "") and "MISP Galaxy 10 entries" in last.get("detail", ""), last)
    stj = json.load(open(os.path.join(tmp, "names_refresh.json"), encoding="utf-8"))
    ok("the last refresh is recorded for the Definitions page", stj.get("ok") is True and stj.get("by") == "lg-test-admin"
       and stj.get("attack_version") == "99.1", stj)
    shrink["on"] = True
    rc = FN.main(["--force", "--only", "misp", "--by", "schedule"])
    last = json.loads(open(alog, encoding="utf-8").read().splitlines()[-1])
    ok("a suddenly much smaller download is refused, the old copy kept", rc == 1 and ON.OfflineNames(tmp).lookup("fxload") is not None
       and ON.OfflineNames(tmp).status()["misp-galaxy"]["entries"] == 10, ON.OfflineNames(tmp).status()["misp-galaxy"])
    ok("...and the refusal is in the audit log with the reason", last.get("event") == "name_sources_refresh_failed"
       and "far fewer" in last.get("detail", "") and last.get("user") == "schedule", last.get("detail"))
    logtxt = open(os.path.join(tmp, "names_refresh.log"), encoding="utf-8").read()
    ok("...and in the refresh log", "far fewer than the 10 in use" in logtxt)
    FN.download = lambda url: (_ for _ in ()).throw(ValueError("Expecting value: line 1 column 1"))   # not JSON
    rc = FN.main(["--force", "--only", "attack"])
    ok("a download that is not valid JSON keeps the old copy", rc == 1 and ON.OfflineNames(tmp).status()["mitre-attack"]["entries"] == 3)
    ok("downloads only from GitHub over https", all(u.startswith(("https://raw.githubusercontent.com/", "https://api.github.com/repos/"))
                                                    for u in [ON.MISP_URL.format(c) for c in ON.MISP_CLUSTERS] + list(ON.ATTACK_URLS.values())
                                                    + [AMAP.KEV_TREE, AMAP.KEV_RAW]))
    ok("the downloads carry no name or host", all("{" not in u for u in ON.ATTACK_URLS.values()) and ON.MISP_URL.count("{}") == 1)
    print("the weekly refresh in the crontab (a stand-in crontab; a folder with a space)")
    import subprocess
    sch = os.path.join(tmp, "my lg")
    os.makedirs(os.path.join(sch, "manage")); os.makedirs(os.path.join(sch, "bin"))
    for f in ("offline_names.py", "attack_map.py"):
        shutil.copy(os.path.join(ROOT, f), os.path.join(sch, f))
    shutil.copy(os.path.join(ROOT, "manage", "fetch_offline_names.py"), os.path.join(sch, "manage", "fetch_offline_names.py"))
    crontxt = os.path.join(tmp, "cron.txt")
    with open(crontxt, "w") as f:
        f.write("17 4 * * 1  /srv/elsewhere/manage/fetch_offline_names.py --by schedule # looking-glass-name-sources\n15 3 * * * /usr/bin/backup-job\n")
    with open(os.path.join(sch, "bin", "crontab"), "w") as f:
        f.write(f'#!/bin/sh\nf="{crontxt}"\ncase "$1" in -l) [ -f "$f" ] && cat "$f" || exit 1 ;; -r) rm -f "$f" ;; -) cat > "$f" ;; esac\n')
    os.chmod(os.path.join(sch, "bin", "crontab"), 0o755)
    env = dict(os.environ, PATH=os.path.join(sch, "bin") + os.pathsep + os.environ.get("PATH", ""), LG_OFFLINE_NAMES_DIR=os.path.join(tmp, "schdata"))
    os.makedirs(env["LG_OFFLINE_NAMES_DIR"])
    script = os.path.join(sch, "manage", "fetch_offline_names.py")
    for _ in range(2):
        subprocess.run([sys.executable, script, "--schedule"], env=env, capture_output=True, text=True, timeout=60)
    cron_now = open(crontxt).read()
    mine = [ln for ln in cron_now.splitlines() if script in ln]
    ok("--schedule writes one line for this folder, the path quoted (a space in it)", len(mine) == 1 and f"'{script}'" in mine[0]
       and "# looking-glass-name-sources" in mine[0], cron_now)
    ok("...another installation's refresh and other jobs kept", "/srv/elsewhere/manage" in cron_now and "backup-job" in cron_now, cron_now)
    subprocess.run([sys.executable, script, "--unschedule"], env=env, capture_output=True, text=True, timeout=60)
    cron_now = open(crontxt).read()
    ok("--unschedule removes only this folder's line", script not in cron_now and "/srv/elsewhere/manage" in cron_now and "backup-job" in cron_now, cron_now)
    inst = open(os.path.join(ROOT, "deploy", "install.sh"), encoding="utf-8").read()
    ok("the installer schedules the refresh and downloads the first copies, never stopping on a failure",
       "fetch_offline_names.py --schedule" in inst and "if manage/fetch_offline_names.py --by installer; then" in inst and "--no-sources" in inst)
    ok("still nothing left the server", not OUT, OUT[:3])
finally:
    socket.socket.connect, socket.create_connection = _real_connect, _real_create
    shutil.rmtree(tmp, ignore_errors=True)

print(f"\n{checks - len(fails)} of {checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
