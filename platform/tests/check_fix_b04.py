#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The whole-codebase audit's batch 04 fixes (2026-11-27), as behaviour, on made-up data in temporary folders only:

4-1  deploy/update_run.py: an error (not only a failed step) after the code moved puts the previous release back
     (code, libraries, restart) and ends "rolled_back"; a roll-back step that errors does not stop the others.
     Fake commands only: no git, no real update.
4-2  deploy/update_run.py Run.cmd: a step that prints nothing is stopped at its timeout, with what it started (124).
4-3  findings.py: a removed account in a finding's history shows its person code, never its sign-in name.
4-4  cves.py: a look-up of N CVEs writes the cache file once for the batch, not once per record.
4-7  cves.py: cards() passes its time budget on; prefetch() passes its stop on to the CVE.org batch.
4-8  data_access.py and deploy/install_cert.py: audit texts never carry "…": a value is in full, or says in words
     how much of it is kept.
4-9  data_access.py: a download leaves no remembered key; the remembered views stay at most SEEN_MAX.
4-10 geo.py: a cache file that cannot be written never fails the map's look-up.
4-5  executive_pdf.py: a text fitted on two lines moves what is under it down (no text drawn over text), with long
     values in the header, the trend table, the regions, the donut legend and an explanation card.
4-6  executive_pdf.py: "Key findings (continued)" starts a new page when the next finding does not fit (no text
     below the page's edge).
LG_FIX_ROOT=<a platform folder> runs the same checks against that code (the audit's old copy, to see them fail).
Run: .venv/bin/python tests/check_fix_b04.py"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.environ.get("LG_FIX_ROOT") or os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(1, HERE)
os.environ.setdefault("LG_QUIET", "1")
os.environ.setdefault("LG_PERSON_CODE_DIR", tempfile.mkdtemp(prefix="lg-b04-codes-"))
TMP = tempfile.mkdtemp(prefix="lg-b04-")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{str(info)[:500]}]"), flush=True)
    if not cond:
        fails.append(label)


def load(rel, name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def guarded(label, fn):
    """A check whose code raises on the old code: the error is its FAIL, the other checks still run."""
    try:
        return fn()
    except Exception as e:                      # noqa: BLE001
        ok(label, False, f"{type(e).__name__}: {e}")
        return None


try:
    # ------------------------------------------------------------------ 4-1, 4-2 deploy/update_run.py
    print("4-1 / 4-2 deploy/update_run.py (fake commands in a temporary folder)")
    sys.path.insert(0, os.path.join(ROOT, "deploy"))
    UR = load("deploy/update_run.py", "update_run_b04")
    VI = UR.VI
    proj = os.path.join(TMP, "install", "platform")
    os.makedirs(proj)
    UR.PROJECT = proj
    UR.STATE = os.path.join(proj, "data", "update")
    UR.REQUEST, UR.STATUS, UR.LOG, UR.LOCK = (os.path.join(UR.STATE, n) for n in ("request.json", "status.json", "log.jsonl", "lock"))
    UR.audit = lambda *a, **k: None
    UR.preflight = lambda run: os.path.dirname(proj)
    UR.remote_tags = lambda run: ["v2026.11.20", "v2026.11.25"]
    VI.installed_tag = lambda p: "v2026.11.20"
    VI.KEY_FINGERPRINT = "SHA256:b04-test-key"
    VI.github_keys = lambda *a, **k: []
    VI.signers_file = lambda *a, **k: 1

    def fake_git(args, timeout=60, **k):
        out = {"cat-file": "tag", "rev-parse": "prevcommit0000", "symbolic-ref": "main"}.get(next((a for a in args if a in
              ("cat-file", "rev-parse", "symbolic-ref", "verify-tag")), ""), "")
        err = f'Good "git" signature with ED25519 key {VI.KEY_FINGERPRINT}' if "verify-tag" in args else ""
        return types.SimpleNamespace(returncode=0, stdout=out, stderr=err)
    VI.git = fake_git
    real_cmd = UR.Run.cmd
    calls, plan = [], {}

    def fake_cmd(self, args, cwd=None, timeout=300, quiet=False):
        what = os.path.basename(args[0]) if args[0] != "git" else "git " + next((a for a in args[3:] if not a.startswith("-")), "")
        calls.append(what)
        act = plan.get((what, calls.count(what)))
        if act == "raise":
            raise OSError(f"made-up error in {what}")
        return (act if isinstance(act, int) else 0), ""
    UR.Run.cmd = fake_cmd

    def update_with(p):
        calls.clear(); plan.clear(); plan.update(p)
        for f in (UR.STATUS, UR.REQUEST):
            if os.path.exists(f):
                os.remove(f)
        os.makedirs(UR.STATE, exist_ok=True)
        with open(UR.REQUEST, "w") as fh:
            json.dump({"kind": "update", "tag": "v2026.11.25", "by": "Grace Mensah", "at": time.time()}, fh)
        rc = guarded("the update run itself", lambda: UR.main([]))
        st = json.load(open(UR.STATUS)) if os.path.exists(UR.STATUS) else {}
        return rc, st, list(calls)

    rc, st, cl = update_with({})
    ok("4-1 the fake update without errors ends done (the stand-in works)", st.get("state") == "done", (st.get("result"), cl))
    rc, st, cl = update_with({("update_libraries.sh", 1): "raise"})
    ok("4-1 an error in the libraries step: the previous release is put back (rolled_back)",
       st.get("state") == "rolled_back", st.get("result"))
    ok("4-1 …the code back (git reset --keep to the previous commit), the old libraries and a restart",
       "git reset" in cl and cl.count("update_libraries.sh") == 2 and "reload.sh" in cl, cl)
    rc, st, cl = update_with({("reload.sh", 1): "raise"})
    ok("4-1 an error in the restart step: rolled back too", st.get("state") == "rolled_back" and "git reset" in cl, (st.get("result"), cl))
    rc, st, cl = update_with({("git merge", 1): "raise"})
    ok("4-1 an error while moving the code: rolled back (the code may have moved)", st.get("state") == "rolled_back"
       and "git reset" in cl, (st.get("result"), cl))
    rc, st, cl = update_with({("update_libraries.sh", 1): "raise", ("git reset", 1): "raise"})
    ok("4-1 a roll-back step that errors does not stop the others; the run still ends rolled_back",
       st.get("state") == "rolled_back" and cl.count("update_libraries.sh") == 2 and "reload.sh" in cl, (st.get("result"), cl))
    UR.Run.cmd = real_cmd

    os.makedirs(UR.STATE, exist_ok=True)
    run = UR.Run("check")
    for label, args in (("a step that prints nothing (sleep)", ["sleep", "6"]),
                        ("a step whose child holds its output open (sh -c 'sleep & wait')", ["sh", "-c", "sleep 6.77 & wait"])):
        t0 = time.time()
        res = {}
        th = threading.Thread(target=lambda: res.update(r=real_cmd(run, args, cwd=TMP, timeout=1)), daemon=True)
        th.start(); th.join(20)
        took = time.time() - t0
        ok(f"4-2 {label} is stopped at its 1 s timeout (124), not when it ends", (res.get("r") or (None,))[0] == 124 and took < 4,
           (res.get("r"), round(took, 1)))
    left = subprocess.run(["pgrep", "-f", "sleep 6.77"], capture_output=True, text=True).stdout.strip()
    ok("4-2 …and what it started is stopped with it", not left, left)
    r = real_cmd(run, ["sh", "-c", "echo one; echo two"], cwd=TMP, timeout=30)
    ok("4-2 a step that ends in time: its exit code and every line", r == (0, "one\ntwo"), r)

    # ------------------------------------------------------------------ 4-3 findings.py
    print("4-3 findings.py: a removed account")
    import people as P
    import person_code
    import findings as FN

    class Users:
        def __init__(self, d):
            self.d = d

        def get(self, u):
            return self.d.get(u)
    ppl = P.People(Users({"ama": {"profile": {"full_name": "Ama Owusu"}}, "kofi.removed": {"profile": {}}}))
    F = FN.Findings(os.path.join(TMP, "findings.json"), ppl)
    F.people_of = lambda kind: [{"user": "ama", "name": "Ama Owusu"}]
    item = F.create({"id": "n1", "text": "Same C2 in two reports.", "codes": []}, "infections", "examplebot", "Shared C2",
                    "kofi.removed", "researcher", "ama")
    ppl.users.d.pop("kofi.removed")                    # the account is removed afterwards
    shown = json.dumps(F.shown(F.get(item["id"])))
    ok("4-3 the finding as shown never carries the removed account's sign-in name", "kofi.removed" not in shown, shown[:300])
    ok("4-3 …it names the account by its person code", person_code.code("kofi.removed") in shown, person_code.code("kofi.removed"))
    ok("4-3 …a present account by its full name", "Ama Owusu" in shown)

    # ------------------------------------------------------------------ 4-4, 4-7 cves.py
    print("4-4 / 4-7 cves.py (no network: made-up answers)")
    import cves as CV
    ids = [f"CVE-2099-{1000 + i}" for i in range(8)]

    def make(delay=0.0):
        ci = CV.CveIntel(os.path.join(TMP, f"cve_cache_{time.time_ns()}.json"))
        got = {"org": 0, "saves": 0}
        real_save = ci._save

        def fake_get(url, headers=None, timeout=30):
            if "cvelistV5" in url:
                got["org"] += 1
                time.sleep(delay)
                cid = url.rsplit("/", 1)[1][:-5]
                return {"cveMetadata": {"state": "PUBLISHED", "cveId": cid}, "containers": {"cna": {"title": f"Made-up {cid}",
                        "descriptions": [{"lang": "en", "value": "A made-up flaw."}]}}}
            if url.startswith(CV.EPSS):                 # the EPSS address exactly (cves.EPSS), not a substring
                return {"data": []}
            return {}
        ci._get = fake_get

        def count_save():
            got["saves"] += 1
            real_save()
        ci._save = count_save
        return ci, got
    ci, got = make()
    ci.lookup_many(ids)
    ok("4-4 a look-up of 8 CVEs writes the cache file at most twice (EPSS, then the batch), not once per record",
       got["saves"] <= 2, got)
    disk = json.load(open(ci.path))
    ok("4-4 …and every record is in the file", all(i in disk.get("cveorg", {}) for i in ids), sorted(disk.get("cveorg", {})))
    ci, got = make(delay=0.3)
    ci.cards(ids, fetch=True, budget=0.05)
    ok("4-7 cards(): its time budget is used (records after it are not fetched now)", got["org"] < len(ids), got)
    ci, got = make()
    ci.prefetch(ids, stop=lambda: True)
    ok("4-7 prefetch(): a stop asked for before it starts fetches no CVE.org record", got["org"] == 0, got)

    # ------------------------------------------------------------------ 4-8, 4-9 data_access.py; 4-8 install_cert.py
    print("4-8 / 4-9 data_access.py, deploy/install_cert.py")
    import data_access as DA
    added = []
    log = DA.DataAccessLog(lambda ev, **k: added.append((ev, k)), lambda: "grace", lambda ip: "R7")
    long_v = "examplebot-" + "x" * 289
    log.record("/api/events", {"name": long_v}, 200)
    det = added[-1][1]["detail"] if added else ""
    ok("4-8 a long value in the audit detail: no '…'", added and "…" not in det, det)
    ok("4-8 …it says in words how much is kept, of how many characters", "of 300 characters" in det and "(the first " in det, det)
    sel = log.selection({"ip": "203.0.113.9"})
    ok("4-8 …an address is still its host reference", "203.0.113.9" not in sel and "host R7" in sel, sel)
    ic = load("deploy/install_cert.py", "install_cert_b04")
    cp = os.path.join(TMP, "certproj")
    os.makedirs(os.path.join(cp, "data"))
    fp = ":".join(["AB"] * 32)
    ic._audit(cp, "Grace Mensah", {"domain": "lg.example.org", "not_after": 1893456000, "fingerprint": fp,
                                   "issuer": "CN=Example Issuing CA with a long name, O=Example Trust Services Limited, C=GH " * 2})
    alog = open(os.path.join(cp, "data", "audit.log"), encoding="utf-8").read() if os.path.exists(os.path.join(cp, "data", "audit.log")) else ""
    ok("4-8 the certificate's audit entry: no '…', the fingerprint in full", alog and "…" not in alog and fp in alog, alog[-300:])

    log2 = DA.DataAccessLog(lambda ev, **k: None, lambda: "grace", lambda ip: "R7")
    log2.record("/api/svc/hosts.csv", {"q": "x"}, 200)
    ok("4-9 a download leaves no remembered key (it is never looked up)", len(log2.seen) == 0, dict(log2.seen))
    cap = getattr(DA, "SEEN_MAX", 20000)
    for i in range(cap + 500):
        log2.record("/api/events", {"q": str(i)}, 200)
    ok(f"4-9 {cap + 500:,} different views within the window: at most {cap:,} remembered", len(log2.seen) <= cap, len(log2.seen))
    n = len(added)
    log.record("/api/events", {"name": long_v}, 200)
    ok("4-9 …the same view again within the window is still not logged twice", len(added) == n)

    # ------------------------------------------------------------------ 4-10 geo.py
    print("4-10 geo.py")
    import geo
    g = geo.Geocoder("", cache_path=os.path.join(TMP, "no-such-folder", "geocache.json"))
    lbl = "4-10 flush() to a folder that cannot be written does not raise (it says False)"
    r = guarded(lbl, g.flush)
    if r is not None:
        ok(lbl, r is False, r)

    def store_many():
        for i in range(30):
            g._store(f"GH|R{i}|", [1.0, 2.0])
        return True
    ok("4-10 …the 25th place stored (the automatic flush) does not fail the map's look-up",
       guarded("4-10 the automatic flush raised", store_many) is True)
    ok("4-10 …the places stay in memory", len([k for k in g.cache if k.startswith("GH|R")]) == 30)

    # ------------------------------------------------------------------ 4-5, 4-6 executive_pdf.py
    print("4-5 / 4-6 executive_pdf.py (made-up long values; every page read back with pypdfium2)")
    import executive_pdf as EXP
    import test_tools
    pdfium = test_tools.find_pypdfium2()
    ok("pypdfium2 is there to read the pages back (not skipped)", pdfium is not None)
    if pdfium is not None:
        src = open(os.path.join(HERE, "pdf_pages_check.py"), encoding="utf-8").read().split("\ndef made_up(")[0]
        PPC = types.ModuleType("pdf_pages_check_functions")
        PPC.__file__ = os.path.join(HERE, "pdf_pages_check.py")
        exec(compile(src, "pdf_pages_check.py", "exec"), PPC.__dict__)  # noqa: S102  (the project's own test file)
        out_dir = os.environ.get("LG_FIX_PDF_OUT")

        def pages(pdf, name):
            if out_dir:
                with open(os.path.join(out_dir, name), "wb") as fh:
                    fh.write(pdf)
            doc = pdfium.PdfDocument(pdf)
            return doc, [(i + 1, PPC.page_problems(doc[i])) for i in range(len(doc))]

        LONG = "Accessible and Exposed Management Interface of Very Long Named Network Equipment Family Number"
        # a card's sub-title, a two-line fitted heading on an explanation card, a long selection in the header
        d = EXP.Doc({"platform_label": "Services", "scope": "s", "day": "2026-11-17", "cities": [], "tz": None, "generated_by": "t",
                     "selection": "Region: " + ", ".join(f"Region number {i} of the country" for i in range(9))})
        y = d.new_page("Overview")
        d.text(EXP.M, y, "First line under the header", 9)
        top = d.card(EXP.M, y - 20, 330, 160, "A card", "Sub-title " + LONG + " " + LONG)
        d.text(EXP.M + 14, top, "The first line of the card's content", 9)
        d.explanation(420, y - 20, 330, "android." + "verylongfamilyname" * 4, {"curated": True, "title": "A family",
                      "description": "What it does, in a few words."}, "1,234 devices on 56 networks in 7 regions", True)
        doc, pp = pages(d.done(), "b04_parts.pdf")
        bad = [(p, x) for p, x in pp if x]
        doc.close()
        ok("4-5 header, card sub-title and explanation heading on two lines: no text drawn over other text", not bad, bad)

        def base():
            infs = [{"value": f"examplebot{i}", "title": f"ExampleBot {i} " + (LONG if i % 3 == 0 else ""), "hosts": 400 - i,
                     "count": 900 - i, "share": .01} for i in range(12)]
            dd = {"platform": "comms", "day": "2026-11-17", "cities_map": [], "tz": None,
                  "findings": ["Headline finding."] + [f"Finding {i}: " + "a finding long enough to wrap over two lines of the "
                                                         "page, saying what was seen and where, in full words. " * 3 for i in range(1, 41)],
                  "hours": [i % 5 + 1 for i in range(24)], "peak_hour": 4,
                  "regions": [{"value": "R1", "label": "The Region With A Really Long Official Name Of Many Words", "count": 60, "hosts": 40}],
                  "region_details": {"R1": {"city_devices": [["A City With A Really Long Official Name Of Many Words Too", 30],
                                                             ["Tema", 8]], "city_devices_total": 2}},
                  "sectors": [{"label": f"Sector {i} " + LONG, "value": f"s{i}", "count": 900 - i, "hosts": 9} for i in range(4)],
                  "attack": [{"label": "Botnet", "value": "botnet", "count": 3000}], "families": [],
                  "networks": [{"label": f"Network number {i}", "value": f"v{i}", "count": 500 - i, "hosts": 300 - i} for i in range(5)],
                  "destinations": [{"label": "US", "count": 100}], "services": [],
                  "multi": {"devices": 10, "hosts": 10, "share": .1, "by_count": [{"label": "2", "count": 8}], "combos": [], "combinations": 0},
                  "cross": {"devices": 7, "hosts": 7, "share": .07, "by_count": [{"label": "2", "count": 7}], "combinations": 0, "combos": [],
                            "pairs": []}, "report_pairs": [], "beacon": {"repeating": 0, "regular": 0, "typical": ""},
                  "issue_kinds": [], "severity": [], "reports": [{"label": "Sinkhole Events", "value": "event4_sinkhole", "hosts": 300, "count": 900}],
                  "totals": {"infections": 12, "networks": 5, "destinations": 1}, "infections": infs,
                  "kpis": {"devices": 300, "infections": 12, "multi_infected": 10, "cross_report": 7, "regions": 1, "networks": 5,
                           "events": 4000, "share_of_day": .4, "critical": 3}}
            dd["baseline"] = {"days": [f"2026-11-{x:02d}" for x in range(10, 17)], "available": 7, "kpis": {"devices": [10] * 7},
                              "items": {r["value"]: [100, 101, 99, 100, 102, 98, 100] for r in infs}, "assess": {"kpis": {}, "items": {}},
                              "scale": []}
            return dd
        meta = {"platform_label": "Network communications", "scope": "Example country", "selection": "Whole country",
                "generated_by": "Grace Mensah", "shapes": None, "nomap": True, "stats": {}, "demo": False}
        pdf = guarded("4-5/4-6 the Executive PDF with long values builds", lambda: EXP.build(base(), {}, meta))
        if pdf:
            doc, pp = pages(pdf, "b04_executive.pdf")
            text = "\n".join(doc[i].get_textpage().get_text_range() for i in range(len(doc)))
            over = [(p, x) for p, x in pp if any("drawn over" in y for y in x)]
            edge = [(p, x) for p, x in pp if any("beyond the page edge" in y for y in x)]
            doc.close()
            ok("4-5 the whole Executive PDF with long names: no text drawn over other text", not over, over)
            ok("4-6 40 findings, the rest on 'Key findings (continued)' pages: no text beyond the page's edge", not edge, edge)
            ok("4-6 …every finding is in it, the last one (40.) too", all(f"Finding {i}:" in text for i in range(1, 41)) and "40." in text,
               [i for i in range(1, 41) if f"Finding {i}:" not in text])
            ok("4-6 …continued over more than one page", text.count("Key findings (continued)") >= 2, text.count("Key findings (continued)"))
            ok("4-5/4-6 …and no '…' anywhere", "…" not in text)
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
