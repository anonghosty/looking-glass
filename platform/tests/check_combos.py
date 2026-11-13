#!/bin/sh
# runs itself with the project's own Python (.venv), from wherever it is called
''''exec "$(dirname -- "$0")/../.venv/bin/python" "$0" "$@" # '''
"""Combination codes and the analyst's combination search (combos.py), end to end, in-process, on throwaway files
(the real data/combo_codes.json and data/notes.json are never touched):

* the matching rule (intel.record_items) gives exactly the combinations Intel gathered counts;
* every combination Intel gathered shows has a code, the same code every time, and it resolves;
* the search over the days in memory finds exactly the devices Intel gathered counted, per report and across reports;
* the same day read from MongoDB (the history path) gives the same devices as the copy in memory;
* the ZIP: a PDF and two CSV files, with the devices, no spreadsheet formula;
* a researcher can build a code only from the name's real indicators, and attach codes to a note; unknown codes refused;
* who may do what: researchers and management read what a code means (no address in it), only analysts and admins
  search, never in demo mode.
Usage: tests/check_combos.py"""
import collections, csv, io, json, os, re, sys, tempfile, time, urllib.parse, zipfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import needs_db  # noqa: E402
needs_db.require()   # no reachable MongoDB (a fresh clone, CI): skipped, not crashed
import app as A  # noqa: E402
import combos as C  # noqa: E402
import intel as I  # noqa: E402
import notes as N  # noqa: E402
from flask import g  # noqa: E402

fails, checks = [], 0
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond: fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{info}]" if info else ""), flush=True)


ANALYST = {"view", "unmasked", "export", "malpedia"}
RESEARCHER = {"definitions", "networks"}


def call(path, perms, method="GET", body=None, role="analyst", raw=False):
    with A.app.test_request_context(path, method=method, json=body):
        g.user = {"user": "lg-check", "role": role, "perms": set(perms), "csrf": None, "automation": True}
        ep = A.app.url_map.bind("localhost").match(path.split("?")[0], method=method)
        r = A.app.view_functions[ep[0]](**ep[1])
        code = r[1] if isinstance(r, tuple) else r.status_code
        r = r[0] if isinstance(r, tuple) else r
        if raw:
            return code, r.get_data()
        return code, json.loads(r.get_data(as_text=True) or "{}")


JIDS = []                                  # the check's searches (their downloads are kept in its temporary folder)


def wait(jid, perms=ANALYST):
    JIDS.append(jid)
    for _ in range(600):
        code, d = call(f"/api/combos/search/{jid}", perms)
        if d.get("state") != "running":
            return d
        time.sleep(0.2)
    return {"state": "timeout"}


tmp = tempfile.mkdtemp(prefix="lg-combos-")
book = A.COMBOS
real_path, real_data, real_loaded = book.path, book.data, book.loaded
real_exports = book.export_paths["dir"]                  # the check's downloads go to its temporary folder, not data/
book.export_paths["dir"] = EXPORTS = os.path.join(tmp, "combo_exports")
book.path, book.data, book.loaded = os.path.join(tmp, "combo_codes.json"), {}, True
real_notes = A.NOTES
audit = A.AUTH["audit"]
real_add = audit.add
audited = []
audit.add = lambda *a, **k: audited.append((a, k))     # the check's searches stay out of the real audit log
# the report itself is checked here; management's decision on across-report views is checked in check_combo_review.py
real_gate = getattr(A.COMBOS, "review_gate", None)
A.COMBOS.review_gate = lambda j: (True, "")
try:
    for d in (A.replay_now(),):
        A.store.get(d); A.svc["store"].get(d)
    data = A.INTEL.index()
    labels = {**{x["name"]: x["label"] for x in A.registry.get()}, **{x["name"]: x["label"] for x in A.svc["registry"].get()}}

    print("The matching rule")
    comms = [e for d in A.store.days.values() for e in d.events]
    svc = [e for d in A.svc["store"].days.values() for e in d.events]
    want = collections.defaultdict(collections.Counter)
    for e in comms:
        n = (e.get("infection") or "").lower()
        if n:
            want[("infections", n, labels.get(e.get("source"), e.get("source") or ""))][I.record_items("infections", e, I._norm(n))] += 1
    for e in svc:
        for issue in e.get("issues") or []:
            want[("issues", issue, e.get("report_label") or e.get("report") or "")][I.record_items("issues", e, I._norm(issue))] += 1
    have = {(s, n, r): slot["combos"] for (s, n), reps in data["by"].items() for r, slot in reps.items()}
    diff = [k for k in set(want) | set(have) if collections.Counter(want.get(k)) != collections.Counter(have.get(k))]
    ok("record_items gives exactly the combinations Intel gathered counts, for every name and report", not diff and have, f"{len(have)} name/report pairs; differ: {diff[:2]}")

    print("Codes")
    # the name with the most combinations, and one with a cross-report pattern
    best = max(((k, len(slot["combos"])) for k, reps in data["by"].items() if k[0] == "infections" for slot in reps.values()), key=lambda x: x[1])[0]
    gat = A.INTEL.gathered(*best)
    rep = max(gat["reports"], key=lambda r: len(r["combinations"]))
    c0 = rep["combinations"][0]
    ok("every combination shown carries a code", all(re.match(r"^LG-C-[0-9A-F]{8}$", c["code"]) for r in gat["reports"] for c in r["combinations"]), c0["code"])
    ok("the same combination gives the same code every time", A.INTEL.gathered(*best)["reports"][0]["combinations"][0]["code"] == gat["reports"][0]["combinations"][0]["code"])
    ok("a code carries no address", not IP_RX.search(json.dumps([c["code"] for r in gat["reports"] for c in r["combinations"]])))
    ok("the codes shown were written to the code book", c0["code"] in book.data and os.path.exists(book.path))
    code, d = call(f"/api/combo-codes/{c0['code']}", RESEARCHER, role="researcher")
    ok("a researcher reads what a code means", code == 200 and d["name"] == best[1] and d["items"] == sorted(c0["items"]), d.get("text", "")[:90])
    ok("…with no address in the answer", not IP_RX.search(json.dumps({k: v for k, v in d.items() if k != "notes"})))
    code, _ = call(f"/api/combo-codes/{c0['code']}", {"management"}, role="management")
    ok("management reads it too", code == 200)
    code, _ = call(f"/api/combo-codes/{c0['code']}", {"view"}, role="external")
    ok("external: refused", code == 403, f"HTTP {code}")
    code, _ = call("/api/combo-codes/LG-C-00000000", ANALYST)
    ok("an unknown code: 404", code == 404)
    book.data.clear()
    code, d = call(f"/api/combo-codes/{c0['code']}", ANALYST)
    ok("a code missing from the book is found again in memory", code == 200 and d["name"] == best[1])

    print("The search over the days in memory")
    code, d = call("/api/combos/search", RESEARCHER, "POST", {"code": c0["code"]}, role="researcher")
    ok("researcher: cannot search (addresses)", code == 403, f"HTTP {code}")
    code, d = call("/api/combos/search", {"management"}, "POST", {"code": c0["code"]}, role="management")
    ok("management: cannot search", code == 403, f"HTTP {code}")
    code, d = call("/api/combos/search?demo=1", ANALYST, "POST", {"code": c0["code"]})
    ok("demo mode: the search is off (it lists real addresses)", code == 403 and "demo" in d.get("error", "").lower(), f"HTTP {code}")
    code, d = call("/api/combos/search", ANALYST, "POST", {"code": c0["code"]})
    ok("analyst: the search starts", code == 200, f"HTTP {code} {d.get('error', '')}")
    j = wait(d["id"])
    s = j.get("summary") or {}
    ok("the devices found are exactly the devices Intel gathered counted", j["state"] == "done" and s.get("devices") == c0["hosts"],
       f"found {s.get('devices')}, Intel gathered {c0['hosts']}")
    ok("…and the records with a device are at most the records counted", s.get("records", 0) <= c0["count"] and s.get("records", 0) >= c0["hosts"],
       f"{s.get('records')} of {c0['count']}")
    ok("the repeating devices agree too", s.get("repeat") == c0["repeat_hosts"], f"{s.get('repeat')} vs {c0['repeat_hosts']}")
    xa = s.get("across") or {}
    ok("the devices are followed into the name's other reports (cross-report patterns, each with an LG-X code)",
       "patterns" in xa and all(re.match(r"^LG-X-[0-9A-F]{8}$", p["code"]) for p in xa["patterns"]),
       f"{xa.get('multi')} devices in other reports, {xa.get('patterns_total')} patterns")
    if xa.get("patterns"):
        code_x, dx = call(f"/api/combo-codes/{xa['patterns'][0]['code']}", ANALYST)
        ok("…and those codes resolve, so the analyst can search them next", code_x == 200 and dx.get("kind") == "x")
    ok("devices per region are counted", sum(r["devices"] for r in s.get("regions") or []) <= s.get("devices", 0) and s.get("regions"),
       ", ".join(f"{r['label']} {r['devices']}" for r in (s.get("regions") or [])[:3]))
    code, z = call(f"/api/combos/search/{d['id']}/download", ANALYST, raw=True)
    ok("the ZIP is also kept on disk (owner-only), so a service restart before the download loses nothing",
       os.path.exists(os.path.join(EXPORTS, d["id"] + ".zip"))
       and oct(os.stat(os.path.join(EXPORTS, d["id"] + ".zip")).st_mode & 0o777) == "0o600")
    zf = zipfile.ZipFile(io.BytesIO(z))
    names = zf.namelist()
    ok("the ZIP holds a PDF, the devices CSV and the records CSV", len(names) == 3 and any(n.endswith(".pdf") for n in names)
       and any(n.endswith("_devices.csv") for n in names) and any(n.endswith("_records.csv") for n in names), ", ".join(names))
    pdf = zf.read(next(n for n in names if n.endswith(".pdf")))
    ok("the PDF is a PDF", pdf[:5] == b"%PDF-", f"{len(pdf):,} bytes")
    devs = zf.read(next(n for n in names if n.endswith("_devices.csv"))).decode("utf-8-sig").splitlines()
    recs = zf.read(next(n for n in names if n.endswith("_records.csv"))).decode("utf-8-sig").splitlines()
    ok("one CSV row per device, one per record", len(devs) - 1 == s["devices"] and len(recs) - 1 == s["records"], f"{len(devs) - 1} / {len(recs) - 1}")
    ok("stable column names for enrichment (source_ip …, combination_code)", recs[0].startswith("time,source_ip,") and recs[0].endswith("combination_code"))
    ok("no cell starts like a spreadsheet formula", not any(re.search(r'(^|,)"?[=+@]', line) for line in devs[1:] + recs[1:]))
    # after a restart (the search gone from memory) the copy on disk is served only if the review gate allows it NOW
    # (review 2026-11-13: the flag kept with it was a snapshot)
    kept_job = book.jobs.pop(d["id"])
    real_gate = getattr(book, "review_gate", None)
    meta_p = os.path.join(EXPORTS, d["id"] + ".json")
    meta = json.load(open(meta_p)); meta["gated"] = False; json.dump(meta, open(meta_p, "w"))   # only the gate decides here
    try:
        book.review_gate = lambda job: (False, "Waiting for management's decision (test)")
        code_r, _ = call(f"/api/combos/search/{d['id']}/download", ANALYST, raw=True)
        ok("after a restart: a combination sent to management since is NOT downloaded from disk", code_r == 409, f"HTTP {code_r}")
        seen = {}
        book.review_gate = lambda job: (seen.update(code=job["inputs"][0]["code"]), (True, ""))[1]
        code_r, zr = call(f"/api/combos/search/{d['id']}/download", ANALYST, raw=True)
        ok("…the gate is asked about this combination, and when it allows, the copy on disk is served",
           code_r == 200 and zr[:2] == b"PK" and seen.get("code") == c0["code"], f"HTTP {code_r} {seen}")
        meta = json.load(open(meta_p)); meta.pop("code", None); json.dump(meta, open(meta_p, "w"))
        code_r, _ = call(f"/api/combos/search/{d['id']}/download", ANALYST, raw=True)
        ok("…a copy kept by an older version (no code to ask about): not served", code_r == 409, f"HTTP {code_r}")
    finally:
        book.review_gate = real_gate
        if real_gate is None:
            del book.review_gate
        book.jobs[d["id"]] = kept_job
    # the report for one network provider: only its devices and records
    na = (s.get("networks_all") or [{}])[0]
    code_n, zn = call(f"/api/combos/search/{d['id']}/download?network={urllib.parse.quote(na.get('label', ''))}", ANALYST, raw=True)
    zfn = zipfile.ZipFile(io.BytesIO(zn))
    dn = zfn.read(next(n for n in zfn.namelist() if n.endswith("_devices.csv"))).decode("utf-8-sig").splitlines()
    hdr = dn[0].split(",")
    nets_in = {next(csv.reader([line]))[hdr.index("network")] for line in dn[1:]}
    ok("a report for one network provider holds only its devices, as many as listed for it", code_n == 200 and nets_in == {na.get("label")}
       and len(dn) - 1 == na.get("devices"), f"{na.get('label')}: {len(dn) - 1} devices · files {', '.join(n.split('_')[-1] for n in zfn.namelist())}")
    with A.app.test_request_context(f"/api/combos/search/{d['id']}"):
        g.user = {"user": "someone-else", "role": "analyst", "perms": ANALYST, "csrf": None, "automation": True}
        r = A.app.view_functions["api_combos_status"](d["id"])
        other = r[1] if isinstance(r, tuple) else r.status_code
    ok("another analyst cannot read or download someone else's search", other == 404, f"HTTP {other}")

    print("Across reports")
    xs = [(k, x) for k in data["by"] for x in (A.INTEL.gathered(*k)["across"]["cross_combos"] if len(data["by"][k]) > 1 else [])][:1]
    if xs:
        (k, x) = xs[0]
        code, d = call("/api/combos/search", ANALYST, "POST", {"code": x["code"]})
        j = wait(d["id"])
        ok("a cross-report code finds exactly the devices counted", (j.get("summary") or {}).get("devices") == x["devices"],
           f"{k[1]}: found {(j.get('summary') or {}).get('devices')}, counted {x['devices']}")
    else:
        ok("a cross-report code (no name in memory has one today: skipped)", True)

    print("Management: the Executive portal filtered by a code (counts only)")
    code_m, dm = call(f"/api/mgmt/comms?code={c0['code']}", {"management"}, role="management")
    ok("the Executive portal counts exactly the devices Intel gathered counted for the code", code_m == 200 and dm["kpis"]["devices"] == c0["hosts"],
       f"{dm.get('kpis', {}).get('devices')} vs {c0['hosts']}")
    ok("…without any address in the answer, and without a 7-day comparison", not IP_RX.search(json.dumps(dm)) and dm.get("baseline") is None)
    code_m, dm = call(f"/api/mgmt/services?code={c0['code']}", {"management"}, role="management")
    ok("a code of the other platform matches nothing there", code_m == 200 and not dm["kpis"]["hosts"], str(dm.get("kpis", {}).get("hosts")))
    code_m, dm = call("/api/findings", {"management"}, role="management")
    ok("management gets 'Show in Executive' on findings, never the search", dm.get("can_portal") and not dm.get("can_search"))
    print("The stored history (MongoDB)")
    day = sorted(A.store.days)[-1]
    entry = book.get(c0["code"]) or C.CodeBook.get(book, c0["code"])
    m = C.Matcher(entry, labels)
    mem = {m.host(e) for e in m.match(A.store.days[day].events)}
    cols = {c for c, lbl in labels.items() if lbl == entry["report"]}
    db = {m.host(e) for e in m.match(A._combo_fetch("infections", cols, day))}
    ok("one day read from MongoDB gives the same devices as the copy in memory", mem == db, f"{day.date()}: {len(mem)} in memory, {len(db)} from MongoDB")
    f = (day - A.timedelta(days=2)).date().isoformat()
    code, d = call("/api/combos/search", ANALYST, "POST", {"code": c0["code"], "from": f, "to": day.date().isoformat()})
    j = wait(d["id"])
    ok("a date range runs day by day and reports each day", j["state"] == "done" and len((j.get("summary") or {}).get("per_day") or []) == 3,
       "; ".join(j.get("log") or [])[:160])
    code, d = call("/api/combos/search", ANALYST, "POST", {"code": c0["code"], "from": "2026-01-01", "to": "2026-03-01"})
    ok(f"more than {C.MAX_DAYS} days: refused", code == 400, d.get("error", ""))

    print("Researchers: building a code, and codes on notes")
    items = c0["items"]
    code, d = call("/api/combo-codes/new", RESEARCHER, "POST", {"section": "infections", "name": best[1], "report": rep["report"], "items": items}, role="researcher")
    ok("a researcher builds a code from ticked indicators: the same code as the one shown", code == 200 and d["code"] == c0["code"] and d["devices"] == c0["hosts"],
       f"{d.get('code')} · {d.get('records')} records")
    code, d = call("/api/combo-codes/new", RESEARCHER, "POST", {"section": "infections", "name": best[1], "report": rep["report"], "items": ["not-a-real-value.example"]}, role="researcher")
    ok("an indicator the name does not carry is refused (no typos)", code == 400, d.get("error", ""))
    code, _ = call("/api/combo-codes/new", ANALYST, "POST", {"section": "infections", "name": best[1], "report": rep["report"], "items": items})
    ok("an analyst cannot make codes (researchers' work)", code == 403, f"HTTP {code}")
    notes = N.Notes(os.path.join(tmp, "notes.json"), A.people); notes.codes = book
    A.NOTES = notes
    n = notes.add("infections", best[1], "Test: this set keeps coming back.", "lg-check", "researcher", [c0["code"]])
    ok("a note carries its codes, with what each means", n["codes"] and n["codes"][0]["code"] == c0["code"] and best[1] in n["codes"][0]["text"], n["codes"][0]["text"][:80])
    card, _ = A.mp_resolve(best[1])
    ok("the name's card (map, services, Executive, PDF) carries the note's codes", any(c["code"] == c0["code"] for x in card.get("notes") or [] for c in x.get("codes") or []))
    code, d = call("/api/notes", RESEARCHER, "POST", {"section": "infections", "name": best[1], "text": "x", "codes": ["LG-C-00000000"]}, role="researcher")
    ok("a note with an unknown code is refused", code == 400, d.get("error", ""))
    ok("every search and every code made is in the audit log", {a[0] for a, _ in audited} >= {"combo_export", "combo_code"},
       ", ".join(sorted({a[0] for a, _ in audited})))
finally:
    if real_gate:
        A.COMBOS.review_gate = real_gate
    book.export_paths["dir"] = real_exports              # its downloads go with the temporary folder below
    audit.add = real_add
    A.NOTES = real_notes
    book.path, book.data, book.loaded = real_path, real_data, real_loaded
    import shutil; shutil.rmtree(tmp, ignore_errors=True)
print(f"\n{checks - len(fails)} of {checks} combination checks passed" + (f"; FAILED: {fails}" if fails else ""))
sys.exit(1 if fails else 0)
