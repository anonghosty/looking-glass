#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""The fixes of the whole-codebase audit, batch 07 (2026-11-27), each kept fixed:
  7-2  a PDF downloaded alone (format=pdf) names no CSV file that does not come with it;
  7-3  a long table cell in a PDF is printed whole, on the page (no "… (more in the CSV)");
  7-4  a services record's extras, product and version are kept whole, or say in words that they were shortened;
  7-5  the response cache keeps no lock for a key nobody works on;
  7-6  a request waiting for a hung computation of the same answer gives up after WAIT_S and answers;
  7-7  a selection's replay counter keeps only positions, not two lists of the day's records;
  7-8  the security retest fails the run when a check is skipped;
  7-9  a Shadowserver report page's lines and field descriptions are read whole;
  7-10 the unused PDF parts (kpi_grid, bar_hours, bar_top) are gone;
  7-11 opening a record on the services platform reads the day once, not twice per click;
  7-12 three constituency changes during one load never return a day of the old constituency;
  7-13 two workers never both run the "seen in" backfill;
  7-14 the replay schedule asks MongoDB for a day's rows once per tick.
In-process, made-up data, temporary folders, no database, no network. LG_B07_ROOT: the code to check (default: this
project; the audit's old copy to prove the checks fail there). Run: .venv/bin/python tests/check_fix_b07.py"""
import ast
import os
import sys
import tempfile
import threading
import time
import types
from datetime import datetime, timedelta, timezone

ROOT = os.environ.get("LG_B07_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("LG_QUIET", "1")
OUT = os.environ.get("LG_B07_OUT") or tempfile.mkdtemp(prefix="lg-b07-")

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    print(("  ok   " if cond else "  FAIL ") + label + ("" if cond else f"  [{str(info)[:600]}]"), flush=True)
    if not cond:
        fails.append(label)


def attempt(label, fn):
    """A check whose code may not exist in the code checked (the old copy): an error is a failed check."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        ok(label, False, f"{type(e).__name__}: {e}")


# ------------------------------------------------------------------------------------------------------- 7-3, 7-10, 7-2
print("7-3 / 7-10 / 7-2: the analysis PDF (reports_pdf.py, report_downloads.py)")
import reports_pdf as RP  # noqa: E402

LONG = " ".join(f"w{i:04d}" for i in range(500)) + " LASTWORD-END"          # 3,013 characters
ok("7-3 a cell's text is kept whole (3,013 characters, no cut)", RP._cell(LONG) == LONG, RP._cell(LONG)[-60:])


def _pdf_check():
    spec = {"platform_label": "Publicly accessible / vulnerable services", "title": "Check b07", "selection": "Selection",
            "day": "2026-11-27", "scope": "Test", "columns": [["name", "Name"], ["text", "Text"]],
            "rows": [{"name": "row one", "text": LONG}, {"name": "row two", "text": "short"}], "total": 2,
            "sources": ["Made-up data."]}
    pdf = RP.build(spec)
    path = os.path.join(OUT, "b07_long_cell.pdf")
    with open(path, "wb") as f:
        f.write(pdf)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import test_tools                              # pypdfium2: this Python's, else the maintainer's (missing = a FAIL)
    pdfium = test_tools.find_pypdfium2()
    if pdfium is None:
        raise RuntimeError("pypdfium2 is needed to read the PDF's own text")
    doc = pdfium.PdfDocument(pdf)
    text, off = "", []
    for i in range(len(doc)):
        page = doc[i]
        w, h = page.get_size()
        tp = page.get_textpage()
        text += tp.get_text_range() + "\n"
        for c in range(tp.count_chars()):
            x0, y0, x1, y1 = tp.get_charbox(c)
            if x0 < 0 or y0 < 0 or x1 > w + 0.5 or y1 > h + 0.5:
                off.append((i + 1, c))
        page.render(scale=1.2).to_pil().save(os.path.join(OUT, f"b07_long_cell_p{i + 1}.png"))
    flat = " ".join(text.split())
    ok("7-3 the PDF prints the whole cell (its last word is there) and no 'more in the CSV'",
       "LASTWORD-END" in flat and "w0499" in flat and "more in the CSV" not in flat, flat[-300:])
    ok("7-3 nothing is drawn off the page", not off, off[:5])
    ok("7-2 a PDF without a CSV names no CSV file delivered with it", "delivered with this report" not in flat, flat[:300])
    print(f"   (pages rendered for a look: {OUT}/b07_long_cell_p*.png)")


attempt("7-3 the PDF with a long cell builds and renders", _pdf_check)
ok("7-10 the unused kpi_grid, bar_hours and bar_top are gone",
   not any(hasattr(RP, n) for n in ("kpi_grid", "bar_hours", "bar_top")), [n for n in ("kpi_grid", "bar_hours", "bar_top") if hasattr(RP, n)])


def _downloads():
    """Both report routes, run against a stand-in for app.py: the spec they give reports_pdf.build, and what they send."""
    import report_downloads as RD
    specs = []
    views = {"svc_insight": {"breakdowns": {}, "day": "2026-11-27"}, "api_insight": {"breakdowns": {}, "as_of": "2026-11-27T10:00:00Z"},
             "svc_drill": {"rows": [], "columns": [["ip", "Host IP"]], "title": "T", "metric": "hosts"},
             "api_insight_drill": {"rows": [], "columns": [["ip", "Host IP"]], "title": "T", "metric": "hosts"},
             "svc_glossary": {"reports": []}}
    fake = types.SimpleNamespace(
        AUTH={"has_perm": lambda p: p == "export", "audit": types.SimpleNamespace(add=lambda *a, **k: None)},
        request=types.SimpleNamespace(args={}), jsonify=lambda **k: k, _view_json=lambda n: (views[n], None),
        _bd_rows=RD._bd_rows, _pdf_rows=RD._pdf_rows, _pdf_label=lambda: "Selection", _file_base=RD._file_base,
        g=types.SimpleNamespace(user={"user": "someone"}), _scope_text=lambda: "Test", is_demo=lambda: False,
        SOURCES_TEXT=RD.SOURCES_TEXT, _report_response=RD._report_response, _enrich_names=lambda o: ({}, {}, ""),
        Counter=__import__("collections").Counter, registry=types.SimpleNamespace(get=lambda: []), _report_def=lambda n: {},
        Response=lambda body, mimetype=None, headers=None: {"mimetype": mimetype, "headers": headers})
    old_a, old_build, old_people = RD._A, RP.build, getattr(RD, "_people", None)
    try:
        RD._A = fake
        RP.build = lambda spec: specs.append(spec) or b"%PDF-1.4"
        if old_people is not None:
            RD._people = types.SimpleNamespace(signed_by=lambda u: "Person")
        got = {}
        for route in ("api_svc_report_pdf", "api_insight_report_pdf"):
            for fmt in ("pdf", None):
                fake.request.args = {"all": "1", **({"format": fmt} if fmt else {})}
                specs.clear()
                resp = getattr(RD, route)()
                got[(route, fmt)] = (specs[-1], resp)
    finally:
        RD._A, RP.build = old_a, old_build
        if old_people is not None:
            RD._people = old_people
    for route in ("api_svc_report_pdf", "api_insight_report_pdf"):
        sp, resp = got[(route, "pdf")]
        ok(f"7-2 {route} format=pdf: a PDF alone, naming no CSV (no csv_name, no 'CSV file delivered' line)",
           resp["mimetype"] == "application/pdf" and not sp.get("csv_name")
           and not any("delivered with this report" in s for s in sp.get("sources") or []), (sp.get("csv_name"), sp.get("sources", [])[-1:]))
        sp, resp = got[(route, None)]
        ok(f"7-2 {route} as a ZIP: the CSV is named, as before", resp["mimetype"] == "application/zip" and sp.get("csv_name"))


attempt("7-2 the report routes with format=pdf", _downloads)

# ------------------------------------------------------------------------------------------------------- 7-4, 7-12
print("7-4 / 7-12: the services day (services.py)")
import services as SV  # noqa: E402

src_ = {"name": "scan_http", "label": "Accessible HTTP", "family": "Exposed service"}
doc = {"_id": 1, "ip": "192.0.2.1", "http_title": "T" * 1000, "server": "P" * 200, "version": "V" * 100, "huge": "H" * 5000}
n = SV.normalise_service(doc, src_)
ok("7-4 an extra of 1,000 characters, a product of 200 and a version of 100 are kept whole",
   n["extras"].get("http_title") == "T" * 1000 and n["product"] == "P" * 200 and n["version"] == "V" * 100,
   (len(n["extras"].get("http_title", "")), len(n["product"]), len(n["version"])))
hv = n["extras"].get("huge", "")
ok("7-4 a 5,000-character extra is shortened and says so in words (no '…')", "shortened" in hv and "…" not in hv
   and "5,000" in hv, hv[-90:])


def _three_changes():
    st = SV.ServiceStore(None, None, None, None)
    start = datetime(2026, 11, 26, tzinfo=timezone.utc)

    def load(s, old=None):
        st.gen = getattr(st, "gen", 0) + 1            # the constituency changes during every load
        return SV.Day(s, [{"_t": s.timestamp(), "ip": "192.0.2.9", "old_constituency": True}])
    st._load = load
    got = st.get(start)
    ok("7-12 three constituency changes during the loads: no record of the old constituency is returned or kept",
       not got.events and start not in st.days, len(got.events))


attempt("7-12 the store's three loads", _three_changes)

# ------------------------------------------------------------------------------------------------------- 7-5, 7-6
print("7-5 / 7-6: the response cache (response_cache.py)")
import response_cache as RC  # noqa: E402
from flask import Flask  # noqa: E402

os.environ["CACHE_TTL_S"] = "180"
RC.OVERRIDE["path"] = None
fapp = Flask("b07")
gate, hang = threading.Event(), {"next": False}


@fapp.route("/x")
def _x():
    from flask import request
    if hang["next"]:                             # this computation hangs (until the check lets it go)
        hang["next"] = False
        gate.wait(30)
    return {"v": len(request.args.get("q", ""))}      # a number from the request, never its text echoed back


rc = RC.install(fapp, ["_x"])
cl = fapp.test_client()
for i in range(50):
    cl.get(f"/x?q={i}")
ok("7-5 after 50 different answers, no lock is left for a key nobody works on", len(rc.locks) == 0, len(rc.locks))
RC.WAIT_S = 1
res = {}
hang["next"] = True
t1 = threading.Thread(target=lambda: res.setdefault("a", fapp.test_client().get("/x?q=h")), daemon=True)
t1.start()
time.sleep(0.3)
t2 = threading.Thread(target=lambda: res.setdefault("b", fapp.test_client().get("/x?q=h")), daemon=True)
t0 = time.time()
t2.start()
t2.join(5)
waited = time.time() - t0
ok("7-6 a request waiting for a hung computation of its answer answers after WAIT_S (not never)",
   not t2.is_alive() and "b" in res and res["b"].status_code == 200 and waited < 4, f"alive={t2.is_alive()} waited={waited:.1f}s")
gate.set()
t1.join(5)
t2.join(5)
ok("7-5 ...and the hung key's lock is gone once both are done", len(rc.locks) == 0, len(rc.locks))

# ------------------------------------------------------------------------------------------------------- 7-7
print("7-7: the replay counter (replay_counts.py)")
import bisect  # noqa: E402
import replay_counts as RPC  # noqa: E402

N = 100000
evs = [{"_t": float(i), "ip": f"10.0.{i % 250}.{i % 7}", "m": i % 2 == 0} for i in range(N)]
day = types.SimpleNamespace(start=datetime(2026, 11, 26, tzinfo=timezone.utc), events=evs, keys=[e["_t"] for e in evs],
                            serial=1, version="v")
cnt = RPC.ReplayCounts()
m = cnt.of(day, ("m",), lambda e: e["m"], lambda e: e["ip"])
want = [e for e in evs if e["m"]]
good = all(cnt.at(m, t) == (bisect.bisect_right([e["_t"] for e in want], t),
                            next((e for e in want if e["_t"] > t), None)) for t in (-1.0, 0.0, 10.5, 99998.0, 99999.0, 1e9))
ok("7-7 the answers are the ones of a full scan (count, next record, hosts, total)",
   good and len(m["keys"]) == len(want) and m["hosts"] == len({e["ip"] for e in want}))


def _size(v, seen=None):
    seen = seen or set()
    if id(v) in seen:
        return 0
    seen.add(id(v))
    s = sys.getsizeof(v)
    if isinstance(v, dict):
        s += sum(_size(x, seen) for x in v.values())
    elif isinstance(v, (list, tuple)):
        s += sum(sys.getsizeof(x) if isinstance(x, (int, float)) else 0 for x in v) if isinstance(v, list) else sum(_size(x, seen) for x in v)
    return s


kept = sum(_size(v) for v in cnt.cache.data.values())
ok("7-7 what is kept for 50,000 matching records is about 4 bytes each (under 300 KB), not two lists of the records",
   kept < 300_000, f"{kept:,} bytes")

# ------------------------------------------------------------------------------------------------------- 7-8
print("7-8: the security retest's verdict (security_testing/security_retest.py)")


def _retest_exit(fails_, skips_):
    """Run the retest's own last lines (and verdict(), when it has one) with these counts: (exit code, printed)."""
    path = os.path.join(ROOT, "security_testing", "security_retest.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    body = tree.body
    last_try = max(i for i, s in enumerate(body) if isinstance(s, ast.Try))
    keep = [s for s in body if isinstance(s, ast.FunctionDef) and s.name == "verdict"] + body[last_try + 1:]
    out, code = [], [None]

    class _Exit(Exception):
        pass

    def _exit(c=0):
        code[0] = c
        raise _Exit()
    ns = {"fails": fails_, "SKIPS": list(skips_), "sys": types.SimpleNamespace(exit=_exit), "print": lambda *a, **k: out.append(" ".join(map(str, a)))}
    try:
        exec(compile(ast.Module(body=keep, type_ignores=[]), path, "exec"), ns)  # nosec B102  # the project's own file
    except _Exit:
        pass
    return code[0], " ".join(out)


attempt("7-8 the retest's verdict", lambda: (
    ok("7-8 a run with a skipped check exits 1 and says what was not checked",
       _retest_exit(0, ["demo mode: the opaque reference still works"])[0] == 1
       and "demo mode" in _retest_exit(0, ["demo mode: the opaque reference still works"])[1], _retest_exit(0, ["x"])),
    ok("7-8 ...a clean run still exits 0, a failed one 1", _retest_exit(0, [])[0] == 0 and _retest_exit(2, [])[0] == 1,
       (_retest_exit(0, []), _retest_exit(2, [])))))

# ------------------------------------------------------------------------------------------------------- 7-9
print("7-9: a Shadowserver report page (report_map.py)")
import report_map as RMP  # noqa: E402

para = "Long paragraph " + "x" * 3000 + " PARA-END."
note = "You can track this report " + "y" * 900 + " NOTE-END."
fdesc = "Field description " + "z" * 1000 + " FIELD-END"
page = ('<h1>Accessible Example Report</h1><div class="content"><p>' + para + "</p><p>" + note + "</p></div>"
        '<div class="fields-list"><div class="name">ip</div><div class="description">' + fdesc + "</div></div>")
pg = RMP.parse_page(page) or {}
ok("7-9 a 3,000-character line, a 900-character note and a 1,000-character field description are read whole",
   any(b["text"] == para for b in pg.get("blocks", [])) and note in pg.get("notes", []) and pg.get("fields", {}).get("ip") == fdesc,
   ([len(b["text"]) for b in pg.get("blocks", [])], [len(x) for x in pg.get("notes", [])], len(pg.get("fields", {}).get("ip", ""))))

# ------------------------------------------------------------------------------------------------------- 7-11
print("7-11: opening a record (services_api.py)")


class _Counted(list):
    reads = 0

    def __iter__(self):
        _Counted.reads += 1
        return super().__iter__()


def _detail():
    import services_api as SA
    rows = _Counted({"id": f"scan_http:{i}", "ip": f"192.0.2.{i % 5}", "service": f"S{i % 3}"} for i in range(30))
    d = types.SimpleNamespace(events=rows, serial=1)
    by_id, per_host = SA._detail_index(d)
    _Counted.reads = 0
    for i in range(5):
        by_id, per_host = SA._detail_index(d)
    ok("7-11 opening five records reads the day no more (the index is built once per day copy)", _Counted.reads == 0, _Counted.reads)
    ip = by_id["scan_http:7"]["ip"]
    ok("7-11 ...with the same answers: the record, the host's records and services",
       by_id["scan_http:7"]["id"] == "scan_http:7" and per_host[ip][0] == sum(1 for x in list.__iter__(rows) if x["ip"] == ip)
       and sorted(per_host[ip][1]) == sorted({x["service"] for x in list.__iter__(rows) if x["ip"] == ip}))
    src = open(SA.__file__, encoding="utf-8").read()
    body = src[src.index("def svc_detail"):src.index("def svc_replayed")]
    ok("7-11 the record view no longer scans the day per click (source)", "for x in day.events" not in body)


attempt("7-11 the record index", _detail)

# ------------------------------------------------------------------------------------------------------- 7-13
print("7-13: the seen-in backfill (seen_index.py)")
import seen_index as SI  # noqa: E402


def _backfill():
    SI.BACKFILL_DAYS = 1
    tmp = tempfile.mkdtemp(prefix="lg-b07-seen-")
    path = os.path.join(tmp, "seen_names.json")
    runs = []

    def load_day(d):
        runs.append(d)
        time.sleep(0.2)
        return types.SimpleNamespace(events=[])
    args = (load_day, lambda dt: dt.replace(hour=0, minute=0, second=0, microsecond=0), lambda: datetime.now(timezone.utc), lambda: {})
    real_exists, a_done, first = os.path.exists, threading.Event(), {"b": True}

    def exists(p):
        # worker B looks for the marker before worker A has written it, and goes on only after A has finished
        if threading.current_thread().name == "worker-b" and p.endswith(".done") and first["b"]:
            first["b"] = False
            a_done.wait(10)
            return False
        return real_exists(p)
    SI.os.path.exists = exists
    try:
        b = threading.Thread(target=lambda: SI.SeenIndex(path).backfill(*args), name="worker-b")
        b.start()
        time.sleep(0.2)
        SI.SeenIndex(path).backfill(*args)               # worker A
        t0 = time.time()
        while time.time() - t0 < 10 and any(t.name == "seen-index-backfill" for t in threading.enumerate()):
            time.sleep(0.05)
        a_done.set()
        b.join(10)
        time.sleep(0.3)
        while time.time() - t0 < 15 and any(t.name == "seen-index-backfill" for t in threading.enumerate()):
            time.sleep(0.05)
    finally:
        SI.os.path.exists = real_exists
    ok("7-13 two workers: the backfill runs once (the second finds it done after taking the lock)", len(runs) == 1, len(runs))


attempt("7-13 two workers backfilling", _backfill)

# ------------------------------------------------------------------------------------------------------- 7-14
print("7-14: the replay schedule (schedule.py)")
import schedule as SCH  # noqa: E402

asked = []
rows = {"n": 0}


def has_data(d):
    asked.append(d)
    return rows["n"]


now = datetime(2026, 11, 27, 12, 0, tzinfo=timezone.utc)
sc = SCH.ReplaySchedule(None, 24, 3600, has_data, now=lambda: now)
sc.tick(now)                                    # nothing yet: waiting for the day
rows["n"] = 5
asked.clear()
sc.tick(now + timedelta(minutes=1))             # the report arrives: settling
per_day = {d: asked.count(d) for d in set(asked)}
ok("7-14 a tick asks MongoDB for a day's rows once", asked and max(per_day.values()) == 1 and sc.status()["state"] == "settling",
   (len(asked), sc.status()["state"]))

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.stdout.flush()
os._exit(1 if fails else 0)
