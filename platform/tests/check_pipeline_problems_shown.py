#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# SPDX-FileCopyrightText: the Looking Glass contributors
"""A pipeline run that left reports out, or has something to check, is said in the admins' bell and on Settings ->
Task monitor, in the pipeline's own words (count audit, 2026-11-26: the status file held only rows inserted and failed,
so a run that refused a zip or could not read a report said "went well", and CSV files whose name is not a report file
name were nowhere). Made-up status files in throwaway folders; the Task monitor's pipeline card RUNS under node on a
small stand-in for the page (read from LG_HELD_DIR/task-monitor.js.new when there is one). No database.
Run: .venv/bin/python tests/check_pipeline_problems_shown.py"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PF = os.path.dirname(HERE)
sys.path.insert(0, PF)
os.environ.setdefault("LG_QUIET", "1"); os.environ.setdefault("THREATMAP_SCHEDULE", "0")
import system_alerts as SA  # noqa: E402

checks, fails = 0, []


def ok(label, cond, info=""):
    global checks
    checks += 1
    if not cond:
        fails.append(label)
    print(f"  {'ok  ' if cond else 'FAIL'} {label}" + (f"  [{str(info)[:600]}]" if info and not cond else ""), flush=True)


ERRORS = [{"key": "zips_refused", "count": 2, "text": "2 zip file(s) were not unpacked and were moved to quarantine "
           "(a limit, or a file that cannot be unpacked): their reports are not loaded"},
          {"key": "reports_failed", "count": 1, "text": "1 report(s) could not be read from the sorted folder and were not "
           "loaded this run (tried again next run)"}]
WARNINGS = [{"key": "csv_not_matched", "count": 2, "text": "2 CSV file(s) do not have a report file name, so they were "
             "not loaded: unzipped_backup/r.zip/2026-11-20-scan_x-kenya.csv, attachments_backup/2026-11-20-scan_x-ke-cidr.csv. "
             "Rename them, or remove them once checked"},
            {"key": "rows_no_time", "count": 3, "text": "3 row(s) have no timestamp: they are stored, but no page shows them"}]

root = tempfile.mkdtemp(prefix="lg-pipeprob-")
plat, pipe = os.path.join(root, "platform"), os.path.join(root, "database")
os.makedirs(os.path.join(plat, "data")); os.makedirs(os.path.join(pipe, "reports"))
open(os.path.join(pipe, "shadowserver_pipeline.py"), "w").write("# stand-in\n")
open(os.path.join(pipe, ".env"), "w").write(f"DATA_DIR={os.path.join(pipe, 'reports')}\n")
stp = os.path.join(pipe, "reports", "pipeline_status.json")
keep_env = os.environ.pop("PIPELINE_DIR", None)
now = time.time()
A = SA.Alerts(plat, env={})


def alerts(prefix):
    return [a for a in A.current(now) if a["key"].startswith(prefix)]


try:
    print("The bell")
    base = {"finished": round(now - 600), "disk_low": False, "free_gb": 900, "min_free_gb": 5, "rows_read": 10,
            "rows_inserted": 7, "rows_duplicates": 0, "rows_same_in_file": 2, "rows_same_hash": 0, "rows_bad_timestamp": 1,
            "rows_failed": 0, "rows_no_time": 3}
    json.dump({**base, "ok": False, "file_errors": 0, "errors": ERRORS, "warnings": []}, open(stp, "w"))
    f = alerts("pipeline-failed")
    ok("a run that refused zips and could not read a report: a problem, each said in the pipeline's words",
       len(f) == 1 and f[0]["problem"] and "2 zip file(s) were not unpacked" in f[0]["text"]
       and "1 report(s) could not be read" in f[0]["text"], f)
    json.dump({**base, "ok": True, "errors": [], "warnings": WARNINGS}, open(stp, "w"))
    w = alerts("pipeline-warnings")
    ok("a run that went well but has CSV files not loaded: an alert naming every file, and the rows without a time",
       len(w) == 1 and w[0]["problem"] and "2026-11-20-scan_x-kenya.csv" in w[0]["text"]
       and "2026-11-20-scan_x-ke-cidr.csv" in w[0]["text"] and "3 row(s) have no timestamp" in w[0]["text"]
       and not alerts("pipeline-failed"), w)
    key1 = w[0]["key"]
    json.dump({**base, "finished": round(now - 60), "ok": True, "errors": [], "warnings": WARNINGS}, open(stp, "w"))
    ok("...the next run says the same: the same alert, so a cleared one stays cleared", alerts("pipeline-warnings")[0]["key"] == key1)
    json.dump({**base, "ok": True, "errors": [], "warnings": WARNINGS[:1]}, open(stp, "w"))
    ok("...something else to say: a new alert", alerts("pipeline-warnings")[0]["key"] != key1)
    A.clear("ann", ["sys:" + alerts("pipeline-warnings")[0]["key"]])
    ok("...for administrators only (the 'settings' permission)",
       not any(i["id"].startswith("sys:pipeline-warnings") for i in A.for_user("bob", now, has_perm=lambda p: p == "findings"))
       and any(i["id"].startswith("sys:pipeline-warnings") for i in A.for_user("cat", now, has_perm=lambda p: p == "settings")))
    json.dump({"finished": round(now - 600), "ok": False, "file_errors": 2, "email_failed": 0, "disk_low": False}, open(stp, "w"))
    f = alerts("pipeline-failed")
    ok("an older pipeline's status (no texts): the counts as before", f and "2 file error" in f[0]["text"], f)
    json.dump({"finished": round(now - 600), "ok": True, "disk_low": False}, open(stp, "w"))
    ok("a good run with nothing to check: nothing", not alerts("pipeline-"), alerts("pipeline-"))
finally:
    shutil.rmtree(root, ignore_errors=True)
    if keep_env is not None:
        os.environ["PIPELINE_DIR"] = keep_env

print("Settings -> Task monitor (task-monitor.js, the pipeline card, run under node)")
node = os.environ.get("LG_NODE") or shutil.which("node") or next(iter(sorted(glob.glob(os.path.expanduser("~/lg-node/*/bin/node")))), None)
held = os.environ.get("LG_HELD_DIR", "")
js = os.path.join(held, "task-monitor.js.new") if held and os.path.isfile(os.path.join(held, "task-monitor.js.new")) \
    else os.path.join(PF, "static", "js", "task-monitor.js")
src = open(js, encoding="utf-8").read()
line = lambda start: (re.search(r"^  " + re.escape(start) + r".*$", src, re.M) or [""])[0]  # noqa: E731
m = re.search(r"^    const p = d\.pipeline \|\| \{\}, last = p\.last;\n.*?^      pipe\.append\(el\(\"small\", \"muted\", \"Schedule \(cron\):\"\), sch\);\n    \}\n",
              src, re.M | re.S)
ok("the pipeline card is found in the page file", bool(m))
if not node:
    if os.environ.get("LG_SUITE") == "all":       # the page-script part is the maintainer's: a failure there
        ok("node is there to run the Task monitor's pipeline card", False)
    else:
        print("  (its page-script part needs Node: a maintainer's check, run by LG_SUITE=all; not part of an installation's checks)")
elif m:
    shim = r"""
class E { constructor(t) { this.tag = t; this.children = []; this.className = ""; this._t = ""; this.href = ""; }
  append(...k) { for (const c of k) this.children.push(typeof c === "string" ? Object.assign(new E("#text"), { _t: c }) : c); }
  set textContent(v) { this.children = []; this._t = String(v); } get textContent() { return this._t + this.children.map((c) => c.textContent).join(""); } }
const document = { createElement: (t) => new E(t), createTextNode: (t) => Object.assign(new E("#text"), { _t: String(t) }) };
"""
    prog = shim + line("const el = ") + "\n" + line("const fmt = ") + "\nfunction drawPipe(d) {\n" + m.group(0) + "\n return pipe; }\n" + \
        "const d = JSON.parse(process.argv[1]); const pipe = drawPipe(d); const lis = [];\n" + \
        "const walk = (n) => { if (n.tag === 'li' || n.tag === 'p') lis.push([n.className, n.textContent]); n.children.forEach(walk); };\n" + \
        "walk(pipe); console.log(JSON.stringify({ text: pipe.textContent, lines: lis }));"
    last = {"finished": round(now - 600), "ok": False, "rows_read": 10, "rows_inserted": 7, "rows_duplicates": 0,
            "rows_same_in_file": 2, "rows_same_hash": 0, "rows_bad_timestamp": 1, "rows_failed": 0, "rows_no_time": 3,
            "file_errors": 0, "errors": ERRORS, "warnings": WARNINGS}
    r = subprocess.run([node, "-e", prog, json.dumps({"pipeline": {"found": True, "last": last, "schedule": [{"what": "run", "when": "hourly"}],
                                                                   "schedule_readable": True}})], capture_output=True, text=True, timeout=60)
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        out = {"text": "", "lines": [], "error": (r.stdout + r.stderr)[-1500:]}
    t = out["text"]
    ok("the card runs", not out.get("error"), out.get("error"))
    ok("every error is listed, as a problem line", all(any(c == "tm-badline" and e["text"] == x for c, x in out["lines"]) for e in ERRORS), out["lines"])
    ok("every warning is listed, with every file not loaded", all(any(w["text"] == x for _, x in out["lines"]) for w in WARNINGS), out["lines"])
    ok("the rows read and where they went, adding up to the rows read (7 + 2 + 1 = 10)",
       "Rows read: 10: 7 new, 2 repeated in the same file (stored once), 1 not stored (timestamp unreadable)." in t, t)
    ok("...and the stored rows without a timestamp", "3 of the stored rows have no timestamp" in t, t)

print(f"\n{checks - len(fails)}/{checks} checks passed" + (f"; FAILED: {', '.join(fails)}" if fails else ""))
sys.exit(1 if fails else 0)
